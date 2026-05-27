//! Deadline calculator trait and beacon-node-derived implementation.

use chrono::{DateTime, Duration, Utc};
use pluto_eth2api::EthBeaconNodeApiClient;

use crate::types::{Duty, DutyType, SlotNumber};

use super::{Result, msecs::Msecs, to_chrono_duration};

/// Fraction of slot duration to use as a margin for network delays.
const MARGIN_FACTOR: i64 = 12;
/// Block proposal must complete within 1/3 of a slot (denominator).
const PROPOSAL_SLOT_FRACTION: i64 = 3;
/// SyncMessage must complete within 2/3 of a slot (numerator over
/// `PROPOSAL_SLOT_FRACTION`).
const SYNC_MESSAGE_PHASES: i64 = 2;
/// Attestation/aggregation deadline = N slots after slot start.
const ATTESTATION_DEADLINE_SLOTS: i64 = 2;

/// Beacon-node-derived deadline calculator.
///
/// Caches genesis time and slot duration fetched from the beacon node, and
/// computes per-duty deadlines from them. Construction is async because it
/// hits the beacon node; the calculator itself is pure once built.
pub struct DutyDeadlineCalculator {
    genesis_time: DateTime<Utc>,
    slot_duration: Duration,
}

impl DutyDeadlineCalculator {
    /// Fetches genesis time and slot duration from the beacon node.
    ///
    /// # Errors
    ///
    /// Returns an error if fetching genesis time or slots config fails.
    pub async fn from_client(client: &EthBeaconNodeApiClient) -> Result<Self> {
        let genesis_time = client.fetch_genesis_time().await?;
        let slots_config = client.fetch_slots_config().await?;
        let (slot_duration, _slots_per_epoch) = slots_config;
        let slot_duration = to_chrono_duration(slot_duration)?;
        Ok(Self {
            genesis_time,
            slot_duration,
        })
    }

    /// Wall-clock start of the given slot: `genesis_time + slot *
    /// slot_duration`.
    fn slot_start(&self, slot: SlotNumber) -> Result<DateTime<Utc>> {
        let offset = Msecs::from(self.slot_duration).checked_mul_slot(slot)?;
        offset.add_to(self.genesis_time)
    }

    /// Network-delay margin added to every deadline: `slot_duration /
    /// MARGIN_FACTOR`.
    fn margin(&self) -> Result<Msecs> {
        Msecs::from(self.slot_duration).checked_div(MARGIN_FACTOR)
    }

    /// Duty-type-specific offset from slot start.
    fn duty_duration(&self, duty_type: &DutyType) -> Result<Msecs> {
        let secs = Msecs::from(self.slot_duration);
        match duty_type {
            DutyType::Proposer | DutyType::Randao => secs.checked_div(PROPOSAL_SLOT_FRACTION),
            DutyType::SyncMessage => secs
                .checked_mul(SYNC_MESSAGE_PHASES)?
                .checked_div(PROPOSAL_SLOT_FRACTION),
            // Attestations/aggregations are still accepted after the deadline,
            // but rewards are heavily diminished.
            DutyType::Attester | DutyType::Aggregator | DutyType::PrepareAggregator => {
                secs.checked_mul(ATTESTATION_DEADLINE_SLOTS)
            }
            _ => Ok(secs),
        }
    }
}

/// Computes deadlines for duties.
///
/// `Ok(Some(deadline))` — duty expires at the given wall-clock time.
/// `Ok(None)`           — duty never expires (e.g. Exit, BuilderRegistration).
/// `Err(_)`             — arithmetic or conversion failure.
pub trait DeadlineCalculator: Send + Sync + 'static {
    /// Computes the deadline for the given duty. See trait docs for return
    /// semantics.
    fn deadline(&self, duty: &Duty) -> Result<Option<DateTime<Utc>>>;
}

/// Calculator that reports every duty as never expiring. Useful for
/// scenarios that need to plug into the deadliner API but don't actually want
/// any eviction (e.g. DKG, which is one-shot and outside the slot timeline).
pub struct NeverExpiringCalculator;

impl DeadlineCalculator for NeverExpiringCalculator {
    fn deadline(&self, _duty: &Duty) -> Result<Option<DateTime<Utc>>> {
        Ok(None)
    }
}

impl DeadlineCalculator for DutyDeadlineCalculator {
    fn deadline(&self, duty: &Duty) -> Result<Option<DateTime<Utc>>> {
        if duty.duty_type.never_expires() {
            Ok(None)
        } else {
            let start = self.slot_start(duty.slot)?;
            let offset = self
                .duty_duration(&duty.duty_type)?
                .checked_add(self.margin()?)?;
            let deadline = offset.add_to(start)?;
            Ok(Some(deadline))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::{Context, Result, ensure};

    use crate::deadline::DeadlineError;

    fn test_calculator(slot_duration_secs: i64) -> Result<DutyDeadlineCalculator> {
        let genesis_time =
            DateTime::from_timestamp(1606824023, 0).context("invalid genesis timestamp")?;
        let slot_duration =
            Duration::try_seconds(slot_duration_secs).context("invalid slot duration")?;
        Ok(DutyDeadlineCalculator {
            genesis_time,
            slot_duration,
        })
    }

    #[test]
    fn slot_start_at_slot_zero_equals_genesis() -> Result<()> {
        let calc = test_calculator(12)?;
        let start = calc.slot_start(SlotNumber::new(0))?;
        ensure!(start == calc.genesis_time, "slot 0 must equal genesis");
        Ok(())
    }

    #[test]
    fn slot_start_advances_by_slot_times_duration() -> Result<()> {
        let slot_duration_secs = 12i64;
        let slot_index = 100u64;
        let calc = test_calculator(slot_duration_secs)?;
        let slot = SlotNumber::new(slot_index);

        let start = calc.slot_start(slot)?;

        let slot_index_i64 = i64::try_from(slot_index).context("slot index doesn't fit in i64")?;
        let offset_secs = slot_duration_secs
            .checked_mul(slot_index_i64)
            .context("offset overflow")?;
        let offset = Duration::try_seconds(offset_secs).context("offset out of chrono range")?;
        let expected = calc
            .genesis_time
            .checked_add_signed(offset)
            .context("expected overflow")?;
        ensure!(
            start == expected,
            "slot_start mismatch: got {start}, expected {expected}"
        );
        Ok(())
    }

    #[test]
    fn slot_start_overflows_on_huge_slot() -> Result<()> {
        let calc = test_calculator(12)?;
        let slot = SlotNumber::new(u64::MAX);
        let result = calc.slot_start(slot);
        ensure!(
            matches!(result, Err(DeadlineError::ArithmeticOverflow)),
            "expected ArithmeticOverflow, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn margin_is_slot_duration_divided_by_margin_factor() -> Result<()> {
        let slot_duration_secs = 12i64;
        let calc = test_calculator(slot_duration_secs)?;

        let margin = calc.margin()?;

        let slot_duration_ms = slot_duration_secs
            .checked_mul(1000)
            .context("ms overflow")?;
        let expected_ms = slot_duration_ms
            .checked_div(MARGIN_FACTOR)
            .context("margin div overflow")?;
        let expected = Msecs::new(expected_ms);
        let margin_offset = margin.add_to(calc.genesis_time)?;
        let expected_offset = expected.add_to(calc.genesis_time)?;
        ensure!(
            margin_offset == expected_offset,
            "margin mismatch: got offset {margin_offset}, expected {expected_offset}"
        );
        Ok(())
    }
}
