//! Deadline calculator trait and beacon-node-derived implementation.

use chrono::{DateTime, Duration, Utc};
use pluto_eth2api::EthBeaconNodeApiClient;

use crate::types::{Duty, DutyType, SlotNumber};

use super::{Result, millis::Millis, to_chrono_duration};

/// Fraction of slot duration to use as a margin for network delays.
const MARGIN_FACTOR: i32 = 12;
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
        let offset = Millis::from(self.slot_duration).checked_mul_slot(slot)?;
        offset.add_to(self.genesis_time)
    }

    /// Network-delay margin added to every deadline: `slot_duration /
    /// MARGIN_FACTOR`.
    fn margin(&self) -> Result<Millis> {
        Millis::from(self.slot_duration).checked_div(MARGIN_FACTOR.into())
    }

    /// Duty-type-specific offset from slot start.
    fn duty_duration(&self, duty_type: &DutyType) -> Result<Millis> {
        let secs = Millis::from(self.slot_duration);
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
