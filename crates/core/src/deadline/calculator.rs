//! Deadline calculator trait and beacon-node-derived implementation.

use chrono::{DateTime, Utc};
use pluto_eth2api::EthBeaconNodeApiClient;

use crate::types::{Duty, DutyType, SlotNumber};

use super::{DeadlineError, Result, to_chrono_duration};

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
    slot_duration: chrono::Duration,
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

/// Whole milliseconds, stored in chrono's native `i64` width with checked
/// conversions. Lifts the `u64`/`i64` `try_from` juggling out of arithmetic
/// call sites: every conversion either succeeds or returns `DeadlineError`.
pub(crate) struct Millis(i64);

impl From<chrono::Duration> for Millis {
    fn from(d: chrono::Duration) -> Self {
        Self(d.num_milliseconds())
    }
}

impl Millis {
    /// Constructs from a raw `i64` count of milliseconds.
    #[cfg(test)]
    pub(crate) fn new(ms: i64) -> Self {
        Self(ms)
    }

    /// Multiplies by a `SlotNumber`, checked for overflow on both the
    /// `u64`→`i64` slot conversion and the `i64`×`i64` multiplication.
    pub(crate) fn checked_mul_slot(self, slot: SlotNumber) -> Result<Self> {
        let mul = i64::try_from(slot.inner()).map_err(|_| DeadlineError::ArithmeticOverflow)?;
        self.0
            .checked_mul(mul)
            .map(Self)
            .ok_or(DeadlineError::ArithmeticOverflow)
    }

    /// Multiplies by `by`, returning `DeadlineError::ArithmeticOverflow` on
    /// overflow.
    fn checked_mul(self, by: i64) -> Result<Self> {
        self.0
            .checked_mul(by)
            .map(Self)
            .ok_or(DeadlineError::ArithmeticOverflow)
    }

    /// Divides by `by`, returning `DeadlineError::ArithmeticOverflow` on
    /// overflow or division by zero.
    fn checked_div(self, by: i64) -> Result<Self> {
        self.0
            .checked_div(by)
            .map(Self)
            .ok_or(DeadlineError::ArithmeticOverflow)
    }

    /// Adds two `Millis`, returning `DeadlineError::ArithmeticOverflow` on
    /// overflow.
    fn checked_add(self, other: Self) -> Result<Self> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(DeadlineError::ArithmeticOverflow)
    }

    /// Returns `base + self`, with both the `Millis → chrono::Duration` and
    /// the `DateTime` addition checked.
    pub(crate) fn add_to(self, base: DateTime<Utc>) -> Result<DateTime<Utc>> {
        let offset =
            chrono::Duration::try_milliseconds(self.0).ok_or(DeadlineError::DurationConversion)?;
        base.checked_add_signed(offset)
            .ok_or(DeadlineError::DateTimeCalculation)
    }
}
