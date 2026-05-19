//! Deadline calculator trait and beacon-node-derived implementation.

use chrono::{DateTime, Utc};
use pluto_eth2api::EthBeaconNodeApiClient;

use crate::types::{Duty, SlotNumber};

use super::{DeadlineError, Result, to_chrono_duration};

/// Beacon-node-derived deadline calculator.
///
/// Caches genesis time and slot duration fetched from the beacon node, and
/// computes per-duty deadlines from them. Construction is async because it
/// hits the beacon node; the calculator itself is pure once built.
pub struct DutyDeadlineCalculator {
    pub(super) genesis_time: DateTime<Utc>,
    pub(super) slot_duration: chrono::Duration,
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
    pub(super) fn slot_start(&self, slot: SlotNumber) -> Result<DateTime<Utc>> {
        let offset = Seconds::from(self.slot_duration).checked_mul_slot(slot)?;
        offset.add_to(self.genesis_time)
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

/// Whole seconds, stored in chrono's native `i64` width with checked
/// conversions. Lifts the `u64`/`i64` `try_from` juggling out of arithmetic
/// call sites: every conversion either succeeds or returns `DeadlineError`.
struct Seconds(i64);

impl From<chrono::Duration> for Seconds {
    fn from(d: chrono::Duration) -> Self {
        Self(d.num_seconds())
    }
}

impl Seconds {
    /// Multiplies by a `SlotNumber`, checked for overflow on both the
    /// `u64`→`i64` slot conversion and the `i64`×`i64` multiplication.
    fn checked_mul_slot(self, slot: SlotNumber) -> Result<Self> {
        let mul = i64::try_from(slot.inner()).map_err(|_| DeadlineError::ArithmeticOverflow)?;
        self.0
            .checked_mul(mul)
            .map(Self)
            .ok_or(DeadlineError::ArithmeticOverflow)
    }

    /// Returns `base + self`, with both the `Seconds → chrono::Duration` and
    /// the `DateTime` addition checked.
    fn add_to(self, base: DateTime<Utc>) -> Result<DateTime<Utc>> {
        let offset =
            chrono::Duration::try_seconds(self.0).ok_or(DeadlineError::DurationConversion)?;
        base.checked_add_signed(offset)
            .ok_or(DeadlineError::DateTimeCalculation)
    }
}
