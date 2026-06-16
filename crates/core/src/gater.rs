//! Duty gater — rejects duties whose type is invalid or that are too far in the
//! future.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use pluto_eth2api::{EthBeaconNodeApiClient, EthBeaconNodeApiClientError};

use crate::{
    clock::{ChronoClock, Clock},
    types::Duty,
};

/// Shared, callable duty-gating predicate: the value form that the wire
/// components (parsigex, consensus) accept and invoke per duty.
pub type DutyGaterFn = Arc<dyn Fn(&Duty) -> bool + Send + Sync + 'static>;

/// Default number of epochs into the future for which duties are accepted.
const DEFAULT_ALLOWED_FUTURE_EPOCHS: u64 = 2;

/// Errors returned while constructing a [`DutyGater`].
#[derive(Debug, thiserror::Error)]
pub enum GaterError {
    /// Failed to fetch beacon node configuration.
    #[error("Failed to fetch beacon node configuration: {0}")]
    BeaconNodeConfigError(#[from] EthBeaconNodeApiClientError),

    /// The slot duration is not a positive whole number of milliseconds
    /// (sub-millisecond, or too large to fit `u64`), so it cannot be used as a
    /// divisor in the millisecond-resolution epoch arithmetic.
    #[error("Slot duration is not a positive number of milliseconds")]
    InvalidSlotDuration,
}

/// Result type for gater operations.
pub type Result<T> = std::result::Result<T, GaterError>;

/// Gates duties by type and recency.
///
/// [`DutyGater::allows`] returns `true` only when a duty may be processed. It
/// rejects duties received from peers over the wire whose type is invalid or
/// whose epoch is more than `allowed_future_epochs` beyond the current epoch.
/// It does **not** reject duties in the past — that is the responsibility of
/// the [`crate::deadline`] component.
pub struct DutyGater {
    genesis_time: DateTime<Utc>,
    /// Slot duration in milliseconds. Always ≥ 1, enforced in
    /// [`DutyGater::with_options`].
    slot_duration_ms: u64,
    /// Slots per epoch. Guaranteed non-zero by the `fetch_slots_config`
    /// contract.
    slots_per_epoch: u64,
    allowed_future_epochs: u64,
    clock: Box<dyn Clock>,
}

impl DutyGater {
    /// Builds a gater from a beacon node client using production defaults: a
    /// real wall clock and a `DEFAULT_ALLOWED_FUTURE_EPOCHS` future-epoch
    /// budget.
    pub async fn new(client: &EthBeaconNodeApiClient) -> Result<Self> {
        Self::with_options(client, Box::new(ChronoClock), DEFAULT_ALLOWED_FUTURE_EPOCHS).await
    }

    /// Builds a gater with an injected clock and future-epoch budget. The
    /// single fetch path shared with [`DutyGater::new`]; the overrides
    /// exist for tests.
    async fn with_options(
        client: &EthBeaconNodeApiClient,
        clock: Box<dyn Clock>,
        allowed_future_epochs: u64,
    ) -> Result<Self> {
        let genesis_time = client.fetch_genesis_time().await?;
        let (slot_duration, slots_per_epoch) = client.fetch_slots_config().await?;

        // Work in whole milliseconds. `as_millis()` is u128 (SECONDS_PER_SLOT
        // keeps it tiny); reject a zero (sub-millisecond) or overflowing value
        // rather than divide by zero in `current_epoch`.
        let slot_duration_ms = u64::try_from(slot_duration.as_millis())
            .ok()
            .filter(|&ms| ms != 0)
            .ok_or(GaterError::InvalidSlotDuration)?;

        Ok(Self {
            genesis_time,
            slot_duration_ms,
            slots_per_epoch,
            allowed_future_epochs,
            clock,
        })
    }

    /// Returns `true` if `duty` may be processed: its type is valid and its
    /// epoch is no more than `allowed_future_epochs` beyond the current epoch.
    #[must_use]
    pub fn allows(&self, duty: &Duty) -> bool {
        if !duty.duty_type.is_valid() {
            return false;
        }

        let duty_epoch = duty
            .slot
            .inner()
            .checked_div(self.slots_per_epoch)
            .expect("slots_per_epoch is non-zero (fetch_slots_config contract)");

        duty_epoch
            <= self
                .current_epoch()
                .saturating_add(self.allowed_future_epochs)
    }

    /// Converts this gater into the shared callable [`DutyGaterFn`] consumed by
    /// the wire components.
    #[must_use]
    pub fn into_fn(self) -> DutyGaterFn {
        let gater = Arc::new(self);
        Arc::new(move |duty: &Duty| gater.allows(duty))
    }

    /// Current epoch derived from the injected clock and genesis time.
    fn current_epoch(&self) -> u64 {
        let elapsed_ms = self
            .clock
            .now()
            .signed_duration_since(self.genesis_time)
            .num_milliseconds();

        // Pre-genesis instants clamp to epoch 0: the gater is only built after
        // genesis, so this path is unreachable in practice, and treating a
        // negative elapsed time as a huge future slot would be nonsense.
        let elapsed_ms = u64::try_from(elapsed_ms).unwrap_or(0);

        let current_slot = elapsed_ms
            .checked_div(self.slot_duration_ms)
            .expect("slot_duration_ms >= 1 (enforced in with_options)");

        current_slot
            .checked_div(self.slots_per_epoch)
            .expect("slots_per_epoch is non-zero (fetch_slots_config contract)")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use chrono::{DateTime, Utc};
    use pluto_testutil::BeaconMock;

    use super::*;
    use crate::types::{DutyType, SlotNumber};

    /// A fixed clock returning `now` regardless of when it is called.
    fn fixed_clock(now: DateTime<Utc>) -> Box<dyn Clock> {
        Box::new(move || now)
    }

    /// Builds a gater from hand-set configuration and a fixed clock, for
    /// non-async coverage that needs no beacon node.
    fn gater(
        genesis_time: DateTime<Utc>,
        slot_duration_ms: u64,
        slots_per_epoch: u64,
        allowed_future_epochs: u64,
        now: DateTime<Utc>,
    ) -> DutyGater {
        DutyGater {
            genesis_time,
            slot_duration_ms,
            slots_per_epoch,
            allowed_future_epochs,
            clock: fixed_clock(now),
        }
    }

    fn attester(slot: u64) -> Duty {
        Duty::new_attester_duty(SlotNumber::new(slot))
    }

    fn duty_with_type(slot: u64, duty_type: DutyType) -> Duty {
        Duty {
            slot: SlotNumber::new(slot),
            duty_type,
        }
    }

    /// genesis == now (current epoch 0), 1s slots, 2 slots/epoch, 2 future
    /// epochs allowed ⇒ slots 0-5 accepted.
    #[tokio::test]
    async fn duty_gater() {
        // Genesis round-trips through the beacon API as whole seconds, so pin
        // `now` to a whole second to make the injected clock equal genesis.
        let now = DateTime::from_timestamp(Utc::now().timestamp(), 0).expect("valid timestamp");

        let bmock = BeaconMock::builder()
            .genesis_time(now)
            .slot_duration(Duration::from_secs(1))
            .slots_per_epoch(2)
            .build()
            .await
            .expect("build beacon mock");

        let gater = DutyGater::with_options(bmock.client(), fixed_clock(now), 2)
            .await
            .expect("build gater");

        // Allowed: slots 0-5 (epochs 0, 1, 2 ≤ budget 2).
        for slot in 0..=5 {
            assert!(
                gater.allows(&attester(slot)),
                "slot {slot} should be allowed"
            );
        }

        // Disallowed: slot 6 onwards (epoch 3+).
        for slot in [6, 7, 1000] {
            assert!(
                !gater.allows(&attester(slot)),
                "slot {slot} should be disallowed"
            );
        }

        // Invalid duty types are rejected regardless of slot.
        assert!(!gater.allows(&duty_with_type(0, DutyType::Unknown)));
        assert!(!gater.allows(&duty_with_type(
            1,
            DutyType::DutySentinel(Box::new(DutyType::Attester))
        )));
    }

    /// Smoke test of the public `new` entrypoint (real `ChronoClock`, default
    /// budget) against a mainnet-like 12s/32-slot config. Genesis is pinned to
    /// ~now, so `current_epoch` stays 0 for the whole test (epochs are 384s
    /// long) and the default future-epoch budget of 2 is locked in: slot 96
    /// (epoch 3) would only be allowed if the default were 3.
    #[tokio::test]
    async fn new_defaults() {
        let now = DateTime::from_timestamp(Utc::now().timestamp(), 0).expect("valid timestamp");

        let bmock = BeaconMock::builder()
            .genesis_time(now)
            .slot_duration(Duration::from_secs(12))
            .slots_per_epoch(32)
            .build()
            .await
            .expect("build beacon mock");

        let gater = DutyGater::new(bmock.client()).await.expect("build gater");

        assert!(gater.allows(&attester(0))); // current epoch
        assert!(gater.allows(&attester(95))); // epoch 2 (= budget)
        assert!(!gater.allows(&attester(96))); // epoch 3 (> budget)
    }

    /// Non-async coverage of the epoch boundary with a non-zero current epoch
    /// (the async test above only exercises current epoch 0).
    #[test]
    fn epoch_boundary() {
        let genesis = DateTime::from_timestamp(1_600_000_000, 0).expect("valid timestamp");
        // 100s after genesis at 1s slots ⇒ slot 100 ⇒ epoch 3 (32 slots/epoch).
        let now = DateTime::from_timestamp(1_600_000_100, 0).expect("valid timestamp");
        // Budget = current epoch 3 + 2 = 5 ⇒ duty epoch ≤ 5 (slot ≤ 191) allowed.
        let gater = gater(genesis, 1_000, 32, 2, now);

        assert!(gater.allows(&attester(96))); // current epoch (3)
        assert!(gater.allows(&attester(128))); // N+1
        assert!(gater.allows(&attester(160))); // N+2 start
        assert!(gater.allows(&attester(191))); // N+2 end
        assert!(!gater.allows(&attester(192))); // N+3
        assert!(!gater.allows(&attester(10_000)));
    }

    /// Pre-genesis instants clamp to epoch 0.
    #[test]
    fn pre_genesis_clamps_to_epoch_zero() {
        let genesis = DateTime::from_timestamp(1_600_000_100, 0).expect("valid timestamp");
        let now = DateTime::from_timestamp(1_600_000_000, 0).expect("valid timestamp");
        // Budget = epoch 0 + 2 = 2 ⇒ slot ≤ 95 (epoch ≤ 2) allowed at 32 slots/epoch.
        let gater = gater(genesis, 1_000, 32, 2, now);

        assert!(gater.allows(&attester(0)));
        assert!(gater.allows(&attester(95))); // epoch 2
        assert!(!gater.allows(&attester(96))); // epoch 3
    }

    /// `into_fn` yields a callable predicate equivalent to `allows`, usable
    /// where a `DutyGaterFn` (e.g. `pluto_parsigex::DutyGater`) is expected.
    #[test]
    fn into_fn_matches_allows() {
        let genesis = DateTime::from_timestamp(1_600_000_000, 0).expect("valid timestamp");
        let now = DateTime::from_timestamp(1_600_000_100, 0).expect("valid timestamp");
        let gater_fn: DutyGaterFn = gater(genesis, 1_000, 32, 2, now).into_fn();

        assert!(gater_fn(&attester(191)));
        assert!(!gater_fn(&attester(192)));
        assert!(!gater_fn(&duty_with_type(0, DutyType::Unknown)));
    }

    #[test]
    fn invalid_type_rejected() {
        let genesis = DateTime::from_timestamp(1_600_000_000, 0).expect("valid timestamp");
        let gater = gater(genesis, 1_000, 32, 2, genesis);

        assert!(!gater.allows(&duty_with_type(0, DutyType::Unknown)));
        assert!(!gater.allows(&duty_with_type(
            0,
            DutyType::DutySentinel(Box::new(DutyType::Attester))
        )));
    }
}
