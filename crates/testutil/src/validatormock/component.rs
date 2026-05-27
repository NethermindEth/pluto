//! Validator-mock scheduler.
//!
//! Rust port of `charon/testutil/validatormock/component.go`. Drives a sliding
//! window of attesters and sync-committee members for the configured pubkeys
//! and dispatches duties (propose, attest, aggregate, sync messages, sync
//! contributions, builder registrations) at their slot-relative offsets.
//!
//! Goroutines map to `tokio::spawn`; `chan struct{}` close-once channels live
//! inside the per-slot attester / per-epoch sync-committee handles already
//! ported in [`super::attest`] and [`super::synccomm`]. Time is driven by an
//! injectable [`Clock`] so tests can advance virtual time without
//! `tokio::time::pause()` (which fights `wiremock`).

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use pluto_core::types::DutyType;
use pluto_eth2api::{EthBeaconNodeApiClient, spec::phase0::BLSPubKey};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::{
    SignFunc,
    attest::SlotAttester,
    clock::{Clock, SystemClock},
    error::{Error, Result},
    meta::{MetaEpoch, MetaSlot, SpecMeta},
    propose,
    synccomm::SyncCommMember,
};

/// Sliding-window depth: keep this many future epochs alive.
const EPOCH_WINDOW: u64 = 2;

/// Number of leading slots [`Component`] swallows before scheduling duties.
/// Mirrors Go's `delayStartSlots` workaround for simnet peer inconsistencies.
const DELAY_START_SLOTS: u32 = 2;

/// Duty + the wall-clock instant it should fire at.
#[derive(Debug, Clone)]
struct ScheduleTuple {
    duty_type: DutyType,
    slot: u64,
    start_time: SystemTime,
}

/// Validator-mock scheduler. Built by [`Component::new`]; drops cleanly when
/// [`Component::shutdown`] is called or the value is dropped.
pub struct Component {
    inner: Arc<Inner>,
    cancel: CancellationToken,
    scheduler: Mutex<Option<JoinHandle<()>>>,
    scheduled_tx: mpsc::Sender<ScheduleTuple>,
}

struct Inner {
    eth2_cl: EthBeaconNodeApiClient,
    sign_func: SignFunc,
    pubkeys: Vec<BLSPubKey>,
    meta: SpecMeta,
    builder_api: bool,
    clock: Arc<dyn Clock>,
    state: Mutex<MutableState>,
}

#[derive(Default)]
struct MutableState {
    delay_slots: u32,
    started: bool,
    attesters_by_slot: HashMap<u64, Arc<SlotAttester>>,
    sync_comms_by_epoch: HashMap<u64, Arc<SyncCommMember>>,
}

impl std::fmt::Debug for Component {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Component")
            .field("pubkeys", &self.inner.pubkeys.len())
            .field("meta", &self.inner.meta)
            .field("builder_api", &self.inner.builder_api)
            .finish()
    }
}

#[bon::bon]
impl Component {
    /// Builds a scheduler and spawns the consumer task that fires duties at
    /// their target times. Mirrors Go's `New(...)`.
    ///
    /// `clock` defaults to [`SystemClock`] when omitted.
    #[builder]
    pub fn new(
        eth2_cl: EthBeaconNodeApiClient,
        sign_func: SignFunc,
        pubkeys: Vec<BLSPubKey>,
        meta: SpecMeta,
        builder_api: bool,
        clock: Option<Arc<dyn Clock>>,
    ) -> Self {
        let cancel = CancellationToken::new();
        let (scheduled_tx, scheduled_rx) = mpsc::channel::<ScheduleTuple>(64);
        let inner = Arc::new(Inner {
            eth2_cl,
            sign_func,
            pubkeys,
            meta,
            builder_api,
            clock: clock.unwrap_or_else(|| Arc::new(SystemClock)),
            state: Mutex::new(MutableState::default()),
        });
        let scheduler = tokio::spawn(run_scheduler(
            Arc::clone(&inner),
            cancel.clone(),
            scheduled_rx,
        ));
        Self {
            inner,
            cancel,
            scheduler: Mutex::new(Some(scheduler)),
            scheduled_tx,
        }
    }
}

impl Component {
    /// Cancels the scheduler and awaits its termination. Idempotent.
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        if let Some(handle) = self.scheduler.lock().await.take() {
            let _ = handle.await;
        }
    }

    /// Called externally each slot. Mirrors Go's `Component.SlotTicked`.
    pub async fn slot_ticked(&self, slot: u64) -> Result<()> {
        if self.delay_on_startup().await {
            return Ok(());
        }
        self.schedule_slot(MetaSlot {
            slot,
            meta: self.inner.meta,
        })
        .await
    }

    async fn delay_on_startup(&self) -> bool {
        let mut state = self.inner.state.lock().await;
        if state.delay_slots == DELAY_START_SLOTS {
            return false;
        }
        state.delay_slots = state.delay_slots.saturating_add(1);
        true
    }

    async fn schedule_slot(&self, slot: MetaSlot) -> Result<()> {
        let is_startup = self.is_startup().await;

        if is_startup || slot.first_in_epoch() {
            self.manage_epoch_state(slot.epoch()).await?;
        }

        let mut duties: Vec<ScheduleTuple> = duties_for_slot(slot, all_duty_types())
            .into_iter()
            .collect();
        duties.sort_by_key(|d| d.start_time);

        for duty in duties {
            if self.cancel.is_cancelled() {
                return Ok(());
            }
            if self.scheduled_tx.send(duty).await.is_err() {
                // Receiver dropped — scheduler is shutting down.
                return Ok(());
            }
        }
        Ok(())
    }

    async fn is_startup(&self) -> bool {
        let mut state = self.inner.state.lock().await;
        let was_started = state.started;
        state.started = true;
        !was_started
    }

    /// Refreshes attester + sync-committee state for the lookahead window.
    /// Mirrors Go's `manageEpochState`.
    async fn manage_epoch_state(&self, epoch: MetaEpoch) -> Result<()> {
        // Drop attesters / sync-comm members for the past `EPOCH_WINDOW` epochs.
        let mut e = epoch;
        for _ in 0..EPOCH_WINDOW {
            self.delete_attesters(e).await;
            self.delete_sync_comm_members(e).await;
            e = e.prev();
        }

        // Bring up future window.
        let mut e = epoch;
        for _ in 0..EPOCH_WINDOW {
            self.start_attesters(e).await;
            self.start_sync_comm_members(e).await?;
            e = e.next();
        }
        Ok(())
    }

    async fn start_attesters(&self, epoch: MetaEpoch) {
        for slot in epoch.slots() {
            let attester = Arc::new(SlotAttester::new(
                Arc::new(self.inner.eth2_cl.clone()),
                slot.slot,
                Arc::clone(&self.inner.sign_func),
                self.inner.pubkeys.clone(),
            ));
            self.inner
                .state
                .lock()
                .await
                .attesters_by_slot
                .insert(slot.slot, attester);
        }
    }

    async fn start_sync_comm_members(&self, epoch: MetaEpoch) -> Result<()> {
        let member = Arc::new(SyncCommMember::new(
            self.inner.eth2_cl.clone(),
            epoch.epoch,
            Arc::clone(&self.inner.sign_func),
            self.inner.pubkeys.clone(),
        ));
        member.prepare_epoch().await?;
        self.inner
            .state
            .lock()
            .await
            .sync_comms_by_epoch
            .insert(epoch.epoch, member);
        Ok(())
    }

    async fn delete_attesters(&self, epoch: MetaEpoch) {
        let mut state = self.inner.state.lock().await;
        for slot in epoch.slots() {
            state.attesters_by_slot.remove(&slot.slot);
        }
    }

    async fn delete_sync_comm_members(&self, epoch: MetaEpoch) {
        self.inner
            .state
            .lock()
            .await
            .sync_comms_by_epoch
            .remove(&epoch.epoch);
    }
}

impl Drop for Component {
    /// Cancels the scheduler best-effort. Tasks are not awaited here — `Drop`
    /// cannot `.await` — so callers that need clean drainage of in-flight
    /// duty tasks MUST call [`Component::shutdown`] explicitly before drop.
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn run_scheduler(
    inner: Arc<Inner>,
    cancel: CancellationToken,
    mut scheduled_rx: mpsc::Receiver<ScheduleTuple>,
) {
    // Track per-duty tasks so `Component::shutdown` can drain them. Dropping
    // the JoinHandle from a bare `tokio::spawn` would let a duty's HTTP
    // request outlive `shutdown().await` and leak across test boundaries.
    let mut duties: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            maybe = scheduled_rx.recv() => {
                let Some(scheduled) = maybe else { break };
                let inner_for_task = Arc::clone(&inner);
                let cancel_for_task = cancel.clone();
                duties.spawn(async move {
                    let start_time = scheduled.start_time;
                    let slot = scheduled.slot;
                    let duty_label = scheduled.duty_type.clone();
                    tokio::select! {
                        _ = cancel_for_task.cancelled() => {},
                        () = inner_for_task.clock.sleep_until(start_time) => {
                            // Race the duty body against cancellation. Go's
                            // `wait(ctx, ch)` selects on ctx, so a never-closed
                            // readiness signal (e.g. when an earlier
                            // `prepare()` failed) does not stick the goroutine
                            // forever. Rust's `CloseOnce::wait` is not
                            // cancellable, so without this outer select a duty
                            // blocked on `duties_ok.wait()` would deadlock
                            // `Component::shutdown`'s JoinSet drain.
                            tokio::select! {
                                _ = cancel_for_task.cancelled() => {},
                                res = run_duty_via_inner(&inner_for_task, scheduled) => {
                                    if let Err(err) = res {
                                        warn!(?err, slot, ?duty_label, "validatormock: duty failed");
                                    }
                                }
                            }
                        }
                    }
                });
            }
            // Reap finished duties to keep the JoinSet bounded. Disabled when
            // empty — `Some(_)` does not match `None`.
            Some(_) = duties.join_next() => {}
        }
    }
    // Drain in-flight duties before returning so callers awaiting
    // `Component::shutdown` see all work settled. Each task observes
    // `cancel.cancelled()` in its outer select; bodies already running run
    // to completion (mirroring Go's `Run`, which lets the duty finish
    // before returning from the loop).
    while duties.join_next().await.is_some() {}
}

async fn run_duty_via_inner(inner: &Inner, duty: ScheduleTuple) -> Result<()> {
    let state = inner.state.lock().await;
    let attester = state.attesters_by_slot.get(&duty.slot).cloned();
    let epoch = inner.meta.epoch_from_slot(duty.slot).epoch;
    let sync_comm = state.sync_comms_by_epoch.get(&epoch).cloned();
    drop(state);

    match duty.duty_type {
        DutyType::PrepareAggregator => {
            attester
                .ok_or_else(|| Error::Malformed(format!("attester nil at slot {}", duty.slot)))?
                .prepare()
                .await
        }
        DutyType::Attester => {
            attester
                .ok_or_else(|| Error::Malformed(format!("attester nil at slot {}", duty.slot)))?
                .attest()
                .await
        }
        DutyType::Aggregator => attester
            .ok_or_else(|| Error::Malformed(format!("attester nil at slot {}", duty.slot)))?
            .aggregate()
            .await
            .map(|_| ()),
        DutyType::Proposer => {
            propose::propose_block(&inner.eth2_cl, &inner.sign_func, duty.slot).await
        }
        DutyType::PrepareSyncContribution => {
            sync_comm
                .ok_or_else(|| Error::Malformed(format!("synccomm nil at slot {}", duty.slot)))?
                .prepare_slot(duty.slot)
                .await
        }
        DutyType::SyncMessage => {
            sync_comm
                .ok_or_else(|| Error::Malformed(format!("synccomm nil at slot {}", duty.slot)))?
                .message(duty.slot)
                .await
        }
        DutyType::SyncContribution => sync_comm
            .ok_or_else(|| Error::Malformed(format!("synccomm nil at slot {}", duty.slot)))?
            .aggregate(duty.slot)
            .await
            .map(|_| ()),
        DutyType::BuilderRegistration => {
            // Go's `runDuty` has no case for this duty type and falls through
            // to the `default:` arm returning "unexpected duty"
            // (charon/testutil/validatormock/component.go:305). Surface the
            // same loud error here — the duty IS scheduled every epoch by
            // `duty_start_times`, matching Go, and the mock has no
            // registration submission path.
            Err(Error::Malformed(
                "unexpected duty: DutyBuilderRegistration".to_string(),
            ))
        }
        DutyType::BuilderProposer => Err(Error::UnsupportedVariant("DutyBuilderProposer")),
        _ => Err(Error::UnsupportedVariant("unexpected duty type")),
    }
}

fn all_duty_types() -> &'static [DutyType] {
    use DutyType::*;
    &[
        PrepareAggregator,
        Attester,
        Aggregator,
        Proposer,
        BuilderRegistration,
        PrepareSyncContribution,
        SyncMessage,
        SyncContribution,
    ]
}

/// Returns the duty start-time offsets for the given duty type. Mirrors the Go
/// `dutyStartTimeFuncsByDuty` table.
fn duty_start_times(duty: DutyType, slot: MetaSlot) -> Vec<SystemTime> {
    use DutyType::*;
    match duty {
        PrepareAggregator => vec![
            slot.epoch().prev().first_slot().start_time(),
            slot.epoch().first_slot().start_time(),
        ],
        Attester => vec![fraction(slot, 1, 3)],
        Aggregator => vec![fraction(slot, 2, 3)],
        Proposer => vec![slot.start_time()],
        BuilderRegistration => vec![slot.epoch().first_slot().start_time()],
        PrepareSyncContribution => vec![slot.start_time()],
        SyncMessage => vec![fraction(slot, 1, 3)],
        SyncContribution => vec![fraction(slot, 2, 3)],
        _ => Vec::new(),
    }
}

/// Returns `slot.start_time + (slot_duration * x / y)`. Saturating arithmetic
/// keeps the workspace's `arithmetic_side_effects` lint happy.
fn fraction(slot: MetaSlot, x: u32, y: u32) -> SystemTime {
    let duration = slot.duration();
    let mul = duration.saturating_mul(x);
    let offset_nanos = mul.as_nanos().checked_div(u128::from(y)).unwrap_or(0);
    let secs = u64::try_from(offset_nanos.checked_div(1_000_000_000).unwrap_or(0)).unwrap_or(0);
    let sub_nanos =
        u32::try_from(offset_nanos.checked_rem(1_000_000_000).unwrap_or(0)).unwrap_or(0);
    let offset = Duration::new(secs, sub_nanos);
    slot.start_time()
        .checked_add(offset)
        .unwrap_or(slot.start_time())
}

/// Returns the duties that should fire in `slot`. Mirrors Go's
/// `dutiesForSlot`: scans a small forward window and keeps the duties whose
/// computed start time falls inside `slot`.
fn duties_for_slot(slot: MetaSlot, duty_types: &[DutyType]) -> Vec<ScheduleTuple> {
    let mut resp: Vec<ScheduleTuple> = Vec::new();
    let mut seen: std::collections::HashSet<(DutyType, u64, SystemTime)> =
        std::collections::HashSet::new();

    for duty_type in duty_types {
        for check_slot in slot.epoch().slots_for_look_ahead(EPOCH_WINDOW) {
            for start_time in duty_start_times(duty_type.clone(), check_slot) {
                if !slot.in_slot(start_time) {
                    continue;
                }
                let key = (duty_type.clone(), check_slot.slot, start_time);
                if seen.insert(key) {
                    resp.push(ScheduleTuple {
                        duty_type: duty_type.clone(),
                        slot: check_slot.slot,
                        start_time,
                    });
                }
            }
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BeaconMock, ValidatorSet, validatormock::Signer};
    use std::time::{Duration, SystemTime};

    fn meta_at(genesis: SystemTime) -> SpecMeta {
        SpecMeta {
            genesis_time: genesis,
            slot_duration: Duration::from_secs(12),
            slots_per_epoch: 16,
        }
    }

    #[tokio::test]
    async fn fraction_returns_partial_slot_offsets() {
        let slot = MetaSlot {
            slot: 0,
            meta: meta_at(SystemTime::UNIX_EPOCH),
        };
        assert_eq!(
            fraction(slot, 1, 3),
            slot.start_time() + Duration::from_secs(4)
        );
        assert_eq!(
            fraction(slot, 2, 3),
            slot.start_time() + Duration::from_secs(8)
        );
    }

    #[tokio::test]
    async fn duties_for_slot_includes_attest_at_third_slot() {
        let slot = MetaSlot {
            slot: 0,
            meta: meta_at(SystemTime::UNIX_EPOCH),
        };
        let duties = duties_for_slot(slot, all_duty_types());
        assert!(
            duties.iter().any(|d| d.duty_type == DutyType::Attester
                && d.start_time == slot.start_time() + Duration::from_secs(4)),
            "missing attester duty: {duties:?}"
        );
        assert!(
            duties
                .iter()
                .any(|d| d.duty_type == DutyType::Proposer && d.start_time == slot.start_time()),
            "missing proposer duty: {duties:?}"
        );
    }

    #[tokio::test]
    async fn slot_ticked_swallows_first_two_slots() {
        use serde_json::json;
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path_regex},
        };

        let genesis = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mock = BeaconMock::builder()
            .validator_set(ValidatorSet::validator_set_a())
            .no_proposer_duties(true)
            .no_attester_duties(true)
            .no_sync_committee_duties(true)
            .build()
            .await
            .expect("build mock");

        // BeaconMock does not mount a default for the validators endpoint;
        // synccomm's prepare_epoch reaches for it. Return an empty active set
        // so duties resolve to no-ops without exercising signing paths.
        Mock::given(method("POST"))
            .and(path_regex(r"^/eth/v1/beacon/states/[^/]+/validators$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "execution_optimistic": false,
                "finalized": true,
                "data": []
            })))
            .with_priority(2)
            .mount(mock.server())
            .await;

        let component = Component::builder()
            .eth2_cl(mock.client().clone())
            .sign_func(Signer::arc(&[]).expect("empty signer"))
            .pubkeys(Vec::new())
            .meta(meta_at(genesis))
            .builder_api(false)
            .build();

        // First two ticks must be no-ops (delay window).
        component.slot_ticked(0).await.expect("tick 0");
        component.slot_ticked(1).await.expect("tick 1");
        {
            let state = component.inner.state.lock().await;
            assert!(state.attesters_by_slot.is_empty());
            assert!(state.sync_comms_by_epoch.is_empty());
        }

        // Third tick starts the window: attesters for current+next epoch get
        // installed (`EPOCH_WINDOW = 2`).
        component.slot_ticked(2).await.expect("tick 2");
        {
            let state = component.inner.state.lock().await;
            // 2 epochs * 16 slots/epoch = 32 attesters in the window.
            assert_eq!(state.attesters_by_slot.len(), 32);
            assert_eq!(state.sync_comms_by_epoch.len(), 2);
        }
        component.shutdown().await;
    }

    /// Regression: when a duty body blocks on a never-closed readiness signal
    /// (e.g. an earlier `prepare()` errored out before closing `duties_ok`),
    /// `shutdown()` must still terminate. Without the inner cancel-race in
    /// `run_scheduler`, the `JoinSet` drain loop would wait forever.
    #[tokio::test]
    async fn shutdown_terminates_when_duty_blocked_on_close_once() {
        use serde_json::json;
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path_regex},
        };

        use crate::validatormock::clock::FakeClock;

        let genesis = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mock = BeaconMock::builder()
            .validator_set(ValidatorSet::validator_set_a())
            .no_proposer_duties(true)
            .no_attester_duties(true)
            .no_sync_committee_duties(true)
            .build()
            .await
            .expect("build mock");

        // Mount an empty validators set so synccomm's `prepare_epoch` succeeds
        // (otherwise `slot_ticked(2)` errors out before any duty is scheduled).
        Mock::given(method("POST"))
            .and(path_regex(r"^/eth/v1/beacon/states/[^/]+/validators$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "execution_optimistic": false,
                "finalized": true,
                "data": []
            })))
            .with_priority(2)
            .mount(mock.server())
            .await;

        let clock = FakeClock::new(genesis);
        let meta = meta_at(genesis);
        let component = Component::builder()
            .eth2_cl(mock.client().clone())
            .sign_func(Signer::arc(&[]).expect("empty signer"))
            .pubkeys(Vec::new())
            .meta(meta)
            .builder_api(false)
            .clock(Arc::new(clock.clone()) as Arc<dyn Clock>)
            .build();

        // Bypass the two-slot startup delay.
        component.slot_ticked(0).await.expect("tick 0");
        component.slot_ticked(1).await.expect("tick 1");

        // Tick a non-epoch-boundary slot. `PrepareAggregator` only fires on
        // epoch starts, so `Attester` here will see a never-closed
        // `duties_ok` and `attest()` will park on `CloseOnce::wait` forever.
        component.slot_ticked(2).await.expect("tick 2");

        // Advance virtual time past the attester offset (1/3 of slot = 4s)
        // so the duty body actually starts running and blocks on
        // `duties_ok.wait()`.
        let slot2 = MetaSlot { slot: 2, meta };
        clock.advance_to(slot2.start_time() + Duration::from_secs(5));

        // Give the scheduler a chance to spawn the duty body and park it.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        // Without the cancel-race fix this hangs forever.
        tokio::time::timeout(Duration::from_secs(2), component.shutdown())
            .await
            .expect("shutdown must terminate even when duty body is parked on CloseOnce");
    }
}
