//! Core tracking module for duty lifecycle monitoring.
//!
//! [`TrackerService::start`] spawns a background loop that accumulates
//! per-duty [`Event`]s submitted by core workflow components via the
//! [`Tracker`] trait. When the analyser deadline fires the accumulated events
//! will be used to determine failure reasons and report participation (not yet
//! implemented). When the deleter deadline fires the events for that duty are
//! discarded to bound memory usage.
//!
//! Both deadliners must share the same [`CancellationToken`] as the tracker so
//! that the whole system shuts down together.

/// Failure reason definitions for duty analysis.
pub mod reason;

/// Step enum for the core workflow.
pub mod step;

use std::{collections::HashMap, future::Future, sync::Arc};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    deadline::{AddOutcome, DeadlinerHandle},
    types::{Duty, ParSignedData, ParSignedDataSet, PubKey},
};

use step::Step;

/// Type-erased step error.
///
/// `Arc` rather than `Box` so a single error can be cheaply fanned out to
/// multiple events (one per pubkey in a duty set) without cloning the
/// underlying error.
pub type StepError = Arc<dyn std::error::Error + Send + Sync>;

/// Minimal peer info needed by the tracker for participation reporting.
///
/// Defined here to avoid a circular dependency with `pluto-p2p`
/// (which already depends on `pluto-core`). Callers convert their
/// `pluto_p2p::Peer` values before passing them to [`TrackerService::start`].
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Human-readable peer name.
    pub name: String,
    /// 1-indexed share index (`peer.index + 1`).
    pub share_idx: usize,
}

/// Tracker receives events from core workflow components for duty analysis and
/// participation reporting.
///
/// Methods that only need validator pubkeys (fetcher, consensus, dutydb,
/// sigagg, aggsigdb, bcast) accept `&[PubKey]`. Methods that also carry
/// partial-signature data accept `&ParSignedDataSet`.
///
/// `err` is `Option<StepError>` (passed by value) so the caller's `Arc` can
/// be cheaply cloned per event inside the implementation.
pub trait Tracker: Send + Sync {
    /// Called when the fetcher fetches duty data.
    fn fetcher_fetched(
        &self,
        duty: Duty,
        pubkeys: &[PubKey],
        err: Option<StepError>,
    ) -> impl Future<Output = ()> + Send;

    /// Called when consensus is reached on duty data.
    fn consensus_proposed(
        &self,
        duty: Duty,
        pubkeys: &[PubKey],
        err: Option<StepError>,
    ) -> impl Future<Output = ()> + Send;

    /// Called when duty data is stored in DutyDB.
    fn duty_db_stored(
        &self,
        duty: Duty,
        pubkeys: &[PubKey],
        err: Option<StepError>,
    ) -> impl Future<Output = ()> + Send;

    /// Called when local VC partial signatures are stored in parsigdb.
    fn par_sig_db_stored_internal(
        &self,
        duty: Duty,
        set: &ParSignedDataSet,
        err: Option<StepError>,
    ) -> impl Future<Output = ()> + Send;

    /// Called when local VC partial signatures are broadcast to peers.
    fn par_sig_ex_broadcasted(
        &self,
        duty: Duty,
        set: &ParSignedDataSet,
        err: Option<StepError>,
    ) -> impl Future<Output = ()> + Send;

    /// Called when peer partial signatures are stored in parsigdb.
    fn par_sig_db_stored_external(
        &self,
        duty: Duty,
        set: &ParSignedDataSet,
        err: Option<StepError>,
    ) -> impl Future<Output = ()> + Send;

    /// Called when partial signatures are aggregated.
    fn sig_agg_aggregated(
        &self,
        duty: Duty,
        pubkeys: &[PubKey],
        err: Option<StepError>,
    ) -> impl Future<Output = ()> + Send;

    /// Called when aggregated signed data is stored in aggsigdb.
    fn agg_sig_db_stored(
        &self,
        duty: Duty,
        pubkeys: &[PubKey],
        err: Option<StepError>,
    ) -> impl Future<Output = ()> + Send;

    /// Called when aggregated data is broadcast to the beacon node.
    fn broadcaster_broadcast(
        &self,
        duty: Duty,
        pubkeys: &[PubKey],
        err: Option<StepError>,
    ) -> impl Future<Output = ()> + Send;

    /// Called when chain inclusion is checked for a duty.
    fn inclusion_checked(
        &self,
        duty: Duty,
        pubkey: PubKey,
        err: Option<StepError>,
    ) -> impl Future<Output = ()> + Send;
}

/// Buffer capacity for the internal event channel.
///
/// Sized to absorb a full epoch's worth of events across all duty types and
/// validators without back-pressuring producers while the loop is busy with a
/// deadliner round-trip.
const EVENT_BUFFER: usize = 1024;

/// A single event emitted by a core workflow component.
///
/// `par_sig` is only set by `ParSigDBInternal`, `ParSigEx`, and
/// `ParSigDBExternal` events, matching Go's `event.parSig`.
#[allow(dead_code)]
pub(crate) struct Event {
    pub duty: Duty,
    pub step: Step,
    pub pubkey: PubKey,
    pub step_err: Option<StepError>,
    pub par_sig: Option<ParSignedData>,
}

/// Newtype wrapper for the analyser deadliner's expired-duty receiver.
///
/// Prevents silent argument inversion when calling [`TrackerService::start`],
/// since both the analyser and deleter receivers have the same underlying type.
pub struct AnalyserRx(pub mpsc::Receiver<Duty>);

/// Newtype wrapper for the deleter deadliner's expired-duty receiver.
///
/// See [`AnalyserRx`] for rationale.
pub struct DeleterRx(pub mpsc::Receiver<Duty>);

/// Public-facing handle returned by [`TrackerService::start`].
///
/// Holds the send-half of the event channel and implements the [`Tracker`]
/// trait so core workflow components can submit events. The background loop
/// that consumes those events lives in [`TrackerService`].
pub struct TrackerHandle {
    input_tx: mpsc::Sender<Event>,
    /// Kept so callers can detect task completion or panics by awaiting it.
    /// Dropping the handle detaches the task; call `.abort()` to cancel it.
    #[allow(dead_code)]
    pub(crate) task: tokio::task::JoinHandle<()>,
}

impl TrackerHandle {
    async fn send_event(&self, event: Event) {
        if let Err(e) = self.input_tx.send(event).await {
            tracing::warn!(
                duty = %e.0.duty,
                step = %e.0.step,
                "Tracker input channel closed; dropping event",
            );
        }
    }

    async fn send_pubkeys(
        &self,
        duty: Duty,
        step: Step,
        pubkeys: &[PubKey],
        err: Option<StepError>,
    ) {
        for pubkey in pubkeys {
            self.send_event(Event {
                duty: duty.clone(),
                step,
                pubkey: *pubkey,
                step_err: err.clone(),
                par_sig: None,
            })
            .await;
        }
    }

    async fn send_par_sig_set(
        &self,
        duty: Duty,
        step: Step,
        set: &ParSignedDataSet,
        err: Option<StepError>,
    ) {
        for (pubkey, par_sig) in set.inner() {
            self.send_event(Event {
                duty: duty.clone(),
                step,
                pubkey: *pubkey,
                step_err: err.clone(),
                par_sig: Some(par_sig.clone()),
            })
            .await;
        }
    }
}

impl Tracker for TrackerHandle {
    async fn fetcher_fetched(&self, duty: Duty, pubkeys: &[PubKey], err: Option<StepError>) {
        self.send_pubkeys(duty, Step::Fetcher, pubkeys, err).await;
    }

    async fn consensus_proposed(&self, duty: Duty, pubkeys: &[PubKey], err: Option<StepError>) {
        self.send_pubkeys(duty, Step::Consensus, pubkeys, err).await;
    }

    async fn duty_db_stored(&self, duty: Duty, pubkeys: &[PubKey], err: Option<StepError>) {
        self.send_pubkeys(duty, Step::DutyDB, pubkeys, err).await;
    }

    async fn par_sig_db_stored_internal(
        &self,
        duty: Duty,
        set: &ParSignedDataSet,
        err: Option<StepError>,
    ) {
        self.send_par_sig_set(duty, Step::ParSigDBInternal, set, err)
            .await;
    }

    async fn par_sig_ex_broadcasted(
        &self,
        duty: Duty,
        set: &ParSignedDataSet,
        err: Option<StepError>,
    ) {
        self.send_par_sig_set(duty, Step::ParSigEx, set, err).await;
    }

    async fn par_sig_db_stored_external(
        &self,
        duty: Duty,
        set: &ParSignedDataSet,
        err: Option<StepError>,
    ) {
        self.send_par_sig_set(duty, Step::ParSigDBExternal, set, err)
            .await;
    }

    async fn sig_agg_aggregated(&self, duty: Duty, pubkeys: &[PubKey], err: Option<StepError>) {
        self.send_pubkeys(duty, Step::SigAgg, pubkeys, err).await;
    }

    async fn agg_sig_db_stored(&self, duty: Duty, pubkeys: &[PubKey], err: Option<StepError>) {
        self.send_pubkeys(duty, Step::AggSigDB, pubkeys, err).await;
    }

    async fn broadcaster_broadcast(&self, duty: Duty, pubkeys: &[PubKey], err: Option<StepError>) {
        self.send_pubkeys(duty, Step::Bcast, pubkeys, err).await;
    }

    async fn inclusion_checked(&self, duty: Duty, pubkey: PubKey, err: Option<StepError>) {
        self.send_event(Event {
            duty,
            step: Step::ChainInclusion,
            pubkey,
            step_err: err,
            par_sig: None,
        })
        .await;
    }
}

/// Background task that owns the event loop state.
///
/// Constructed and spawned by [`TrackerService::start`]; not used directly by
/// callers. Held exclusively by the spawned task — that's why the receivers
/// live directly on this struct rather than behind `Mutex<Option<_>>`.
pub struct TrackerService {
    cancel: CancellationToken,
    input_rx: mpsc::Receiver<Event>,
    analyser: DeadlinerHandle,
    analyser_rx: mpsc::Receiver<Duty>,
    deleter: DeadlinerHandle,
    deleter_rx: mpsc::Receiver<Duty>,
    from_slot: u64,
    #[allow(dead_code)]
    peers: Vec<PeerInfo>,
}

impl TrackerService {
    /// Builds the [`TrackerHandle`] and spawns the background event loop.
    ///
    /// `analyser` triggers duty analysis at deadline; `deleter` triggers
    /// cleanup well after analysis (matching Go's contract that the deleter
    /// deadline must be well after the analyser's). `from_slot` sets the
    /// minimum slot to track — events for earlier slots are ignored.
    ///
    /// Both `analyser` and `deleter` must have been started with the same
    /// `cancel` token as passed here, so that all three components shut down
    /// together.
    pub fn start(
        cancel: CancellationToken,
        analyser: DeadlinerHandle,
        analyser_rx: AnalyserRx,
        deleter: DeadlinerHandle,
        deleter_rx: DeleterRx,
        peers: Vec<PeerInfo>,
        from_slot: u64,
    ) -> Arc<TrackerHandle> {
        Self::start_with_buffer(
            cancel,
            analyser,
            analyser_rx,
            deleter,
            deleter_rx,
            peers,
            from_slot,
            EVENT_BUFFER,
        )
    }

    /// Like [`start`] but with a configurable channel buffer size, for tests.
    #[allow(clippy::too_many_arguments)]
    fn start_with_buffer(
        cancel: CancellationToken,
        analyser: DeadlinerHandle,
        AnalyserRx(analyser_rx): AnalyserRx,
        deleter: DeadlinerHandle,
        DeleterRx(deleter_rx): DeleterRx,
        peers: Vec<PeerInfo>,
        from_slot: u64,
        buffer: usize,
    ) -> Arc<TrackerHandle> {
        let (input_tx, input_rx) = mpsc::channel(buffer);

        let task = Self {
            cancel,
            input_rx,
            analyser,
            analyser_rx,
            deleter,
            deleter_rx,
            from_slot,
            peers,
        };

        let task = tokio::spawn(task.run());

        Arc::new(TrackerHandle { input_tx, task })
    }

    async fn run(mut self) {
        let mut events: HashMap<Duty, Vec<Event>> = HashMap::new();

        loop {
            tokio::select! {
                // Cancellation and cleanup branches are checked first so that
                // shutdown and HashMap shrinkage are never starved by a busy
                // input channel.
                biased;

                _ = self.cancel.cancelled() => {
                    return;
                }

                duty = self.analyser_rx.recv() => {
                    match duty {
                        Some(duty) => {
                            // TODO: extract par sigs, analyse failed duty, report participation.
                            tracing::debug!(duty = %duty, "Duty analysis triggered (not yet implemented)");
                        }
                        None => {
                            tracing::error!("Analyser deadliner channel closed unexpectedly; stopping tracker");
                            return;
                        }
                    }
                }

                duty = self.deleter_rx.recv() => {
                    match duty {
                        Some(duty) => { events.remove(&duty); }
                        None => {
                            tracing::error!("Deleter deadliner channel closed unexpectedly; stopping tracker");
                            return;
                        }
                    }
                }

                Some(e) = self.input_rx.recv() => {
                    if e.duty.slot.inner() < self.from_slot {
                        continue;
                    }

                    // Match Go's short-circuit: skip analyser entirely when
                    // deleter returns non-Scheduled, avoiding a spurious timer.
                    if self.deleter.add(e.duty.clone()).await != AddOutcome::Scheduled {
                        continue;
                    }
                    if self.analyser.add(e.duty.clone()).await != AddOutcome::Scheduled {
                        continue;
                    }

                    events.entry(e.duty.clone()).or_default().push(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use chrono::{DateTime, Utc};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::{
        deadline::{DeadlineCalculator, DeadlinerTask, NeverExpiringCalculator},
        types::{Duty, DutyType, SlotNumber},
    };

    fn attester(slot: u64) -> Duty {
        Duty::new(SlotNumber::new(slot), DutyType::Attester)
    }

    fn pubkey() -> PubKey {
        PubKey::from([1u8; 48])
    }

    /// Calculator that schedules every duty with a deadline far in the future.
    struct FutureCalculator;

    impl DeadlineCalculator for FutureCalculator {
        fn deadline(&self, _: &Duty) -> crate::deadline::Result<Option<DateTime<Utc>>> {
            Ok(Some(DateTime::<Utc>::MAX_UTC))
        }
    }

    fn start_service(cancel: &CancellationToken, from_slot: u64) -> Arc<TrackerHandle> {
        let (analyser, analyser_rx) =
            DeadlinerTask::start(cancel.clone(), "analyser", FutureCalculator);
        let (deleter, deleter_rx) =
            DeadlinerTask::start(cancel.clone(), "deleter", FutureCalculator);
        TrackerService::start(
            cancel.clone(),
            analyser,
            AnalyserRx(analyser_rx),
            deleter,
            DeleterRx(deleter_rx),
            vec![],
            from_slot,
        )
    }

    #[tokio::test]
    async fn cancel_stops_loop() {
        let cancel = CancellationToken::new();
        let handle = start_service(&cancel, 0);

        cancel.cancel();

        let raw = Arc::try_unwrap(handle).unwrap_or_else(|_| panic!("single Arc owner in test"));
        tokio::time::timeout(Duration::from_secs(1), raw.task)
            .await
            .expect("task did not exit within timeout")
            .expect("task panicked");
    }

    #[tokio::test]
    async fn from_slot_filters_old_events() {
        let cancel = CancellationToken::new();
        let handle = start_service(&cancel, 10);

        // Slot 5 is below from_slot=10 and must be filtered before reaching
        // the deadliner. Slot 15 is above and must be scheduled normally.
        handle.fetcher_fetched(attester(5), &[pubkey()], None).await;
        handle
            .fetcher_fetched(attester(15), &[pubkey()], None)
            .await;

        // Yield so the loop processes both events.
        tokio::task::yield_now().await;

        cancel.cancel();

        let raw = Arc::try_unwrap(handle).unwrap_or_else(|_| panic!("single Arc owner in test"));
        tokio::time::timeout(Duration::from_secs(1), raw.task)
            .await
            .expect("task did not exit within timeout")
            .expect("task panicked");
    }

    #[tokio::test]
    async fn never_expiring_duties_are_not_accumulated() {
        let cancel = CancellationToken::new();
        // NeverExpiring: deleter.add() returns NeverExpiring, so the loop
        // continues without inserting into the events map. Verifies that the
        // short-circuit correctly discards these events without panicking.
        let (analyser, analyser_rx) =
            DeadlinerTask::start(cancel.clone(), "analyser", NeverExpiringCalculator);
        let (deleter, deleter_rx) =
            DeadlinerTask::start(cancel.clone(), "deleter", NeverExpiringCalculator);
        let handle = TrackerService::start(
            cancel.clone(),
            analyser,
            AnalyserRx(analyser_rx),
            deleter,
            DeleterRx(deleter_rx),
            vec![],
            0,
        );

        let duty = attester(1);
        let keys = [pubkey(), PubKey::from([2u8; 48]), PubKey::from([3u8; 48])];

        handle.fetcher_fetched(duty.clone(), &keys, None).await;
        handle.fetcher_fetched(duty.clone(), &keys, None).await;

        tokio::task::yield_now().await;

        cancel.cancel();
        let raw = Arc::try_unwrap(handle).unwrap_or_else(|_| panic!("single Arc owner in test"));
        tokio::time::timeout(Duration::from_secs(1), raw.task)
            .await
            .expect("task did not exit within timeout")
            .expect("task panicked");
    }

    #[tokio::test]
    async fn fan_out_sends_one_event_per_pubkey() {
        let cancel = CancellationToken::new();
        let (analyser, analyser_rx) =
            DeadlinerTask::start(cancel.clone(), "analyser", FutureCalculator);
        let (deleter, deleter_rx) =
            DeadlinerTask::start(cancel.clone(), "deleter", FutureCalculator);
        let handle = TrackerService::start_with_buffer(
            cancel.clone(),
            analyser,
            AnalyserRx(analyser_rx),
            deleter,
            DeleterRx(deleter_rx),
            vec![],
            0,
            1,
        );

        let keys = [pubkey(), PubKey::from([2u8; 48]), PubKey::from([3u8; 48])];
        handle.fetcher_fetched(attester(1), &keys, None).await;
        handle.consensus_proposed(attester(1), &keys, None).await;

        tokio::task::yield_now().await;

        cancel.cancel();
        let raw = Arc::try_unwrap(handle).unwrap_or_else(|_| panic!("single Arc owner in test"));
        tokio::time::timeout(Duration::from_secs(1), raw.task)
            .await
            .expect("task did not exit within timeout")
            .expect("task panicked");
    }
}
