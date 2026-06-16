//! Core tracking module for duty lifecycle monitoring.
//!
//! [`TrackerService::start`] spawns a background loop that accumulates
//! per-duty [`Event`]s submitted by core workflow components via the
//! [`Tracker`] trait. When the analyser deadline fires the accumulated events
//! are passed through [`analysis::analyse_duty_failed`] and
//! [`analysis::analyse_participation`], and the results are dispatched to the
//! reporters in [`reporters`] for metrics and structured logging. When the
//! deleter deadline fires the events for that duty are discarded to bound
//! memory usage.
//!
//! Both deadliners must share the same [`CancellationToken`] as the tracker so
//! that the whole system shuts down together.

/// Failure reason definitions for duty analysis.
pub mod reason;

/// Step enum for the core workflow.
pub mod step;

/// Pure analysis functions used by the tracker loop.
pub mod analysis;

/// Prometheus metrics for the tracker.
pub mod metrics;

/// Reporters that consume analysis results and emit metrics/logs.
pub mod reporters;

/// On-chain inclusion checking for broadcast duties.
pub mod inclusion;

use std::{collections::HashMap, future::Future, sync::Arc};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    deadline::{AddOutcome, DeadlinerHandle},
    types::{Duty, ParSignedData, ParSignedDataSet, PubKey},
};

use analysis::{
    DutyFailure, analyse_duty_failed, analyse_participation, duty_failed_step, extract_par_sigs,
    msg_roots_consistent,
};
use reason::REASON_UNKNOWN;
use reporters::{
    DutyResultReporter, MetricsDutyReporter, MetricsParticipationReporter, ParticipationReporter,
    UnsupportedIgnorer, report_par_sigs,
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
#[derive(Clone)]
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
        // Shutdown is signalled by the receiver being dropped, which causes
        // send() to return Err immediately — no explicit cancellation select needed.
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
    failed_duty_reporter: Box<dyn DutyResultReporter>,
    participation_reporter: Box<dyn ParticipationReporter>,
    unsupported_ignorer: UnsupportedIgnorer,
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
        Self::start_with_buffer_and_sinks(
            cancel,
            analyser,
            analyser_rx,
            deleter,
            deleter_rx,
            from_slot,
            EVENT_BUFFER,
            Box::new(MetricsDutyReporter::new()),
            Box::new(MetricsParticipationReporter::new(peers)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_with_buffer_and_sinks(
        cancel: CancellationToken,
        analyser: DeadlinerHandle,
        AnalyserRx(analyser_rx): AnalyserRx,
        deleter: DeadlinerHandle,
        DeleterRx(deleter_rx): DeleterRx,
        from_slot: u64,
        buffer: usize,
        failed_duty_reporter: Box<dyn DutyResultReporter>,
        participation_reporter: Box<dyn ParticipationReporter>,
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
            failed_duty_reporter,
            participation_reporter,
            unsupported_ignorer: UnsupportedIgnorer::new(),
        };

        let task = tokio::spawn(task.run());

        Arc::new(TrackerHandle { input_tx, task })
    }

    fn analyse(&mut self, duty: &Duty, events: &std::collections::HashMap<Duty, Vec<Event>>) {
        let duty_events = events.get(duty).map(Vec::as_slice).unwrap_or(&[]);
        let parsigs = extract_par_sigs(duty_events);
        report_par_sigs(duty, &parsigs);

        let failed_step = duty_failed_step(duty_events);
        let outcome =
            analyse_duty_failed(duty, events, &failed_step, msg_roots_consistent(&parsigs));

        if self.unsupported_ignorer.check(duty, outcome.as_ref()) {
            return;
        }

        let failed = outcome.is_some();
        // On success the reporter only reads `step`: `Fetcher` for
        // aggregator/sync-contribution slots with no selection (a no-op the
        // reporter must skip, not count) versus `Zero` for a genuine success.
        let result = outcome.unwrap_or(DutyFailure {
            step: failed_step.step,
            reason: REASON_UNKNOWN,
            err: None,
        });

        self.failed_duty_reporter.report(duty, failed, &result);

        let part = analyse_participation(duty, events);
        self.participation_reporter.report(
            duty,
            failed,
            &part.participated,
            &part.unexpected,
            part.validators_per_duty,
        );
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
                            self.analyse(&duty, &events);
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
    use std::{collections::HashMap, sync::Mutex, time::Duration};

    use chrono::{DateTime, Utc};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::{
        deadline::{DeadlineCalculator, DeadlinerTask, NeverExpiringCalculator},
        signeddata::SignedDataError,
        tracker::{
            reason::Reason,
            reporters::{DutyResultReporter, ParticipationReporter},
        },
        types::{Duty, DutyType, ParSignedData, ParSignedDataSet, SlotNumber},
    };

    // ── Integration test infrastructure ─────────────────────────────────────

    #[derive(Debug, Clone)]
    struct FailRecord {
        duty: Duty,
        failed: bool,
        step: Step,
        reason: Reason,
    }

    #[derive(Debug, Clone)]
    struct ParticipationRecord {
        duty: Duty,
        failed: bool,
        participated: HashMap<u64, usize>,
        unexpected: HashMap<u64, usize>,
        expected_per_peer: usize,
    }

    struct RecordingFailureReporter {
        records: std::sync::Arc<Mutex<Vec<FailRecord>>>,
        cancel: CancellationToken,
        trigger_on: usize,
    }

    impl DutyResultReporter for RecordingFailureReporter {
        fn report(&mut self, duty: &Duty, failed: bool, result: &DutyFailure) {
            let mut recs = self.records.lock().unwrap();
            recs.push(FailRecord {
                duty: duty.clone(),
                failed,
                step: result.step,
                reason: result.reason,
            });
            if recs.len() >= self.trigger_on {
                self.cancel.cancel();
            }
        }
    }

    struct RecordingParticipationReporter {
        records: std::sync::Arc<Mutex<Vec<ParticipationRecord>>>,
        cancel: CancellationToken,
        trigger_on: usize,
    }

    impl ParticipationReporter for RecordingParticipationReporter {
        fn report(
            &mut self,
            duty: &Duty,
            failed: bool,
            participated: &HashMap<u64, usize>,
            unexpected: &HashMap<u64, usize>,
            expected_per_peer: usize,
        ) {
            let mut recs = self.records.lock().unwrap();
            recs.push(ParticipationRecord {
                duty: duty.clone(),
                failed,
                participated: participated.clone(),
                unexpected: unexpected.clone(),
                expected_per_peer,
            });
            if recs.len() >= self.trigger_on {
                self.cancel.cancel();
            }
        }
    }

    struct NopFailureReporter;

    impl DutyResultReporter for NopFailureReporter {
        fn report(&mut self, _: &Duty, _: bool, _: &DutyFailure) {}
    }

    struct NopParticipationReporter;

    impl ParticipationReporter for NopParticipationReporter {
        fn report(
            &mut self,
            _: &Duty,
            _: bool,
            _: &HashMap<u64, usize>,
            _: &HashMap<u64, usize>,
            _: usize,
        ) {
        }
    }

    /// Starts a `TrackerService` with custom reporters and test-controlled
    /// analyser/deleter trigger channels (bypassing the real deadliner).
    fn start_test_tracker(
        cancel: &CancellationToken,
        from_slot: u64,
        failure_sink: Box<dyn reporters::DutyResultReporter>,
        participation_sink: Box<dyn reporters::ParticipationReporter>,
    ) -> (Arc<TrackerHandle>, mpsc::Sender<Duty>, mpsc::Sender<Duty>) {
        let (analyser_handle, _) =
            DeadlinerTask::start(cancel.clone(), "analyser", FutureCalculator);
        let (deleter_handle, _) = DeadlinerTask::start(cancel.clone(), "deleter", FutureCalculator);
        let (analyser_tx, analyser_rx) = mpsc::channel(16);
        let (deleter_tx, deleter_rx) = mpsc::channel(16);

        let handle = TrackerService::start_with_buffer_and_sinks(
            cancel.clone(),
            analyser_handle,
            AnalyserRx(analyser_rx),
            deleter_handle,
            DeleterRx(deleter_rx),
            from_slot,
            EVENT_BUFFER,
            failure_sink,
            participation_sink,
        );

        (handle, analyser_tx, deleter_tx)
    }

    async fn wait_for_task(handle: Arc<TrackerHandle>) {
        let raw = Arc::try_unwrap(handle).unwrap_or_else(|_| panic!("single Arc owner in test"));
        tokio::time::timeout(Duration::from_secs(1), raw.task)
            .await
            .expect("task did not exit within timeout")
            .expect("task panicked");
    }

    /// Minimal [`crate::types::SignedData`] for constructing [`ParSignedData`]
    /// in tests without needing real ETH2 attestation data.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SimpleSignedData;

    impl crate::types::SignedData for SimpleSignedData {
        fn signature(&self) -> Result<pluto_crypto::types::Signature, SignedDataError> {
            Ok([0u8; 96])
        }

        fn set_signature(
            &self,
            _sig: pluto_crypto::types::Signature,
        ) -> Result<Self, SignedDataError> {
            Ok(Self)
        }

        fn set_signature_boxed(
            &self,
            sig: pluto_crypto::types::Signature,
        ) -> Result<Box<dyn crate::types::SignedData>, SignedDataError> {
            Ok(Box::new(self.set_signature(sig)?))
        }

        fn message_root(&self) -> Result<[u8; 32], SignedDataError> {
            Ok([0u8; 32])
        }
    }

    fn par_sig_set(pubkeys: &[PubKey], share_idx: u64) -> ParSignedDataSet {
        let mut set = ParSignedDataSet::new();
        for pk in pubkeys {
            set.insert(*pk, ParSignedData::new(SimpleSignedData, share_idx));
        }
        set
    }

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

        let fail_records: std::sync::Arc<Mutex<Vec<FailRecord>>> = Default::default();

        // from_slot=10: slot-5 events must be discarded, slot-15 events kept.
        let (handle, analyser_tx, deleter_tx) = start_test_tracker(
            &cancel,
            10,
            Box::new(RecordingFailureReporter {
                records: fail_records.clone(),
                cancel: cancel.clone(),
                trigger_on: 2,
            }),
            Box::new(NopParticipationReporter),
        );

        handle.fetcher_fetched(attester(5), &[pubkey()], None).await;
        handle
            .fetcher_fetched(attester(15), &[pubkey()], None)
            .await;
        tokio::task::yield_now().await;

        // Trigger analysis for both; only slot-15 had events stored.
        analyser_tx.send(attester(5)).await.unwrap();
        analyser_tx.send(attester(15)).await.unwrap();
        tokio::task::yield_now().await;
        let _ = deleter_tx.send(attester(5)).await;
        let _ = deleter_tx.send(attester(15)).await;

        wait_for_task(handle).await;

        let recs = fail_records.lock().unwrap();
        assert_eq!(recs.len(), 2);

        let slot5 = recs.iter().find(|r| r.duty == attester(5)).unwrap();
        assert!(slot5.failed);
        // No events stored for slot 5 (filtered): analysis sees an empty map.
        assert_eq!(
            slot5.step,
            Step::Zero,
            "slot-5 was filtered: no events in map"
        );

        let slot15 = recs.iter().find(|r| r.duty == attester(15)).unwrap();
        assert!(slot15.failed);
        // Slot-15 fetcher event was stored and analysed (fails at fetcher, no
        // completion).
        assert_eq!(slot15.step, Step::Fetcher, "slot-15 events were accepted");
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

    // ── Integration tests ────────────────────────────────────────────────────

    /// Sends a fetcher event and a consensus event with an error, triggers the
    /// analyser, and verifies the failure is reported at the consensus step.
    #[tokio::test]
    async fn tracker_failed_duty_fail_at_consensus() {
        use crate::tracker::reason::REASON_NO_CONSENSUS;

        let cancel = CancellationToken::new();
        let duty = attester(1);
        let keys = [pubkey(), PubKey::from([2u8; 48]), PubKey::from([3u8; 48])];

        let fail_records: std::sync::Arc<Mutex<Vec<FailRecord>>> = Default::default();
        let part_records: std::sync::Arc<Mutex<Vec<ParticipationRecord>>> = Default::default();

        let (handle, analyser_tx, deleter_tx) = start_test_tracker(
            &cancel,
            0,
            Box::new(RecordingFailureReporter {
                records: fail_records.clone(),
                cancel: cancel.clone(),
                trigger_on: 1,
            }),
            Box::new(RecordingParticipationReporter {
                records: part_records.clone(),
                cancel: cancel.clone(),
                trigger_on: usize::MAX,
            }),
        );

        let consensus_err: StepError =
            std::sync::Arc::new(std::io::Error::other("consensus error"));
        handle.fetcher_fetched(duty.clone(), &keys, None).await;
        handle
            .consensus_proposed(duty.clone(), &keys, Some(consensus_err))
            .await;
        tokio::task::yield_now().await;

        analyser_tx.send(duty.clone()).await.unwrap();
        tokio::task::yield_now().await;
        // Cancel fires inside the sink; deleter send may race — ignore errors.
        let _ = deleter_tx.send(duty.clone()).await;

        wait_for_task(handle).await;

        let recs = fail_records.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].duty, duty);
        assert!(recs[0].failed);
        assert_eq!(recs[0].step, Step::Consensus);
        assert_eq!(recs[0].reason, REASON_NO_CONSENSUS);

        let part = part_records.lock().unwrap();
        assert_eq!(part.len(), 1);
        assert!(part[0].failed);
    }

    /// Sends a broadcast (Bcast) event with no error — the terminal step for
    /// an Attester duty — and verifies the duty is reported as successful.
    #[tokio::test]
    async fn tracker_failed_duty_success() {
        let cancel = CancellationToken::new();
        let duty = attester(1);
        let keys = [pubkey(), PubKey::from([2u8; 48]), PubKey::from([3u8; 48])];

        let fail_records: std::sync::Arc<Mutex<Vec<FailRecord>>> = Default::default();
        let part_records: std::sync::Arc<Mutex<Vec<ParticipationRecord>>> = Default::default();

        let (handle, analyser_tx, deleter_tx) = start_test_tracker(
            &cancel,
            0,
            Box::new(RecordingFailureReporter {
                records: fail_records.clone(),
                cancel: cancel.clone(),
                trigger_on: 1,
            }),
            Box::new(RecordingParticipationReporter {
                records: part_records.clone(),
                cancel: cancel.clone(),
                trigger_on: usize::MAX,
            }),
        );

        handle
            .broadcaster_broadcast(duty.clone(), &keys, None)
            .await;
        tokio::task::yield_now().await;

        analyser_tx.send(duty.clone()).await.unwrap();
        tokio::task::yield_now().await;
        let _ = deleter_tx.send(duty.clone()).await;

        wait_for_task(handle).await;

        let recs = fail_records.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].duty, duty);
        assert!(!recs[0].failed);
        assert_eq!(recs[0].step, Step::Zero);

        let part = part_records.lock().unwrap();
        assert_eq!(part.len(), 1);
        assert!(!part[0].failed);
    }

    /// A partial-signature event arrives for a peer whose share index has no
    /// corresponding fetcher event, so it is counted as unexpected rather than
    /// participated.
    #[tokio::test]
    async fn unexpected_participation() {
        const UNEXPECTED_PEER: u64 = 2;
        let cancel = CancellationToken::new();
        let duty = attester(123);
        let pk = pubkey();

        let part_records: std::sync::Arc<Mutex<Vec<ParticipationRecord>>> = Default::default();

        let (handle, analyser_tx, deleter_tx) = start_test_tracker(
            &cancel,
            0,
            Box::new(NopFailureReporter),
            Box::new(RecordingParticipationReporter {
                records: part_records.clone(),
                cancel: cancel.clone(),
                trigger_on: 1,
            }),
        );

        handle
            .par_sig_db_stored_external(duty.clone(), &par_sig_set(&[pk], UNEXPECTED_PEER), None)
            .await;
        tokio::task::yield_now().await;

        analyser_tx.send(duty.clone()).await.unwrap();
        tokio::task::yield_now().await;
        let _ = deleter_tx.send(duty.clone()).await;

        wait_for_task(handle).await;

        let recs = part_records.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].duty, duty);
        assert!(recs[0].failed);
        assert_eq!(recs[0].participated, HashMap::new());
        assert_eq!(recs[0].unexpected, HashMap::from([(UNEXPECTED_PEER, 1)]));
    }

    /// When Proposer events are deleted before Randao is analysed, the Randao
    /// partial signature cannot be cross-referenced to a scheduled Proposer
    /// duty and must be counted as unexpected.
    #[tokio::test]
    async fn duty_randao_unexpected() {
        const VALID_PEER: u64 = 1;
        let cancel = CancellationToken::new();
        let slot = SlotNumber::new(123);
        let duty_proposer = Duty::new_proposer_duty(slot);
        let duty_randao = Duty::new_randao_duty(slot);
        let pk = pubkey();

        let part_records: std::sync::Arc<Mutex<Vec<ParticipationRecord>>> = Default::default();

        let (handle, analyser_tx, deleter_tx) = start_test_tracker(
            &cancel,
            0,
            Box::new(NopFailureReporter),
            Box::new(RecordingParticipationReporter {
                records: part_records.clone(),
                cancel: cancel.clone(),
                trigger_on: 2,
            }),
        );

        let fetch_err: StepError =
            std::sync::Arc::new(std::io::Error::other("failed to query randao"));
        handle
            .fetcher_fetched(duty_proposer.clone(), &[pk], Some(fetch_err))
            .await;
        handle
            .par_sig_db_stored_external(duty_randao.clone(), &par_sig_set(&[pk], VALID_PEER), None)
            .await;
        tokio::task::yield_now().await;

        analyser_tx.send(duty_proposer.clone()).await.unwrap();
        tokio::task::yield_now().await;
        deleter_tx.send(duty_proposer.clone()).await.unwrap();
        tokio::task::yield_now().await;
        // Cancel fires after both records are received; send may race.
        let _ = analyser_tx.send(duty_randao.clone()).await;

        wait_for_task(handle).await;

        let recs = part_records.lock().unwrap();
        let randao_rec = recs
            .iter()
            .find(|r| r.duty == duty_randao)
            .expect("randao record");
        assert!(randao_rec.failed);
        assert_eq!(randao_rec.participated, HashMap::new());
        assert_eq!(randao_rec.unexpected, HashMap::from([(VALID_PEER, 1)]));
    }

    /// When Proposer events are still present when Randao is analysed, the
    /// Randao partial signature is cross-referenced to the scheduled Proposer
    /// duty and counted as normal participation (not unexpected).
    #[tokio::test]
    async fn duty_randao_expected() {
        const VALID_PEER: u64 = 1;
        let cancel = CancellationToken::new();
        let slot = SlotNumber::new(123);
        let duty_proposer = Duty::new_proposer_duty(slot);
        let duty_randao = Duty::new_randao_duty(slot);
        let pk = pubkey();

        let part_records: std::sync::Arc<Mutex<Vec<ParticipationRecord>>> = Default::default();

        let (handle, analyser_tx, deleter_tx) = start_test_tracker(
            &cancel,
            0,
            Box::new(NopFailureReporter),
            Box::new(RecordingParticipationReporter {
                records: part_records.clone(),
                cancel: cancel.clone(),
                trigger_on: 2,
            }),
        );

        let fetch_err: StepError =
            std::sync::Arc::new(std::io::Error::other("failed to query randao"));
        handle
            .fetcher_fetched(duty_proposer.clone(), &[pk], Some(fetch_err))
            .await;
        handle
            .par_sig_db_stored_external(duty_randao.clone(), &par_sig_set(&[pk], VALID_PEER), None)
            .await;
        tokio::task::yield_now().await;

        analyser_tx.send(duty_proposer.clone()).await.unwrap();
        tokio::task::yield_now().await;
        analyser_tx.send(duty_randao.clone()).await.unwrap();
        tokio::task::yield_now().await;
        // Cancel fires after the randao record; deleter send may race.
        let _ = deleter_tx.send(duty_proposer.clone()).await;

        wait_for_task(handle).await;

        let recs = part_records.lock().unwrap();
        let randao_rec = recs
            .iter()
            .find(|r| r.duty == duty_randao)
            .expect("randao record");
        assert!(randao_rec.failed);
        assert_eq!(randao_rec.participated, HashMap::from([(VALID_PEER, 1)]));
        assert_eq!(randao_rec.unexpected, HashMap::new());
    }

    #[tokio::test]
    async fn fan_out_sends_one_event_per_pubkey() {
        let cancel = CancellationToken::new();
        let duty = attester(1);
        let keys = [pubkey(), PubKey::from([2u8; 48]), PubKey::from([3u8; 48])];

        let part_records: std::sync::Arc<Mutex<Vec<ParticipationRecord>>> = Default::default();

        let (handle, analyser_tx, deleter_tx) = start_test_tracker(
            &cancel,
            0,
            Box::new(NopFailureReporter),
            Box::new(RecordingParticipationReporter {
                records: part_records.clone(),
                cancel: cancel.clone(),
                trigger_on: 1,
            }),
        );

        handle.fetcher_fetched(duty.clone(), &keys, None).await;
        handle.consensus_proposed(duty.clone(), &keys, None).await;
        tokio::task::yield_now().await;

        analyser_tx.send(duty.clone()).await.unwrap();
        tokio::task::yield_now().await;
        let _ = deleter_tx.send(duty.clone()).await;

        wait_for_task(handle).await;

        let recs = part_records.lock().unwrap();
        assert_eq!(recs.len(), 1);
        // analyse_participation counts distinct pubkeys across all stored events;
        // expected_per_peer==3 proves each key produced its own event entry.
        assert_eq!(recs[0].expected_per_peer, 3);
    }
}
