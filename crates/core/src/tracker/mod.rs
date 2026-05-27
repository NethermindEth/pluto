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

/// Type-erased step error, matching Go's `error` interface.
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
/// participation reporting, matching Go's `core.Tracker` interface.
///
/// Methods that only need validator pubkeys (fetcher, consensus, dutydb,
/// sigagg, aggsigdb, bcast) accept `&[PubKey]` for object safety. Methods
/// that also carry partial-signature data accept `&ParSignedDataSet`.
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
const INPUT_BUFFER: usize = 1024;

/// A single event emitted by a core workflow component.
///
/// `par_sig` is only set by `ValidatorAPI`, `ParSigDBInternal`, and
/// `ParSigEx` events, matching Go's `event.parSig`.
#[allow(dead_code)]
pub(crate) struct Event {
    pub duty: Duty,
    pub step: Step,
    pub pubkey: PubKey,
    pub step_err: Option<StepError>,
    pub par_sig: Option<ParSignedData>,
}

/// Public-facing handle returned by [`TrackerService::start`].
///
/// Holds the send-half of the event channel and implements the [`Tracker`]
/// trait so core workflow components can submit events. The background loop
/// that consumes those events lives in [`TrackerService`].
pub struct TrackerHandle {
    input_tx: mpsc::Sender<Event>,
}

impl TrackerHandle {
    async fn send_event(&self, event: Event) {
        if let Err(e) = self.input_tx.send(event).await {
            tracing::warn!(error = %e, "Tracker input channel closed; dropping event");
        }
    }
}

impl Tracker for TrackerHandle {
    async fn fetcher_fetched(&self, duty: Duty, pubkeys: &[PubKey], err: Option<StepError>) {
        for pubkey in pubkeys {
            self.send_event(Event {
                duty: duty.clone(),
                step: Step::Fetcher,
                pubkey: *pubkey,
                step_err: err.clone(),
                par_sig: None,
            })
            .await;
        }
    }

    async fn consensus_proposed(&self, duty: Duty, pubkeys: &[PubKey], err: Option<StepError>) {
        for pubkey in pubkeys {
            self.send_event(Event {
                duty: duty.clone(),
                step: Step::Consensus,
                pubkey: *pubkey,
                step_err: err.clone(),
                par_sig: None,
            })
            .await;
        }
    }

    async fn duty_db_stored(&self, duty: Duty, pubkeys: &[PubKey], err: Option<StepError>) {
        for pubkey in pubkeys {
            self.send_event(Event {
                duty: duty.clone(),
                step: Step::DutyDB,
                pubkey: *pubkey,
                step_err: err.clone(),
                par_sig: None,
            })
            .await;
        }
    }

    async fn par_sig_db_stored_internal(
        &self,
        duty: Duty,
        set: &ParSignedDataSet,
        err: Option<StepError>,
    ) {
        for (pubkey, par_sig) in set.inner() {
            self.send_event(Event {
                duty: duty.clone(),
                step: Step::ParSigDBInternal,
                pubkey: *pubkey,
                step_err: err.clone(),
                par_sig: Some(par_sig.clone()),
            })
            .await;
        }
    }

    async fn par_sig_ex_broadcasted(
        &self,
        duty: Duty,
        set: &ParSignedDataSet,
        err: Option<StepError>,
    ) {
        for (pubkey, par_sig) in set.inner() {
            self.send_event(Event {
                duty: duty.clone(),
                step: Step::ParSigEx,
                pubkey: *pubkey,
                step_err: err.clone(),
                par_sig: Some(par_sig.clone()),
            })
            .await;
        }
    }

    async fn par_sig_db_stored_external(
        &self,
        duty: Duty,
        set: &ParSignedDataSet,
        err: Option<StepError>,
    ) {
        for (pubkey, par_sig) in set.inner() {
            self.send_event(Event {
                duty: duty.clone(),
                step: Step::ParSigDBExternal,
                pubkey: *pubkey,
                step_err: err.clone(),
                par_sig: Some(par_sig.clone()),
            })
            .await;
        }
    }

    async fn sig_agg_aggregated(&self, duty: Duty, pubkeys: &[PubKey], err: Option<StepError>) {
        for pubkey in pubkeys {
            self.send_event(Event {
                duty: duty.clone(),
                step: Step::SigAgg,
                pubkey: *pubkey,
                step_err: err.clone(),
                par_sig: None,
            })
            .await;
        }
    }

    async fn agg_sig_db_stored(&self, duty: Duty, pubkeys: &[PubKey], err: Option<StepError>) {
        for pubkey in pubkeys {
            self.send_event(Event {
                duty: duty.clone(),
                step: Step::AggSigDB,
                pubkey: *pubkey,
                step_err: err.clone(),
                par_sig: None,
            })
            .await;
        }
    }

    async fn broadcaster_broadcast(&self, duty: Duty, pubkeys: &[PubKey], err: Option<StepError>) {
        for pubkey in pubkeys {
            self.send_event(Event {
                duty: duty.clone(),
                step: Step::Bcast,
                pubkey: *pubkey,
                step_err: err.clone(),
                par_sig: None,
            })
            .await;
        }
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
    pub fn start(
        cancel: CancellationToken,
        analyser: DeadlinerHandle,
        analyser_rx: mpsc::Receiver<Duty>,
        deleter: DeadlinerHandle,
        deleter_rx: mpsc::Receiver<Duty>,
        peers: Vec<PeerInfo>,
        from_slot: u64,
    ) -> Arc<TrackerHandle> {
        let (input_tx, input_rx) = mpsc::channel(INPUT_BUFFER);

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

        tokio::spawn(task.run());

        Arc::new(TrackerHandle { input_tx })
    }

    async fn run(mut self) {
        let mut events: HashMap<Duty, Vec<Event>> = HashMap::new();

        loop {
            tokio::select! {
                biased;

                _ = self.cancel.cancelled() => {
                    return;
                }

                Some(e) = self.input_rx.recv() => {
                    if e.duty.slot.inner() < self.from_slot {
                        continue;
                    }

                    // Ignore expired or never-expiring duties.
                    if self.deleter.add(e.duty.clone()).await != AddOutcome::Scheduled
                        || self.analyser.add(e.duty.clone()).await != AddOutcome::Scheduled
                    {
                        continue;
                    }

                    events.entry(e.duty.clone()).or_default().push(e);
                }

                Some(duty) = self.analyser_rx.recv() => {
                    // TODO: extract par sigs, analyse failed duty, report participation.
                    let _ = &events;
                    tracing::debug!(duty = %duty, "Duty analysis triggered (not yet implemented)");
                }

                Some(duty) = self.deleter_rx.recv() => {
                    events.remove(&duty);
                }
            }
        }
    }
}
