/// Failure reason definitions for duty analysis.
pub mod reason;

/// Step enum for the core workflow.
pub mod step;

use std::{collections::HashMap, fmt, future::Future, sync::Arc};

use pluto_featureset::{Feature, GLOBAL_STATE};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    deadline::{AddOutcome, DeadlinerHandle},
    types::{Duty, DutyType, ParSignedData, ParSignedDataSet, PubKey},
};

use reason::Reason;
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
///
/// Sized to absorb a full epoch's worth of events across all duty types and
/// validators without back-pressuring producers while the loop is busy with a
/// deadliner round-trip.
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

// ---------------------------------------------------------------------------
// Duty analysis helpers
// ---------------------------------------------------------------------------

/// Partial signatures grouped by message root, grouped by pubkey.
///
/// Matches Go's `parsigsByMsg` type: `map[PubKey]map[[32]byte][]ParSignedData`.
type ParSigsByMsg = HashMap<PubKey, HashMap<[u8; 32], Vec<ParSignedData>>>;

/// Returns true if all pubkeys in `sigs` share a single unique message root.
///
/// Matches Go's `parsigsByMsg.MsgRootsConsistent`.
fn msg_roots_consistent(sigs: &ParSigsByMsg) -> bool {
    sigs.values().all(|roots| roots.len() <= 1)
}

/// Returns true if the duty type supports chain-inclusion checking.
///
/// Matches Go's `inclSupported()` in `inclusion.go`.
fn incl_supported(duty_type: &DutyType) -> bool {
    match duty_type {
        DutyType::Proposer => true,
        DutyType::Attester | DutyType::Aggregator => GLOBAL_STATE
            .read()
            .expect("global feature set lock poisoned")
            .enabled(Feature::AttestationInclusion),
        _ => false,
    }
}

/// Returns the last expected step of a duty.
///
/// Matches Go's `lastStep` in `tracker.go`.
fn last_step(duty_type: &DutyType) -> Step {
    if incl_supported(duty_type) {
        Step::ChainInclusion
    } else {
        Step::Bcast
    }
}

/// Returns true if the duty type is expected to sometimes produce inconsistent
/// partial signed data (sync committee duties).
///
/// Matches Go's `expectInconsistentParSigs`.
fn expect_inconsistent_par_sigs(duty_type: &DutyType) -> bool {
    matches!(
        duty_type,
        DutyType::SyncMessage | DutyType::SyncContribution
    )
}

/// Collects unique partial signatures from events, grouped by pubkey then
/// message root.
///
/// Deduplicates by `(pubkey, share_idx)`. Events without a `par_sig` are
/// skipped. On `message_root()` failure the event is skipped with a warning.
///
/// Matches Go's `extractParSigs`.
fn extract_par_sigs(events: &[Event]) -> ParSigsByMsg {
    #[derive(Eq, PartialEq, Hash)]
    struct DedupKey {
        pubkey: PubKey,
        share_idx: u64,
    }

    let mut dedup: HashMap<DedupKey, bool> = HashMap::new();
    let mut result: ParSigsByMsg = HashMap::new();

    for e in events {
        let Some(par_sig) = &e.par_sig else {
            continue;
        };

        let key = DedupKey {
            pubkey: e.pubkey,
            share_idx: par_sig.share_idx,
        };
        if dedup.insert(key, true).is_some() {
            continue;
        }

        let root = match par_sig.signed_data.message_root() {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!(error = %err, "Parsig message root");
                continue;
            }
        };

        result
            .entry(e.pubkey)
            .or_default()
            .entry(root)
            .or_default()
            .push(par_sig.clone());
    }

    result
}

/// Logs inconsistent partial-signature message roots for a duty.
///
/// Matches Go's `reportParSigs`.
fn report_par_sigs(duty: &Duty, sigs: &ParSigsByMsg) {
    if msg_roots_consistent(sigs) {
        return;
    }

    for (pubkey, by_root) in sigs {
        if by_root.len() <= 1 {
            continue;
        }

        if expect_inconsistent_par_sigs(&duty.duty_type) {
            tracing::debug!(
                pubkey = %pubkey.abbreviated(),
                duty = %duty,
                "Inconsistent sync committee partial signed data"
            );
        } else {
            tracing::warn!(
                pubkey = %pubkey.abbreviated(),
                duty = %duty,
                "Inconsistent partial signed data"
            );
        }
    }
}

/// Creates a `StepError` from a static string, used for bug-sentinel errors.
fn make_bug_err(msg: &'static str) -> StepError {
    #[derive(Debug)]
    struct BugError(&'static str);

    impl fmt::Display for BugError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for BugError {}

    Arc::new(BugError(msg))
}

/// Identifies the step where a duty got stuck and whether it failed.
///
/// Returns `(failed, step, error)`. When `failed` is false, `step` is
/// `Step::Zero` and `error` is `None`.
///
/// Matches Go's `dutyFailedStep`.
pub(crate) fn duty_failed_step(events: &[Event]) -> (bool, Step, Option<StepError>) {
    if events.is_empty() {
        return (true, Step::Zero, None);
    }

    let mut by_step: HashMap<Step, Vec<&Event>> = HashMap::new();
    for e in events {
        by_step.entry(e.step).or_default().push(e);
    }

    // Find the highest-numbered step that has events (excluding Zero).
    let last = by_step
        .iter()
        .filter(|(s, _)| **s > Step::Zero)
        .max_by_key(|(s, _)| *s)
        .and_then(|(_, evts)| evts.last().copied());

    let duty_type = &events[0].duty.duty_type;

    match last {
        Some(e) if e.step == last_step(duty_type) && e.step_err.is_none() => {
            (false, Step::Zero, None)
        }
        Some(e) => (true, e.step, e.step_err.clone()),
        None => (true, Step::Zero, None),
    }
}

/// Analyses why an aggregator fetcher duty failed, checking the prerequisite
/// prepare-aggregator and attester duties.
///
/// Matches Go's `analyseFetcherFailedAggregator`.
fn analyse_fetcher_failed_aggregator(
    duty: &Duty,
    all_events: &HashMap<Duty, Vec<Event>>,
    fetch_err: Option<StepError>,
) -> (bool, Step, Option<Reason>, Option<StepError>) {
    // No aggregators selected for this slot — not actually a failure.
    if fetch_err.is_none() {
        return (false, Step::Fetcher, None, None);
    }

    let empty = vec![];
    let mut failed_reason = reason::REASON_BUG_FETCH_ERROR;

    let prep_agg_duty = Duty::new_prepare_aggregator_duty(duty.slot);
    let prep_events = all_events.get(&prep_agg_duty).unwrap_or(&empty);
    let (prep_failed, prep_step, _) = duty_failed_step(prep_events);

    if prep_failed {
        failed_reason = match prep_step {
            Step::ParSigEx => reason::REASON_NO_AGGREGATOR_SELECTIONS,
            Step::ParSigDBExternal => reason::REASON_INSUFFICIENT_AGGREGATOR_SELECTIONS,
            Step::Zero => reason::REASON_ZERO_AGGREGATOR_SELECTIONS,
            _ => reason::REASON_FAILED_AGGREGATOR_SELECTION,
        };
        return (true, Step::Fetcher, Some(failed_reason), fetch_err);
    }

    let att_duty = Duty::new_attester_duty(duty.slot);
    let att_events = all_events.get(&att_duty).unwrap_or(&empty);
    let (att_failed, att_step, _) = duty_failed_step(att_events);

    if att_failed && att_step <= Step::DutyDB {
        failed_reason = reason::REASON_MISSING_AGGREGATOR_ATTESTATION;
    }

    (true, Step::Fetcher, Some(failed_reason), fetch_err)
}

/// Analyses why a proposer fetcher duty failed, checking the randao duty.
///
/// Matches Go's `analyseFetcherFailedProposer`.
fn analyse_fetcher_failed_proposer(
    duty: &Duty,
    all_events: &HashMap<Duty, Vec<Event>>,
    fetch_err: Option<StepError>,
) -> (bool, Step, Option<Reason>, Option<StepError>) {
    let empty = vec![];
    let mut reason_val = reason::REASON_BUG_FETCH_ERROR;

    let randao_duty = Duty::new_randao_duty(duty.slot);
    let randao_events = all_events.get(&randao_duty).unwrap_or(&empty);
    let (randao_failed, randao_step, _) = duty_failed_step(randao_events);

    if randao_failed {
        reason_val = match randao_step {
            Step::ParSigEx => reason::REASON_PROPOSER_NO_EXTERNAL_RANDAOS,
            Step::ParSigDBExternal => reason::REASON_PROPOSER_INSUFFICIENT_RANDAOS,
            Step::Zero => reason::REASON_PROPOSER_ZERO_RANDAOS,
            _ => reason::REASON_FAILED_PROPOSER_RANDAO,
        };
    }

    (true, Step::Fetcher, Some(reason_val), fetch_err)
}

/// Analyses why a sync-contribution fetcher duty failed, checking the
/// prepare-sync-contribution and sync-message duties.
///
/// Matches Go's `analyseFetcherFailedSyncContribution`.
fn analyse_fetcher_failed_sync_contribution(
    duty: &Duty,
    all_events: &HashMap<Duty, Vec<Event>>,
    fetch_err: Option<StepError>,
) -> (bool, Step, Option<Reason>, Option<StepError>) {
    // No sync committee aggregators selected — not actually a failure.
    if fetch_err.is_none() {
        return (false, Step::Fetcher, None, None);
    }

    let empty = vec![];
    let mut fail_reason = reason::REASON_BUG_FETCH_ERROR;

    let prep_sync_duty = Duty::new_prepare_sync_contribution_duty(duty.slot);
    let prep_events = all_events.get(&prep_sync_duty).unwrap_or(&empty);
    let (prep_failed, prep_step, _) = duty_failed_step(prep_events);

    if prep_failed {
        fail_reason = match prep_step {
            Step::ParSigEx => reason::REASON_SYNC_CONTRIBUTION_NO_EXTERNAL_PREPARES,
            Step::ParSigDBExternal => reason::REASON_SYNC_CONTRIBUTION_FEW_PREPARES,
            Step::Zero => reason::REASON_SYNC_CONTRIBUTION_ZERO_PREPARES,
            _ => reason::REASON_SYNC_CONTRIBUTION_FAILED_PREPARE,
        };
        return (true, Step::Fetcher, Some(fail_reason), fetch_err);
    }

    let sync_msg_duty = Duty::new_sync_message_duty(duty.slot);
    let sync_events = all_events.get(&sync_msg_duty).unwrap_or(&empty);
    let (sync_failed, sync_step, _) = duty_failed_step(sync_events);

    if sync_failed && sync_step <= Step::AggSigDB {
        fail_reason = reason::REASON_SYNC_CONTRIBUTION_NO_SYNC_MSG;
    }

    (true, Step::Fetcher, Some(fail_reason), fetch_err)
}

/// Analyses why a fetcher duty failed, routing to duty-type-specific helpers.
///
/// Matches Go's `analyseFetcherFailed`.
fn analyse_fetcher_failed(
    duty: &Duty,
    all_events: &HashMap<Duty, Vec<Event>>,
    fetch_err: Option<StepError>,
) -> (bool, Step, Option<Reason>, Option<StepError>) {
    match &duty.duty_type {
        DutyType::Proposer => analyse_fetcher_failed_proposer(duty, all_events, fetch_err),
        DutyType::Aggregator => analyse_fetcher_failed_aggregator(duty, all_events, fetch_err),
        DutyType::SyncContribution => {
            analyse_fetcher_failed_sync_contribution(duty, all_events, fetch_err)
        }
        _ => (
            true,
            Step::Fetcher,
            Some(reason::REASON_BUG_FETCH_ERROR),
            fetch_err,
        ),
    }
}

/// Analyses whether a duty failed and determines the reason.
///
/// Returns `(failed, step, reason, error)`. When `failed` is false all other
/// fields are their zero values.
///
/// Matches Go's `analyseDutyFailed`.
pub(crate) fn analyse_duty_failed(
    duty: &Duty,
    all_events: &HashMap<Duty, Vec<Event>>,
    msg_root_consistent: bool,
) -> (bool, Step, Option<Reason>, Option<StepError>) {
    let empty = vec![];
    let events = all_events.get(duty).unwrap_or(&empty);
    let (failed, mut failed_step, mut failed_err) = duty_failed_step(events);

    if !failed {
        return (false, Step::Zero, None, None);
    }

    let mut reason_val = Some(reason::REASON_UNKNOWN);

    match failed_step {
        Step::Fetcher => {
            return analyse_fetcher_failed(duty, all_events, failed_err);
        }
        Step::Consensus => {
            if failed_err.is_some() {
                reason_val = Some(reason::REASON_NO_CONSENSUS);
            }
        }
        Step::DutyDB => {
            if failed_err.is_some() {
                reason_val = Some(reason::REASON_BUG_DUTY_DB_ERROR);
            } else {
                failed_step = Step::ValidatorAPI;
                reason_val = Some(reason::REASON_NO_LOCAL_VC_SIGNATURE);
            }
        }
        Step::ParSigDBInternal => {
            reason_val = Some(reason::REASON_BUG_PAR_SIG_DB_INTERNAL);
        }
        Step::ParSigEx => {
            if failed_err.is_none() {
                reason_val = Some(reason::REASON_NO_PEER_SIGNATURES);
            }
        }
        Step::ParSigDBExternal => {
            if failed_err.is_some() {
                return (
                    true,
                    Step::ParSigDBExternal,
                    Some(reason::REASON_BUG_PAR_SIG_DB_EXTERNAL),
                    failed_err,
                );
            }
            reason_val = if msg_root_consistent {
                Some(reason::REASON_INSUFFICIENT_PEER_SIGNATURES)
            } else if expect_inconsistent_par_sigs(&duty.duty_type) {
                Some(reason::REASON_PAR_SIG_DB_INCONSISTENT_SYNC)
            } else {
                Some(reason::REASON_BUG_PAR_SIG_DB_INCONSISTENT)
            };
        }
        Step::SigAgg => {
            if failed_err.is_some() {
                reason_val = Some(reason::REASON_BUG_SIG_AGG);
            }
        }
        Step::AggSigDB => {
            reason_val = Some(reason::REASON_BUG_AGGREGATION_ERROR);
        }
        Step::Bcast => {
            if failed_err.is_none() {
                failed_err = Some(make_bug_err("bug: missing chain inclusion event"));
            } else {
                reason_val = Some(reason::REASON_BROADCAST_BN_ERROR);
            }
        }
        Step::ChainInclusion => {
            if failed_err.is_none() {
                failed_err = Some(make_bug_err("bug: missing chain inclusion error"));
            } else {
                reason_val = Some(reason::REASON_NOT_INCLUDED_ON_CHAIN);
            }
        }
        Step::Zero => {
            failed_err = Some(make_bug_err("no events for duty"));
        }
        Step::ValidatorAPI | Step::Sentinel => {
            failed_err = Some(make_bug_err("duty failed at unexpected step"));
        }
    }

    (true, failed_step, reason_val, failed_err)
}

/// Returns true if a partial-signature event is expected for the given duty
/// and pubkey, based on whether the corresponding scheduled duty was fetched.
///
/// Matches Go's `isParSigEventExpected`.
fn is_par_sig_event_expected(
    duty: &Duty,
    pubkey: PubKey,
    all_events: &HashMap<Duty, Vec<Event>>,
) -> bool {
    // Exit and builder-registration duties are always expected.
    if matches!(
        duty.duty_type,
        DutyType::Exit | DutyType::BuilderRegistration
    ) {
        return true;
    }

    let scheduled = |check_type: DutyType| {
        let check_duty = Duty::new(duty.slot, check_type);
        all_events
            .get(&check_duty)
            .map(|evts| {
                evts.iter()
                    .any(|e| e.step == Step::Fetcher && e.pubkey == pubkey)
            })
            .unwrap_or(false)
    };

    match &duty.duty_type {
        DutyType::Randao => scheduled(DutyType::Proposer) || scheduled(DutyType::BuilderProposer),
        DutyType::PrepareAggregator => scheduled(DutyType::Attester),
        DutyType::PrepareSyncContribution | DutyType::SyncMessage => {
            scheduled(DutyType::SyncContribution)
        }
        t => scheduled(t.clone()),
    }
}

/// Counts peer participation from partial-signature events for a duty.
///
/// Returns `(participated_shares, unexpected_shares, pubkey_count)`.
/// - `participated_shares`: map of share_idx → count of distinct pubkeys that
///   signed.
/// - `unexpected_shares`: map of share_idx → count of unexpected events.
/// - `pubkey_count`: number of distinct validator pubkeys seen for the duty.
///
/// Matches Go's `analyseParticipation`.
fn analyse_participation(
    duty: &Duty,
    all_events: &HashMap<Duty, Vec<Event>>,
) -> (HashMap<u64, u64>, HashMap<u64, u64>, usize) {
    #[derive(Eq, PartialEq, Hash)]
    struct DedupKey {
        share_idx: u64,
        pubkey: PubKey,
    }

    let mut participated: HashMap<u64, u64> = HashMap::new();
    let mut unexpected: HashMap<u64, u64> = HashMap::new();
    let mut pubkey_set: HashMap<PubKey, bool> = HashMap::new();
    let mut dedup: HashMap<DedupKey, bool> = HashMap::new();

    let empty = vec![];
    let events = all_events.get(duty).unwrap_or(&empty);

    for e in events {
        pubkey_set.insert(e.pubkey, true);

        if !matches!(e.step, Step::ParSigDBExternal | Step::ParSigDBInternal) {
            continue;
        }

        let Some(par_sig) = &e.par_sig else {
            continue;
        };

        if !is_par_sig_event_expected(duty, e.pubkey, all_events) {
            let v = unexpected.entry(par_sig.share_idx).or_default();
            *v = v.saturating_add(1);
            continue;
        }

        let key = DedupKey {
            share_idx: par_sig.share_idx,
            pubkey: e.pubkey,
        };
        if dedup.insert(key, true).is_none() {
            let v = participated.entry(par_sig.share_idx).or_default();
            *v = v.saturating_add(1);
        }
    }

    (participated, unexpected, pubkey_set.len())
}

// ---------------------------------------------------------------------------
// Background service
// ---------------------------------------------------------------------------

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

        // Unsupported-duty ignorer state: once a duty type succeeds we know it
        // is supported, and stop suppressing its failures.
        let mut aggregation_supported = false;
        let mut contribution_supported = false;
        let mut logged_no_aggregator = false;
        let mut logged_no_contribution = false;

        // Track previous absent-peer sets per duty type to avoid log spam.
        let mut prev_absent: HashMap<DutyType, Vec<String>> = HashMap::new();

        loop {
            tokio::select! {
                // Cancellation is checked first so shutdown is never delayed by
                // a busy event or deadliner channel.
                biased;

                _ = self.cancel.cancelled() => {
                    return;
                }

                Some(e) = self.input_rx.recv() => {
                    if e.duty.slot.inner() < self.from_slot {
                        continue;
                    }

                    // Run both deadliner adds concurrently to avoid stalling
                    // the loop on two sequential channel round-trips.
                    let (deleter_outcome, analyser_outcome) = tokio::join!(
                        self.deleter.add(e.duty.clone()),
                        self.analyser.add(e.duty.clone()),
                    );

                    // Ignore expired or never-expiring duties.
                    if deleter_outcome != AddOutcome::Scheduled
                        || analyser_outcome != AddOutcome::Scheduled
                    {
                        continue;
                    }

                    events.entry(e.duty.clone()).or_default().push(e);
                }

                Some(duty) = self.analyser_rx.recv() => {
                    let duty_events = events.get(&duty).map(Vec::as_slice).unwrap_or(&[]);
                    let parsigs = extract_par_sigs(duty_events);
                    report_par_sigs(&duty, &parsigs);

                    let consistent = msg_roots_consistent(&parsigs);
                    let (failed, failed_step, reason_val, failed_err) =
                        analyse_duty_failed(&duty, &events, consistent);

                    // Update unsupported-duty state before checking whether to ignore.
                    if !failed {
                        if duty.duty_type == DutyType::Aggregator {
                            aggregation_supported = true;
                        }
                        if duty.duty_type == DutyType::SyncContribution {
                            contribution_supported = true;
                        }
                    }

                    // Suppress known-unsupported duty failures with a one-time warning.
                    let ignore = if failed {
                        if !aggregation_supported
                            && duty.duty_type == DutyType::Aggregator
                            && failed_step == Step::Fetcher
                            && reason_val == Some(reason::REASON_ZERO_AGGREGATOR_SELECTIONS)
                        {
                            if !logged_no_aggregator {
                                tracing::warn!(
                                    duty = %duty,
                                    "Ignoring attestation aggregation failures since VCs do not seem to support beacon committee selection aggregation"
                                );
                            }
                            logged_no_aggregator = true;
                            true
                        } else if !contribution_supported
                            && duty.duty_type == DutyType::SyncContribution
                            && failed_step == Step::Fetcher
                            && reason_val == Some(reason::REASON_SYNC_CONTRIBUTION_ZERO_PREPARES)
                        {
                            if !logged_no_contribution {
                                tracing::warn!(
                                    duty = %duty,
                                    "Ignoring sync contribution failures since VCs do not seem to support sync committee selection aggregation"
                                );
                            }
                            logged_no_contribution = true;
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if ignore {
                        continue;
                    }

                    // Log the duty result.
                    if failed {
                        tracing::warn!(
                            duty = %duty,
                            step = %failed_step,
                            reason_code = reason_val.map(|r| r.code).unwrap_or(""),
                            reason = reason_val.map(|r| r.short).unwrap_or(""),
                            error = failed_err.as_ref().map(|e| e.to_string()).unwrap_or_default(),
                            "Duty failed"
                        );
                    } else if failed_step != Step::Fetcher {
                        tracing::debug!(duty = %duty, "Duty succeeded");
                    }

                    // Analyse and log peer participation.
                    let (participated, unexpected, _pubkey_count) =
                        analyse_participation(&duty, &events);

                    if participated.is_empty() && !failed {
                        // Noop duty (e.g. aggregation with no selection) — skip.
                        continue;
                    }

                    let mut absent_peers: Vec<String> = Vec::new();
                    for peer in &self.peers {
                        let share_idx = peer.share_idx as u64;
                        let n_participated = participated.get(&share_idx).copied().unwrap_or(0);
                        let n_unexpected = unexpected.get(&share_idx).copied().unwrap_or(0);

                        if n_participated > 0 {
                            // peer participated — nothing to log per-peer
                        } else if n_unexpected > 0 {
                            tracing::warn!(
                                peer = %peer.name,
                                duty = %duty,
                                "Unexpected event found"
                            );
                        } else {
                            absent_peers.push(peer.name.clone());
                        }
                    }

                    let prev = prev_absent.get(&duty.duty_type).cloned().unwrap_or_default();
                    if prev != absent_peers {
                        if absent_peers.is_empty() {
                            tracing::info!(duty = %duty, "All peers participated in duty");
                        } else if absent_peers.len() == self.peers.len() {
                            tracing::info!(duty = %duty, "No peers participated in duty");
                        } else {
                            tracing::info!(
                                duty = %duty,
                                absent = ?absent_peers,
                                "Not all peers participated in duty"
                            );
                        }
                    }
                    prev_absent.insert(duty.duty_type.clone(), absent_peers);
                }

                Some(duty) = self.deleter_rx.recv() => {
                    events.remove(&duty);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_err(msg: &'static str) -> StepError {
        make_bug_err(msg)
    }

    fn att_duty() -> Duty {
        Duty::new_attester_duty(1.into())
    }

    fn proposer_duty() -> Duty {
        Duty::new_proposer_duty(1.into())
    }

    fn randao_duty() -> Duty {
        Duty::new_randao_duty(1.into())
    }

    fn sync_msg_duty() -> Duty {
        Duty::new_sync_message_duty(1.into())
    }

    fn event_at(duty: Duty, step: Step) -> Event {
        Event {
            duty,
            step,
            pubkey: PubKey::new([0u8; 48]),
            step_err: None,
            par_sig: None,
        }
    }

    fn event_at_err(duty: Duty, step: Step, err: StepError) -> Event {
        Event {
            duty,
            step,
            pubkey: PubKey::new([0u8; 48]),
            step_err: Some(err),
            par_sig: None,
        }
    }

    // -----------------------------------------------------------------------
    // duty_failed_step tests — matches Go's TestDutyFailedStep
    // -----------------------------------------------------------------------

    #[test]
    fn duty_failed_step_empty() {
        let (failed, step, err) = duty_failed_step(&[]);
        assert!(failed);
        assert_eq!(step, Step::Zero);
        assert!(err.is_none());
    }

    #[test]
    fn duty_failed_step_success_attester() {
        // Attester duty: success requires events at all steps up to Bcast.
        let duty = att_duty();
        let events: Vec<Event> = (Step::Fetcher as u8..Step::ChainInclusion as u8)
            .map(|s| {
                let step = match s {
                    1 => Step::Fetcher,
                    2 => Step::Consensus,
                    3 => Step::DutyDB,
                    4 => Step::ValidatorAPI,
                    5 => Step::ParSigDBInternal,
                    6 => Step::ParSigEx,
                    7 => Step::ParSigDBExternal,
                    8 => Step::SigAgg,
                    9 => Step::AggSigDB,
                    10 => Step::Bcast,
                    _ => Step::Zero,
                };
                event_at(duty.clone(), step)
            })
            .collect();

        let (failed, step, err) = duty_failed_step(&events);
        assert!(!failed, "should not be failed");
        assert_eq!(step, Step::Zero);
        assert!(err.is_none());
    }

    // -----------------------------------------------------------------------
    // analyse_duty_failed tests — matches Go's TestAnalyseDutyFailed
    // -----------------------------------------------------------------------

    #[test]
    fn analyse_duty_failed_fetcher() {
        let duty = att_duty();
        let fetch_err = make_err("fetcher failed");
        let mut all_events: HashMap<Duty, Vec<Event>> = HashMap::new();
        all_events
            .entry(duty.clone())
            .or_default()
            .push(event_at_err(duty.clone(), Step::Fetcher, fetch_err.clone()));

        let (failed, step, reason_val, err) = analyse_duty_failed(&duty, &all_events, true);
        assert!(failed);
        assert_eq!(step, Step::Fetcher);
        assert_eq!(reason_val, Some(reason::REASON_BUG_FETCH_ERROR));
        assert!(err.is_some());
    }

    #[test]
    fn analyse_duty_failed_consensus() {
        let duty = att_duty();
        let consensus_err = make_err("consensus failed");
        let mut all_events: HashMap<Duty, Vec<Event>> = HashMap::new();
        all_events
            .entry(duty.clone())
            .or_default()
            .push(event_at_err(
                duty.clone(),
                Step::Consensus,
                consensus_err.clone(),
            ));

        let (failed, step, reason_val, err) = analyse_duty_failed(&duty, &all_events, true);
        assert!(failed);
        assert_eq!(step, Step::Consensus);
        assert_eq!(reason_val, Some(reason::REASON_NO_CONSENSUS));
        assert!(err.is_some());
        assert!(err.unwrap().to_string().contains("consensus failed"));
    }

    #[test]
    fn analyse_duty_failed_validator_api() {
        let duty = att_duty();
        let mut all_events: HashMap<Duty, Vec<Event>> = HashMap::new();
        // DutyDB with no error → step rewritten to ValidatorAPI
        all_events
            .entry(duty.clone())
            .or_default()
            .push(event_at(duty.clone(), Step::DutyDB));

        let (failed, step, reason_val, err) = analyse_duty_failed(&duty, &all_events, true);
        assert!(failed);
        assert_eq!(step, Step::ValidatorAPI);
        assert_eq!(reason_val, Some(reason::REASON_NO_LOCAL_VC_SIGNATURE));
        assert!(err.is_none());
    }

    #[test]
    fn analyse_duty_failed_par_sig_db_internal() {
        let duty = att_duty();
        let par_err = make_err("parsigdb_internal failed");
        let mut all_events: HashMap<Duty, Vec<Event>> = HashMap::new();
        all_events.entry(duty.clone()).or_default().extend([
            event_at(duty.clone(), Step::Fetcher),
            event_at(duty.clone(), Step::Consensus),
            event_at(duty.clone(), Step::DutyDB),
            event_at_err(duty.clone(), Step::ParSigDBInternal, par_err),
        ]);

        let (failed, step, reason_val, _) = analyse_duty_failed(&duty, &all_events, true);
        assert!(failed);
        assert_eq!(step, Step::ParSigDBInternal);
        assert_eq!(reason_val, Some(reason::REASON_BUG_PAR_SIG_DB_INTERNAL));
    }

    #[test]
    fn analyse_duty_failed_par_sig_ex_no_peers() {
        let duty = att_duty();
        let mut all_events: HashMap<Duty, Vec<Event>> = HashMap::new();
        all_events.entry(duty.clone()).or_default().extend([
            event_at(duty.clone(), Step::Fetcher),
            event_at(duty.clone(), Step::Consensus),
            event_at(duty.clone(), Step::DutyDB),
            event_at(duty.clone(), Step::ParSigDBInternal),
            event_at(duty.clone(), Step::ParSigEx), // no error → no peer sigs
        ]);

        let (failed, step, reason_val, err) = analyse_duty_failed(&duty, &all_events, true);
        assert!(failed);
        assert_eq!(step, Step::ParSigEx);
        assert_eq!(reason_val, Some(reason::REASON_NO_PEER_SIGNATURES));
        assert!(err.is_none());
    }

    #[test]
    fn analyse_duty_failed_par_sig_db_external_bug() {
        let duty = att_duty();
        let ext_err = make_err("parsigdb_external failed");
        let mut all_events: HashMap<Duty, Vec<Event>> = HashMap::new();
        all_events.entry(duty.clone()).or_default().extend([
            event_at(duty.clone(), Step::Fetcher),
            event_at(duty.clone(), Step::Consensus),
            event_at(duty.clone(), Step::DutyDB),
            event_at(duty.clone(), Step::ParSigDBInternal),
            event_at(duty.clone(), Step::ParSigEx),
            event_at_err(duty.clone(), Step::ParSigDBExternal, ext_err),
        ]);

        let (failed, step, reason_val, _) = analyse_duty_failed(&duty, &all_events, true);
        assert!(failed);
        assert_eq!(step, Step::ParSigDBExternal);
        assert_eq!(reason_val, Some(reason::REASON_BUG_PAR_SIG_DB_EXTERNAL));
    }

    #[test]
    fn analyse_duty_failed_par_sig_db_threshold() {
        let duty = att_duty();
        let mut all_events: HashMap<Duty, Vec<Event>> = HashMap::new();
        all_events.entry(duty.clone()).or_default().extend([
            event_at(duty.clone(), Step::Fetcher),
            event_at(duty.clone(), Step::Consensus),
            event_at(duty.clone(), Step::DutyDB),
            event_at(duty.clone(), Step::ParSigDBInternal),
            event_at(duty.clone(), Step::ParSigEx),
            event_at(duty.clone(), Step::ParSigDBExternal), // no error
        ]);

        // Consistent roots → insufficient signatures
        let (failed, step, reason_val, err) = analyse_duty_failed(&duty, &all_events, true);
        assert!(failed);
        assert_eq!(step, Step::ParSigDBExternal);
        assert_eq!(
            reason_val,
            Some(reason::REASON_INSUFFICIENT_PEER_SIGNATURES)
        );
        assert!(err.is_none());

        // Inconsistent roots → bug
        let (failed, step, reason_val, _) = analyse_duty_failed(&duty, &all_events, false);
        assert!(failed);
        assert_eq!(step, Step::ParSigDBExternal);
        assert_eq!(reason_val, Some(reason::REASON_BUG_PAR_SIG_DB_INCONSISTENT));

        // Inconsistent roots for sync message → known limitation
        let sync_events = all_events[&duty].iter().map(|e| Event {
            duty: sync_msg_duty(),
            step: e.step,
            pubkey: e.pubkey,
            step_err: e.step_err.clone(),
            par_sig: e.par_sig.clone(),
        });
        let mut sync_all: HashMap<Duty, Vec<Event>> = HashMap::new();
        sync_all
            .entry(sync_msg_duty())
            .or_default()
            .extend(sync_events);

        let (failed, step, reason_val, _) = analyse_duty_failed(&sync_msg_duty(), &sync_all, false);
        assert!(failed);
        assert_eq!(step, Step::ParSigDBExternal);
        assert_eq!(
            reason_val,
            Some(reason::REASON_PAR_SIG_DB_INCONSISTENT_SYNC)
        );
    }

    #[test]
    fn analyse_duty_failed_bcast_error() {
        let duty = att_duty();
        let bcast_err = make_err("bcast failed");
        let mut all_events: HashMap<Duty, Vec<Event>> = HashMap::new();
        all_events.entry(duty.clone()).or_default().extend([
            event_at(duty.clone(), Step::Fetcher),
            event_at(duty.clone(), Step::Consensus),
            event_at(duty.clone(), Step::DutyDB),
            event_at(duty.clone(), Step::ParSigDBInternal),
            event_at(duty.clone(), Step::ParSigEx),
            event_at(duty.clone(), Step::ParSigDBExternal),
            event_at(duty.clone(), Step::SigAgg),
            event_at(duty.clone(), Step::AggSigDB),
            event_at_err(duty.clone(), Step::Bcast, bcast_err),
        ]);

        let (failed, step, reason_val, err) = analyse_duty_failed(&duty, &all_events, true);
        assert!(failed);
        assert_eq!(step, Step::Bcast);
        assert_eq!(reason_val, Some(reason::REASON_BROADCAST_BN_ERROR));
        assert!(err.is_some());
        assert!(err.unwrap().to_string().contains("bcast failed"));
    }

    #[test]
    fn analyse_duty_failed_chain_inclusion() {
        let duty = att_duty();
        let incl_err = make_err("not included on chain");
        let mut all_events: HashMap<Duty, Vec<Event>> = HashMap::new();
        all_events.entry(duty.clone()).or_default().extend([
            event_at(duty.clone(), Step::Fetcher),
            event_at(duty.clone(), Step::Consensus),
            event_at(duty.clone(), Step::DutyDB),
            event_at(duty.clone(), Step::ParSigDBInternal),
            event_at(duty.clone(), Step::ParSigEx),
            event_at(duty.clone(), Step::ParSigDBExternal),
            event_at(duty.clone(), Step::SigAgg),
            event_at(duty.clone(), Step::AggSigDB),
            event_at(duty.clone(), Step::Bcast),
            event_at_err(duty.clone(), Step::ChainInclusion, incl_err),
        ]);

        let (failed, step, reason_val, err) = analyse_duty_failed(&duty, &all_events, true);
        assert!(failed);
        assert_eq!(step, Step::ChainInclusion);
        assert_eq!(reason_val, Some(reason::REASON_NOT_INCLUDED_ON_CHAIN));
        assert!(err.is_some());
    }

    #[test]
    fn analyse_duty_failed_attester_success() {
        let duty = att_duty();
        let mut all_events: HashMap<Duty, Vec<Event>> = HashMap::new();
        // Add events at all steps up to (but not including) ChainInclusion.
        // Attester's last step is Bcast, so this should be a success.
        for s in [
            Step::Fetcher,
            Step::Consensus,
            Step::DutyDB,
            Step::ValidatorAPI,
            Step::ParSigDBInternal,
            Step::ParSigEx,
            Step::ParSigDBExternal,
            Step::SigAgg,
            Step::AggSigDB,
            Step::Bcast,
        ] {
            all_events
                .entry(duty.clone())
                .or_default()
                .push(event_at(duty.clone(), s));
        }

        assert_eq!(last_step(&DutyType::Attester), Step::Bcast);

        let (failed, step, reason_val, err) = analyse_duty_failed(&duty, &all_events, true);
        assert!(!failed);
        assert_eq!(step, Step::Zero);
        assert!(reason_val.is_none());
        assert!(err.is_none());
    }

    #[test]
    fn analyse_duty_failed_proposer_randao_failed() {
        let prop_duty = proposer_duty();
        let randao = randao_duty();
        let fetch_err = make_err("context canceled");

        let mut all_events: HashMap<Duty, Vec<Event>> = HashMap::new();
        all_events
            .entry(prop_duty.clone())
            .or_default()
            .push(event_at_err(prop_duty.clone(), Step::Fetcher, fetch_err));

        // Randao stopped at ParSigEx → no external randaos
        all_events.entry(randao.clone()).or_default().extend([
            event_at(randao.clone(), Step::ValidatorAPI),
            event_at(randao.clone(), Step::ParSigDBInternal),
            event_at(randao.clone(), Step::ParSigEx),
        ]);

        let (failed, step, reason_val, _) = analyse_duty_failed(&prop_duty, &all_events, true);
        assert!(failed);
        assert_eq!(step, Step::Fetcher);
        assert_eq!(
            reason_val,
            Some(reason::REASON_PROPOSER_NO_EXTERNAL_RANDAOS)
        );

        // Randao stopped at ParSigDBExternal → insufficient randaos
        all_events
            .entry(randao.clone())
            .or_default()
            .push(event_at(randao.clone(), Step::ParSigDBExternal));

        let (failed, step, reason_val, _) = analyse_duty_failed(&prop_duty, &all_events, true);
        assert!(failed);
        assert_eq!(step, Step::Fetcher);
        assert_eq!(
            reason_val,
            Some(reason::REASON_PROPOSER_INSUFFICIENT_RANDAOS)
        );

        // No randao events → zero randaos
        all_events.insert(randao.clone(), vec![]);

        let (failed, step, reason_val, _) = analyse_duty_failed(&prop_duty, &all_events, true);
        assert!(failed);
        assert_eq!(step, Step::Fetcher);
        assert_eq!(reason_val, Some(reason::REASON_PROPOSER_ZERO_RANDAOS));
    }
}
