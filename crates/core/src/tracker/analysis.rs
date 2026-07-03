//! Pure analysis functions for tracker duty failure detection and peer
//! participation accounting.

use std::collections::{HashMap, HashSet};

use pluto_eth2api::EthBeaconNodeApiClientError;
use pluto_featureset::{Feature, FeatureSet};
use pluto_ssz::HashRoot;

use crate::{
    tracker::{
        Event, StepError,
        reason::{
            REASON_BROADCAST_BN_ERROR, REASON_BUG_AGGREGATION_ERROR, REASON_BUG_DUTY_DB_ERROR,
            REASON_BUG_FETCH_ERROR, REASON_BUG_PAR_SIG_DB_EXTERNAL,
            REASON_BUG_PAR_SIG_DB_INCONSISTENT, REASON_BUG_PAR_SIG_DB_INTERNAL, REASON_BUG_SIG_AGG,
            REASON_FAILED_AGGREGATOR_SELECTION, REASON_FAILED_PROPOSER_RANDAO,
            REASON_FETCH_BN_ERROR, REASON_INSUFFICIENT_AGGREGATOR_SELECTIONS,
            REASON_INSUFFICIENT_PEER_SIGNATURES, REASON_MISSING_AGGREGATOR_ATTESTATION,
            REASON_NO_AGGREGATOR_SELECTIONS, REASON_NO_CONSENSUS, REASON_NO_LOCAL_VC_SIGNATURE,
            REASON_NO_PEER_SIGNATURES, REASON_NOT_INCLUDED_ON_CHAIN,
            REASON_PAR_SIG_DB_INCONSISTENT_SYNC, REASON_PROPOSER_INSUFFICIENT_RANDAOS,
            REASON_PROPOSER_NO_EXTERNAL_RANDAOS, REASON_PROPOSER_ZERO_RANDAOS,
            REASON_SYNC_CONTRIBUTION_FAILED_PREPARE, REASON_SYNC_CONTRIBUTION_FEW_PREPARES,
            REASON_SYNC_CONTRIBUTION_NO_EXTERNAL_PREPARES, REASON_SYNC_CONTRIBUTION_NO_SYNC_MSG,
            REASON_SYNC_CONTRIBUTION_ZERO_PREPARES, REASON_UNKNOWN,
            REASON_ZERO_AGGREGATOR_SELECTIONS, Reason,
        },
        step::Step,
    },
    types::{Duty, DutyType, ParSignedData, PubKey},
};

/// Partial signatures grouped by message root, grouped by pubkey.
pub type ParSigsByMsg = HashMap<PubKey, HashMap<HashRoot, Vec<ParSignedData>>>;

/// Returns true if every pubkey has at most one distinct message root.
pub(crate) fn msg_roots_consistent(parsigs: &ParSigsByMsg) -> bool {
    parsigs.values().all(|roots| roots.len() <= 1)
}

/// Duty types for which on-chain inclusion is tracked: always proposers, plus
/// attesters and aggregators when `AttestationInclusion` is enabled.
pub(crate) fn incl_supported(fs: &FeatureSet) -> HashSet<DutyType> {
    let mut set = HashSet::new();
    set.insert(DutyType::Proposer);
    if fs.enabled(Feature::AttestationInclusion) {
        set.insert(DutyType::Attester);
        set.insert(DutyType::Aggregator);
    }
    set
}

/// Returns the terminal step for a duty type — either `Bcast` or
/// `ChainInclusion` depending on whether inclusion checks are supported.
pub(crate) fn last_step(duty_type: &DutyType, feature_set: &FeatureSet) -> Step {
    if incl_supported(feature_set).contains(duty_type) {
        Step::ChainInclusion
    } else {
        Step::Bcast
    }
}

/// Duty types that are expected to occasionally produce inconsistent partial
/// signatures (sync committee duties).
pub(crate) fn expect_inconsistent_par_sigs(duty_type: &DutyType) -> bool {
    matches!(
        duty_type,
        DutyType::SyncMessage | DutyType::SyncContribution
    )
}

/// Outcome of duty failure analysis.
#[derive(Debug, Clone)]
pub struct DutyFailure {
    /// The step where the duty got stuck.
    pub step: Step,
    /// Human-friendly reason for the failure.
    pub reason: Reason,
    /// Underlying step error if any.
    pub err: Option<StepError>,
}

/// The step at which a duty stopped progressing.
#[derive(Debug, Clone)]
pub(crate) struct DutyFailedStep {
    /// Whether the duty failed, i.e. did not reach its terminal step.
    pub failed: bool,
    /// The step the duty got stuck at; `Zero` on success.
    pub step: Step,
    /// The error reported by that step, if any.
    pub err: Option<StepError>,
}

/// Locates the step where a duty got stuck, the last error reported by that
/// step, and whether the duty failed.
///
/// An empty event slice indicates a duty
/// that failed before any event was recorded (returns `step = Zero`).
pub(crate) fn duty_failed_step(events: &[Event], feature_set: &FeatureSet) -> DutyFailedStep {
    if events.is_empty() {
        return DutyFailedStep {
            failed: true,
            step: Step::Zero,
            err: None,
        };
    }

    let mut events_by_step: HashMap<Step, Vec<&Event>> = HashMap::new();
    for e in events {
        events_by_step.entry(e.step).or_default().push(e);
    }

    // Scan backwards from the step just before Sentinel down to Fetcher,
    // returning the last event of the highest-numbered step that recorded any
    // events. Matches Go's `for step := sentinel - 1; step > zero; step--`.
    const STEPS: &[Step] = &[
        Step::ChainInclusion,
        Step::Bcast,
        Step::AggSigDB,
        Step::SigAgg,
        Step::ParSigDBExternal,
        Step::ParSigEx,
        Step::ParSigDBInternal,
        Step::ValidatorAPI,
        Step::DutyDB,
        Step::Consensus,
        Step::Fetcher,
    ];

    let last = STEPS
        .iter()
        .filter_map(|s| events_by_step.get(s).and_then(|es| es.last()).copied())
        .next();

    let Some(last) = last else {
        return DutyFailedStep {
            failed: true,
            step: Step::Zero,
            err: None,
        };
    };

    // Determine if the final step was successful. Use the duty type from the
    // first event (all events in the slice share the same duty).
    let last_for_duty = last_step(&events[0].duty.duty_type, feature_set);
    if last.step == last_for_duty && last.step_err.is_none() {
        return DutyFailedStep {
            failed: false,
            step: Step::Zero,
            err: None,
        };
    }

    DutyFailedStep {
        failed: true,
        step: last.step,
        err: last.step_err.clone(),
    }
}

/// Analyses whether a duty failed and, if so, why.
pub(crate) fn analyse_duty_failed(
    duty: &Duty,
    all_events: &HashMap<Duty, Vec<Event>>,
    failed_step: &DutyFailedStep,
    msg_root_consistent: bool,
    feature_set: &FeatureSet,
) -> Option<DutyFailure> {
    if !failed_step.failed {
        return None;
    }

    let mut reason = REASON_UNKNOWN;
    let mut step = failed_step.step;
    let mut err = failed_step.err.clone();

    match failed_step.step {
        Step::Fetcher => return analyse_fetcher_failed(duty, all_events, err, feature_set),
        Step::Consensus => {
            if err.is_some() {
                reason = REASON_NO_CONSENSUS;
            }
        }
        Step::DutyDB => {
            if err.is_some() {
                reason = REASON_BUG_DUTY_DB_ERROR;
            } else {
                step = Step::ValidatorAPI;
                reason = REASON_NO_LOCAL_VC_SIGNATURE;
            }
        }
        Step::ParSigDBInternal => {
            reason = REASON_BUG_PAR_SIG_DB_INTERNAL;
        }
        Step::ParSigEx => {
            if err.is_none() {
                reason = REASON_NO_PEER_SIGNATURES;
            }
        }
        Step::ParSigDBExternal => {
            if err.is_some() {
                return Some(DutyFailure {
                    step: Step::ParSigDBExternal,
                    reason: REASON_BUG_PAR_SIG_DB_EXTERNAL,
                    err,
                });
            }
            if msg_root_consistent {
                reason = REASON_INSUFFICIENT_PEER_SIGNATURES;
            } else if expect_inconsistent_par_sigs(&duty.duty_type) {
                reason = REASON_PAR_SIG_DB_INCONSISTENT_SYNC;
            } else {
                reason = REASON_BUG_PAR_SIG_DB_INCONSISTENT;
            }
        }
        Step::SigAgg => {
            if err.is_some() {
                reason = REASON_BUG_SIG_AGG;
            }
        }
        Step::AggSigDB => {
            reason = REASON_BUG_AGGREGATION_ERROR;
        }
        Step::Bcast => {
            if err.is_none() {
                err = Some(string_error("bug: missing chain inclusion event"));
            } else {
                reason = REASON_BROADCAST_BN_ERROR;
            }
        }
        Step::ChainInclusion => {
            if err.is_none() {
                err = Some(string_error("bug: missing chain inclusion error"));
            } else {
                reason = REASON_NOT_INCLUDED_ON_CHAIN;
            }
        }
        Step::Zero => {
            err = Some(string_error("no events for duty"));
        }
        _ => {
            err = Some(string_error(&format!(
                "duty failed at step {}",
                failed_step.step
            )));
        }
    }

    Some(DutyFailure { step, reason, err })
}

/// Analyses fetcher-step failures, checking pre-requisite duties for
/// proposer, aggregator, and sync-contribution duty types.
pub(crate) fn analyse_fetcher_failed(
    duty: &Duty,
    all_events: &HashMap<Duty, Vec<Event>>,
    fetch_err: Option<StepError>,
    feature_set: &FeatureSet,
) -> Option<DutyFailure> {
    match &duty.duty_type {
        DutyType::Proposer => Some(analyse_fetcher_failed_proposer(
            duty,
            all_events,
            fetch_err,
            feature_set,
        )),
        DutyType::Aggregator => {
            analyse_fetcher_failed_aggregator(duty, all_events, fetch_err, feature_set)
        }
        DutyType::SyncContribution => {
            analyse_fetcher_failed_sync_contribution(duty, all_events, fetch_err, feature_set)
        }
        _ => {
            // Parity: charon core/tracker/tracker.go:296-324 @ v1.7.1
            // classifies the fetch error in three tiers — (a) eth2 API error =>
            // REASON_FETCH_BN_ERROR, (b) context.Canceled /
            // context.DeadlineExceeded => the default reason, (c) otherwise =>
            // REASON_BUG_FETCH_ERROR. Go computes this upfront for all duty
            // types, but the proposer/aggregator/sync-contribution arms
            // recompute their own reason, so the classification only affects
            // this default arm.
            //
            // Accepted divergence (temporary): tiers (a) and (c) are
            // implemented but NOT the cancellation tier (b), because the
            // fetcher is not yet ported and there is no cancellation/timeout
            // error variant to match against. When the fetcher lands, add an
            // `is_cancelled_error(...)` check (mirroring `is_eth2_api_error`
            // below) so cancellation/deadline errors map to the default reason
            // rather than REASON_BUG_FETCH_ERROR.
            let reason = if let Some(e) = &fetch_err
                && is_eth2_api_error(e.as_ref())
            {
                REASON_FETCH_BN_ERROR
            } else {
                REASON_BUG_FETCH_ERROR
            };
            Some(DutyFailure {
                step: Step::Fetcher,
                reason,
                err: fetch_err,
            })
        }
    }
}

fn analyse_fetcher_failed_proposer(
    duty: &Duty,
    all_events: &HashMap<Duty, Vec<Event>>,
    fetch_err: Option<StepError>,
    feature_set: &FeatureSet,
) -> DutyFailure {
    let randao_duty = Duty::new_randao_duty(duty.slot);
    let randao_events = all_events
        .get(&randao_duty)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let randao = duty_failed_step(randao_events, feature_set);

    let reason = if randao.failed {
        match randao.step {
            Step::ParSigEx => REASON_PROPOSER_NO_EXTERNAL_RANDAOS,
            Step::ParSigDBExternal => REASON_PROPOSER_INSUFFICIENT_RANDAOS,
            Step::Zero => REASON_PROPOSER_ZERO_RANDAOS,
            _ => REASON_FAILED_PROPOSER_RANDAO,
        }
    } else {
        REASON_BUG_FETCH_ERROR
    };

    DutyFailure {
        step: Step::Fetcher,
        reason,
        err: fetch_err,
    }
}

fn analyse_fetcher_failed_aggregator(
    duty: &Duty,
    all_events: &HashMap<Duty, Vec<Event>>,
    fetch_err: Option<StepError>,
    feature_set: &FeatureSet,
) -> Option<DutyFailure> {
    fetch_err.as_ref()?;

    let prep_agg_duty = Duty::new_prepare_aggregator_duty(duty.slot);
    let prep_events = all_events
        .get(&prep_agg_duty)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let prep = duty_failed_step(prep_events, feature_set);

    if prep.failed {
        let reason = match prep.step {
            Step::ParSigEx => REASON_NO_AGGREGATOR_SELECTIONS,
            Step::ParSigDBExternal => REASON_INSUFFICIENT_AGGREGATOR_SELECTIONS,
            Step::Zero => REASON_ZERO_AGGREGATOR_SELECTIONS,
            _ => REASON_FAILED_AGGREGATOR_SELECTION,
        };
        return Some(DutyFailure {
            step: Step::Fetcher,
            reason,
            err: fetch_err,
        });
    }

    let attester_duty = Duty::new_attester_duty(duty.slot);
    let att_events = all_events
        .get(&attester_duty)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let att = duty_failed_step(att_events, feature_set);

    let reason = if att.failed && att.step <= Step::DutyDB {
        REASON_MISSING_AGGREGATOR_ATTESTATION
    } else {
        REASON_BUG_FETCH_ERROR
    };

    Some(DutyFailure {
        step: Step::Fetcher,
        reason,
        err: fetch_err,
    })
}

fn analyse_fetcher_failed_sync_contribution(
    duty: &Duty,
    all_events: &HashMap<Duty, Vec<Event>>,
    fetch_err: Option<StepError>,
    feature_set: &FeatureSet,
) -> Option<DutyFailure> {
    fetch_err.as_ref()?;

    let prep_duty = Duty::new_prepare_sync_contribution_duty(duty.slot);
    let prep_events = all_events.get(&prep_duty).map(Vec::as_slice).unwrap_or(&[]);
    let prep = duty_failed_step(prep_events, feature_set);

    if prep.failed {
        let reason = match prep.step {
            Step::ParSigEx => REASON_SYNC_CONTRIBUTION_NO_EXTERNAL_PREPARES,
            Step::ParSigDBExternal => REASON_SYNC_CONTRIBUTION_FEW_PREPARES,
            Step::Zero => REASON_SYNC_CONTRIBUTION_ZERO_PREPARES,
            _ => REASON_SYNC_CONTRIBUTION_FAILED_PREPARE,
        };
        return Some(DutyFailure {
            step: Step::Fetcher,
            reason,
            err: fetch_err,
        });
    }

    let sync_msg_duty = Duty::new_sync_message_duty(duty.slot);
    let sync_events = all_events
        .get(&sync_msg_duty)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let sync = duty_failed_step(sync_events, feature_set);

    let reason = if sync.failed && sync.step <= Step::AggSigDB {
        REASON_SYNC_CONTRIBUTION_NO_SYNC_MSG
    } else {
        REASON_BUG_FETCH_ERROR
    };

    Some(DutyFailure {
        step: Step::Fetcher,
        reason,
        err: fetch_err,
    })
}

/// Groups partial signatures by message root, per pubkey, deduplicating by
/// `(pubkey, share_idx)`.
pub(crate) fn extract_par_sigs(events: &[Event]) -> ParSigsByMsg {
    let mut dedup: HashSet<(PubKey, u64)> = HashSet::new();
    let mut resp: ParSigsByMsg = HashMap::new();

    for e in events {
        let Some(par_sig) = &e.par_sig else {
            continue;
        };

        let key = (e.pubkey, par_sig.share_idx);
        if !dedup.insert(key) {
            continue;
        }

        let root = match par_sig.signed_data.message_root() {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!(error = %err, "Parsig message root");
                continue;
            }
        };

        resp.entry(e.pubkey)
            .or_default()
            .entry(root)
            .or_default()
            .push(par_sig.clone());
    }

    resp
}

/// Result of [`analyse_participation`].
pub(crate) struct ParticipationResult {
    /// Partial-signature count per peer share index for expected peers.
    pub participated: HashMap<u64, usize>,
    /// Partial-signature count per peer share index for unexpected peers.
    pub unexpected: HashMap<u64, usize>,
    /// Number of distinct validator pubkeys that had any event for this duty.
    pub validators_per_duty: usize,
}

/// Counts partial signatures per peer share index — both expected
/// participations and unexpected events — plus the total number of distinct
/// validator pubkeys that had this duty scheduled.
pub(crate) fn analyse_participation(
    duty: &Duty,
    all_events: &HashMap<Duty, Vec<Event>>,
) -> ParticipationResult {
    let mut participated: HashMap<u64, usize> = HashMap::new();
    let mut unexpected: HashMap<u64, usize> = HashMap::new();
    let mut dedup: HashSet<(u64, PubKey)> = HashSet::new();
    let mut pubkeys: HashSet<PubKey> = HashSet::new();

    let Some(events) = all_events.get(duty) else {
        return ParticipationResult {
            participated,
            unexpected,
            validators_per_duty: 0,
        };
    };

    for e in events {
        pubkeys.insert(e.pubkey);

        if !matches!(e.step, Step::ParSigDBExternal | Step::ParSigDBInternal) {
            continue;
        }

        let Some(par_sig) = &e.par_sig else {
            continue;
        };
        let share_idx = par_sig.share_idx;

        if !is_par_sig_event_expected(duty, e.pubkey, all_events) {
            let slot = unexpected.entry(share_idx).or_insert(0);
            *slot = slot.saturating_add(1);
            continue;
        }

        if dedup.insert((share_idx, e.pubkey)) {
            let slot = participated.entry(share_idx).or_insert(0);
            *slot = slot.saturating_add(1);
        }
    }

    ParticipationResult {
        participated,
        unexpected,
        validators_per_duty: pubkeys.len(),
    }
}

/// Returns true if a partial-signature event is expected for the given duty
/// and pubkey — i.e. that duty (or an associated prerequisite) was scheduled.
pub(crate) fn is_par_sig_event_expected(
    duty: &Duty,
    pubkey: PubKey,
    all_events: &HashMap<Duty, Vec<Event>>,
) -> bool {
    // VAPI-triggered duties cannot be cross-referenced to a scheduled duty.
    if matches!(
        duty.duty_type,
        DutyType::Exit | DutyType::BuilderRegistration
    ) {
        return true;
    }

    let scheduled = |typ: DutyType| -> bool {
        let key = Duty::new(duty.slot, typ);
        let events = match all_events.get(&key) {
            Some(es) => es,
            None => return false,
        };
        events
            .iter()
            .any(|e| e.step == Step::Fetcher && e.pubkey == pubkey)
    };

    match &duty.duty_type {
        DutyType::Randao => scheduled(DutyType::Proposer) || scheduled(DutyType::BuilderProposer),
        DutyType::PrepareAggregator => scheduled(DutyType::Attester),
        DutyType::PrepareSyncContribution | DutyType::SyncMessage => {
            scheduled(DutyType::SyncContribution)
        }
        other => scheduled(other.clone()),
    }
}

fn is_eth2_api_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = current {
        if e.downcast_ref::<EthBeaconNodeApiClientError>().is_some() {
            return true;
        }
        current = e.source();
    }
    false
}

fn string_error(s: &str) -> StepError {
    #[derive(Debug)]
    struct Msg(String);
    impl std::fmt::Display for Msg {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for Msg {}
    std::sync::Arc::new(Msg(s.to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pluto_crypto::types::{SIGNATURE_LENGTH, Signature};

    use super::*;
    use crate::{
        signeddata::SignedDataError,
        types::{ParSignedData, SignedData, SlotNumber},
    };

    fn pubkey(byte: u8) -> PubKey {
        PubKey::from([byte; 48])
    }

    /// Computes the failed step for `duty` and runs the failure analysis,
    /// mirroring how `TrackerService::analyse` wires the two together.
    fn analyse_failed(
        duty: &Duty,
        events: &HashMap<Duty, Vec<Event>>,
        msg_root_consistent: bool,
    ) -> Option<DutyFailure> {
        let fs = FeatureSet::new();
        let failed_step = duty_failed_step(events.get(duty).map(Vec::as_slice).unwrap_or(&[]), &fs);
        analyse_duty_failed(duty, events, &failed_step, msg_root_consistent, &fs)
    }

    fn evt(duty: Duty, step: Step) -> Event {
        Event {
            duty,
            step,
            pubkey: pubkey(0),
            step_err: None,
            par_sig: None,
        }
    }

    fn evt_with_err(duty: Duty, step: Step, msg: &str) -> Event {
        Event {
            duty,
            step,
            pubkey: pubkey(0),
            step_err: Some(string_error(msg)),
            par_sig: None,
        }
    }

    fn evt_pubkey(duty: Duty, step: Step, pk: PubKey) -> Event {
        Event {
            duty,
            step,
            pubkey: pk,
            step_err: None,
            par_sig: None,
        }
    }

    /// Wraps an `EthBeaconNodeApiClientError` so [`is_eth2_api_error`] picks it
    /// up via the error chain (mirrors Go's `errors.Wrap(eth2api.Error{...})`).
    #[derive(Debug)]
    struct WrappedEth2(EthBeaconNodeApiClientError);

    impl std::fmt::Display for WrappedEth2 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "wrapped: {}", self.0)
        }
    }

    impl std::error::Error for WrappedEth2 {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    fn eth2_err() -> StepError {
        Arc::new(WrappedEth2(EthBeaconNodeApiClientError::UnexpectedResponse))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestSignedData {
        id: HashRoot,
        sig: [u8; SIGNATURE_LENGTH],
    }

    impl TestSignedData {
        fn new(id_byte: u8) -> Self {
            Self {
                id: [id_byte; 32],
                sig: [0u8; SIGNATURE_LENGTH],
            }
        }
    }

    impl SignedData for TestSignedData {
        fn signature(&self) -> Result<Signature, SignedDataError> {
            Ok(self.sig)
        }

        fn set_signature(&self, sig: Signature) -> Result<Self, SignedDataError>
        where
            Self: Sized,
        {
            Ok(Self { id: self.id, sig })
        }

        fn set_signature_boxed(
            &self,
            sig: Signature,
        ) -> Result<Box<dyn SignedData>, SignedDataError> {
            Ok(Box::new(self.set_signature(sig)?))
        }

        fn message_root(&self) -> Result<HashRoot, SignedDataError> {
            Ok(self.id)
        }
    }

    #[test]
    fn analyse_duty_failed_progressive() {
        // Replicates Go's TestAnalyseDutyFailed which uses one shared events
        // map; subtests append the next step in workflow order so the last
        // step recorded is always the one we just added.
        let att = Duty::new_attester_duty(SlotNumber::new(1));
        let mut events: HashMap<Duty, Vec<Event>> = HashMap::new();

        // Failed at fetcher with a non-eth2 error → BugFetchError.
        events.entry(att.clone()).or_default().push(evt_with_err(
            att.clone(),
            Step::Fetcher,
            "fetcher failed",
        ));
        let r = analyse_failed(&att, &events, true).unwrap();
        assert_eq!(r.step, Step::Fetcher);
        assert_eq!(r.reason, REASON_BUG_FETCH_ERROR);
        assert!(r.err.is_some());

        // Failed at consensus.
        events.entry(att.clone()).or_default().push(evt_with_err(
            att.clone(),
            Step::Consensus,
            "consensus failed",
        ));
        let r = analyse_failed(&att, &events, true).unwrap();
        assert_eq!(r.step, Step::Consensus);
        assert_eq!(r.reason, REASON_NO_CONSENSUS);

        // dutyDB step with no error → reported as validatorAPI / NoLocalVCSignature.
        events
            .entry(att.clone())
            .or_default()
            .push(evt(att.clone(), Step::DutyDB));
        let r = analyse_failed(&att, &events, true).unwrap();
        assert_eq!(r.step, Step::ValidatorAPI);
        assert_eq!(r.reason, REASON_NO_LOCAL_VC_SIGNATURE);
        assert!(r.err.is_none());

        // Failed at parsigDBInternal with err.
        events.entry(att.clone()).or_default().push(evt_with_err(
            att.clone(),
            Step::ParSigDBInternal,
            "parsigdb_internal failed",
        ));
        let r = analyse_failed(&att, &events, true).unwrap();
        assert_eq!(r.step, Step::ParSigDBInternal);
        assert_eq!(r.reason, REASON_BUG_PAR_SIG_DB_INTERNAL);

        // Failed at parsigEx with no error → NoPeerSignatures.
        events
            .entry(att.clone())
            .or_default()
            .push(evt(att.clone(), Step::ParSigEx));
        let r = analyse_failed(&att, &events, true).unwrap();
        assert_eq!(r.step, Step::ParSigEx);
        assert_eq!(r.reason, REASON_NO_PEER_SIGNATURES);

        // parsigDBExternal with err → BugParSigDBExternal.
        events.entry(att.clone()).or_default().push(evt_with_err(
            att.clone(),
            Step::ParSigDBExternal,
            "parsigdb_external failed",
        ));
        let r = analyse_failed(&att, &events, true).unwrap();
        assert_eq!(r.step, Step::ParSigDBExternal);
        assert_eq!(r.reason, REASON_BUG_PAR_SIG_DB_EXTERNAL);

        // parsigDBExternal with no err: three msg_root variants.
        events
            .entry(att.clone())
            .or_default()
            .push(evt(att.clone(), Step::ParSigDBExternal));
        let r = analyse_failed(&att, &events, true).unwrap();
        assert_eq!(r.step, Step::ParSigDBExternal);
        assert_eq!(r.reason, REASON_INSUFFICIENT_PEER_SIGNATURES);

        let r = analyse_failed(&att, &events, false).unwrap();
        assert_eq!(r.step, Step::ParSigDBExternal);
        assert_eq!(r.reason, REASON_BUG_PAR_SIG_DB_INCONSISTENT);

        // Sync-committee duty reuses the same events for the inconsistent case.
        let sync_msg = Duty::new_sync_message_duty(SlotNumber::new(1));
        events.insert(sync_msg.clone(), events.get(&att).cloned().unwrap());
        let r = analyse_failed(&sync_msg, &events, false).unwrap();
        assert_eq!(r.step, Step::ParSigDBExternal);
        assert_eq!(r.reason, REASON_PAR_SIG_DB_INCONSISTENT_SYNC);

        // Failed at bcast with err.
        events.entry(att.clone()).or_default().push(evt_with_err(
            att.clone(),
            Step::Bcast,
            "bcast failed",
        ));
        let r = analyse_failed(&att, &events, true).unwrap();
        assert_eq!(r.step, Step::Bcast);
        assert_eq!(r.reason, REASON_BROADCAST_BN_ERROR);

        // Failed at chainInclusion with err.
        events.entry(att.clone()).or_default().push(evt_with_err(
            att.clone(),
            Step::ChainInclusion,
            "not included on chain",
        ));
        let r = analyse_failed(&att, &events, true).unwrap();
        assert_eq!(r.step, Step::ChainInclusion);
        assert_eq!(r.reason, REASON_NOT_INCLUDED_ON_CHAIN);
    }

    #[test]
    fn analyse_duty_failed_proposer_via_randao() {
        let proposer = Duty::new_proposer_duty(SlotNumber::new(1));
        let randao = Duty::new_randao_duty(SlotNumber::new(1));

        let mut events: HashMap<Duty, Vec<Event>> = HashMap::new();
        events.insert(
            proposer.clone(),
            vec![evt_with_err(
                proposer.clone(),
                Step::Fetcher,
                "context canceled",
            )],
        );
        events.insert(
            randao.clone(),
            vec![
                evt(randao.clone(), Step::ValidatorAPI),
                evt(randao.clone(), Step::ParSigDBInternal),
                evt(randao.clone(), Step::ParSigEx),
            ],
        );

        // Randao reached ParSigEx → ProposerNoExternalRandaos.
        let r = analyse_failed(&proposer, &events, true).unwrap();
        assert_eq!(r.step, Step::Fetcher);
        assert_eq!(r.reason, REASON_PROPOSER_NO_EXTERNAL_RANDAOS);

        // Randao reached ParSigDBExternal → ProposerInsufficientRandaos.
        events
            .get_mut(&randao)
            .unwrap()
            .push(evt(randao.clone(), Step::ParSigDBExternal));
        let r = analyse_failed(&proposer, &events, true).unwrap();
        assert_eq!(r.reason, REASON_PROPOSER_INSUFFICIENT_RANDAOS);

        // No Randao events at all → ProposerZeroRandaos.
        events.insert(randao, vec![]);
        let r = analyse_failed(&proposer, &events, true).unwrap();
        assert_eq!(r.reason, REASON_PROPOSER_ZERO_RANDAOS);
    }

    #[test]
    fn analyse_duty_failed_attester_success() {
        let att = Duty::new_attester_duty(SlotNumber::new(1));
        assert_eq!(last_step(&att.duty_type, &FeatureSet::new()), Step::Bcast);

        // Events for every step up to (but not including) chainInclusion.
        let steps = [
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
        ];
        let events: HashMap<Duty, Vec<Event>> = std::iter::once((
            att.clone(),
            steps.iter().map(|s| evt(att.clone(), *s)).collect(),
        ))
        .collect();

        assert!(analyse_failed(&att, &events, true).is_none());
    }

    #[test]
    fn duty_failed_step_success_and_empty() {
        let att = Duty::new_attester_duty(SlotNumber::new(0));
        let steps = [
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
        ];
        let events: Vec<Event> = steps.iter().map(|s| evt(att.clone(), *s)).collect();

        let r = duty_failed_step(&events, &FeatureSet::new());
        assert!(!r.failed);
        assert_eq!(r.step, Step::Zero);
        assert!(r.err.is_none());

        let r = duty_failed_step(&[], &FeatureSet::new());
        assert!(r.failed);
        assert_eq!(r.step, Step::Zero);
        assert!(r.err.is_none());
    }

    #[test]
    fn duty_failed_step_picks_last_step_with_multiple_events() {
        // Many events per step, all carrying the same error → last step in
        // workflow order (bcast) is the failure point.
        let att = Duty::new_attester_duty(SlotNumber::new(123));
        let steps = [
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
        ];
        let mut events: Vec<Event> = Vec::new();
        for s in steps {
            for _ in 0..5 {
                events.push(evt_with_err(att.clone(), s, "test error"));
            }
        }

        let r = duty_failed_step(&events, &FeatureSet::new());
        assert!(r.failed);
        assert_eq!(r.step, Step::Bcast);
        assert!(r.err.is_some());

        // Now also append success (no-error) events for every step. The
        // newest event at the terminal step has no error → success.
        for s in steps {
            events.push(evt(att.clone(), s));
        }
        let r = duty_failed_step(&events, &FeatureSet::new());
        assert!(!r.failed);
        assert_eq!(r.step, Step::Zero);
        assert!(r.err.is_none());
    }

    #[test]
    fn analyse_fetcher_failed_table() {
        let slot = SlotNumber::new(123);
        let agg = Duty::new_aggregator_duty(slot);
        let prep_agg = Duty::new_prepare_aggregator_duty(slot);
        let att = Duty::new_attester_duty(slot);
        let sync_con = Duty::new_sync_contribution_duty(slot);
        let sync_msg = Duty::new_sync_message_duty(slot);
        let prep_sync_con = Duty::new_prepare_sync_contribution_duty(slot);

        struct Case {
            name: &'static str,
            duty: Duty,
            events: HashMap<Duty, Vec<Event>>,
            reason: Reason,
            failed: bool,
            has_err: bool,
        }

        let cases = vec![
            Case {
                name: "eth2 error",
                duty: att.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(
                        att.clone(),
                        vec![Event {
                            duty: att.clone(),
                            step: Step::Fetcher,
                            pubkey: pubkey(0),
                            step_err: Some(eth2_err()),
                            par_sig: None,
                        }],
                    );
                    m
                },
                reason: REASON_FETCH_BN_ERROR,
                failed: true,
                has_err: true,
            },
            Case {
                name: "no aggregator selections endpoint support",
                duty: agg.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(
                        agg.clone(),
                        vec![evt_with_err(agg.clone(), Step::Fetcher, "context canceled")],
                    );
                    m
                },
                reason: REASON_ZERO_AGGREGATOR_SELECTIONS,
                failed: true,
                has_err: true,
            },
            Case {
                name: "no external prepare-aggregator signatures",
                duty: agg.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(
                        agg.clone(),
                        vec![evt_with_err(agg.clone(), Step::Fetcher, "context canceled")],
                    );
                    m.insert(
                        prep_agg.clone(),
                        vec![evt(prep_agg.clone(), Step::ParSigEx)],
                    );
                    m
                },
                reason: REASON_NO_AGGREGATOR_SELECTIONS,
                failed: true,
                has_err: true,
            },
            Case {
                name: "insufficient prepare-aggregator signatures",
                duty: agg.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(
                        agg.clone(),
                        vec![evt_with_err(agg.clone(), Step::Fetcher, "context canceled")],
                    );
                    m.insert(
                        prep_agg.clone(),
                        vec![evt(prep_agg.clone(), Step::ParSigDBExternal)],
                    );
                    m
                },
                reason: REASON_INSUFFICIENT_AGGREGATOR_SELECTIONS,
                failed: true,
                has_err: true,
            },
            Case {
                name: "prepare-aggregator failed at sigAgg",
                duty: agg.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(
                        agg.clone(),
                        vec![evt_with_err(agg.clone(), Step::Fetcher, "context canceled")],
                    );
                    m.insert(prep_agg.clone(), vec![evt(prep_agg.clone(), Step::SigAgg)]);
                    m
                },
                reason: REASON_FAILED_AGGREGATOR_SELECTION,
                failed: true,
                has_err: true,
            },
            Case {
                name: "attester failed for aggregator",
                duty: agg.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(
                        agg.clone(),
                        vec![evt_with_err(agg.clone(), Step::Fetcher, "context canceled")],
                    );
                    m.insert(prep_agg.clone(), vec![evt(prep_agg.clone(), Step::Bcast)]);
                    m.insert(
                        att.clone(),
                        vec![evt_with_err(att.clone(), Step::Fetcher, "some error")],
                    );
                    m
                },
                reason: REASON_MISSING_AGGREGATOR_ATTESTATION,
                failed: true,
                has_err: true,
            },
            Case {
                name: "no aggregator found (nil err)",
                duty: agg.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(agg.clone(), vec![evt(agg.clone(), Step::Fetcher)]);
                    m.insert(prep_agg.clone(), vec![evt(prep_agg.clone(), Step::Bcast)]);
                    m.insert(att.clone(), vec![evt(att.clone(), Step::Bcast)]);
                    m
                },
                reason: REASON_UNKNOWN,
                failed: false,
                has_err: false,
            },
            Case {
                name: "sync committee selections endpoint not supported",
                duty: sync_con.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(
                        sync_con.clone(),
                        vec![evt_with_err(
                            sync_con.clone(),
                            Step::Fetcher,
                            "context canceled",
                        )],
                    );
                    m
                },
                reason: REASON_SYNC_CONTRIBUTION_ZERO_PREPARES,
                failed: true,
                has_err: true,
            },
            Case {
                name: "no external prepare-sync-contribution signatures",
                duty: sync_con.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(
                        sync_con.clone(),
                        vec![evt_with_err(
                            sync_con.clone(),
                            Step::Fetcher,
                            "context canceled",
                        )],
                    );
                    m.insert(
                        prep_sync_con.clone(),
                        vec![evt(prep_sync_con.clone(), Step::ParSigEx)],
                    );
                    m
                },
                reason: REASON_SYNC_CONTRIBUTION_NO_EXTERNAL_PREPARES,
                failed: true,
                has_err: true,
            },
            Case {
                name: "insufficient prepare-sync-contribution",
                duty: sync_con.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(
                        sync_con.clone(),
                        vec![evt_with_err(
                            sync_con.clone(),
                            Step::Fetcher,
                            "context canceled",
                        )],
                    );
                    m.insert(
                        prep_sync_con.clone(),
                        vec![evt(prep_sync_con.clone(), Step::ParSigDBExternal)],
                    );
                    m
                },
                reason: REASON_SYNC_CONTRIBUTION_FEW_PREPARES,
                failed: true,
                has_err: true,
            },
            Case {
                name: "prepare-sync-contribution failed",
                duty: sync_con.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(
                        sync_con.clone(),
                        vec![evt_with_err(
                            sync_con.clone(),
                            Step::Fetcher,
                            "context canceled",
                        )],
                    );
                    m.insert(
                        prep_sync_con.clone(),
                        vec![evt(prep_sync_con.clone(), Step::SigAgg)],
                    );
                    m
                },
                reason: REASON_SYNC_CONTRIBUTION_FAILED_PREPARE,
                failed: true,
                has_err: true,
            },
            Case {
                name: "sync-message failed for sync-contribution",
                duty: sync_con.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(
                        sync_con.clone(),
                        vec![evt_with_err(
                            sync_con.clone(),
                            Step::Fetcher,
                            "context canceled",
                        )],
                    );
                    m.insert(
                        prep_sync_con.clone(),
                        vec![evt(prep_sync_con.clone(), Step::Bcast)],
                    );
                    m.insert(
                        sync_msg.clone(),
                        vec![evt(sync_msg.clone(), Step::ParSigEx)],
                    );
                    m
                },
                reason: REASON_SYNC_CONTRIBUTION_NO_SYNC_MSG,
                failed: true,
                has_err: true,
            },
            Case {
                name: "no sync-committee aggregators (nil err)",
                duty: sync_con.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(sync_con.clone(), vec![evt(sync_con.clone(), Step::Fetcher)]);
                    m.insert(
                        prep_sync_con.clone(),
                        vec![evt(prep_sync_con.clone(), Step::Bcast)],
                    );
                    m.insert(sync_msg.clone(), vec![evt(sync_msg.clone(), Step::Bcast)]);
                    m
                },
                reason: REASON_UNKNOWN,
                failed: false,
                has_err: false,
            },
            Case {
                name: "unexpected error",
                duty: att.clone(),
                events: {
                    let mut m = HashMap::new();
                    m.insert(
                        att.clone(),
                        vec![evt_with_err(att.clone(), Step::Fetcher, "unexpected error")],
                    );
                    m
                },
                reason: REASON_BUG_FETCH_ERROR,
                failed: true,
                has_err: true,
            },
        ];

        for c in cases {
            let r = analyse_failed(&c.duty, &c.events, true);
            assert_eq!(r.is_some(), c.failed, "{}: failed mismatch", c.name);
            if let Some(f) = r {
                assert_eq!(f.reason, c.reason, "{}: reason mismatch", c.name);
                assert_eq!(f.step, Step::Fetcher, "{}: step mismatch", c.name);
                assert_eq!(f.err.is_some(), c.has_err, "{}: err presence", c.name);
            } else {
                // Not-failed fetcher cases (no aggregator/sync selected this
                // slot) must surface as `Step::Fetcher` so the metrics reporter
                // skips them rather than counting a success.
                assert_eq!(
                    duty_failed_step(&c.events[&c.duty], &FeatureSet::new()).step,
                    Step::Fetcher,
                    "{}: expected fetcher no-op step",
                    c.name
                );
            }
        }
    }

    #[test]
    fn is_par_sig_event_expected_table() {
        let slot = SlotNumber::new(123);
        let pk = pubkey(7);

        // DutyExit and DutyBuilderRegistration always expected.
        assert!(is_par_sig_event_expected(
            &Duty::new_voluntary_exit_duty(slot),
            pk,
            &HashMap::new()
        ));
        assert!(is_par_sig_event_expected(
            &Duty::new_builder_registration_duty(slot),
            pk,
            &HashMap::new()
        ));

        // Randao expected when proposer is scheduled with matching pubkey.
        let mut events: HashMap<Duty, Vec<Event>> = HashMap::new();
        let proposer = Duty::new_proposer_duty(slot);
        events.insert(
            proposer.clone(),
            vec![evt_pubkey(proposer, Step::Fetcher, pk)],
        );
        assert!(is_par_sig_event_expected(
            &Duty::new_randao_duty(slot),
            pk,
            &events
        ));

        // Randao unexpected without proposer.
        assert!(!is_par_sig_event_expected(
            &Duty::new_randao_duty(slot),
            pk,
            &HashMap::new()
        ));

        // PrepareAggregator expected when attester scheduled.
        let mut events: HashMap<Duty, Vec<Event>> = HashMap::new();
        let attester = Duty::new_attester_duty(slot);
        events.insert(
            attester.clone(),
            vec![evt_pubkey(attester, Step::Fetcher, pk)],
        );
        assert!(is_par_sig_event_expected(
            &Duty::new_prepare_aggregator_duty(slot),
            pk,
            &events
        ));

        // PrepareAggregator unexpected without attester.
        assert!(!is_par_sig_event_expected(
            &Duty::new_prepare_aggregator_duty(slot),
            pk,
            &HashMap::new()
        ));

        // PrepareSyncContribution / SyncMessage expected when SyncContribution
        // scheduled.
        let mut events: HashMap<Duty, Vec<Event>> = HashMap::new();
        let sc = Duty::new_sync_contribution_duty(slot);
        events.insert(sc.clone(), vec![evt_pubkey(sc, Step::Fetcher, pk)]);
        assert!(is_par_sig_event_expected(
            &Duty::new_prepare_sync_contribution_duty(slot),
            pk,
            &events
        ));
        assert!(is_par_sig_event_expected(
            &Duty::new_sync_message_duty(slot),
            pk,
            &events
        ));

        // SyncMessage and PrepareSyncContribution unexpected without
        // SyncContribution.
        assert!(!is_par_sig_event_expected(
            &Duty::new_sync_message_duty(slot),
            pk,
            &HashMap::new()
        ));
        assert!(!is_par_sig_event_expected(
            &Duty::new_prepare_sync_contribution_duty(slot),
            pk,
            &HashMap::new()
        ));
    }

    #[test]
    fn extract_par_sigs_empty() {
        assert!(extract_par_sigs(&[]).is_empty());
    }

    #[test]
    fn extract_par_sigs_groups_by_msg_root_per_pubkey() {
        // Mirrors Go's TestAnalyseParSigs: pubkey "a" gets two batches with
        // distinct message roots (4 sigs and 2 sigs), pubkey "b" gets one
        // batch (6 sigs). Result is keyed by pubkey then by root.
        let att = Duty::new_attester_duty(SlotNumber::new(0));
        let pk_a = pubkey(1);
        let pk_b = pubkey(2);

        // Build events: each event has a unique share_idx (so dedup keeps
        // all of them) and shares the message root within the batch.
        let mut events: Vec<Event> = Vec::new();
        let mut next_idx: u64 = 0;

        // pk_a, root=A, 4 sigs.
        let data_a = TestSignedData::new(0xAA);
        for _ in 0..4 {
            events.push(Event {
                duty: att.clone(),
                step: Step::ParSigDBExternal,
                pubkey: pk_a,
                step_err: None,
                par_sig: Some(ParSignedData::new(data_a.clone(), next_idx)),
            });
            next_idx = next_idx.checked_add(1).unwrap();
        }

        // pk_a, root=B, 2 sigs.
        let data_b = TestSignedData::new(0xBB);
        for _ in 0..2 {
            events.push(Event {
                duty: att.clone(),
                step: Step::ParSigDBExternal,
                pubkey: pk_a,
                step_err: None,
                par_sig: Some(ParSignedData::new(data_b.clone(), next_idx)),
            });
            next_idx = next_idx.checked_add(1).unwrap();
        }

        // pk_b, root=C, 6 sigs.
        let data_c = TestSignedData::new(0xCC);
        for _ in 0..6 {
            events.push(Event {
                duty: att.clone(),
                step: Step::ParSigDBExternal,
                pubkey: pk_b,
                step_err: None,
                par_sig: Some(ParSignedData::new(data_c.clone(), next_idx)),
            });
            next_idx = next_idx.checked_add(1).unwrap();
        }

        let result = extract_par_sigs(&events);

        // pk_a has two roots, pk_b has one.
        assert_eq!(result.len(), 2);
        let a_groups = result.get(&pk_a).expect("pk_a missing");
        let b_groups = result.get(&pk_b).expect("pk_b missing");
        assert_eq!(a_groups.len(), 2);
        assert_eq!(b_groups.len(), 1);

        let mut a_sizes: Vec<usize> = a_groups.values().map(Vec::len).collect();
        a_sizes.sort_unstable();
        assert_eq!(a_sizes, vec![2, 4]);

        let b_sizes: Vec<usize> = b_groups.values().map(Vec::len).collect();
        assert_eq!(b_sizes, vec![6]);

        // Inconsistent: pk_a has more than one root, pk_b has just one.
        assert!(!msg_roots_consistent(&result));
    }

    #[test]
    fn extract_par_sigs_dedups_by_pubkey_and_share_idx() {
        // Two events with the same (pubkey, share_idx) → deduped down to one
        // entry, regardless of differing signature content.
        let att = Duty::new_attester_duty(SlotNumber::new(0));
        let pk = pubkey(1);
        let data = TestSignedData::new(0xAA);

        let events = vec![
            Event {
                duty: att.clone(),
                step: Step::ParSigDBExternal,
                pubkey: pk,
                step_err: None,
                par_sig: Some(ParSignedData::new(data.clone(), 0)),
            },
            Event {
                duty: att,
                step: Step::ParSigDBExternal,
                pubkey: pk,
                step_err: None,
                par_sig: Some(ParSignedData::new(data, 0)),
            },
        ];
        let result = extract_par_sigs(&events);
        let groups = result.get(&pk).unwrap();
        let total: usize = groups.values().map(Vec::len).sum();
        assert_eq!(total, 1);
    }

    #[test]
    fn analyse_duty_failed_unexpected_failures() {
        let att = Duty::new_attester_duty(SlotNumber::new(123));

        // consensus with nil error → REASON_UNKNOWN (Go's reasonUnknown).
        let mut events = HashMap::new();
        events.insert(att.clone(), vec![evt(att.clone(), Step::Consensus)]);
        let r = analyse_failed(&att, &events, false).unwrap();
        assert_eq!(r.step, Step::Consensus);
        assert_eq!(r.reason, REASON_UNKNOWN);
        assert!(r.err.is_none());

        // parsigex with error → REASON_UNKNOWN (err.is_none() branch missed).
        let mut events = HashMap::new();
        events.insert(
            att.clone(),
            vec![evt_with_err(
                att.clone(),
                Step::ParSigEx,
                "parsigex broadcast err",
            )],
        );
        let r = analyse_failed(&att, &events, false).unwrap();
        assert_eq!(r.step, Step::ParSigEx);
        assert_eq!(r.reason, REASON_UNKNOWN);
        assert!(r.err.is_some());

        // sigAgg with nil error → REASON_UNKNOWN.
        let mut events = HashMap::new();
        events.insert(att.clone(), vec![evt(att.clone(), Step::SigAgg)]);
        let r = analyse_failed(&att, &events, false).unwrap();
        assert_eq!(r.step, Step::SigAgg);
        assert_eq!(r.reason, REASON_UNKNOWN);
        assert!(r.err.is_none());
    }
}
