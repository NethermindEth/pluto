//! QBFT definition callbacks.

use std::{sync::Arc, time};

use crate::{instance::RECV_BUFFER_SIZE, timer::RoundTimer};
use crossbeam::channel as mpmc;
use pluto_core::{
    qbft::{self, QbftLogger},
    signeddata::AttestationData as CoreAttestationData,
    types::{Duty, DutyType, PubKey},
    unsigneddata::{UnsignedDataSet, UnsignedDutyData, unsigned_data_set_from_proto},
};
use prost_types::Any;
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;

use super::{
    component::{DecodedValue, Error as ComponentError, SubscriberSet, decode_supported_any},
    msg::{self, ConsensusQbftTypes},
};

/// Callback invoked with the decided commit quorum.
pub(crate) type DecideCallback =
    Arc<dyn Fn(Vec<qbft::Msg<ConsensusQbftTypes>>) + Send + Sync + 'static>;

/// Definition constructor config.
pub(crate) struct DefinitionConfig {
    /// Number of QBFT participants.
    pub(crate) nodes: usize,
    /// Subscriber registry notified after decode.
    pub(crate) subscribers: SubscriberSet,
    /// Round timer for this consensus instance.
    pub(crate) round_timer: Box<dyn RoundTimer>,
    /// Internal callback invoked when the core decides.
    pub(crate) decide_callback: DecideCallback,
    /// Whether attester proposal comparison is enabled.
    pub(crate) compare_attestations: bool,
    /// Runtime used to host timer futures for the blocking QBFT core.
    pub(crate) runtime: Handle,
}

/// Returns a QBFT core definition for one consensus instance.
pub(crate) fn new_definition(config: DefinitionConfig) -> qbft::Definition<ConsensusQbftTypes> {
    let nodes = i64::try_from(config.nodes).expect("node count fits i64");
    let quorum = usize::try_from(qbft::quorum(nodes)).expect("quorum fits usize");
    let round_timer: Arc<dyn RoundTimer> = Arc::from(config.round_timer);
    let compare_attestations = config.compare_attestations;
    let subscribers = config.subscribers;
    let decide_callback = config.decide_callback;

    qbft::Definition {
        is_leader: Box::new(move |request| {
            leader(request.instance, request.round, nodes) == request.process
        }),
        new_timer: Box::new({
            let runtime = config.runtime;
            move |round| new_timer(Arc::clone(&round_timer), runtime.clone(), round)
        }),
        compare: Arc::new(move |request| compare(compare_attestations, request)),
        decide: Box::new(move |request| {
            decide(request, Arc::clone(&decide_callback), subscribers.clone());
        }),
        logger: QbftLogger {
            upon_rule: Box::new(|log| {
                tracing::debug!(
                    duty = %log.instance,
                    process = log.process,
                    rule = %log.upon_rule,
                    round = log.round,
                    "QBFT upon rule triggered"
                );
            }),
            round_change: Box::new(move |log| {
                let leader = usize::try_from(leader(log.instance, log.round, nodes))
                    .expect("leader index fits usize");
                let steps = group_round_messages(log.msgs, config.nodes, log.round, leader);
                let pre_prepare = fmt_step_peers(step_by_type(&steps, qbft::MSG_PRE_PREPARE));
                let prepare = fmt_step_peers(step_by_type(&steps, qbft::MSG_PREPARE));
                let commit = fmt_step_peers(step_by_type(&steps, qbft::MSG_COMMIT));
                let round_change = fmt_step_peers(step_by_type(&steps, qbft::MSG_ROUND_CHANGE));

                if log.upon_rule == qbft::UPON_ROUND_TIMEOUT {
                    tracing::debug!(
                        duty = %log.instance,
                        process = log.process,
                        rule = %log.upon_rule,
                        round = log.round,
                        new_round = log.new_round,
                        pre_prepare,
                        prepare,
                        commit,
                        round_change,
                        timeout_reason = %timeout_reason(&steps, log.round, quorum),
                        "QBFT round changed"
                    );
                } else {
                    tracing::debug!(
                        duty = %log.instance,
                        process = log.process,
                        rule = %log.upon_rule,
                        round = log.round,
                        new_round = log.new_round,
                        pre_prepare,
                        prepare,
                        commit,
                        round_change,
                        "QBFT round changed"
                    );
                }
            }),
            unjust: Box::new(|log| {
                tracing::warn!(
                    duty = %log.instance,
                    process = log.process,
                    type = %log.msg.type_(),
                    peer = log.msg.source(),
                    "Unjustified consensus message from peer"
                );
            }),
        },
        nodes,
        fifo_limit: i64::try_from(RECV_BUFFER_SIZE).expect("receive buffer size fits i64"),
    }
}

/// Handles a QBFT core decision by decoding the decided value and notifying
/// listeners.
fn decide(
    request: qbft::DecideRequest<'_, ConsensusQbftTypes>,
    decide_callback: DecideCallback,
    subscribers: SubscriberSet,
) {
    let Some(qcommit_msg) = request.qcommit.first() else {
        tracing::error!("Invalid message type");
        return;
    };

    let Some(msg) = qcommit_msg.as_any().downcast_ref::<msg::Msg>() else {
        tracing::error!("Invalid message type");
        return;
    };

    let Some(any_value) = msg.values().get(request.value) else {
        tracing::error!("Invalid value hash");
        return;
    };

    let decoded = match decode_supported_any(any_value) {
        Ok(decoded) => decoded,
        Err(err) => {
            tracing::error!(error = %err, "Invalid any value");
            return;
        }
    };

    decide_callback(request.qcommit.clone());
    subscribers.dispatch_decoded(request.instance, &decoded);
}

/// Compares proposal values before commit when attester comparison is enabled.
fn compare(compare_attestations: bool, request: qbft::CompareRequest<'_, ConsensusQbftTypes>) {
    if !compare_attestations || request.qcommit.instance().duty_type != DutyType::Attester {
        let _ = request.return_err.send(Ok(()));
        return;
    }

    let result = compare_attester(&request).map_err(|err| {
        tracing::warn!(error = %err, "QBFT attester compare failed");
        qbft::QbftError::CompareError
    });
    let _ = request.return_err.send(result);
}

/// Compares the leader's attestation source/target with the local value.
fn compare_attester(
    request: &qbft::CompareRequest<'_, ConsensusQbftTypes>,
) -> std::result::Result<(), AttesterCompareError> {
    let leader_any = request
        .qcommit
        .value_source()
        .map_err(AttesterCompareError::ValueSource)?;
    let leader = decode_attester_set(&leader_any)?;
    let local_any = local_compare_value(request)?;
    let local = decode_attester_set(&local_any)?;

    for (pubkey, leader_data) in &leader {
        let leader_data = attestation_data(leader_data)?;
        let Some(local_data) = local.get(pubkey) else {
            tracing::warn!(pubkey = %pubkey, "No local attestation found, skipping");
            continue;
        };
        let local_data = attestation_data(local_data)?;

        if leader_data.data.source.epoch != local_data.data.source.epoch {
            return Err(attestation_mismatch(pubkey, "source epoch"));
        }
        if leader_data.data.source.root != local_data.data.source.root {
            return Err(attestation_mismatch(pubkey, "source root"));
        }
        if leader_data.data.target.epoch != local_data.data.target.epoch {
            return Err(attestation_mismatch(pubkey, "target epoch"));
        }
        if leader_data.data.target.root != local_data.data.target.root {
            return Err(attestation_mismatch(pubkey, "target root"));
        }
    }

    Ok(())
}

/// Returns the cached local compare value or waits for the runner-provided one.
fn local_compare_value(
    request: &qbft::CompareRequest<'_, ConsensusQbftTypes>,
) -> std::result::Result<Any, AttesterCompareError> {
    // The generic QBFT core uses `T::Compare::default()` as the "not cached"
    // sentinel. For this adapter that is `Any::default()`.
    if request.input_value_source != &Any::default() {
        return Ok(request.input_value_source.clone());
    }

    let (cancel_tx, cancel_rx) = mpmc::bounded(1);

    request.ct.run(
        move || {
            let _ = cancel_tx.try_send(());
        },
        || {
            mpmc::select! {
                recv(request.input_value_source_ch) -> msg => {
                    let value = msg.map_err(|_| AttesterCompareError::LocalValueChannelClosed)?;
                    let _ = request.return_value.send(value.clone());
                    Ok(value)
                },
                recv(cancel_rx) -> _ => Err(AttesterCompareError::TimeoutWaitingLocalValue),
            }
        },
    )
}

fn decode_attester_set(any: &Any) -> std::result::Result<UnsignedDataSet, AttesterCompareError> {
    match decode_supported_any(any).map_err(AttesterCompareError::DecodeAny)? {
        DecodedValue::UnsignedDataSet(value) => {
            unsigned_data_set_from_proto(&DutyType::Attester, &value)
                .map_err(AttesterCompareError::DecodeUnsignedDataSet)
        }
        DecodedValue::PriorityResult(_) => Err(AttesterCompareError::UnexpectedValueType),
    }
}

fn attestation_data(
    data: &UnsignedDutyData,
) -> std::result::Result<&CoreAttestationData, AttesterCompareError> {
    match data {
        UnsignedDutyData::Attestation(data) => Ok(data),
        _ => Err(AttesterCompareError::UnexpectedUnsignedDataType),
    }
}

fn attestation_mismatch(pubkey: &PubKey, field: &'static str) -> AttesterCompareError {
    AttesterCompareError::AttestationMismatch {
        pubkey: pubkey.to_string(),
        field,
    }
}

#[derive(Debug, thiserror::Error)]
enum AttesterCompareError {
    #[error("msg has no value source: {0}")]
    ValueSource(#[source] qbft::QbftError),
    #[error("decode any: {0}")]
    DecodeAny(#[source] ComponentError),
    #[error("unexpected compare value type")]
    UnexpectedValueType,
    #[error("timeout on waiting for local value")]
    TimeoutWaitingLocalValue,
    #[error("local value channel closed")]
    LocalValueChannelClosed,
    #[error("decode unsigned data set: {0}")]
    DecodeUnsignedDataSet(#[source] pluto_core::ParSigExCodecError),
    #[error("unexpected unsigned data type")]
    UnexpectedUnsignedDataType,
    #[error("leader attestation {field} differs from local {field}; public_key={pubkey}")]
    AttestationMismatch { pubkey: String, field: &'static str },
}

/// Adapts an async round timer future into the blocking QBFT core timer type.
fn new_timer(round_timer: Arc<dyn RoundTimer>, runtime: Handle, round: i64) -> qbft::Timer {
    let (timer_tx, timer_rx) = mpmc::bounded(1);
    let timer = match round_timer.timer(round) {
        Ok(timer) => timer,
        Err(err) => {
            tracing::warn!(round, error = %err, "QBFT round timer construction failed");
            drop(timer_tx);
            return qbft::Timer {
                receive: timer_rx,
                stop: Box::new(|| {}),
            };
        }
    };

    let ct = CancellationToken::new();
    let task_ct = ct.clone();
    runtime.spawn(async move {
        tokio::select! {
            () = task_ct.cancelled() => {}
            _ = timer => {
                let _ = timer_tx.send(time::Instant::now());
            }
        }
    });

    qbft::Timer {
        receive: timer_rx,
        stop: Box::new(move || ct.cancel()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoundStep {
    type_: qbft::MessageType,
    present: Vec<usize>,
    missing: Vec<usize>,
    peers: usize,
}

/// Groups received round messages by protocol step for timeout diagnostics.
fn group_round_messages(
    msgs: &[qbft::Msg<ConsensusQbftTypes>],
    peers: usize,
    round: i64,
    leader: usize,
) -> Vec<RoundStep> {
    [
        qbft::MSG_PRE_PREPARE,
        qbft::MSG_PREPARE,
        qbft::MSG_COMMIT,
        qbft::MSG_ROUND_CHANGE,
    ]
    .into_iter()
    .map(|type_| {
        let (present, missing) = check_peers(msgs, peers, round, leader, type_);
        RoundStep {
            type_,
            present,
            missing,
            peers,
        }
    })
    .collect()
}

/// Returns present and missing peers for a round step.
fn check_peers(
    msgs: &[qbft::Msg<ConsensusQbftTypes>],
    peers: usize,
    round: i64,
    leader: usize,
    type_: qbft::MessageType,
) -> (Vec<usize>, Vec<usize>) {
    let mut present = vec![];
    let mut missing = vec![];

    for peer in 0..peers {
        let peer_idx = i64::try_from(peer).expect("peer index fits i64");
        let included = msgs
            .iter()
            .any(|msg| msg.type_() == type_ && msg.source() == peer_idx);

        if included {
            present.push(peer);
            continue;
        }

        if type_ == qbft::MSG_PRE_PREPARE && peer != leader {
            continue;
        }

        if type_ == qbft::MSG_ROUND_CHANGE && round == 1 {
            continue;
        }

        missing.push(peer);
    }

    (present, missing)
}

/// Returns the most specific timeout reason visible from round message state.
fn timeout_reason(steps: &[RoundStep], round: i64, quorum: usize) -> String {
    if round > 1 {
        let step = step_by_type(steps, qbft::MSG_ROUND_CHANGE);
        if step.present.len() < quorum {
            return format!(
                "insufficient round-changes, missing peers={}",
                fmt_peer_list(&step.missing)
            );
        }
    }

    let step = step_by_type(steps, qbft::MSG_PRE_PREPARE);
    if step.present.is_empty() {
        return format!(
            "no pre-prepare, missing leader={}",
            fmt_peer_list(&step.missing)
        );
    }

    let step = step_by_type(steps, qbft::MSG_PREPARE);
    if step.present.len() < quorum {
        return format!(
            "insufficient prepares, missing peers={}",
            fmt_peer_list(&step.missing)
        );
    }

    let step = step_by_type(steps, qbft::MSG_COMMIT);
    if step.present.len() < quorum {
        return format!(
            "insufficient commits, missing peers={}",
            fmt_peer_list(&step.missing)
        );
    }

    "unknown reason".to_string()
}

/// Finds the diagnostic record for a message type.
fn step_by_type(steps: &[RoundStep], type_: qbft::MessageType) -> &RoundStep {
    steps
        .iter()
        .find(|step| step.type_ == type_)
        .expect("round step type exists")
}

/// Formats a round step as a compact peer bitmap for logs.
fn fmt_step_peers(step: &RoundStep) -> String {
    let mut out = vec!["_"; step.peers];

    for peer in &step.present {
        out[*peer] = "*";
    }

    for peer in &step.missing {
        out[*peer] = "?";
    }

    out.join("")
}

/// Formats peer indices for timeout reason strings.
fn fmt_peer_list(peers: &[usize]) -> String {
    format!(
        "[{}]",
        peers
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    )
}

/// Returns the deterministic leader index for a duty and round.
pub(crate) fn leader(duty: &Duty, round: i64, nodes: i64) -> i64 {
    debug_assert!(nodes > 0);

    let duty_type = match i32::try_from(&duty.duty_type) {
        Ok(value) => value,
        Err(_) => i32::try_from(&DutyType::Unknown).expect("unknown duty type maps to i32"),
    };

    let total = i128::from(duty.slot.inner())
        .checked_add(i128::from(duty_type))
        .and_then(|value| value.checked_add(i128::from(round)))
        .expect("slot, duty type, and round fit i128");
    let nodes = i128::from(nodes);

    i64::try_from(total.rem_euclid(nodes)).expect("leader index fits i64")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    use pluto_eth2api::spec::phase0;
    use prost::{Message, bytes::Bytes};
    use prost_types::Any;
    use ssz::Encode;
    use test_case::test_case;

    use super::*;
    use crate::qbft::{component, msg};
    use pluto_core::{
        corepb::v1::{consensus as pbconsensus, core as pbcore},
        types::{Duty, DutyType, SlotNumber},
    };

    const ATTESTATION_DATA_SSZ_OFFSET: usize = 8;
    const ATTESTER_DUTY_SSZ_SIZE: usize = 96;

    #[test_case(0, DutyType::Attester, 1, 4, 3 ; "attester_round_1")]
    #[test_case(42, DutyType::Attester, 1, 4, 1 ; "slot_42_attester")]
    #[test_case(42, DutyType::Proposer, 3, 4, 2 ; "slot_42_proposer_round_3")]
    #[test_case(10, DutyType::SyncContribution, 2, 7, 3 ; "sync_contribution")]
    fn leader_matches_go_formula(
        slot: u64,
        duty_type: DutyType,
        round: i64,
        nodes: i64,
        want: i64,
    ) {
        let duty = Duty::new(SlotNumber::new(slot), duty_type);

        assert_eq!(leader(&duty, round, nodes), want);
    }

    #[test]
    fn group_round_messages_marks_present_and_missing_peers() {
        let msgs = vec![
            test_msg(qbft::MSG_PRE_PREPARE, 1, 2),
            test_msg(qbft::MSG_PREPARE, 0, 2),
            test_msg(qbft::MSG_PREPARE, 2, 2),
            test_msg(qbft::MSG_COMMIT, 3, 2),
            test_msg(qbft::MSG_ROUND_CHANGE, 0, 2),
        ];

        let steps = group_round_messages(&msgs, 4, 2, 1);

        assert_eq!(
            steps,
            vec![
                RoundStep {
                    type_: qbft::MSG_PRE_PREPARE,
                    present: vec![1],
                    missing: vec![],
                    peers: 4,
                },
                RoundStep {
                    type_: qbft::MSG_PREPARE,
                    present: vec![0, 2],
                    missing: vec![1, 3],
                    peers: 4,
                },
                RoundStep {
                    type_: qbft::MSG_COMMIT,
                    present: vec![3],
                    missing: vec![0, 1, 2],
                    peers: 4,
                },
                RoundStep {
                    type_: qbft::MSG_ROUND_CHANGE,
                    present: vec![0],
                    missing: vec![1, 2, 3],
                    peers: 4,
                },
            ]
        );
    }

    #[test]
    fn group_round_messages_ignores_round_change_missing_peers_in_round_one() {
        let steps = group_round_messages(&[], 4, 1, 1);

        let round_change = step_by_type(&steps, qbft::MSG_ROUND_CHANGE);

        assert!(round_change.present.is_empty());
        assert!(round_change.missing.is_empty());
    }

    #[test_case(
        vec![
            step(qbft::MSG_ROUND_CHANGE, vec![0, 1], vec![2, 3]),
            step(qbft::MSG_PRE_PREPARE, vec![1], vec![]),
            step(qbft::MSG_PREPARE, vec![0, 1, 2], vec![3]),
            step(qbft::MSG_COMMIT, vec![0, 1, 2], vec![3]),
        ],
        2,
        3,
        "insufficient round-changes, missing peers=[2 3]" ;
        "insufficient_round_changes"
    )]
    #[test_case(
        vec![
            step(qbft::MSG_PRE_PREPARE, vec![], vec![1]),
            step(qbft::MSG_PREPARE, vec![0, 1, 2], vec![3]),
            step(qbft::MSG_COMMIT, vec![0, 1, 2], vec![3]),
            step(qbft::MSG_ROUND_CHANGE, vec![], vec![]),
        ],
        1,
        3,
        "no pre-prepare, missing leader=[1]" ;
        "no_preprepare"
    )]
    #[test_case(
        vec![
            step(qbft::MSG_PRE_PREPARE, vec![1], vec![]),
            step(qbft::MSG_PREPARE, vec![0, 1], vec![2, 3]),
            step(qbft::MSG_COMMIT, vec![0, 1, 2], vec![3]),
            step(qbft::MSG_ROUND_CHANGE, vec![], vec![]),
        ],
        1,
        3,
        "insufficient prepares, missing peers=[2 3]" ;
        "insufficient_prepares"
    )]
    #[test_case(
        vec![
            step(qbft::MSG_PRE_PREPARE, vec![1], vec![]),
            step(qbft::MSG_PREPARE, vec![0, 1, 2], vec![3]),
            step(qbft::MSG_COMMIT, vec![0, 1], vec![2, 3]),
            step(qbft::MSG_ROUND_CHANGE, vec![], vec![]),
        ],
        1,
        3,
        "insufficient commits, missing peers=[2 3]" ;
        "insufficient_commits"
    )]
    #[test_case(
        vec![
            step(qbft::MSG_PRE_PREPARE, vec![1], vec![]),
            step(qbft::MSG_PREPARE, vec![0, 1, 2], vec![3]),
            step(qbft::MSG_COMMIT, vec![0, 1, 2], vec![3]),
            step(qbft::MSG_ROUND_CHANGE, vec![], vec![]),
        ],
        1,
        3,
        "unknown reason" ;
        "unknown"
    )]
    fn timeout_reason_matches_go_order(
        steps: Vec<RoundStep>,
        round: i64,
        quorum: usize,
        want: &str,
    ) {
        assert_eq!(timeout_reason(&steps, round, quorum), want);
    }

    #[test]
    fn fmt_step_peers_renders_present_missing_and_absent_markers() {
        let step = RoundStep {
            type_: qbft::MSG_PREPARE,
            present: vec![0, 2],
            missing: vec![3],
            peers: 5,
        };

        assert_eq!(fmt_step_peers(&step), "*_*?_");
    }

    #[tokio::test]
    async fn new_definition_decide_dispatches_decoded_value_and_callback() {
        let consensus = component::tests::consensus(0, true);
        let duty = component::tests::duty();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let callback_called = Arc::new(AtomicBool::new(false));

        {
            let observed = Arc::clone(&observed);
            consensus.subscribe(move |duty, value| {
                observed.lock().unwrap().push((duty, value));
                Ok(())
            });
        }

        let def = new_definition(DefinitionConfig {
            nodes: consensus.node_count(),
            subscribers: consensus.subscribers(),
            round_timer: consensus.round_timer(duty.clone()),
            decide_callback: {
                let callback_called = Arc::clone(&callback_called);
                Arc::new(move |qcommit| {
                    assert_eq!(qcommit.len(), 1);
                    callback_called.store(true, Ordering::Relaxed);
                })
            },
            compare_attestations: false,
            runtime: tokio::runtime::Handle::current(),
        });
        let value = unsigned_value();
        let hash = msg::hash_proto(&value).unwrap();
        let qcommit = vec![commit_msg(duty.clone(), hash, any_unsigned(&value))];
        let cts = cancellation::CancellationTokenSource::new();
        let ct = cts.token().clone();

        (def.decide)(qbft::DecideRequest {
            ct: &ct,
            instance: &duty,
            value: &hash,
            qcommit: &qcommit,
        });

        assert!(callback_called.load(Ordering::Relaxed));
        assert_eq!(observed.lock().unwrap().as_slice(), [(duty, value)]);
    }

    #[test_case(false, DutyType::Attester, Ok(()) ; "disabled_attester")]
    #[test_case(true, DutyType::Proposer, Ok(()) ; "enabled_non_attester")]
    fn compare_accepts_disabled_or_non_attester(
        compare_attestations: bool,
        duty_type: DutyType,
        want: Result<(), qbft::QbftError>,
    ) {
        let result = run_compare(compare_attestations, duty_type);

        assert!(matches!((result, want), (Ok(()), Ok(()))));
    }

    #[test]
    fn compare_attester_accepts_matching_source_target() {
        let leader = unsigned_attestation_set(&pubkey(1), attestation_data());
        let local = leader.clone();

        let result = run_compare_attester(leader, Some(any_unsigned(&local)), Any::default());

        assert!(matches!(result, Ok(())));
    }

    #[test_case(
        |data: &mut phase0::AttestationData| data.source.epoch = 2 ;
        "source_epoch"
    )]
    #[test_case(
        |data: &mut phase0::AttestationData| data.source.root = [3; 32] ;
        "source_root"
    )]
    #[test_case(
        |data: &mut phase0::AttestationData| data.target.epoch = 4 ;
        "target_epoch"
    )]
    #[test_case(
        |data: &mut phase0::AttestationData| data.target.root = [5; 32] ;
        "target_root"
    )]
    fn compare_attester_rejects_source_target_mismatch(mutate: fn(&mut phase0::AttestationData)) {
        let pubkey = pubkey(1);
        let leader = unsigned_attestation_set(&pubkey, attestation_data());
        let mut local_data = attestation_data();
        mutate(&mut local_data);
        let local = unsigned_attestation_set(&pubkey, local_data);

        let result = run_compare_attester(leader, Some(any_unsigned(&local)), Any::default());

        assert!(matches!(result, Err(qbft::QbftError::CompareError)));
    }

    #[test]
    fn compare_attester_skips_missing_local_attestation() {
        let leader = unsigned_attestation_set(&pubkey(1), attestation_data());
        let local = unsigned_attestation_set(&pubkey(2), changed_attestation_data());

        let result = run_compare_attester(leader, Some(any_unsigned(&local)), Any::default());

        assert!(matches!(result, Ok(())));
    }

    #[test]
    fn compare_attester_waits_for_local_value_and_returns_cache() {
        let leader = unsigned_attestation_set(&pubkey(1), attestation_data());
        let local = any_unsigned(&leader);
        let cts = cancellation::CancellationTokenSource::new();
        let ct = cts.token().clone();
        let qcommit = qcommit_for_value(component::tests::duty(), any_unsigned(&leader));
        let (input_tx, input_rx) = mpmc::bounded(1);
        input_tx.send(local.clone()).unwrap();
        let (return_err_tx, return_err_rx) = mpmc::bounded(1);
        let (return_value_tx, return_value_rx) = mpmc::bounded(1);
        let input_value = Any::default();

        compare(
            true,
            qbft::CompareRequest {
                ct: &ct,
                qcommit: &qcommit,
                input_value_source_ch: &input_rx,
                input_value_source: &input_value,
                return_err: &return_err_tx,
                return_value: &return_value_tx,
            },
        );

        assert!(matches!(return_err_rx.recv().unwrap(), Ok(())));
        assert_eq!(return_value_rx.recv().unwrap(), local);
    }

    #[test]
    fn compare_attester_uses_cached_local_value() {
        let leader = unsigned_attestation_set(&pubkey(1), attestation_data());
        let local = any_unsigned(&leader);
        let result = run_compare_attester(leader, None, local);

        assert!(matches!(result, Ok(())));
    }

    #[test]
    fn compare_attester_returns_error_when_cancelled_waiting_for_local_value() {
        let leader = unsigned_attestation_set(&pubkey(1), attestation_data());
        let cts = cancellation::CancellationTokenSource::new();
        cts.cancel();
        let ct = cts.token().clone();
        let qcommit = qcommit_for_value(component::tests::duty(), any_unsigned(&leader));
        let (_input_tx, input_rx) = mpmc::bounded(1);
        let (return_err_tx, return_err_rx) = mpmc::bounded(1);
        let (return_value_tx, _return_value_rx) = mpmc::bounded(1);
        let input_value = Any::default();

        compare(
            true,
            qbft::CompareRequest {
                ct: &ct,
                qcommit: &qcommit,
                input_value_source_ch: &input_rx,
                input_value_source: &input_value,
                return_err: &return_err_tx,
                return_value: &return_value_tx,
            },
        );

        assert!(matches!(
            return_err_rx.recv().unwrap(),
            Err(qbft::QbftError::CompareError)
        ));
    }

    #[test]
    fn compare_attester_wakes_when_cancelled_while_waiting_for_local_value() {
        let leader = unsigned_attestation_set(&pubkey(1), attestation_data());
        let cts = cancellation::CancellationTokenSource::new();
        let ct = cts.token().clone();
        let qcommit = qcommit_for_value(component::tests::duty(), any_unsigned(&leader));
        let (_input_tx, input_rx) = mpmc::bounded(1);
        let (return_err_tx, return_err_rx) = mpmc::bounded(1);
        let (return_value_tx, _return_value_rx) = mpmc::bounded(1);
        let input_value = Any::default();

        std::thread::scope(|scope| {
            scope.spawn(|| {
                compare(
                    true,
                    qbft::CompareRequest {
                        ct: &ct,
                        qcommit: &qcommit,
                        input_value_source_ch: &input_rx,
                        input_value_source: &input_value,
                        return_err: &return_err_tx,
                        return_value: &return_value_tx,
                    },
                );
            });

            cts.cancel();
        });

        assert!(matches!(
            return_err_rx.recv().unwrap(),
            Err(qbft::QbftError::CompareError)
        ));
    }

    #[tokio::test]
    async fn new_definition_leader_callback_uses_go_formula() {
        let consensus = component::tests::consensus(0, true);
        let duty = Duty::new(SlotNumber::new(42), DutyType::Proposer);
        let def = new_definition(DefinitionConfig {
            nodes: 4,
            subscribers: consensus.subscribers(),
            round_timer: consensus.round_timer(duty.clone()),
            decide_callback: Arc::new(|_| {}),
            compare_attestations: false,
            runtime: tokio::runtime::Handle::current(),
        });

        assert!((def.is_leader)(qbft::LeaderRequest {
            instance: &duty,
            round: 3,
            process: 2,
        }));
        assert!(!(def.is_leader)(qbft::LeaderRequest {
            instance: &duty,
            round: 3,
            process: 1,
        }));
    }

    #[tokio::test]
    async fn new_timer_failure_disconnects_receiver() {
        let timer = new_timer(
            Arc::new(FailingRoundTimer),
            tokio::runtime::Handle::current(),
            i64::MAX,
        );

        assert!(timer.receive.recv().is_err());
        (timer.stop)();
    }

    struct FailingRoundTimer;

    impl RoundTimer for FailingRoundTimer {
        fn timer_type(&self) -> crate::timer::TimerType {
            crate::timer::TimerType::Increasing
        }

        fn timer(&self, round: i64) -> crate::timer::Result<crate::timer::RoundTimerFuture> {
            Err(crate::timer::Error::DurationOverflow { round })
        }
    }

    fn step(type_: qbft::MessageType, present: Vec<usize>, missing: Vec<usize>) -> RoundStep {
        RoundStep {
            type_,
            present,
            missing,
            peers: 4,
        }
    }

    fn test_msg(
        type_: qbft::MessageType,
        peer_idx: i64,
        round: i64,
    ) -> qbft::Msg<ConsensusQbftTypes> {
        let (value_hash, values) = test_value_parts(type_);
        Arc::new(
            msg::Msg::new(
                pbconsensus::QbftMsg {
                    r#type: i64::from(type_),
                    duty: Some(pbcore::Duty {
                        slot: 1,
                        r#type: i32::try_from(&DutyType::Attester).unwrap(),
                    }),
                    peer_idx,
                    round,
                    value_hash,
                    ..Default::default()
                },
                vec![],
                values,
            )
            .unwrap(),
        )
    }

    fn run_compare(
        compare_attestations: bool,
        duty_type: DutyType,
    ) -> std::result::Result<(), qbft::QbftError> {
        let cts = cancellation::CancellationTokenSource::new();
        let ct = cts.token().clone();
        let qcommit = test_msg_with_duty(qbft::MSG_COMMIT, 0, 1, duty_type);
        let (_input_tx, input_rx) = mpmc::bounded(1);
        let (return_err_tx, return_err_rx) = mpmc::bounded(1);
        let (return_value_tx, _return_value_rx) = mpmc::bounded(1);
        let input_value = Any::default();

        compare(
            compare_attestations,
            qbft::CompareRequest {
                ct: &ct,
                qcommit: &qcommit,
                input_value_source_ch: &input_rx,
                input_value_source: &input_value,
                return_err: &return_err_tx,
                return_value: &return_value_tx,
            },
        );

        return_err_rx.recv().unwrap()
    }

    fn run_compare_attester(
        leader: pbcore::UnsignedDataSet,
        local_from_channel: Option<Any>,
        cached_local: Any,
    ) -> std::result::Result<(), qbft::QbftError> {
        let cts = cancellation::CancellationTokenSource::new();
        let ct = cts.token().clone();
        let qcommit = qcommit_for_value(component::tests::duty(), any_unsigned(&leader));
        let (input_tx, input_rx) = mpmc::bounded(1);
        if let Some(local) = local_from_channel {
            input_tx.send(local).unwrap();
        }
        let (return_err_tx, return_err_rx) = mpmc::bounded(1);
        let (return_value_tx, _return_value_rx) = mpmc::bounded(1);

        compare(
            true,
            qbft::CompareRequest {
                ct: &ct,
                qcommit: &qcommit,
                input_value_source_ch: &input_rx,
                input_value_source: &cached_local,
                return_err: &return_err_tx,
                return_value: &return_value_tx,
            },
        );

        return_err_rx.recv().unwrap()
    }

    fn commit_msg(duty: Duty, hash: [u8; 32], value: Any) -> qbft::Msg<ConsensusQbftTypes> {
        qcommit_for_hash(duty, hash, value)
    }

    fn qcommit_for_value(duty: Duty, value: Any) -> qbft::Msg<ConsensusQbftTypes> {
        let decoded = pbcore::UnsignedDataSet::decode(value.value.as_slice()).unwrap();
        let hash = msg::hash_proto(&decoded).unwrap();
        qcommit_for_hash(duty, hash, value)
    }

    fn qcommit_for_hash(duty: Duty, hash: [u8; 32], value: Any) -> qbft::Msg<ConsensusQbftTypes> {
        let values = Arc::new(HashMap::from([(hash, value)]));
        Arc::new(
            msg::Msg::new(
                pbconsensus::QbftMsg {
                    r#type: i64::from(qbft::MSG_COMMIT),
                    duty: Some(pbcore::Duty::try_from(&duty).unwrap()),
                    peer_idx: 0,
                    round: 1,
                    value_hash: hash.to_vec().into(),
                    ..Default::default()
                },
                vec![],
                values,
            )
            .unwrap(),
        )
    }

    fn test_msg_with_duty(
        type_: qbft::MessageType,
        peer_idx: i64,
        round: i64,
        duty_type: DutyType,
    ) -> qbft::Msg<ConsensusQbftTypes> {
        let (value_hash, values) = test_value_parts(type_);
        Arc::new(
            msg::Msg::new(
                pbconsensus::QbftMsg {
                    r#type: i64::from(type_),
                    duty: Some(pbcore::Duty {
                        slot: 1,
                        r#type: i32::try_from(&duty_type).unwrap(),
                    }),
                    peer_idx,
                    round,
                    value_hash,
                    ..Default::default()
                },
                vec![],
                values,
            )
            .unwrap(),
        )
    }

    fn test_value_parts(type_: qbft::MessageType) -> (Bytes, Arc<HashMap<[u8; 32], Any>>) {
        if type_ == qbft::MSG_ROUND_CHANGE || !type_.valid() {
            return (Bytes::new(), Arc::default());
        }

        let value = unsigned_value();
        let hash = msg::hash_proto(&value).unwrap();
        (
            hash.to_vec().into(),
            Arc::new(HashMap::from([(hash, any_unsigned(&value))])),
        )
    }

    fn unsigned_value() -> pbcore::UnsignedDataSet {
        pbcore::UnsignedDataSet {
            set: [("0x1".to_string(), Bytes::from_static(&[1]))].into(),
        }
    }

    fn unsigned_attestation_set(
        pubkey: &str,
        data: phase0::AttestationData,
    ) -> pbcore::UnsignedDataSet {
        pbcore::UnsignedDataSet {
            set: [(pubkey.to_string(), attestation_bytes(&data))].into(),
        }
    }

    fn attestation_bytes(data: &phase0::AttestationData) -> Bytes {
        let data = data.as_ssz_bytes();
        let duty_offset = ATTESTATION_DATA_SSZ_OFFSET
            .checked_add(data.len())
            .expect("test attestation data offset fits usize");
        let capacity = duty_offset
            .checked_add(ATTESTER_DUTY_SSZ_SIZE)
            .expect("test attestation data length fits usize");
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(
            &u32::try_from(ATTESTATION_DATA_SSZ_OFFSET)
                .expect("test attestation data offset fits u32")
                .to_le_bytes(),
        );
        out.extend_from_slice(
            &u32::try_from(duty_offset)
                .expect("test attestation duty offset fits u32")
                .to_le_bytes(),
        );
        out.extend_from_slice(&data);
        out.extend_from_slice(&[0; ATTESTER_DUTY_SSZ_SIZE]);
        Bytes::from(out)
    }

    fn attestation_data() -> phase0::AttestationData {
        phase0::AttestationData {
            slot: 1,
            index: 2,
            beacon_block_root: [3; 32],
            source: phase0::Checkpoint {
                epoch: 4,
                root: [5; 32],
            },
            target: phase0::Checkpoint {
                epoch: 6,
                root: [7; 32],
            },
        }
    }

    fn changed_attestation_data() -> phase0::AttestationData {
        phase0::AttestationData {
            source: phase0::Checkpoint {
                epoch: 8,
                root: [9; 32],
            },
            target: phase0::Checkpoint {
                epoch: 10,
                root: [11; 32],
            },
            ..attestation_data()
        }
    }

    fn any_unsigned(value: &pbcore::UnsignedDataSet) -> Any {
        Any::from_msg(value).unwrap()
    }

    fn pubkey(seed: u8) -> String {
        format!("0x{}", hex::encode([seed; 48]))
    }
}
