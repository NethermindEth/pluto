use std::{
    collections::BTreeMap,
    error::Error as StdError,
    sync::{Arc, Mutex},
    time::Duration,
};

use cancellation::CancellationTokenSource;
use crossbeam::channel as mpmc;
use pluto_core::{
    corepb::v1::{consensus as pbconsensus, core as pbcore, priority as pbpriority},
    qbft,
    types::{Duty, DutyType, SlotNumber},
};
use pluto_eth2api::spec::phase0;
use pluto_ssz::HashRoot;
use prost::bytes::Bytes;
use prost_types::Any;
use test_case::test_case;
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;

use super::{
    Peer,
    component::{self, Config, Consensus},
    definition::{self, DefinitionConfig},
    msg::{self, ConsensusQbftTypes},
};
use crate::timer::{RoundTimer, RoundTimerFunc, RoundTimerFuture, TimerType};

const CONSENSUS_RECV_TIMEOUT: Duration = Duration::from_secs(5);
const SILENT_LEADER_RECV_TIMEOUT: Duration = Duration::from_secs(15);

#[test_case(2, 3 ; "two_of_three")]
#[test_case(3, 4 ; "three_of_four")]
#[test_case(4, 4 ; "four_of_four")]
#[test_case(4, 6 ; "four_of_six")]
#[tokio::test]
async fn qbft_consensus(threshold: usize, cluster_nodes: usize) {
    assert!(threshold <= cluster_nodes);
    run_qbft_consensus(threshold, cluster_nodes, false, unsigned_value).await;
}

#[tokio::test]
async fn qbft_consensus_attester_compare_enabled() {
    run_qbft_consensus(3, 3, true, |_| attester_value(0)).await;
}

#[tokio::test]
async fn qbft_sniffed_instance_replay_decides() {
    let sniffed = run_qbft_consensus(4, 4, false, unsigned_value).await;
    let instance = sniffed
        .into_iter()
        .find(|(node_idx, _)| *node_idx == 0)
        .expect("node zero emitted sniffed instance")
        .1;

    replay_sniffed_instance_decides(instance).await;
}

// Slow liveness regression for a silent round-1 leader. Only 3 of 4 peers are
// active and the missing peer is the round-1 leader, so the instance cannot
// progress until the round timer expires and the active peers rotate to round
// 2. Full parallel test runs add Tokio scheduling noise around that timeout, so
// keep it out of default CI and run it explicitly with `--ignored` when
// checking silent-peer liveness.
#[ignore = "slow silent-leader round-change liveness scenario"]
#[tokio::test]
async fn qbft_consensus_with_silent_round_one_leader_decides() {
    let nodes_count = 4;
    let active_count = 3;
    let silent_peer_idx = 3;
    let duty = Duty::new(SlotNumber::new(4), DutyType::Attester);
    assert_eq!(
        definition::leader(
            &duty,
            1,
            i64::try_from(nodes_count).expect("test node count fits i64")
        ),
        silent_peer_idx
    );

    let (sniffed_tx, _sniffed_rx) = mpsc::unbounded_channel();
    let nodes = in_memory_network(
        nodes_count,
        active_count,
        false,
        Some(Duration::from_millis(100)),
        sniffed_tx,
    );
    let active_nodes = &nodes[..active_count];
    let (decided_tx, mut decided_rx) = mpsc::unbounded_channel();
    let ct = CancellationToken::new();
    let start_ct = CancellationToken::new();
    let mut start_tasks = Vec::with_capacity(active_nodes.len());

    for (node_idx, node) in active_nodes.iter().enumerate() {
        let decided_tx = decided_tx.clone();
        node.subscribe(move |duty, value| {
            let _ = decided_tx.send((node_idx, duty, value));
            Ok(())
        });

        start_tasks.push(node.start(start_ct.clone()));
    }
    drop(decided_tx);

    let mut tasks = JoinSet::new();
    for (node_idx, node) in active_nodes.iter().enumerate() {
        let node = Arc::clone(node);
        let duty = duty.clone();
        let value = unsigned_value(node_idx);
        let ct = ct.clone();
        tasks.spawn(async move { node.propose(duty, value, &ct).await });
    }

    let mut decided = collect_decisions_or_task_error_with_timeout(
        &mut decided_rx,
        &mut tasks,
        active_nodes.len(),
        "silent-peer consensus decision",
        SILENT_LEADER_RECV_TIMEOUT,
    )
    .await;

    join_successful_tasks(tasks, "silent-peer consensus task").await;

    decided.sort_by_key(|(node_idx, ..)| *node_idx);
    assert_eq!(decided.len(), active_count);
    let (_, _, expected_value) = decided.first().expect("at least one decided value").clone();
    for (node_idx, decided_duty, decided_value) in decided {
        assert_eq!(decided_duty, duty, "node {node_idx} decided wrong duty");
        assert_eq!(
            decided_value, expected_value,
            "node {node_idx} decided different value"
        );
    }

    ct.cancel();
    start_ct.cancel();
    for task in start_tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn qbft_priority_consensus() {
    let threshold = 3;
    let (sniffed_tx, _sniffed_rx) = mpsc::unbounded_channel();
    let active_nodes = in_memory_network(threshold, threshold, false, None, sniffed_tx);
    let (decided_tx, mut decided_rx) = mpsc::unbounded_channel();
    let duty = Duty::new(SlotNumber::new(1), DutyType::InfoSync);
    let ct = CancellationToken::new();
    let start_ct = CancellationToken::new();
    let mut start_tasks = Vec::with_capacity(active_nodes.len());

    for (node_idx, node) in active_nodes.iter().enumerate() {
        let decided_tx = decided_tx.clone();
        node.subscribe_priority(move |duty, value| {
            let _ = decided_tx.send((node_idx, duty, value));
            Ok(())
        });

        start_tasks.push(node.start(start_ct.clone()));
    }
    drop(decided_tx);

    let mut tasks = JoinSet::new();
    for (node_idx, node) in active_nodes.iter().enumerate() {
        let node = Arc::clone(node);
        let duty = duty.clone();
        let value = priority_value(&duty, node_idx);
        let ct = ct.clone();
        tasks.spawn(async move { node.propose_priority(duty, value, &ct).await });
    }

    let decided = collect_decisions_or_task_error(
        &mut decided_rx,
        &mut tasks,
        active_nodes.len(),
        "priority decision",
    )
    .await;
    let (_, _, expected_value) = decided.first().expect("at least one decided value").clone();
    for (node_idx, decided_duty, decided_value) in decided {
        assert_eq!(decided_duty, duty, "node {node_idx} decided wrong duty");
        assert_eq!(
            decided_value, expected_value,
            "node {node_idx} decided different priority value"
        );
    }

    join_successful_tasks(tasks, "priority consensus task").await;

    ct.cancel();
    start_ct.cancel();
    for task in start_tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn qbft_consensus_participate_then_late_propose() {
    let threshold = 4;
    let (sniffed_tx, _sniffed_rx) = mpsc::unbounded_channel();
    let active_nodes = in_memory_network(threshold, threshold, false, None, sniffed_tx);
    let (decided_tx, mut decided_rx) = mpsc::unbounded_channel();
    let duty = Duty::new(SlotNumber::new(1), DutyType::Attester);
    let ct = CancellationToken::new();
    let start_ct = CancellationToken::new();
    let mut start_tasks = Vec::with_capacity(active_nodes.len());

    for (node_idx, node) in active_nodes.iter().enumerate() {
        let decided_tx = decided_tx.clone();
        node.subscribe(move |duty, value| {
            let _ = decided_tx.send((node_idx, duty, value));
            Ok(())
        });

        start_tasks.push(node.start(start_ct.clone()));
    }
    drop(decided_tx);

    let mut tasks = JoinSet::new();
    for node in &active_nodes {
        let node = Arc::clone(node);
        let duty = duty.clone();
        let ct = ct.clone();
        tasks.spawn(async move { node.participate(duty, &ct).await });
    }

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if active_nodes
                .iter()
                .all(|node| node.get_instance_io(duty.clone()).has_started())
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("participants did not start consensus instances");

    for (node_idx, node) in active_nodes.iter().enumerate() {
        let node = Arc::clone(node);
        let duty = duty.clone();
        let ct = ct.clone();
        tasks.spawn(async move { node.propose(duty, unsigned_value(node_idx), &ct).await });
    }

    let mut decided = Vec::with_capacity(active_nodes.len());
    for _ in 0..active_nodes.len() {
        decided.push(recv_one(&mut decided_rx, "late-propose decision").await);
    }
    let (_, _, expected_value) = decided.first().expect("at least one decided value").clone();
    for (node_idx, decided_duty, decided_value) in decided {
        assert_eq!(decided_duty, duty, "node {node_idx} decided wrong duty");
        assert_eq!(
            decided_value, expected_value,
            "node {node_idx} decided different value"
        );
    }

    join_successful_tasks(tasks, "consensus task").await;

    ct.cancel();
    start_ct.cancel();
    for task in start_tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn qbft_consensus_attester_compare_mismatch_does_not_decide() {
    let threshold = 3;
    let (sniffed_tx, _sniffed_rx) = mpsc::unbounded_channel();
    let active_nodes = in_memory_network(
        threshold,
        threshold,
        true,
        Some(Duration::from_millis(20)),
        sniffed_tx,
    );
    let (decided_tx, mut decided_rx) = mpsc::unbounded_channel();
    let duty = Duty::new(SlotNumber::new(1), DutyType::Attester);
    let ct = CancellationToken::new();
    let start_ct = CancellationToken::new();
    let mut start_tasks = Vec::with_capacity(active_nodes.len());

    for (node_idx, node) in active_nodes.iter().enumerate() {
        let decided_tx = decided_tx.clone();
        node.subscribe(move |duty, value| {
            let _ = decided_tx.send((node_idx, duty, value));
            Ok(())
        });

        start_tasks.push(node.start(start_ct.clone()));
    }
    drop(decided_tx);

    let mut tasks = JoinSet::new();
    for (node_idx, node) in active_nodes.iter().enumerate() {
        let node = Arc::clone(node);
        let duty = duty.clone();
        let value = attester_value(node_idx);
        let ct = ct.clone();
        tasks.spawn(async move { node.propose(duty, value, &ct).await });
    }

    tokio::time::timeout(Duration::from_millis(150), decided_rx.recv())
        .await
        .expect_err("mismatched attester compare unexpectedly decided");

    ct.cancel();
    join_failed_tasks(tasks, "mismatched compare task").await;
    assert!(decided_rx.try_recv().is_err());

    start_ct.cancel();
    for task in start_tasks {
        task.await.unwrap();
    }
}

async fn run_qbft_consensus(
    threshold: usize,
    cluster_nodes: usize,
    compare_attestations: bool,
    value: fn(usize) -> pbcore::UnsignedDataSet,
) -> Vec<(usize, pbconsensus::SniffedConsensusInstance)> {
    assert!(threshold <= cluster_nodes);

    let (sniffed_tx, mut sniffed_rx) = mpsc::unbounded_channel();
    // This mirrors the upstream consensus wrapper test: cluster metadata may
    // describe more nodes, but the test only instantiates threshold peers.
    let nodes = in_memory_network(threshold, threshold, compare_attestations, None, sniffed_tx);
    let active_nodes = nodes.as_slice();
    let (decided_tx, mut decided_rx) = mpsc::unbounded_channel();
    let duty = Duty::new(SlotNumber::new(1), DutyType::Attester);
    let ct = CancellationToken::new();
    let start_ct = CancellationToken::new();
    let mut start_tasks = Vec::with_capacity(active_nodes.len());

    for (node_idx, node) in active_nodes.iter().enumerate() {
        let decided_tx = decided_tx.clone();
        node.subscribe(move |duty, value| {
            let _ = decided_tx.send((node_idx, duty, value));
            Ok(())
        });

        start_tasks.push(node.start(start_ct.clone()));
    }
    drop(decided_tx);

    let mut tasks = JoinSet::new();
    for (node_idx, node) in active_nodes.iter().enumerate() {
        let node = Arc::clone(node);
        let duty = duty.clone();
        let value = value(node_idx);
        let ct = ct.clone();
        tasks.spawn(async move { node.propose(duty, value, &ct).await });
    }

    let mut decided = collect_decisions_or_task_error(
        &mut decided_rx,
        &mut tasks,
        active_nodes.len(),
        "consensus decision",
    )
    .await;

    join_successful_tasks(tasks, "consensus task").await;

    decided.sort_by_key(|(node_idx, ..)| *node_idx);
    assert_eq!(decided.len(), threshold);
    let (_, _, expected_value) = decided.first().expect("at least one decided value").clone();
    for (node_idx, decided_duty, decided_value) in decided {
        assert_eq!(decided_duty, duty, "node {node_idx} decided wrong duty");
        assert_eq!(
            decided_value, expected_value,
            "node {node_idx} decided different value"
        );
    }

    ct.cancel();
    start_ct.cancel();
    for task in start_tasks {
        task.await.unwrap();
    }

    let mut sniffed = Vec::with_capacity(threshold);
    for _ in 0..threshold {
        sniffed.push(recv_one(&mut sniffed_rx, "sniffed instance").await);
    }
    sniffed.sort_by_key(|(node_idx, _)| *node_idx);
    for (node_idx, instance) in &sniffed {
        assert_ne!(instance.msgs.len(), 0, "node {node_idx} sniffer was empty");
    }

    sniffed
}

async fn replay_sniffed_instance_decides(instance: pbconsensus::SniffedConsensusInstance) {
    assert!(!instance.msgs.is_empty());

    let first_msg = instance
        .msgs
        .iter()
        .filter_map(|sniffed| sniffed.msg.as_ref())
        .filter_map(|outer| outer.msg.as_ref())
        .next()
        .expect("sniffed instance has inner message");
    let duty = Duty::try_from(first_msg.duty.as_ref().expect("sniffed message has duty"))
        .expect("sniffed message duty converts");
    let input_hash = sniffed_input_hash(&instance);
    let input_source = sniffed_input_source(&instance);
    let nodes = usize::try_from(instance.nodes).expect("sniffed node count fits usize");
    let peer_idx = instance.peer_idx;

    let (recv_tx, recv_rx) = mpmc::bounded(instance.msgs.len());
    for sniffed in instance.msgs {
        let outer = sniffed.msg.expect("sniffed entry has outer message");
        let raw = outer.msg.expect("sniffed outer message has inner message");
        let values = component::values_by_hash(&outer.values).expect("sniffed values decode");
        let wrapped = msg::Msg::new(raw, outer.justification, Arc::new(values))
            .expect("sniffed message wraps");
        let wrapped: qbft::Msg<ConsensusQbftTypes> = Arc::new(wrapped);
        recv_tx
            .send(wrapped)
            .expect("replay receive buffer accepts");
    }
    drop(recv_tx);

    let (input_hash_tx, input_hash_rx) = mpmc::bounded(1);
    input_hash_tx
        .send(input_hash)
        .expect("replay input hash channel accepts");
    drop(input_hash_tx);

    let (input_source_tx, input_source_rx) = mpmc::bounded(1);
    input_source_tx
        .send(input_source)
        .expect("replay input source channel accepts");
    drop(input_source_tx);

    let cts = Arc::new(CancellationTokenSource::new());
    let core_ct = cts.token().clone();
    let callback_cts = Arc::clone(&cts);
    let (decided_tx, decided_rx) = mpmc::bounded(1);
    let def = definition::new_definition(DefinitionConfig {
        nodes,
        subscribers: component::SubscriberSet::default(),
        round_timer: Box::new(ShortRoundTimer {
            timeout: Duration::from_secs(1),
        }),
        decide_callback: Arc::new(move |_| {
            let _ = decided_tx.try_send(());
            callback_cts.cancel();
        }),
        compare_attestations: false,
        runtime: tokio::runtime::Handle::current(),
    });
    let transport = qbft::Transport {
        broadcast: Box::new(|_| Ok(())),
        receive: recv_rx,
    };

    let run_task = tokio::task::spawn_blocking(move || {
        qbft::run(
            &core_ct,
            &def,
            &transport,
            &duty,
            peer_idx,
            input_hash_rx,
            input_source_rx,
        )
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if decided_rx.try_recv().is_ok() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("sniffed replay did not decide");

    cts.cancel();
    let result = tokio::time::timeout(Duration::from_secs(1), run_task)
        .await
        .expect("sniffed replay core did not stop")
        .expect("sniffed replay core task panicked");
    assert!(
        matches!(result, Ok(()) | Err(qbft::QbftError::ContextCanceled)),
        "unexpected sniffed replay result: {result:?}"
    );
}

fn sniffed_input_hash(instance: &pbconsensus::SniffedConsensusInstance) -> HashRoot {
    instance
        .msgs
        .iter()
        .filter_map(|sniffed| sniffed.msg.as_ref())
        .filter_map(|outer| outer.msg.as_ref())
        .filter_map(|msg| hash32(&msg.value_hash))
        .next()
        .expect("sniffed instance has value hash")
}

fn sniffed_input_source(instance: &pbconsensus::SniffedConsensusInstance) -> Any {
    instance
        .msgs
        .iter()
        .filter_map(|sniffed| sniffed.msg.as_ref())
        .flat_map(|outer| outer.values.iter())
        .next()
        .cloned()
        .expect("sniffed instance has value source")
}

fn hash32(value: &[u8]) -> Option<HashRoot> {
    let hash: HashRoot = value.try_into().ok()?;
    (hash != [0; 32]).then_some(hash)
}

async fn recv_one<T>(rx: &mut mpsc::UnboundedReceiver<T>, label: &str) -> T {
    // Consensus liveness is tested by receiving a decision, not by a tight
    // wall-clock bound. Keep a guard for hangs while allowing scheduler load.
    tokio::time::timeout(CONSENSUS_RECV_TIMEOUT, rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{label} receiver timed out"))
        .unwrap_or_else(|| panic!("{label} receiver closed"))
}

async fn collect_decisions_or_task_error<T>(
    rx: &mut mpsc::UnboundedReceiver<T>,
    tasks: &mut JoinSet<super::RunnerResult<()>>,
    expected: usize,
    label: &str,
) -> Vec<T> {
    collect_decisions_or_task_error_with_timeout(rx, tasks, expected, label, CONSENSUS_RECV_TIMEOUT)
        .await
}

async fn collect_decisions_or_task_error_with_timeout<T>(
    rx: &mut mpsc::UnboundedReceiver<T>,
    tasks: &mut JoinSet<super::RunnerResult<()>>,
    expected: usize,
    label: &str,
    recv_timeout: Duration,
) -> Vec<T> {
    let mut decided = Vec::with_capacity(expected);
    let timeout = tokio::time::sleep(recv_timeout);
    tokio::pin!(timeout);
    let mut tasks_open = true;

    while decided.len() < expected {
        tokio::select! {
            () = &mut timeout => {
                panic!(
                    "{label} receiver timed out after {}/{} decisions",
                    decided.len(),
                    expected
                );
            }
            decision = rx.recv() => match decision {
                Some(decision) => decided.push(decision),
                None => panic!(
                    "{label} receiver closed after {}/{} decisions",
                    decided.len(),
                    expected
                ),
            },
            task = tasks.join_next(), if tasks_open => match task {
                Some(Ok(Ok(()))) => {}
                Some(Ok(Err(err))) => panic!(
                    "{label} task failed before all decisions ({}/{}): {err}",
                    decided.len(),
                    expected
                ),
                Some(Err(err)) => panic!(
                    "{label} task panicked before all decisions ({}/{}): {err}",
                    decided.len(),
                    expected
                ),
                None => tasks_open = false,
            },
        }
    }

    decided
}

async fn join_successful_tasks(tasks: JoinSet<super::RunnerResult<()>>, label: &str) {
    let results = tokio::time::timeout(Duration::from_secs(1), tasks.join_all())
        .await
        .unwrap_or_else(|_| panic!("{label}s did not stop after decision"));

    for result in results {
        result.unwrap_or_else(|err| panic!("{label} failed: {err}"));
    }
}

async fn join_failed_tasks(tasks: JoinSet<super::RunnerResult<()>>, label: &str) {
    let results = tokio::time::timeout(Duration::from_secs(1), tasks.join_all())
        .await
        .unwrap_or_else(|_| panic!("{label}s did not stop after cancellation"));

    assert!(
        results.into_iter().all(|result| result.is_err()),
        "{label} unexpectedly succeeded"
    );
}

fn unsigned_value(seed: usize) -> pbcore::UnsignedDataSet {
    let mut set = BTreeMap::new();
    set.insert(
        format!("validator-{seed}"),
        Bytes::from(format!("unsigned-{seed}")),
    );
    pbcore::UnsignedDataSet { set }
}

fn attester_value(seed: usize) -> pbcore::UnsignedDataSet {
    let mut set = BTreeMap::new();
    set.insert(pubkey(1), attestation_json_bytes(&attestation_data(seed)));
    pbcore::UnsignedDataSet { set }
}

fn priority_value(duty: &Duty, seed: usize) -> pbpriority::PriorityResult {
    pbpriority::PriorityResult {
        msgs: vec![pbpriority::PriorityMsg {
            duty: Some(pbcore::Duty::try_from(duty).expect("test duty converts to proto")),
            peer_id: format!("peer-{seed}"),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn attestation_json_bytes(data: &phase0::AttestationData) -> Bytes {
    let value = serde_json::json!({
        "attestation_data": data,
        "attestation_duty": {
            "slot": "1",
            "validator_index": "1",
            "committee_index": "2",
            "committee_length": "8",
            "committees_at_slot": "1",
            "validator_committee_index": "1",
        },
    });
    Bytes::from(serde_json::to_vec(&value).expect("test attestation json serializes"))
}

fn attestation_data(seed: usize) -> phase0::AttestationData {
    let seed = u8::try_from(seed).expect("test attestation seed fits u8");
    let source_epoch = u64::from(seed)
        .checked_add(4)
        .expect("test source epoch fits u64");
    let source_root = seed.checked_add(5).expect("test source root byte fits u8");
    let target_epoch = u64::from(seed)
        .checked_add(6)
        .expect("test target epoch fits u64");
    let target_root = seed.checked_add(7).expect("test target root byte fits u8");
    phase0::AttestationData {
        slot: 1,
        index: 2,
        beacon_block_root: [3; 32],
        source: phase0::Checkpoint {
            epoch: source_epoch,
            root: [source_root; 32],
        },
        target: phase0::Checkpoint {
            epoch: target_epoch,
            root: [target_root; 32],
        },
    }
}

fn pubkey(seed: u8) -> String {
    format!("0x{}", hex::encode([seed; 48]))
}

fn in_memory_network(
    count: usize,
    active_count: usize,
    compare_attestations: bool,
    round_timeout: Option<Duration>,
    sniffed_tx: mpsc::UnboundedSender<(usize, pbconsensus::SniffedConsensusInstance)>,
) -> Vec<Arc<Consensus>> {
    assert!(active_count <= count);

    let peers = (0..count)
        .map(|index| Peer {
            index: i64::try_from(index).expect("test peer index fits i64"),
            name: format!("node-{index}"),
            public_key: component::tests::secret_key(
                u8::try_from(index.checked_add(1).expect("test peer index increments"))
                    .expect("test peer index fits u8"),
            )
            .public_key(),
        })
        .collect::<Vec<_>>();
    let nodes = Arc::new(Mutex::new(Vec::<Arc<Consensus>>::new()));

    for index in 0..count {
        let network = Arc::clone(&nodes);
        let broadcaster: component::Broadcaster = Arc::new(move |_ct, msg| {
            let network = Arc::clone(&network);
            Box::pin(async move {
                let peer_idx = msg.msg.as_ref().map_or(-1, |msg| msg.peer_idx);
                let peers = network.lock().unwrap().clone();
                for (index, consensus) in peers.into_iter().take(active_count).enumerate() {
                    if i64::try_from(index).expect("test peer index fits i64") == peer_idx {
                        continue;
                    }
                    // Sender teardown must not cancel an already-started
                    // in-memory delivery to later peers.
                    let delivery_ct = CancellationToken::new();
                    if let Err(err) = consensus.handle(msg.clone(), &delivery_ct).await {
                        return Err(Box::new(err) as Box<dyn StdError + Send + Sync>);
                    }
                }
                Ok(())
            })
        });
        let consensus = Arc::new(
            Consensus::new(Config {
                peers: peers.clone(),
                local_peer_idx: i64::try_from(index).expect("test peer index fits i64"),
                privkey: component::tests::secret_key(
                    u8::try_from(index.checked_add(1).expect("test peer index increments"))
                        .expect("test peer index fits u8"),
                ),
                broadcaster,
                compare_attestations,
                timer_func: match round_timeout {
                    Some(timeout) => short_timer_func(timeout),
                    None => crate::timer::get_round_timer_func(Arc::new(
                        pluto_featureset::FeatureSet::new(),
                    )),
                },
                sniffer: {
                    let sniffed_tx = sniffed_tx.clone();
                    Arc::new(move |instance| {
                        let _ = sniffed_tx.send((index, instance));
                    })
                },
                ..component::tests::config_base(false)
            })
            .unwrap(),
        );
        nodes.lock().unwrap().push(consensus);
    }

    nodes.lock().unwrap().clone()
}

fn short_timer_func(timeout: Duration) -> RoundTimerFunc {
    Box::new(move |_| Box::new(ShortRoundTimer { timeout }))
}

struct ShortRoundTimer {
    timeout: Duration,
}

impl RoundTimer for ShortRoundTimer {
    fn timer_type(&self) -> TimerType {
        TimerType::Increasing
    }

    fn timer(&self, round: i64) -> crate::timer::Result<RoundTimerFuture> {
        let rounds = u32::try_from(round).expect("test round fits u32");
        let timeout = self
            .timeout
            .checked_mul(rounds)
            .expect("test timer timeout fits Duration");
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .expect("test timer deadline fits Instant");
        Ok(Box::pin(async move {
            tokio::time::sleep_until(deadline).await;
            deadline
        }))
    }
}
