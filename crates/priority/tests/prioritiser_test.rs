//! Three-host integration test for the priority protocol.
//!
//! Three in-process libp2p hosts run the priority exchange against a mock
//! consensus that "decides" on the first proposal and asserts every proposal is
//! identical. Each host proposes a different number of priorities (`0:[0]`,
//! `1:[0,1]`, `2:[0,1,2]`); the cluster-agreed result keeps only priority `0`
//! (proposed by all three) with score `n*1000`.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::{FutureExt as _, StreamExt as _, future::select_all};
use libp2p::{
    Multiaddr, PeerId, Swarm,
    core::{Transport as _, transport::MemoryTransport, upgrade::Version},
    multiaddr::Protocol,
    swarm::SwarmEvent,
};
use pluto_core::{
    corepb::v1::{
        core::Duty as ProtoDuty,
        priority::{PriorityMsg, PriorityResult, PriorityTopicProposal},
    },
    deadline::{DeadlineCalculator, DeadlineError, DeadlinerHandle, DeadlinerTask},
    types::{Duty, DutyType, SlotNumber},
};
use pluto_priority::{Consensus, ConsensusError, Prioritiser, PrioritySubscriber};
use prost_types::Any;
use tokio::{sync::mpsc, time::timeout};
use tokio_util::sync::CancellationToken;

use pluto_p2p::{p2p_context::P2PContext, peer::peer_id_from_key, utils::keypair_from_secret_key};
use pluto_priority::p2p::Behaviour;
use pluto_testutil::random::generate_insecure_k1_key;

/// Calculator that schedules every duty one hour out.
struct FutureCalculator;

impl DeadlineCalculator for FutureCalculator {
    fn deadline(
        &self,
        _duty: &Duty,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, DeadlineError> {
        Ok(Some(
            chrono::Utc::now()
                .checked_add_signed(chrono::Duration::hours(1))
                .expect("deadline in range"),
        ))
    }
}

/// Mock consensus that decides on the first proposal per duty by invoking its
/// subscribers, and asserts every subsequent proposal for that duty is
/// identical.
#[derive(Default)]
struct TestConsensus {
    subs: Mutex<Vec<PrioritySubscriber>>,
    proposed: Mutex<HashMap<u64, PriorityResult>>,
}

#[async_trait::async_trait]
impl Consensus for TestConsensus {
    async fn propose_priority(
        &self,
        duty: Duty,
        result: PriorityResult,
        _ct: &CancellationToken,
    ) -> Result<(), ConsensusError> {
        let slot = duty.slot.inner();

        // Decide-once: if already proposed, assert identical and return.
        {
            let proposed = self.proposed.lock().expect("proposed mutex");
            if let Some(prev) = proposed.get(&slot) {
                assert_eq!(
                    prev.topics, result.topics,
                    "all proposals for a duty must be identical"
                );
                return Ok(());
            }
        }

        let subs = self.subs.lock().expect("subs mutex");
        for sub in subs.iter() {
            sub(duty.clone(), result.clone())?;
        }
        drop(subs);

        self.proposed
            .lock()
            .expect("proposed mutex")
            .insert(slot, result);
        Ok(())
    }

    fn subscribe_priority(&self, callback: PrioritySubscriber) {
        self.subs.lock().expect("subs mutex").push(callback);
    }
}

/// Wraps priority `prio` as an `Any` of `Duty{slot: prio}`.
fn prio_to_any(prio: u64) -> Any {
    Any::from_msg(&ProtoDuty {
        slot: prio,
        r#type: 0,
    })
    .expect("pack Duty")
}

/// A built node: its swarm, the prioritiser, and its listen address.
struct Host {
    swarm: Swarm<Behaviour>,
    prioritiser: Prioritiser,
    addr: Multiaddr,
    peer_id: PeerId,
}

/// In-process `/memory/<N>` address, where `N` is derived from the seed
/// (non-zero so the kernel does not auto-assign a port).
fn memory_addr(seed: u8) -> Multiaddr {
    Multiaddr::empty().with(Protocol::Memory(u64::from(seed) + 1))
}

/// Builds one host wired to the shared `consensus` and `deadliner`, running its
/// priority behaviour over an in-process [`MemoryTransport`]. The libp2p
/// identity is derived from the same secp256k1 key used for the peer id.
fn build_host(
    seed: u8,
    peers: Vec<PeerId>,
    consensus: Arc<dyn Consensus>,
    deadliner: DeadlinerHandle,
) -> Host {
    let key = generate_insecure_k1_key(seed);
    let peer_id = peer_id_from_key(key.public_key()).expect("peer id");
    let keypair = keypair_from_secret_key(key).expect("keypair");

    // A permissive verifier returning Ok for every message.
    let validator = Box::new(|_: &PriorityMsg| Ok(()));

    let (prioritiser, behaviour) = Prioritiser::new_internal(
        peer_id,
        peers.clone(),
        i64::try_from(peers.len()).expect("peer count fits i64"),
        consensus,
        validator,
        Duration::from_secs(3600),
        deadliner,
        // Cluster context for known-peer gating. Addresses are unused here: the
        // test pre-dials a full mesh by address, so exchanges reuse existing
        // connections rather than dialing by peer id.
        P2PContext::new(peers.clone()),
    );

    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_other_transport(|key| {
            MemoryTransport::default()
                .upgrade(Version::V1)
                .authenticate(libp2p::noise::Config::new(key).expect("noise config"))
                .multiplex(libp2p::yamux::Config::default())
        })
        .expect("transport")
        .with_behaviour(|_key| behaviour)
        .expect("behaviour")
        .build();

    Host {
        swarm,
        prioritiser,
        addr: memory_addr(seed),
        peer_id,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_host_prioritiser() {
    const N: usize = 3;
    const SEEDS: [u8; N] = [0, 1, 2];

    let duties = [
        Duty::new(SlotNumber::new(97), DutyType::Unknown),
        Duty::new(SlotNumber::new(98), DutyType::Unknown),
        Duty::new(SlotNumber::new(99), DutyType::Unknown),
    ];

    // Derive the peer set deterministically from the per-host seeds.
    let keys: Vec<_> = SEEDS.into_iter().map(generate_insecure_k1_key).collect();
    let peers: Vec<PeerId> = keys
        .iter()
        .map(|k| peer_id_from_key(k.public_key()).expect("peer id"))
        .collect();

    let ct = CancellationToken::new();
    let consensus = Arc::new(TestConsensus::default());

    // One deadliner shared across all hosts.
    let (deadliner, expired) = DeadlinerTask::start(ct.clone(), "test", FutureCalculator);

    // The deadliner emits expired duties to a single consumer, and `start`
    // consumes the receiver once. Hand it to the first prioritiser; the others
    // get a never-emitting channel (their buffers are cleaned via cancellation
    // on `ct`).
    let mut expired_opt = Some(expired);

    // Build hosts.
    let mut hosts: Vec<Host> = Vec::with_capacity(N);
    for &seed in &SEEDS {
        hosts.push(build_host(
            seed,
            peers.clone(),
            consensus.clone(),
            deadliner.clone(),
        ));
    }

    // Collect all decided priority lists across subscribers.
    let (results_tx, mut results_rx) =
        mpsc::unbounded_channel::<Vec<pluto_core::corepb::v1::priority::PriorityScoredResult>>();

    // Wire one subscriber per prioritiser. Each asserts the topic shape and
    // forwards the priorities.
    let topic_any = Any::from_msg(&pluto_core::corepb::v1::core::ParSignedData {
        data: b"test topic".to_vec().into(),
        ..Default::default()
    })
    .expect("pack topic");

    for host in &hosts {
        let tx = results_tx.clone();
        let expected_topic = topic_any.clone();
        host.prioritiser.subscribe(Box::new(move |duty, result| {
            let slot = duty.slot.inner();
            assert!(
                [97, 98, 99].contains(&slot),
                "decided duty slot must be one of the proposed duties, got {slot}"
            );
            assert_eq!(result.topics.len(), 1, "exactly one topic");
            let topic = &result.topics[0];
            assert_eq!(
                topic.topic.as_ref().expect("topic any"),
                &expected_topic,
                "topic round-trips"
            );
            let _ = tx.send(topic.priorities.clone());
            Ok(())
        }));
    }
    drop(results_tx);

    // Start cleanup loops. The shared deadliner has a single expired receiver,
    // so only the first prioritiser drives real cleanup; the others get an
    // open (never-emitting) channel. The senders are kept alive for the test so
    // those cleanup loops park on `recv()` rather than exiting and cancelling
    // their quit tokens (which would break inbound exchange handling).
    let mut keepalive_senders: Vec<mpsc::Sender<Duty>> = Vec::new();
    for host in &hosts {
        let rx = expired_opt.take().unwrap_or_else(|| {
            let (tx, rx) = mpsc::channel::<Duty>(1);
            keepalive_senders.push(tx);
            rx
        });
        host.prioritiser.start(rx, ct.clone());
    }

    // Begin listening, then full-mesh dial.
    for host in &mut hosts {
        host.swarm.listen_on(host.addr.clone()).expect("listen");
    }
    for host in &mut hosts {
        loop {
            if matches!(
                host.swarm.select_next_some().await,
                SwarmEvent::NewListenAddr { .. }
            ) {
                break;
            }
        }
    }

    // Dial every other host from each host.
    let addrs: Vec<Multiaddr> = hosts.iter().map(|h| h.addr.clone()).collect();
    for (i, host) in hosts.iter_mut().enumerate() {
        for (j, addr) in addrs.iter().enumerate() {
            if i != j {
                host.swarm.dial(addr.clone()).expect("dial");
            }
        }
    }

    // Wait until every host is connected to all its peers before exchanging.
    // The priority exchange opens substreams on existing connections; launching
    // it before the mesh is up would race connection setup and could drop an
    // exchange, stalling a duty's consensus.
    {
        let mut connected: Vec<HashSet<PeerId>> = vec![HashSet::new(); N];
        let mesh = async {
            while connected.iter().any(|peers| peers.len() < N - 1) {
                let next = hosts
                    .iter_mut()
                    .map(|h| h.swarm.select_next_some().boxed())
                    .collect::<Vec<_>>();
                let (event, idx, _) = select_all(next).await;
                if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                    connected[idx].insert(peer_id);
                }
            }
        };
        timeout(Duration::from_secs(30), mesh)
            .await
            .expect("full connection mesh within timeout");
    }

    // Extract per-host prioritisers (with their key/peer id) and drive each
    // swarm in the background. Host `i` proposes priorities `0..=i`.
    let mut launchers = Vec::with_capacity(N);
    let mut drivers = Vec::with_capacity(N);
    for (i, host) in hosts.into_iter().enumerate() {
        let count = u64::try_from(i).expect("host index fits u64");
        launchers.push((host.prioritiser, keys[i].clone(), host.peer_id, count));
        let mut swarm = host.swarm;
        drivers.push(tokio::spawn(async move {
            loop {
                let _ = swarm.select_next_some().await;
            }
        }));
    }

    // Launch prioritise across all (host, duty) pairs.
    let (err_tx, mut err_rx) = mpsc::unbounded_channel();
    let mut prioritise_tasks = Vec::new();
    for (prio, key, peer_id, max_prio) in &launchers {
        // Propose 0:[0], 1:[0,1], 2:[0,1,2].
        let priorities: Vec<Any> = (0..=*max_prio).map(prio_to_any).collect();

        for duty in &duties {
            let proto_duty = ProtoDuty {
                slot: duty.slot.inner(),
                r#type: 0,
            };
            let msg = sign(
                key,
                PriorityMsg {
                    duty: Some(proto_duty),
                    topics: vec![PriorityTopicProposal {
                        topic: Some(topic_any.clone()),
                        priorities: priorities.clone(),
                    }],
                    peer_id: peer_id.to_string(),
                    signature: Default::default(),
                },
            );

            let prio = prio.clone();
            let ct = ct.clone();
            let err_tx = err_tx.clone();
            prioritise_tasks.push(tokio::spawn(async move {
                let res = prio.prioritise(msg, ct).await;
                let _ = err_tx.send(res);
            }));
        }
    }
    drop(err_tx);

    // Expect N * len(duties) decided priority lists, each [prio 0] @ score N*1000.
    let expected_results = N * duties.len();
    let expected_score = i64::try_from(N).expect("N fits i64") * 1000;
    let zero_any = prio_to_any(0);

    for _ in 0..expected_results {
        let res = timeout(Duration::from_secs(30), results_rx.recv())
            .await
            .expect("result within timeout")
            .expect("result delivered");
        assert_eq!(res.len(), 1, "exactly one priority survives");
        assert_eq!(res[0].score, expected_score, "score is n*1000");
        assert_eq!(
            res[0].priority.as_ref().expect("priority any"),
            &zero_any,
            "the surviving priority is 0"
        );
    }

    // Cancel: every prioritise instance returns the cancellation error.
    ct.cancel();
    for _ in 0..expected_results {
        let res = timeout(Duration::from_secs(10), err_rx.recv())
            .await
            .expect("error within timeout")
            .expect("error delivered");
        assert!(
            matches!(res, Err(pluto_priority::Error::Cancelled)),
            "cancelled prioritise returns Error::Cancelled, got {res:?}"
        );
    }

    for d in drivers {
        d.abort();
    }
    for t in prioritise_tasks {
        t.abort();
    }
}

/// Signs a priority message with the secp256k1 key.
fn sign(key: &k256::SecretKey, msg: PriorityMsg) -> PriorityMsg {
    pluto_priority::component::sign_msg(&msg, key).expect("sign")
}
