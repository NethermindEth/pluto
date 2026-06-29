//! Three-host integration test for infosync.
//!
//! Rather than booting full multi-node apps (infosync is not yet wired into the
//! app), it drives three in-process libp2p hosts at the infosync+priority
//! layer. Each host runs a real priority exchange over a shared
//! "decide-on-first" consensus and triggers infosync for the same slot with
//! identical inputs; the test asserts every host converges on the same
//! cluster-wide version/protocol/proposal priorities.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use futures::{FutureExt as _, StreamExt as _, future::select_all};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder,
    core::{Transport as _, transport::MemoryTransport, upgrade::Version},
    multiaddr::Protocol,
    swarm::SwarmEvent,
};
use pluto_core::{
    corepb::v1::priority::PriorityResult,
    deadline::{DeadlineCalculator, DeadlineError},
    types::{Duty, DutyType, ProposalType, SlotNumber},
    version::SUPPORTED,
};
use pluto_featureset::FeatureSet;
use pluto_infosync::Component as InfoSync;
use pluto_p2p::{p2p_context::P2PContext, peer::peer_id_from_key, utils::keypair_from_secret_key};
use pluto_priority::{
    Consensus, ConsensusError, PrioritySubscriber, TopicResult, new_component, p2p::Behaviour,
};
use pluto_testutil::random::generate_insecure_k1_key;
use tokio::{sync::mpsc, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

/// Calculator that schedules every duty one hour out, so triggered infosync
/// duties never expire mid-test.
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
/// identical. Shared across all hosts so they all observe the same decision.
#[derive(Default)]
struct TestConsensus {
    subs: Mutex<Vec<PrioritySubscriber>>,
    proposed: Mutex<HashMap<u64, PriorityResult>>,
}

#[async_trait]
impl Consensus for TestConsensus {
    async fn propose_priority(
        &self,
        duty: Duty,
        result: PriorityResult,
        _ct: &CancellationToken,
    ) -> Result<(), ConsensusError> {
        let slot = duty.slot.inner();

        // Claim the decision atomically before fanning out: hold the lock across
        // the check and the insert so two concurrent first proposals for the
        // same duty cannot both notify subscribers. Later proposals see the
        // recorded result and assert it is identical.
        {
            let mut proposed = self.proposed.lock().expect("proposed mutex");
            if let Some(prev) = proposed.get(&slot) {
                assert_eq!(
                    prev.topics, result.topics,
                    "all proposals for a duty must be identical"
                );
                return Ok(());
            }
            proposed.insert(slot, result.clone());
        }

        let subs = self.subs.lock().expect("subs mutex");
        for sub in subs.iter() {
            sub(duty.clone(), result.clone())?;
        }
        Ok(())
    }

    fn subscribe_priority(&self, callback: PrioritySubscriber) {
        self.subs.lock().expect("subs mutex").push(callback);
    }
}

/// In-process `/memory/<N>` address (non-zero so the kernel does not
/// auto-assign).
fn memory_addr(seed: u8) -> Multiaddr {
    Multiaddr::empty().with(Protocol::Memory(u64::from(seed) + 1))
}

/// The full set of protocol ids a node advertises, aggregated across components
/// (consensus, parsigex, peerinfo, priority) in that order — the same set and
/// order a node would prioritise via infosync, built without standing up an
/// app.
fn app_protocols() -> Vec<String> {
    let mut resp: Vec<String> = Vec::new();
    resp.extend(
        pluto_consensus::protocols::protocols()
            .iter()
            .map(ToString::to_string),
    );
    resp.extend(pluto_parsigex::protocols().iter().map(ToString::to_string));
    resp.extend(pluto_peerinfo::protocols().iter().map(ToString::to_string));
    resp.extend(pluto_priority::protocols().iter().map(ToString::to_string));
    resp
}

/// Decided topic results captured per host, alongside the host index and duty.
type Captured = (usize, Duty, Vec<TopicResult>);

/// A built host: its swarm and the infosync component driving it.
struct Host {
    swarm: Swarm<Behaviour>,
    infosync: Arc<InfoSync>,
    addr: Multiaddr,
}

/// Builds one host: a priority [`Prioritiser`] + [`Behaviour`] over an
/// in-process [`MemoryTransport`], wrapped by an infosync [`InfoSync`]
/// component. A capture subscriber is registered *after* infosync's own, so
/// receiving a capture message guarantees infosync's store is already updated.
#[allow(clippy::too_many_arguments)]
fn build_host(
    seed: u8,
    idx: usize,
    peers: Vec<PeerId>,
    consensus: Arc<dyn Consensus>,
    ct: &CancellationToken,
    versions: Vec<pluto_core::version::SemVer>,
    protocols: Vec<String>,
    proposals: Vec<ProposalType>,
    capture: mpsc::UnboundedSender<Captured>,
) -> Host {
    let key = generate_insecure_k1_key(seed);
    let keypair = keypair_from_secret_key(key.clone()).expect("keypair");

    let (prio, behaviour, expired) = new_component(
        peers.clone(),
        i64::try_from(peers.len()).expect("peer count fits i64"),
        consensus,
        Duration::from_secs(30),
        key,
        FutureCalculator,
        P2PContext::new(peers),
        ct.clone(),
    )
    .expect("new_component");
    let prio = Arc::new(prio);

    // infosync subscribes to the prioritiser inside `new`.
    let infosync = Arc::new(InfoSync::new(
        prio.clone(),
        versions,
        protocols,
        proposals,
        &FeatureSet::new(),
    ));

    // Capture subscriber registered after infosync's (fan-out runs in
    // registration order, so a capture message implies infosync is updated).
    prio.subscribe(Box::new(move |duty, results| {
        let _ = capture.send((idx, duty, results));
        Ok(())
    }));

    let swarm = SwarmBuilder::with_existing_identity(keypair)
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

    prio.start(expired, ct.clone());

    Host {
        swarm,
        infosync,
        addr: memory_addr(seed),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_host_infosync() {
    const N: usize = 3;
    const SEEDS: [u8; N] = [0, 1, 2];
    let slot = SlotNumber::new(99);

    // Identical inputs on every host: the supported versions, the aggregated
    // protocol set, and the default proposal types (builder/synthetic disabled
    // leaves the single `Full` fallback).
    let versions = SUPPORTED.to_vec();
    let protocols = app_protocols();
    let proposals = vec![ProposalType::Full];

    // Deterministic peer set from per-host seeds.
    let keys: Vec<_> = SEEDS.into_iter().map(generate_insecure_k1_key).collect();
    let peers: Vec<PeerId> = keys
        .iter()
        .map(|k| peer_id_from_key(k.public_key()).expect("peer id"))
        .collect();

    let ct = CancellationToken::new();
    let consensus = Arc::new(TestConsensus::default());
    let (cap_tx, mut cap_rx) = mpsc::unbounded_channel::<Captured>();

    let mut hosts: Vec<Host> = Vec::with_capacity(N);
    for (idx, &seed) in SEEDS.iter().enumerate() {
        hosts.push(build_host(
            seed,
            idx,
            peers.clone(),
            consensus.clone(),
            &ct,
            versions.clone(),
            protocols.clone(),
            proposals.clone(),
            cap_tx.clone(),
        ));
    }
    drop(cap_tx);

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
    let addrs: Vec<Multiaddr> = hosts.iter().map(|h| h.addr.clone()).collect();
    for (i, host) in hosts.iter_mut().enumerate() {
        for (j, addr) in addrs.iter().enumerate() {
            if i != j {
                host.swarm.dial(addr.clone()).expect("dial");
            }
        }
    }

    // Wait until every host is connected to all peers before triggering, so the
    // priority exchange reuses established connections rather than racing dials.
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
        timeout(Duration::from_secs(10), mesh)
            .await
            .expect("full connection mesh within timeout");
    }

    // Drive each swarm in the background; keep the infosync handles.
    let mut infosyncs: Vec<Arc<InfoSync>> = Vec::with_capacity(N);
    let mut drivers = JoinSet::new();
    for host in hosts {
        infosyncs.push(host.infosync);
        let mut swarm = host.swarm;
        drivers.spawn(async move {
            loop {
                let _ = swarm.select_next_some().await;
            }
        });
    }

    // Trigger infosync on every host for the same slot. `trigger` blocks until
    // the duty deadline / cancellation, so it runs in the background while the
    // decision is observed via the capture channel.
    let mut triggers = JoinSet::new();
    for isync in &infosyncs {
        let isync = isync.clone();
        let ct = ct.clone();
        triggers.spawn(async move { isync.trigger(ct, slot).await });
    }

    // Expect one decided result per host (the single decision fans out to all).
    let expected_versions: Vec<String> = versions.iter().map(|v| v.to_string()).collect();
    let expected_proposals: Vec<String> = proposals.iter().map(|p| p.as_str().to_owned()).collect();

    let mut seen_hosts: HashSet<usize> = HashSet::new();
    for _ in 0..N {
        let (idx, duty, results) = timeout(Duration::from_secs(30), cap_rx.recv())
            .await
            .expect("decided result within timeout")
            .expect("result delivered");

        assert!(seen_hosts.insert(idx), "one decision per host");
        assert_eq!(duty.slot, slot, "decided duty is for the triggered slot");
        assert_eq!(
            duty.duty_type,
            DutyType::InfoSync,
            "decided duty is the info-sync duty"
        );
        assert_eq!(
            results.len(),
            3,
            "three topics: version, protocol, proposal"
        );

        for tr in &results {
            let got = tr.priorities_only();
            match tr.topic.as_str() {
                "version" => assert_eq!(got, expected_versions, "agreed versions"),
                "protocol" => assert_eq!(got, protocols, "agreed protocols"),
                "proposal" => assert_eq!(got, expected_proposals, "agreed proposals"),
                other => panic!("unexpected topic: {other}"),
            }
        }
    }

    // Every host's infosync recorded the agreed protocols and proposals.
    for isync in &infosyncs {
        assert_eq!(isync.protocols(slot), protocols, "infosync protocols");
        assert_eq!(isync.proposals(slot), proposals, "infosync proposals");
    }

    // Teardown.
    ct.cancel();
    triggers.abort_all();
    drivers.abort_all();
}
