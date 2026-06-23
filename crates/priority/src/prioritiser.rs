//! Priority protocol engine: per-duty exchange and consensus orchestration.
//!
//! [`Prioritiser`] resolves cluster-wide priorities for a duty in two steps:
//! first it exchanges its own signed [`PriorityMsg`] with all peers and
//! collects their responses (until all received or the exchange timeout
//! elapses), then it deterministically computes a [`PriorityResult`] and
//! proposes it through cluster [`Consensus`].
//!
//! The engine is built on tokio primitives: a per-duty request buffer
//! ([`mpsc`]) feeds the [`run_instance`] select loop,
//! peer exchanges run as spawned tasks writing into a shared responses channel,
//! request responses travel over [`oneshot`] channels, and shutdown is
//! signalled by a [`CancellationToken`].

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::FutureExt;
use libp2p::PeerId;
use pluto_core::{
    corepb::v1::{core::Duty as ProtoDuty, priority::PriorityMsg},
    deadline::{AddOutcome, DeadlinerHandle},
    types::{Duty, DutyType, SlotNumber},
};
use pluto_p2p::p2p_context::P2PContext;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::{
    calculate::calculate_result,
    component::MsgVerifier,
    consensus::{Consensus, PrioritySubscriber},
    error::{Error, Result},
    p2p::{self, Behaviour, InboundHandler, Sender, protocol::RECEIVE_TIMEOUT},
};

/// Supported priority protocol identifier (the libp2p-negotiated wire token).
///
/// Slash-less, to match the reference implementation's wire token exactly for
/// cross-implementation interop. Stock rust-libp2p multistream-select rejects
/// slash-less names; the workspace patches it (see
/// third_party/multistream-select) so this exact token negotiates.
pub const PROTOCOL_ID: &str = "charon/priority/2.0.0";

/// A received peer request paired with a channel to deliver this peer's reply.
struct Request {
    /// The peer's priority message.
    msg: PriorityMsg,
    /// Channel on which to send our own message back to the peer.
    response: oneshot::Sender<PriorityMsg>,
}

/// Output subscriber callback invoked with each decided priority result.
type Subscriber = PrioritySubscriber;

/// Per-duty request buffer: a cloneable sender shared with peer handlers and a
/// receiver consumed once by the duty's run loop.
struct BufferEntry {
    /// Sender clones handed to inbound request handlers.
    tx: mpsc::Sender<Request>,
    /// Receiver, taken by the single run loop for the duty.
    rx: Option<mpsc::Receiver<Request>>,
}

/// Returns a [`Duty`] from its proto form, tolerating any encoded duty type.
///
/// The conversion is infallible and preserves the raw type integer;
/// out-of-range values map to [`DutyType::Unknown`] so engine bookkeeping never
/// rejects a message that passed validation.
fn duty_from_proto(duty: &ProtoDuty) -> Duty {
    let duty_type = DutyType::try_from(duty.r#type).unwrap_or(DutyType::Unknown);
    Duty::new(SlotNumber::new(duty.slot), duty_type)
}

/// Returns the proto form of a [`Duty`], preserving the type integer.
///
/// The conversion is infallible; a duty type with no proto integer maps to the
/// unknown encoding (`0`), the inverse of [`duty_from_proto`]'s tolerance, so a
/// proto value round-trips through both without rejecting the duty.
pub(crate) fn duty_to_proto(duty: &Duty) -> ProtoDuty {
    ProtoDuty {
        slot: duty.slot.inner(),
        r#type: i32::try_from(&duty.duty_type).unwrap_or(0),
    }
}

/// Engine state shared with the inbound request handler.
///
/// Holds everything `handle_request` needs and — deliberately — nothing that
/// depends on the transport `Sender`. Being `Sender`-free is what lets it be
/// built before the `Sender` exists, so the inbound handler can capture it
/// directly rather than through a lazily filled slot (no construction cycle).
struct Shared {
    /// Cluster peers participating in the protocol.
    peers: Vec<PeerId>,
    /// Validates received messages (peer membership + signature).
    msg_validator: Arc<MsgVerifier>,
    /// Cancelled when the engine shuts down, signalling instances to stop.
    quit: CancellationToken,
    /// Deadline scheduler; expired duties drop their request buffers.
    deadliner: DeadlinerHandle,
    /// Per-duty request buffers feeding each instance's run loop.
    req_buffers: Mutex<HashMap<Duty, BufferEntry>>,
}

/// Engine state for the owner-driven paths (`prioritise` / `run_instance`).
struct Inner {
    /// State also shared with the inbound request handler.
    shared: Arc<Shared>,
    /// Local peer id; excluded when exchanging with peers.
    local_id: PeerId,
    /// Outbound request/response transport (the p2p send-receive seam).
    sender: Sender,
    /// Minimum number of peers that must propose a priority to include it.
    min_required: i64,
    /// Per-instance exchange timeout before falling back to consensus.
    exchange_timeout: Duration,
    /// Cluster consensus over priority results.
    consensus: Arc<dyn Consensus>,
}

impl Shared {
    /// Request buffer capacity: `2 * peers` so neither peer requests nor our
    /// responses block the run loop.
    fn buffer_capacity(&self) -> usize {
        self.peers.len().max(1).saturating_mul(2)
    }

    /// Returns the request sender for a duty, creating the buffer on first use.
    fn get_req_buffer(&self, duty: Duty) -> mpsc::Sender<Request> {
        let cap = self.buffer_capacity();
        let mut buffers = self.req_buffers.lock().expect("req_buffers mutex poisoned");
        buffers
            .entry(duty)
            .or_insert_with(|| {
                let (tx, rx) = mpsc::channel(cap);
                BufferEntry { tx, rx: Some(rx) }
            })
            .tx
            .clone()
    }

    /// Takes the receiver for a duty's run loop, creating the buffer if absent.
    ///
    /// Returns `None` if a run loop already took it (one instance per duty).
    fn take_req_receiver(&self, duty: Duty) -> Option<mpsc::Receiver<Request>> {
        let cap = self.buffer_capacity();
        let mut buffers = self.req_buffers.lock().expect("req_buffers mutex poisoned");
        buffers
            .entry(duty)
            .or_insert_with(|| {
                let (tx, rx) = mpsc::channel(cap);
                BufferEntry { tx, rx: Some(rx) }
            })
            .rx
            .take()
    }

    /// Drops the request buffer for an expired duty.
    fn delete_recv_buffer(&self, duty: Duty) {
        self.req_buffers
            .lock()
            .expect("req_buffers mutex poisoned")
            .remove(&duty);
    }

    /// Handles a priority message exchange initiated by a peer.
    ///
    /// Validates the message, enqueues it for the duty's run loop, and awaits
    /// this node's own message to return as the response. Returns
    /// [`Error::Shutdown`] if the engine stops while waiting.
    async fn handle_request(&self, peer: PeerId, msg: PriorityMsg) -> Result<PriorityMsg> {
        if peer.to_string() != msg.peer_id {
            return Err(Error::InvalidPeerId);
        }

        (self.msg_validator)(&msg)?; // Arc<Box<dyn Fn>> auto-derefs for call.

        let proto_duty = msg.duty.as_ref().ok_or(Error::InvalidMsgProtoFields)?;
        let duty = duty_from_proto(proto_duty);

        match self.deadliner.add(duty.clone()).await {
            AddOutcome::Scheduled => {}
            AddOutcome::FailedToCompute => return Err(Error::DeadlineComputeFailed),
            AddOutcome::AlreadyExpired | AddOutcome::NoDeadline => {
                return Err(Error::DutyExpired);
            }
        }

        let buffer = self.get_req_buffer(duty);
        let (response_tx, response_rx) = oneshot::channel();
        let req = Request {
            msg,
            response: response_tx,
        };

        // The enqueue and response-wait phases share a single receive-timeout
        // deadline: a peer that opens a stream cannot pin the handler past it.
        let deadline = tokio::time::sleep(RECEIVE_TIMEOUT);
        tokio::pin!(deadline);

        tokio::select! {
            send_res = buffer.send(req) => {
                send_res.map_err(|_| Error::Shutdown)?;
            }
            () = &mut deadline => return Err(Error::TimeoutEnqueuing),
            () = self.quit.cancelled() => return Err(Error::Shutdown),
        }

        tokio::select! {
            resp = response_rx => resp.map_err(|_| Error::Shutdown),
            () = &mut deadline => Err(Error::TimeoutWaiting),
            () = self.quit.cancelled() => Err(Error::Shutdown),
        }
    }
}

/// Resolves cluster-wide priorities for duties.
#[derive(Clone)]
pub struct Prioritiser {
    inner: Arc<Inner>,
    /// Output subscribers; appended via [`Prioritiser::subscribe`] before
    /// [`Prioritiser::start`]. `Arc<Mutex<_>>` so the consensus subscription,
    /// wired at construction, can read the set populated later by `subscribe`.
    subs: Arc<Mutex<Vec<Subscriber>>>,
}

impl Prioritiser {
    /// Constructs a prioritiser and its libp2p transport behaviour.
    ///
    /// Returns the [`Prioritiser`] plus the [`Behaviour`] the caller must
    /// register with the swarm. The behaviour's inbound handler dispatches into
    /// [`Shared::handle_request`].
    ///
    /// `p2p_context`'s known-peer set must cover every entry in `peers`
    /// (enforced by [`new_component`](crate::new_component)). Exchanges target
    /// `peers`; a target the context does not recognise is gated to a no-op
    /// handler and its exchange silently skipped, so the instance could
    /// otherwise reach consensus on a partial message set. Callers using this
    /// seam directly must uphold that invariant.
    #[allow(clippy::too_many_arguments)]
    pub fn new_internal(
        local_id: PeerId,
        peers: Vec<PeerId>,
        min_required: i64,
        consensus: Arc<dyn Consensus>,
        msg_validator: MsgVerifier,
        exchange_timeout: Duration,
        deadliner: DeadlinerHandle,
        p2p_context: P2PContext,
    ) -> (Self, Behaviour) {
        // The inbound handler needs engine state, but only the `Sender`-free
        // subset (`Shared`). Build that first so the handler can capture it
        // directly; the `Sender` (which itself depends on the handler) then
        // feeds the remaining `Inner` fields — no construction cycle.
        let shared = Arc::new(Shared {
            peers,
            msg_validator: Arc::new(msg_validator),
            quit: CancellationToken::new(),
            deadliner,
            req_buffers: Mutex::new(HashMap::new()),
        });

        let handler_shared = shared.clone();
        let inbound: InboundHandler = Arc::new(move |peer, msg| {
            let shared = handler_shared.clone();
            async move { shared.handle_request(peer, msg).await.map(Some) }.boxed()
        });

        let (behaviour, sender) = p2p::new(inbound, p2p_context);

        let inner = Arc::new(Inner {
            shared,
            local_id,
            sender,
            min_required,
            exchange_timeout,
            consensus: consensus.clone(),
        });

        let subs: Arc<Mutex<Vec<Subscriber>>> = Arc::new(Mutex::new(Vec::new()));

        // Wire consensus output to our subscribers: invoke each in order under
        // the lock (subscribers are synchronous and registered before `start`),
        // returning on the first error.
        let subs_for_consensus = subs.clone();
        consensus.subscribe_priority(Box::new(move |duty, result| {
            let subs = subs_for_consensus
                .lock()
                .expect("subscribers mutex poisoned");
            for sub in subs.iter() {
                sub(duty.clone(), result.clone())?;
            }
            Ok(())
        }));

        (Self { inner, subs }, behaviour)
    }

    /// Starts the background loop that drops request buffers for expired
    /// duties.
    ///
    /// Must be called exactly once. The returned task runs until `ct` is
    /// cancelled, then signals engine shutdown via the internal quit token.
    /// `expired` is the deadliner's expired-duty receiver.
    pub fn start(&self, mut expired: mpsc::Receiver<Duty>, ct: CancellationToken) {
        let shared = self.inner.shared.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = ct.cancelled() => break,
                    maybe = expired.recv() => match maybe {
                        Some(duty) => shared.delete_recv_buffer(duty),
                        None => break,
                    },
                }
            }
            // Cancelling `quit` on exit unblocks any in-flight `handle_request`.
            shared.quit.cancel();
        });
    }

    /// Registers an output subscriber invoked with each decided result.
    ///
    /// Not thread safe relative to a running instance; call before any
    /// [`Prioritiser::prioritise`].
    pub fn subscribe(&self, sub: Subscriber) {
        self.subs
            .lock()
            .expect("subscribers mutex poisoned")
            .push(sub);
    }

    /// Starts a new prioritisation instance for `msg` and runs it to
    /// completion.
    ///
    /// Drops the instance silently (returns `Ok`) if the duty has already
    /// expired. Otherwise blocks until consensus is proposed and `ct` is
    /// cancelled, returning [`Error::Cancelled`] on cancellation.
    pub async fn prioritise(&self, msg: PriorityMsg, ct: CancellationToken) -> Result<()> {
        let proto_duty = msg.duty.as_ref().ok_or(Error::InvalidMsgProtoFields)?;
        let duty = duty_from_proto(proto_duty);

        match self.inner.shared.deadliner.add(duty.clone()).await {
            AddOutcome::Scheduled => {}
            AddOutcome::FailedToCompute => {
                // The deadliner shares the engine/instance cancellation token, so
                // a failure while shutting down is a cancellation, not a genuine
                // compute error — report it like the run-loop cancel path.
                if ct.is_cancelled() || self.inner.shared.quit.is_cancelled() {
                    return Err(Error::Cancelled);
                }
                return Err(Error::DeadlineComputeFailed);
            }
            AddOutcome::AlreadyExpired | AddOutcome::NoDeadline => {
                tracing::warn!(%duty, "Dropping priority protocol instance for expired duty");
                return Ok(());
            }
        }

        let requests = self
            .inner
            .shared
            .take_req_receiver(duty.clone())
            .ok_or_else(|| Error::DuplicateInstance(duty.clone()))?;
        run_instance(&self.inner, duty, msg, requests, ct).await
    }
}

/// Runs a single priority instance: exchange messages, respond to peer
/// requests, and start consensus once all messages are collected or the
/// exchange timeout elapses.
///
/// Blocks until `ct` is cancelled (returning [`Error::Cancelled`]) or a
/// consensus calculation fails.
async fn run_instance(
    inner: &Inner,
    duty: Duty,
    own: PriorityMsg,
    mut request_rx: mpsc::Receiver<Request>,
    ct: CancellationToken,
) -> Result<()> {
    tracing::debug!(%duty, "Priority protocol instance started");

    // Seed `msgs` with our own message but leave the dedup set empty, so a
    // (rejected-by-validation) duplicate of our peer id surfaces in
    // `calculate_result` as a duplicate-peer error rather than being silently
    // swallowed.
    let mut msgs: Vec<PriorityMsg> = vec![own.clone()];
    let mut dedup_peers: HashSet<String> = HashSet::new();

    let mut cons_started = false;

    let (responses_tx, mut responses_rx) =
        mpsc::channel::<PriorityMsg>(inner.shared.peers.len().max(1));

    let exchange_timeout = tokio::time::sleep(inner.exchange_timeout);
    tokio::pin!(exchange_timeout);

    exchange(inner, responses_tx, own.clone(), &ct);

    loop {
        let mut should_start_consensus = false;

        tokio::select! {
            () = ct.cancelled() => return Err(Error::Cancelled),
            // Matching-pattern arms: when every sender drops the channel
            // closes, recv resolves to None, and the arm is disabled rather
            // than completing the select and re-looping. A disabled arm behaves
            // like a channel that simply never becomes ready again.
            Some(req) = request_rx.recv() => {
                add_msg(&mut msgs, &mut dedup_peers, req.msg);
                // Respond with our own message; the buffer guarantees the
                // receiver never blocks, so a dropped peer is harmless.
                let _ = req.response.send(own.clone());
            }
            Some(msg) = responses_rx.recv() => {
                add_msg(&mut msgs, &mut dedup_peers, msg);
            }
            () = &mut exchange_timeout, if !cons_started => {
                tracing::debug!(%duty, "Priority protocol instance exchange timeout, starting consensus");
                should_start_consensus = true;
            }
        }

        if should_start_consensus {
            cons_started = true;
            start_consensus(inner, &duty, &msgs, &ct)?;
        }

        if !cons_started && msgs.len() == inner.shared.peers.len() {
            tracing::debug!(%duty, "Priority protocol instance messages exchanged, starting consensus");
            cons_started = true;
            start_consensus(inner, &duty, &msgs, &ct)?;
        }
    }
}

/// Adds the first message seen from each peer to `msgs`.
fn add_msg(msgs: &mut Vec<PriorityMsg>, dedup: &mut HashSet<String>, msg: PriorityMsg) {
    if dedup.contains(&msg.peer_id) {
        return;
    }
    dedup.insert(msg.peer_id.clone());
    msgs.push(msg);
}

/// Initiates a priority message exchange with every peer except self.
///
/// Each peer is handled in its own task: send our message, validate the
/// response's peer id and signature, then forward it to the run loop. Failures
/// are dropped silently (the transport logs them).
fn exchange(
    inner: &Inner,
    responses: mpsc::Sender<PriorityMsg>,
    own: PriorityMsg,
    ct: &CancellationToken,
) {
    for &peer in &inner.shared.peers {
        if peer == inner.local_id {
            continue;
        }

        let ct = ct.clone();
        let sender = inner.sender.clone();
        let validator = inner.shared.msg_validator.clone();
        let responses = responses.clone();
        let own = own.clone();

        tokio::spawn(async move {
            let send = sender.send_receive(peer, own);
            let response = tokio::select! {
                () = ct.cancelled() => return,
                res = send => match res {
                    Ok(resp) => resp,
                    Err(_) => return, // Transport already logged.
                },
            };

            if peer.to_string() != response.peer_id {
                tracing::warn!(%peer, "Invalid priority message peer id");
                return;
            }

            if let Err(err) = validator(&response) {
                tracing::warn!(%peer, %err, "Invalid priority message from peer");
                return;
            }

            tokio::select! {
                () = ct.cancelled() => {}
                _ = responses.send(response) => {}
            }
        });
    }
}

/// Calculates the deterministic result and proposes it through consensus.
///
/// Consensus runs in a spawned task because it blocks until agreement while the
/// instance must keep servicing peer requests.
fn start_consensus(
    inner: &Inner,
    duty: &Duty,
    msgs: &[PriorityMsg],
    ct: &CancellationToken,
) -> Result<()> {
    let result = calculate_result(msgs, inner.min_required)
        .map_err(|e| Error::CalculateResult(Box::new(e)))?;

    let consensus = inner.consensus.clone();
    let duty = duty.clone();
    let ct = ct.clone();
    tokio::spawn(async move {
        // Fire-and-forget so the instance keeps servicing peer requests while
        // consensus runs. The instance token reaches consensus, so cancellation
        // tears the proposal down; a propose failure is unexpected.
        if let Err(err) = consensus.propose_priority(duty, result, &ct).await {
            tracing::warn!(%err, "Priority protocol consensus");
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use chrono::{Duration as ChronoDuration, Utc};
    use pluto_core::{
        corepb::v1::priority::{PriorityResult, PriorityTopicProposal},
        deadline::{DeadlineCalculator, DeadlinerTask},
    };

    use super::*;
    use crate::{
        component::{TopicProposal, new_msg_verifier, sign_msg},
        consensus::ConsensusError,
    };

    /// Calculator reporting every duty as expiring one hour from now, so the
    /// deadliner schedules (does not drop) duties under test.
    struct FutureCalculator;

    impl DeadlineCalculator for FutureCalculator {
        fn deadline(
            &self,
            _duty: &Duty,
        ) -> pluto_core::deadline::Result<Option<chrono::DateTime<Utc>>> {
            Ok(Some(
                Utc::now()
                    .checked_add_signed(ChronoDuration::hours(1))
                    .expect("deadline in range"),
            ))
        }
    }

    /// Mock consensus that decides on the first proposal by invoking
    /// subscribers and records every proposed result for assertions.
    #[derive(Default)]
    struct MockConsensus {
        subs: StdMutex<Vec<PrioritySubscriber>>,
        proposed: Arc<StdMutex<Vec<(Duty, PriorityResult)>>>,
    }

    #[async_trait::async_trait]
    impl Consensus for MockConsensus {
        async fn propose_priority(
            &self,
            duty: Duty,
            result: PriorityResult,
            _ct: &CancellationToken,
        ) -> std::result::Result<(), ConsensusError> {
            let first = {
                let mut proposed = self.proposed.lock().expect("proposed mutex");
                let first = proposed.is_empty();
                proposed.push((duty.clone(), result.clone()));
                first
            };
            if first {
                let subs = self.subs.lock().expect("subs mutex");
                for sub in subs.iter() {
                    sub(duty.clone(), result.clone()).map_err(|e| -> ConsensusError { e })?;
                }
            }
            Ok(())
        }

        fn subscribe_priority(&self, callback: PrioritySubscriber) {
            self.subs.lock().expect("subs mutex").push(callback);
        }
    }

    fn key_and_peer(seed: u8) -> (k256::SecretKey, PeerId) {
        let key = pluto_testutil::random::generate_insecure_k1_key(seed);
        let peer = pluto_p2p::peer::peer_id_from_key(key.public_key()).expect("peer id");
        (key, peer)
    }

    fn build_msg(key: &k256::SecretKey, peer: PeerId, prio: &str) -> PriorityMsg {
        let msg = PriorityMsg {
            duty: Some(ProtoDuty {
                slot: 97,
                r#type: 0,
            }),
            topics: vec![PriorityTopicProposal::from(&TopicProposal {
                topic: "topic".to_owned(),
                priorities: vec![prio.to_owned()],
            })],
            peer_id: peer.to_string(),
            signature: Default::default(),
        };
        sign_msg(&msg, key).expect("sign")
    }

    /// A second `prioritise` for a duty whose instance already holds the
    /// receiver surfaces [`Error::DuplicateInstance`] rather than panicking.
    #[tokio::test]
    async fn duplicate_instance_returns_error() {
        let (key, peer) = key_and_peer(0);
        let peers = vec![peer];
        let validator = new_msg_verifier(&peers).expect("verifier");
        let consensus = Arc::new(MockConsensus::default());
        let ct = CancellationToken::new();
        let (deadliner, _expired) = DeadlinerTask::start(ct.clone(), "test", FutureCalculator);
        let (prio, _behaviour) = Prioritiser::new_internal(
            peer,
            peers,
            1,
            consensus,
            validator,
            Duration::from_secs(3600),
            deadliner,
            P2PContext::default(),
        );

        let msg = build_msg(&key, peer, "v1");
        let duty = duty_from_proto(msg.duty.as_ref().expect("duty"));

        // Simulate a running instance that already took the duty's receiver.
        let _rx = prio
            .inner
            .shared
            .take_req_receiver(duty.clone())
            .expect("first take");

        // The duplicate is rejected after the (passing) deadliner gate.
        let res = prio.prioritise(msg, ct).await;
        assert!(matches!(res, Err(Error::DuplicateInstance(d)) if d == duty));
    }

    /// Single-node instance reaches consensus on the exchange timeout and
    /// delivers the decided result to the prioritiser's subscriber.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn single_node_prioritise_decides_and_notifies() {
        let (key, peer) = key_and_peer(0);
        let peers = vec![peer];
        let validator = new_msg_verifier(&peers).expect("verifier");

        let consensus = Arc::new(MockConsensus::default());
        let proposed = consensus.proposed.clone();

        let ct = CancellationToken::new();
        let (deadliner, expired) = DeadlinerTask::start(ct.clone(), "test", FutureCalculator);

        // A single-node instance has no peers to exchange with, so it starts
        // consensus on the exchange timeout (matching the reference, which
        // never short-circuits the empty exchange). Keep the timeout short so
        // the test decides promptly.
        let (prio, _behaviour) = Prioritiser::new_internal(
            peer,
            peers,
            1,
            consensus,
            validator,
            Duration::from_millis(100),
            deadliner,
            P2PContext::default(),
        );

        let (result_tx, mut result_rx) = mpsc::unbounded_channel();
        prio.subscribe(Box::new(move |duty, result| {
            let _ = result_tx.send((duty, result));
            Ok(())
        }));
        prio.start(expired, ct.clone());

        let msg = build_msg(&key, peer, "v1");
        let run_ct = ct.clone();
        let handle = tokio::spawn(async move { prio.prioritise(msg, run_ct).await });

        let (duty, result) = tokio::time::timeout(Duration::from_secs(5), result_rx.recv())
            .await
            .expect("subscriber notified")
            .expect("result delivered");
        assert_eq!(duty.slot, SlotNumber::new(97));
        assert_eq!(result.topics.len(), 1);

        // The mock recorded exactly one proposal.
        assert_eq!(proposed.lock().expect("proposed").len(), 1);

        // Cancelling returns the cancellation error from the run loop.
        ct.cancel();
        let res = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("join")
            .expect("task");
        assert!(matches!(res, Err(Error::Cancelled)));
    }

    /// The run loop makes progress only on real events, never by busy-spinning,
    /// and cancellation completes promptly.
    ///
    /// Uses a paused clock: tokio auto-advances virtual time only when the
    /// runtime is otherwise idle (every task parked). The assertions rely on
    /// that idleness — they would not resolve if the loop spun. Concretely the
    /// empty single-peer exchange does not start consensus until the exchange
    /// timeout fires (event-driven progress), the loop then parks (it does not
    /// complete on its own), and cancellation ends it at once.
    #[tokio::test(start_paused = true)]
    async fn run_instance_makes_progress_only_on_events() {
        let (key, peer) = key_and_peer(0);
        let peers = vec![peer];
        let validator = new_msg_verifier(&peers).expect("verifier");
        let consensus = Arc::new(MockConsensus::default());
        let proposed = consensus.proposed.clone();

        let ct = CancellationToken::new();
        let (deadliner, expired) = DeadlinerTask::start(ct.clone(), "test", FutureCalculator);
        let exchange_timeout = Duration::from_secs(2);
        let (prio, _behaviour) = Prioritiser::new_internal(
            peer,
            peers,
            1,
            consensus,
            validator,
            exchange_timeout,
            deadliner,
            P2PContext::default(),
        );
        prio.start(expired, ct.clone());

        let msg = build_msg(&key, peer, "v1");
        let run_ct = ct.clone();
        let handle = tokio::spawn(async move { prio.prioritise(msg, run_ct).await });

        // Before the exchange timeout the empty exchange yields no event, so no
        // consensus is proposed. The clock only advances here because the loop
        // is parked rather than spinning.
        tokio::time::sleep(exchange_timeout / 2).await;
        assert_eq!(proposed.lock().expect("proposed").len(), 0);

        // After the exchange timeout the loop wakes on that single event and
        // proposes exactly once, then parks again.
        tokio::time::sleep(exchange_timeout).await;
        assert_eq!(proposed.lock().expect("proposed").len(), 1);
        assert!(!handle.is_finished());

        ct.cancel();
        let res = handle.await.expect("task joins");
        assert!(matches!(res, Err(Error::Cancelled)));
    }

    /// `handle_request` does not pin a stream indefinitely: with no run loop to
    /// fulfil the response, it returns the receive-timeout error after the
    /// deadline elapses.
    #[tokio::test(start_paused = true)]
    async fn handle_request_times_out_waiting_for_response() {
        let (key, peer) = key_and_peer(0);
        let peers = vec![peer];
        let validator = new_msg_verifier(&peers).expect("verifier");
        let consensus = Arc::new(MockConsensus::default());

        let ct = CancellationToken::new();
        let (deadliner, _expired) = DeadlinerTask::start(ct.clone(), "test", FutureCalculator);
        let (prio, _behaviour) = Prioritiser::new_internal(
            peer,
            peers,
            1,
            consensus,
            validator,
            Duration::from_secs(3600),
            deadliner,
            P2PContext::default(),
        );

        // No prioritise instance runs for this duty, so the buffered request's
        // response oneshot is never fulfilled; the wait must time out.
        let msg = build_msg(&key, peer, "v1");
        let err = tokio::time::timeout(
            RECEIVE_TIMEOUT + Duration::from_secs(1),
            prio.inner.shared.handle_request(peer, msg),
        )
        .await
        .expect("handle_request returns within the receive timeout")
        .expect_err("response wait times out");
        assert!(matches!(err, Error::TimeoutWaiting));
        assert_eq!(err.to_string(), "timeout waiting for proposed priorities");
    }

    /// `handle_request` rejects a message whose peer id differs from the
    /// connection's peer id.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_request_invalid_peer_id() {
        let (key, peer) = key_and_peer(0);
        let peers = vec![peer];
        let validator = new_msg_verifier(&peers).expect("verifier");
        let consensus = Arc::new(MockConsensus::default());

        let ct = CancellationToken::new();
        let (deadliner, _expired) = DeadlinerTask::start(ct.clone(), "test", FutureCalculator);
        let (prio, _behaviour) = Prioritiser::new_internal(
            peer,
            peers,
            1,
            consensus,
            validator,
            Duration::from_secs(3600),
            deadliner,
            P2PContext::default(),
        );

        let msg = build_msg(&key, peer, "v1");
        // Use a different connection peer id than the message claims.
        let other = PeerId::random();
        let err = prio
            .inner
            .shared
            .handle_request(other, msg)
            .await
            .expect_err("peer id mismatch");
        assert!(matches!(err, Error::InvalidPeerId));
        assert_eq!(err.to_string(), "invalid priority message peer id");
    }

    /// `handle_request` rejects a message for a duty the deadliner cannot
    /// schedule (already expired).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_request_duty_expired() {
        struct ExpiredCalculator;
        impl DeadlineCalculator for ExpiredCalculator {
            fn deadline(
                &self,
                _duty: &Duty,
            ) -> pluto_core::deadline::Result<Option<chrono::DateTime<Utc>>> {
                Ok(Some(
                    Utc::now()
                        .checked_sub_signed(ChronoDuration::hours(1))
                        .expect("deadline in range"),
                ))
            }
        }

        let (key, peer) = key_and_peer(0);
        let peers = vec![peer];
        let validator = new_msg_verifier(&peers).expect("verifier");
        let consensus = Arc::new(MockConsensus::default());

        let ct = CancellationToken::new();
        let (deadliner, _expired) = DeadlinerTask::start(ct.clone(), "test", ExpiredCalculator);
        let (prio, _behaviour) = Prioritiser::new_internal(
            peer,
            peers,
            1,
            consensus,
            validator,
            Duration::from_secs(3600),
            deadliner,
            P2PContext::default(),
        );

        let msg = build_msg(&key, peer, "v1");
        let err = prio
            .inner
            .shared
            .handle_request(peer, msg)
            .await
            .expect_err("duty expired");
        assert!(matches!(err, Error::DutyExpired));
        assert_eq!(err.to_string(), "duty expired");
    }

    /// The `Start` cleanup loop drops the duty's request buffer when the
    /// deadliner reports it expired.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_cleans_expired_buffer() {
        let (_key, peer) = key_and_peer(0);
        let peers = vec![peer];
        let validator = new_msg_verifier(&peers).expect("verifier");
        let consensus = Arc::new(MockConsensus::default());

        let ct = CancellationToken::new();
        // The cleanup loop consumes whatever the deadliner emits; drive it with
        // a hand-built expired-duty channel to assert deletion deterministically.
        let (expired_tx, expired_rx) = mpsc::channel(1);
        let (deadliner, _real_expired) = DeadlinerTask::start(ct.clone(), "test", FutureCalculator);
        let (prio, _behaviour) = Prioritiser::new_internal(
            peer,
            peers,
            1,
            consensus,
            validator,
            Duration::from_secs(3600),
            deadliner,
            P2PContext::default(),
        );
        prio.start(expired_rx, ct.clone());

        let duty = Duty::new(SlotNumber::new(42), DutyType::Unknown);
        let _ = prio.inner.shared.get_req_buffer(duty.clone());
        assert!(
            prio.inner
                .shared
                .req_buffers
                .lock()
                .expect("lock")
                .contains_key(&duty)
        );

        expired_tx.send(duty.clone()).await.expect("send expired");

        // Poll until the cleanup loop removes the entry.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if !prio
                    .inner
                    .shared
                    .req_buffers
                    .lock()
                    .expect("lock")
                    .contains_key(&duty)
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("buffer cleaned");
    }
}
