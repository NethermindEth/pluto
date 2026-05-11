//! FROST DKG P2P transport.
//!
//! This module provides the network transport used by `frost.rs`. The local
//! FROST code creates cryptographic round messages; this module moves those
//! messages between cluster nodes over libp2p.
//!
//! Round 1 has a public broadcast path and a private direct-P2P path:
//!
//! ```text
//! ROUND 1
//! =======
//!
//! Public broadcast, same data to everyone:
//!
//!   node1 === Round1Bcast(commitments/proof) ===> node1,node2,node3,node4
//!   node2 === Round1Bcast(commitments/proof) ===> node1,node2,node3,node4
//!   node3 === Round1Bcast(commitments/proof) ===> node1,node2,node3,node4
//!   node4 === Round1Bcast(commitments/proof) ===> node1,node2,node3,node4
//!
//! Private direct P2P, different data per target:
//!
//!              +-- ShamirShare(for share_idx 2) --> node2
//!   node1 -----+-- ShamirShare(for share_idx 3) --> node3
//!              +-- ShamirShare(for share_idx 4) --> node4
//!
//!              +-- ShamirShare(for share_idx 1) --> node1
//!   node2 -----+-- ShamirShare(for share_idx 3) --> node3
//!              +-- ShamirShare(for share_idx 4) --> node4
//!
//!   ... same pattern for node3 and node4.
//!
//! Each direct message contains the private shares for that target node across
//! all validators in the DKG run. The shares cannot be broadcast because they
//! are secret, and node X does not send the same share to every peer.
//! ```
//!
//! Round 2 is broadcast-only. After round 1, each node has public commitments
//! from all nodes and private shares sent specifically to itself. It verifies
//! those private shares and broadcasts public verification material:
//!
//! ```text
//! ROUND 2
//! =======
//!
//!   node1 === Round2Bcast(public verification shares) ===> node1,node2,node3,node4
//!   node2 === Round2Bcast(public verification shares) ===> node1,node2,node3,node4
//!   node3 === Round2Bcast(public verification shares) ===> node1,node2,node3,node4
//!   node4 === Round2Bcast(public verification shares) ===> node1,node2,node3,node4
//!
//! No direct P2P is needed in round 2 because there is no new per-target secret.
//! ```
//!
//! End-to-end this module bridges the async FROST transport API to libp2p's
//! event-driven swarm:
//!
//! ```text
//! run_frost_parallel
//!        |
//!        v
//!   FrostP2P::round1
//!        |-----------------------> bcast::Component
//!        |                              |
//!        |                              v
//!        |                       bcast::Behaviour
//!        |                              |
//!        |                              v
//!        |                    FrostP2PHandle::handle_bcast_event
//!        |
//!        +-----------------------> FrostP2PSender
//!                                       |
//!                                       v
//!                                FrostP2PBehaviour
//!                                       |
//!                                       v
//!                                FrostP2PHandler
//!                                       |
//!                                       v
//!                              direct libp2p streams
//!
//!   FrostP2P::round2
//!        |
//!        +-----------------------> bcast::Component
//! ```
//!
//! The module is split across two integration surfaces:
//!
//! - [`FrostP2PBehaviour`] owns the direct round-1 P2P libp2p protocol.
//! - [`FrostP2P`] implements the FROST transport by combining direct P2P with
//!   reliable broadcast through [`bcast::Component`].
//!
//! The outer DKG network behaviour must install both `bcast::Behaviour` and
//! [`FrostP2PBehaviour`]. It must also forward FROST broadcast completion
//! events emitted by `bcast::Behaviour` into
//! [`FrostP2PHandle::handle_bcast_event`]. Without that event bridge,
//! [`FrostP2P`] cannot observe broadcast completion and `round1`/`round2` will
//! wait until cancellation.
//!
//! FROST observation events are emitted through [`FrostP2PBehaviour`] as swarm
//! events. Transport-level code forwards round and broadcast milestones back to
//! the behaviour through the same command channel used for direct sends.
//!
//! These transport objects are single-use for one DKG run. Dedup state is
//! intentionally not reset; create a fresh [`FrostP2PBehaviour`],
//! [`FrostP2PHandle`], and [`FrostP2P`] for each DKG.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use either::Either;
use futures::{AsyncWriteExt, FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use libp2p::{
    Multiaddr, PeerId,
    core::upgrade::ReadyUpgrade,
    swarm::{
        ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, FromSwarm,
        NetworkBehaviour, NotifyHandler, Stream, StreamProtocol, StreamUpgradeError,
        SubstreamProtocol, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
        dial_opts::{DialOpts, PeerCondition},
        dummy,
        handler::{
            ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
        },
    },
};
use pluto_crypto::types::{G1_COMPRESSED_LENGTH, SCALAR_LENGTH};
use pluto_frost::{
    G1Projective,
    kryptology::{self, Round1Bcast, Round2Bcast, ShamirShare},
};
use pluto_p2p::p2p_context::P2PContext;
use prost::bytes::Bytes;
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use crate::{
    bcast,
    dkgpb::v1::frost::{
        FrostMsgKey, FrostRound1Cast, FrostRound1Casts, FrostRound1P2p, FrostRound1ShamirShare,
        FrostRound2Cast, FrostRound2Casts,
    },
    frost::{FTransport, FrostError, MsgKey},
};

/// bcast message ID for FROST round-1 broadcasts.
pub(crate) const ROUND1_CAST_ID: &str = "/charon/dkg/frost/2.0.0/round1/cast";
/// bcast message ID for FROST round-2 broadcasts.
pub(crate) const ROUND2_CAST_ID: &str = "/charon/dkg/frost/2.0.0/round2/cast";
/// Direct P2P protocol for FROST round-1 Shamir share delivery.
pub(crate) const ROUND1_P2P_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/charon/dkg/frost/2.0.0/round1/p2p");

/// Charon's default direct-P2P inbound read timeout.
pub(crate) const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Charon's default direct-P2P send timeout.
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(7);

/// FROST direct-P2P delivery errors.
#[derive(Debug, thiserror::Error)]
pub enum FrostP2PError {
    /// The behaviour task is no longer running.
    #[error("frost p2p behaviour is no longer running")]
    BehaviourClosed,
    /// The outbound send failed.
    #[error("outbound send failed: {0}")]
    SendFailed(String),
    /// The peer was disconnected before the send completed.
    #[error("peer is not connected: {0}")]
    PeerNotConnected(PeerId),
    /// The peer is outside this FROST transport's configured peer set.
    #[error("unknown frost p2p peer: {0}")]
    UnknownPeer(PeerId),
    /// The send result channel closed.
    #[error("send result channel closed")]
    ResultClosed,
}

#[derive(Debug)]
pub(crate) enum InEvent {
    Send { op_id: u64, msg: FrostRound1P2p },
    CancelAllPending,
}

#[derive(Debug)]
pub(crate) enum OutEvent {
    Received(FrostRound1P2p),
    Sent { op_id: u64 },
    Failed { op_id: u64, message: String },
}

/// Event emitted while the FROST P2P transport progresses through its rounds.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum FrostP2PEvent {
    /// A FROST transport round started.
    RoundStarted {
        /// Round number.
        round: u8,
    },
    /// A FROST broadcast was started.
    BroadcastStarted {
        /// Round number.
        round: u8,
    },
    /// A FROST broadcast completed.
    BroadcastCompleted {
        /// Round number.
        round: u8,
    },
    /// A FROST broadcast failed.
    BroadcastFailed {
        /// Round number.
        round: u8,
        /// Failure message.
        error: String,
    },
    /// Round-1 direct P2P sends started.
    DirectSendStarted {
        /// Number of target peers.
        peer_count: usize,
    },
    /// A round-1 direct P2P message was delivered to a peer.
    DirectSent {
        /// Target peer.
        peer_id: PeerId,
    },
    /// A round-1 direct P2P message failed to deliver.
    DirectSendFailed {
        /// Target peer.
        peer_id: PeerId,
        /// Failure message.
        error: String,
    },
    /// A valid round-1 direct P2P message was received from a peer.
    DirectReceived {
        /// Source peer.
        peer_id: PeerId,
    },
    /// A FROST transport round completed.
    RoundCompleted {
        /// Round number.
        round: u8,
    },
    /// Both FROST P2P transport rounds completed.
    ProtocolCompleted,
}

type ActiveFuture = BoxFuture<'static, Option<OutEvent>>;
type Round1Response = (HashMap<MsgKey, Round1Bcast>, HashMap<MsgKey, ShamirShare>);

struct PeerShareIndices {
    peers_by_share_idx: HashMap<u32, PeerId>,
    share_idx_by_peer: HashMap<PeerId, u32>,
}

/// Connection handler for the FROST round-1 direct P2P protocol.
pub(crate) struct FrostP2PHandler {
    pending_open: VecDeque<(u64, FrostRound1P2p)>,
    active_futures: FuturesUnordered<ActiveFuture>,
}

impl FrostP2PHandler {
    fn new() -> Self {
        Self {
            pending_open: VecDeque::new(),
            active_futures: FuturesUnordered::new(),
        }
    }

    fn handle_fully_negotiated_inbound(&mut self, mut stream: Stream) {
        self.active_futures.push(
            async move {
                read_inbound_message(&mut stream)
                    .await
                    .map(OutEvent::Received)
            }
            .boxed(),
        );
    }

    fn handle_fully_negotiated_outbound(
        &mut self,
        mut stream: Stream,
        (op_id, msg): (u64, FrostRound1P2p),
    ) {
        self.active_futures
            .push(async move { write_outbound_message(&mut stream, op_id, &msg).await }.boxed());
    }

    fn handle_dial_upgrade_error<E>(
        &mut self,
        (op_id, _): (u64, FrostRound1P2p),
        error: StreamUpgradeError<E>,
    ) where
        E: std::error::Error + Send + Sync + 'static,
    {
        let message = match error {
            StreamUpgradeError::NegotiationFailed => "protocol negotiation failed".to_string(),
            StreamUpgradeError::Timeout => "operation timed out".to_string(),
            StreamUpgradeError::Io(error) => error.to_string(),
            StreamUpgradeError::Apply(error) => error.to_string(),
        };
        self.active_futures
            .push(async move { Some(OutEvent::Failed { op_id, message }) }.boxed());
    }
}

impl ConnectionHandler for FrostP2PHandler {
    type FromBehaviour = InEvent;
    type InboundOpenInfo = ();
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundOpenInfo = (u64, FrostRound1P2p);
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type ToBehaviour = OutEvent;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(ReadyUpgrade::new(ROUND1_P2P_PROTOCOL), ())
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            InEvent::Send { op_id, msg } => self.pending_open.push_back((op_id, msg)),
            InEvent::CancelAllPending => self.pending_open.clear(),
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if let Some(open_info) = self.pending_open.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(ReadyUpgrade::new(ROUND1_P2P_PROTOCOL), open_info),
            });
        }

        while let Poll::Ready(Some(event)) = self.active_futures.poll_next_unpin(cx) {
            if let Some(event) = event {
                return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
            }
        }

        Poll::Pending
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol, ..
            }) => self.handle_fully_negotiated_inbound(protocol),
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol,
                info,
                ..
            }) => self.handle_fully_negotiated_outbound(protocol, info),
            ConnectionEvent::DialUpgradeError(DialUpgradeError { info, error }) => {
                self.handle_dial_upgrade_error(info, error);
            }
            _ => {}
        }
    }
}

async fn read_inbound_message(stream: &mut Stream) -> Option<FrostRound1P2p> {
    let result = timeout(
        RECEIVE_TIMEOUT,
        pluto_p2p::proto::read_protobuf_with_max_size::<FrostRound1P2p, _>(
            stream,
            pluto_p2p::proto::MAX_MESSAGE_SIZE,
        ),
    )
    .await;
    let msg = match result {
        Ok(Ok(msg)) => Some(msg),
        Ok(Err(error)) => {
            warn!(%error, "failed to read frost p2p inbound message");
            None
        }
        Err(_) => {
            warn!("timed out reading frost p2p inbound message");
            None
        }
    };

    if let Err(error) = stream.close().await {
        warn!(%error, "failed to close frost p2p inbound stream");
    }

    msg
}

async fn write_outbound_message(
    stream: &mut Stream,
    op_id: u64,
    msg: &FrostRound1P2p,
) -> Option<OutEvent> {
    let result = timeout(SEND_TIMEOUT, async {
        pluto_p2p::proto::write_protobuf(stream, msg).await?;
        stream.close().await
    })
    .await;

    Some(match result {
        Ok(Ok(())) => OutEvent::Sent { op_id },
        Ok(Err(error)) => OutEvent::Failed {
            op_id,
            message: error.to_string(),
        },
        Err(_) => OutEvent::Failed {
            op_id,
            message: "operation timed out".to_string(),
        },
    })
}

type SendResultTx = oneshot::Sender<Result<(), FrostP2PError>>;

#[derive(Debug)]
enum SendCommand {
    Send {
        peer_id: PeerId,
        msg: FrostRound1P2p,
        result_tx: SendResultTx,
    },
    EmitEvent(FrostP2PEvent),
    CancelAll,
}

/// User-facing FROST direct-P2P sender.
#[derive(Clone)]
pub(crate) struct FrostP2PSender {
    cmd_tx: mpsc::UnboundedSender<SendCommand>,
}

impl FrostP2PSender {
    fn new(cmd_tx: mpsc::UnboundedSender<SendCommand>) -> Self {
        Self { cmd_tx }
    }

    fn emit_event(&self, event: FrostP2PEvent) {
        if self.cmd_tx.send(SendCommand::EmitEvent(event)).is_err() {
            debug!("frost p2p behaviour dropped before observation event");
        }
    }

    /// Sends a round-1 P2P message to `peer_id` and waits for stream delivery.
    pub async fn send(
        &self,
        peer_id: PeerId,
        msg: &FrostRound1P2p,
        cancellation: &CancellationToken,
    ) -> Result<(), FrostError> {
        if cancellation.is_cancelled() {
            return Err(FrostError::Cancelled);
        }

        let (result_tx, result_rx) = oneshot::channel();
        self.cmd_tx
            .send(SendCommand::Send {
                peer_id,
                msg: msg.clone(),
                result_tx,
            })
            .map_err(|_| FrostP2PError::BehaviourClosed)?;

        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                let _ = self.cmd_tx.send(SendCommand::CancelAll);
                Err(FrostError::Cancelled)
            }
            result = result_rx => Ok(result.map_err(|_| FrostP2PError::ResultClosed)??),
        }
    }
}

/// User-facing handle for the FROST direct-P2P behaviour.
pub(crate) struct FrostP2PHandle {
    /// Receives `(sender_peer_id, message)` for inbound round-1 P2P messages.
    inbound_rx: Option<mpsc::UnboundedReceiver<(PeerId, FrostRound1P2p)>>,
    sender: FrostP2PSender,
    bcast_event_tx: mpsc::UnboundedSender<bcast::Event>,
    bcast_event_rx: Option<mpsc::UnboundedReceiver<bcast::Event>>,
}

impl FrostP2PHandle {
    /// Forwards FROST bcast completion events into the round state machine.
    ///
    /// The outer DKG network behaviour should route only events for FROST
    /// message IDs here. Events for other bcast users are ignored defensively,
    /// since this handle cannot re-deliver them to their owner.
    pub(crate) fn handle_bcast_event(&self, event: bcast::Event) -> Result<(), FrostError> {
        let msg_id = match &event {
            bcast::Event::BroadcastCompleted { msg_id }
            | bcast::Event::BroadcastFailed { msg_id, .. } => msg_id.as_str(),
        };
        if !is_frost_bcast_msg_id(msg_id) {
            debug!(msg_id, "ignoring non-FROST bcast event");
            return Ok(());
        }

        self.bcast_event_tx
            .send(event)
            .map_err(|_| FrostError::ChannelClosed("frost bcast event channel"))
    }

    fn take_inbound_rx(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<(PeerId, FrostRound1P2p)>, FrostError> {
        self.inbound_rx
            .take()
            .ok_or(FrostError::P2PInboundReceiverAlreadyTaken)
    }

    fn take_bcast_event_rx(&mut self) -> Result<mpsc::UnboundedReceiver<bcast::Event>, FrostError> {
        self.bcast_event_rx
            .take()
            .ok_or(FrostError::BcastEventReceiverAlreadyTaken)
    }
}

/// libp2p behaviour for FROST round-1 direct P2P.
pub(crate) struct FrostP2PBehaviour {
    peers: HashSet<PeerId>,
    p2p_context: P2PContext,
    share_idx_by_peer: HashMap<PeerId, u32>,
    local_share_idx: u32,
    num_validators: usize,
    inbound_tx: mpsc::UnboundedSender<(PeerId, FrostRound1P2p)>,
    /// Direct P2P dedup for this DKG run; create a fresh behaviour per DKG.
    accepted_round1_p2p: HashSet<PeerId>,
    cmd_rx: mpsc::UnboundedReceiver<SendCommand>,
    pending_events: VecDeque<ToSwarm<FrostP2PEvent, InEvent>>,
    pending_by_peer: HashMap<PeerId, VecDeque<(u64, FrostRound1P2p)>>,
    result_by_op: HashMap<u64, (PeerId, SendResultTx)>,
    next_op_id: u64,
}

impl FrostP2PBehaviour {
    /// Creates a new FROST P2P behaviour and handle.
    pub(crate) fn new(
        p2p_context: P2PContext,
        peers: impl IntoIterator<Item = PeerId>,
        share_idx_by_peer: HashMap<PeerId, u32>,
        local_share_idx: u32,
        num_validators: usize,
    ) -> (Self, FrostP2PHandle) {
        let peers = peers.into_iter().collect::<HashSet<_>>();
        let num_peers = peers.len();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (bcast_event_tx, bcast_event_rx) = mpsc::unbounded_channel();
        let sender = FrostP2PSender::new(cmd_tx);
        (
            Self {
                peers,
                p2p_context,
                share_idx_by_peer,
                local_share_idx,
                num_validators,
                inbound_tx,
                accepted_round1_p2p: HashSet::with_capacity(num_peers),
                cmd_rx,
                pending_events: VecDeque::new(),
                pending_by_peer: HashMap::new(),
                result_by_op: HashMap::new(),
                next_op_id: 0,
            },
            FrostP2PHandle {
                inbound_rx: Some(inbound_rx),
                sender,
                bcast_event_tx,
                bcast_event_rx: Some(bcast_event_rx),
            },
        )
    }

    fn connection_handler_for_peer(&self, peer_id: PeerId) -> THandler<Self> {
        if self.peers.contains(&peer_id) {
            Either::Left(FrostP2PHandler::new())
        } else {
            Either::Right(dummy::ConnectionHandler)
        }
    }

    fn next_op_id(&mut self) -> u64 {
        let current = self.next_op_id;
        self.next_op_id = self.next_op_id.wrapping_add(1);
        current
    }

    fn is_connected(&self, peer_id: &PeerId) -> bool {
        !self
            .p2p_context
            .peer_store_lock()
            .connections_to_peer(peer_id)
            .is_empty()
    }

    fn drain_commands(&mut self, cx: &mut Context<'_>) {
        while let Poll::Ready(Some(command)) = self.cmd_rx.poll_recv(cx) {
            match command {
                SendCommand::Send {
                    peer_id,
                    msg,
                    result_tx,
                } => {
                    let op_id = self.next_op_id();
                    self.result_by_op.insert(op_id, (peer_id, result_tx));
                    self.enqueue_send(peer_id, op_id, msg);
                }
                SendCommand::EmitEvent(event) => {
                    self.pending_events.push_back(ToSwarm::GenerateEvent(event))
                }
                SendCommand::CancelAll => self.cancel_all_sends(),
            }
        }
    }

    fn enqueue_send(&mut self, peer_id: PeerId, op_id: u64, msg: FrostRound1P2p) {
        if !self.peers.contains(&peer_id) {
            if let Some(event) = self.complete_send(op_id, Err(FrostP2PError::UnknownPeer(peer_id)))
            {
                self.pending_events.push_back(ToSwarm::GenerateEvent(event));
            }
            return;
        }

        if self.is_connected(&peer_id) {
            self.pending_events.push_back(ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event: InEvent::Send { op_id, msg },
            });
            return;
        }

        self.pending_by_peer
            .entry(peer_id)
            .or_default()
            .push_back((op_id, msg));
        self.pending_events.push_back(ToSwarm::Dial {
            opts: DialOpts::peer_id(peer_id)
                .condition(PeerCondition::DisconnectedAndNotDialing)
                .build(),
        });
    }

    fn flush_pending_for_peer(&mut self, peer_id: PeerId) {
        let Some(mut pending) = self.pending_by_peer.remove(&peer_id) else {
            return;
        };

        while let Some((op_id, msg)) = pending.pop_front() {
            self.pending_events.push_back(ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event: InEvent::Send { op_id, msg },
            });
        }
    }

    fn complete_send(
        &mut self,
        op_id: u64,
        result: Result<(), FrostP2PError>,
    ) -> Option<FrostP2PEvent> {
        if let Some((peer_id, result_tx)) = self.result_by_op.remove(&op_id) {
            let event = match &result {
                Ok(()) => FrostP2PEvent::DirectSent { peer_id },
                Err(error) => {
                    let error = error.to_string();
                    FrostP2PEvent::DirectSendFailed { peer_id, error }
                }
            };
            let _ = result_tx.send(result);
            return Some(event);
        }

        None
    }

    fn cancel_all_sends(&mut self) {
        let peers = self
            .result_by_op
            .values()
            .map(|(peer_id, _)| *peer_id)
            .collect::<HashSet<_>>();
        self.result_by_op.clear();
        self.pending_by_peer.clear();
        self.pending_events.retain(|event| match event {
            ToSwarm::NotifyHandler {
                event: InEvent::Send { .. },
                ..
            } => false,
            ToSwarm::Dial { opts } => opts
                .get_peer_id()
                .is_none_or(|peer_id| !peers.contains(&peer_id)),
            _ => true,
        });

        for peer_id in peers {
            // This can only cancel handler-local queued opens. If the handler has
            // already started writing, stale completion is ignored because all
            // result waiters were removed above.
            self.pending_events.push_back(ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event: InEvent::CancelAllPending,
            });
        }
    }

    fn fail_peer_sends(&mut self, peer_id: PeerId) {
        let pending_ops = self
            .pending_by_peer
            .remove(&peer_id)
            .unwrap_or_default()
            .into_iter()
            .map(|(op_id, _)| op_id)
            .collect::<Vec<_>>();
        for op_id in pending_ops {
            if let Some(event) =
                self.complete_send(op_id, Err(FrostP2PError::PeerNotConnected(peer_id)))
            {
                self.pending_events.push_back(ToSwarm::GenerateEvent(event));
            }
        }

        let active_ops = self
            .result_by_op
            .iter()
            .filter_map(|(op_id, (peer, _))| (*peer == peer_id).then_some(*op_id))
            .collect::<Vec<_>>();
        for op_id in active_ops {
            if let Some(event) =
                self.complete_send(op_id, Err(FrostP2PError::PeerNotConnected(peer_id)))
            {
                self.pending_events.push_back(ToSwarm::GenerateEvent(event));
            }
        }
    }
}

impl NetworkBehaviour for FrostP2PBehaviour {
    type ConnectionHandler = Either<FrostP2PHandler, dummy::ConnectionHandler>;
    type ToSwarm = FrostP2PEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.connection_handler_for_peer(peer))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.connection_handler_for_peer(peer))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(event) => {
                self.flush_pending_for_peer(event.peer_id);
            }
            FromSwarm::ConnectionClosed(event) if !self.is_connected(&event.peer_id) => {
                // PlutoBehaviour runs conn_logger before inner behaviours, so the
                // shared peer store already reflects this close. Multiple live
                // connections per peer are valid; only fail sends when none remain.
                self.fail_peer_sends(event.peer_id);
            }
            FromSwarm::DialFailure(event) => {
                if let Some(peer_id) = event.peer_id {
                    if self.is_connected(&peer_id) {
                        self.flush_pending_for_peer(peer_id);
                    } else {
                        self.fail_peer_sends(peer_id);
                    }
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        let event = match event {
            Either::Left(event) => event,
            Either::Right(unreachable) => match unreachable {},
        };
        match event {
            OutEvent::Received(msg) => {
                if let Err(error) = validate_round1_p2p(
                    peer_id,
                    &self.share_idx_by_peer,
                    self.local_share_idx,
                    &msg,
                    self.num_validators,
                ) {
                    warn!(%peer_id, %error, "dropping invalid round 1 p2p message");
                    return;
                }
                if !self.accepted_round1_p2p.insert(peer_id) {
                    debug!(%peer_id, "ignoring duplicate round 1 p2p message");
                    return;
                }
                if let Err(error) = self.inbound_tx.send((peer_id, msg)) {
                    warn!(%peer_id, %error, "dropping round 1 p2p message because inbound receiver is closed");
                    return;
                }
                self.pending_events.push_back(ToSwarm::GenerateEvent(
                    FrostP2PEvent::DirectReceived { peer_id },
                ));
            }
            OutEvent::Sent { op_id } => {
                if let Some(event) = self.complete_send(op_id, Ok(())) {
                    self.pending_events.push_back(ToSwarm::GenerateEvent(event));
                }
            }
            OutEvent::Failed { op_id, message } => {
                if let Some(event) =
                    self.complete_send(op_id, Err(FrostP2PError::SendFailed(message)))
                {
                    self.pending_events.push_back(ToSwarm::GenerateEvent(event));
                }
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.drain_commands(cx);

        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event.map_in(Either::Left));
        }

        Poll::Pending
    }
}

/// P2P transport for FROST rounds. Registers bcast callbacks on construction.
pub(crate) struct FrostP2P {
    bcast_comp: bcast::Component,
    frost_sender: FrostP2PSender,
    bcast_event_rx: mpsc::UnboundedReceiver<bcast::Event>,
    round1_casts_tx: mpsc::UnboundedSender<FrostRound1Casts>,
    round1_casts_rx: mpsc::UnboundedReceiver<FrostRound1Casts>,
    round1_p2p_rx: mpsc::UnboundedReceiver<(PeerId, FrostRound1P2p)>,
    round2_casts_tx: mpsc::UnboundedSender<FrostRound2Casts>,
    round2_casts_rx: mpsc::UnboundedReceiver<FrostRound2Casts>,
    peers_by_share_idx: HashMap<u32, PeerId>,
    local_share_idx: u32,
    num_peers: usize,
}

/// Creates a FROST P2P transport and registers its bcast callbacks.
///
/// The `frost_handle` must come from the [`FrostP2PBehaviour`] installed in the
/// same outer network behaviour that owns `bcast_comp`. The outer behaviour
/// must keep using that handle to forward [`bcast::Event`] values through
/// [`FrostP2PHandle::handle_bcast_event`].
pub(crate) async fn new_frost_p2p(
    bcast_comp: bcast::Component,
    frost_handle: &mut FrostP2PHandle,
    peers: &HashMap<PeerId, u32>,
    local_share_idx: u32,
    threshold: usize,
    num_validators: usize,
) -> Result<FrostP2P, FrostError> {
    let peer_share_indices = validate_peer_share_indices(peers, local_share_idx)?;

    let (round1_casts_tx, round1_casts_rx) = mpsc::unbounded_channel();
    let (round2_casts_tx, round2_casts_rx) = mpsc::unbounded_channel();
    let round1_p2p_rx = frost_handle.take_inbound_rx()?;
    let bcast_event_rx = frost_handle.take_bcast_event_rx()?;

    register_round1_bcast(
        &bcast_comp,
        peer_share_indices.share_idx_by_peer.clone(),
        round1_casts_tx.clone(),
        threshold,
        num_validators,
    )
    .await?;
    register_round2_bcast(
        &bcast_comp,
        peer_share_indices.share_idx_by_peer.clone(),
        round2_casts_tx.clone(),
        num_validators,
    )
    .await?;

    Ok(FrostP2P {
        bcast_comp,
        frost_sender: frost_handle.sender.clone(),
        bcast_event_rx,
        round1_casts_tx,
        round1_casts_rx,
        round1_p2p_rx,
        round2_casts_tx,
        round2_casts_rx,
        peers_by_share_idx: peer_share_indices.peers_by_share_idx,
        local_share_idx,
        num_peers: peers.len(),
    })
}

fn validate_peer_share_indices(
    peers: &HashMap<PeerId, u32>,
    local_share_idx: u32,
) -> Result<PeerShareIndices, FrostError> {
    let mut peers_by_share_idx = HashMap::new();
    let mut share_idx_by_peer = HashMap::new();

    for (&peer_id, &share_idx) in peers {
        if share_idx == 0 {
            return Err(FrostError::ConfigError(
                "frost peer share index cannot be zero",
            ));
        }
        if peers_by_share_idx.insert(share_idx, peer_id).is_some() {
            return Err(FrostError::ConfigError("duplicate frost peer share index"));
        }
        share_idx_by_peer.insert(peer_id, share_idx);
    }

    if !peers_by_share_idx.contains_key(&local_share_idx) {
        return Err(FrostError::ConfigError(
            "local frost share index missing from peer map",
        ));
    }

    Ok(PeerShareIndices {
        peers_by_share_idx,
        share_idx_by_peer,
    })
}

async fn register_round1_bcast(
    bcast_comp: &bcast::Component,
    share_idx_by_peer: HashMap<PeerId, u32>,
    tx: mpsc::UnboundedSender<FrostRound1Casts>,
    threshold: usize,
    num_validators: usize,
) -> Result<(), FrostError> {
    // Bcast dedup for this DKG run; create a fresh `FrostP2P` per DKG.
    let dedup = Arc::new(Mutex::new(HashSet::<PeerId>::new()));
    let share_idx_by_peer = Arc::new(share_idx_by_peer);
    let check_share_idx_by_peer = share_idx_by_peer.clone();
    bcast_comp
        .register_message::<FrostRound1Casts>(
            ROUND1_CAST_ID,
            Box::new(move |peer_id, msg| {
                validate_round1_casts(
                    peer_id,
                    &check_share_idx_by_peer,
                    threshold,
                    num_validators,
                    msg,
                )
            }),
            Box::new(move |peer_id, _, msg| {
                let tx = tx.clone();
                let dedup = dedup.clone();
                let share_idx_by_peer = share_idx_by_peer.clone();
                Box::pin(async move {
                    validate_round1_casts(
                        peer_id,
                        &share_idx_by_peer,
                        threshold,
                        num_validators,
                        &msg,
                    )?;
                    {
                        let mut dedup = dedup.lock().map_err(|_| bcast::Error::BehaviourClosed)?;
                        if !dedup.insert(peer_id) {
                            debug!(%peer_id, "ignoring duplicate round 1 message");
                            return Ok(());
                        }
                    }

                    tx.send(msg).map_err(|_| bcast::Error::BehaviourClosed)?;
                    Ok(())
                })
            }),
        )
        .await?;
    Ok(())
}

async fn register_round2_bcast(
    bcast_comp: &bcast::Component,
    share_idx_by_peer: HashMap<PeerId, u32>,
    tx: mpsc::UnboundedSender<FrostRound2Casts>,
    num_validators: usize,
) -> Result<(), FrostError> {
    // Bcast dedup for this DKG run; create a fresh `FrostP2P` per DKG.
    let dedup = Arc::new(Mutex::new(HashSet::<PeerId>::new()));
    let share_idx_by_peer = Arc::new(share_idx_by_peer);
    let check_share_idx_by_peer = share_idx_by_peer.clone();
    bcast_comp
        .register_message::<FrostRound2Casts>(
            ROUND2_CAST_ID,
            Box::new(move |peer_id, msg| {
                validate_round2_casts(peer_id, &check_share_idx_by_peer, num_validators, msg)
            }),
            Box::new(move |peer_id, _, msg| {
                let tx = tx.clone();
                let dedup = dedup.clone();
                let share_idx_by_peer = share_idx_by_peer.clone();
                Box::pin(async move {
                    validate_round2_casts(peer_id, &share_idx_by_peer, num_validators, &msg)?;
                    {
                        let mut dedup = dedup.lock().map_err(|_| bcast::Error::BehaviourClosed)?;
                        if !dedup.insert(peer_id) {
                            debug!(%peer_id, "ignoring duplicate round 2 message");
                            return Ok(());
                        }
                    }

                    tx.send(msg).map_err(|_| bcast::Error::BehaviourClosed)?;
                    Ok(())
                })
            }),
        )
        .await?;
    Ok(())
}

fn validate_round1_casts(
    peer_id: PeerId,
    share_idx_by_peer: &HashMap<PeerId, u32>,
    threshold: usize,
    num_validators: usize,
    msg: &FrostRound1Casts,
) -> Result<(), bcast::Error> {
    let source_id = *share_idx_by_peer
        .get(&peer_id)
        .ok_or(bcast::Error::InvalidPeerIndex(peer_id))?;
    // Stricter than Charon: reject malformed batches before point decoding.
    if msg.casts.len() != num_validators {
        return Err(bcast::Error::InvalidSignatureCount {
            expected: num_validators,
            actual: msg.casts.len(),
        });
    }
    let mut seen_validators = HashSet::with_capacity(msg.casts.len());
    for cast in &msg.casts {
        let Some(key) = cast.key.as_ref() else {
            return Err(bcast::Error::MissingField("key"));
        };
        if key.source_id != source_id {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        if key.target_id != 0 {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        let val_idx =
            usize::try_from(key.val_idx).map_err(|_| bcast::Error::InvalidPeerIndex(peer_id))?;
        if val_idx >= num_validators {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        if !seen_validators.insert(key.val_idx) {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        if cast.commitments.len() != threshold {
            return Err(bcast::Error::InvalidSignatureCount {
                expected: threshold,
                actual: cast.commitments.len(),
            });
        }
    }

    Ok(())
}

fn validate_round2_casts(
    peer_id: PeerId,
    share_idx_by_peer: &HashMap<PeerId, u32>,
    num_validators: usize,
    msg: &FrostRound2Casts,
) -> Result<(), bcast::Error> {
    let source_id = *share_idx_by_peer
        .get(&peer_id)
        .ok_or(bcast::Error::InvalidPeerIndex(peer_id))?;
    // Stricter than Charon: reject malformed batches before point decoding.
    if msg.casts.len() != num_validators {
        return Err(bcast::Error::InvalidSignatureCount {
            expected: num_validators,
            actual: msg.casts.len(),
        });
    }
    let mut seen_validators = HashSet::with_capacity(msg.casts.len());
    for cast in &msg.casts {
        let Some(key) = cast.key.as_ref() else {
            return Err(bcast::Error::MissingField("key"));
        };
        if key.source_id != source_id {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        if key.target_id != 0 {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        let val_idx =
            usize::try_from(key.val_idx).map_err(|_| bcast::Error::InvalidPeerIndex(peer_id))?;
        if val_idx >= num_validators {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        if !seen_validators.insert(key.val_idx) {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
    }

    Ok(())
}

#[async_trait]
impl FTransport for FrostP2P {
    async fn round1(
        &mut self,
        cancellation: &CancellationToken,
        bcast: HashMap<MsgKey, Round1Bcast>,
        shares: HashMap<MsgKey, ShamirShare>,
    ) -> Result<(HashMap<MsgKey, Round1Bcast>, HashMap<MsgKey, ShamirShare>), FrostError> {
        self.emit_event(FrostP2PEvent::RoundStarted { round: 1 });
        let casts_msg = build_round1_casts(&bcast);
        self.emit_event(FrostP2PEvent::BroadcastStarted { round: 1 });
        self.bcast_comp
            .broadcast(ROUND1_CAST_ID, &casts_msg)
            .await?;
        self.wait_for_bcast_completion(ROUND1_CAST_ID, cancellation)
            .await?;
        if let Err(error) = self.round1_casts_tx.send(casts_msg) {
            error!(%error, "frost round 1 casts receiver dropped before self-delivery");
            return Err(FrostError::Round1CastsReceiverDropped);
        }

        let p2p_msgs = self.build_round1_p2p_by_peer(&shares)?;
        self.emit_event(FrostP2PEvent::DirectSendStarted {
            peer_count: p2p_msgs.len(),
        });
        for (peer_id, msg) in p2p_msgs {
            self.frost_sender.send(peer_id, &msg, cancellation).await?;
        }

        let mut cast_msgs = Vec::with_capacity(self.num_peers);
        let mut p2p_msgs = Vec::with_capacity(self.num_peers.saturating_sub(1));

        loop {
            if cast_msgs.len() == self.num_peers
                && p2p_msgs.len() == self.num_peers.saturating_sub(1)
            {
                break;
            }

            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(FrostError::Cancelled),
                msg = self.round1_casts_rx.recv() => {
                    let msg = msg.ok_or(FrostError::ChannelClosed("round 1 casts channel"))?;
                    cast_msgs.push(msg);
                    if cast_msgs.len() > self.num_peers {
                        return Err(FrostError::TooManyRound1CastsMessages);
                    }
                }
                msg = self.round1_p2p_rx.recv() => {
                    let (_peer_id, msg) = msg.ok_or(FrostError::ChannelClosed("round 1 p2p channel"))?;
                    p2p_msgs.push(msg);
                    if p2p_msgs.len() > self.num_peers.saturating_sub(1) {
                        return Err(FrostError::TooManyRound1P2PMessages);
                    }
                }
            }
        }

        let response = make_round1_response(cast_msgs, p2p_msgs)?;
        self.emit_event(FrostP2PEvent::RoundCompleted { round: 1 });
        Ok(response)
    }

    async fn round2(
        &mut self,
        cancellation: &CancellationToken,
        bcast: HashMap<MsgKey, Round2Bcast>,
    ) -> Result<HashMap<MsgKey, Round2Bcast>, FrostError> {
        self.emit_event(FrostP2PEvent::RoundStarted { round: 2 });
        let casts_msg = build_round2_casts(&bcast);
        self.emit_event(FrostP2PEvent::BroadcastStarted { round: 2 });
        self.bcast_comp
            .broadcast(ROUND2_CAST_ID, &casts_msg)
            .await?;
        self.wait_for_bcast_completion(ROUND2_CAST_ID, cancellation)
            .await?;
        if let Err(error) = self.round2_casts_tx.send(casts_msg) {
            error!(%error, "frost round 2 casts receiver dropped before self-delivery");
            return Err(FrostError::Round2CastsReceiverDropped);
        }

        let mut cast_msgs = Vec::with_capacity(self.num_peers);

        while cast_msgs.len() != self.num_peers {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(FrostError::Cancelled),
                msg = self.round2_casts_rx.recv() => {
                    let msg = msg.ok_or(FrostError::ChannelClosed("round 2 casts channel"))?;
                    cast_msgs.push(msg);
                    if cast_msgs.len() > self.num_peers {
                        return Err(FrostError::TooManyRound2CastsMessages);
                    }
                }
            }
        }

        let response = make_round2_response(cast_msgs)?;
        self.emit_event(FrostP2PEvent::RoundCompleted { round: 2 });
        self.emit_event(FrostP2PEvent::ProtocolCompleted);
        Ok(response)
    }
}

impl FrostP2P {
    fn emit_event(&self, event: FrostP2PEvent) {
        self.frost_sender.emit_event(event);
    }

    async fn wait_for_bcast_completion(
        &mut self,
        expected_msg_id: &'static str,
        cancellation: &CancellationToken,
    ) -> Result<(), FrostError> {
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(FrostError::Cancelled),
                event = self.bcast_event_rx.recv() => {
                    match event.ok_or(FrostError::ChannelClosed("frost bcast event channel"))? {
                        bcast::Event::BroadcastCompleted { msg_id } if msg_id == expected_msg_id => {
                            self.emit_event(FrostP2PEvent::BroadcastCompleted {
                                round: round_for_msg_id(expected_msg_id),
                            });
                            return Ok(());
                        }
                        bcast::Event::BroadcastFailed { msg_id, error } if msg_id == expected_msg_id => {
                            self.emit_event(FrostP2PEvent::BroadcastFailed {
                                round: round_for_msg_id(expected_msg_id),
                                error: error.to_string(),
                            });
                            return Err(error.into());
                        }
                        bcast::Event::BroadcastFailed { msg_id, error } => {
                            warn!(msg_id, expected_msg_id, %error, "ignoring unrelated failed bcast event")
                        }
                        event => debug!(?event, expected_msg_id, "ignoring unrelated bcast event"),
                    }
                }
            }
        }
    }

    fn build_round1_p2p_by_peer(
        &self,
        shares: &HashMap<MsgKey, ShamirShare>,
    ) -> Result<HashMap<PeerId, FrostRound1P2p>, FrostError> {
        let mut p2p_msgs =
            HashMap::<PeerId, FrostRound1P2p>::with_capacity(self.num_peers.saturating_sub(1));

        for (key, share) in shares {
            if key.target_id == self.local_share_idx {
                return Err(FrostError::UnexpectedP2PMessageToSelf);
            }
            let peer_id = *self
                .peers_by_share_idx
                .get(&key.target_id)
                .ok_or(FrostError::ConfigError("unknown target"))?;
            p2p_msgs
                .entry(peer_id)
                .or_default()
                .shares
                .push(shamir_share_to_proto(*key, share));
        }

        Ok(p2p_msgs)
    }
}

fn round_for_msg_id(msg_id: &'static str) -> u8 {
    match msg_id {
        ROUND1_CAST_ID => 1,
        ROUND2_CAST_ID => 2,
        _ => 0,
    }
}

fn is_frost_bcast_msg_id(msg_id: &str) -> bool {
    matches!(msg_id, ROUND1_CAST_ID | ROUND2_CAST_ID)
}

fn validate_round1_p2p(
    peer_id: PeerId,
    share_idx_by_peer: &HashMap<PeerId, u32>,
    local_share_idx: u32,
    msg: &FrostRound1P2p,
    num_validators: usize,
) -> Result<(), FrostError> {
    let source_id = *share_idx_by_peer
        .get(&peer_id)
        .ok_or(FrostError::InvalidRound1P2PSourceId)?;
    // Stricter than Charon's handler: valid senders emit exactly one share per
    // validator, so reject malformed batches before later map overwrites.
    if msg.shares.len() != num_validators {
        return Err(FrostError::InvalidRound1P2PSharesCount);
    }
    let mut seen_validators = HashSet::with_capacity(msg.shares.len());
    for share in &msg.shares {
        let key = share.key.as_ref().ok_or(FrostError::MissingMsgKey)?;
        if key.source_id != source_id {
            return Err(FrostError::InvalidRound1P2PSourceId);
        }
        if key.target_id != local_share_idx {
            return Err(FrostError::InvalidRound1P2PTargetId);
        }
        let val_idx =
            usize::try_from(key.val_idx).map_err(|_| FrostError::InvalidRound1P2PValidatorIndex)?;
        if val_idx >= num_validators {
            return Err(FrostError::InvalidRound1P2PValidatorIndex);
        }
        if !seen_validators.insert(key.val_idx) {
            return Err(FrostError::DuplicateRound1P2PValidatorIndex);
        }
    }

    Ok(())
}

fn key_to_proto(key: MsgKey) -> FrostMsgKey {
    FrostMsgKey {
        val_idx: key.val_idx,
        source_id: key.source_id,
        target_id: key.target_id,
    }
}

fn key_from_proto(key: Option<&FrostMsgKey>) -> Result<MsgKey, FrostError> {
    let key = key.ok_or(FrostError::MissingMsgKey)?;
    Ok(MsgKey {
        val_idx: key.val_idx,
        source_id: key.source_id,
        target_id: key.target_id,
    })
}

fn round1_cast_to_proto(key: MsgKey, cast: &Round1Bcast) -> FrostRound1Cast {
    FrostRound1Cast {
        key: Some(key_to_proto(key)),
        wi: Bytes::copy_from_slice(&cast.wi),
        ci: Bytes::copy_from_slice(&cast.ci),
        commitments: cast
            .commitments
            .iter()
            .map(|commitment| Bytes::copy_from_slice(commitment))
            .collect(),
    }
}

fn round1_cast_from_proto(cast: &FrostRound1Cast) -> Result<(MsgKey, Round1Bcast), FrostError> {
    let wi = bytes_to_scalar(|| FrostError::DecodeWiScalar, &cast.wi)?;
    let ci = bytes_to_scalar(|| FrostError::DecodeC1Scalar, &cast.ci)?;
    let commitments = cast
        .commitments
        .iter()
        .map(|commitment| bytes_to_g1(|| FrostError::DecodeCommitment, commitment))
        .collect::<Result<Vec<_>, _>>()?;
    let key = key_from_proto(cast.key.as_ref())?;
    Ok((
        key,
        Round1Bcast {
            commitments,
            wi,
            ci,
        },
    ))
}

fn shamir_share_to_proto(key: MsgKey, share: &ShamirShare) -> FrostRound1ShamirShare {
    FrostRound1ShamirShare {
        key: Some(key_to_proto(key)),
        id: share.id,
        value: Bytes::copy_from_slice(&share.value),
    }
}

fn shamir_share_from_proto(
    share: &FrostRound1ShamirShare,
) -> Result<(MsgKey, ShamirShare), FrostError> {
    let key = key_from_proto(share.key.as_ref())?;
    let value = bytes_to_scalar(|| FrostError::DecodeShamirScalar, &share.value)?;
    Ok((
        key,
        ShamirShare {
            id: share.id,
            value,
        },
    ))
}

fn round2_cast_to_proto(key: MsgKey, cast: &Round2Bcast) -> FrostRound2Cast {
    FrostRound2Cast {
        key: Some(key_to_proto(key)),
        verification_key: Bytes::copy_from_slice(&cast.verification_key),
        vk_share: Bytes::copy_from_slice(&cast.vk_share),
    }
}

fn round2_cast_from_proto(cast: &FrostRound2Cast) -> Result<(MsgKey, Round2Bcast), FrostError> {
    let verification_key = bytes_to_g1(
        || FrostError::DecodeVerificationKeyScalar,
        &cast.verification_key,
    )?;
    let vk_share = bytes_to_g1(|| FrostError::DecodeVkShare, &cast.vk_share)?;
    let key = key_from_proto(cast.key.as_ref())?;
    Ok((
        key,
        Round2Bcast {
            verification_key,
            vk_share,
        },
    ))
}

fn build_round1_casts(cast_r1: &HashMap<MsgKey, Round1Bcast>) -> FrostRound1Casts {
    FrostRound1Casts {
        casts: cast_r1
            .iter()
            .map(|(key, cast)| round1_cast_to_proto(*key, cast))
            .collect(),
    }
}

fn build_round2_casts(cast_r2: &HashMap<MsgKey, Round2Bcast>) -> FrostRound2Casts {
    FrostRound2Casts {
        casts: cast_r2
            .iter()
            .map(|(key, cast)| round2_cast_to_proto(*key, cast))
            .collect(),
    }
}

fn make_round1_response(
    casts: Vec<FrostRound1Casts>,
    p2ps: Vec<FrostRound1P2p>,
) -> Result<Round1Response, FrostError> {
    let mut cast_map = HashMap::new();
    let mut p2p_map = HashMap::new();

    for msg in &casts {
        for cast in &msg.casts {
            let (key, cast) = round1_cast_from_proto(cast)?;
            cast_map.insert(key, cast);
        }
    }
    for msg in &p2ps {
        for share in &msg.shares {
            let (key, share) = shamir_share_from_proto(share)?;
            p2p_map.insert(key, share);
        }
    }

    Ok((cast_map, p2p_map))
}

fn make_round2_response(
    msgs: Vec<FrostRound2Casts>,
) -> Result<HashMap<MsgKey, Round2Bcast>, FrostError> {
    let mut cast_map = HashMap::new();
    for msg in &msgs {
        for cast in &msg.casts {
            let (key, cast) = round2_cast_from_proto(cast)?;
            cast_map.insert(key, cast);
        }
    }

    Ok(cast_map)
}

fn bytes_to_scalar(context: fn() -> FrostError, bytes: &Bytes) -> Result<[u8; 32], FrostError> {
    let scalar = bytes_to_array::<SCALAR_LENGTH>(context, bytes)?;
    kryptology::scalar_from_be(&scalar).map_err(|_| context())?;
    Ok(scalar)
}

fn bytes_to_g1(
    context: fn() -> FrostError,
    bytes: &Bytes,
) -> Result<[u8; G1_COMPRESSED_LENGTH], FrostError> {
    let point = bytes_to_array::<G1_COMPRESSED_LENGTH>(context, bytes)?;
    G1Projective::from_compressed(&point).ok_or_else(context)?;
    Ok(point)
}

fn bytes_to_array<const N: usize>(
    context: fn() -> FrostError,
    bytes: &Bytes,
) -> Result<[u8; N], FrostError> {
    bytes.as_ref().try_into().map_err(|_| context())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Name;

    #[test]
    fn constants_match_reference() {
        assert_eq!(ROUND1_CAST_ID, "/charon/dkg/frost/2.0.0/round1/cast");
        assert_eq!(
            ROUND1_P2P_PROTOCOL.as_ref(),
            "/charon/dkg/frost/2.0.0/round1/p2p"
        );
        assert_eq!(ROUND2_CAST_ID, "/charon/dkg/frost/2.0.0/round2/cast");
        assert_eq!(pluto_p2p::proto::MAX_MESSAGE_SIZE, 128 << 20);
        assert_eq!(RECEIVE_TIMEOUT, Duration::from_secs(5));
        assert_eq!(SEND_TIMEOUT, Duration::from_secs(7));
    }

    #[test]
    fn frost_type_urls_use_dkg_package() {
        assert_eq!(
            FrostRound1Casts::type_url(),
            "type.googleapis.com/dkg.dkgpb.v1.FrostRound1Casts"
        );
        assert_eq!(
            FrostRound2Casts::type_url(),
            "type.googleapis.com/dkg.dkgpb.v1.FrostRound2Casts"
        );
    }

    #[test]
    fn key_round_trip() {
        let key = MsgKey {
            val_idx: 2,
            source_id: 3,
            target_id: 4,
        };

        assert_eq!(key_from_proto(Some(&key_to_proto(key))).unwrap(), key);
    }

    #[test]
    fn missing_key_is_rejected() {
        assert!(matches!(
            key_from_proto(None),
            Err(FrostError::MissingMsgKey)
        ));
    }

    #[test]
    fn invalid_scalar_is_rejected() {
        let cast = FrostRound1Cast {
            key: Some(key_to_proto(MsgKey {
                val_idx: 0,
                source_id: 1,
                target_id: 0,
            })),
            wi: Bytes::from_static(&[0xff; 32]),
            ci: Bytes::from_static(&[1; 32]),
            commitments: vec![],
        };

        assert!(matches!(
            round1_cast_from_proto(&cast),
            Err(FrostError::DecodeWiScalar)
        ));
    }

    #[test]
    fn invalid_point_is_rejected() {
        let cast = FrostRound2Cast {
            key: Some(key_to_proto(MsgKey {
                val_idx: 0,
                source_id: 1,
                target_id: 0,
            })),
            verification_key: Bytes::from(vec![42; 48]),
            vk_share: Bytes::from(vec![42; 48]),
        };

        assert!(matches!(
            round2_cast_from_proto(&cast),
            Err(FrostError::DecodeVerificationKeyScalar)
        ));
    }

    #[test]
    fn validate_round1_casts_rejects_invalid_fields() {
        let peer_id = PeerId::random();
        let share_idx_by_peer = HashMap::from([(peer_id, 1)]);
        let cast = |key: MsgKey, commitments| FrostRound1Casts {
            casts: vec![FrostRound1Cast {
                key: Some(key_to_proto(key)),
                wi: Bytes::new(),
                ci: Bytes::new(),
                commitments,
            }],
        };

        assert!(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                1,
                &cast(
                    MsgKey {
                        val_idx: 0,
                        source_id: 1,
                        target_id: 0,
                    },
                    vec![Bytes::new()],
                ),
            )
            .is_ok()
        );
        assert_invalid_peer_index(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                1,
                &cast(
                    MsgKey {
                        val_idx: 0,
                        source_id: 2,
                        target_id: 0,
                    },
                    vec![Bytes::new()],
                ),
            ),
            peer_id,
        );
        let unknown_peer = PeerId::random();
        assert_invalid_peer_index(
            validate_round1_casts(
                unknown_peer,
                &share_idx_by_peer,
                1,
                1,
                &cast(
                    MsgKey {
                        val_idx: 0,
                        source_id: 1,
                        target_id: 0,
                    },
                    vec![Bytes::new()],
                ),
            ),
            unknown_peer,
        );
        assert_invalid_peer_index(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                1,
                &cast(
                    MsgKey {
                        val_idx: 0,
                        source_id: 1,
                        target_id: 1,
                    },
                    vec![Bytes::new()],
                ),
            ),
            peer_id,
        );
        assert_invalid_peer_index(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                1,
                &cast(
                    MsgKey {
                        val_idx: 1,
                        source_id: 1,
                        target_id: 0,
                    },
                    vec![Bytes::new()],
                ),
            ),
            peer_id,
        );
        assert_invalid_signature_count(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                1,
                &cast(
                    MsgKey {
                        val_idx: 0,
                        source_id: 1,
                        target_id: 0,
                    },
                    vec![],
                ),
            ),
            1,
            0,
        );
        assert_invalid_signature_count(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                2,
                &cast(
                    MsgKey {
                        val_idx: 0,
                        source_id: 1,
                        target_id: 0,
                    },
                    vec![Bytes::new()],
                ),
            ),
            2,
            1,
        );
        assert_invalid_peer_index(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                2,
                &FrostRound1Casts {
                    casts: vec![
                        FrostRound1Cast {
                            key: Some(key_to_proto(MsgKey {
                                val_idx: 0,
                                source_id: 1,
                                target_id: 0,
                            })),
                            wi: Bytes::new(),
                            ci: Bytes::new(),
                            commitments: vec![Bytes::new()],
                        },
                        FrostRound1Cast {
                            key: Some(key_to_proto(MsgKey {
                                val_idx: 0,
                                source_id: 1,
                                target_id: 0,
                            })),
                            wi: Bytes::new(),
                            ci: Bytes::new(),
                            commitments: vec![Bytes::new()],
                        },
                    ],
                },
            ),
            peer_id,
        );
    }

    #[test]
    fn validate_round2_casts_rejects_invalid_fields() {
        let peer_id = PeerId::random();
        let share_idx_by_peer = HashMap::from([(peer_id, 1)]);
        let cast = |key: MsgKey| FrostRound2Casts {
            casts: vec![FrostRound2Cast {
                key: Some(key_to_proto(key)),
                verification_key: Bytes::new(),
                vk_share: Bytes::new(),
            }],
        };

        assert!(
            validate_round2_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                &cast(MsgKey {
                    val_idx: 0,
                    source_id: 1,
                    target_id: 0,
                }),
            )
            .is_ok()
        );
        assert_invalid_peer_index(
            validate_round2_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                &cast(MsgKey {
                    val_idx: 0,
                    source_id: 2,
                    target_id: 0,
                }),
            ),
            peer_id,
        );
        let unknown_peer = PeerId::random();
        assert_invalid_peer_index(
            validate_round2_casts(
                unknown_peer,
                &share_idx_by_peer,
                1,
                &cast(MsgKey {
                    val_idx: 0,
                    source_id: 1,
                    target_id: 0,
                }),
            ),
            unknown_peer,
        );
        assert_invalid_peer_index(
            validate_round2_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                &cast(MsgKey {
                    val_idx: 0,
                    source_id: 1,
                    target_id: 1,
                }),
            ),
            peer_id,
        );
        assert_invalid_peer_index(
            validate_round2_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                &cast(MsgKey {
                    val_idx: 1,
                    source_id: 1,
                    target_id: 0,
                }),
            ),
            peer_id,
        );
        assert_invalid_signature_count(
            validate_round2_casts(
                peer_id,
                &share_idx_by_peer,
                2,
                &cast(MsgKey {
                    val_idx: 0,
                    source_id: 1,
                    target_id: 0,
                }),
            ),
            2,
            1,
        );
        assert_invalid_peer_index(
            validate_round2_casts(
                peer_id,
                &share_idx_by_peer,
                2,
                &FrostRound2Casts {
                    casts: vec![
                        FrostRound2Cast {
                            key: Some(key_to_proto(MsgKey {
                                val_idx: 0,
                                source_id: 1,
                                target_id: 0,
                            })),
                            verification_key: Bytes::new(),
                            vk_share: Bytes::new(),
                        },
                        FrostRound2Cast {
                            key: Some(key_to_proto(MsgKey {
                                val_idx: 0,
                                source_id: 1,
                                target_id: 0,
                            })),
                            verification_key: Bytes::new(),
                            vk_share: Bytes::new(),
                        },
                    ],
                },
            ),
            peer_id,
        );
    }

    #[test]
    fn bcast_check_rejects_invalid_round_casts_before_signing() {
        let peer_id = PeerId::random();
        let share_idx_by_peer = Arc::new(HashMap::from([(peer_id, 1)]));
        let round1_check_share_idx_by_peer = share_idx_by_peer.clone();
        let round1_check: bcast::CheckFn<FrostRound1Casts> = Box::new(move |peer_id, msg| {
            validate_round1_casts(peer_id, &round1_check_share_idx_by_peer, 1, 2, msg)
        });
        let round2_check_share_idx_by_peer = share_idx_by_peer.clone();
        let round2_check: bcast::CheckFn<FrostRound2Casts> = Box::new(move |peer_id, msg| {
            validate_round2_casts(peer_id, &round2_check_share_idx_by_peer, 2, msg)
        });

        let invalid_round1 = FrostRound1Casts {
            casts: vec![FrostRound1Cast {
                key: Some(key_to_proto(MsgKey {
                    val_idx: 0,
                    source_id: 1,
                    target_id: 0,
                })),
                wi: Bytes::new(),
                ci: Bytes::new(),
                commitments: vec![Bytes::new()],
            }],
        };
        let invalid_round2 = FrostRound2Casts {
            casts: vec![FrostRound2Cast {
                key: Some(key_to_proto(MsgKey {
                    val_idx: 0,
                    source_id: 1,
                    target_id: 0,
                })),
                verification_key: Bytes::new(),
                vk_share: Bytes::new(),
            }],
        };

        assert_invalid_signature_count(round1_check(peer_id, &invalid_round1), 2, 1);
        assert_invalid_signature_count(round2_check(peer_id, &invalid_round2), 2, 1);
    }

    #[test]
    fn cancel_all_removes_handler_pending_open() {
        let mut handler = FrostP2PHandler::new();

        handler.on_behaviour_event(InEvent::Send {
            op_id: 7,
            msg: FrostRound1P2p::default(),
        });
        handler.on_behaviour_event(InEvent::CancelAllPending);

        assert!(handler.pending_open.is_empty());
    }

    #[test]
    fn cancel_all_removes_behaviour_pending_sends() {
        let peer_id = PeerId::random();
        let (mut behaviour, _handle) = FrostP2PBehaviour::new(
            P2PContext::new([peer_id]),
            [peer_id],
            HashMap::from([(peer_id, 1)]),
            1,
            1,
        );
        let (result_tx, _result_rx) = oneshot::channel();

        behaviour.result_by_op.insert(7, (peer_id, result_tx));
        behaviour.enqueue_send(peer_id, 7, FrostRound1P2p::default());
        behaviour.cancel_all_sends();

        assert!(behaviour.result_by_op.is_empty());
        assert!(behaviour.pending_by_peer.is_empty());
        assert!(behaviour.pending_events.iter().all(|event| {
            !matches!(
                event,
                ToSwarm::NotifyHandler {
                    event: InEvent::Send { op_id: 7, .. },
                    ..
                }
            )
        }));
        assert!(behaviour.pending_events.iter().all(|event| {
            !matches!(
                event,
                ToSwarm::Dial { opts } if opts.get_peer_id() == Some(peer_id)
            )
        }));
    }

    #[test]
    fn behaviour_uses_dummy_handler_for_unknown_peer() {
        let known_peer = PeerId::random();
        let unknown_peer = PeerId::random();
        let (behaviour, _handle) = FrostP2PBehaviour::new(
            P2PContext::new([known_peer]),
            [known_peer],
            HashMap::from([(known_peer, 1)]),
            1,
            1,
        );

        assert!(matches!(
            behaviour.connection_handler_for_peer(known_peer),
            Either::Left(_)
        ));
        assert!(matches!(
            behaviour.connection_handler_for_peer(unknown_peer),
            Either::Right(_)
        ));
    }

    #[test]
    fn enqueue_send_fails_unknown_peer_without_leaking_state() {
        let known_peer = PeerId::random();
        let unknown_peer = PeerId::random();
        let (mut behaviour, _handle) = FrostP2PBehaviour::new(
            P2PContext::new([known_peer, unknown_peer]),
            [known_peer],
            HashMap::from([(known_peer, 1)]),
            1,
            1,
        );
        let (result_tx, result_rx) = oneshot::channel();

        behaviour.result_by_op.insert(7, (unknown_peer, result_tx));
        behaviour.enqueue_send(unknown_peer, 7, FrostRound1P2p::default());

        assert!(behaviour.result_by_op.is_empty());
        assert!(behaviour.pending_by_peer.is_empty());
        assert!(matches!(
            behaviour.pending_events.pop_front(),
            Some(ToSwarm::GenerateEvent(FrostP2PEvent::DirectSendFailed {
                peer_id,
                ..
            })) if peer_id == unknown_peer
        ));
        assert!(behaviour.pending_events.is_empty());
        assert!(matches!(
            result_rx
                .now_or_never()
                .expect("send result should be ready")
                .expect("send result channel should be open"),
            Err(FrostP2PError::UnknownPeer(peer)) if peer == unknown_peer
        ));
    }

    #[test]
    fn behaviour_dedups_round1_p2p_before_queueing() {
        let peer_id = PeerId::random();
        let (mut behaviour, mut handle) = FrostP2PBehaviour::new(
            P2PContext::new([peer_id]),
            [peer_id],
            HashMap::from([(peer_id, 1)]),
            2,
            1,
        );
        let mut inbound_rx = handle.take_inbound_rx().unwrap();
        let msg = FrostRound1P2p {
            shares: vec![FrostRound1ShamirShare {
                key: Some(key_to_proto(MsgKey {
                    val_idx: 0,
                    source_id: 1,
                    target_id: 2,
                })),
                id: 1,
                value: Bytes::from_static(&[7]),
            }],
        };

        behaviour.on_connection_handler_event(
            peer_id,
            ConnectionId::new_unchecked(1),
            Either::Left(OutEvent::Received(msg.clone())),
        );
        behaviour.on_connection_handler_event(
            peer_id,
            ConnectionId::new_unchecked(1),
            Either::Left(OutEvent::Received(msg.clone())),
        );

        let (queued_peer_id, queued_msg) = inbound_rx.try_recv().unwrap();
        assert_eq!(queued_peer_id, peer_id);
        assert_eq!(queued_msg, msg);
        assert!(inbound_rx.try_recv().is_err());
    }

    #[test]
    fn validate_round1_p2p_requires_all_validator_shares_once() {
        let peer_id = PeerId::random();
        let share_idx_by_peer = HashMap::from([(peer_id, 1)]);
        let share = |val_idx| FrostRound1ShamirShare {
            key: Some(key_to_proto(MsgKey {
                val_idx,
                source_id: 1,
                target_id: 2,
            })),
            id: 1,
            value: Bytes::from_static(&[7]),
        };

        assert!(
            validate_round1_p2p(
                peer_id,
                &share_idx_by_peer,
                2,
                &FrostRound1P2p {
                    shares: vec![share(0), share(1)]
                },
                2,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_round1_p2p(
                peer_id,
                &share_idx_by_peer,
                2,
                &FrostRound1P2p {
                    shares: vec![share(0)]
                },
                2,
            ),
            Err(FrostError::InvalidRound1P2PSharesCount)
        ));
        assert!(matches!(
            validate_round1_p2p(
                peer_id,
                &share_idx_by_peer,
                2,
                &FrostRound1P2p {
                    shares: vec![share(0), share(0)]
                },
                2,
            ),
            Err(FrostError::DuplicateRound1P2PValidatorIndex)
        ));
    }

    #[test]
    fn peer_share_index_validation_rejects_invalid_maps() {
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();

        assert!(matches!(
            validate_peer_share_indices(&HashMap::from([(peer_a, 0)]), 1),
            Err(FrostError::ConfigError(
                "frost peer share index cannot be zero"
            ))
        ));
        assert!(matches!(
            validate_peer_share_indices(&HashMap::from([(peer_a, 1), (peer_b, 1)]), 1),
            Err(FrostError::ConfigError("duplicate frost peer share index"))
        ));
        assert!(matches!(
            validate_peer_share_indices(&HashMap::from([(peer_a, 1)]), 2),
            Err(FrostError::ConfigError(
                "local frost share index missing from peer map"
            ))
        ));
    }

    #[tokio::test]
    async fn sender_emits_cancel_all_command_on_cancellation() {
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let sender = FrostP2PSender::new(cmd_tx);
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let peer_id = PeerId::random();

        let task = tokio::spawn(async move {
            sender
                .send(peer_id, &FrostRound1P2p::default(), &task_cancellation)
                .await
        });

        let send_command = cmd_rx.recv().await.unwrap();
        assert!(matches!(send_command, SendCommand::Send { .. }));

        cancellation.cancel();

        assert!(matches!(task.await.unwrap(), Err(FrostError::Cancelled)));
        assert!(matches!(
            cmd_rx.recv().await.unwrap(),
            SendCommand::CancelAll
        ));
        drop(send_command);
    }

    #[tokio::test]
    async fn bcast_event_handler_forwards_event() {
        let (handler, mut event_rx) = frost_p2p_handle_for_test();

        handler
            .handle_bcast_event(bcast::Event::BroadcastCompleted {
                msg_id: "other".to_string(),
            })
            .unwrap();
        assert!(event_rx.try_recv().is_err());

        handler
            .handle_bcast_event(bcast::Event::BroadcastCompleted {
                msg_id: ROUND1_CAST_ID.to_string(),
            })
            .unwrap();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            bcast::Event::BroadcastCompleted { msg_id } if msg_id == ROUND1_CAST_ID
        ));
    }

    #[tokio::test]
    async fn wait_for_bcast_completion_observes_failure() {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut transport = frost_p2p_for_bcast_event_test(event_rx);

        event_tx
            .send(bcast::Event::BroadcastFailed {
                msg_id: ROUND2_CAST_ID.to_string(),
                error: bcast::Error::BehaviourClosed,
            })
            .unwrap();

        assert!(matches!(
            transport
                .wait_for_bcast_completion(ROUND2_CAST_ID, &CancellationToken::new())
                .await,
            Err(FrostError::Bcast(bcast::Error::BehaviourClosed))
        ));
    }

    fn frost_p2p_handle_for_test() -> (FrostP2PHandle, mpsc::UnboundedReceiver<bcast::Event>) {
        let (_inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        let (bcast_event_tx, bcast_event_rx) = mpsc::unbounded_channel();
        (
            FrostP2PHandle {
                inbound_rx: Some(inbound_rx),
                sender: FrostP2PSender::new(cmd_tx),
                bcast_event_tx,
                bcast_event_rx: None,
            },
            bcast_event_rx,
        )
    }

    fn frost_p2p_for_bcast_event_test(
        bcast_event_rx: mpsc::UnboundedReceiver<bcast::Event>,
    ) -> FrostP2P {
        let (round1_casts_tx, round1_casts_rx) = mpsc::unbounded_channel();
        let (_round1_p2p_tx, round1_p2p_rx) = mpsc::unbounded_channel();
        let (round2_casts_tx, round2_casts_rx) = mpsc::unbounded_channel();
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        let (bcast_behaviour, bcast_comp) = bcast::Behaviour::new(
            Vec::new(),
            pluto_p2p::p2p_context::P2PContext::default(),
            pluto_testutil::random::generate_insecure_k1_key(1),
        );
        drop(bcast_behaviour);

        FrostP2P {
            bcast_comp,
            frost_sender: FrostP2PSender::new(cmd_tx),
            bcast_event_rx,
            round1_casts_tx,
            round1_casts_rx,
            round1_p2p_rx,
            round2_casts_tx,
            round2_casts_rx,
            peers_by_share_idx: HashMap::new(),
            local_share_idx: 1,
            num_peers: 0,
        }
    }

    fn assert_invalid_peer_index<T>(result: Result<T, bcast::Error>, expected: PeerId) {
        assert!(matches!(
            result,
            Err(bcast::Error::InvalidPeerIndex(peer_id)) if peer_id == expected
        ));
    }

    fn assert_invalid_signature_count<T>(
        result: Result<T, bcast::Error>,
        expected: usize,
        actual: usize,
    ) {
        assert!(matches!(
            result,
            Err(bcast::Error::InvalidSignatureCount {
                expected: got_expected,
                actual: got_actual,
            }) if got_expected == expected && got_actual == actual
        ));
    }
}
