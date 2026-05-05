//! FROST DKG P2P transport.
//!
//! This module is split across two integration surfaces:
//!
//! - [`FrostP2PBehaviour`] owns the direct round-1 P2P libp2p protocol.
//! - [`FrostP2P`] implements the FROST transport by combining direct P2P with
//!   reliable broadcast through [`bcast::Component`].
//!
//! The outer DKG network behaviour must install both `bcast::Behaviour` and
//! [`FrostP2PBehaviour`]. It must also forward every [`bcast::Event`] emitted
//! by `bcast::Behaviour` into [`FrostP2PHandle::handle_bcast_event`]. Without
//! that event bridge, [`FrostP2P`] cannot observe broadcast completion and
//! `round1`/`round2` will wait until cancellation.

#![allow(dead_code)]

use std::{
    collections::{HashMap, HashSet, VecDeque},
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
use tracing::{debug, warn};

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

/// Maximum FROST P2P protobuf message size. Charon's default libp2p
/// delimited-reader limit is 128 MiB.
pub(crate) const MAX_MESSAGE_SIZE: usize = pluto_p2p::proto::MAX_MESSAGE_SIZE;
/// Charon's default direct-P2P inbound read timeout.
pub(crate) const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Charon's default direct-P2P send timeout.
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(7);

const SCALAR_LEN: usize = 32;
const G1_COMPRESSED_LEN: usize = 48;

/// FROST direct-P2P delivery errors.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FrostP2PError {
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
    CancelPending,
}

#[derive(Debug)]
pub(crate) enum OutEvent {
    Received(FrostRound1P2p),
    Sent { op_id: u64 },
    Failed { op_id: u64, message: String },
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
            InEvent::CancelPending => self.pending_open.clear(),
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
            MAX_MESSAGE_SIZE,
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
    inbound_rx: Option<mpsc::Receiver<(PeerId, FrostRound1P2p)>>,
    sender: FrostP2PSender,
    bcast_event_tx: mpsc::UnboundedSender<bcast::Event>,
    bcast_event_rx: Option<mpsc::UnboundedReceiver<bcast::Event>>,
}

impl FrostP2PHandle {
    /// Forwards bcast completion events into the FROST round state machine.
    ///
    /// The outer DKG network behaviour must call this for every event emitted
    /// by `bcast::Behaviour`; `FrostP2P::round1` and `FrostP2P::round2` block
    /// on these forwarded events after starting their broadcasts.
    pub(crate) fn handle_bcast_event(&self, event: bcast::Event) -> Result<(), FrostError> {
        self.bcast_event_tx
            .send(event)
            .map_err(|_| FrostError::ChannelClosed("frost bcast event channel"))
    }

    fn take_inbound_rx(&mut self) -> Result<mpsc::Receiver<(PeerId, FrostRound1P2p)>, FrostError> {
        self.inbound_rx.take().ok_or(FrostError::InternalState(
            "frost p2p inbound receiver already taken",
        ))
    }

    fn take_bcast_event_rx(&mut self) -> Result<mpsc::UnboundedReceiver<bcast::Event>, FrostError> {
        self.bcast_event_rx.take().ok_or(FrostError::InternalState(
            "frost bcast event receiver already taken",
        ))
    }
}

/// libp2p behaviour for FROST round-1 direct P2P.
pub(crate) struct FrostP2PBehaviour {
    peers: HashSet<PeerId>,
    p2p_context: P2PContext,
    share_idx_by_peer: HashMap<PeerId, u32>,
    local_share_idx: u32,
    num_validators: u32,
    inbound_tx: mpsc::Sender<(PeerId, FrostRound1P2p)>,
    accepted_round1_p2p: HashSet<PeerId>,
    cmd_rx: mpsc::UnboundedReceiver<SendCommand>,
    pending_events: VecDeque<ToSwarm<(), InEvent>>,
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
        num_validators: u32,
    ) -> (Self, FrostP2PHandle) {
        let peers = peers.into_iter().collect::<HashSet<_>>();
        let num_peers = peers.len();
        let (inbound_tx, inbound_rx) = mpsc::channel(peers.len().max(1));
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
                SendCommand::CancelAll => self.cancel_all_sends(),
            }
        }
    }

    fn enqueue_send(&mut self, peer_id: PeerId, op_id: u64, msg: FrostRound1P2p) {
        if !self.peers.contains(&peer_id) {
            self.complete_send(op_id, Err(FrostP2PError::UnknownPeer(peer_id)));
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

    fn complete_send(&mut self, op_id: u64, result: Result<(), FrostP2PError>) {
        if let Some((_peer_id, result_tx)) = self.result_by_op.remove(&op_id) {
            let _ = result_tx.send(result);
        }
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
                event: InEvent::CancelPending,
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
            self.complete_send(op_id, Err(FrostP2PError::PeerNotConnected(peer_id)));
        }

        let active_ops = self
            .result_by_op
            .iter()
            .filter_map(|(op_id, (peer, _))| (*peer == peer_id).then_some(*op_id))
            .collect::<Vec<_>>();
        for op_id in active_ops {
            self.complete_send(op_id, Err(FrostP2PError::PeerNotConnected(peer_id)));
        }
    }
}

impl NetworkBehaviour for FrostP2PBehaviour {
    type ConnectionHandler = Either<FrostP2PHandler, dummy::ConnectionHandler>;
    type ToSwarm = ();

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
                match self.inbound_tx.try_send((peer_id, msg)) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full((peer_id, _))) => {
                        self.accepted_round1_p2p.remove(&peer_id);
                        warn!(%peer_id, "dropping round 1 p2p message because inbound queue is full");
                    }
                    Err(mpsc::error::TrySendError::Closed((peer_id, _))) => {
                        self.accepted_round1_p2p.remove(&peer_id);
                        warn!(%peer_id, "dropping round 1 p2p message because inbound queue is closed");
                    }
                }
            }
            OutEvent::Sent { op_id } => self.complete_send(op_id, Ok(())),
            OutEvent::Failed { op_id, message } => {
                self.complete_send(op_id, Err(FrostP2PError::SendFailed(message)));
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
    round1_p2p_rx: mpsc::Receiver<(PeerId, FrostRound1P2p)>,
    round2_casts_tx: mpsc::UnboundedSender<FrostRound2Casts>,
    round2_casts_rx: mpsc::UnboundedReceiver<FrostRound2Casts>,
    peers_by_share_idx: HashMap<u32, PeerId>,
    share_idx_by_peer: HashMap<PeerId, u32>,
    local_share_idx: u32,
    num_validators: u32,
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
    num_validators: u32,
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
        share_idx_by_peer: peer_share_indices.share_idx_by_peer,
        local_share_idx,
        num_validators,
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
    num_validators: u32,
) -> Result<(), FrostError> {
    let dedup = std::sync::Arc::new(std::sync::Mutex::new(HashSet::<PeerId>::new()));
    bcast_comp
        .register_message::<FrostRound1Casts>(
            ROUND1_CAST_ID,
            Box::new(|_, _| Ok(())),
            Box::new(move |peer_id, _, msg| {
                let tx = tx.clone();
                let dedup = dedup.clone();
                let share_idx_by_peer = share_idx_by_peer.clone();
                Box::pin(async move {
                    {
                        let mut dedup = dedup
                            .lock()
                            .map_err(|_| bcast::Error::InvalidMessage("dedup mutex poisoned"))?;
                        if !dedup.insert(peer_id) {
                            debug!(%peer_id, "ignoring duplicate round 1 message");
                            return Ok(());
                        }
                    }

                    let source_id =
                        *share_idx_by_peer
                            .get(&peer_id)
                            .ok_or(bcast::Error::InvalidMessage(
                                "invalid round 1 cast source ID",
                            ))?;
                    for cast in &msg.casts {
                        let key = cast.key.as_ref().ok_or(bcast::Error::MissingField("key"))?;
                        if key.source_id != source_id {
                            return Err(bcast::Error::InvalidMessage(
                                "invalid round 1 cast source ID",
                            ));
                        }
                        if key.target_id != 0 {
                            return Err(bcast::Error::InvalidMessage(
                                "invalid round 1 cast target ID",
                            ));
                        }
                        if key.val_idx >= num_validators {
                            return Err(bcast::Error::InvalidMessage(
                                "invalid round 1 cast validator index",
                            ));
                        }
                        if cast.commitments.len() != threshold {
                            return Err(bcast::Error::InvalidMessage(
                                "invalid amount of commitments in round 1",
                            ));
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
    num_validators: u32,
) -> Result<(), FrostError> {
    let dedup = std::sync::Arc::new(std::sync::Mutex::new(HashSet::<PeerId>::new()));
    bcast_comp
        .register_message::<FrostRound2Casts>(
            ROUND2_CAST_ID,
            Box::new(|_, _| Ok(())),
            Box::new(move |peer_id, _, msg| {
                let tx = tx.clone();
                let dedup = dedup.clone();
                let share_idx_by_peer = share_idx_by_peer.clone();
                Box::pin(async move {
                    {
                        let mut dedup = dedup
                            .lock()
                            .map_err(|_| bcast::Error::InvalidMessage("dedup mutex poisoned"))?;
                        if !dedup.insert(peer_id) {
                            debug!(%peer_id, "ignoring duplicate round 2 message");
                            return Ok(());
                        }
                    }

                    let source_id =
                        *share_idx_by_peer
                            .get(&peer_id)
                            .ok_or(bcast::Error::InvalidMessage(
                                "invalid round 2 cast source ID",
                            ))?;
                    for cast in &msg.casts {
                        let key = cast.key.as_ref().ok_or(bcast::Error::MissingField("key"))?;
                        if key.source_id != source_id {
                            return Err(bcast::Error::InvalidMessage(
                                "invalid round 2 cast source ID",
                            ));
                        }
                        if key.target_id != 0 {
                            return Err(bcast::Error::InvalidMessage(
                                "invalid round 2 cast target ID",
                            ));
                        }
                        if key.val_idx >= num_validators {
                            return Err(bcast::Error::InvalidMessage(
                                "invalid round 2 cast validator index",
                            ));
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

#[async_trait]
impl FTransport for FrostP2P {
    async fn round1(
        &mut self,
        cancellation: &CancellationToken,
        bcast: HashMap<MsgKey, Round1Bcast>,
        shares: HashMap<MsgKey, ShamirShare>,
    ) -> Result<(HashMap<MsgKey, Round1Bcast>, HashMap<MsgKey, ShamirShare>), FrostError> {
        let casts_msg = build_round1_casts(&bcast);
        self.bcast_comp
            .broadcast(ROUND1_CAST_ID, &casts_msg)
            .await?;
        self.wait_for_bcast_completion(ROUND1_CAST_ID, cancellation)
            .await?;
        let _ = self.round1_casts_tx.send(casts_msg);

        let p2p_msgs = self.build_round1_p2p_by_peer(&shares)?;
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
                _ = cancellation.cancelled() => return Err(FrostError::Cancelled),
                msg = self.round1_casts_rx.recv() => {
                    let msg = msg.ok_or(FrostError::ChannelClosed("round 1 casts channel"))?;
                    cast_msgs.push(msg);
                    if cast_msgs.len() > self.num_peers {
                        return Err(FrostError::InvalidMessage("too many round 1 casts messages"));
                    }
                }
                msg = self.round1_p2p_rx.recv() => {
                    let (_peer_id, msg) = msg.ok_or(FrostError::ChannelClosed("round 1 p2p channel"))?;
                    p2p_msgs.push(msg);
                    if p2p_msgs.len() > self.num_peers.saturating_sub(1) {
                        return Err(FrostError::InvalidMessage("too many round 1 p2p messages"));
                    }
                }
            }
        }

        make_round1_response(cast_msgs, p2p_msgs)
    }

    async fn round2(
        &mut self,
        cancellation: &CancellationToken,
        bcast: HashMap<MsgKey, Round2Bcast>,
    ) -> Result<HashMap<MsgKey, Round2Bcast>, FrostError> {
        let casts_msg = build_round2_casts(&bcast);
        self.bcast_comp
            .broadcast(ROUND2_CAST_ID, &casts_msg)
            .await?;
        self.wait_for_bcast_completion(ROUND2_CAST_ID, cancellation)
            .await?;
        let _ = self.round2_casts_tx.send(casts_msg);

        let mut cast_msgs = Vec::with_capacity(self.num_peers);

        while cast_msgs.len() != self.num_peers {
            tokio::select! {
                _ = cancellation.cancelled() => return Err(FrostError::Cancelled),
                msg = self.round2_casts_rx.recv() => {
                    let msg = msg.ok_or(FrostError::ChannelClosed("round 2 casts channel"))?;
                    cast_msgs.push(msg);
                    if cast_msgs.len() > self.num_peers {
                        return Err(FrostError::InvalidMessage("too many round 2 casts messages"));
                    }
                }
            }
        }

        make_round2_response(cast_msgs)
    }
}

impl FrostP2P {
    async fn wait_for_bcast_completion(
        &mut self,
        expected_msg_id: &'static str,
        cancellation: &CancellationToken,
    ) -> Result<(), FrostError> {
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => return Err(FrostError::Cancelled),
                event = self.bcast_event_rx.recv() => {
                    match event.ok_or(FrostError::ChannelClosed("frost bcast event channel"))? {
                        bcast::Event::BroadcastCompleted { msg_id } if msg_id == expected_msg_id => return Ok(()),
                        bcast::Event::BroadcastFailed { msg_id, error } if msg_id == expected_msg_id => return Err(error.into()),
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
        let mut p2p_msgs = HashMap::<PeerId, FrostRound1P2p>::new();

        for (key, share) in shares {
            if key.target_id == self.local_share_idx {
                return Err(FrostError::InternalState(
                    "bug: unexpected p2p message to self",
                ));
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

fn validate_round1_p2p(
    peer_id: PeerId,
    share_idx_by_peer: &HashMap<PeerId, u32>,
    local_share_idx: u32,
    msg: &FrostRound1P2p,
    num_validators: u32,
) -> Result<(), FrostError> {
    let source_id = *share_idx_by_peer
        .get(&peer_id)
        .ok_or(FrostError::InvalidMessage("invalid round 1 p2p source ID"))?;
    // A direct round-1 P2P message contains this peer's share for every validator.
    if msg.shares.len()
        != usize::try_from(num_validators)
            .map_err(|_| FrostError::InvalidMessage("invalid number of validators"))?
    {
        return Err(FrostError::InvalidMessage(
            "invalid round 1 p2p shares count",
        ));
    }
    let mut seen_validators = HashSet::with_capacity(msg.shares.len());
    for share in &msg.shares {
        let key = share
            .key
            .as_ref()
            .ok_or(FrostError::InvalidMessage("frost msg key cannot be nil"))?;
        if key.source_id != source_id {
            return Err(FrostError::InvalidMessage("invalid round 1 p2p source ID"));
        }
        if key.target_id != local_share_idx {
            return Err(FrostError::InvalidMessage("invalid round 1 p2p target ID"));
        }
        if key.val_idx >= num_validators {
            return Err(FrostError::InvalidMessage(
                "invalid round 1 p2p validator index",
            ));
        }
        if !seen_validators.insert(key.val_idx) {
            return Err(FrostError::InvalidMessage(
                "duplicate round 1 p2p validator index",
            ));
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
    let key = key.ok_or(FrostError::InvalidMessage("frost msg key cannot be nil"))?;
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
    let wi = bytes_to_scalar("decode wi scalar", &cast.wi)?;
    let ci = bytes_to_scalar("decode c1 scalar", &cast.ci)?;
    let commitments = cast
        .commitments
        .iter()
        .map(|commitment| bytes_to_g1("decode commitment", commitment))
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
    let value = bytes_to_scalar("decode shamir scalar", &share.value)?;
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
    let verification_key = bytes_to_g1("decode verification key scalar", &cast.verification_key)?;
    let vk_share = bytes_to_g1("decode vk share", &cast.vk_share)?;
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

fn bytes_to_scalar(context: &'static str, bytes: &Bytes) -> Result<[u8; 32], FrostError> {
    let scalar = bytes_to_array::<SCALAR_LEN>(context, bytes)?;
    kryptology::scalar_from_be(&scalar).map_err(|_| FrostError::InvalidMessage(context))?;
    Ok(scalar)
}

fn bytes_to_g1(context: &'static str, bytes: &Bytes) -> Result<[u8; 48], FrostError> {
    let point = bytes_to_array::<G1_COMPRESSED_LEN>(context, bytes)?;
    G1Projective::from_compressed(&point).ok_or(FrostError::InvalidMessage(context))?;
    Ok(point)
}

fn bytes_to_array<const N: usize>(
    context: &'static str,
    bytes: &Bytes,
) -> Result<[u8; N], FrostError> {
    bytes
        .as_ref()
        .try_into()
        .map_err(|_| FrostError::InvalidMessage(context))
}

#[cfg(test)]
mod tests {
    use prost::Name;

    use super::*;

    #[test]
    fn constants_match_reference() {
        assert_eq!(ROUND1_CAST_ID, "/charon/dkg/frost/2.0.0/round1/cast");
        assert_eq!(
            ROUND1_P2P_PROTOCOL.as_ref(),
            "/charon/dkg/frost/2.0.0/round1/p2p"
        );
        assert_eq!(ROUND2_CAST_ID, "/charon/dkg/frost/2.0.0/round2/cast");
        assert_eq!(MAX_MESSAGE_SIZE, 128 << 20);
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
            Err(FrostError::InvalidMessage("frost msg key cannot be nil"))
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
            Err(FrostError::InvalidMessage("decode wi scalar"))
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
            Err(FrostError::InvalidMessage("decode verification key scalar"))
        ));
    }

    #[test]
    fn cancel_all_removes_handler_pending_open() {
        let mut handler = FrostP2PHandler::new();

        handler.on_behaviour_event(InEvent::Send {
            op_id: 7,
            msg: FrostRound1P2p::default(),
        });
        handler.on_behaviour_event(InEvent::CancelPending);

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
            Err(FrostError::InvalidMessage(
                "invalid round 1 p2p shares count"
            ))
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
            Err(FrostError::InvalidMessage(
                "duplicate round 1 p2p validator index"
            ))
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
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
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
        let (_round1_p2p_tx, round1_p2p_rx) = mpsc::channel(1);
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
            share_idx_by_peer: HashMap::new(),
            local_share_idx: 1,
            num_validators: 0,
            num_peers: 0,
        }
    }
}
