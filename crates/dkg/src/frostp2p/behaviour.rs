//! libp2p `NetworkBehaviour` for FROST round-1 direct P2P and the user-facing
//! sender/handle types it produces.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    task::{Context, Poll},
};

use either::Either;
use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
        dial_opts::{DialOpts, PeerCondition},
        dummy,
    },
};
use pluto_p2p::p2p_context::P2PContext;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::{
    FrostP2PError, FrostP2PEvent,
    handler::{FrostP2PHandler, InEvent, OutEvent},
    transport::validate_round1_p2p,
};
use crate::{dkgpb::v1::frost::FrostRound1P2p, frost::FrostError};

type SendResultTx = oneshot::Sender<Result<(), FrostP2PError>>;

#[derive(Debug)]
pub(super) enum SendCommand {
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

    pub(super) fn emit_event(&self, event: FrostP2PEvent) {
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
    pub(super) sender: FrostP2PSender,
}

impl FrostP2PHandle {
    pub(super) fn take_inbound_rx(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<(PeerId, FrostRound1P2p)>, FrostError> {
        self.inbound_rx
            .take()
            .ok_or(FrostError::P2PInboundReceiverAlreadyTaken)
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
        self.p2p_context.peer_store_lock().has_connection(peer_id)
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

#[cfg(test)]
mod tests {
    use futures::FutureExt;
    use libp2p::swarm::ConnectionId;
    use prost::bytes::Bytes;

    use super::*;
    use crate::{
        dkgpb::v1::frost::FrostRound1ShamirShare, frost::MsgKey, frostp2p::codec::key_to_proto,
    };

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
}
