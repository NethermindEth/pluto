//! Swarm behaviour for the DKG reliable-broadcast protocol.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    task::{Context, Poll},
};

use either::Either;
use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm, dummy,
    },
};
use prost::bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use crate::dkgpb::v1::bcast::BCastMessage;

use super::{
    component::{BroadcastCommand, Component, Registry},
    error::{Error, Result},
    handler::{DedupStore, Handler, InEvent, OutEvent},
    protocol,
};

/// Event emitted by the reliable-broadcast behaviour.
#[derive(Debug, Clone)]
pub enum Event {}

struct SigOp {
    peer: PeerId,
    index: usize,
}

struct BroadcastState {
    msg_id: String,
    any_msg: prost_types::Any,
    signatures: Vec<Option<Vec<u8>>>,
    sig_ops: HashMap<u64, SigOp>,
    msg_ops: HashMap<u64, PeerId>,
    resp_tx: oneshot::Sender<Result<()>>,
}

/// Swarm-owned behaviour for reliable broadcast.
pub struct Behaviour {
    local_peer_id: PeerId,
    peers: Arc<Vec<PeerId>>,
    secret: Arc<k256::SecretKey>,
    registry: Registry,
    dedup: DedupStore,
    command_rx: mpsc::UnboundedReceiver<BroadcastCommand>,
    pending_commands: VecDeque<BroadcastCommand>,
    pending_events: VecDeque<ToSwarm<Event, InEvent>>,
    connections: HashMap<PeerId, HashSet<ConnectionId>>,
    active_broadcast: Option<BroadcastState>,
    next_op_id: u64,
}

impl Behaviour {
    /// Creates a new behaviour instance and its user-facing component handle.
    pub fn new(
        local_peer_id: PeerId,
        peers: Vec<PeerId>,
        secret: k256::SecretKey,
    ) -> (Self, Component) {
        let registry: Registry = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let behaviour =
            Self::with_parts(local_peer_id, peers, secret, registry.clone(), command_rx);
        let component = Component::new(command_tx, registry);

        (behaviour, component)
    }

    fn with_parts(
        local_peer_id: PeerId,
        peers: Vec<PeerId>,
        secret: k256::SecretKey,
        registry: Registry,
        command_rx: mpsc::UnboundedReceiver<BroadcastCommand>,
    ) -> Self {
        Self {
            local_peer_id,
            peers: Arc::new(peers),
            secret: Arc::new(secret),
            registry,
            dedup: Arc::default(),
            command_rx,
            pending_commands: VecDeque::new(),
            pending_events: VecDeque::new(),
            connections: HashMap::new(),
            active_broadcast: None,
            next_op_id: 0,
        }
    }

    fn next_op_id(&mut self) -> u64 {
        let current = self.next_op_id;
        self.next_op_id = self.next_op_id.wrapping_add(1);
        current
    }

    fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.connections.contains_key(peer_id)
    }

    fn new_handler(&self, peer: PeerId) -> Handler {
        Handler::new(
            peer,
            self.registry.clone(),
            self.dedup.clone(),
            self.secret.clone(),
            self.peers.clone(),
        )
    }

    fn complete_active_broadcast(&mut self, result: Result<()>) {
        if let Some(state) = self.active_broadcast.take() {
            let _ = state.resp_tx.send(result);
        }
    }

    fn start_next_broadcast(&mut self) {
        if self.active_broadcast.is_some() {
            return;
        }

        let Some(BroadcastCommand {
            msg_id,
            any_msg,
            resp_tx,
        }) = self.pending_commands.pop_front()
        else {
            return;
        };

        self.start_broadcast(msg_id, any_msg, resp_tx);
    }

    fn start_broadcast(
        &mut self,
        msg_id: String,
        any_msg: prost_types::Any,
        resp_tx: oneshot::Sender<Result<()>>,
    ) {
        let local_index = match self
            .peers
            .iter()
            .position(|peer_id| peer_id == &self.local_peer_id)
        {
            Some(index) => index,
            None => {
                let _ = resp_tx.send(Err(Error::LocalPeerMissing));
                return;
            }
        };

        let mut signatures = vec![None; self.peers.len()];
        let local_signature = match protocol::sign_any(&self.secret, &any_msg) {
            Ok(signature) => signature,
            Err(error) => {
                let _ = resp_tx.send(Err(error));
                return;
            }
        };
        signatures[local_index] = Some(local_signature);

        let peers = self.peers.clone();
        let mut sig_dispatches = Vec::new();
        for (index, peer_id) in peers.iter().enumerate() {
            if peer_id == &self.local_peer_id {
                continue;
            }

            if !self.is_connected(peer_id) {
                let _ = resp_tx.send(Err(Error::PeerNotConnected(*peer_id)));
                return;
            }
            sig_dispatches.push((index, *peer_id));
        }

        let mut state = BroadcastState {
            msg_id,
            any_msg,
            signatures,
            sig_ops: HashMap::new(),
            msg_ops: HashMap::new(),
            resp_tx,
        };

        for (index, peer_id) in sig_dispatches {
            let op_id = self.next_op_id();
            state.sig_ops.insert(
                op_id,
                SigOp {
                    peer: peer_id,
                    index,
                },
            );
            self.pending_events.push_back(ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event: InEvent::RequestSignature {
                    op_id,
                    request: crate::dkgpb::v1::bcast::BCastSigRequest {
                        id: state.msg_id.clone(),
                        message: Some(state.any_msg.clone()),
                    },
                },
            });
        }

        self.active_broadcast = Some(state);
        if let Err(error) = self.maybe_advance_broadcast() {
            self.complete_active_broadcast(Err(error));
        }
    }

    fn maybe_advance_broadcast(&mut self) -> Result<()> {
        let Some(state) = self.active_broadcast.as_ref() else {
            return Ok(());
        };

        if !state.sig_ops.is_empty() || !state.msg_ops.is_empty() {
            return Ok(());
        }

        let signatures = state
            .signatures
            .iter()
            .cloned()
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::SignatureCollectionIncomplete)?;
        let msg_id = state.msg_id.clone();
        let any_msg = state.any_msg.clone();

        protocol::verify_signatures(&any_msg, &signatures, &self.peers)?;

        let message = BCastMessage {
            id: msg_id,
            message: Some(any_msg),
            signatures: signatures
                .iter()
                .cloned()
                .map(Bytes::from)
                .collect::<Vec<_>>(),
        };

        let peer_ids: Vec<PeerId> = self.peers.iter().copied().collect();
        let mut dispatches: Vec<(PeerId, u64)> = Vec::new();
        for peer_id in peer_ids {
            if peer_id == self.local_peer_id {
                continue;
            }

            if !self.is_connected(&peer_id) {
                return Err(Error::PeerNotConnected(peer_id));
            }
            let op_id = self.next_op_id();
            dispatches.push((peer_id, op_id));
        }

        if dispatches.is_empty() {
            self.complete_active_broadcast(Ok(()));
            return Ok(());
        }

        if let Some(state) = self.active_broadcast.as_mut() {
            for (peer_id, op_id) in &dispatches {
                state.msg_ops.insert(*op_id, *peer_id);
            }
        }

        for (peer_id, op_id) in dispatches {
            self.pending_events.push_back(ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event: InEvent::BroadcastMessage {
                    op_id,
                    message: message.clone(),
                },
            });
        }

        Ok(())
    }

    fn handle_handler_event(&mut self, peer_id: PeerId, event: OutEvent) {
        match event {
            OutEvent::SigResponse { op_id, signature } => {
                let mut should_advance = false;
                if let Some(state) = self.active_broadcast.as_mut()
                    && let Some(sig_op) = state.sig_ops.remove(&op_id)
                {
                    state.signatures[sig_op.index] = Some(signature);
                    should_advance = true;
                }

                if should_advance && let Err(error) = self.maybe_advance_broadcast() {
                    self.complete_active_broadcast(Err(error));
                }
            }
            OutEvent::MessageSent { op_id } => {
                let mut completed = false;
                if let Some(state) = self.active_broadcast.as_mut()
                    && state.msg_ops.remove(&op_id).is_some()
                {
                    completed = state.msg_ops.is_empty();
                }

                if completed {
                    self.complete_active_broadcast(Ok(()));
                }
            }
            OutEvent::OutboundFailure { op_id, failure } => {
                if let Some(state) = self.active_broadcast.as_mut() {
                    let failed_peer = state
                        .sig_ops
                        .remove(&op_id)
                        .map(|sig_op| sig_op.peer)
                        .or_else(|| state.msg_ops.remove(&op_id))
                        .unwrap_or(peer_id);
                    self.complete_active_broadcast(Err(Error::OutboundFailure {
                        peer: failed_peer,
                        failure,
                    }));
                } else {
                    debug!(peer = %peer_id, op_id, "ignoring stale outbound failure");
                }
            }
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Either<Handler, dummy::ConnectionHandler>;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        if self.peers.contains(&peer) {
            Ok(Either::Left(self.new_handler(peer)))
        } else {
            Ok(Either::Right(dummy::ConnectionHandler))
        }
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        if self.peers.contains(&peer) {
            Ok(Either::Left(self.new_handler(peer)))
        } else {
            Ok(Either::Right(dummy::ConnectionHandler))
        }
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(event) => {
                if !self.peers.contains(&event.peer_id) {
                    return;
                }

                self.connections
                    .entry(event.peer_id)
                    .or_default()
                    .insert(event.connection_id);
            }
            FromSwarm::ConnectionClosed(event) => {
                if !self.peers.contains(&event.peer_id) {
                    return;
                }

                if let Some(connections) = self.connections.get_mut(&event.peer_id) {
                    connections.remove(&event.connection_id);
                    if connections.is_empty() {
                        self.connections.remove(&event.peer_id);
                    } else {
                        return;
                    }

                    let should_fail = self.active_broadcast.as_ref().is_some_and(|state| {
                        state.sig_ops.values().any(|op| op.peer == event.peer_id)
                            || state.msg_ops.values().any(|peer| *peer == event.peer_id)
                    });

                    if should_fail {
                        self.complete_active_broadcast(Err(Error::PeerNotConnected(event.peer_id)));
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
        self.handle_handler_event(peer_id, event);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event.map_in(Either::Left));
        }

        while let Poll::Ready(Some(command)) = self.command_rx.poll_recv(cx) {
            self.pending_commands.push_back(command);
        }

        if self.active_broadcast.is_none() {
            self.start_next_broadcast();
        }

        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event.map_in(Either::Left));
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, net::TcpListener, time::Duration};

    use anyhow::Context as _;
    use futures::StreamExt;
    use libp2p::{Multiaddr, PeerId, swarm::SwarmEvent};
    use pluto_p2p::{
        config::P2PConfig,
        p2p::{Node, NodeType},
        peer::peer_id_from_key,
    };
    use pluto_testutil::random::generate_insecure_k1_key;
    use tokio::sync::{mpsc, oneshot};

    use crate::bcast::{Component, Error};

    use super::Behaviour;

    #[derive(Debug)]
    struct Receipt {
        target: usize,
        source: PeerId,
        msg_id: String,
        seconds: i64,
    }

    struct LocalNode {
        peer_id: PeerId,
        component: Component,
        node: Node<Behaviour>,
        addr: Multiaddr,
    }

    struct RunningNode {
        component: Component,
        stop_tx: oneshot::Sender<()>,
        join: tokio::task::JoinHandle<anyhow::Result<()>>,
    }

    fn timestamp(seconds: i64) -> prost_types::Timestamp {
        prost_types::Timestamp { seconds, nanos: 0 }
    }

    fn available_tcp_port() -> anyhow::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?.port())
    }

    async fn wait_for_connections(
        conn_rx: &mut mpsc::UnboundedReceiver<(usize, PeerId)>,
        expected_peers: &[PeerId],
    ) -> anyhow::Result<()> {
        let mut seen = vec![HashSet::<PeerId>::new(); expected_peers.len()];

        tokio::time::timeout(Duration::from_secs(10), async {
            while seen
                .iter()
                .any(|peers| peers.len() < expected_peers.len().saturating_sub(1))
            {
                let (index, peer_id) = conn_rx
                    .recv()
                    .await
                    .context("connection event channel closed")?;
                seen[index].insert(peer_id);

                if seen
                    .iter()
                    .all(|peers| peers.len() == expected_peers.len().saturating_sub(1))
                {
                    return Ok(());
                }
            }

            Ok(())
        })
        .await
        .context("timed out waiting for libp2p connections")?
    }

    async fn wait_for_receipts(
        receipt_rx: &mut mpsc::UnboundedReceiver<Receipt>,
        expected_count: usize,
    ) -> anyhow::Result<Vec<Receipt>> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut receipts = Vec::with_capacity(expected_count);
            while receipts.len() < expected_count {
                receipts.push(receipt_rx.recv().await.context("receipt channel closed")?);
            }
            Ok(receipts)
        })
        .await
        .context("timed out waiting for receipts")?
    }

    async fn register_timestamp_message(
        component: &Component,
        node_index: usize,
        receipt_tx: mpsc::UnboundedSender<Receipt>,
    ) -> crate::bcast::Result<()> {
        component
            .register_message::<prost_types::Timestamp>(
                "timestamp",
                Box::new(|_peer_id, _msg| Ok(())),
                Box::new(move |peer_id, msg_id, msg| {
                    receipt_tx
                        .send(Receipt {
                            target: node_index,
                            source: peer_id,
                            msg_id: msg_id.to_string(),
                            seconds: msg.seconds,
                        })
                        .map_err(|_| Error::ReceiptChannelClosed)?;
                    Ok(())
                }),
            )
            .await
    }

    async fn spawn_nodes(
        mut nodes: Vec<LocalNode>,
        conn_tx: mpsc::UnboundedSender<(usize, PeerId)>,
    ) -> anyhow::Result<Vec<RunningNode>> {
        for node in &mut nodes {
            node.node.listen_on(node.addr.clone())?;
        }

        let dial_targets = (0..nodes.len())
            .map(|index| {
                nodes
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other > index)
                    .map(|(_, node)| node.addr.clone())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut running = Vec::with_capacity(nodes.len());
        for (index, (local, targets)) in nodes.into_iter().zip(dial_targets).enumerate() {
            let mut node = local.node;
            let conn_tx = conn_tx.clone();
            let (stop_tx, mut stop_rx) = oneshot::channel();

            let join = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                for target in targets {
                    node.dial(target)?;
                }

                loop {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        event = node.select_next_some() => {
                            if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                                let _ = conn_tx.send((index, peer_id));
                            }
                        }
                    }
                }

                Ok(())
            });

            running.push(RunningNode {
                component: local.component,
                stop_tx,
                join,
            });
        }

        Ok(running)
    }

    async fn shutdown_nodes(nodes: Vec<RunningNode>) -> anyhow::Result<()> {
        for node in nodes {
            let _ = node.stop_tx.send(());
            node.join.await??;
        }

        Ok(())
    }

    #[tokio::test]
    async fn broadcast_round_trip_and_duplicate_semantics() -> anyhow::Result<()> {
        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();
        let (receipt_tx, mut receipt_rx) = mpsc::unbounded_channel();
        let ports = (0..3)
            .map(|_| available_tcp_port())
            .collect::<anyhow::Result<Vec<_>>>()?;

        let keys = (0u8..3).map(generate_insecure_k1_key).collect::<Vec<_>>();
        let peer_ids = keys
            .iter()
            .map(|key| peer_id_from_key(key.public_key()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut nodes = Vec::with_capacity(keys.len());
        for (index, key) in keys.into_iter().enumerate() {
            let peer_id = peer_ids[index];
            let (behaviour, component) = Behaviour::new(peer_id, peer_ids.clone(), key.clone());
            register_timestamp_message(&component, index, receipt_tx.clone()).await?;
            let node = Node::new_server(
                P2PConfig::default(),
                key,
                NodeType::TCP,
                false,
                peer_ids.clone(),
                |builder, _keypair| builder.with_inner(behaviour),
            )?;
            let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", ports[index]).parse()?;
            nodes.push(LocalNode {
                peer_id,
                component,
                node,
                addr,
            });
        }
        let expected_peers = nodes.iter().map(|node| node.peer_id).collect::<Vec<_>>();

        let running = spawn_nodes(nodes, conn_tx).await?;
        wait_for_connections(&mut conn_rx, &expected_peers).await?;

        running[0]
            .component
            .broadcast("timestamp", &timestamp(10))
            .await?;

        let receipts = wait_for_receipts(&mut receipt_rx, 2).await?;
        let targets = receipts
            .iter()
            .map(|receipt| receipt.target)
            .collect::<HashSet<_>>();
        assert_eq!(targets, HashSet::from([1usize, 2usize]));
        let sources = receipts
            .iter()
            .map(|receipt| receipt.source)
            .collect::<HashSet<_>>();
        assert_eq!(sources, HashSet::from([expected_peers[0]]));
        assert!(receipts.iter().all(|receipt| receipt.msg_id == "timestamp"));
        assert!(receipts.iter().all(|receipt| receipt.seconds == 10));

        running[0]
            .component
            .broadcast("timestamp", &timestamp(10))
            .await?;
        let receipts = wait_for_receipts(&mut receipt_rx, 2).await?;
        assert!(receipts.iter().all(|receipt| receipt.seconds == 10));

        let error = running[0]
            .component
            .broadcast("timestamp", &timestamp(11))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::OutboundFailure { .. }));

        let error = running[0]
            .component
            .broadcast("unknown", &timestamp(99))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::UnknownMessageId(_)));

        shutdown_nodes(running).await?;
        Ok(())
    }
}
