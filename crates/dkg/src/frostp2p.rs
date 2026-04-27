//! FROST round-1 direct P2P transport.
//!
//! Implements the `/charon/dkg/frost/2.0.0/round1/p2p` stream protocol used
//! to exchange Shamir shares between pairs of participants during FROST DKG.
//! Each participant opens one outbound stream per remote peer and sends a
//! [`FrostRound1P2p`] message; inbound messages from all peers are collected
//! and forwarded to the caller via a channel.
//!
//! The protocol is one-shot: every pair exchanges exactly one message.

use std::{
    collections::{HashMap, VecDeque},
    task::{Context, Poll},
};

use futures::{AsyncWriteExt, FutureExt, future::BoxFuture};
use libp2p::{
    Multiaddr, PeerId,
    core::upgrade::ReadyUpgrade,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
        dial_opts::DialOpts,
        handler::{
            ConnectionEvent, ConnectionHandler, ConnectionHandlerEvent, FullyNegotiatedInbound,
            FullyNegotiatedOutbound, SubstreamProtocol,
        },
    },
};
use prost::Message;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::dkgpb::v1::frost::FrostRound1P2p;

/// `/charon/dkg/frost/2.0.0/round1/p2p` — direct Shamir-share delivery.
pub const PROTOCOL: libp2p::swarm::StreamProtocol =
    libp2p::swarm::StreamProtocol::new("/charon/dkg/frost/2.0.0/round1/p2p");

const MAX_MSG_SIZE: usize = 4 * 1024 * 1024;

// ── Handler ────────────────────────────────────────────────────────────────

/// Event sent from the behaviour to a handler.
#[derive(Debug)]
pub enum InEvent {
    /// Payload to send to the remote peer.
    Send(Vec<u8>),
}

/// Event sent from a handler back to the behaviour.
#[derive(Debug)]
pub enum OutEvent {
    /// A decoded frost round-1 P2P message was received.
    Received(FrostRound1P2p),
}

/// Connection handler for the FROST round-1 P2P protocol.
pub struct Handler {
    inbound: Option<BoxFuture<'static, Option<FrostRound1P2p>>>,
    pending_send: Option<Vec<u8>>,
    outbound: Option<BoxFuture<'static, ()>>,
}

impl Handler {
    fn new() -> Self {
        Self {
            inbound: None,
            pending_send: None,
            outbound: None,
        }
    }

    fn substream_protocol() -> SubstreamProtocol<ReadyUpgrade<libp2p::swarm::StreamProtocol>> {
        SubstreamProtocol::new(ReadyUpgrade::new(PROTOCOL), ())
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = InEvent;
    type InboundOpenInfo = ();
    type InboundProtocol = ReadyUpgrade<libp2p::swarm::StreamProtocol>;
    type OutboundOpenInfo = ();
    type OutboundProtocol = ReadyUpgrade<libp2p::swarm::StreamProtocol>;
    type ToBehaviour = OutEvent;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        Self::substream_protocol()
    }

    fn on_behaviour_event(&mut self, event: InEvent) {
        let InEvent::Send(payload) = event;
        self.pending_send = Some(payload);
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
                protocol: mut stream,
                ..
            }) => {
                self.inbound = Some(Box::pin(async move {
                    match pluto_p2p::proto::read_length_delimited(&mut stream, MAX_MSG_SIZE).await {
                        Ok(bytes) => FrostRound1P2p::decode(bytes.as_slice()).ok(),
                        Err(e) => {
                            warn!(err = %e, "Failed to read frost p2p inbound message");
                            None
                        }
                    }
                }));
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: mut stream,
                ..
            }) => {
                let payload = self.pending_send.take().unwrap_or_default();
                self.outbound = Some(Box::pin(async move {
                    if let Err(e) =
                        pluto_p2p::proto::write_length_delimited(&mut stream, &payload).await
                    {
                        warn!(err = %e, "Failed to write frost p2p outbound message");
                        return;
                    }
                    let _ = stream.close().await;
                }));
            }
            ConnectionEvent::DialUpgradeError(libp2p::swarm::handler::DialUpgradeError {
                error,
                ..
            }) => {
                warn!(err = ?error, "Frost p2p dial upgrade error");
                self.pending_send = None;
            }
            _ => {}
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        // Drive pending inbound future.
        if let Some(Poll::Ready(result)) = self.inbound.as_mut().map(|f| f.poll_unpin(cx)) {
            self.inbound = None;
            if let Some(msg) = result {
                return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(OutEvent::Received(
                    msg,
                )));
            }
        }

        // Drive active outbound future.
        if matches!(
            self.outbound.as_mut().map(|f| f.poll_unpin(cx)),
            Some(Poll::Ready(()))
        ) {
            self.outbound = None;
        }

        // Request a new outbound stream if we have a pending payload.
        if self.outbound.is_none() && self.pending_send.is_some() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: Self::substream_protocol(),
            });
        }

        Poll::Pending
    }
}

// ── Behaviour ──────────────────────────────────────────────────────────────

/// User-facing handle for the [`FrostP2PBehaviour`].
pub struct FrostP2PHandle {
    /// Receives `(sender_peer_id, message)` as inbound messages arrive.
    pub inbound_rx: mpsc::UnboundedReceiver<(PeerId, FrostRound1P2p)>,
    cmd_tx: mpsc::UnboundedSender<(PeerId, Vec<u8>)>,
}

impl FrostP2PHandle {
    /// Enqueues a frost round-1 P2P message for delivery to `peer_id`.
    pub fn send(&self, peer_id: PeerId, msg: &FrostRound1P2p) {
        let payload = msg.encode_to_vec();
        if self.cmd_tx.send((peer_id, payload)).is_err() {
            warn!("FrostP2P handle: behaviour dropped before send");
        }
    }
}

/// libp2p behaviour for the FROST round-1 direct P2P protocol.
pub struct FrostP2PBehaviour {
    inbound_tx: mpsc::UnboundedSender<(PeerId, FrostRound1P2p)>,
    cmd_rx: mpsc::UnboundedReceiver<(PeerId, Vec<u8>)>,
    /// Payloads waiting for a connection to the peer.
    pending: HashMap<PeerId, Vec<u8>>,
    /// Most recently seen connection per peer.
    connections: HashMap<PeerId, ConnectionId>,
    pending_events: VecDeque<ToSwarm<(), THandlerInEvent<Self>>>,
}

impl FrostP2PBehaviour {
    /// Creates a new `FrostP2PBehaviour` and its user-facing
    /// [`FrostP2PHandle`].
    pub fn new() -> (Self, FrostP2PHandle) {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let behaviour = Self {
            inbound_tx,
            cmd_rx,
            pending: HashMap::new(),
            connections: HashMap::new(),
            pending_events: VecDeque::new(),
        };
        let handle = FrostP2PHandle { inbound_rx, cmd_tx };
        (behaviour, handle)
    }

    fn drain_commands(&mut self) {
        while let Ok((peer_id, payload)) = self.cmd_rx.try_recv() {
            if let Some(&conn_id) = self.connections.get(&peer_id) {
                debug!(%peer_id, "Frost p2p: notifying handler to send");
                self.pending_events.push_back(ToSwarm::NotifyHandler {
                    peer_id,
                    handler: NotifyHandler::One(conn_id),
                    event: InEvent::Send(payload),
                });
            } else {
                debug!(%peer_id, "Frost p2p: dialing peer for send");
                self.pending.insert(peer_id, payload);
                self.pending_events.push_back(ToSwarm::Dial {
                    opts: DialOpts::peer_id(peer_id).build(),
                });
            }
        }
    }
}

impl NetworkBehaviour for FrostP2PBehaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = ();

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new())
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(info) => {
                self.connections.insert(info.peer_id, info.connection_id);
                if let Some(payload) = self.pending.remove(&info.peer_id) {
                    debug!(peer_id = %info.peer_id, "Frost p2p: flushing pending send on connect");
                    self.pending_events.push_back(ToSwarm::NotifyHandler {
                        peer_id: info.peer_id,
                        handler: NotifyHandler::One(info.connection_id),
                        event: InEvent::Send(payload),
                    });
                }
            }
            FromSwarm::ConnectionClosed(info)
                if self.connections.get(&info.peer_id) == Some(&info.connection_id) =>
            {
                self.connections.remove(&info.peer_id);
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
        let OutEvent::Received(msg) = event;
        debug!(%peer_id, "Frost p2p: received round1 p2p message");
        let _ = self.inbound_tx.send((peer_id, msg));
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.drain_commands();

        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}
