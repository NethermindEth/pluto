//! Swarm behaviour backing the priority request/response protocol.
//!
//! The behaviour owns a registered inbound handler callback and routes
//! outbound [`SendReceive`](super::Command::SendReceive) commands to the
//! connection handler for the target peer, dialing first when no connection
//! exists.
//!
//! Cluster membership and dial addresses come from the shared
//! [`P2PContext`]: non-cluster peers are served a no-op handler, and outbound
//! dials by peer id resolve their address from the context's peer store.

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
use tokio::sync::mpsc;

use super::{
    Command, InboundHandler,
    handler::{FromBehaviour, Handler, InboundFailure, OutboundRequest},
};

/// Swarm behaviour for the priority protocol.
pub struct Behaviour {
    inbound_handler: InboundHandler,
    command_rx: mpsc::UnboundedReceiver<Command>,
    /// Shared cluster context: source of truth for known-peer gating and
    /// outbound dial-address resolution.
    p2p_context: P2PContext,
    /// Peers with at least one established connection.
    connected: HashSet<PeerId>,
    /// Outbound requests waiting for a connection to the target peer.
    awaiting_connection: HashMap<PeerId, Vec<OutboundRequest>>,
    pending_events: VecDeque<ToSwarm<Event, FromBehaviour>>,
}

/// Swarm-level event emitted by the priority behaviour.
///
/// The only event is an inbound-exchange failure, surfaced so the application
/// can log or meter rejected/malformed inbound requests. Outbound results are
/// delivered through the [`Sender`](super::Sender)'s per-request channel, not
/// as events.
#[derive(Debug)]
pub enum Event {
    /// An inbound priority exchange from `peer` failed; no response was sent.
    InboundFailure {
        /// The peer whose inbound request failed.
        peer: PeerId,
        /// Why the exchange failed.
        failure: InboundFailure,
    },
}

impl Behaviour {
    pub(crate) fn new(
        inbound_handler: InboundHandler,
        command_rx: mpsc::UnboundedReceiver<Command>,
        p2p_context: P2PContext,
    ) -> Self {
        Self {
            inbound_handler,
            command_rx,
            p2p_context,
            connected: HashSet::new(),
            awaiting_connection: HashMap::new(),
            pending_events: VecDeque::new(),
        }
    }

    /// Installs a real handler only for configured cluster peers; a non-cluster
    /// peer gets a no-op handler so it cannot open priority substreams.
    fn connection_handler_for_peer(&self, peer: PeerId) -> THandler<Self> {
        if self.p2p_context.is_known_peer(&peer) {
            Either::Left(Handler::new(peer, self.inbound_handler.clone()))
        } else {
            Either::Right(dummy::ConnectionHandler)
        }
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::SendReceive { peer, request } => self.send_receive(peer, request),
        }
    }

    fn send_receive(&mut self, peer: PeerId, request: OutboundRequest) {
        // The send path must share the gate used by `connection_handler_for_peer`:
        // a non-cluster peer is served a `dummy` (`Either::Right`) handler, so
        // delivering a `SendReceive` (`Either::Left`) event to it would mismatch
        // the handler arm and abort the whole swarm task via libp2p's
        // `unreachable!()`. Refuse here with the same outcome the remote side
        // produces when it gates us out (`Unsupported`). This keeps the engine
        // panic-safe even if a caller wires a `peers` set that is not a subset of
        // the context's known peers.
        if !self.p2p_context.is_known_peer(&peer) {
            let _ = request.response.send(Err(crate::Error::Unsupported));
            return;
        }

        if self.connected.contains(&peer) {
            self.notify_handler(peer, request);
            return;
        }

        let first = self.awaiting_connection.entry(peer).or_default();
        let needs_dial = first.is_empty();
        first.push(request);

        if needs_dial {
            self.pending_events.push_back(ToSwarm::Dial {
                opts: DialOpts::peer_id(peer)
                    .condition(PeerCondition::DisconnectedAndNotDialing)
                    .build(),
            });
        }
    }

    fn notify_handler(&mut self, peer: PeerId, request: OutboundRequest) {
        self.pending_events.push_back(ToSwarm::NotifyHandler {
            peer_id: peer,
            handler: NotifyHandler::Any,
            event: FromBehaviour::SendReceive(request),
        });
    }

    fn flush_awaiting(&mut self, peer: PeerId) {
        if let Some(requests) = self.awaiting_connection.remove(&peer) {
            for request in requests {
                self.notify_handler(peer, request);
            }
        }
    }

    fn fail_awaiting(&mut self, peer: PeerId, error: &crate::Error) {
        if let Some(requests) = self.awaiting_connection.remove(&peer) {
            for request in requests {
                let _ = request.response.send(Err(clone_error(error)));
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
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.connection_handler_for_peer(peer))
    }

    /// Supplies peer-store addresses for outbound dials issued by peer id, so a
    /// priority exchange can re-establish a dropped connection to a cluster
    /// peer on its own rather than depending on a sibling behaviour to
    /// resolve the address. The store is populated from identify by the
    /// node-wide context.
    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _effective_role: libp2p::core::Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let Some(peer_id) = maybe_peer else {
            return Ok(vec![]);
        };

        Ok(self
            .p2p_context
            .peer_store_lock()
            .peer_addresses(&peer_id)
            .cloned()
            .unwrap_or_default())
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
                self.connected.insert(event.peer_id);
                self.flush_awaiting(event.peer_id);
            }
            FromSwarm::ConnectionClosed(event) if event.remaining_established == 0 => {
                self.connected.remove(&event.peer_id);
            }
            FromSwarm::DialFailure(event) => {
                if let Some(peer) = event.peer_id {
                    self.fail_awaiting(peer, &crate::Error::Transport(event.error.to_string()));
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
        // `Left` is the real handler's inbound-failure report; `Right` is the
        // dummy handler, whose `ToBehaviour` is uninhabited (unreachable).
        let failure = match event {
            Either::Left(failure) => failure,
            Either::Right(unreachable) => match unreachable {},
        };
        self.pending_events
            .push_back(ToSwarm::GenerateEvent(Event::InboundFailure {
                peer: peer_id,
                failure,
            }));
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        while let Poll::Ready(Some(command)) = self.command_rx.poll_recv(cx) {
            self.handle_command(command);
        }

        if let Some(event) = self.pending_events.pop_front() {
            // Route handler-bound events to the real (`Left`) handler; non-peer
            // events (e.g. `Dial`) pass through unchanged.
            return Poll::Ready(event.map_in(Either::Left));
        }

        Poll::Pending
    }
}

/// Clones the subset of [`crate::Error`] that can reach the awaiting-connection
/// path (dial/negotiation outcomes), which is not `Clone` as a whole.
///
/// Only `Unsupported` and `Transport` are expected here; any other variant is a
/// bug (caught in debug) and is flattened to `Transport` rather than re-wrapped
/// — re-wrapping a `Transport` via `to_string()` would duplicate its Display
/// prefix.
fn clone_error(error: &crate::Error) -> crate::Error {
    match error {
        crate::Error::Unsupported => crate::Error::Unsupported,
        crate::Error::Transport(msg) => crate::Error::Transport(msg.clone()),
        other => {
            debug_assert!(false, "unexpected error on awaiting path: {other}");
            crate::Error::Transport(other.to_string())
        }
    }
}
