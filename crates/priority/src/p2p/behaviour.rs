//! Swarm behaviour backing the priority request/response protocol.
//!
//! The behaviour owns a registered inbound handler callback and routes
//! outbound [`SendReceive`](super::Command::SendReceive) commands to the
//! connection handler for the target peer, dialing first when no connection
//! exists.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
        dial_opts::{DialOpts, PeerCondition},
    },
};
use tokio::sync::mpsc;

use super::{
    Command, InboundHandler,
    handler::{FromBehaviour, Handler, OutboundRequest},
};

/// Swarm behaviour for the priority protocol.
pub struct Behaviour {
    inbound_handler: InboundHandler,
    command_rx: mpsc::UnboundedReceiver<Command>,
    /// Peers with at least one established connection.
    connected: HashSet<PeerId>,
    /// Outbound requests waiting for a connection to the target peer.
    awaiting_connection: HashMap<PeerId, Vec<OutboundRequest>>,
    pending_events: VecDeque<ToSwarm<Event, THandlerInEvent<Self>>>,
}

/// The priority behaviour emits no swarm-level events.
pub type Event = std::convert::Infallible;

impl Behaviour {
    pub(crate) fn new(
        inbound_handler: InboundHandler,
        command_rx: mpsc::UnboundedReceiver<Command>,
    ) -> Self {
        Self {
            inbound_handler,
            command_rx,
            connected: HashSet::new(),
            awaiting_connection: HashMap::new(),
            pending_events: VecDeque::new(),
        }
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::SendReceive { peer, request } => self.send_receive(peer, request),
        }
    }

    fn send_receive(&mut self, peer: PeerId, request: OutboundRequest) {
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
    type ConnectionHandler = Handler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(peer, self.inbound_handler.clone()))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(peer, self.inbound_handler.clone()))
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
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        while let Poll::Ready(Some(command)) = self.command_rx.poll_recv(cx) {
            self.handle_command(command);
        }

        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}

/// Clones an [`crate::Error`] for fan-out to multiple awaiting requests.
///
/// Only transport/unsupported variants reach this path; both are cheaply
/// reconstructable from their displayed form without losing parity-relevant
/// detail.
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
