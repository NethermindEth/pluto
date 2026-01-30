//! Gater is responsible for whitelisting / blacklisting peers.
//!
//! This module provides connection gating functionality that limits access to
//! cluster peers and relays. In Rust libp2p, connection gating is implemented
//! via the `NetworkBehaviour` trait, specifically through the
//! `handle_established_inbound_connection` and
//! `handle_established_outbound_connection` methods which can reject
//! connections by returning `ConnectionDenied`.

use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
    },
};

use crate::peer::MutablePeer;

mod handler;

/// Configuration for the connection gater.
#[derive(Debug, Clone, Default)]
pub struct Config {
    peer_ids: HashSet<PeerId>,
    relays: Vec<Arc<MutablePeer>>,
    open: bool,
}

impl Config {
    /// Creates a new open gater configuration that does not gate any
    /// connections.
    pub fn open() -> Self {
        Self {
            peer_ids: HashSet::new(),
            relays: Vec::new(),
            open: true,
        }
    }

    /// Creates a new closed gater configuration that gates all connections
    /// except those explicitly allowed.
    pub fn closed() -> Self {
        Self {
            peer_ids: HashSet::new(),
            relays: Vec::new(),
            open: false,
        }
    }

    /// Sets the allowed peer IDs.
    pub fn with_peer_ids(mut self, peer_ids: Vec<PeerId>) -> Self {
        self.peer_ids = peer_ids.into_iter().collect();
        self
    }

    /// Sets the relay peers.
    pub fn with_relays(mut self, relays: Vec<Arc<MutablePeer>>) -> Self {
        self.relays = relays;
        self
    }
}

/// ConnGater filters incoming and outgoing connections by the cluster peers.
#[derive(Debug, Clone, Default)]
pub struct ConnGater {
    config: Config,
    events: VecDeque<Event>,
}

impl ConnGater {
    /// Creates a new connection gater with the given configuration.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            events: VecDeque::new(),
        }
    }

    /// Creates a new connection gater that limits access to the cluster peers
    /// and relays.
    pub fn new_conn_gater(peers: Vec<PeerId>, relays: Vec<Arc<MutablePeer>>) -> Self {
        Self {
            config: Config::closed().with_peer_ids(peers).with_relays(relays),
            events: VecDeque::new(),
        }
    }

    /// Creates a new open gater that does not gate any connections.
    pub fn new_open_gater() -> Self {
        Self {
            config: Config::open(),
            events: VecDeque::new(),
        }
    }

    /// Returns true if the gater is open (not gating any connections).
    pub fn is_open(&self) -> bool {
        self.config.open
    }

    /// Checks if a peer is allowed to connect.
    fn is_peer_allowed(&self, peer_id: &PeerId) -> bool {
        if self.config.open {
            return true;
        }

        // Check if peer is in the allowed set
        if self.config.peer_ids.contains(peer_id) {
            return true;
        }

        // Check if peer is a relay
        for relay in &self.config.relays {
            if let Ok(Some(peer)) = relay.peer()
                && peer.id == *peer_id
            {
                return true;
            }
        }

        false
    }
}

/// Event emitted by the connection gater behaviour.
#[derive(Debug, Clone)]
pub enum Event {
    /// A peer was blocked from connecting.
    PeerBlocked(PeerId),
}

impl NetworkBehaviour for ConnGater {
    type ConnectionHandler = handler::Handler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if self.is_peer_allowed(&peer) {
            Ok(handler::Handler::new())
        } else {
            self.events.push_back(Event::PeerBlocked(peer));
            Err(ConnectionDenied::new(PeerNotAllowed(peer)))
        }
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // Allow all outbound connections
        Ok(handler::Handler::new())
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {
        // No special handling needed for swarm events
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        _event: THandlerOutEvent<Self>,
    ) {
        // Handler events are Void, so this is unreachable
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // Emit any blocked events
        if !self.events.is_empty() {
            let event = self.events.pop_front().expect("events is not empty");
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }

        Poll::Pending
    }
}

/// Error indicating a peer is not allowed to connect.
#[derive(Debug, Clone)]
pub struct PeerNotAllowed(pub PeerId);

impl std::fmt::Display for PeerNotAllowed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer {} is not in the allowed list", self.0)
    }
}

impl std::error::Error for PeerNotAllowed {}
