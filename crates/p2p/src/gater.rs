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
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm, dummy,
    },
};

use crate::peer::MutablePeer;

/// Configuration for the connection gater.
#[derive(Debug, Clone, Default)]
pub struct Config {
    peer_ids: HashSet<PeerId>,
    relays: Vec<MutablePeer>,
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
    pub fn with_relays(mut self, relays: Vec<MutablePeer>) -> Self {
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
    pub fn new_conn_gater(peers: Vec<PeerId>, relays: Vec<MutablePeer>) -> Self {
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
            if let Some(peer) = relay.peer()
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
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if self.is_peer_allowed(&peer) {
            Ok(dummy::ConnectionHandler)
        } else {
            self.events.push_back(Event::PeerBlocked(peer));
            Err(ConnectionDenied::new(PeerNotAllowed(peer)))
        }
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // Charon's `InterceptSecured` ignores the connection direction and gates
        // both inbound and outbound secured connections, so mirror the inbound
        // gating logic here. Legitimate outbound dials (relay dials,
        // force-direct, QUIC-upgrade) target relays and cluster peers, which are
        // both in the allow-list.
        if self.is_peer_allowed(&peer) {
            Ok(dummy::ConnectionHandler)
        } else {
            self.events.push_back(Event::PeerBlocked(peer));
            Err(ConnectionDenied::new(PeerNotAllowed(peer)))
        }
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

#[cfg(test)]
mod tests {
    use std::task::Waker;

    use libp2p::core::{Endpoint, transport::PortUse};

    use super::*;
    use crate::peer::Peer;

    fn dummy_addr() -> Multiaddr {
        "/ip4/127.0.0.1/tcp/9000".parse().unwrap()
    }

    fn relay_peer(id: PeerId) -> MutablePeer {
        MutablePeer::new(Peer {
            id,
            addresses: vec![],
            index: 0,
            name: "relay".to_string(),
        })
    }

    fn try_inbound(gater: &mut ConnGater, peer: PeerId) -> bool {
        gater
            .handle_established_inbound_connection(
                ConnectionId::new_unchecked(0),
                peer,
                &dummy_addr(),
                &dummy_addr(),
            )
            .is_ok()
    }

    fn try_outbound(gater: &mut ConnGater, peer: PeerId) -> bool {
        gater
            .handle_established_outbound_connection(
                ConnectionId::new_unchecked(0),
                peer,
                &dummy_addr(),
                Endpoint::Dialer,
                PortUse::Reuse,
            )
            .is_ok()
    }

    /// Drains a single event from `poll`, mirroring how the swarm would
    /// consume generated events.
    fn poll_event(gater: &mut ConnGater) -> Option<Event> {
        let mut cx = Context::from_waker(Waker::noop());
        match gater.poll(&mut cx) {
            Poll::Ready(ToSwarm::GenerateEvent(event)) => Some(event),
            _ => None,
        }
    }

    /// Mirrors Charon's `TestOpenGater`: an open gater allows any peer in
    /// either direction.
    #[test]
    fn open_gater_allows_all() {
        let mut gater = ConnGater::new_open_gater();
        let peer = PeerId::random();

        assert!(gater.is_open());
        assert!(try_inbound(&mut gater, peer));
        assert!(try_outbound(&mut gater, peer));
        assert!(poll_event(&mut gater).is_none());
    }

    /// Mirrors Charon's `TestInterceptSecured`: a known cluster peer is
    /// allowed, an unknown peer is denied. Charon ignores the direction, so we
    /// assert both directions behave identically.
    #[test]
    fn known_peer_allowed_unknown_denied_both_directions() {
        let known = PeerId::random();
        let unknown = PeerId::random();

        let mut gater = ConnGater::new_conn_gater(vec![known], vec![]);

        // Known peer: allowed inbound and outbound, no event.
        assert!(try_inbound(&mut gater, known));
        assert!(try_outbound(&mut gater, known));
        assert!(poll_event(&mut gater).is_none());

        // Unknown peer: denied inbound and outbound.
        assert!(!try_inbound(&mut gater, unknown));
        assert!(!try_outbound(&mut gater, unknown));
    }

    /// Relays are part of the allow-list, so both directions must succeed for a
    /// relay peer. This pins the invariant that outbound relay dials keep
    /// working after the outbound gate is enabled.
    #[test]
    fn relay_peer_allowed_both_directions() {
        let relay_id = PeerId::random();
        let mut gater = ConnGater::new_conn_gater(vec![], vec![relay_peer(relay_id)]);

        assert!(try_inbound(&mut gater, relay_id));
        assert!(try_outbound(&mut gater, relay_id));
        assert!(poll_event(&mut gater).is_none());
    }

    /// A closed gater with no allowed peers denies everything in both
    /// directions.
    #[test]
    fn closed_gater_denies_unknown_both_directions() {
        let mut gater = ConnGater::new_conn_gater(vec![], vec![]);
        let peer = PeerId::random();

        assert!(!try_inbound(&mut gater, peer));
        assert!(!try_outbound(&mut gater, peer));
    }

    /// Denying an inbound connection queues a `PeerBlocked` event that `poll`
    /// surfaces to the swarm.
    #[test]
    fn inbound_denial_emits_peer_blocked_event() {
        let mut gater = ConnGater::new_conn_gater(vec![], vec![]);
        let peer = PeerId::random();

        assert!(!try_inbound(&mut gater, peer));

        match poll_event(&mut gater) {
            Some(Event::PeerBlocked(blocked)) => assert_eq!(blocked, peer),
            other => panic!("expected PeerBlocked event, got {other:?}"),
        }
        // No further events are pending.
        assert!(poll_event(&mut gater).is_none());
    }

    /// Denying an outbound connection also queues a `PeerBlocked` event that
    /// `poll` surfaces to the swarm — the behaviour the issue requires.
    #[test]
    fn outbound_denial_emits_peer_blocked_event() {
        let mut gater = ConnGater::new_conn_gater(vec![], vec![]);
        let peer = PeerId::random();

        assert!(!try_outbound(&mut gater, peer));

        match poll_event(&mut gater) {
            Some(Event::PeerBlocked(blocked)) => assert_eq!(blocked, peer),
            other => panic!("expected PeerBlocked event, got {other:?}"),
        }
        assert!(poll_event(&mut gater).is_none());
    }
}
