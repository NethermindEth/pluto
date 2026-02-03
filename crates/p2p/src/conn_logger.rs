use std::{
    collections::{HashMap, HashSet},
    task::Poll,
};

use libp2p::{
    Multiaddr, PeerId,
    swarm::{ConnectionDenied, ConnectionId, NetworkBehaviour, THandler},
};
use tracing::{debug, instrument};

use crate::{
    behaviours::dummy_handler,
    metrics::{
        ConnectionType, P2P_METRICS, P2PMetrics, PeerConnectionLabels, Protocol,
        RelayConnectionLabels,
    },
    name::peer_name,
    utils,
};

/// Connection key for tracking connection counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConnKey {
    peer_id: PeerId,
    connection_type: ConnectionType,
    protocol: Protocol,
}

/// Existing connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ExistingConnection {
    peer_id: PeerId,
    connection_type: ConnectionType,
}

/// Connection logger behaviour.
///
/// Tracks and logs libp2p connection events. This is implemented as a
/// `NetworkBehaviour` to receive connection lifecycle events from the swarm.
#[derive(Debug)]
pub struct ConnectionLoggerBehaviour<M: ConnectionLoggerMetrics> {
    metrics: M,
    /// Connection counts by peer, type, and protocol.
    counts: HashMap<ConnKey, u64>,
    peers: HashSet<PeerId>,
    existing_connections: HashSet<ExistingConnection>,
}

/// Metrics for the connection logger behaviour.
pub trait ConnectionLoggerMetrics {
    /// Creates a new connection logger metrics.
    fn new() -> Self;
    /// Increments the total number of connections for a peer.
    fn inc_peer_connection_total(&self, peer: &PeerId);
    /// Sets the number of connections for a peer by type and protocol.
    fn set_peer_connection_type(&self, peer: &PeerId, addr: &Multiaddr, count: u64);
    /// Sets the number of connections for a relay by type and protocol.
    fn set_relay_connection_type(&self, peer: &PeerId, addr: &Multiaddr, count: u64);
}

/// Default implementation of the connection logger metrics.
pub struct DefaultConnectionLoggerMetrics;

impl ConnectionLoggerMetrics for DefaultConnectionLoggerMetrics {
    fn new() -> Self {
        Self
    }

    fn inc_peer_connection_total(&self, peer: &PeerId) {
        P2P_METRICS.peer_connection_total[&peer.to_string()].inc();
    }

    fn set_peer_connection_type(&self, peer: &PeerId, addr: &Multiaddr, count: u64) {
        P2P_METRICS.peer_connection_types[&PeerConnectionLabels::new(
            &peer.to_string(),
            utils::addr_type(addr),
            utils::addr_protocol(addr),
        )]
            .set(count);
    }

    fn set_relay_connection_type(&self, peer: &PeerId, addr: &Multiaddr, count: u64) {
        P2P_METRICS.relay_connection_types[&RelayConnectionLabels::new(
            &peer.to_string(),
            utils::addr_type(addr),
            utils::addr_protocol(addr),
        )]
            .set(count);
    }
}

/// Test implementation of the connection logger metrics.
#[derive(Debug)]
pub struct TestConnectionLoggerMetrics {
    metrics: P2PMetrics,
}

impl TestConnectionLoggerMetrics {
    /// Returns the inner metrics for testing.
    #[cfg(test)]
    pub fn inner(&self) -> &P2PMetrics {
        &self.metrics
    }
}

impl ConnectionLoggerMetrics for TestConnectionLoggerMetrics {
    fn new() -> Self {
        Self {
            metrics: P2PMetrics::default(),
        }
    }

    fn inc_peer_connection_total(&self, peer: &PeerId) {
        self.metrics.peer_connection_total[&peer.to_string()].inc();
    }

    fn set_peer_connection_type(&self, peer: &PeerId, addr: &Multiaddr, count: u64) {
        self.metrics.peer_connection_types[&PeerConnectionLabels::new(
            &peer.to_string(),
            utils::addr_type(addr),
            utils::addr_protocol(addr),
        )]
            .set(count);
    }

    fn set_relay_connection_type(&self, peer: &PeerId, addr: &Multiaddr, count: u64) {
        self.metrics.relay_connection_types[&RelayConnectionLabels::new(
            &peer.to_string(),
            utils::addr_type(addr),
            utils::addr_protocol(addr),
        )]
            .set(count);
    }
}

impl<M: ConnectionLoggerMetrics> ConnectionLoggerBehaviour<M> {
    /// Creates a new connection logger behaviour.
    pub fn new(peers: impl IntoIterator<Item = PeerId>) -> Self {
        Self {
            metrics: M::new(),
            counts: HashMap::new(),
            peers: peers.into_iter().collect(),
            existing_connections: HashSet::new(),
        }
    }

    /// Increments the connection count for the given peer and address.
    fn increment_connection(&mut self, peer: PeerId, addr: &Multiaddr) {
        let conn_key = ConnKey {
            peer_id: peer,
            connection_type: utils::addr_type(addr),
            protocol: utils::addr_protocol(addr),
        };

        let count = self
            .counts
            .entry(conn_key)
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);

        if self.peers.contains(&peer) {
            // Do not instrument relays.
            self.metrics.inc_peer_connection_total(&peer);
            self.metrics.set_peer_connection_type(&peer, addr, *count);
        } else {
            self.metrics.set_relay_connection_type(&peer, addr, *count);
        }

        if *count == 1 {
            self.existing_connections.insert(ExistingConnection {
                peer_id: peer,
                connection_type: utils::addr_type(addr),
            });
        }
    }

    /// Decrements the connection count for the given peer and address.
    fn decrement_connection(&mut self, peer: PeerId, addr: &Multiaddr) {
        let conn_key = ConnKey {
            peer_id: peer,
            connection_type: utils::addr_type(addr),
            protocol: utils::addr_protocol(addr),
        };
        if let Some(count) = self.counts.get_mut(&conn_key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.counts.remove(&conn_key);
                self.existing_connections.remove(&ExistingConnection {
                    peer_id: peer,
                    connection_type: utils::addr_type(addr),
                });
                self.metrics.set_peer_connection_type(&peer, addr, 0);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn counts(&self) -> &HashMap<ConnKey, u64> {
        &self.counts
    }

    #[cfg(test)]
    pub(crate) fn existing_connections(&self) -> &HashSet<ExistingConnection> {
        &self.existing_connections
    }

    #[cfg(test)]
    pub(crate) fn metrics(&self) -> &M {
        &self.metrics
    }
}

impl<M: ConnectionLoggerMetrics + 'static> NetworkBehaviour for ConnectionLoggerBehaviour<M> {
    type ConnectionHandler = dummy_handler::Handler;
    type ToSwarm = ();

    #[instrument(skip(self, _local_addr, remote_addr), fields(peer = %peer_name(&peer), addr = %remote_addr))]
    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        debug!(
            peer = %peer_name(&peer),
            addr = %remote_addr,
            conn_type = ?utils::addr_type(remote_addr),
            protocol = ?utils::addr_protocol(remote_addr),
            "inbound connection established"
        );
        self.increment_connection(peer, remote_addr);
        Ok(dummy_handler::Handler)
    }

    #[instrument(skip(self, _role_override, _port_use), fields(peer = %peer_name(&peer), addr = %addr))]
    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        debug!(
            peer = %peer_name(&peer),
            addr = %addr,
            conn_type = ?utils::addr_type(addr),
            protocol = ?utils::addr_protocol(addr),
            "outbound connection established"
        );
        self.increment_connection(peer, addr);
        Ok(dummy_handler::Handler)
    }

    fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm) {
        match event {
            libp2p::swarm::FromSwarm::ConnectionEstablished(event) => {
                debug!(
                    peer = %peer_name(&event.peer_id),
                    endpoint = ?event.endpoint,
                    other_established = event.other_established,
                    "connection established"
                );
            }
            libp2p::swarm::FromSwarm::ConnectionClosed(event) => {
                debug!(
                    peer = %peer_name(&event.peer_id),
                    endpoint = ?event.endpoint,
                    num_established = event.remaining_established,
                    "connection closed"
                );
                // Decrement the connection count based on the endpoint address
                let addr = match &event.endpoint {
                    libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
                    libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
                };
                self.decrement_connection(event.peer_id, addr);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        _event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        // Handler emits Infallible, so this is unreachable
    }

    fn poll(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<libp2p::swarm::ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>>
    {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{
        PeerId,
        core::{ConnectedPoint, Endpoint, transport::PortUse},
        swarm::{ConnectionId, FromSwarm, NetworkBehaviour, behaviour::ConnectionClosed},
    };

    fn tcp_direct_addr() -> Multiaddr {
        "/ip4/127.0.0.1/tcp/9000".parse().unwrap()
    }

    fn quic_direct_addr() -> Multiaddr {
        "/ip4/127.0.0.1/udp/9000/quic-v1".parse().unwrap()
    }

    fn tcp_relay_addr() -> Multiaddr {
        "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit"
            .parse()
            .unwrap()
    }

    fn quic_relay_addr() -> Multiaddr {
        "/ip4/127.0.0.1/udp/9000/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit"
            .parse()
            .unwrap()
    }

    fn random_peer_id() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_is_relay_addr() {
        assert!(!utils::is_relay_addr(&tcp_direct_addr()));
        assert!(!utils::is_relay_addr(&quic_direct_addr()));
        assert!(utils::is_relay_addr(&tcp_relay_addr()));
        assert!(utils::is_relay_addr(&quic_relay_addr()));
    }

    #[test]
    fn test_is_quic_addr() {
        assert!(!utils::is_quic_addr(&tcp_direct_addr()));
        assert!(utils::is_quic_addr(&quic_direct_addr()));
        assert!(!utils::is_quic_addr(&tcp_relay_addr()));
        assert!(utils::is_quic_addr(&quic_relay_addr()));
    }

    #[test]
    fn test_addr_type() {
        assert_eq!(utils::addr_type(&tcp_direct_addr()), ConnectionType::Direct);
        assert_eq!(
            utils::addr_type(&quic_direct_addr()),
            ConnectionType::Direct
        );
        assert_eq!(utils::addr_type(&tcp_relay_addr()), ConnectionType::Relay);
        assert_eq!(utils::addr_type(&quic_relay_addr()), ConnectionType::Relay);
    }

    #[test]
    fn test_addr_protocol() {
        assert_eq!(utils::addr_protocol(&tcp_direct_addr()), Protocol::Tcp);
        assert_eq!(utils::addr_protocol(&quic_direct_addr()), Protocol::Quic);
        assert_eq!(utils::addr_protocol(&tcp_relay_addr()), Protocol::Tcp);
        assert_eq!(utils::addr_protocol(&quic_relay_addr()), Protocol::Quic);
    }

    #[test]
    fn test_new_behaviour() {
        let peer1 = random_peer_id();
        let peer2 = random_peer_id();

        let behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer1, peer2]);

        assert!(behaviour.counts().is_empty());
        assert!(behaviour.existing_connections().is_empty());
        assert!(behaviour.peers.contains(&peer1));
        assert!(behaviour.peers.contains(&peer2));
    }

    #[test]
    fn test_increment_connection_for_known_peer() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        let addr = tcp_direct_addr();
        behaviour.increment_connection(peer, &addr);

        assert_eq!(behaviour.counts().len(), 1);
        let key = ConnKey {
            peer_id: peer,
            connection_type: ConnectionType::Direct,
            protocol: Protocol::Tcp,
        };
        assert_eq!(behaviour.counts().get(&key), Some(&1));
        assert!(
            behaviour
                .existing_connections()
                .contains(&ExistingConnection {
                    peer_id: peer,
                    connection_type: ConnectionType::Direct,
                })
        );
    }

    #[test]
    fn test_increment_connection_multiple_times() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        let addr = tcp_direct_addr();
        behaviour.increment_connection(peer, &addr);
        behaviour.increment_connection(peer, &addr);
        behaviour.increment_connection(peer, &addr);

        let key = ConnKey {
            peer_id: peer,
            connection_type: ConnectionType::Direct,
            protocol: Protocol::Tcp,
        };
        assert_eq!(behaviour.counts().get(&key), Some(&3));
        // existing_connections should still only have one entry
        assert_eq!(behaviour.existing_connections().len(), 1);
    }

    #[test]
    fn test_increment_connection_different_types() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        behaviour.increment_connection(peer, &tcp_direct_addr());
        behaviour.increment_connection(peer, &quic_direct_addr());
        behaviour.increment_connection(peer, &tcp_relay_addr());
        behaviour.increment_connection(peer, &quic_relay_addr());

        // counts tracks (peer, type, protocol) - 4 unique combinations
        assert_eq!(behaviour.counts().len(), 4);
        // existing_connections tracks (peer, type) - only 2 unique combinations
        // (Direct, Relay)
        assert_eq!(behaviour.existing_connections().len(), 2);
    }

    #[test]
    fn test_decrement_connection() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        let addr = tcp_direct_addr();
        behaviour.increment_connection(peer, &addr);
        behaviour.increment_connection(peer, &addr);
        behaviour.decrement_connection(peer, &addr);

        let key = ConnKey {
            peer_id: peer,
            connection_type: ConnectionType::Direct,
            protocol: Protocol::Tcp,
        };
        assert_eq!(behaviour.counts().get(&key), Some(&1));
        assert!(
            behaviour
                .existing_connections()
                .contains(&ExistingConnection {
                    peer_id: peer,
                    connection_type: ConnectionType::Direct,
                })
        );
    }

    #[test]
    fn test_decrement_connection_to_zero() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        let addr = tcp_direct_addr();
        behaviour.increment_connection(peer, &addr);
        behaviour.decrement_connection(peer, &addr);

        let key = ConnKey {
            peer_id: peer,
            connection_type: ConnectionType::Direct,
            protocol: Protocol::Tcp,
        };
        assert!(behaviour.counts().get(&key).is_none());
        assert!(behaviour.existing_connections().is_empty());
    }

    #[test]
    fn test_decrement_nonexistent_connection() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        // Decrementing a connection that doesn't exist should be a no-op
        behaviour.decrement_connection(peer, &tcp_direct_addr());

        assert!(behaviour.counts().is_empty());
        assert!(behaviour.existing_connections().is_empty());
    }

    #[test]
    fn test_metrics_for_known_peer() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        let addr = tcp_direct_addr();
        behaviour.increment_connection(peer, &addr);

        // Check peer_connection_total was incremented
        let total = behaviour.metrics().inner().peer_connection_total[&peer.to_string()].get();
        assert_eq!(total, 1);

        // Check peer_connection_types was set
        let labels =
            PeerConnectionLabels::new(&peer.to_string(), ConnectionType::Direct, Protocol::Tcp);
        let count = behaviour.metrics().inner().peer_connection_types[&labels].get();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_metrics_for_unknown_peer_uses_relay_metrics() {
        let known_peer = random_peer_id();
        let unknown_peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([known_peer]);

        let addr = tcp_direct_addr();
        behaviour.increment_connection(unknown_peer, &addr);

        // Check relay_connection_types was set (not peer_connection_types)
        let labels = RelayConnectionLabels::new(
            &unknown_peer.to_string(),
            ConnectionType::Direct,
            Protocol::Tcp,
        );
        let count = behaviour.metrics().inner().relay_connection_types[&labels].get();
        assert_eq!(count, 1);

        // peer_connection_total should not have been incremented for unknown peer
        let total =
            behaviour.metrics().inner().peer_connection_total[&unknown_peer.to_string()].get();
        assert_eq!(total, 0);
    }

    #[test]
    fn test_metrics_decrement_to_zero_sets_gauge() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        let addr = tcp_direct_addr();
        behaviour.increment_connection(peer, &addr);
        behaviour.decrement_connection(peer, &addr);

        // After decrementing to zero, the gauge should be set to 0
        let labels =
            PeerConnectionLabels::new(&peer.to_string(), ConnectionType::Direct, Protocol::Tcp);
        let count = behaviour.metrics().inner().peer_connection_types[&labels].get();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_conn_key_equality() {
        let peer = random_peer_id();
        let key1 = ConnKey {
            peer_id: peer,
            connection_type: ConnectionType::Direct,
            protocol: Protocol::Tcp,
        };
        let key2 = ConnKey {
            peer_id: peer,
            connection_type: ConnectionType::Direct,
            protocol: Protocol::Tcp,
        };
        let key3 = ConnKey {
            peer_id: peer,
            connection_type: ConnectionType::Relay,
            protocol: Protocol::Tcp,
        };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_existing_connection_equality() {
        let peer = random_peer_id();
        let conn1 = ExistingConnection {
            peer_id: peer,
            connection_type: ConnectionType::Direct,
        };
        let conn2 = ExistingConnection {
            peer_id: peer,
            connection_type: ConnectionType::Direct,
        };
        let conn3 = ExistingConnection {
            peer_id: peer,
            connection_type: ConnectionType::Relay,
        };

        assert_eq!(conn1, conn2);
        assert_ne!(conn1, conn3);
    }

    // =========================================================================
    // E2E NetworkBehaviour tests
    // =========================================================================

    fn local_addr() -> Multiaddr {
        "/ip4/127.0.0.1/tcp/9001".parse().unwrap()
    }

    #[test]
    fn test_handle_established_inbound_connection() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        let connection_id = ConnectionId::new_unchecked(1);
        let local_addr = local_addr();
        let remote_addr = tcp_direct_addr();

        let result = behaviour.handle_established_inbound_connection(
            connection_id,
            peer,
            &local_addr,
            &remote_addr,
        );

        assert!(result.is_ok());
        assert_eq!(behaviour.counts().len(), 1);

        let key = ConnKey {
            peer_id: peer,
            connection_type: ConnectionType::Direct,
            protocol: Protocol::Tcp,
        };
        assert_eq!(behaviour.counts().get(&key), Some(&1));

        // Verify metrics were updated
        let total = behaviour.metrics().inner().peer_connection_total[&peer.to_string()].get();
        assert_eq!(total, 1);
    }

    #[test]
    fn test_handle_established_outbound_connection() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        let connection_id = ConnectionId::new_unchecked(1);
        let addr = quic_direct_addr();

        let result = behaviour.handle_established_outbound_connection(
            connection_id,
            peer,
            &addr,
            Endpoint::Dialer,
            PortUse::New,
        );

        assert!(result.is_ok());
        assert_eq!(behaviour.counts().len(), 1);

        let key = ConnKey {
            peer_id: peer,
            connection_type: ConnectionType::Direct,
            protocol: Protocol::Quic,
        };
        assert_eq!(behaviour.counts().get(&key), Some(&1));

        // Verify metrics were updated
        let total = behaviour.metrics().inner().peer_connection_total[&peer.to_string()].get();
        assert_eq!(total, 1);
    }

    #[test]
    fn test_handle_established_inbound_connection_relay() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        let connection_id = ConnectionId::new_unchecked(1);
        let local_addr = local_addr();
        let remote_addr = tcp_relay_addr();

        let result = behaviour.handle_established_inbound_connection(
            connection_id,
            peer,
            &local_addr,
            &remote_addr,
        );

        assert!(result.is_ok());

        let key = ConnKey {
            peer_id: peer,
            connection_type: ConnectionType::Relay,
            protocol: Protocol::Tcp,
        };
        assert_eq!(behaviour.counts().get(&key), Some(&1));
    }

    #[test]
    fn test_on_swarm_event_connection_closed_dialer() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        let addr = tcp_direct_addr();

        // First establish a connection
        behaviour.increment_connection(peer, &addr);
        assert_eq!(behaviour.counts().len(), 1);

        // Now simulate connection closed via swarm event
        let endpoint = ConnectedPoint::Dialer {
            address: addr.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };

        let event = FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer,
            connection_id: ConnectionId::new_unchecked(1),
            endpoint: &endpoint,
            remaining_established: 0,
            cause: None,
        });

        behaviour.on_swarm_event(event);

        // Connection should be removed
        assert!(behaviour.counts().is_empty());
        assert!(behaviour.existing_connections().is_empty());
    }

    #[test]
    fn test_on_swarm_event_connection_closed_listener() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        let remote_addr = tcp_direct_addr();
        let local_addr = local_addr();

        // First establish a connection
        behaviour.increment_connection(peer, &remote_addr);
        assert_eq!(behaviour.counts().len(), 1);

        // Now simulate connection closed via swarm event (listener side)
        let endpoint = ConnectedPoint::Listener {
            local_addr: local_addr.clone(),
            send_back_addr: remote_addr.clone(),
        };

        let event = FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer,
            connection_id: ConnectionId::new_unchecked(1),
            endpoint: &endpoint,
            remaining_established: 0,
            cause: None,
        });

        behaviour.on_swarm_event(event);

        // Connection should be removed
        assert!(behaviour.counts().is_empty());
        assert!(behaviour.existing_connections().is_empty());
    }

    #[test]
    fn test_full_connection_lifecycle() {
        let peer = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer]);

        let addr = quic_direct_addr();
        let connection_id = ConnectionId::new_unchecked(1);

        // Step 1: Establish outbound connection
        let result = behaviour.handle_established_outbound_connection(
            connection_id,
            peer,
            &addr,
            Endpoint::Dialer,
            PortUse::New,
        );
        assert!(result.is_ok());

        let key = ConnKey {
            peer_id: peer,
            connection_type: ConnectionType::Direct,
            protocol: Protocol::Quic,
        };
        assert_eq!(behaviour.counts().get(&key), Some(&1));
        assert_eq!(behaviour.existing_connections().len(), 1);

        // Step 2: Establish another connection (same type)
        let connection_id2 = ConnectionId::new_unchecked(2);
        let _ = behaviour.handle_established_outbound_connection(
            connection_id2,
            peer,
            &addr,
            Endpoint::Dialer,
            PortUse::New,
        );
        assert_eq!(behaviour.counts().get(&key), Some(&2));
        assert_eq!(behaviour.existing_connections().len(), 1); // Still 1, same type

        // Step 3: Close one connection
        let endpoint = ConnectedPoint::Dialer {
            address: addr.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };
        let close_event = FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer,
            connection_id,
            endpoint: &endpoint,
            remaining_established: 1,
            cause: None,
        });
        behaviour.on_swarm_event(close_event);

        assert_eq!(behaviour.counts().get(&key), Some(&1));
        assert_eq!(behaviour.existing_connections().len(), 1);

        // Step 4: Close the last connection
        let close_event2 = FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer,
            connection_id: connection_id2,
            endpoint: &endpoint,
            remaining_established: 0,
            cause: None,
        });
        behaviour.on_swarm_event(close_event2);

        assert!(behaviour.counts().is_empty());
        assert!(behaviour.existing_connections().is_empty());
    }

    #[test]
    fn test_multiple_peers_connection_lifecycle() {
        let peer1 = random_peer_id();
        let peer2 = random_peer_id();
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([peer1, peer2]);

        let tcp_addr = tcp_direct_addr();
        let quic_addr = quic_direct_addr();

        // Establish connections for peer1 (TCP) and peer2 (QUIC)
        let _ = behaviour.handle_established_inbound_connection(
            ConnectionId::new_unchecked(1),
            peer1,
            &local_addr(),
            &tcp_addr,
        );
        let _ = behaviour.handle_established_outbound_connection(
            ConnectionId::new_unchecked(2),
            peer2,
            &quic_addr,
            Endpoint::Dialer,
            PortUse::New,
        );

        assert_eq!(behaviour.counts().len(), 2);
        assert_eq!(behaviour.existing_connections().len(), 2);

        // Close peer1's connection
        let endpoint1 = ConnectedPoint::Listener {
            local_addr: local_addr(),
            send_back_addr: tcp_addr.clone(),
        };
        behaviour.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer1,
            connection_id: ConnectionId::new_unchecked(1),
            endpoint: &endpoint1,
            remaining_established: 0,
            cause: None,
        }));

        // peer1's connection should be gone, peer2's should remain
        assert_eq!(behaviour.counts().len(), 1);
        let key2 = ConnKey {
            peer_id: peer2,
            connection_type: ConnectionType::Direct,
            protocol: Protocol::Quic,
        };
        assert_eq!(behaviour.counts().get(&key2), Some(&1));
    }

    #[test]
    fn test_relay_vs_known_peer_metrics() {
        let known_peer = random_peer_id();
        let relay_peer = random_peer_id(); // Not in the known peers list
        let mut behaviour: ConnectionLoggerBehaviour<TestConnectionLoggerMetrics> =
            ConnectionLoggerBehaviour::new([known_peer]);

        let addr = tcp_direct_addr();

        // Establish connection for known peer
        let _ = behaviour.handle_established_inbound_connection(
            ConnectionId::new_unchecked(1),
            known_peer,
            &local_addr(),
            &addr,
        );

        // Establish connection for relay/unknown peer
        let _ = behaviour.handle_established_inbound_connection(
            ConnectionId::new_unchecked(2),
            relay_peer,
            &local_addr(),
            &addr,
        );

        // Both should be tracked
        assert_eq!(behaviour.counts().len(), 2);

        // Known peer should have peer_connection_total incremented
        let known_total =
            behaviour.metrics().inner().peer_connection_total[&known_peer.to_string()].get();
        assert_eq!(known_total, 1);

        // Relay peer should NOT have peer_connection_total incremented
        let relay_total =
            behaviour.metrics().inner().peer_connection_total[&relay_peer.to_string()].get();
        assert_eq!(relay_total, 0);

        // But relay_connection_types should be set
        let relay_labels = RelayConnectionLabels::new(
            &relay_peer.to_string(),
            ConnectionType::Direct,
            Protocol::Tcp,
        );
        let relay_count = behaviour.metrics().inner().relay_connection_types[&relay_labels].get();
        assert_eq!(relay_count, 1);
    }
}
