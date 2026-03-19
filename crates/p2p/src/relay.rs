//! Relay reservation functionality and relay router.
//!
//! This behaviour is responsible for resolving relays that are being passed by
//! a mutable peer.
//!
//! Mutable peer is used for updating the relay addresses in the background by
//! fetching the enr servers.
//!
//! Relay router is responsible for routing *all* known peers through the
//! relays, even if they are not directly connected to the node.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use crate::{
    p2p_context::P2PContext,
    peer::{MutablePeer, Peer},
    utils,
};
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    multiaddr::Protocol as MaProtocol,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        ToSwarm, dial_opts::DialOpts, dummy,
    },
};
use tokio::time::{Instant, Interval};

const RELAY_ROUTER_INTERVAL: Duration = Duration::from_secs(60);
const RELAY_ROUTER_INITIAL_DELAY: Duration = Duration::from_secs(10);

/// Mutable relay reservation behaviour.
///
/// This behaviour manages relay reservations by:
/// 1. Dialing relay servers
/// 2. Waiting for connections to establish
/// 3. Creating relay circuit listeners once connected
/// 4. Subscribing to relay peer updates to handle dynamic address resolution
pub struct MutableRelayReservation {
    /// Events to emit to the swarm
    events: VecDeque<ToSwarm<Infallible, Infallible>>,
    /// Relay peers we're waiting to connect to
    pending_relays: HashSet<PeerId>,
    /// Circuit addresses to listen on once relay connections are established
    pending_circuit_addrs: HashMap<PeerId, Vec<Multiaddr>>,
    /// Shared queue for events from subscription callbacks
    subscription_events: Arc<Mutex<VecDeque<Peer>>>,
}

impl MutableRelayReservation {
    /// Creates a new mutable relay reservation.
    ///
    /// This behaviour dials relays and waits for connections to establish
    /// before creating circuit listeners, allowing other peers to reach
    /// this node through the relays.
    ///
    /// Subscribes to each relay peer for dynamic address resolution.
    pub fn new(mutable_peers: Vec<MutablePeer>) -> Self {
        let mut events = VecDeque::new();
        let mut pending_relays = HashSet::new();
        let mut pending_circuit_addrs = HashMap::new();
        let subscription_events = Arc::new(Mutex::new(VecDeque::new()));

        // Subscribe to relay peer updates and process initial peers
        for mutable_peer in &mutable_peers {
            // Set up subscription for this relay peer
            let sub_events = Arc::clone(&subscription_events);
            let subscription = Box::new(move |peer: &Peer| {
                if let Ok(mut queue) = sub_events.lock() {
                    queue.push_back(peer.clone());
                }
            });

            if let Err(e) = mutable_peer.subscribe(subscription) {
                tracing::warn!(err = %e, "Failed to subscribe to relay peer updates");
            }

            // Process peer if already available
            if let Ok(Some(peer)) = mutable_peer.peer() {
                Self::queue_relay_dial(
                    &mut events,
                    &mut pending_relays,
                    &mut pending_circuit_addrs,
                    &peer,
                );
            }
        }

        Self {
            events,
            pending_relays,
            pending_circuit_addrs,
            subscription_events,
        }
    }

    /// Queues dial events for a relay peer.
    fn queue_relay_dial(
        events: &mut VecDeque<ToSwarm<Infallible, Infallible>>,
        pending_relays: &mut HashSet<PeerId>,
        pending_circuit_addrs: &mut HashMap<PeerId, Vec<Multiaddr>>,
        peer: &Peer,
    ) {
        pending_relays.insert(peer.id);

        // Build circuit addresses for this relay
        let mut circuit_addrs = Vec::new();
        for addr in &peer.addresses {
            let mut relay_addr = addr.clone();
            relay_addr.push(MaProtocol::P2p(peer.id));
            relay_addr.push(MaProtocol::P2pCircuit);
            circuit_addrs.push(relay_addr);
        }
        pending_circuit_addrs.insert(peer.id, circuit_addrs);

        // Dial the relay server (required before listening on circuit)
        for addr in &peer.addresses {
            let mut relay_addr = addr.clone();
            relay_addr.push(MaProtocol::P2p(peer.id));
            // Do NOT add P2pCircuit here - we're dialing the relay server directly
            events.push_back(ToSwarm::Dial {
                opts: DialOpts::unknown_peer_id().address(relay_addr).build(),
            });
        }

        tracing::debug!(
            relay_peer_id = %peer.id,
            "Queued relay dial, will listen on circuit after connection establishes"
        );
    }

    /// Processes pending subscription events.
    fn process_subscription_events(&mut self) {
        tracing::debug!("Processing subscription events");
        let peers = {
            let Ok(mut queue) = self.subscription_events.lock() else {
                tracing::warn!("Failed to lock subscription events queue");
                return;
            };
            queue.drain(..).collect::<Vec<_>>()
        };

        for peer in peers {
            tracing::info!(
                relay_peer_id = %peer.id,
                "Relay peer updated via subscription, queuing dial"
            );
            Self::queue_relay_dial(
                &mut self.events,
                &mut self.pending_relays,
                &mut self.pending_circuit_addrs,
                &peer,
            );
        }
    }
}

impl NetworkBehaviour for MutableRelayReservation {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        // Listen for relay connection establishment
        if let FromSwarm::ConnectionEstablished(conn) = event {
            // Check if this is a relay we're waiting for
            if self.pending_relays.remove(&conn.peer_id) {
                tracing::info!(
                    relay_peer_id = %conn.peer_id,
                    "Relay connection established, listening on circuit addresses"
                );

                // Queue ListenOn events for this relay's circuit addresses
                if let Some(circuit_addrs) = self.pending_circuit_addrs.remove(&conn.peer_id) {
                    for circuit_addr in circuit_addrs {
                        self.events.push_back(ToSwarm::ListenOn {
                            opts: libp2p::swarm::ListenOpts::new(circuit_addr),
                        });
                    }
                }
            }
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: libp2p::PeerId,
        _connection_id: libp2p::swarm::ConnectionId,
        _event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        // No special handling needed for connection handler events
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // Process any pending subscription updates first
        self.process_subscription_events();

        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }
        Poll::Pending
    }
}

/// Relay router behaviour.
///
/// Continuously advertises relay circuit addresses for known peers.
/// Polls relay peers periodically to detect address updates.
pub struct RelayRouter {
    relays: Vec<MutablePeer>,
    p2p_context: P2PContext,
    events: VecDeque<ToSwarm<Infallible, Infallible>>,
    interval: Interval,
    local_peer_id: PeerId,
}

impl RelayRouter {
    /// Creates a new relay router.
    pub fn new(relays: Vec<MutablePeer>, p2p_context: P2PContext, local_peer_id: PeerId) -> Self {
        let mut interval = tokio::time::interval_at(
            Instant::now() + RELAY_ROUTER_INITIAL_DELAY,
            RELAY_ROUTER_INTERVAL,
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        Self {
            relays,
            p2p_context,
            events: VecDeque::new(),
            interval,
            local_peer_id,
        }
    }

    fn run_relay_router(&mut self) {
        tracing::debug!("Running relay router");
        let peers = self.p2p_context.known_peers();
        for target_peer_id in peers {
            if *target_peer_id == self.local_peer_id {
                continue;
            }

            for mutable in &self.relays {
                let Ok(Some(relay_peer)) = mutable.peer() else {
                    continue;
                };

                let relay_addrs = utils::multi_addrs_via_relay(&relay_peer, target_peer_id);

                self.events.push_back(ToSwarm::Dial {
                    opts: DialOpts::peer_id(*target_peer_id)
                        .addresses(relay_addrs)
                        .build(),
                });
            }
        }
    }
}

impl NetworkBehaviour for RelayRouter {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {
        // No special handling needed for swarm events
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        _event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        // No special handling needed for connection handler events
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }
        if self.interval.poll_tick(cx).is_ready() {
            self.run_relay_router();
        }
        Poll::Pending
    }
}
