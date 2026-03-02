//! Relay reservation functionality.
//!
//! This behaviour is responsible for resolving relays that are being passed by
//! a mutable peer.
//!
//! Mutable peer is used for updating the relay addresses in the background by
//! fetching the enr servers.

use std::{
    collections::VecDeque,
    convert::Infallible,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use crate::{p2p_context::P2PContext, peer::MutablePeer, utils};
use futures::FutureExt;
use futures_timer::Delay;
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    multiaddr::Protocol as MaProtocol,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        ToSwarm, dial_opts::DialOpts, dummy,
    },
};

/// Mutable relay reservation behaviour.
pub struct MutableRelayReservation {
    events: Arc<Mutex<VecDeque<ToSwarm<Infallible, Infallible>>>>,
}

impl MutableRelayReservation {
    /// Creates a new mutable relay reservation.
    ///
    /// This behaviour listens on relay addresses to create reservations,
    /// allowing other peers to reach this node through the relays.
    pub fn new(mutable_peer: Vec<MutablePeer>) -> Self {
        let events = Arc::new(Mutex::new(VecDeque::new()));
        for mutable_peer in &mutable_peer {
            let events_clone = events.clone();
            // Listen on the relay to create a reservation
            {
                if let Ok(Some(peer)) = mutable_peer.peer() {
                    let mut events = events.lock().unwrap();
                    // Create relay circuit addresses: /ip4/.../tcp/.../p2p/{relay-id}/p2p-circuit
                    for addr in &peer.addresses {
                        let mut relay_addr = addr.clone();
                        relay_addr.push(MaProtocol::P2p(peer.id));
                        relay_addr.push(MaProtocol::P2pCircuit);
                        events.push_back(ToSwarm::ListenOn {
                            opts: libp2p::swarm::ListenOpts::new(relay_addr),
                        });
                    }
                }
            }
            mutable_peer
                .subscribe(Box::new(move |peer| {
                    let mut events = events_clone.lock().unwrap();
                    // Create relay circuit addresses: /ip4/.../tcp/.../p2p/{relay-id}/p2p-circuit
                    for addr in &peer.addresses {
                        let mut relay_addr = addr.clone();
                        relay_addr.push(MaProtocol::P2p(peer.id));
                        relay_addr.push(MaProtocol::P2pCircuit);
                        events.push_back(ToSwarm::ListenOn {
                            opts: libp2p::swarm::ListenOpts::new(relay_addr),
                        });
                    }
                }))
                .unwrap();
        }
        Self { events }
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

    fn on_swarm_event(&mut self, _event: FromSwarm) {
        // No special handling needed for swarm events
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
        let mut events = self.events.lock().unwrap();
        if let Some(event) = events.pop_front() {
            return Poll::Ready(event);
        }
        Poll::Pending
    }
}

const RELAY_ROUTER_INTERVAL: Duration = Duration::from_secs(10);

/// Relay router behaviour.
pub struct RelayRouter {
    relays: Vec<MutablePeer>,
    p2p_context: P2PContext,
    events: VecDeque<ToSwarm<Infallible, Infallible>>,
    interval: Delay,
    local_peer_id: PeerId,
}

impl RelayRouter {
    /// Creates a new relay router.
    pub fn new(relays: Vec<MutablePeer>, p2p_context: P2PContext, local_peer_id: PeerId) -> Self {
        Self {
            relays,
            p2p_context,
            events: VecDeque::new(),
            // We reset the interval to 0 to run the relay router immediately.
            interval: Delay::new(Duration::new(0, 0)),
            local_peer_id,
        }
    }

    fn run_relay_router(&mut self) {
        let peers = self.p2p_context.known_peers();
        for target_peer_id in peers {
            if *target_peer_id == self.local_peer_id {
                continue;
            }

            for mutable in &self.relays {
                let Ok(Some(relay_peer)) = mutable.peer() else {
                    continue;
                };

                let relay_addrs =
                    utils::multi_addrs_via_relay(&relay_peer, target_peer_id).unwrap();

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
        if self.interval.poll_unpin(cx).is_ready() {
            self.interval.reset(RELAY_ROUTER_INTERVAL);
            self.run_relay_router();
        }
        Poll::Pending
    }
}
