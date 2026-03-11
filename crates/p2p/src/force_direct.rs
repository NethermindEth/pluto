//! Force direct connection behaviour.

use std::{
    collections::{HashSet, VecDeque},
    convert::Infallible,
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, ToSwarm,
        behaviour::ConnectionEstablished,
        dial_opts::{DialOpts, PeerCondition},
        dummy,
    },
};
use std::time::Duration;
use tokio::time::Interval;
use tracing::{debug, warn};

use crate::{name::peer_name, p2p_context::P2PContext, utils};

const FORCE_DIRECT_INTERVAL: Duration = Duration::from_secs(60);

/// Force direct connection behaviour.
pub struct ForceDirectBehaviour {
    /// P2P context for accessing peer store and known peers.
    p2p_context: P2PContext,

    /// Local peer ID (to skip self).
    local_peer_id: PeerId,

    /// Pending events to emit.
    pending_events: VecDeque<ToSwarm<ForceDirectEvent, Infallible>>,

    /// Pending forcings to emit.
    pending_forcings: HashSet<PeerId>,

    /// Interval timer for running force direct logic periodically.
    ticker: Interval,
}

impl std::fmt::Debug for ForceDirectBehaviour {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForceDirectBehaviour")
            .field("p2p_context", &self.p2p_context)
            .field("local_peer_id", &self.local_peer_id)
            .field("pending_events", &self.pending_events.len())
            .field("ticker", &"<Interval>")
            .finish()
    }
}

/// Events emitted by the force direct behaviour.
#[derive(Debug, Clone)]
pub enum ForceDirectEvent {
    /// Force direct connection to a peer.
    ForceDirectSuccess {
        /// The peer to force direct connection to.
        peer: PeerId,
    },
    /// Force direct connection failed.
    ForceDirectFailure {
        /// The peer to force direct connection to.
        peer: PeerId,
        /// The reason for the failure.
        reason: String,
    },
}

impl ForceDirectBehaviour {
    /// Creates a new force direct behaviour.
    pub fn new(p2p_context: P2PContext, local_peer_id: PeerId) -> Self {
        let mut ticker = tokio::time::interval(FORCE_DIRECT_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        Self {
            p2p_context,
            local_peer_id,
            pending_events: VecDeque::new(),
            ticker,
            pending_forcings: HashSet::new(),
        }
    }

    /// Runs force direct connection logic for all known peers.
    ///
    /// For each known peer:
    /// 1. Skip if it's the local peer
    /// 2. Skip if already attempting to force direct connection
    /// 3. Skip if no connections exist
    /// 4. Skip if any connection is not through relay
    /// 5. Attempt to dial direct addresses
    fn force_direct_connections(&mut self) {
        let peers = self.p2p_context.known_peers();

        for peer in peers {
            if *peer == self.local_peer_id {
                continue;
            }

            if self.pending_forcings.contains(peer) {
                continue;
            }

            let (connections, available_addresses): (
                Vec<crate::p2p_context::Peer>,
                Option<Vec<Multiaddr>>,
            ) = {
                let lock = self.p2p_context.peer_store_lock();

                (
                    lock.connections_to_peer(peer)
                        .into_iter()
                        .cloned()
                        .collect::<Vec<_>>(),
                    lock.peer_addresses(peer)
                        .cloned()
                        .map(|v| v.into_iter().collect()),
                )
            };

            if connections.is_empty() {
                warn!(
                    peer = %peer_name(peer),
                    "no connections to peer"
                );
                continue;
            }

            if connections
                .iter()
                .any(|c| !utils::is_relay_addr(&c.remote_addr))
            {
                debug!(
                    peer = %peer_name(peer),
                    "not all connections to peer are relay connections, skipping force direct"
                );
                continue;
            }

            let Some(addresses) = available_addresses else {
                warn!(
                    peer = %peer_name(peer),
                    "no known addresses for peer"
                );
                continue;
            };

            // Find non-relay addresses
            let direct_addresses: Vec<Multiaddr> = addresses
                .iter()
                .filter(|addr| utils::is_direct_addr(addr))
                .cloned()
                .collect();

            if direct_addresses.is_empty() {
                warn!(
                    peer = %peer_name(peer),
                    "no direct addresses for peer, cannot force direct connection"
                );
                continue;
            }

            debug!(
                peer = %peer_name(peer),
                direct_addresses = ?direct_addresses,
                "forcing direct connection to peer using {} available addresses",
                direct_addresses.len()
            );

            self.pending_forcings.insert(*peer);

            self.pending_events.push_back(ToSwarm::Dial {
                opts: DialOpts::peer_id(*peer)
                    .addresses(direct_addresses)
                    .condition(PeerCondition::Always)
                    .build(),
            });
        }
    }

    fn handle_connection_established(&mut self, event: ConnectionEstablished) {
        let addr = match &event.endpoint {
            libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
            libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
        };

        if self.pending_forcings.contains(&event.peer_id) && utils::is_direct_addr(addr) {
            self.pending_forcings.remove(&event.peer_id);
            self.pending_events.push_back(ToSwarm::GenerateEvent(
                ForceDirectEvent::ForceDirectSuccess {
                    peer: event.peer_id,
                },
            ));
        }
    }

    fn handle_dial_failure(&mut self, peer_id: Option<PeerId>) {
        let Some(peer_id) = peer_id else {
            return;
        };

        if self.pending_forcings.remove(&peer_id) {
            self.pending_events.push_back(ToSwarm::GenerateEvent(
                ForceDirectEvent::ForceDirectFailure {
                    peer: peer_id,
                    reason: "dial failed".to_string(),
                },
            ));
        }
    }
}

impl NetworkBehaviour for ForceDirectBehaviour {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = ForceDirectEvent;

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
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(event) => {
                self.handle_connection_established(event);
            }
            FromSwarm::DialFailure(event) => {
                self.handle_dial_failure(event.peer_id);
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
        cx: &mut Context<'_>,
    ) -> std::task::Poll<ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event);
        }

        if self.ticker.poll_tick(cx).is_ready() {
            self.force_direct_connections();

            if let Some(event) = self.pending_events.pop_front() {
                return Poll::Ready(event);
            }
        }

        Poll::Pending
    }
}
