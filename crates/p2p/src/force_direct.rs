//! Force direct connection behaviour.

use std::{
    collections::{HashMap, VecDeque},
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

    /// Peers with a force-direct dial in flight, and the direct addresses it
    /// was given.
    pending_forcings: HashMap<PeerId, Vec<Multiaddr>>,

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
        /// The direct addresses the failed dial was given.
        addresses: Vec<Multiaddr>,
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
            pending_forcings: HashMap::new(),
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

            if self.pending_forcings.contains_key(peer) {
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

            self.pending_forcings
                .insert(*peer, direct_addresses.clone());

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

        if self.pending_forcings.contains_key(&event.peer_id) && utils::is_direct_addr(addr) {
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

        if let Some(addresses) = self.pending_forcings.remove(&peer_id) {
            self.pending_events.push_back(ToSwarm::GenerateEvent(
                ForceDirectEvent::ForceDirectFailure {
                    peer: peer_id,
                    addresses,
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

#[cfg(test)]
mod tests {
    use libp2p::swarm::ConnectionId;

    use super::*;
    use crate::p2p_context::Peer;

    const RELAY_ID: &str = "16Uiu2HAkzdQ5Y9SYT91K1ue5SxXwgmajXntfScGnLYeip5hHyWmT";

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn relayed(transport: &str) -> Multiaddr {
        addr(&format!("{transport}/p2p/{RELAY_ID}/p2p-circuit"))
    }

    fn conn(id: PeerId, n: usize, remote_addr: Multiaddr) -> Peer {
        Peer {
            id,
            connection_id: ConnectionId::new_unchecked(n),
            remote_addr,
        }
    }

    fn behaviour(local: PeerId, peers: impl IntoIterator<Item = PeerId>) -> ForceDirectBehaviour {
        let known: Vec<PeerId> = peers.into_iter().chain(std::iter::once(local)).collect();

        ForceDirectBehaviour::new(P2PContext::new(known), local)
    }

    /// Seeds `conns` and, when `addresses` is `Some`, the identify-reported
    /// addresses for `peer`.
    fn seed_store(
        behaviour: &ForceDirectBehaviour,
        peer: PeerId,
        conns: Vec<Peer>,
        addresses: Option<Vec<Multiaddr>>,
    ) {
        // Scoped so the write lock is released before the logic under test
        // takes its read lock.
        let mut store = behaviour.p2p_context.peer_store_write_lock();
        for conn in conns {
            store.add_peer(conn);
        }
        if let Some(addresses) = addresses {
            store.set_peer_addresses(peer, addresses);
        }
    }

    /// The peers the queued events dial.
    fn dialled(behaviour: &ForceDirectBehaviour) -> Vec<PeerId> {
        behaviour
            .pending_events
            .iter()
            .filter_map(|event| match event {
                ToSwarm::Dial { opts } => opts.get_peer_id(),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn forces_direct_when_every_connection_is_relayed() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let behaviour = &mut behaviour(local, [peer]);
        seed_store(
            behaviour,
            peer,
            vec![conn(peer, 1, relayed("/ip4/1.2.3.4/tcp/3610"))],
            // Of the two known addresses only the direct one is dialable.
            Some(vec![
                relayed("/ip4/1.2.3.4/tcp/3610"),
                addr("/ip4/5.6.7.8/tcp/3610"),
            ]),
        );

        behaviour.force_direct_connections();

        assert_eq!(dialled(behaviour), vec![peer]);
        // The relayed address is filtered out of the dial: forcing a direct
        // connection through the relay would be a no-op.
        assert_eq!(
            behaviour.pending_forcings.get(&peer),
            Some(&vec![addr("/ip4/5.6.7.8/tcp/3610")])
        );
    }

    #[tokio::test]
    async fn skips_the_local_peer() {
        let local = PeerId::random();
        let behaviour = &mut behaviour(local, []);
        seed_store(
            behaviour,
            local,
            vec![conn(local, 1, relayed("/ip4/1.2.3.4/tcp/3610"))],
            Some(vec![addr("/ip4/5.6.7.8/tcp/3610")]),
        );

        behaviour.force_direct_connections();

        assert!(dialled(behaviour).is_empty());
        assert!(behaviour.pending_forcings.is_empty());
    }

    #[tokio::test]
    async fn skips_a_peer_already_being_forced() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let behaviour = &mut behaviour(local, [peer]);
        seed_store(
            behaviour,
            peer,
            vec![conn(peer, 1, relayed("/ip4/1.2.3.4/tcp/3610"))],
            Some(vec![addr("/ip4/5.6.7.8/tcp/3610")]),
        );

        behaviour.pending_forcings.insert(peer, vec![]);

        behaviour.force_direct_connections();

        assert!(dialled(behaviour).is_empty());
    }

    #[tokio::test]
    async fn skips_a_peer_without_connections() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let behaviour = &mut behaviour(local, [peer]);
        // Addresses are known, but there is no relayed connection to replace.
        seed_store(
            behaviour,
            peer,
            vec![],
            Some(vec![addr("/ip4/5.6.7.8/tcp/3610")]),
        );

        behaviour.force_direct_connections();

        assert!(dialled(behaviour).is_empty());
        assert!(behaviour.pending_forcings.is_empty());
    }

    #[tokio::test]
    async fn skips_a_peer_that_already_has_one_direct_connection() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let behaviour = &mut behaviour(local, [peer]);
        // The all-relay guard: one direct connection is enough to leave it alone.
        seed_store(
            behaviour,
            peer,
            vec![
                conn(peer, 1, relayed("/ip4/1.2.3.4/tcp/3610")),
                conn(peer, 2, addr("/ip4/5.6.7.8/tcp/3610")),
            ],
            Some(vec![addr("/ip4/5.6.7.8/tcp/3610")]),
        );

        behaviour.force_direct_connections();

        assert!(dialled(behaviour).is_empty());
        assert!(behaviour.pending_forcings.is_empty());
    }

    #[tokio::test]
    async fn skips_a_peer_without_known_addresses() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let behaviour = &mut behaviour(local, [peer]);
        // Identify has not reported an address yet, so there is nothing to dial.
        seed_store(
            behaviour,
            peer,
            vec![conn(peer, 1, relayed("/ip4/1.2.3.4/tcp/3610"))],
            None,
        );

        behaviour.force_direct_connections();

        assert!(dialled(behaviour).is_empty());
        assert!(behaviour.pending_forcings.is_empty());
    }

    #[tokio::test]
    async fn skips_a_peer_whose_known_addresses_are_all_relayed() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let behaviour = &mut behaviour(local, [peer]);
        seed_store(
            behaviour,
            peer,
            vec![conn(peer, 1, relayed("/ip4/1.2.3.4/tcp/3610"))],
            Some(vec![
                relayed("/ip4/1.2.3.4/tcp/3610"),
                relayed("/ip4/1.2.3.4/udp/3610/quic-v1"),
            ]),
        );

        behaviour.force_direct_connections();

        assert!(dialled(behaviour).is_empty());
        assert!(behaviour.pending_forcings.is_empty());
    }
}
