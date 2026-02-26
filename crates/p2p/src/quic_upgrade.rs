//! QUIC connection upgrade behaviour.

use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    task::{Context, Poll},
    time::Duration,
};

use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
        dial_opts::{DialOpts, PeerCondition},
        dummy,
    },
};
use tokio::time::Instant;
use tracing::{debug, info};

use crate::{
    name::peer_name,
    p2p_context::P2PContext,
    utils::{
        filter_direct_quic_addrs, has_direct_quic_conn, has_direct_tcp_conn, is_quic_addr,
        is_relay_addr, is_tcp_addr,
    },
};

/// Interval between QUIC upgrade attempts (1 minute).
const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);

/// Backoff state for a peer's QUIC upgrade attempts.
#[derive(Debug, Clone)]
struct QuicUpgradeBackoff {
    /// Number of tickers (minutes) remaining before next upgrade attempt.
    tickers_remaining: u32,
    /// Current backoff duration in minutes/tickers.
    backoff_duration: u32,
}

impl QuicUpgradeBackoff {
    /// Initial backoff duration (2 minutes).
    const INITIAL: u32 = 2;
    /// Maximum backoff duration (512 minutes / ~8 hours).
    const MAX: u32 = 512;

    /// Creates a new backoff state with initial values.
    fn new() -> Self {
        Self {
            tickers_remaining: Self::INITIAL,
            backoff_duration: Self::INITIAL,
        }
    }

    /// Records a failure, doubling the backoff duration up to the maximum.
    fn record_failure(&mut self) {
        self.backoff_duration = self.backoff_duration.saturating_mul(2).min(Self::MAX);
        self.tickers_remaining = self.backoff_duration;
    }
}

/// Events emitted by the QUIC upgrade behaviour.
#[derive(Debug, Clone)]
pub enum QuicUpgradeEvent {
    /// Successfully upgraded to QUIC.
    Upgraded {
        /// The peer that was upgraded.
        peer: PeerId,
    },
    /// Upgrade failed.
    UpgradeFailed {
        /// The peer that failed to upgrade.
        peer: PeerId,
        /// The reason for the failure.
        reason: String,
    },
}

/// State of an in-progress upgrade attempt.
#[derive(Debug)]
enum UpgradeState {
    /// Waiting for QUIC connection to be established.
    DialingQuic {
        /// TCP connection IDs to close after QUIC is established.
        tcp_conn_ids: Vec<ConnectionId>,
    },
}

/// QUIC connection upgrade behaviour.
///
/// Periodically (every 1 minute) attempts to upgrade direct TCP connections
/// to QUIC connections with exponential backoff on failures.
///
/// The behaviour assumes that the peer store is updated correctly and will work only with the given set of known peers.
///
/// # Upgrade Logic
///
/// For each known peer:
/// 1. Skip if already has direct QUIC connection (close redundant TCP)
/// 2. Skip if no direct TCP connection
/// 3. Skip if no known QUIC addresses
/// 4. Attempt to dial QUIC addresses
/// 5. On success, close redundant TCP connections
/// 6. On failure, apply exponential backoff
pub struct QuicUpgradeBehaviour {
    /// P2P context for accessing peer store and known peers.
    p2p_context: P2PContext,
    /// Local peer ID (to skip self).
    local_peer_id: PeerId,
    /// Backoff state per peer.
    backoffs: HashMap<PeerId, QuicUpgradeBackoff>,
    /// Pending events to emit.
    pending_events: VecDeque<ToSwarm<QuicUpgradeEvent, Infallible>>,
    /// In-progress upgrade attempts.
    pending_upgrades: HashMap<PeerId, UpgradeState>,
    /// Next time to run upgrade logic.
    next_tick: Instant,
    /// Interval between upgrade attempts.
    interval: Duration,
    /// Whether QUIC is enabled on this node.
    quic_enabled: bool,
}

impl std::fmt::Debug for QuicUpgradeBehaviour {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicUpgradeBehaviour")
            .field("local_peer_id", &self.local_peer_id)
            .field("backoffs", &self.backoffs)
            .field("pending_events", &self.pending_events.len())
            .field("pending_upgrades", &self.pending_upgrades.len())
            .field("next_tick", &self.next_tick)
            .field("interval", &self.interval)
            .field("quic_enabled", &self.quic_enabled)
            .finish()
    }
}

impl QuicUpgradeBehaviour {
    /// Creates a new QUIC upgrade behaviour.
    ///
    /// # Arguments
    ///
    /// * `p2p_context` - Shared P2P context for accessing peer store
    /// * `local_peer_id` - Local peer ID to skip self
    /// * `quic_enabled` - Whether QUIC is enabled on this node
    pub fn new(p2p_context: P2PContext, local_peer_id: PeerId, quic_enabled: bool) -> Self {
        let now = Instant::now();
        Self {
            p2p_context,
            local_peer_id,
            backoffs: HashMap::new(),
            pending_events: VecDeque::new(),
            pending_upgrades: HashMap::new(),
            next_tick: now.checked_add(UPGRADE_INTERVAL).unwrap_or(now),
            interval: UPGRADE_INTERVAL,
            quic_enabled,
        }
    }

    /// Checks if a peer should skip upgrade due to active backoff.
    fn should_skip(&mut self, peer: &PeerId) -> bool {
        if let Some(backoff) = self.backoffs.get_mut(peer)
            && backoff.tickers_remaining > 0
        {
            backoff.tickers_remaining = backoff.tickers_remaining.saturating_sub(1);
            debug!(
                peer = %peer_name(peer),
                remaining = backoff.tickers_remaining,
                backoff_duration_minutes = backoff.backoff_duration,
                "skipping QUIC upgrade due to backoff"
            );
            return true;
        }
        false
    }

    /// Records a failure for a peer, applying exponential backoff.
    fn record_failure(&mut self, peer: PeerId, reason: &str) {
        self.backoffs
            .entry(peer)
            .or_insert_with(QuicUpgradeBackoff::new)
            .record_failure();

        self.pending_events
            .push_back(ToSwarm::GenerateEvent(QuicUpgradeEvent::UpgradeFailed {
                peer,
                reason: reason.to_string(),
            }));
    }

    /// Clears backoff state for a peer after successful upgrade.
    fn clear_backoff(&mut self, peer: &PeerId) {
        self.backoffs.remove(peer);
    }

    /// Runs the upgrade logic for all known peers.
    fn run_upgrade_logic(&mut self) {
        if !self.quic_enabled {
            debug!("node doesn't have feature QUIC enabled");
            return;
        }

        let peer_ids: Vec<PeerId> = self.p2p_context.known_peers().iter().copied().collect();

        for peer_id in peer_ids {
            if peer_id == self.local_peer_id || self.should_skip(&peer_id) || self.pending_upgrades.contains_key(&peer_id) {
                continue;
            }

            let conns: Vec<_> = self
                .p2p_context
                .peer_store_lock()
                .connections_to_peer(&peer_id)
                .into_iter()
                .cloned()
                .collect();

            if conns.is_empty() {
                debug!(
                    peer = %peer_name(&peer_id),
                    "no connection to peer"
                );
                continue;
            }

            let conn_refs: Vec<_> = conns.iter().collect();

            if has_direct_quic_conn(&conn_refs) {
                debug!(
                    peer = %peer_name(&peer_id),
                    "already has direct QUIC connection to peer"
                );

                let tcp_conn_ids: Vec<_> = conns
                    .iter()
                    .filter(|c| is_tcp_addr(&c.remote_addr) && !is_relay_addr(&c.remote_addr))
                    .map(|c| c.connection_id)
                    .collect();

                debug!(
                    peer = %peer_name(&peer_id),
                    "closing {} redundant TCP connections after QUIC upgrade",
                    tcp_conn_ids.len()
                );
                self.close_tcp_connections(peer_id, tcp_conn_ids);

                continue;
            }

            if !has_direct_tcp_conn(&conn_refs) {
                debug!(
                    peer = %peer_name(&peer_id),
                    "no direct connection via TCP to peer"
                );
                continue;
            }

            let quic_addrs = self
                .p2p_context
                .peer_store_lock()
                .peer_addresses(&peer_id)
                .map(|addrs| filter_direct_quic_addrs(addrs.iter().cloned()))
                .unwrap_or_default();

            if quic_addrs.is_empty() {
                debug!(
                    peer = %peer_name(&peer_id),
                    "no known QUIC addresses to peer"
                );
                continue;
            }

            info!(
                peer = %peer_name(&peer_id),
                quic_addrs = ?quic_addrs,
                "trying to upgrade to QUIC connection with peer"
            );

            let tcp_conn_ids: Vec<_> = conns
                .iter()
                .filter(|c| is_tcp_addr(&c.remote_addr) && !is_relay_addr(&c.remote_addr))
                .map(|c| c.connection_id)
                .collect();

            self.pending_upgrades
                .insert(peer_id, UpgradeState::DialingQuic { tcp_conn_ids });

            self.pending_events.push_back(ToSwarm::Dial {
                opts: DialOpts::peer_id(peer_id)
                    .addresses(quic_addrs)
                    .condition(PeerCondition::Always)
                    .build(),
            });
        }
    }

    fn close_tcp_connections(&mut self, peer_id: PeerId, conn_ids: Vec<ConnectionId>) {
        for conn_id in conn_ids {
            self.pending_events.push_back(ToSwarm::CloseConnection {
                peer_id,
                connection: libp2p::swarm::CloseConnection::One(conn_id),
            });
        }
    }

    /// Handles a successful connection establishment.
    fn handle_connection_established(&mut self, peer_id: PeerId, addr: &Multiaddr) {
        if let Some(UpgradeState::DialingQuic { tcp_conn_ids }) =
            self.pending_upgrades.remove(&peer_id)
        {
            if is_quic_addr(addr) && !is_relay_addr(addr) {
                info!(
                    peer = %peer_name(&peer_id),
                    addr = %addr,
                    "upgraded connection to QUIC"
                );

                debug!(
                    peer = %peer_name(&peer_id),
                    "closing {} redundant TCP connections after QUIC upgrade",
                    tcp_conn_ids.len()
                );
                self.close_tcp_connections(peer_id, tcp_conn_ids);

                self.clear_backoff(&peer_id);
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(QuicUpgradeEvent::Upgraded {
                        peer: peer_id,
                    }));
            } else {
                debug!(
                    peer = %peer_name(&peer_id),
                    addr = %addr,
                    "connected via TCP after upgrade to QUIC connection"
                );
                self.record_failure(peer_id, "connected via TCP instead of QUIC");
            }
        }
    }

    /// Handles a dial failure.
    fn handle_dial_failure(&mut self, peer_id: Option<PeerId>) {
        if let Some(peer_id) = peer_id
            && self.pending_upgrades.remove(&peer_id).is_some()
        {
            info!(
                peer = %peer_name(&peer_id),
                "failed to connect to peer during QUIC upgrade"
            );
            self.record_failure(peer_id, "dial failed");
        }
    }
}

impl NetworkBehaviour for QuicUpgradeBehaviour {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = QuicUpgradeEvent;

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

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(event) => {
                let addr = match &event.endpoint {
                    libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
                    libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
                };
                self.handle_connection_established(event.peer_id, addr);
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
        _event: THandlerOutEvent<Self>,
    ) {
        // Handler emits Infallible, so this is unreachable
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event);
        }

        let now = Instant::now();
        if now >= self.next_tick {
            self.next_tick = now.checked_add(self.interval).unwrap_or(now);
            self.run_upgrade_logic();

            if let Some(event) = self.pending_events.pop_front() {
                return Poll::Ready(event);
            }
        }

        // Wake to check timer
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p_context::Peer;

    fn random_peer_id() -> PeerId {
        PeerId::random()
    }

    fn tcp_addr() -> Multiaddr {
        "/ip4/192.168.1.1/tcp/9000".parse().unwrap()
    }

    fn quic_addr() -> Multiaddr {
        "/ip4/192.168.1.1/udp/9000/quic-v1".parse().unwrap()
    }

    fn relay_quic_addr(relay_peer: &PeerId) -> Multiaddr {
        format!("/ip4/1.2.3.4/udp/9000/quic-v1/p2p/{relay_peer}/p2p-circuit")
            .parse()
            .unwrap()
    }

    #[test]
    fn test_backoff_initial() {
        let backoff = QuicUpgradeBackoff::new();
        assert_eq!(backoff.tickers_remaining, 2);
        assert_eq!(backoff.backoff_duration, 2);
    }

    #[test]
    fn test_backoff_record_failure() {
        let mut backoff = QuicUpgradeBackoff::new();
        backoff.record_failure();
        assert_eq!(backoff.backoff_duration, 4);
        assert_eq!(backoff.tickers_remaining, 4);

        backoff.record_failure();
        assert_eq!(backoff.backoff_duration, 8);
        assert_eq!(backoff.tickers_remaining, 8);
    }

    #[test]
    fn test_backoff_max() {
        let mut backoff = QuicUpgradeBackoff::new();
        for _ in 0..20 {
            backoff.record_failure();
        }
        assert_eq!(backoff.backoff_duration, QuicUpgradeBackoff::MAX);
        assert_eq!(backoff.tickers_remaining, QuicUpgradeBackoff::MAX);
    }

    #[test]
    fn test_backoff_overflow_protection() {
        let mut backoff = QuicUpgradeBackoff {
            tickers_remaining: u32::MAX,
            backoff_duration: u32::MAX,
        };
        backoff.record_failure();
        assert_eq!(backoff.backoff_duration, QuicUpgradeBackoff::MAX);
    }

    #[test]
    fn test_upgrade_skips_self() {
        let local_peer_id = random_peer_id();
        let p2p_context = P2PContext::new([local_peer_id]);

        let mut behaviour = QuicUpgradeBehaviour::new(p2p_context, local_peer_id, true);
        behaviour.run_upgrade_logic();

        assert!(behaviour.pending_events.is_empty());
    }

    #[test]
    fn test_upgrade_skips_when_quic_disabled() {
        let local_peer_id = random_peer_id();
        let peer_id = random_peer_id();
        let p2p_context = P2PContext::new([peer_id]);

        p2p_context.peer_store_write_lock().add_peer(Peer {
            id: peer_id,
            connection_id: ConnectionId::new_unchecked(1),
            remote_addr: tcp_addr(),
        });

        p2p_context
            .peer_store_write_lock()
            .set_peer_addresses(peer_id, vec![quic_addr()]);

        let mut behaviour = QuicUpgradeBehaviour::new(p2p_context, local_peer_id, false);
        behaviour.run_upgrade_logic();

        assert!(behaviour.pending_events.is_empty());
    }

    #[test]
    fn test_upgrade_skips_peer_in_backoff() {
        let local_peer_id = random_peer_id();
        let peer_id = random_peer_id();
        let p2p_context = P2PContext::new([peer_id]);

        p2p_context.peer_store_write_lock().add_peer(Peer {
            id: peer_id,
            connection_id: ConnectionId::new_unchecked(1),
            remote_addr: tcp_addr(),
        });

        p2p_context
            .peer_store_write_lock()
            .set_peer_addresses(peer_id, vec![quic_addr()]);

        let mut behaviour = QuicUpgradeBehaviour::new(p2p_context, local_peer_id, true);

        behaviour.record_failure(peer_id, "test failure");
        behaviour.pending_events.clear();

        behaviour.run_upgrade_logic();

        assert!(behaviour.pending_events.is_empty());
    }

    #[test]
    fn test_upgrade_skips_no_connections() {
        let local_peer_id = random_peer_id();
        let peer_id = random_peer_id();
        let p2p_context = P2PContext::new([peer_id]);

        p2p_context
            .peer_store_write_lock()
            .set_peer_addresses(peer_id, vec![quic_addr()]);

        let mut behaviour = QuicUpgradeBehaviour::new(p2p_context, local_peer_id, true);
        behaviour.run_upgrade_logic();

        assert!(behaviour.pending_events.is_empty());
    }

    #[test]
    fn test_upgrade_closes_tcp_when_has_quic() {
        let local_peer_id = random_peer_id();
        let peer_id = random_peer_id();
        let p2p_context = P2PContext::new([peer_id]);

        let tcp_conn_id = ConnectionId::new_unchecked(1);
        let quic_conn_id = ConnectionId::new_unchecked(2);

        {
            let mut store = p2p_context.peer_store_write_lock();
            store.add_peer(Peer {
                id: peer_id,
                connection_id: tcp_conn_id,
                remote_addr: tcp_addr(),
            });
            store.add_peer(Peer {
                id: peer_id,
                connection_id: quic_conn_id,
                remote_addr: quic_addr(),
            });
        }

        let mut behaviour = QuicUpgradeBehaviour::new(p2p_context, local_peer_id, true);
        behaviour.run_upgrade_logic();

        assert_eq!(behaviour.pending_events.len(), 1);
        assert!(matches!(
            behaviour.pending_events.pop_front(),
            Some(ToSwarm::CloseConnection { .. })
        ));
    }

    #[test]
    fn test_upgrade_skips_no_tcp_connection() {
        let local_peer_id = random_peer_id();
        let peer_id = random_peer_id();
        let relay_peer = random_peer_id();
        let p2p_context = P2PContext::new([peer_id]);

        p2p_context.peer_store_write_lock().add_peer(Peer {
            id: peer_id,
            connection_id: ConnectionId::new_unchecked(1),
            remote_addr: relay_quic_addr(&relay_peer),
        });

        p2p_context
            .peer_store_write_lock()
            .set_peer_addresses(peer_id, vec![quic_addr()]);

        let mut behaviour = QuicUpgradeBehaviour::new(p2p_context, local_peer_id, true);
        behaviour.run_upgrade_logic();

        assert!(behaviour.pending_events.is_empty());
    }

    #[test]
    fn test_upgrade_skips_no_quic_addresses() {
        let local_peer_id = random_peer_id();
        let peer_id = random_peer_id();
        let p2p_context = P2PContext::new([peer_id]);

        p2p_context.peer_store_write_lock().add_peer(Peer {
            id: peer_id,
            connection_id: ConnectionId::new_unchecked(1),
            remote_addr: tcp_addr(),
        });

        let mut behaviour = QuicUpgradeBehaviour::new(p2p_context, local_peer_id, true);
        behaviour.run_upgrade_logic();

        assert!(behaviour.pending_events.is_empty());
    }

    #[test]
    fn test_upgrade_dials_quic_addresses() {
        let local_peer_id = random_peer_id();
        let peer_id = random_peer_id();
        let p2p_context = P2PContext::new([peer_id]);

        p2p_context.peer_store_write_lock().add_peer(Peer {
            id: peer_id,
            connection_id: ConnectionId::new_unchecked(1),
            remote_addr: tcp_addr(),
        });

        p2p_context
            .peer_store_write_lock()
            .set_peer_addresses(peer_id, vec![quic_addr()]);

        let mut behaviour = QuicUpgradeBehaviour::new(p2p_context, local_peer_id, true);
        behaviour.run_upgrade_logic();

        assert_eq!(behaviour.pending_events.len(), 1);
        assert!(matches!(
            behaviour.pending_events.pop_front(),
            Some(ToSwarm::Dial { .. })
        ));

        assert!(behaviour.pending_upgrades.contains_key(&peer_id));
    }

    #[test]
    fn test_handle_connection_established_quic_success() {
        let local_peer_id = random_peer_id();
        let peer_id = random_peer_id();
        let p2p_context = P2PContext::new([peer_id]);
        let tcp_conn_id = ConnectionId::new_unchecked(1);

        let mut behaviour = QuicUpgradeBehaviour::new(p2p_context, local_peer_id, true);

        behaviour.pending_upgrades.insert(
            peer_id,
            UpgradeState::DialingQuic {
                tcp_conn_ids: vec![tcp_conn_id],
            },
        );

        behaviour.handle_connection_established(peer_id, &quic_addr());

        assert_eq!(behaviour.pending_events.len(), 2);

        assert!(matches!(
            behaviour.pending_events.pop_front(),
            Some(ToSwarm::CloseConnection { .. })
        ));

        assert!(matches!(
            behaviour.pending_events.pop_front(),
            Some(ToSwarm::GenerateEvent(QuicUpgradeEvent::Upgraded { .. }))
        ));

        assert!(!behaviour.pending_upgrades.contains_key(&peer_id));
    }

    #[test]
    fn test_handle_connection_established_tcp_instead_of_quic() {
        let local_peer_id = random_peer_id();
        let peer_id = random_peer_id();
        let p2p_context = P2PContext::new([peer_id]);

        let mut behaviour = QuicUpgradeBehaviour::new(p2p_context, local_peer_id, true);

        behaviour.pending_upgrades.insert(
            peer_id,
            UpgradeState::DialingQuic {
                tcp_conn_ids: vec![],
            },
        );

        behaviour.handle_connection_established(peer_id, &tcp_addr());

        assert_eq!(behaviour.pending_events.len(), 1);
        assert!(matches!(
            behaviour.pending_events.pop_front(),
            Some(ToSwarm::GenerateEvent(QuicUpgradeEvent::UpgradeFailed { .. }))
        ));

        assert!(behaviour.backoffs.contains_key(&peer_id));
    }

    #[test]
    fn test_handle_dial_failure() {
        let local_peer_id = random_peer_id();
        let peer_id = random_peer_id();
        let p2p_context = P2PContext::new([peer_id]);

        let mut behaviour = QuicUpgradeBehaviour::new(p2p_context, local_peer_id, true);

        behaviour.pending_upgrades.insert(
            peer_id,
            UpgradeState::DialingQuic {
                tcp_conn_ids: vec![],
            },
        );

        behaviour.handle_dial_failure(Some(peer_id));

        assert_eq!(behaviour.pending_events.len(), 1);
        assert!(matches!(
            behaviour.pending_events.pop_front(),
            Some(ToSwarm::GenerateEvent(QuicUpgradeEvent::UpgradeFailed { .. }))
        ));

        assert!(!behaviour.pending_upgrades.contains_key(&peer_id));
        assert!(behaviour.backoffs.contains_key(&peer_id));
    }

    #[test]
    fn test_backoff_decrements_on_skip() {
        let local_peer_id = random_peer_id();
        let peer_id = random_peer_id();
        let p2p_context = P2PContext::new([peer_id]);

        let mut behaviour = QuicUpgradeBehaviour::new(p2p_context, local_peer_id, true);

        behaviour.backoffs.insert(
            peer_id,
            QuicUpgradeBackoff {
                tickers_remaining: 3,
                backoff_duration: 4,
            },
        );

        assert!(behaviour.should_skip(&peer_id));
        assert_eq!(behaviour.backoffs.get(&peer_id).unwrap().tickers_remaining, 2);

        assert!(behaviour.should_skip(&peer_id));
        assert_eq!(behaviour.backoffs.get(&peer_id).unwrap().tickers_remaining, 1);

        assert!(behaviour.should_skip(&peer_id));
        assert_eq!(behaviour.backoffs.get(&peer_id).unwrap().tickers_remaining, 0);

        assert!(!behaviour.should_skip(&peer_id));
    }

    #[test]
    fn test_clear_backoff() {
        let local_peer_id = random_peer_id();
        let peer_id = random_peer_id();
        let p2p_context = P2PContext::new([peer_id]);

        let mut behaviour = QuicUpgradeBehaviour::new(p2p_context, local_peer_id, true);

        behaviour.backoffs.insert(peer_id, QuicUpgradeBackoff::new());
        assert!(behaviour.backoffs.contains_key(&peer_id));

        behaviour.clear_backoff(&peer_id);
        assert!(!behaviour.backoffs.contains_key(&peer_id));
    }
}
