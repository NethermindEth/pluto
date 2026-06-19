//! The [`RelayManager`] behaviour: reservation lifecycle and peer routing.

use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::stream::StreamExt;
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    multiaddr::Protocol as MaProtocol,
    swarm::{
        ConnectionDenied, ConnectionId, DialError, FromSwarm, NetworkBehaviour, THandler,
        THandlerInEvent, ToSwarm, dummy,
    },
};
use tokio::time::{Instant, Sleep, sleep_until};
use tokio_stream::wrappers::WatchStream;

use super::{
    dial::{RelayDialState, addr_sets_equal},
    event::{RelayDialError, RelayDialType, RelayManagerEvent},
};
use crate::{
    p2p_context::P2PContext,
    peer::{MutablePeer, Peer},
};

#[cfg(test)]
mod tests;

/// How long a relay may stay in `Established` (transport connected, no
/// reservation yet) before the watchdog force-closes the transport so a fresh
/// dial campaign can recover. Mirrors Charon's "no relay connection,
/// reconnecting" path (`charon/p2p/relay.go:73-92`).
const ESTABLISHED_STUCK_THRESHOLD: Duration = Duration::from_secs(60);
/// How often the watchdog re-evaluates stuck-in-Established relays.
const ESTABLISHED_WATCHDOG_TICK: Duration = Duration::from_secs(15);

/// Lifecycle of a relay reservation.
///
/// - `Dialing`: a `RelayDialState` is in flight; no transport connection to the
///   relay yet.
/// - `Established`: transport connection to the relay is up; the swarm has been
///   asked to listen on the circuit address(es) but no reservation has been
///   confirmed yet.
/// - `Reserved`: the swarm has emitted `NewListenAddr` for the circuit address,
///   meaning the relay accepted our reservation and we can route peers through
///   it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayConnectionState {
    /// Dial campaign in flight; no transport connection to the relay yet.
    Dialing,
    /// Transport connection up; reservation not yet confirmed.
    Established,
    /// Reservation confirmed; circuits through this relay are usable.
    Reserved,
}

/// Libp2p [`NetworkBehaviour`] that reserves circuits on a configured set of
/// relays and routes known cluster peers through them. See the module-level
/// docs for the full responsibility breakdown.
pub struct RelayManager {
    /// Events to emit to the swarm
    events: VecDeque<ToSwarm<RelayManagerEvent, Infallible>>,

    /// Streams of relay peer updates. Each stream yields the current value on
    /// first poll, so initial peers are picked up automatically without a
    /// separate bootstrap pass.
    relay_subs: Vec<WatchStream<Option<Peer>>>,

    /// Dial states for each relay.
    dial_states: HashMap<PeerId, RelayDialState>,

    /// Connection states for each relay.
    connection_states: HashMap<PeerId, RelayConnectionState>,

    /// Latest known transport addresses for each relay. Persists across the
    /// connection lifecycle so we can redial after `ConnectionClosed` without
    /// waiting for another `MutablePeer` update.
    relay_addrs: HashMap<PeerId, Vec<Multiaddr>>,

    /// Tracks when each relay last entered `Established` without having since
    /// reached `Reserved`. The watchdog uses this to identify relays whose
    /// reservation never confirmed (or whose refresh was denied so libp2p's
    /// relay client silently gave up) and force-close them so we redial fresh.
    established_at: HashMap<PeerId, Instant>,

    /// Watchdog tick. Fires every `ESTABLISHED_WATCHDOG_TICK`; on fire we walk
    /// `established_at` and emit `ToSwarm::CloseConnection` for any relay
    /// stuck beyond `ESTABLISHED_STUCK_THRESHOLD`. Lazily initialised on the
    /// first `poll` so `RelayManager::new` can be called outside a Tokio
    /// runtime (e.g. in unit tests that exercise pure helpers).
    watchdog: Option<Pin<Box<Sleep>>>,

    /// Shared P2P context used to enumerate known cluster peers when routing
    /// them through reserved relays.
    p2p_context: P2PContext,
}

impl RelayManager {
    /// Creates a new relay manager: reserves circuits on the supplied relays
    /// and routes known cluster peers through them.
    pub fn new(mutable_peers: Vec<MutablePeer>, p2p_context: P2PContext) -> Self {
        let relay_subs = mutable_peers
            .iter()
            .map(|mp| WatchStream::new(mp.subscribe()))
            .collect();

        Self {
            events: VecDeque::new(),
            relay_subs,
            dial_states: HashMap::new(),
            connection_states: HashMap::new(),
            relay_addrs: HashMap::new(),
            established_at: HashMap::new(),
            watchdog: None,
            p2p_context,
        }
    }

    /// Builds circuit listen addresses for a relay from its transport
    /// addresses: `/ip4/.../tcp/.../p2p/<relay-id>/p2p-circuit`.
    fn circuit_addrs(relay_id: PeerId, addrs: &[Multiaddr]) -> Vec<Multiaddr> {
        addrs
            .iter()
            .map(|addr| {
                let mut circuit: Multiaddr = addr
                    .iter()
                    .filter(|p| !matches!(p, MaProtocol::P2p(_)))
                    .collect();
                circuit.push(MaProtocol::P2p(relay_id));
                circuit.push(MaProtocol::P2pCircuit);
                circuit
            })
            .collect()
    }

    /// Extracts the relay peer id from a circuit listen address of the form
    /// `/.../p2p/<relay-id>/p2p-circuit`. Returns `None` if the address is not
    /// a relay circuit address.
    fn relay_id_from_circuit_addr(addr: &Multiaddr) -> Option<PeerId> {
        let mut last_p2p: Option<PeerId> = None;
        for proto in addr.iter() {
            match proto {
                MaProtocol::P2p(id) => last_p2p = Some(id),
                MaProtocol::P2pCircuit => return last_p2p,
                _ => {}
            }
        }
        None
    }

    /// Applies a relay address update from a [`MutablePeer`]: refreshes
    /// tracked addresses and, if this is the first time we've seen this
    /// relay, kicks off a new dial campaign.
    fn queue_relay_update(&mut self, relay: Peer) {
        self.relay_addrs.insert(relay.id, relay.addresses.clone());

        // In-flight dial campaign: refresh its address list without resetting
        // the backoff schedule.
        if let Some(dial_state) = self.dial_states.get_mut(&relay.id) {
            dial_state.addrs = relay.addresses;
            return;
        }

        // Already connected (Established or Reserved): nothing to do now;
        // `relay_addrs` is updated and the next disconnect will pick it up.
        if self.connection_states.contains_key(&relay.id) {
            return;
        }

        // First time we see this relay: start the dial campaign.
        self.dial_states.insert(
            relay.id,
            RelayDialState::new(RelayDialType::RelayServer, relay.id, relay.addresses),
        );
        self.set_relay_state(relay.id, RelayConnectionState::Dialing);
    }

    /// Updates the connection state for a relay, logging the transition and
    /// maintaining the `established_at` watchdog timestamp.
    fn set_relay_state(&mut self, relay_id: PeerId, next: RelayConnectionState) {
        let prev = self.connection_states.insert(relay_id, next);
        if prev != Some(next) {
            tracing::debug!(
                relay_peer_id = %relay_id,
                ?prev,
                ?next,
                "Relay connection state transition"
            );
        }
        match next {
            // Entering or refreshing the no-reservation-yet state: start (or
            // restart, on demote from Reserved) the stuck-Established timer.
            RelayConnectionState::Established => {
                if prev != Some(RelayConnectionState::Established) {
                    self.established_at.insert(relay_id, Instant::now());
                }
            }
            // Promoted to Reserved or back to Dialing: the relay isn't stuck
            // in Established anymore, so clear its watchdog timestamp.
            RelayConnectionState::Reserved | RelayConnectionState::Dialing => {
                self.established_at.remove(&relay_id);
            }
        }
    }

    /// Polls every active dial state once, queuing a `ToSwarm::Dial` event for
    /// any whose backoff has elapsed. Wakers for the remaining (pending) ones
    /// are registered via the underlying `Sleep` futures.
    fn process_relay_dials(&mut self, cx: &mut Context<'_>) {
        for state in self.dial_states.values_mut() {
            if let Poll::Ready(Some(event)) = state.poll_next_unpin(cx) {
                self.events.push_back(event);
            }
        }
    }

    /// Watchdog for relays stuck in `Established`.
    ///
    /// Libp2p's relay client owns reservation refresh; if a relay denies a
    /// refresh (overloaded, quota exhausted, version mismatch), the client
    /// typically gives up silently — no further `NewListenAddr` is emitted
    /// and the transport stays up, so `on_connection_closed` never fires.
    /// Without intervention the relay would stay in `Established` forever.
    ///
    /// On each tick, any relay that has been `Established` for longer than
    /// [`ESTABLISHED_STUCK_THRESHOLD`] gets a `ToSwarm::CloseConnection`; the
    /// resulting `FromSwarm::ConnectionClosed` drives `on_connection_closed`
    /// → `redial_relay`, mirroring Charon's "no relay connection,
    /// reconnecting" recovery path (`charon/p2p/relay.go:73-92`).
    fn process_established_watchdog(&mut self, cx: &mut Context<'_>) {
        let watchdog = self.watchdog.get_or_insert_with(|| {
            let deadline = Instant::now()
                .checked_add(ESTABLISHED_WATCHDOG_TICK)
                .unwrap_or_else(Instant::now);
            Box::pin(sleep_until(deadline))
        });
        if watchdog.as_mut().poll(cx).is_pending() {
            return;
        }

        let now = Instant::now();
        let stuck: Vec<PeerId> = self
            .established_at
            .iter()
            .filter(|(id, since)| {
                now.saturating_duration_since(**since) >= ESTABLISHED_STUCK_THRESHOLD
                    && matches!(
                        self.connection_states.get(id),
                        Some(RelayConnectionState::Established)
                    )
            })
            .map(|(id, _)| *id)
            .collect();

        for relay_id in stuck {
            tracing::warn!(
                relay_peer_id = %relay_id,
                threshold = ?ESTABLISHED_STUCK_THRESHOLD,
                "Relay stuck in Established without reservation; force-closing for redial"
            );
            // Clear the timestamp so we don't re-fire CloseConnection on the
            // next tick while ConnectionClosed is in flight; on_connection_closed
            // will eventually transition us back to Dialing.
            self.established_at.remove(&relay_id);
            self.events.push_back(ToSwarm::CloseConnection {
                peer_id: relay_id,
                connection: libp2p::swarm::CloseConnection::All,
            });
        }

        let next_deadline = now
            .checked_add(ESTABLISHED_WATCHDOG_TICK)
            .unwrap_or_else(Instant::now);
        // Watchdog is Some by construction inside this function — we just
        // initialised or polled it above.
        if let Some(watchdog) = self.watchdog.as_mut() {
            watchdog.as_mut().reset(next_deadline);
        }
    }

    /// Returns the peer ids of relays whose circuit reservation has been
    /// confirmed (i.e. swarm has issued `NewListenAddr` for the circuit).
    fn reserved_relay_ids(&self) -> Vec<PeerId> {
        self.connection_states
            .iter()
            .filter(|(_, s)| matches!(s, RelayConnectionState::Reserved))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Builds circuit dial addresses for reaching `target` through every
    /// currently reserved relay:
    /// `/.../p2p/<relay-id>/p2p-circuit/p2p/<target>`.
    fn peer_circuit_addrs(&self, target: &PeerId) -> Vec<Multiaddr> {
        let mut addrs = Vec::new();
        for relay_id in self.reserved_relay_ids() {
            let Some(relay_addrs) = self.relay_addrs.get(&relay_id) else {
                continue;
            };
            for relay_addr in relay_addrs {
                let mut circuit: Multiaddr = relay_addr
                    .iter()
                    .filter(|p| !matches!(p, MaProtocol::P2p(_)))
                    .collect();
                circuit.push(MaProtocol::P2p(relay_id));
                circuit.push(MaProtocol::P2pCircuit);
                circuit.push(MaProtocol::P2p(*target));
                addrs.push(circuit);
            }
        }
        addrs
    }

    /// Ensures every known cluster peer (≠ self) has a dial state armed to
    /// reach it through the current set of reserved relays.
    fn route_known_peers(&mut self) {
        let local = self.p2p_context.local_peer_id();
        let targets: Vec<PeerId> = self
            .p2p_context
            .known_peers()
            .iter()
            .copied()
            .filter(|id| Some(*id) != local)
            .collect();

        for target in targets {
            self.upsert_peer_dial(target);
        }
    }

    /// Inserts or refreshes a dial state for `target` using the current circuit
    /// addrs.
    ///
    /// If the address set changed (or there was no dial state yet) the backoff
    /// schedule is reset so the new route is tried immediately. If the address
    /// set is unchanged, the existing dial state is left alone — its backoff
    /// schedule survives so we don't hammer peers that have been unreachable
    /// just because re-routing was re-evaluated. If no reserved relay can
    /// currently reach `target`, any pre-existing dial state is removed so we
    /// don't keep firing `Dial` events at circuits through unreserved relays.
    fn upsert_peer_dial(&mut self, target: PeerId) {
        let addrs = self.peer_circuit_addrs(&target);
        if addrs.is_empty() {
            self.dial_states.remove(&target);
            return;
        }

        if let Some(existing) = self.dial_states.get(&target)
            && addr_sets_equal(&existing.addrs, &addrs)
        {
            return;
        }

        self.dial_states.insert(
            target,
            RelayDialState::new(RelayDialType::ClusterPeer, target, addrs),
        );
    }

    /// Re-evaluates every active cluster-peer dial state against the current
    /// set of reserved relays. Called when a relay leaves `Reserved` so that
    /// peer dial campaigns stop self-rearming through circuits that no longer
    /// exist.
    fn refresh_peer_dials(&mut self) {
        let peer_targets: Vec<PeerId> = self
            .dial_states
            .iter()
            .filter(|(_, s)| matches!(s.ty, RelayDialType::ClusterPeer))
            .map(|(id, _)| *id)
            .collect();
        for target in peer_targets {
            self.upsert_peer_dial(target);
        }
    }

    /// Reacts to a new transport connection on a peer we previously dialed.
    /// Relay dials transition into `Established` and queue circuit listeners;
    /// peer routing dials just drop their dial state — libp2p takes it from
    /// here.
    fn on_connection_established(&mut self, peer_id: PeerId) {
        let Some(dial_state) = self.dial_states.remove(&peer_id) else {
            return;
        };

        match dial_state.ty {
            RelayDialType::RelayServer => {
                self.events
                    .push_back(ToSwarm::GenerateEvent(RelayManagerEvent::RelayConnected(
                        peer_id,
                    )));
                self.set_relay_state(peer_id, RelayConnectionState::Established);

                for circuit_addr in Self::circuit_addrs(peer_id, &dial_state.addrs) {
                    tracing::debug!(
                        relay_peer_id = %peer_id,
                        %circuit_addr,
                        "Requesting circuit listener on relay"
                    );
                    self.events.push_back(ToSwarm::ListenOn {
                        opts: libp2p::swarm::ListenOpts::new(circuit_addr),
                    });
                }
            }
            RelayDialType::ClusterPeer => {
                tracing::debug!(
                    peer_id = %peer_id,
                    "Routed peer connection established"
                );
                self.events.push_back(ToSwarm::GenerateEvent(
                    RelayManagerEvent::PeerRoutedConnected(peer_id),
                ));
            }
        }
    }

    /// Reacts to a new listen address. If it's a circuit address for one of
    /// our relays, promotes that relay's state to `Reserved` and re-routes
    /// known peers through the updated set of reserved relays.
    fn on_new_listen_addr(&mut self, addr: &Multiaddr) {
        let Some(relay_id) = Self::relay_id_from_circuit_addr(addr) else {
            return;
        };
        let Some(state) = self.connection_states.get(&relay_id).copied() else {
            return;
        };
        match state {
            RelayConnectionState::Dialing => {
                tracing::warn!(
                    relay_peer_id = %relay_id,
                    listen_addr = %addr,
                    "NewListenAddr for relay in Dialing state; ignoring"
                );
            }
            RelayConnectionState::Reserved => {
                // Second circuit address from the same relay — already routed.
            }
            RelayConnectionState::Established => {
                tracing::info!(
                    relay_peer_id = %relay_id,
                    listen_addr = %addr,
                    "Relay reservation confirmed; routing known peers via this relay"
                );
                self.set_relay_state(relay_id, RelayConnectionState::Reserved);
                self.events
                    .push_back(ToSwarm::GenerateEvent(RelayManagerEvent::RelayReserved(
                        relay_id,
                    )));
                self.route_known_peers();
            }
        }
    }

    /// Reacts to a circuit listen address expiring. If the relay was in
    /// `Reserved`, demote it to `Established` so we stop routing peers through
    /// it. libp2p's circuit-client will normally refresh the reservation and
    /// emit `NewListenAddr` again, which promotes us back. If the transport
    /// connection also drops, `on_connection_closed` will handle the redial.
    fn on_expired_listen_addr(&mut self, addr: &Multiaddr) {
        let Some(relay_id) = Self::relay_id_from_circuit_addr(addr) else {
            return;
        };
        let Some(state) = self.connection_states.get(&relay_id).copied() else {
            return;
        };
        if matches!(state, RelayConnectionState::Reserved) {
            tracing::info!(
                relay_peer_id = %relay_id,
                listen_addr = %addr,
                "Relay circuit listener expired; demoting to Established"
            );
            self.set_relay_state(relay_id, RelayConnectionState::Established);
            self.events.push_back(ToSwarm::GenerateEvent(
                RelayManagerEvent::RelayReservationLost(relay_id),
            ));
            // The reserved-relay set just shrank: drop or refresh any peer
            // dial campaigns routed through this relay so they don't keep
            // self-rearming through dead circuits.
            self.refresh_peer_dials();
        }
    }

    /// Reacts to the last connection to `peer_id` closing. Either it's one of
    /// our relays (queue a fresh re-dial cycle) or a known cluster peer
    /// (arm a fresh routing dial through the current reserved relays).
    /// Anything else is ignored.
    ///
    /// If the relay was previously in `Reserved`, `RelayReservationLost` is
    /// emitted before `RelayDisconnected` so subscribers see the reservation
    /// tear down explicitly, and the peer routing campaigns through this
    /// relay are refreshed to drop now-dead circuits.
    fn on_connection_closed(&mut self, peer_id: PeerId) {
        if let Some(prev_state) = self.connection_states.get(&peer_id).copied() {
            let was_reserved = matches!(prev_state, RelayConnectionState::Reserved);
            if was_reserved {
                self.events.push_back(ToSwarm::GenerateEvent(
                    RelayManagerEvent::RelayReservationLost(peer_id),
                ));
            }
            self.events.push_back(ToSwarm::GenerateEvent(
                RelayManagerEvent::RelayDisconnected(peer_id),
            ));
            self.redial_relay(peer_id);
            if was_reserved {
                self.refresh_peer_dials();
            }
        } else if self.p2p_context.is_known_peer(&peer_id) {
            self.reroute_peer(peer_id);
        }
    }

    /// Reacts to a dial failure by logging and emitting a `DialFailed` event.
    /// The underlying `RelayDialState` self-rearms with exponential backoff
    /// on the next swarm poll, so by default no state change is needed here.
    ///
    /// One special case: `DialError::DialPeerConditionFalse` means libp2p
    /// refused the dial because we're already connected to (or dialing) the
    /// target. Behaviour depends on the dial type:
    ///
    /// - [`RelayDialType::ClusterPeer`]: libp2p owns the existing direct
    ///   connection. Drop the dial state and rely on
    ///   [`Self::on_connection_closed`] → [`Self::reroute_peer`] to re-arm the
    ///   dial once the existing connection actually closes.
    /// - [`RelayDialType::RelayServer`]: dropping the dial state here would
    ///   wedge `connection_states` in `Dialing` forever — no
    ///   `on_connection_closed` will fire if libp2p already has the transport
    ///   connection, and `queue_relay_update` short-circuits while
    ///   `connection_states` has an entry. Instead leave the campaign armed;
    ///   backoff retries are cheap (libp2p re-rejects with the same error) and
    ///   `on_connection_established` will tear the dial state down once libp2p
    ///   surfaces the connection.
    fn on_dial_failure(&mut self, peer_id: Option<PeerId>, error: &DialError) {
        let Some(peer_id) = peer_id else { return };
        let Some(state) = self.dial_states.get(&peer_id) else {
            return;
        };
        let target = state.ty;
        let retry_count = state.retry_count;
        let skipped = matches!(error, DialError::DialPeerConditionFalse(_));

        if skipped {
            match target {
                RelayDialType::ClusterPeer => {
                    tracing::debug!(
                        peer_id = %peer_id,
                        dial_type = ?target,
                        retry_count,
                        %error,
                        "Dial skipped (already connected or dialing); dropping dial state"
                    );
                    self.dial_states.remove(&peer_id);
                }
                RelayDialType::RelayServer => {
                    tracing::debug!(
                        peer_id = %peer_id,
                        dial_type = ?target,
                        retry_count,
                        %error,
                        "Dial skipped for relay; keeping campaign armed for backoff retry"
                    );
                }
            }
        } else {
            tracing::debug!(
                peer_id = %peer_id,
                dial_type = ?target,
                retry_count,
                %error,
                "Dial failed, will retry with backoff"
            );
        }

        self.events
            .push_back(ToSwarm::GenerateEvent(RelayManagerEvent::DialFailed {
                peer_id,
                target,
                retry_count,
                error: RelayDialError::from(error),
            }));
    }

    /// Schedules a re-dial for a relay whose last connection just dropped.
    fn redial_relay(&mut self, relay_id: PeerId) {
        let Some(addrs) = self.relay_addrs.get(&relay_id).cloned() else {
            tracing::warn!(
                relay_peer_id = %relay_id,
                "Relay closed but addresses no longer tracked; cannot redial"
            );
            self.connection_states.remove(&relay_id);
            return;
        };
        tracing::debug!(
            relay_peer_id = %relay_id,
            "Relay connection closed, queuing re-dial with backoff"
        );
        self.dial_states.insert(
            relay_id,
            RelayDialState::new(RelayDialType::RelayServer, relay_id, addrs),
        );
        self.set_relay_state(relay_id, RelayConnectionState::Dialing);
    }

    /// Arms a dial campaign for a known cluster peer whose last connection
    /// just dropped, routing through all currently reserved relays. Delegates
    /// to [`Self::upsert_peer_dial`] so that an existing dial state with the
    /// same circuit addrs survives — its backoff schedule is preserved across
    /// rapid disconnect/reconnect cycles when the route hasn't changed. No-op
    /// if no relay is currently reserved.
    fn reroute_peer(&mut self, peer_id: PeerId) {
        tracing::debug!(
            peer_id = %peer_id,
            "Peer connection closed, re-routing via reserved relays"
        );
        self.upsert_peer_dial(peer_id);
    }
}

impl NetworkBehaviour for RelayManager {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = RelayManagerEvent;

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
        match event {
            FromSwarm::ConnectionEstablished(conn) => {
                self.on_connection_established(conn.peer_id);
            }
            FromSwarm::NewListenAddr(ev) => {
                self.on_new_listen_addr(ev.addr);
            }
            FromSwarm::ExpiredListenAddr(ev) => {
                self.on_expired_listen_addr(ev.addr);
            }
            FromSwarm::ConnectionClosed(conn) if conn.remaining_established == 0 => {
                self.on_connection_closed(conn.peer_id);
            }
            FromSwarm::DialFailure(ev) => {
                self.on_dial_failure(ev.peer_id, ev.error);
            }
            _ => {}
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
        cx: &mut Context<'_>,
    ) -> std::task::Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        let mut updates: Vec<Peer> = Vec::new();
        for stream in &mut self.relay_subs {
            while let Poll::Ready(Some(Some(peer))) = stream.poll_next_unpin(cx) {
                updates.push(peer);
            }
        }
        for peer in updates {
            self.queue_relay_update(peer);
        }

        self.process_relay_dials(cx);
        self.process_established_watchdog(cx);

        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}
