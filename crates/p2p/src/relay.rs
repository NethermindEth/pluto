//! Relay reservation and routing.
//!
//! [`RelayBehaviour`] is a single [`NetworkBehaviour`] that, for each relay
//! configured via [`crate::peer::MutablePeer`]:
//!
//! 1. Dials the relay server and listens on the corresponding `/p2p-circuit`
//!    addresses so other peers can reach us through the relay.
//! 2. Awaits the relay client's
//!    [`relay::client::Event::ReservationReqAccepted`] event before considering
//!    the relay usable for routing. The libp2p relay client takes care of
//!    renewing the reservation; we just react to the confirmation events it
//!    emits.
//! 3. Provides circuit multiaddrs for known cluster peers, both proactively
//!    (periodic [`ToSwarm::Dial`] so addresses are present in libp2p's caches)
//!    and on demand via
//!    [`NetworkBehaviour::handle_pending_outbound_connection`] for callers that
//!    opt into address extension.
//! 4. Handles disconnects, dial failures, and reservation refusals with
//!    exponential backoff matching Charon's `expbackoff.DefaultConfig`.
//!
//! Watch updates from [`MutablePeer`] flow into the behaviour through a
//! [`tokio_stream::wrappers::WatchStream`], so address changes wake the swarm
//! immediately rather than being polled lazily.
//!
//! ## Wiring `relay::client::Event`
//!
//! Reservation acceptance is signalled by [`relay::client::Event`], which is
//! emitted by a sibling behaviour (the libp2p relay client). The parent swarm
//! event loop must forward those events into
//! [`RelayBehaviour::on_relay_client_event`]; without that, the behaviour can
//! never reach `Reserved`.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    task::{Context, Poll},
    time::Duration,
};

use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId,
    core::{
        Endpoint,
        transport::{ListenerId, PortUse},
    },
    multiaddr::Protocol as MaProtocol,
    relay,
    swarm::{
        ConnectionDenied, ConnectionId, DialError, FromSwarm, ListenOpts, NetworkBehaviour,
        THandler, THandlerInEvent, ToSwarm,
        dial_opts::{DialOpts, PeerCondition},
        dummy,
    },
};
use tokio_stream::{StreamMap, wrappers::WatchStream};
use tokio_util::time::{DelayQueue, delay_queue};
use tracing::{debug, info, trace, warn};

use crate::{
    p2p_context::P2PContext,
    peer::{MutablePeer, Peer},
    utils,
};

// ── Defaults ────────────────────────────────────────────────────────────────

/// Default initial backoff before the first retry. Matches Charon
/// `expbackoff.DefaultConfig.BaseDelay`.
pub const DEFAULT_BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Default upper bound on retry backoff. Matches Charon
/// `expbackoff.DefaultConfig.MaxDelay`.
pub const DEFAULT_BACKOFF_MAX: Duration = Duration::from_secs(120);
/// Default backoff growth factor. Matches Charon's default of 1.6.
pub const DEFAULT_BACKOFF_FACTOR: f64 = 1.6;
/// Default jitter applied to backoff delays. Matches Charon's 0.2.
pub const DEFAULT_BACKOFF_JITTER: f64 = 0.2;
/// Default period for re-emitting circuit dials to known peers via every
/// reserved relay. Keeps libp2p's address caches warm for peers that are
/// otherwise unreachable directly.
pub const DEFAULT_ROUTER_INTERVAL: Duration = Duration::from_secs(60);

// ── Configuration ───────────────────────────────────────────────────────────

/// Tunables for [`RelayBehaviour`].
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Initial backoff between retry attempts.
    pub backoff_base: Duration,
    /// Maximum backoff between retry attempts.
    pub backoff_max: Duration,
    /// Backoff growth factor per retry attempt.
    pub backoff_factor: f64,
    /// Jitter fraction applied to backoff (`±jitter * delay`).
    pub backoff_jitter: f64,
    /// How often to re-advertise circuit addresses by dialling known peers.
    pub router_interval: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            backoff_base: DEFAULT_BACKOFF_BASE,
            backoff_max: DEFAULT_BACKOFF_MAX,
            backoff_factor: DEFAULT_BACKOFF_FACTOR,
            backoff_jitter: DEFAULT_BACKOFF_JITTER,
            router_interval: DEFAULT_ROUTER_INTERVAL,
        }
    }
}

// ── State machine ───────────────────────────────────────────────────────────

/// Per-relay state machine.
///
/// Each variant carries the data needed only in that state — illegal
/// combinations (e.g. "in backoff without a timer") are not representable.
#[derive(Debug)]
enum Phase {
    /// Address known but no dial issued yet.
    Idle,
    /// Outbound dial in flight.
    Dialing,
    /// TCP/QUIC connected; awaiting `ReservationReqAccepted`.
    Connected,
    /// Reservation confirmed by the relay server. The libp2p relay client
    /// takes care of renewals from here.
    Reserved,
    /// Waiting for the retry timer to fire.
    Backoff { retry_key: delay_queue::Key },
}

#[derive(Debug)]
struct RelayState {
    /// Last value seen on the watch (relay address etc.).
    peer: Peer,
    phase: Phase,
    /// Number of consecutive failures (resets on `Reserved`).
    retry_count: u32,
    /// Listener IDs for circuit listeners we opened on this relay. Kept open
    /// across reconnect attempts; the libp2p relay client uses them to
    /// re-issue reservations transparently.
    listeners: Vec<ListenerId>,
}

#[derive(Debug, Clone, Copy)]
enum TimerKey {
    /// Fire a retry dial for this relay.
    Retry(PeerId),
    /// Re-emit dials for known peers across all reserved relays.
    RouterTick,
}

// ── Public events ───────────────────────────────────────────────────────────

/// Lifecycle events emitted by [`RelayBehaviour`].
#[derive(Debug, Clone)]
pub enum RelayEvent {
    /// Relay reservation has been confirmed; we are reachable through this
    /// relay.
    Ready {
        /// Peer ID of the relay whose reservation is now active.
        peer: PeerId,
    },
    /// Reservation or relay connection was lost; the behaviour will attempt
    /// to re-establish it with backoff.
    Lost {
        /// Peer ID of the relay whose reservation/connection ended.
        peer: PeerId,
    },
    /// A dial or reservation attempt failed; backoff is now in effect.
    Failed {
        /// Peer ID of the relay whose dial failed.
        peer: PeerId,
        /// Zero-based attempt count of the failed dial.
        attempt: u32,
    },
}

// ── Behaviour ───────────────────────────────────────────────────────────────

/// Combined relay reservation and circuit-routing behaviour.
///
/// See the module-level docs for an overview.
pub struct RelayBehaviour {
    /// Per-relay state, keyed by the relay's [`PeerId`] once known.
    relays: HashMap<PeerId, RelayState>,
    /// Address-update streams keyed by the original relay slot index.
    /// Streams live here rather than under the relay's `PeerId` because a
    /// relay's identity is not known until the first watch update.
    addr_updates: StreamMap<usize, WatchStream<Option<Peer>>>,
    /// Maps a relay slot index to the most recently observed peer ID, so we
    /// can route updates into [`Self::relays`].
    slot_to_peer: HashMap<usize, PeerId>,
    /// Combined retry / router timer.
    timers: DelayQueue<TimerKey>,
    /// Pending swarm events.
    events: VecDeque<ToSwarm<RelayEvent, Infallible>>,
    /// Shared P2P context (used by the router half to look up known peers).
    ctx: P2PContext,
    /// Local peer ID — never returned as a routing target.
    local: PeerId,
    /// Behaviour tunables.
    cfg: RelayConfig,
    /// Key for the periodic router tick, if scheduled.
    router_tick: Option<delay_queue::Key>,
}

impl std::fmt::Debug for RelayBehaviour {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayBehaviour")
            .field("relays", &self.relays)
            .field("local", &self.local)
            .field("cfg", &self.cfg)
            .finish()
    }
}

impl RelayBehaviour {
    /// Creates a new relay behaviour with default configuration.
    pub fn new(relays: Vec<MutablePeer>, ctx: P2PContext, local: PeerId) -> Self {
        Self::with_config(relays, ctx, local, RelayConfig::default())
    }

    /// Creates a new relay behaviour with the given configuration.
    pub fn with_config(
        relays: Vec<MutablePeer>,
        ctx: P2PContext,
        local: PeerId,
        cfg: RelayConfig,
    ) -> Self {
        let mut this = Self {
            relays: HashMap::new(),
            addr_updates: StreamMap::new(),
            slot_to_peer: HashMap::new(),
            timers: DelayQueue::new(),
            events: VecDeque::new(),
            ctx,
            local,
            cfg,
            router_tick: None,
        };

        for (slot, mp) in relays.into_iter().enumerate() {
            // `from_changes` skips the initial value so we can seed it
            // explicitly via `current()` below.
            let stream = WatchStream::from_changes(mp.subscribe());
            this.addr_updates.insert(slot, stream);

            if let Some(peer) = mp.current() {
                this.handle_addr_resolved(slot, peer);
            }
        }

        this.schedule_router_tick();
        this
    }

    /// Forwards a [`relay::client::Event`] from the parent compound behaviour
    /// into this state machine.
    ///
    /// The reservation lifecycle is driven exclusively by these events;
    /// without forwarding, the behaviour can never reach `Reserved` and will
    /// never advertise circuit addresses to peers. Takes the event by
    /// reference because [`relay::client::Event`] does not implement `Clone`.
    pub fn on_relay_client_event(&mut self, event: &relay::client::Event) {
        match event {
            relay::client::Event::ReservationReqAccepted { relay_peer_id, .. } => {
                self.handle_reservation_accepted(*relay_peer_id);
            }
            // Per-circuit events (peer-to-peer through us) — not part of the
            // reservation lifecycle. Nothing to do here.
            relay::client::Event::OutboundCircuitEstablished { .. }
            | relay::client::Event::InboundCircuitEstablished { .. } => {}
        }
    }

    // ── Address-update path ────────────────────────────────────────────────

    /// Handles the first or an updated value on a relay's watch.
    fn handle_addr_resolved(&mut self, slot: usize, peer: Peer) {
        let new_id = peer.id;

        // Detect "the relay's identity changed" (rare in practice; treat the
        // previous one as gone so we don't leak state).
        if let Some(prev) = self.slot_to_peer.insert(slot, new_id)
            && prev != new_id
        {
            self.drop_relay(prev);
        }

        let entry_existed = self.relays.contains_key(&new_id);

        let state = self.relays.entry(new_id).or_insert_with(|| RelayState {
            peer: peer.clone(),
            phase: Phase::Idle,
            retry_count: 0,
            listeners: Vec::new(),
        });
        state.peer = peer;

        if !entry_existed {
            self.dial(new_id);
        } else if matches!(self.relays[&new_id].phase, Phase::Backoff { .. }) {
            // Address change while waiting to retry → cancel backoff and try
            // the new address now.
            self.cancel_backoff(new_id);
            self.dial(new_id);
        }
        // For Idle/Dialing/Connected/Reserved: keep the current attempt
        // running with the freshest stored address; future re-dials pick it
        // up automatically.
    }

    // ── Phase transitions ──────────────────────────────────────────────────

    fn dial(&mut self, peer_id: PeerId) {
        let Some(state) = self.relays.get_mut(&peer_id) else {
            return;
        };
        let dial_addrs = relay_dial_addrs(&state.peer);

        state.phase = Phase::Dialing;

        if !dial_addrs.is_empty() {
            self.events.push_back(ToSwarm::Dial {
                opts: DialOpts::peer_id(peer_id)
                    .condition(PeerCondition::DisconnectedAndNotDialing)
                    .addresses(dial_addrs)
                    .build(),
            });
        }

        debug!(relay_peer_id = %peer_id, "Dialing relay");
    }

    /// Opens circuit listeners for `peer_id`, but only if none exist yet.
    ///
    /// Must be called only after a TCP/QUIC connection to the relay is
    /// established — listening on a circuit address before the connection is
    /// up gives the relay client nothing to send the HOP reservation request
    /// over, and the listener never produces a reservation. We keep listeners
    /// through reconnects: the libp2p relay client re-issues the reservation
    /// automatically when the underlying connection comes back.
    fn ensure_circuit_listeners(&mut self, peer_id: PeerId) {
        let Some(state) = self.relays.get_mut(&peer_id) else {
            return;
        };
        if !state.listeners.is_empty() {
            return;
        }
        let circuit_addrs = circuit_listen_addrs(&state.peer);
        for circuit_addr in circuit_addrs {
            let opts = ListenOpts::new(circuit_addr);
            state.listeners.push(opts.listener_id());
            self.events.push_back(ToSwarm::ListenOn { opts });
        }
    }

    fn handle_reservation_accepted(&mut self, peer_id: PeerId) {
        let Some(state) = self.relays.get_mut(&peer_id) else {
            return;
        };
        let was_reserved = matches!(state.phase, Phase::Reserved);
        state.phase = Phase::Reserved;
        state.retry_count = 0;

        if !was_reserved {
            info!(relay_peer_id = %peer_id, "Relay reservation ready");
            self.events
                .push_back(ToSwarm::GenerateEvent(RelayEvent::Ready { peer: peer_id }));
            // Now that the relay is usable, advertise circuit addresses for
            // known peers immediately rather than waiting for the next
            // router tick. Some of these dials will fail because the target
            // peer has not reserved its own circuit yet — the swarm-event
            // handler classifies those as expected and logs them at debug.
            self.advertise_known_peers_via(peer_id);
        }
    }

    fn schedule_retry(&mut self, peer_id: PeerId) {
        let Some(state) = self.relays.get_mut(&peer_id) else {
            return;
        };
        // Idempotent: if we're already in Backoff, leave the existing timer.
        if matches!(state.phase, Phase::Backoff { .. }) {
            return;
        }
        let attempt = state.retry_count;
        state.retry_count = state.retry_count.saturating_add(1);

        let delay = backoff_delay(&self.cfg, attempt);
        let key = self.timers.insert(TimerKey::Retry(peer_id), delay);
        state.phase = Phase::Backoff { retry_key: key };

        debug!(relay_peer_id = %peer_id, ?delay, attempt, "Scheduling relay re-dial");
        self.events
            .push_back(ToSwarm::GenerateEvent(RelayEvent::Failed {
                peer: peer_id,
                attempt,
            }));
    }

    fn cancel_backoff(&mut self, peer_id: PeerId) {
        if let Some(state) = self.relays.get_mut(&peer_id)
            && let Phase::Backoff { retry_key } = &state.phase
        {
            let key = *retry_key;
            self.timers.try_remove(&key);
            state.phase = Phase::Idle;
        }
    }

    fn drop_relay(&mut self, peer_id: PeerId) {
        let Some(state) = self.relays.remove(&peer_id) else {
            return;
        };
        for id in state.listeners {
            self.events.push_back(ToSwarm::RemoveListener { id });
        }
        if let Phase::Backoff { retry_key } = state.phase {
            self.timers.try_remove(&retry_key);
        }
        self.events
            .push_back(ToSwarm::GenerateEvent(RelayEvent::Lost { peer: peer_id }));
    }

    // ── Router half ────────────────────────────────────────────────────────

    fn schedule_router_tick(&mut self) {
        if let Some(prev) = self.router_tick.take() {
            self.timers.try_remove(&prev);
        }
        self.router_tick = Some(
            self.timers
                .insert(TimerKey::RouterTick, self.cfg.router_interval),
        );
    }

    fn run_router_tick(&mut self) {
        let reserved: Vec<PeerId> = self
            .relays
            .iter()
            .filter(|(_, s)| matches!(s.phase, Phase::Reserved))
            .map(|(id, _)| *id)
            .collect();
        for relay_id in reserved {
            self.advertise_known_peers_via(relay_id);
        }
        self.schedule_router_tick();
    }

    fn advertise_known_peers_via(&mut self, relay_id: PeerId) {
        let Some(state) = self.relays.get(&relay_id) else {
            return;
        };
        let relay_peer = state.peer.clone();
        let peers: Vec<PeerId> = self
            .ctx
            .known_peers()
            .iter()
            .copied()
            .filter(|p| *p != self.local)
            .collect();
        for target in peers {
            let addrs = utils::multi_addrs_via_relay(&relay_peer, &target);
            if addrs.is_empty() {
                continue;
            }
            self.events.push_back(ToSwarm::Dial {
                opts: DialOpts::peer_id(target)
                    .condition(PeerCondition::DisconnectedAndNotDialing)
                    .addresses(addrs)
                    .build(),
            });
        }
    }

    // ── Timer dispatch ─────────────────────────────────────────────────────

    fn fire_timer(&mut self, key: TimerKey) {
        match key {
            TimerKey::Retry(peer) => {
                // Only act if we're still in Backoff. If the relay reconnected
                // on its own (e.g. through the circuit listener) we'd already
                // be in Connected/Reserved and re-dialing would be rejected by
                // the swarm with `DialPeerConditionFalse`.
                if let Some(state) = self.relays.get(&peer)
                    && matches!(state.phase, Phase::Backoff { .. })
                {
                    self.dial(peer);
                }
            }
            TimerKey::RouterTick => {
                self.router_tick = None;
                self.run_router_tick();
            }
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn relay_dial_addrs(peer: &Peer) -> Vec<Multiaddr> {
    peer.addresses
        .iter()
        .map(|addr| {
            let transport: Multiaddr = addr
                .iter()
                .filter(|p| !matches!(p, MaProtocol::P2p(_)))
                .collect();
            transport.with(MaProtocol::P2p(peer.id))
        })
        .collect()
}

fn circuit_listen_addrs(peer: &Peer) -> Vec<Multiaddr> {
    peer.addresses
        .iter()
        .map(|addr| {
            let transport: Multiaddr = addr
                .iter()
                .filter(|p| !matches!(p, MaProtocol::P2p(_)))
                .collect();
            transport
                .with(MaProtocol::P2p(peer.id))
                .with(MaProtocol::P2pCircuit)
        })
        .collect()
}

/// Computes the exponential backoff delay for a given retry attempt.
///
/// `retry_count == 0` returns the base delay with no jitter (matching
/// Charon's `expbackoff` early-return path); subsequent attempts apply
/// `backoff_factor^retry_count`, cap at `backoff_max`, then add ±jitter.
fn backoff_delay(cfg: &RelayConfig, retry_count: u32) -> Duration {
    if retry_count == 0 {
        return cfg.backoff_base;
    }
    let base = cfg.backoff_base.as_secs_f64();
    let max = cfg.backoff_max.as_secs_f64();
    let raw = base * cfg.backoff_factor.powi(retry_count.cast_signed());
    let capped = raw.min(max);
    let jitter = 1.0 + cfg.backoff_jitter * (rand::random::<f64>() * 2.0 - 1.0);
    Duration::from_secs_f64((capped * jitter).max(0.0))
}

// ── NetworkBehaviour ────────────────────────────────────────────────────────

impl NetworkBehaviour for RelayBehaviour {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = RelayEvent;

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

    /// Provides circuit-via-relay addresses for outbound dials of known
    /// peers. Only callers that opt in via
    /// `extend_addresses_through_behaviour` will receive these.
    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let Some(target) = maybe_peer else {
            return Ok(Vec::new());
        };
        if target == self.local || !self.ctx.is_known_peer(&target) {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut seen: HashSet<Multiaddr> = HashSet::new();
        for state in self.relays.values() {
            if !matches!(state.phase, Phase::Reserved) {
                continue;
            }
            for addr in utils::multi_addrs_via_relay(&state.peer, &target) {
                if seen.insert(addr.clone()) {
                    out.push(addr);
                }
            }
        }
        Ok(out)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(c) => {
                if let Some(state) = self.relays.get_mut(&c.peer_id) {
                    debug!(relay_peer_id = %c.peer_id, "Relay connection established");
                    // Cancel any pending retry — libp2p reconnected (possibly
                    // on its own through the circuit listener) so the queued
                    // retry would now race with the live connection.
                    if let Phase::Backoff { retry_key } = &state.phase {
                        let key = *retry_key;
                        self.timers.try_remove(&key);
                    }
                    state.phase = Phase::Connected;
                    // Now that the underlying connection is up, open the
                    // circuit listener so the relay client can negotiate a
                    // HOP reservation over it. Reservation acceptance follows
                    // via `relay::client::Event::ReservationReqAccepted`.
                    self.ensure_circuit_listeners(c.peer_id);
                }
            }
            FromSwarm::ConnectionClosed(c)
                if c.remaining_established == 0 && self.relays.contains_key(&c.peer_id) =>
            {
                debug!(relay_peer_id = %c.peer_id, "Relay connection closed");
                self.events
                    .push_back(ToSwarm::GenerateEvent(RelayEvent::Lost { peer: c.peer_id }));
                self.schedule_retry(c.peer_id);
            }
            FromSwarm::DialFailure(ev) => {
                if let Some(peer_id) = ev.peer_id
                    && self.relays.contains_key(&peer_id)
                {
                    // `DialPeerConditionFalse` means the swarm skipped our
                    // dial because the peer is already connected or a dial
                    // is in flight — not a failure. Treating it as one would
                    // create a retry loop where every fired retry re-races
                    // with the live connection.
                    if matches!(ev.error, DialError::DialPeerConditionFalse(_)) {
                        trace!(
                            relay_peer_id = %peer_id,
                            "Relay dial skipped: already connected or dialing"
                        );
                    } else {
                        warn!(relay_peer_id = %peer_id, error = %ev.error, "Relay dial failed");
                        self.schedule_retry(peer_id);
                    }
                }
            }
            FromSwarm::ListenerError(ev) => {
                trace!(listener_id = ?ev.listener_id, "Relay listener error");
            }
            FromSwarm::ListenerClosed(ev) => {
                trace!(listener_id = ?ev.listener_id, "Relay listener closed");
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
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            if let Some(ev) = self.events.pop_front() {
                return Poll::Ready(ev);
            }

            if let Poll::Ready(Some(expired)) = self.timers.poll_expired(cx) {
                self.fire_timer(expired.into_inner());
                continue;
            }

            if let Poll::Ready(Some((slot, maybe_peer))) = self.addr_updates.poll_next_unpin(cx) {
                if let Some(peer) = maybe_peer {
                    self.handle_addr_resolved(slot, peer);
                }
                continue;
            }

            return Poll::Pending;
        }
    }
}
