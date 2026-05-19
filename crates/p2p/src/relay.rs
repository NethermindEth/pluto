//! Relay reservation and cluster-peer routing.
//!
//! [`RelayManager`] is a libp2p [`NetworkBehaviour`] with three
//! responsibilities:
//!
//! 1. Subscribe to [`MutablePeer`] watch channels to receive relay address
//!    updates as they're discovered.
//! 2. Manage each relay's reservation lifecycle (`Dialing → Established →
//!    Reserved`) and redial with exponential backoff when transport connections
//!    drop.
//! 3. Route known cluster peers through reserved relay circuits so peer-to-peer
//!    traffic can traverse NATs that would otherwise block direct dials.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use crate::{
    p2p_context::P2PContext,
    peer::{MutablePeer, Peer},
};
use futures::{Stream, stream::StreamExt};
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    multiaddr::Protocol as MaProtocol,
    swarm::{
        ConnectionDenied, ConnectionId, DialError, FromSwarm, NetworkBehaviour, THandler,
        THandlerInEvent, ToSwarm, dial_opts::DialOpts, dummy,
    },
};
use tokio::time::{Instant, Sleep, sleep_until};
use tokio_stream::wrappers::WatchStream;

/// Initial backoff delay before the first reconnect attempt. Matches Charon's
/// `DefaultConfig.BaseDelay`.
const RELAY_BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Maximum backoff delay between reconnect attempts. Matches Charon's
/// `DefaultConfig.MaxDelay`.
const RELAY_BACKOFF_MAX: Duration = Duration::from_secs(120);
/// Jitter factor applied to backoff delays. Matches Charon's
/// `DefaultConfig.Jitter`.
const RELAY_BACKOFF_JITTER: f64 = 0.2;

/// How long a relay may stay in `Established` (transport connected, no
/// reservation yet) before the watchdog force-closes the transport so a fresh
/// dial campaign can recover. Mirrors Charon's "no relay connection,
/// reconnecting" path (`charon/p2p/relay.go:73-92`).
const ESTABLISHED_STUCK_THRESHOLD: Duration = Duration::from_secs(60);
/// How often the watchdog re-evaluates stuck-in-Established relays.
const ESTABLISHED_WATCHDOG_TICK: Duration = Duration::from_secs(15);

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

/// Events emitted by [`RelayManager`] to the swarm.
///
/// Mirrors the relay lifecycle (`Dialing → Established → Reserved`) plus the
/// outcomes of routing known cluster peers through reserved circuits. Consumers
/// can observe the full progression of a reservation, or pick out just the
/// events they care about (e.g. `RelayReserved` for "circuits are usable now").
#[derive(Debug)]
pub enum RelayManagerEvent {
    /// Transport connection to a relay is up. A circuit listener has been
    /// requested but the reservation is not yet confirmed.
    RelayConnected(PeerId),
    /// Relay accepted the reservation; circuits through this relay are now
    /// usable for routing cluster peers.
    RelayReserved(PeerId),
    /// Circuit listener for this relay expired; the relay has been demoted to
    /// `Established`. libp2p's circuit client typically refreshes the
    /// reservation shortly, which will re-emit `RelayReserved`.
    RelayReservationLost(PeerId),
    /// Last transport connection to the relay closed. A re-dial campaign with
    /// exponential backoff has been queued.
    RelayDisconnected(PeerId),
    /// A cluster peer has been reached through one of the reserved relay
    /// circuits. From here libp2p owns the connection; this event exists for
    /// telemetry only.
    PeerRoutedConnected(PeerId),
    /// A dial attempt failed. The underlying [`RelayDialState`] self-rearms
    /// with exponential backoff, so consumers don't need to take any action.
    DialFailed {
        /// Target peer id (a relay server, or a routed cluster peer).
        peer_id: PeerId,
        /// Whether this dial was targeting a relay or a routed peer.
        target: RelayDialType,
        /// Number of attempts so far (including this one).
        retry_count: u32,
        /// Categorised dial error.
        error: RelayDialError,
    },
}

/// Categorised dial error surfaced via [`RelayManagerEvent::DialFailed`].
///
/// Translated from libp2p's [`DialError`] so consumers can match on variants
/// without depending on libp2p's swarm types directly. Free-form details are
/// preserved as strings on the variants where they carry diagnostic value.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RelayDialError {
    /// Attempted to dial our own peer id.
    #[error("local peer id")]
    LocalPeerId,
    /// No transport addresses were available for the target.
    #[error("no addresses")]
    NoAddresses,
    /// Dial was skipped because of a peer condition (already
    /// connected/dialing).
    #[error("dial skipped: peer condition not met")]
    Skipped,
    /// Pending connection attempt was aborted (e.g. swarm shutdown, or a newer
    /// dial superseded it).
    #[error("aborted")]
    Aborted,
    /// Connected, but the remote reported a peer id different from the
    /// expected one.
    #[error("wrong peer id")]
    WrongPeerId,
    /// Connection was denied by a behaviour or upgrade step.
    #[error("denied: {0}")]
    Denied(String),
    /// All transport attempts failed; details preserved as `addr: err`,
    /// joined by `; `.
    #[error("transport: {0}")]
    Transport(String),
}

impl From<&DialError> for RelayDialError {
    fn from(err: &DialError) -> Self {
        match err {
            DialError::LocalPeerId { .. } => Self::LocalPeerId,
            DialError::NoAddresses => Self::NoAddresses,
            DialError::DialPeerConditionFalse(_) => Self::Skipped,
            DialError::Aborted => Self::Aborted,
            DialError::WrongPeerId { .. } => Self::WrongPeerId,
            DialError::Denied { cause } => Self::Denied(cause.to_string()),
            DialError::Transport(errors) => Self::Transport(
                errors
                    .iter()
                    .map(|(addr, e)| format!("{addr}: {e}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
        }
    }
}

/// Whether a [`RelayDialState`] is targeting a relay server or a cluster peer
/// reached through reserved relay circuits.
#[derive(Debug, Clone, Copy)]
pub enum RelayDialType {
    /// Dial a known cluster peer via reserved relay circuits.
    ClusterPeer,
    /// Dial a relay server directly.
    RelayServer,
}

/// State of an in-flight dial campaign, polled to produce a `ToSwarm::Dial`
/// event each time its backoff elapses.
struct RelayDialState {
    /// Kind of target this campaign is dialing.
    ty: RelayDialType,
    /// Target peer id for the dial.
    peer_id: PeerId,
    /// Transport (for `RelayServer`) or circuit (for `ClusterPeer`) addresses
    /// to try.
    addrs: Vec<Multiaddr>,
    /// Number of dial attempts so far, used to compute the next backoff.
    retry_count: u32,
    /// Sleeps until the next dial is due. Boxed-and-pinned so the struct stays
    /// `Unpin` and can be stored in a `HashMap`; the inner `Sleep` is `!Unpin`.
    sleep: Pin<Box<Sleep>>,
}

impl RelayDialState {
    /// Creates a fresh dial state armed to fire after the base backoff.
    fn new(ty: RelayDialType, peer_id: PeerId, addrs: Vec<Multiaddr>) -> Self {
        Self {
            ty,
            peer_id,
            addrs,
            retry_count: 0,
            sleep: Box::pin(sleep_until(Instant::now())),
        }
    }
}

/// Lifecycle of a relay reservation.
///
/// - `Dialing`: a [`RelayDialState`] is in flight; no transport connection to
///   the relay yet.
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

impl Stream for RelayDialState {
    type Item = ToSwarm<RelayManagerEvent, Infallible>;

    /// Drives the dial schedule. Yields a `Dial` event when the next attempt
    /// is due, then self-rearms with an exponential backoff so subsequent
    /// `poll_next` calls produce later retries. The stream never terminates.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        std::task::ready!(self.sleep.as_mut().poll(cx));

        let next_delay = backoff_delay(self.retry_count);
        self.retry_count = self.retry_count.saturating_add(1);
        let next_deadline = Instant::now()
            .checked_add(next_delay)
            .unwrap_or_else(Instant::now);
        self.sleep.as_mut().reset(next_deadline);

        let opts = DialOpts::peer_id(self.peer_id)
            .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
            .addresses(self.addrs.clone())
            .build();

        Poll::Ready(Some(ToSwarm::Dial { opts }))
    }
}

/// Returns true if both slices contain the same multiaddrs (order-independent).
/// Used to decide whether a routing refresh actually expanded the available
/// circuit paths to a peer — if it did, the dial state's backoff is reset.
fn addr_sets_equal(a: &[Multiaddr], b: &[Multiaddr]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let a_set: HashSet<&Multiaddr> = a.iter().collect();
    b.iter().all(|x| a_set.contains(x))
}

/// Exponential backoff delay for a given retry count.
///
/// Mirrors Charon's `expbackoff.DefaultConfig`: base=1s, multiplier=1.6,
/// jitter=0.2, max=120s. `retry_count == 0` returns the base delay with no
/// jitter, matching Go's early-return path. For `retry_count > 0`, ±20%
/// jitter is applied after capping so nodes don't retry in lockstep.
fn backoff_delay(retry_count: u32) -> Duration {
    if retry_count == 0 {
        return RELAY_BACKOFF_BASE;
    }
    let mut delay = RELAY_BACKOFF_BASE.as_secs_f64();
    let max = RELAY_BACKOFF_MAX.as_secs_f64();
    for _ in 0..retry_count {
        delay *= 1.6;
        if delay >= max {
            delay = max;
            break;
        }
    }
    let rand_val = rand::random::<f64>();
    delay *= 1.0 + RELAY_BACKOFF_JITTER * (rand_val * 2.0 - 1.0);
    if delay < 0.0 {
        return Duration::ZERO;
    }
    Duration::from_secs_f64(delay)
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
    /// The underlying [`RelayDialState`] self-rearms with exponential backoff
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn addr(s: &str) -> Multiaddr {
        Multiaddr::from_str(s).expect("valid multiaddr")
    }

    fn manager() -> RelayManager {
        RelayManager::new(Vec::new(), P2PContext::new(Vec::<PeerId>::new()))
    }

    // ---- circuit_addrs -------------------------------------------------

    #[test]
    fn circuit_addrs_strips_existing_p2p_and_appends_relay_suffix() {
        let relay = PeerId::random();
        let transport = addr(&format!("/ip4/127.0.0.1/tcp/9000/p2p/{relay}"));

        let out = RelayManager::circuit_addrs(relay, &[transport]);

        let expected = addr(&format!("/ip4/127.0.0.1/tcp/9000/p2p/{relay}/p2p-circuit"));
        assert_eq!(out, vec![expected]);
    }

    #[test]
    fn circuit_addrs_handles_addr_without_existing_p2p_component() {
        let relay = PeerId::random();
        let transport = addr("/ip4/10.0.0.1/udp/9000/quic-v1");

        let out = RelayManager::circuit_addrs(relay, &[transport]);

        let expected = addr(&format!(
            "/ip4/10.0.0.1/udp/9000/quic-v1/p2p/{relay}/p2p-circuit"
        ));
        assert_eq!(out, vec![expected]);
    }

    #[test]
    fn circuit_addrs_preserves_input_order_for_multiple_addrs() {
        let relay = PeerId::random();
        let other = PeerId::random();
        let inputs = vec![
            addr(&format!("/ip4/127.0.0.1/tcp/9000/p2p/{other}")),
            addr("/ip4/10.0.0.1/udp/9000/quic-v1"),
        ];

        let out = RelayManager::circuit_addrs(relay, &inputs);

        assert_eq!(
            out,
            vec![
                addr(&format!("/ip4/127.0.0.1/tcp/9000/p2p/{relay}/p2p-circuit")),
                addr(&format!(
                    "/ip4/10.0.0.1/udp/9000/quic-v1/p2p/{relay}/p2p-circuit"
                )),
            ]
        );
    }

    #[test]
    fn circuit_addrs_empty_input_yields_empty_output() {
        let relay = PeerId::random();
        let out = RelayManager::circuit_addrs(relay, &[]);
        assert!(out.is_empty());
    }

    // ---- relay_id_from_circuit_addr -----------------------------------

    #[test]
    fn relay_id_from_circuit_addr_extracts_last_p2p_before_circuit() {
        let relay = PeerId::random();
        let circuit = addr(&format!("/ip4/127.0.0.1/tcp/9000/p2p/{relay}/p2p-circuit"));

        assert_eq!(
            RelayManager::relay_id_from_circuit_addr(&circuit),
            Some(relay)
        );
    }

    #[test]
    fn relay_id_from_circuit_addr_ignores_target_p2p_after_circuit() {
        // Full circuit-dial form `/.../p2p/<relay>/p2p-circuit/p2p/<target>`
        // must return the relay id (before `/p2p-circuit`), not the target.
        let relay = PeerId::random();
        let target = PeerId::random();
        let circuit = addr(&format!(
            "/ip4/127.0.0.1/tcp/9000/p2p/{relay}/p2p-circuit/p2p/{target}"
        ));

        assert_eq!(
            RelayManager::relay_id_from_circuit_addr(&circuit),
            Some(relay)
        );
    }

    #[test]
    fn relay_id_from_circuit_addr_returns_none_when_no_circuit_component() {
        let peer = PeerId::random();
        let plain = addr(&format!("/ip4/127.0.0.1/tcp/9000/p2p/{peer}"));

        assert_eq!(RelayManager::relay_id_from_circuit_addr(&plain), None);
    }

    #[test]
    fn relay_id_from_circuit_addr_returns_none_when_circuit_has_no_preceding_p2p() {
        let bare = addr("/ip4/127.0.0.1/tcp/9000/p2p-circuit");
        assert_eq!(RelayManager::relay_id_from_circuit_addr(&bare), None);
    }

    // ---- peer_circuit_addrs -------------------------------------------

    #[test]
    fn peer_circuit_addrs_returns_empty_when_no_relays_reserved() {
        let mgr = manager();
        let target = PeerId::random();
        assert!(mgr.peer_circuit_addrs(&target).is_empty());
    }

    #[test]
    fn peer_circuit_addrs_ignores_relays_in_dialing_or_established() {
        let mut mgr = manager();
        let target = PeerId::random();
        let dialing = PeerId::random();
        let established = PeerId::random();

        mgr.connection_states
            .insert(dialing, RelayConnectionState::Dialing);
        mgr.relay_addrs
            .insert(dialing, vec![addr("/ip4/10.0.0.1/tcp/9000")]);
        mgr.connection_states
            .insert(established, RelayConnectionState::Established);
        mgr.relay_addrs
            .insert(established, vec![addr("/ip4/10.0.0.2/tcp/9000")]);

        assert!(mgr.peer_circuit_addrs(&target).is_empty());
    }

    #[test]
    fn peer_circuit_addrs_skips_reserved_relay_without_tracked_addrs() {
        let mut mgr = manager();
        let target = PeerId::random();
        let relay = PeerId::random();

        mgr.connection_states
            .insert(relay, RelayConnectionState::Reserved);
        // No entry in relay_addrs: the relay is reserved but we have no
        // transport addrs to build a circuit through it.

        assert!(mgr.peer_circuit_addrs(&target).is_empty());
    }

    #[test]
    fn peer_circuit_addrs_builds_one_circuit_per_reserved_relay_addr() {
        let mut mgr = manager();
        let target = PeerId::random();
        let relay = PeerId::random();

        let relay_addrs = vec![
            // With and without trailing /p2p/<relay> — both should produce the
            // same canonical circuit form.
            addr(&format!("/ip4/10.0.0.1/tcp/9000/p2p/{relay}")),
            addr("/ip4/10.0.0.1/udp/9000/quic-v1"),
        ];
        mgr.connection_states
            .insert(relay, RelayConnectionState::Reserved);
        mgr.relay_addrs.insert(relay, relay_addrs);

        let out = mgr.peer_circuit_addrs(&target);

        let expected = vec![
            addr(&format!(
                "/ip4/10.0.0.1/tcp/9000/p2p/{relay}/p2p-circuit/p2p/{target}"
            )),
            addr(&format!(
                "/ip4/10.0.0.1/udp/9000/quic-v1/p2p/{relay}/p2p-circuit/p2p/{target}"
            )),
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn peer_circuit_addrs_aggregates_across_multiple_reserved_relays() {
        let mut mgr = manager();
        let target = PeerId::random();
        let relay_a = PeerId::random();
        let relay_b = PeerId::random();

        mgr.connection_states
            .insert(relay_a, RelayConnectionState::Reserved);
        mgr.relay_addrs
            .insert(relay_a, vec![addr("/ip4/10.0.0.1/tcp/9000")]);
        mgr.connection_states
            .insert(relay_b, RelayConnectionState::Reserved);
        mgr.relay_addrs
            .insert(relay_b, vec![addr("/ip4/10.0.0.2/tcp/9000")]);

        let out: HashSet<Multiaddr> = mgr.peer_circuit_addrs(&target).into_iter().collect();

        let expected: HashSet<Multiaddr> = [
            addr(&format!(
                "/ip4/10.0.0.1/tcp/9000/p2p/{relay_a}/p2p-circuit/p2p/{target}"
            )),
            addr(&format!(
                "/ip4/10.0.0.2/tcp/9000/p2p/{relay_b}/p2p-circuit/p2p/{target}"
            )),
        ]
        .into_iter()
        .collect();
        assert_eq!(out, expected);
    }

    // ---- backoff_delay ------------------------------------------------

    #[test]
    fn backoff_delay_retry_zero_returns_base_exactly() {
        // Charon's early-return path: retry == 0 returns base with no jitter.
        assert_eq!(backoff_delay(0), RELAY_BACKOFF_BASE);
    }

    #[test]
    fn backoff_delay_caps_at_max_with_jitter_bound() {
        // 1.6^n grows past max well before retry == 50; we should be capped at
        // max ± 20% jitter and never wander outside that envelope.
        let max = RELAY_BACKOFF_MAX.as_secs_f64();
        let lower = max * (1.0 - RELAY_BACKOFF_JITTER);
        let upper = max * (1.0 + RELAY_BACKOFF_JITTER);
        for _ in 0..32 {
            let d = backoff_delay(50).as_secs_f64();
            assert!(
                d >= lower && d <= upper,
                "delay {d}s outside jitter envelope [{lower}, {upper}]"
            );
        }
    }

    #[test]
    fn backoff_delay_grows_then_plateaus() {
        // Averaging out jitter, retry=1 should be larger than base and
        // retry=10 should already be at the cap.
        let mut sum_1 = 0.0;
        let mut sum_10 = 0.0;
        let samples = 64;
        for _ in 0..samples {
            sum_1 += backoff_delay(1).as_secs_f64();
            sum_10 += backoff_delay(10).as_secs_f64();
        }
        let avg_1 = sum_1 / f64::from(samples);
        let avg_10 = sum_10 / f64::from(samples);
        assert!(avg_1 > RELAY_BACKOFF_BASE.as_secs_f64());
        assert!(avg_10 >= RELAY_BACKOFF_MAX.as_secs_f64() * (1.0 - RELAY_BACKOFF_JITTER));
    }

    // ---- queue_relay_update -------------------------------------------

    fn relay_peer(id: PeerId, addrs: Vec<Multiaddr>) -> Peer {
        Peer {
            id,
            addresses: addrs,
            index: 0,
            name: crate::name::peer_name(&id),
        }
    }

    #[tokio::test]
    async fn queue_relay_update_first_seen_starts_dial_campaign() {
        let mut mgr = manager();
        let relay_id = PeerId::random();
        let addrs = vec![addr("/ip4/10.0.0.1/tcp/9000")];

        mgr.queue_relay_update(relay_peer(relay_id, addrs.clone()));

        assert!(mgr.dial_states.contains_key(&relay_id));
        assert_eq!(
            mgr.connection_states.get(&relay_id),
            Some(&RelayConnectionState::Dialing)
        );
        assert_eq!(mgr.relay_addrs.get(&relay_id), Some(&addrs));
    }

    #[tokio::test]
    async fn queue_relay_update_refreshes_inflight_addrs_without_resetting_backoff() {
        let mut mgr = manager();
        let relay_id = PeerId::random();

        mgr.queue_relay_update(relay_peer(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]));
        // Pretend the dial state has already retried a few times.
        mgr.dial_states.get_mut(&relay_id).unwrap().retry_count = 7;

        let new_addrs = vec![
            addr("/ip4/10.0.0.1/tcp/9000"),
            addr("/ip4/10.0.0.2/tcp/9000"),
        ];
        mgr.queue_relay_update(relay_peer(relay_id, new_addrs.clone()));

        let state = mgr.dial_states.get(&relay_id).unwrap();
        assert_eq!(state.addrs, new_addrs);
        assert_eq!(
            state.retry_count, 7,
            "backoff schedule must survive refresh"
        );
        assert_eq!(mgr.relay_addrs.get(&relay_id), Some(&new_addrs));
    }

    #[tokio::test]
    async fn queue_relay_update_no_op_when_relay_already_connected() {
        let mut mgr = manager();
        let relay_id = PeerId::random();
        mgr.connection_states
            .insert(relay_id, RelayConnectionState::Reserved);

        let new_addrs = vec![addr("/ip4/10.0.0.99/tcp/9000")];
        mgr.queue_relay_update(relay_peer(relay_id, new_addrs.clone()));

        assert!(
            !mgr.dial_states.contains_key(&relay_id),
            "no dial campaign while connected"
        );
        // Connection state untouched.
        assert_eq!(
            mgr.connection_states.get(&relay_id),
            Some(&RelayConnectionState::Reserved)
        );
        // relay_addrs still gets refreshed so we have the latest list ready
        // for redial after a disconnect.
        assert_eq!(mgr.relay_addrs.get(&relay_id), Some(&new_addrs));
    }

    // ---- state machine: on_connection_established ----------------------

    #[tokio::test]
    async fn on_connection_established_relay_promotes_to_established_and_queues_listen() {
        let mut mgr = manager();
        let relay_id = PeerId::random();
        let relay_addrs = vec![addr("/ip4/10.0.0.1/tcp/9000")];

        mgr.queue_relay_update(relay_peer(relay_id, relay_addrs.clone()));
        mgr.events.clear();
        mgr.on_connection_established(relay_id);

        assert!(!mgr.dial_states.contains_key(&relay_id));
        assert_eq!(
            mgr.connection_states.get(&relay_id),
            Some(&RelayConnectionState::Established)
        );
        let listen_count = mgr
            .events
            .iter()
            .filter(|e| matches!(e, ToSwarm::ListenOn { .. }))
            .count();
        assert_eq!(listen_count, relay_addrs.len());
        let relay_connected = mgr.events.iter().any(|e| {
            matches!(
                e,
                ToSwarm::GenerateEvent(RelayManagerEvent::RelayConnected(id)) if *id == relay_id
            )
        });
        assert!(relay_connected, "RelayConnected event must be emitted");
    }

    #[tokio::test]
    async fn on_connection_established_cluster_peer_drops_dial_state() {
        let mut mgr = manager();
        let target = PeerId::random();
        // Seed a peer-routing dial state (skipping upsert which requires
        // reserved relays).
        mgr.dial_states.insert(
            target,
            RelayDialState::new(
                RelayDialType::ClusterPeer,
                target,
                vec![addr("/ip4/10.0.0.1/tcp/9000/p2p-circuit")],
            ),
        );

        mgr.on_connection_established(target);

        assert!(!mgr.dial_states.contains_key(&target));
        let routed = mgr.events.iter().any(|e| {
            matches!(
                e,
                ToSwarm::GenerateEvent(RelayManagerEvent::PeerRoutedConnected(id)) if *id == target
            )
        });
        assert!(routed, "PeerRoutedConnected event must be emitted");
    }

    // ---- state machine: on_new_listen_addr -----------------------------

    #[tokio::test]
    async fn on_new_listen_addr_promotes_established_to_reserved() {
        let mut mgr = manager();
        let relay_id = PeerId::random();
        mgr.connection_states
            .insert(relay_id, RelayConnectionState::Established);
        mgr.relay_addrs
            .insert(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

        let circuit = addr(&format!(
            "/ip4/10.0.0.1/tcp/9000/p2p/{relay_id}/p2p-circuit"
        ));
        mgr.on_new_listen_addr(&circuit);

        assert_eq!(
            mgr.connection_states.get(&relay_id),
            Some(&RelayConnectionState::Reserved)
        );
        let reserved = mgr.events.iter().any(|e| {
            matches!(
                e,
                ToSwarm::GenerateEvent(RelayManagerEvent::RelayReserved(id)) if *id == relay_id
            )
        });
        assert!(reserved);
    }

    // ---- state machine: on_expired_listen_addr -------------------------

    #[tokio::test]
    async fn on_expired_listen_addr_demotes_reserved_and_emits_reservation_lost() {
        let mut mgr = manager();
        let relay_id = PeerId::random();
        mgr.connection_states
            .insert(relay_id, RelayConnectionState::Reserved);
        mgr.relay_addrs
            .insert(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

        let circuit = addr(&format!(
            "/ip4/10.0.0.1/tcp/9000/p2p/{relay_id}/p2p-circuit"
        ));
        mgr.on_expired_listen_addr(&circuit);

        assert_eq!(
            mgr.connection_states.get(&relay_id),
            Some(&RelayConnectionState::Established)
        );
        let lost = mgr.events.iter().any(|e| {
            matches!(
                e,
                ToSwarm::GenerateEvent(RelayManagerEvent::RelayReservationLost(id))
                    if *id == relay_id
            )
        });
        assert!(lost, "RelayReservationLost must be emitted on demote");
    }

    #[tokio::test]
    async fn on_expired_listen_addr_drops_peer_dials_with_no_route_left() {
        let mut mgr = manager();
        let relay_id = PeerId::random();
        let target = PeerId::random();

        // Single reserved relay supporting a peer-routing dial.
        mgr.connection_states
            .insert(relay_id, RelayConnectionState::Reserved);
        mgr.relay_addrs
            .insert(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]);
        mgr.dial_states.insert(
            target,
            RelayDialState::new(
                RelayDialType::ClusterPeer,
                target,
                vec![addr(&format!(
                    "/ip4/10.0.0.1/tcp/9000/p2p/{relay_id}/p2p-circuit/p2p/{target}"
                ))],
            ),
        );

        let circuit = addr(&format!(
            "/ip4/10.0.0.1/tcp/9000/p2p/{relay_id}/p2p-circuit"
        ));
        mgr.on_expired_listen_addr(&circuit);

        assert!(
            !mgr.dial_states.contains_key(&target),
            "peer dial state must be dropped once no reserved relay can route to it"
        );
    }

    // ---- state machine: on_connection_closed ---------------------------

    #[tokio::test]
    async fn on_connection_closed_reserved_relay_emits_lost_before_disconnected() {
        let mut mgr = manager();
        let relay_id = PeerId::random();
        mgr.connection_states
            .insert(relay_id, RelayConnectionState::Reserved);
        mgr.relay_addrs
            .insert(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

        mgr.on_connection_closed(relay_id);

        let lost_idx = mgr.events.iter().position(|e| {
            matches!(
                e,
                ToSwarm::GenerateEvent(RelayManagerEvent::RelayReservationLost(id))
                    if *id == relay_id
            )
        });
        let disc_idx = mgr.events.iter().position(|e| {
            matches!(
                e,
                ToSwarm::GenerateEvent(RelayManagerEvent::RelayDisconnected(id)) if *id == relay_id
            )
        });
        let lost = lost_idx.expect("RelayReservationLost must fire when prev state was Reserved");
        let disc = disc_idx.expect("RelayDisconnected must fire on relay close");
        assert!(lost < disc, "ReservationLost must precede Disconnected");
        assert_eq!(
            mgr.connection_states.get(&relay_id),
            Some(&RelayConnectionState::Dialing),
            "redial campaign must arm"
        );
        assert!(mgr.dial_states.contains_key(&relay_id));
    }

    #[tokio::test]
    async fn on_connection_closed_established_relay_skips_reservation_lost() {
        let mut mgr = manager();
        let relay_id = PeerId::random();
        mgr.connection_states
            .insert(relay_id, RelayConnectionState::Established);
        mgr.relay_addrs
            .insert(relay_id, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

        mgr.on_connection_closed(relay_id);

        let lost = mgr.events.iter().any(|e| {
            matches!(
                e,
                ToSwarm::GenerateEvent(RelayManagerEvent::RelayReservationLost(_))
            )
        });
        assert!(
            !lost,
            "no ReservationLost event when prev state wasn't Reserved"
        );
    }

    // ---- on_dial_failure: Skipped path --------------------------------

    fn skipped_dial_error() -> DialError {
        DialError::DialPeerConditionFalse(
            libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing,
        )
    }

    #[tokio::test]
    async fn on_dial_failure_skipped_cluster_peer_drops_dial_state() {
        let mut mgr = manager();
        let target = PeerId::random();
        mgr.dial_states.insert(
            target,
            RelayDialState::new(
                RelayDialType::ClusterPeer,
                target,
                vec![addr("/ip4/10.0.0.1/tcp/9000")],
            ),
        );

        mgr.on_dial_failure(Some(target), &skipped_dial_error());

        assert!(
            !mgr.dial_states.contains_key(&target),
            "cluster-peer dial state must be dropped on Skipped"
        );
    }

    #[tokio::test]
    async fn on_dial_failure_skipped_relay_keeps_dial_state() {
        // Regression for the wedge bug: keep the campaign armed so backoff
        // continues to retry until libp2p surfaces the connection state.
        let mut mgr = manager();
        let relay_id = PeerId::random();
        mgr.connection_states
            .insert(relay_id, RelayConnectionState::Dialing);
        mgr.dial_states.insert(
            relay_id,
            RelayDialState::new(
                RelayDialType::RelayServer,
                relay_id,
                vec![addr("/ip4/10.0.0.1/tcp/9000")],
            ),
        );

        mgr.on_dial_failure(Some(relay_id), &skipped_dial_error());

        assert!(
            mgr.dial_states.contains_key(&relay_id),
            "relay dial state must survive Skipped so backoff can retry"
        );
        assert_eq!(
            mgr.connection_states.get(&relay_id),
            Some(&RelayConnectionState::Dialing),
            "connection state must still be Dialing"
        );
    }

    // ---- upsert_peer_dial ---------------------------------------------

    #[tokio::test]
    async fn upsert_peer_dial_preserves_backoff_when_addrs_unchanged() {
        let mut mgr = manager();
        let target = PeerId::random();
        let relay = PeerId::random();
        mgr.connection_states
            .insert(relay, RelayConnectionState::Reserved);
        mgr.relay_addrs
            .insert(relay, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

        mgr.upsert_peer_dial(target);
        let inserted_count = mgr.dial_states.get(&target).map(|s| s.retry_count);
        // Pretend the dial has retried.
        if let Some(s) = mgr.dial_states.get_mut(&target) {
            s.retry_count = 5;
        }
        mgr.upsert_peer_dial(target);
        let after = mgr.dial_states.get(&target).map(|s| s.retry_count);
        assert_eq!(inserted_count, Some(0));
        assert_eq!(
            after,
            Some(5),
            "addr-set unchanged: existing dial state (and its backoff) must be preserved"
        );
    }

    #[tokio::test]
    async fn upsert_peer_dial_resets_backoff_when_addrs_change() {
        let mut mgr = manager();
        let target = PeerId::random();
        let relay_a = PeerId::random();
        let relay_b = PeerId::random();
        mgr.connection_states
            .insert(relay_a, RelayConnectionState::Reserved);
        mgr.relay_addrs
            .insert(relay_a, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

        mgr.upsert_peer_dial(target);
        if let Some(s) = mgr.dial_states.get_mut(&target) {
            s.retry_count = 5;
        }

        // Reserve a second relay → new circuit addr → addr-set changes.
        mgr.connection_states
            .insert(relay_b, RelayConnectionState::Reserved);
        mgr.relay_addrs
            .insert(relay_b, vec![addr("/ip4/10.0.0.2/tcp/9000")]);
        mgr.upsert_peer_dial(target);

        assert_eq!(
            mgr.dial_states.get(&target).map(|s| s.retry_count),
            Some(0),
            "addr-set changed: dial state (and backoff) must be replaced"
        );
    }

    #[tokio::test]
    async fn upsert_peer_dial_drops_stale_state_when_no_route_left() {
        let mut mgr = manager();
        let target = PeerId::random();
        let relay = PeerId::random();
        mgr.connection_states
            .insert(relay, RelayConnectionState::Reserved);
        mgr.relay_addrs
            .insert(relay, vec![addr("/ip4/10.0.0.1/tcp/9000")]);

        mgr.upsert_peer_dial(target);
        assert!(mgr.dial_states.contains_key(&target));

        // Demote the only reserved relay → no circuit addrs left.
        mgr.connection_states
            .insert(relay, RelayConnectionState::Established);
        mgr.upsert_peer_dial(target);

        assert!(
            !mgr.dial_states.contains_key(&target),
            "no reserved relay can reach target: stale dial state must be dropped"
        );
    }
}
