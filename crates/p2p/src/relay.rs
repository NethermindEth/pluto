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
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use crate::{
    p2p_context::P2PContext,
    peer::{MutablePeer, Peer},
};
use futures::stream::StreamExt;
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

/// Mutable relay reservation behaviour.
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
    Peer,
    /// Dial a relay server directly.
    Relay,
}

/// State of an in-flight dial campaign, polled to produce a `ToSwarm::Dial`
/// event each time its backoff elapses.
pub struct RelayDialState {
    /// Kind of target this campaign is dialing.
    pub ty: RelayDialType,
    /// Target peer id for the dial.
    pub peer_id: PeerId,
    /// Transport (for `Relay`) or circuit (for `Peer`) addresses to try.
    pub addrs: Vec<Multiaddr>,
    /// Number of dial attempts so far, used to compute the next backoff.
    pub retry_count: u32,
    /// Sleeps until the next dial is due. Boxed-and-pinned so the struct stays
    /// `Unpin` and can be stored in a `HashMap`; the inner `Sleep` is `!Unpin`.
    sleep: Pin<Box<Sleep>>,
}

impl RelayDialState {
    /// Creates a fresh dial state armed to fire after the base backoff.
    pub fn new(ty: RelayDialType, peer_id: PeerId, addrs: Vec<Multiaddr>) -> Self {
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

impl Future for RelayDialState {
    type Output = ToSwarm<RelayManagerEvent, Infallible>;

    /// Drives the dial schedule. Returns `Ready` with a `Dial` event when the
    /// next attempt is due, then self-rearms with an exponential backoff so
    /// the future can keep being polled to produce subsequent retries.
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
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

        Poll::Ready(ToSwarm::Dial { opts })
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
    pub fn queue_relay_update(&mut self, relay: Peer) {
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
            RelayDialState::new(RelayDialType::Relay, relay.id, relay.addresses),
        );
        self.set_relay_state(relay.id, RelayConnectionState::Dialing);
    }

    /// Updates the connection state for a relay, logging the transition.
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
    }

    /// Polls every active dial state once, queuing a `ToSwarm::Dial` event for
    /// any whose backoff has elapsed. Wakers for the remaining (pending) ones
    /// are registered via the underlying `Sleep` futures.
    pub fn process_relay_dials(&mut self, cx: &mut Context<'_>) {
        for (_, state) in self.dial_states.iter_mut() {
            let state = Pin::new(state);
            if let Poll::Ready(event) = state.poll(cx) {
                self.events.push_back(event);
            }
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
    /// just because re-routing was re-evaluated.
    fn upsert_peer_dial(&mut self, target: PeerId) {
        let addrs = self.peer_circuit_addrs(&target);
        if addrs.is_empty() {
            return;
        }

        if let Some(existing) = self.dial_states.get(&target)
            && addr_sets_equal(&existing.addrs, &addrs)
        {
            return;
        }

        self.dial_states.insert(
            target,
            RelayDialState::new(RelayDialType::Peer, target, addrs),
        );
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
            RelayDialType::Relay => {
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
            RelayDialType::Peer => {
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
        }
    }

    /// Reacts to the last connection to `peer_id` closing. Either it's one of
    /// our relays (queue a fresh re-dial cycle) or a known cluster peer
    /// (arm a fresh routing dial through the current reserved relays).
    /// Anything else is ignored.
    fn on_connection_closed(&mut self, peer_id: PeerId) {
        if self.connection_states.contains_key(&peer_id) {
            self.events.push_back(ToSwarm::GenerateEvent(
                RelayManagerEvent::RelayDisconnected(peer_id),
            ));
            self.redial_relay(peer_id);
        } else if self.p2p_context.is_known_peer(&peer_id) {
            self.reroute_peer(peer_id);
        }
    }

    /// Reacts to a dial failure by logging and emitting a `DialFailed` event.
    /// The underlying [`RelayDialState`] self-rearms with exponential backoff
    /// on the next swarm poll, so no state change is needed here.
    fn on_dial_failure(&mut self, peer_id: Option<PeerId>, error: &DialError) {
        let Some(peer_id) = peer_id else { return };
        let Some(state) = self.dial_states.get(&peer_id) else {
            return;
        };
        let target = state.ty;
        let retry_count = state.retry_count;
        tracing::debug!(
            peer_id = %peer_id,
            dial_type = ?target,
            retry_count,
            %error,
            "Dial failed, will retry with backoff"
        );
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
            RelayDialState::new(RelayDialType::Relay, relay_id, addrs),
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

        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}
