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
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use crate::{
    p2p_context::P2PContext,
    peer::{MutablePeer, Peer},
    utils,
};
use futures::stream::StreamExt;
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    multiaddr::Protocol as MaProtocol,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        ToSwarm, dial_opts::DialOpts, dummy,
    },
};
use tokio::time::{Instant, Interval, Sleep, sleep_until};
use tokio_stream::wrappers::WatchStream;

const RELAY_ROUTER_INTERVAL: Duration = Duration::from_secs(60);
const RELAY_ROUTER_INITIAL_DELAY: Duration = Duration::from_secs(10);
const RELAY_READY_DELAY: Duration = Duration::from_secs(2);
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
}

pub enum RelayManagerEvent {
    /// Dialed relay successfully.
    Dialed(PeerId),
    /// Dialed relay failed.
    DialFailed(PeerId, String),
}

pub enum RelayDialType {
    /// Dial a peer directly.
    Peer,
    /// Dial a relay directly.
    Relay,
}

pub struct RelayDialState {
    pub ty: RelayDialType,
    pub peer_id: PeerId,
    pub addrs: Vec<Multiaddr>,
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
            sleep: Box::pin(sleep_until(Instant::now() + RELAY_BACKOFF_BASE)),
        }
    }
}

pub enum RelayConnectionState {
    Reserved,
    Established,
    Dialing,
    Closed, 
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
        self.sleep.as_mut().reset(Instant::now() + next_delay);

        let opts = DialOpts::peer_id(self.peer_id)
            .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
            .addresses(self.addrs.clone())
            .build();

        Poll::Ready(ToSwarm::Dial { opts })
    }
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
    /// Creates a new mutable relay reservation.
    pub fn new(mutable_peers: Vec<MutablePeer>) -> Self {
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
        let mut iter = addr.iter().peekable();
        let mut last_p2p: Option<PeerId> = None;
        while let Some(proto) = iter.next() {
            match proto {
                MaProtocol::P2p(id) => last_p2p = Some(id),
                MaProtocol::P2pCircuit => return last_p2p,
                _ => {}
            }
        }
        None
    }

    pub fn queue_relay_update(&mut self, relay: Peer) {
        self.relay_addrs.insert(relay.id, relay.addresses.clone());

        // If we're already connected (or actively reserving), don't restart
        // the dial cycle — the address store has been refreshed and the next
        // disconnect will pick it up.
        if self.connection_states.contains_key(&relay.id) {
            return;
        }

        self.dial_states.insert(
            relay.id,
            RelayDialState::new(RelayDialType::Relay, relay.id, relay.addresses),
        );
    }

    pub fn process_relay_dials(&mut self, cx: &mut Context<'_>) {
        for (_, state) in self.dial_states.iter_mut() {
            let state = Pin::new(state);
            if let Poll::Ready(event) = state.poll(cx) {
                self.events.push_back(event);
            }
        }
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
                let Some(dial_state) = self.dial_states.remove(&conn.peer_id) else {
                    return;
                };

                self.events
                    .push_back(ToSwarm::GenerateEvent(RelayManagerEvent::Dialed(
                        conn.peer_id,
                    )));
                self.connection_states
                    .insert(conn.peer_id, RelayConnectionState::Established);

                for circuit_addr in Self::circuit_addrs(conn.peer_id, &dial_state.addrs) {
                    tracing::debug!(
                        relay_peer_id = %conn.peer_id,
                        %circuit_addr,
                        "Requesting circuit listener on relay"
                    );
                    self.events.push_back(ToSwarm::ListenOn {
                        opts: libp2p::swarm::ListenOpts::new(circuit_addr),
                    });
                }
            }
            FromSwarm::NewListenAddr(ev) => {
                if let Some(relay_id) = Self::relay_id_from_circuit_addr(ev.addr)
                    && let Some(state) = self.connection_states.get_mut(&relay_id)
                {
                    tracing::info!(
                        relay_peer_id = %relay_id,
                        listen_addr = %ev.addr,
                        "Relay reservation confirmed"
                    );
                    *state = RelayConnectionState::Reserved;
                }
            }
            FromSwarm::ConnectionClosed(conn) if conn.remaining_established == 0 => {
                if self.connection_states.remove(&conn.peer_id).is_none() {
                    return;
                }

                let Some(addrs) = self.relay_addrs.get(&conn.peer_id).cloned() else {
                    tracing::warn!(
                        relay_peer_id = %conn.peer_id,
                        "Relay closed but addresses no longer tracked; cannot redial"
                    );
                    return;
                };

                tracing::debug!(
                    relay_peer_id = %conn.peer_id,
                    "Relay connection closed, queuing re-dial with backoff"
                );
                self.dial_states.insert(
                    conn.peer_id,
                    RelayDialState::new(RelayDialType::Relay, conn.peer_id, addrs),
                );
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
