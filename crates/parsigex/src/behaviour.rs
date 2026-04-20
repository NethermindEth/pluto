//! Network behaviour and control handle for partial signature exchange.

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use either::Either;
use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm, dummy,
    },
};
use tokio::sync::{RwLock, mpsc};

use pluto_core::types::{Duty, ParSignedData, ParSignedDataSet, PubKey};
use pluto_p2p::p2p_context::P2PContext;

use super::{Handler, encode_message};
use crate::{
    error::{Error, Failure, Result, VerifyError},
    handler::{FromHandler, ToHandler},
};

/// Future returned by verifier callbacks.
pub type VerifyFuture =
    Pin<Box<dyn Future<Output = std::result::Result<(), VerifyError>> + Send + 'static>>;

/// Verifier callback type.
pub type Verifier =
    Arc<dyn Fn(Duty, PubKey, ParSignedData) -> VerifyFuture + Send + Sync + 'static>;

/// Duty gate callback type.
pub type DutyGater = Arc<dyn Fn(&Duty) -> bool + Send + Sync + 'static>;

/// Future returned by received subscriber callbacks.
pub type ReceivedSubFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Subscriber callback for received partial signature sets.
///
/// Called when a verified partial signature set is received from a peer.
pub type ReceivedSub =
    Arc<dyn Fn(Duty, ParSignedDataSet) -> ReceivedSubFuture + Send + Sync + 'static>;

/// Helper to create a received subscriber from a closure.
pub fn received_subscriber<F, Fut>(f: F) -> ReceivedSub
where
    F: Fn(Duty, ParSignedDataSet) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    Arc::new(move |duty, set| Box::pin(f(duty, set)))
}

/// Event emitted by the partial signature exchange behaviour.
#[derive(Debug)]
pub enum Event {
    /// A verified partial signature set was received from a peer.
    Received {
        /// The remote peer.
        peer: PeerId,
        /// Connection on which it was received.
        connection: ConnectionId,
        /// Duty associated with the data set.
        duty: Duty,
        /// Partial signature set.
        data_set: ParSignedDataSet,
    },
    /// A peer sent invalid data or verification failed.
    Error {
        /// The remote peer.
        peer: PeerId,
        /// Connection on which the error occurred.
        connection: ConnectionId,
        /// Failure reason.
        error: Failure,
    },
    /// Broadcast failed.
    BroadcastError {
        /// Request identifier.
        request_id: u64,
        /// Peer for which the broadcast failed, if known.
        peer: Option<PeerId>,
        /// Failure reason.
        error: Failure,
    },
    /// Broadcast completed successfully for all targeted peers.
    BroadcastComplete {
        /// Request identifier.
        request_id: u64,
    },
    /// Broadcast failed after one or more peer failures.
    BroadcastFailed {
        /// Request identifier.
        request_id: u64,
    },
}

#[derive(Debug)]
struct PendingBroadcast {
    remaining: usize,
    failed: bool,
}

#[derive(Debug)]
struct BroadcastRequest {
    request_id: u64,
    duty: Duty,
    data_set: ParSignedDataSet,
}

/// Shared subscriber list between [`Handle`] and [`Behaviour`].
#[derive(Default)]
struct SharedSubs {
    subs: RwLock<Vec<ReceivedSub>>,
}

/// Async handle for outbound partial signature broadcasts.
#[derive(Clone)]
pub struct Handle {
    tx: mpsc::UnboundedSender<BroadcastRequest>,
    next_request_id: Arc<AtomicU64>,
    shared_subs: Arc<SharedSubs>,
}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle")
            .field("next_request_id", &self.next_request_id)
            .finish_non_exhaustive()
    }
}

impl Handle {
    /// Broadcasts a partial signature set to all peers except self.
    pub async fn broadcast(&self, duty: Duty, data_set: ParSignedDataSet) -> Result<u64> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.tx
            .send(BroadcastRequest {
                request_id,
                duty,
                data_set,
            })
            .map_err(|_| Error::Closed)?;
        Ok(request_id)
    }

    /// Subscribers registered after the swarm begins polling may miss messages
    /// already in flight. Register all subscribers before starting the event
    /// loop.
    pub async fn subscribe(&self, sub: ReceivedSub) {
        self.shared_subs.subs.write().await.push(sub);
    }
}

/// Configuration for the partial signature exchange behaviour.
#[derive(Clone)]
pub struct Config {
    peer_id: PeerId,
    p2p_context: P2PContext,
    verifier: Verifier,
    duty_gater: DutyGater,
    timeout: Duration,
}

impl Config {
    /// Creates a new configuration.
    pub fn new(
        peer_id: PeerId,
        p2p_context: P2PContext,
        verifier: Verifier,
        duty_gater: DutyGater,
    ) -> Self {
        Self {
            peer_id,
            p2p_context,
            verifier,
            duty_gater,
            timeout: Duration::from_secs(20),
        }
    }

    /// Sets the send/receive timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Behaviour for partial signature exchange.
pub struct Behaviour {
    config: Config,
    rx: mpsc::UnboundedReceiver<BroadcastRequest>,
    pending_events: VecDeque<ToSwarm<Event, ToHandler>>,
    pending_broadcasts: HashMap<u64, PendingBroadcast>,
    shared_subs: Arc<SharedSubs>,
}

impl Behaviour {
    /// Creates a behaviour and a clonable broadcast handle.
    pub fn new(config: Config) -> (Self, Handle) {
        let (tx, rx) = mpsc::unbounded_channel();
        let shared_subs = Arc::new(SharedSubs::default());
        let handle = Handle {
            tx,
            next_request_id: Arc::new(AtomicU64::new(0)),
            shared_subs: shared_subs.clone(),
        };
        (
            Self {
                config,
                rx,
                pending_events: VecDeque::new(),
                pending_broadcasts: HashMap::new(),
                shared_subs,
            },
            handle,
        )
    }

    fn connection_handler_for_peer(&self, peer: PeerId) -> THandler<Self> {
        if !self.config.p2p_context.is_known_peer(&peer) {
            return Either::Right(dummy::ConnectionHandler);
        }
        Either::Left(Handler::new(
            self.config.timeout,
            self.config.verifier.clone(),
            self.config.duty_gater.clone(),
        ))
    }

    fn handle_command(&mut self, req: BroadcastRequest) {
        let BroadcastRequest {
            request_id,
            duty,
            data_set,
        } = req;
        let message = match encode_message(&duty, &data_set) {
            Ok(message) => message,
            Err(err) => {
                self.emit_broadcast_error(request_id, None, Failure::Codec(err.to_string()));
                return;
            }
        };

        let peers: Vec<_> = self
            .config
            .p2p_context
            .known_peers()
            .iter()
            .copied()
            .collect();
        let mut targeted = 0usize;
        for peer in peers {
            if peer == self.config.peer_id {
                continue;
            }

            if self
                .config
                .p2p_context
                .peer_store_lock()
                .connections_to_peer(&peer)
                .is_empty()
            {
                self.emit_broadcast_error(
                    request_id,
                    Some(peer),
                    Failure::Io(std::io::Error::other(format!(
                        "peer {peer} is not connected"
                    ))),
                );
                continue;
            }

            self.pending_events.push_back(ToSwarm::NotifyHandler {
                peer_id: peer,
                handler: NotifyHandler::Any,
                event: ToHandler::Send {
                    request_id,
                    payload: message.clone(),
                },
            });
            targeted = targeted.saturating_add(1);
        }

        if targeted == 0 {
            return;
        }

        self.pending_broadcasts.insert(
            request_id,
            PendingBroadcast {
                remaining: targeted,
                failed: false,
            },
        );
    }

    fn finish_broadcast_result(&mut self, request_id: u64, failed: bool) {
        let Some(entry) = self.pending_broadcasts.get_mut(&request_id) else {
            return;
        };

        entry.failed |= failed;
        entry.remaining = entry.remaining.saturating_sub(1);
        if entry.remaining == 0 {
            let failed = self
                .pending_broadcasts
                .remove(&request_id)
                .map(|entry| entry.failed)
                .unwrap_or(failed);
            if failed {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::BroadcastFailed {
                        request_id,
                    }));
            } else {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::BroadcastComplete {
                        request_id,
                    }));
            }
        }
    }

    fn emit_broadcast_error(&mut self, request_id: u64, peer: Option<PeerId>, error: Failure) {
        self.pending_events
            .push_back(ToSwarm::GenerateEvent(Event::BroadcastError {
                request_id,
                peer,
                error,
            }));
    }

    fn handle_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: FromHandler,
    ) {
        match event {
            FromHandler::Received { duty, data_set } => {
                self.notify_subscribers(duty.clone(), data_set.clone());
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::Received {
                        peer: peer_id,
                        connection: connection_id,
                        duty,
                        data_set,
                    }));
            }
            FromHandler::InboundError(error) => {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::Error {
                        peer: peer_id,
                        connection: connection_id,
                        error,
                    }));
            }
            FromHandler::OutboundSuccess { request_id } => {
                self.finish_broadcast_result(request_id, false);
            }
            FromHandler::OutboundError { request_id, error } => {
                self.finish_broadcast_result(request_id, true);
                self.emit_broadcast_error(request_id, Some(peer_id), error);
            }
        }
    }

    /// Notifies all registered subscribers of a received partial signature set.
    ///
    /// Each subscriber is invoked in a spawned task since `poll()` is
    /// synchronous. This matches Go's intended behaviour (see Go TODO to call
    /// subscribers async).
    fn notify_subscribers(&self, duty: Duty, data_set: ParSignedDataSet) {
        let shared_subs = self.shared_subs.clone();
        tokio::spawn(async move {
            let subs = shared_subs.subs.read().await.clone();
            for sub in &subs {
                sub(duty.clone(), data_set.clone()).await;
            }
        });
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Either<Handler, dummy::ConnectionHandler>;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        Ok(self.connection_handler_for_peer(peer))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        Ok(self.connection_handler_for_peer(peer))
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        let event = match event {
            Either::Left(event) => event,
            Either::Right(unreachable) => match unreachable {},
        };
        self.handle_handler_event(peer_id, connection_id, event);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event.map_in(Either::Left));
        }

        while let Poll::Ready(Some(command)) = self.rx.poll_recv(cx) {
            self.handle_command(command);
        }

        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event.map_in(Either::Left));
        }

        Poll::Pending
    }
}
