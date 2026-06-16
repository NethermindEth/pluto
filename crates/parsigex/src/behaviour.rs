//! Network behaviour and control handle for partial signature exchange.

use std::{
    collections::{HashMap, HashSet, VecDeque},
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
use tokio::sync::{RwLock, mpsc, oneshot};

use pluto_core::{
    gater::DutyGaterFn,
    types::{Duty, ParSignedData, ParSignedDataSet, PubKey},
};
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
    pending_peers: HashSet<PeerId>,
    failure: Option<Failure>,
    result_tx: Option<oneshot::Sender<Result<u64>>>,
}

#[derive(Debug)]
struct BroadcastRequest {
    request_id: u64,
    duty: Duty,
    data_set: ParSignedDataSet,
    result_tx: Option<oneshot::Sender<Result<u64>>>,
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
    /// Enqueues a partial signature set for broadcast to all peers except self.
    pub async fn broadcast(&self, duty: Duty, data_set: ParSignedDataSet) -> Result<u64> {
        self.enqueue(duty, data_set, None).await
    }

    /// Broadcasts a partial signature set and waits until the behaviour reports
    /// terminal success or failure.
    pub async fn broadcast_and_wait(&self, duty: Duty, data_set: ParSignedDataSet) -> Result<u64> {
        let (result_tx, result_rx) = oneshot::channel();
        self.enqueue(duty, data_set, Some(result_tx)).await?;
        result_rx.await.map_err(|_| Error::Closed)?
    }

    async fn enqueue(
        &self,
        duty: Duty,
        data_set: ParSignedDataSet,
        result_tx: Option<oneshot::Sender<Result<u64>>>,
    ) -> Result<u64> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.tx
            .send(BroadcastRequest {
                request_id,
                duty,
                data_set,
                result_tx,
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
    duty_gater: DutyGaterFn,
    timeout: Duration,
}

impl Config {
    /// Creates a new configuration.
    pub fn new(
        peer_id: PeerId,
        p2p_context: P2PContext,
        verifier: Verifier,
        duty_gater: DutyGaterFn,
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
            result_tx,
        } = req;
        let message = match encode_message(&duty, &data_set) {
            Ok(message) => message,
            Err(err) => {
                let error = err.to_string();
                self.emit_broadcast_error(request_id, None, Failure::Codec(error.clone()));
                self.finish_broadcast_failure(result_tx, request_id, Failure::Codec(error));
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
        let mut pending_peers = HashSet::new();
        let mut failure = None;
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
                let error = Failure::Io(std::io::Error::other(format!(
                    "peer {peer} is not connected"
                )));
                if failure.is_none() {
                    failure = Some(error.clone());
                }
                self.emit_broadcast_error(request_id, Some(peer), error);
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
            pending_peers.insert(peer);
        }

        if pending_peers.is_empty() {
            self.pending_events
                .push_back(ToSwarm::GenerateEvent(Event::BroadcastFailed {
                    request_id,
                }));
            self.finish_broadcast_failure(
                result_tx,
                request_id,
                failure.unwrap_or_else(|| {
                    Failure::Io(std::io::Error::other("no peers available for broadcast"))
                }),
            );
            return;
        }

        self.pending_broadcasts.insert(
            request_id,
            PendingBroadcast {
                pending_peers,
                failure,
                result_tx,
            },
        );
    }

    fn finish_broadcast_result(
        &mut self,
        request_id: u64,
        peer_id: PeerId,
        failure: Option<Failure>,
    ) {
        let Some(entry) = self.pending_broadcasts.get_mut(&request_id) else {
            return;
        };

        if entry.failure.is_none() {
            entry.failure = failure;
        }
        entry.pending_peers.remove(&peer_id);
        if entry.pending_peers.is_empty() {
            let Some(entry) = self.pending_broadcasts.remove(&request_id) else {
                return;
            };
            if let Some(error) = entry.failure {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::BroadcastFailed {
                        request_id,
                    }));
                self.finish_broadcast_failure(entry.result_tx, request_id, error);
            } else {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::BroadcastComplete {
                        request_id,
                    }));
                self.finish_broadcast_request(entry.result_tx, Ok(request_id));
            }
        }
    }

    fn finish_broadcast_failure(
        &self,
        result_tx: Option<oneshot::Sender<Result<u64>>>,
        request_id: u64,
        error: Failure,
    ) {
        let Some(result_tx) = result_tx else {
            return;
        };
        let _ = result_tx.send(Err(Error::BroadcastFailed { request_id, error }));
    }

    fn finish_broadcast_request(
        &self,
        result_tx: Option<oneshot::Sender<Result<u64>>>,
        result: Result<u64>,
    ) {
        if let Some(result_tx) = result_tx {
            let _ = result_tx.send(result);
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
                self.finish_broadcast_result(request_id, peer_id, None);
            }
            FromHandler::OutboundError { request_id, error } => {
                self.finish_broadcast_result(request_id, peer_id, Some(error.clone()));
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

    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let FromSwarm::ConnectionClosed(e) = event
            && e.remaining_established == 0
        {
            let peer_id = e.peer_id;
            let affected: Vec<u64> = self
                .pending_broadcasts
                .iter()
                .filter(|(_, b)| b.pending_peers.contains(&peer_id))
                .map(|(id, _)| *id)
                .collect();
            for request_id in affected {
                let error = Failure::Io(std::io::Error::other("connection closed"));
                self.emit_broadcast_error(request_id, Some(peer_id), error.clone());
                self.finish_broadcast_result(request_id, peer_id, Some(error));
            }
        }
    }

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
