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

use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
};
use tokio::sync::{mpsc, oneshot};

use crate::types::{Duty, ParSignedData, ParSignedDataSet, PubKey};

use super::{
    Error as CodecError, Handler, encode_message,
    handler::{Failure as HandlerFailure, FromHandler, ToHandler},
};

/// Future returned by verifier callbacks.
pub type VerifyFuture =
    Pin<Box<dyn Future<Output = std::result::Result<(), VerifyError>> + Send + 'static>>;

/// Verifier callback type.
pub type Verifier =
    Arc<dyn Fn(Duty, PubKey, ParSignedData) -> VerifyFuture + Send + Sync + 'static>;

/// Duty gate callback type.
pub type DutyGater = Arc<dyn Fn(&Duty) -> bool + Send + Sync + 'static>;

/// Peer connection callback type.
pub type PeerConnectionChecker = Arc<dyn Fn(&PeerId) -> bool + Send + Sync + 'static>;

/// Error type for signature verification callbacks.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Unknown validator public key.
    #[error("unknown pubkey, not part of cluster lock")]
    UnknownPubKey,

    /// Invalid share index for the validator.
    #[error("invalid shareIdx")]
    InvalidShareIndex,

    /// Invalid signed-data family for the duty.
    #[error("invalid eth2 signed data")]
    InvalidSignedDataFamily,

    /// Generic verification error.
    #[error("{0}")]
    Other(String),
}

/// Error type for behaviour operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Message conversion failed.
    #[error(transparent)]
    Codec(#[from] CodecError),

    /// Channel closed.
    #[error("parsigex handle closed")]
    Closed,

    /// Broadcast failed for a peer.
    #[error("broadcast to peer {peer} failed: {source}")]
    BroadcastPeer {
        /// Peer for which the broadcast failed.
        peer: PeerId,
        /// Source error.
        #[source]
        source: HandlerFailure,
    },

    /// Peer is not currently connected.
    #[error("peer {0} is not connected")]
    PeerNotConnected(PeerId),
}

/// Result type for partial signature exchange behaviour operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Event emitted by the partial signature exchange behaviour.
#[derive(Debug, Clone)]
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
        error: HandlerFailure,
    },
}

#[derive(Debug)]
struct PendingBroadcast {
    remaining: usize,
    responder: oneshot::Sender<Result<()>>,
}

#[derive(Debug)]
enum Command {
    Broadcast {
        request_id: u64,
        duty: Duty,
        data_set: ParSignedDataSet,
        responder: oneshot::Sender<Result<()>>,
    },
}

/// Async handle for outbound partial signature broadcasts.
#[derive(Debug, Clone)]
pub struct Handle {
    tx: mpsc::UnboundedSender<Command>,
    next_request_id: Arc<AtomicU64>,
}

impl Handle {
    /// Broadcasts a partial signature set to all peers except self.
    pub async fn broadcast(&self, duty: Duty, data_set: ParSignedDataSet) -> Result<()> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::Broadcast {
                request_id,
                duty,
                data_set,
                responder: tx,
            })
            .map_err(|_| Error::Closed)?;

        Ok(())
    }
}

/// Configuration for the partial signature exchange behaviour.
#[derive(Clone)]
pub struct Config {
    peers: Vec<PeerId>,
    self_index: usize,
    verifier: Verifier,
    duty_gater: DutyGater,
    is_peer_connected: PeerConnectionChecker,
    timeout: Duration,
}

impl Config {
    /// Creates a new configuration.
    pub fn new(
        peers: Vec<PeerId>,
        self_index: usize,
        verifier: Verifier,
        duty_gater: DutyGater,
        is_peer_connected: PeerConnectionChecker,
    ) -> Self {
        Self {
            peers,
            self_index,
            verifier,
            duty_gater,
            is_peer_connected,
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
    rx: mpsc::UnboundedReceiver<Command>,
    pending_actions: VecDeque<ToSwarm<Event, THandlerInEvent<Self>>>,
    events: VecDeque<Event>,
    pending_broadcasts: HashMap<u64, PendingBroadcast>,
}

impl Behaviour {
    /// Creates a behaviour and a clonable broadcast handle.
    pub fn new(config: Config) -> (Self, Handle) {
        let (tx, rx) = mpsc::unbounded_channel();
        let handle = Handle {
            tx,
            next_request_id: Arc::new(AtomicU64::new(0)),
        };

        (
            Self {
                config,
                rx,
                pending_actions: VecDeque::new(),
                events: VecDeque::new(),
                pending_broadcasts: HashMap::new(),
            },
            handle,
        )
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::Broadcast {
                request_id,
                duty,
                data_set,
                responder,
            } => {
                let message = match encode_message(&duty, &data_set) {
                    Ok(message) => message,
                    Err(err) => {
                        let _ = responder.send(Err(Error::from(err)));
                        return;
                    }
                };

                let mut targeted = 0usize;
                for (idx, peer) in self.config.peers.iter().enumerate() {
                    if idx == self.config.self_index {
                        continue;
                    }

                    if !(self.config.is_peer_connected)(peer) {
                        let _ = responder.send(Err(Error::PeerNotConnected(*peer)));
                        return;
                    }

                    self.pending_actions.push_back(ToSwarm::NotifyHandler {
                        peer_id: *peer,
                        handler: NotifyHandler::Any,
                        event: ToHandler::Send {
                            request_id,
                            payload: message.clone(),
                        },
                    });
                    targeted = targeted.saturating_add(1);
                }

                if targeted == 0 {
                    let _ = responder.send(Ok(()));
                    return;
                }

                self.pending_broadcasts.insert(
                    request_id,
                    PendingBroadcast {
                        remaining: targeted,
                        responder,
                    },
                );
            }
        }
    }

    fn finish_broadcast_success(&mut self, request_id: u64) {
        let Some(entry) = self.pending_broadcasts.get_mut(&request_id) else {
            return;
        };

        entry.remaining = entry.remaining.saturating_sub(1);
        if entry.remaining == 0 {
            if let Some(entry) = self.pending_broadcasts.remove(&request_id) {
                let _ = entry.responder.send(Ok(()));
            }
        }
    }

    fn finish_broadcast_error(&mut self, request_id: u64, peer: PeerId, error: HandlerFailure) {
        if let Some(entry) = self.pending_broadcasts.remove(&request_id) {
            let _ = entry.responder.send(Err(Error::BroadcastPeer {
                peer,
                source: error,
            }));
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        tracing::trace!("establishing inbound connection to peer: {:?}", peer);
        Ok(Handler::new(
            self.config.timeout,
            self.config.verifier.clone(),
            self.config.duty_gater.clone(),
            peer,
        ))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        tracing::trace!("establishing outbound connection to peer: {:?}", peer);
        Ok(Handler::new(
            self.config.timeout,
            self.config.verifier.clone(),
            self.config.duty_gater.clone(),
            peer,
        ))
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        tracing::trace!("received connection handler event: {:?}", event);
        match event {
            FromHandler::Received { duty, data_set } => {
                self.events.push_back(Event::Received {
                    peer: peer_id,
                    connection: connection_id,
                    duty,
                    data_set,
                });
            }
            FromHandler::InboundError(error) => {
                self.events.push_back(Event::Error {
                    peer: peer_id,
                    connection: connection_id,
                    error,
                });
            }
            FromHandler::OutboundSuccess { request_id } => {
                self.finish_broadcast_success(request_id);
            }
            FromHandler::OutboundError { request_id, error } => {
                self.finish_broadcast_error(request_id, peer_id, error);
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        tracing::trace!("polling parsigex behaviour");

        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }

        if let Poll::Ready(Some(command)) = self.rx.poll_recv(cx) {
            self.handle_command(command);
        }

        if let Some(action) = self.pending_actions.pop_front() {
            return Poll::Ready(action);
        }

        Poll::Pending
    }
}
