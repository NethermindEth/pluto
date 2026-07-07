//! libp2p adapter for QBFT consensus messages.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use either::Either;
use futures::{AsyncRead, AsyncWrite, AsyncWriteExt, FutureExt, StreamExt};
use libp2p::{
    Multiaddr, PeerId,
    core::upgrade::ReadyUpgrade,
    swarm::{
        ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, DialError,
        FromSwarm, NetworkBehaviour, NotifyHandler, Stream, StreamProtocol, StreamUpgradeError,
        SubstreamProtocol, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
        dial_opts::{DialOpts, PeerCondition},
        dummy,
        handler::{
            ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
        },
    },
};
use tokio::{sync::mpsc, time::timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{protocols::QBFT_V2_PROTOCOL_ID, qbft::BroadcastResult};
use pluto_core::corepb::v1::consensus as pbconsensus;
use pluto_p2p::p2p_context::P2PContext;

use super::Consensus;

/// Caps the wire size of an incoming `QbftConsensusMsg`, well below the 128 MB
/// default p2p frame limit. A legitimate message carries at most a handful of
/// small justification sub-messages (bounded in `handle`) plus its values, the
/// largest of which is a single block proposal (a few MB on mainnet); 32 MB
/// leaves ample margin while bounding the receive/decode/allocation cost a
/// malicious peer can inflict per message.
pub const MAX_CONSENSUS_MSG_SIZE: usize = 32 * 1024 * 1024;

/// Charon-compatible inbound receive timeout.
pub const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Charon-compatible outbound send timeout.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(7);

/// Returns the QBFT libp2p stream protocol.
pub fn protocol_id() -> StreamProtocol {
    StreamProtocol::new(QBFT_V2_PROTOCOL_ID)
}

/// QBFT libp2p adapter configuration.
#[derive(Clone)]
pub struct Config {
    /// Consensus component that admits inbound QBFT messages.
    pub consensus: Arc<Consensus>,
    /// Shared runtime P2P state, source of truth for cluster membership and
    /// connection checks.
    pub p2p_context: P2PContext,
    /// Local libp2p peer ID.
    pub local_peer_id: PeerId,
    /// Cancellation token for inbound admission.
    pub cancellation: CancellationToken,
}

/// QBFT adapter construction errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Local peer ID is absent from the configured cluster peer list.
    #[error("local qbft peer missing: {peer_id}")]
    LocalPeerMissing {
        /// Missing local peer ID.
        peer_id: PeerId,
    },

    /// Behaviour command channel is closed.
    #[error("qbft p2p behaviour is no longer running")]
    BehaviourClosed,
}

/// Inbound QBFT stream read or admission failure.
#[derive(Debug, thiserror::Error)]
pub enum InboundError {
    /// Reading the framed protobuf message failed.
    #[error("read qbft frame: {0}")]
    Read(#[source] std::io::Error),

    /// Consensus admission rejected the message.
    #[error("admit qbft message: {0}")]
    Admit(#[source] super::component::Error),

    /// The inbound stream exceeded the receive timeout.
    #[error("inbound stream timed out")]
    Timeout,
}

/// Outbound QBFT stream write, upgrade, or dial failure.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// Writing the framed protobuf message to the stream failed.
    #[error("write qbft frame: {0}")]
    Write(#[source] std::io::Error),

    /// Closing the outbound stream after writing failed.
    #[error("close qbft stream: {0}")]
    Close(#[source] std::io::Error),

    /// The outbound stream exceeded the send timeout.
    #[error("outbound stream timed out")]
    Timeout,

    /// Negotiating the QBFT protocol on the outbound stream failed.
    #[error("protocol negotiation failed")]
    NegotiationFailed,

    /// Upgrading the outbound stream failed.
    #[error("outbound stream upgrade failed: {0}")]
    Upgrade(String),

    /// Dialing the peer failed before a stream could open.
    #[error("dial failed: {0}")]
    Dial(String),
}

/// Event emitted by the QBFT libp2p adapter.
#[derive(Debug)]
pub enum Event {
    /// A broadcast command was queued for network delivery.
    BroadcastQueued {
        /// Broadcast request identifier.
        request_id: u64,
        /// Number of non-self target peers.
        target_count: usize,
    },
    /// A QBFT message was admitted from an inbound stream.
    Received {
        /// Remote peer.
        peer: PeerId,
        /// Connection that carried the stream.
        connection: ConnectionId,
    },
    /// Inbound stream read or admission failed.
    InboundError {
        /// Remote peer.
        peer: PeerId,
        /// Connection that carried the stream.
        connection: ConnectionId,
        /// Failure reason.
        error: InboundError,
    },
    /// Outbound stream write completed.
    Sent {
        /// Broadcast request identifier.
        request_id: u64,
        /// Target peer.
        peer: PeerId,
    },
    /// Outbound stream write or dial failed.
    SendError {
        /// Broadcast request identifier.
        request_id: u64,
        /// Target peer.
        peer: PeerId,
        /// Failure reason.
        error: SendError,
    },
}

/// User-facing handle for QBFT outbound broadcasts.
#[derive(Clone, Debug)]
pub struct Handle {
    cmd_tx: mpsc::UnboundedSender<BroadcastCommand>,
    next_request_id: Arc<AtomicU64>,
}

impl Handle {
    /// Enqueues a QBFT message for async broadcast to every non-self peer.
    pub async fn broadcast(&self, msg: pbconsensus::QbftConsensusMsg) -> BroadcastResult {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.cmd_tx
            .send(BroadcastCommand {
                request_id,
                msg: Arc::new(msg),
            })
            .map_err(|_| Box::new(Error::BehaviourClosed) as _)
    }

    /// Returns a consensus broadcaster callback backed by this handle.
    pub fn broadcaster(&self) -> super::Broadcaster {
        let handle = self.clone();
        Arc::new(move |_ct, msg| {
            let handle = handle.clone();
            Box::pin(async move { handle.broadcast(msg).await })
        })
    }
}

#[derive(Debug)]
struct BroadcastCommand {
    request_id: u64,
    /// Shared so the per-peer fan-out clones a pointer rather than the
    /// (potentially multi-MB) payload.
    msg: Arc<pbconsensus::QbftConsensusMsg>,
}

#[doc(hidden)]
#[derive(Debug)]
pub enum ToHandler {
    Send {
        request_id: u64,
        msg: Arc<pbconsensus::QbftConsensusMsg>,
    },
}

#[doc(hidden)]
#[derive(Debug)]
pub enum FromHandler {
    Received,
    InboundError(InboundError),
    Sent { request_id: u64 },
    SendError { request_id: u64, error: SendError },
}

type ActiveFuture = futures::future::BoxFuture<'static, Option<FromHandler>>;

/// Connection handler for the QBFT stream protocol.
pub struct Handler {
    consensus: Arc<Consensus>,
    cancellation: CancellationToken,
    pending_open: VecDeque<(u64, Arc<pbconsensus::QbftConsensusMsg>)>,
    active_futures: futures::stream::FuturesUnordered<ActiveFuture>,
}

impl Handler {
    /// Creates a stream handler bound to the consensus component.
    fn new(consensus: Arc<Consensus>, cancellation: CancellationToken) -> Self {
        Self {
            consensus,
            cancellation,
            pending_open: VecDeque::new(),
            active_futures: futures::stream::FuturesUnordered::new(),
        }
    }

    /// Reads an inbound stream and forwards the decoded message to admission.
    fn handle_fully_negotiated_inbound(&mut self, mut stream: Stream) {
        stream.ignore_for_keep_alive();
        let consensus = Arc::clone(&self.consensus);
        let cancellation = self.cancellation.clone();
        self.active_futures.push(
            async move {
                Some(
                    match read_and_handle_inbound(
                        &mut stream,
                        consensus,
                        cancellation,
                        RECEIVE_TIMEOUT,
                    )
                    .await
                    {
                        Ok(()) => FromHandler::Received,
                        Err(error) => FromHandler::InboundError(error),
                    },
                )
            }
            .boxed(),
        );
    }

    /// Writes one outbound consensus message to a negotiated stream.
    fn handle_fully_negotiated_outbound(
        &mut self,
        mut stream: Stream,
        request_id: u64,
        msg: Arc<pbconsensus::QbftConsensusMsg>,
    ) {
        stream.ignore_for_keep_alive();
        self.active_futures.push(
            async move {
                Some(
                    match write_outbound(&mut stream, &msg, SEND_TIMEOUT).await {
                        Ok(()) => FromHandler::Sent { request_id },
                        Err(error) => FromHandler::SendError { request_id, error },
                    },
                )
            }
            .boxed(),
        );
    }

    /// Converts outbound stream upgrade failure into a behaviour event.
    fn handle_dial_upgrade_error<E>(&mut self, request_id: u64, error: StreamUpgradeError<E>)
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        let error = match error {
            StreamUpgradeError::NegotiationFailed => SendError::NegotiationFailed,
            StreamUpgradeError::Timeout => SendError::Timeout,
            StreamUpgradeError::Io(error) => SendError::Upgrade(error.to_string()),
            StreamUpgradeError::Apply(error) => SendError::Upgrade(error.to_string()),
        };
        self.active_futures
            .push(async move { Some(FromHandler::SendError { request_id, error }) }.boxed());
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = ToHandler;
    type InboundOpenInfo = ();
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundOpenInfo = (u64, Arc<pbconsensus::QbftConsensusMsg>);
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type ToBehaviour = FromHandler;

    /// Advertises the single QBFT stream protocol.
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(ReadyUpgrade::new(protocol_id()), ())
    }

    /// Queues a behaviour send request until libp2p opens a stream.
    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            ToHandler::Send { request_id, msg } => self.pending_open.push_back((request_id, msg)),
        }
    }

    /// Drives pending stream opens and completed read/write futures.
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if let Some(open_info) = self.pending_open.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(ReadyUpgrade::new(protocol_id()), open_info),
            });
        }

        while let Poll::Ready(Some(event)) = self.active_futures.poll_next_unpin(cx) {
            if let Some(event) = event {
                return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
            }
        }

        Poll::Pending
    }

    /// Routes negotiated streams and stream-open errors to handler helpers.
    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol, ..
            }) => self.handle_fully_negotiated_inbound(protocol),
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol,
                info: (request_id, msg),
                ..
            }) => self.handle_fully_negotiated_outbound(protocol, request_id, msg),
            ConnectionEvent::DialUpgradeError(DialUpgradeError {
                info: (request_id, _),
                error,
            }) => self.handle_dial_upgrade_error(request_id, error),
            _ => {}
        }
    }
}

/// Reads one inbound protobuf frame and passes it to consensus admission.
async fn read_and_handle_inbound<S>(
    stream: &mut S,
    consensus: Arc<Consensus>,
    cancellation: CancellationToken,
    receive_timeout: Duration,
) -> Result<(), InboundError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let result = timeout(receive_timeout, async {
        let msg =
            pluto_p2p::proto::read_protobuf_with_max_size::<pbconsensus::QbftConsensusMsg, _>(
                stream,
                MAX_CONSENSUS_MSG_SIZE,
            )
            .await
            .map_err(InboundError::Read)?;

        consensus
            .handle(msg, &cancellation)
            .await
            .map_err(InboundError::Admit)
    })
    .await;

    close_stream(stream).await;

    match result {
        Ok(result) => result,
        Err(_elapsed) => Err(InboundError::Timeout),
    }
}

/// Writes one outbound protobuf frame and closes the stream.
async fn write_outbound<S>(
    stream: &mut S,
    msg: &pbconsensus::QbftConsensusMsg,
    send_timeout: Duration,
) -> Result<(), SendError>
where
    S: AsyncWrite + Unpin,
{
    let result = timeout(send_timeout, async {
        pluto_p2p::proto::write_protobuf(stream, msg)
            .await
            .map_err(SendError::Write)?;
        match stream.close().await {
            Ok(()) => Ok(()),
            Err(error) if is_ignorable_close_error(&error) => Ok(()),
            Err(error) => Err(SendError::Close(error)),
        }
    })
    .await;

    match result {
        Ok(result) => result,
        Err(_elapsed) => Err(SendError::Timeout),
    }
}

/// Returns true for stream-close errors caused by already-cancelled streams.
fn is_ignorable_close_error(error: &std::io::Error) -> bool {
    error
        .to_string()
        .contains("close called for canceled stream")
}

/// Best-effort closes a stream after inbound reads.
async fn close_stream<S>(stream: &mut S)
where
    S: AsyncWrite + Unpin,
{
    if let Err(error) = stream.close().await {
        debug!(%error, "failed to close qbft p2p stream");
    }
}

#[derive(Debug)]
struct PendingSend {
    request_id: u64,
    msg: Arc<pbconsensus::QbftConsensusMsg>,
}

/// libp2p behaviour for QBFT consensus messages.
pub struct Behaviour {
    config: Config,
    cmd_rx: mpsc::UnboundedReceiver<BroadcastCommand>,
    pending_events: VecDeque<ToSwarm<Event, ToHandler>>,
    pending_by_peer: HashMap<PeerId, VecDeque<PendingSend>>,
}

impl Behaviour {
    /// Creates a behaviour and its outbound broadcast handle.
    pub fn new(config: Config) -> Result<(Self, Handle), Error> {
        if !config.p2p_context.is_known_peer(&config.local_peer_id) {
            return Err(Error::LocalPeerMissing {
                peer_id: config.local_peer_id,
            });
        }

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let handle = Handle {
            cmd_tx,
            next_request_id: Arc::new(AtomicU64::new(0)),
        };

        Ok((
            Self {
                config,
                cmd_rx,
                pending_events: VecDeque::new(),
                pending_by_peer: HashMap::new(),
            },
            handle,
        ))
    }

    /// Returns a real QBFT handler only for configured cluster peers.
    fn connection_handler_for_peer(&self, peer_id: PeerId) -> THandler<Self> {
        if self.config.p2p_context.is_known_peer(&peer_id) {
            Either::Left(Handler::new(
                Arc::clone(&self.config.consensus),
                self.config.cancellation.clone(),
            ))
        } else {
            Either::Right(dummy::ConnectionHandler)
        }
    }

    /// Returns whether the peer store has any live connection for the peer.
    fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.config
            .p2p_context
            .peer_store_lock()
            .has_connection(peer_id)
    }

    /// Drains outbound broadcast commands queued through the public handle.
    fn drain_commands(&mut self, cx: &mut Context<'_>) {
        while let Poll::Ready(Some(command)) = self.cmd_rx.poll_recv(cx) {
            self.handle_broadcast(command);
        }
    }

    /// Fans a broadcast command out to every non-self peer.
    fn handle_broadcast(&mut self, command: BroadcastCommand) {
        let local_peer_id = self.config.local_peer_id;
        let targets: Vec<PeerId> = self
            .config
            .p2p_context
            .known_peers()
            .iter()
            .copied()
            .filter(|peer_id| *peer_id != local_peer_id)
            .collect();
        let target_count = targets.len();

        for peer_id in targets {
            self.enqueue_send(
                peer_id,
                PendingSend {
                    request_id: command.request_id,
                    msg: Arc::clone(&command.msg),
                },
            );
        }

        self.pending_events
            .push_back(ToSwarm::GenerateEvent(Event::BroadcastQueued {
                request_id: command.request_id,
                target_count,
            }));
    }

    /// Sends immediately to connected peers or queues a dial first.
    fn enqueue_send(&mut self, peer_id: PeerId, pending: PendingSend) {
        if self.is_connected(&peer_id) {
            self.pending_events.push_back(ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event: ToHandler::Send {
                    request_id: pending.request_id,
                    msg: pending.msg,
                },
            });
            return;
        }

        self.pending_by_peer
            .entry(peer_id)
            .or_default()
            .push_back(pending);
        self.pending_events.push_back(ToSwarm::Dial {
            opts: DialOpts::peer_id(peer_id)
                .condition(PeerCondition::DisconnectedAndNotDialing)
                .build(),
        });
    }

    /// Emits all queued sends for a peer after connection establishment.
    fn flush_pending_for_peer(&mut self, peer_id: PeerId) {
        let Some(mut pending) = self.pending_by_peer.remove(&peer_id) else {
            return;
        };

        while let Some(pending) = pending.pop_front() {
            self.pending_events.push_back(ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event: ToHandler::Send {
                    request_id: pending.request_id,
                    msg: pending.msg,
                },
            });
        }
    }

    /// Converts queued sends for an unreachable peer into send errors.
    fn fail_pending_for_peer(&mut self, peer_id: PeerId, error: &DialError) {
        let Some(pending) = self.pending_by_peer.remove(&peer_id) else {
            return;
        };

        for pending in pending {
            self.pending_events
                .push_back(ToSwarm::GenerateEvent(Event::SendError {
                    request_id: pending.request_id,
                    peer: peer_id,
                    error: SendError::Dial(error.to_string()),
                }));
        }
    }

    /// Handles dial failures without dropping sends that libp2p is still
    /// dialing.
    fn on_dial_failure(&mut self, peer_id: PeerId, error: &DialError) {
        if self.is_connected(&peer_id) {
            self.flush_pending_for_peer(peer_id);
            return;
        }

        if matches!(error, DialError::DialPeerConditionFalse(_)) {
            return;
        }

        self.fail_pending_for_peer(peer_id, error);
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Either<Handler, dummy::ConnectionHandler>;
    type ToSwarm = Event;

    /// Creates the per-connection handler for accepted inbound connections.
    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.connection_handler_for_peer(peer))
    }

    /// Supplies queued peer-store addresses for outbound dials.
    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _effective_role: libp2p::core::Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let Some(peer_id) = maybe_peer else {
            return Ok(vec![]);
        };

        Ok(self
            .config
            .p2p_context
            .peer_store_lock()
            .peer_addresses(&peer_id)
            .cloned()
            .unwrap_or_default())
    }

    /// Creates the per-connection handler for established outbound connections.
    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.connection_handler_for_peer(peer))
    }

    /// Flushes or fails pending sends based on swarm connection events.
    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(event) => {
                self.flush_pending_for_peer(event.peer_id);
            }
            FromSwarm::DialFailure(event) => {
                if let Some(peer_id) = event.peer_id {
                    self.on_dial_failure(peer_id, event.error);
                }
            }
            _ => {}
        }
    }

    /// Converts handler read/write outcomes into behaviour events.
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

        match event {
            FromHandler::Received => {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::Received {
                        peer: peer_id,
                        connection: connection_id,
                    }));
            }
            FromHandler::InboundError(error) => {
                warn!(%peer_id, %error, "dropping invalid qbft p2p message");
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::InboundError {
                        peer: peer_id,
                        connection: connection_id,
                        error,
                    }));
            }
            FromHandler::Sent { request_id } => {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::Sent {
                        request_id,
                        peer: peer_id,
                    }));
            }
            FromHandler::SendError { request_id, error } => {
                warn!(%peer_id, %error, "failed to send qbft p2p message");
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::SendError {
                        request_id,
                        peer: peer_id,
                        error,
                    }));
            }
        }
    }

    /// Polls command input first, then emits one pending swarm action.
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.drain_commands(cx);

        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event.map_in(Either::Left));
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashSet},
        error::Error as StdError,
        sync::OnceLock,
        task::{Context, Poll},
    };

    use futures::{StreamExt as _, io::Cursor, task::noop_waker};
    use k256::SecretKey;
    use libp2p::{
        Multiaddr, PeerId,
        identity::Keypair,
        multiaddr::Protocol,
        swarm::{
            ConnectionId, DialError, DialFailure, NetworkBehaviour, SwarmEvent, ToSwarm,
            dial_opts::PeerCondition,
        },
    };
    use prost::{Message, bytes::Bytes};
    use prost_types::Any;
    use tokio::{
        sync::{mpsc, oneshot},
        task::JoinSet,
    };

    use crate::{
        protocols::QBFT_V2_PROTOCOL_ID,
        qbft::{
            component::{
                Peer,
                tests::{config_base, consensus, duty, secret_key},
            },
            msg,
        },
    };
    use pluto_core::{
        corepb::v1::{consensus as pbconsensus, core as pbcore},
        qbft,
        types::Duty,
    };
    use pluto_p2p::{
        behaviours::pluto::PlutoBehaviourEvent,
        config::P2PConfig,
        p2p::{Node, NodeType},
        p2p_context::{P2PContext, Peer as StoredPeer},
    };

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);
    const LIBP2P_SETUP_TIMEOUT: Duration = Duration::from_secs(60);
    const REFERENCE_SIGNATURE: &str = "4cf90756a4241bce7b71e18c6fb9cf91dc96abc6ef1739218974d96e75faf0a15921d47997210232cf064b5e401c6de800fb1f654fcadca0e293dea335fe924200";
    const REFERENCE_PAYLOAD: &str = "0a6f08021204082a1002200142414cf90756a4241bce7b71e18c6fb9cf91dc96abc6ef1739218974d96e75faf0a15921d47997210232cf064b5e401c6de800fb1f654fcadca0e293dea335fe9242005a200a0c0a04307839391204010203040000000000000000000000000000000000001a440a32747970652e676f6f676c65617069732e636f6d2f636f72652e636f726570622e76312e556e7369676e656444617461536574120e0a0c0a0430783939120401020304";
    const REFERENCE_FRAME: &str = "b7010a6f08021204082a1002200142414cf90756a4241bce7b71e18c6fb9cf91dc96abc6ef1739218974d96e75faf0a15921d47997210232cf064b5e401c6de800fb1f654fcadca0e293dea335fe9242005a200a0c0a04307839391204010203040000000000000000000000000000000000001a440a32747970652e676f6f676c65617069732e636f6d2f636f72652e636f726570622e76312e556e7369676e656444617461536574120e0a0c0a0430783939120401020304";

    type TestResult<T> = Result<T, Box<dyn StdError + Send + Sync>>;

    #[test]
    fn protocol_id_matches_qbft_v2() {
        assert_eq!(protocol_id().to_string(), QBFT_V2_PROTOCOL_ID);
    }

    #[tokio::test]
    async fn reference_framed_message_decodes() {
        let mut cursor = Cursor::new(hex::decode(REFERENCE_FRAME).expect("valid fixture hex"));

        let decoded = pluto_p2p::proto::read_protobuf_with_max_size::<
            pbconsensus::QbftConsensusMsg,
            _,
        >(&mut cursor, pluto_p2p::proto::MAX_MESSAGE_SIZE)
        .await
        .expect("reference frame should decode");

        assert_eq!(decoded, reference_consensus_msg());
    }

    #[tokio::test]
    async fn rust_rebuilds_reference_message_and_frame() {
        let rebuilt = build_reference_consensus_msg();
        let mut frame = Cursor::new(Vec::new());

        pluto_p2p::proto::write_protobuf(&mut frame, &rebuilt)
            .await
            .expect("frame write should succeed");

        assert_eq!(rebuilt, reference_consensus_msg());
        assert_eq!(hex::encode(rebuilt.encode_to_vec()), REFERENCE_PAYLOAD);
        assert_eq!(hex::encode(frame.into_inner()), REFERENCE_FRAME);
    }

    #[tokio::test]
    async fn inbound_handler_decodes_and_calls_consensus_handle() -> TestResult<()> {
        let consensus = Arc::new(consensus(0, true));
        let duty = duty();
        let mut recv_rx = consensus.get_instance_io(duty.clone()).take_recv_rx()?;
        let msg = signed_consensus_msg(&duty, 1)?;
        let mut stream = Cursor::new(Vec::new());
        pluto_p2p::proto::write_protobuf(&mut stream, &msg).await?;
        stream.set_position(0);

        read_and_handle_inbound(
            &mut stream,
            Arc::clone(&consensus),
            CancellationToken::new(),
            RECEIVE_TIMEOUT,
        )
        .await
        .map_err(std::io::Error::other)?;

        let received = tokio::time::timeout(TEST_TIMEOUT, recv_rx.recv())
            .await?
            .ok_or_else(|| std::io::Error::other("receive buffer closed"))?;
        assert_eq!(received.msg().peer_idx, 1);
        Ok(())
    }

    #[tokio::test]
    async fn inbound_rejects_message_exceeding_max_consensus_size() -> TestResult<()> {
        // Frame declaring one byte over the cap; read_length_delimited rejects on
        // the varint length prefix before allocating or reading the body, so no
        // oversized payload is needed.
        let mut varint = Vec::new();
        let mut remaining = MAX_CONSENSUS_MSG_SIZE + 1;
        loop {
            let mut byte = u8::try_from(remaining & 0x7f).expect("7-bit masked value fits in u8");
            remaining >>= 7;
            if remaining != 0 {
                byte |= 0x80;
            }
            varint.push(byte);
            if remaining == 0 {
                break;
            }
        }
        let mut stream = Cursor::new(varint);

        let error = read_and_handle_inbound(
            &mut stream,
            Arc::new(consensus(0, true)),
            CancellationToken::new(),
            RECEIVE_TIMEOUT,
        )
        .await
        .expect_err("oversized inbound message must be rejected");

        assert!(
            matches!(&error, InboundError::Read(io) if io.to_string().contains("too large")),
            "expected read size error, got {error:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn outbound_broadcast_skips_self_and_targets_non_self_peers() -> TestResult<()> {
        let keys = test_keys()?;
        let peer_ids = peer_ids(&keys)?;
        let local_peer_id = peer_ids[1];
        let p2p_context = connected_context(&peer_ids)?;
        let (mut behaviour, handle) = Behaviour::new(Config {
            consensus: Arc::new(consensus(1, true)),
            p2p_context,
            local_peer_id,
            cancellation: CancellationToken::new(),
        })?;

        handle.broadcast(signed_consensus_msg(&duty(), 1)?).await?;

        let events = drain_behaviour_events(&mut behaviour);
        let targets = events
            .iter()
            .filter_map(|event| match event {
                ToSwarm::NotifyHandler {
                    peer_id,
                    event: Either::Left(ToHandler::Send { .. }),
                    ..
                } => Some(*peer_id),
                _ => None,
            })
            .collect::<HashSet<_>>();
        let queued = events.iter().find_map(|event| match event {
            ToSwarm::GenerateEvent(Event::BroadcastQueued { target_count, .. }) => {
                Some(*target_count)
            }
            _ => None,
        });

        assert_eq!(queued, Some(2));
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&peer_ids[0]));
        assert!(targets.contains(&peer_ids[2]));
        assert!(!targets.contains(&local_peer_id));

        // The fan-out must share one `Arc<QbftConsensusMsg>` across all targets
        // rather than deep-cloning the payload per peer.
        let payloads = events
            .iter()
            .filter_map(|event| match event {
                ToSwarm::NotifyHandler {
                    event: Either::Left(ToHandler::Send { msg, .. }),
                    ..
                } => Some(msg.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(payloads.len(), 2);
        assert!(Arc::ptr_eq(&payloads[0], &payloads[1]));
        Ok(())
    }

    #[tokio::test]
    async fn dial_peer_condition_false_preserves_pending_send() -> TestResult<()> {
        let keys = test_keys()?;
        let peer_ids = peer_ids(&keys)?[..2].to_vec();
        let local_peer_id = peer_ids[0];
        let target = peer_ids[1];
        let (mut behaviour, handle) = Behaviour::new(Config {
            consensus: Arc::new(consensus(0, true)),
            p2p_context: P2PContext::new(peer_ids.iter().copied()),
            local_peer_id,
            cancellation: CancellationToken::new(),
        })?;
        handle.broadcast(signed_consensus_msg(&duty(), 0)?).await?;
        let _ = drain_behaviour_events(&mut behaviour);

        let error = DialError::DialPeerConditionFalse(PeerCondition::DisconnectedAndNotDialing);
        behaviour.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: Some(target),
            error: &error,
            connection_id: ConnectionId::new_unchecked(1),
        }));
        let events = drain_behaviour_events(&mut behaviour);

        assert!(behaviour.pending_by_peer.contains_key(&target));
        assert!(!events.iter().any(|event| {
            matches!(
                event,
                ToSwarm::GenerateEvent(Event::SendError { peer, .. }) if *peer == target
            )
        }));
        Ok(())
    }

    #[tokio::test]
    async fn terminal_dial_failure_reports_pending_send_error() -> TestResult<()> {
        let keys = test_keys()?;
        let peer_ids = peer_ids(&keys)?[..2].to_vec();
        let local_peer_id = peer_ids[0];
        let target = peer_ids[1];
        let (mut behaviour, handle) = Behaviour::new(Config {
            consensus: Arc::new(consensus(0, true)),
            p2p_context: P2PContext::new(peer_ids.iter().copied()),
            local_peer_id,
            cancellation: CancellationToken::new(),
        })?;
        handle.broadcast(signed_consensus_msg(&duty(), 0)?).await?;
        let _ = drain_behaviour_events(&mut behaviour);

        let error = DialError::NoAddresses;
        behaviour.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: Some(target),
            error: &error,
            connection_id: ConnectionId::new_unchecked(1),
        }));
        let events = drain_behaviour_events(&mut behaviour);

        assert!(!behaviour.pending_by_peer.contains_key(&target));
        assert!(events.iter().any(|event| {
            matches!(
                event,
                ToSwarm::GenerateEvent(Event::SendError { peer, .. }) if *peer == target
            )
        }));
        Ok(())
    }

    #[tokio::test]
    async fn framing_round_trips_qbft_consensus_msg() -> TestResult<()> {
        let msg = signed_consensus_msg(&duty(), 1)?;
        let mut stream = Cursor::new(Vec::new());

        pluto_p2p::proto::write_protobuf(&mut stream, &msg).await?;
        stream.set_position(0);
        let decoded = pluto_p2p::proto::read_protobuf_with_max_size::<
            pbconsensus::QbftConsensusMsg,
            _,
        >(&mut stream, pluto_p2p::proto::MAX_MESSAGE_SIZE)
        .await?;

        assert_eq!(decoded, msg);
        Ok(())
    }

    #[tokio::test]
    async fn real_libp2p_loopback_uses_stream_framing() -> TestResult<()> {
        let keys = test_keys()?;
        let peer_ids = peer_ids(&keys)?;
        let mut nodes = build_nodes(keys, peer_ids.clone())?;
        let mut node0_recv = nodes
            .get_mut(0)
            .and_then(|node| node.recv_rx.take())
            .ok_or_else(|| std::io::Error::other("missing node 0 receiver"))?;
        let mut node1_recv = nodes
            .get_mut(1)
            .and_then(|node| node.recv_rx.take())
            .ok_or_else(|| std::io::Error::other("missing node 1 receiver"))?;
        let handle = nodes
            .first()
            .map(|node| node.handle.clone())
            .ok_or_else(|| std::io::Error::other("missing node 0 handle"))?;

        let (listen_tx, mut listen_rx) = mpsc::unbounded_channel();
        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let (task_err_tx, mut task_err_rx) = mpsc::unbounded_channel();
        let running = spawn_nodes(nodes, listen_tx, conn_tx, event_tx, task_err_tx)?;
        let addrs = wait_for_listen_addrs(2, &mut listen_rx, &mut task_err_rx).await?;
        dial_forward_pairs(&running, &addrs)?;
        wait_for_connections(&mut conn_rx, &peer_ids[..2]).await?;

        let network_msg = signed_consensus_msg(&duty(), 0)?;
        handle.broadcast(network_msg.clone()).await?;

        wait_for_event(&mut event_rx, 1, |event| {
            matches!(event, Event::Received { .. })
        })
        .await?;
        let received = tokio::time::timeout(TEST_TIMEOUT, node1_recv.recv())
            .await?
            .ok_or_else(|| std::io::Error::other("node 1 receive buffer closed"))?;

        assert_eq!(
            received.msg(),
            network_msg.msg.as_ref().ok_or_else(|| {
                std::io::Error::other("test message missing inner qbft message")
            })?
        );
        assert!(matches!(
            node0_recv.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        stop_nodes(running).await?;
        Ok(())
    }

    #[tokio::test]
    async fn real_libp2p_loopback_runs_consensus() -> TestResult<()> {
        let keys = test_keys()?;
        let peer_ids = peer_ids(&keys)?;
        let (decided_tx, mut decided_rx) = mpsc::unbounded_channel();
        let nodes = build_consensus_nodes(keys, peer_ids.clone(), decided_tx)?;
        let consensuses = nodes
            .iter()
            .map(|node| Arc::clone(&node.consensus))
            .collect::<Vec<_>>();

        let (listen_tx, mut listen_rx) = mpsc::unbounded_channel();
        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (task_err_tx, mut task_err_rx) = mpsc::unbounded_channel();
        let running = spawn_nodes(nodes, listen_tx, conn_tx, event_tx, task_err_tx)?;
        let addrs = wait_for_listen_addrs(peer_ids.len(), &mut listen_rx, &mut task_err_rx).await?;
        dial_forward_pairs(&running, &addrs)?;
        wait_for_connections(&mut conn_rx, &peer_ids).await?;

        let ct = CancellationToken::new();
        let duty = duty();
        let mut tasks = JoinSet::new();
        for (index, consensus) in consensuses.iter().enumerate() {
            let consensus = Arc::clone(consensus);
            let duty = duty.clone();
            let ct = ct.clone();
            tasks.spawn(async move { consensus.propose(duty, unsigned_value(index), &ct).await });
        }

        let mut decided = Vec::with_capacity(consensuses.len());
        for _ in 0..consensuses.len() {
            decided.push(
                tokio::time::timeout(TEST_TIMEOUT, decided_rx.recv())
                    .await?
                    .ok_or_else(|| std::io::Error::other("decided channel closed"))?,
            );
        }

        tokio::time::timeout(TEST_TIMEOUT, async {
            while let Some(result) = tasks.join_next().await {
                result
                    .expect("consensus task panicked")
                    .expect("consensus task failed");
            }
        })
        .await
        .map_err(|_| std::io::Error::other("timeout waiting for consensus tasks"))?;

        ct.cancel();
        stop_nodes(running).await?;

        let (_, _, expected) = decided.first().expect("at least one decision").clone();
        for (node_index, decided_duty, value) in decided {
            assert_eq!(decided_duty, duty, "node {node_index} decided wrong duty");
            assert_eq!(value, expected, "node {node_index} decided different value");
        }

        Ok(())
    }

    struct LocalNode {
        node: Node<Behaviour>,
        consensus: Arc<Consensus>,
        handle: Handle,
        recv_rx: Option<mpsc::Receiver<super::super::msg::Msg>>,
    }

    struct RunningNode {
        dial_tx: mpsc::UnboundedSender<Vec<Multiaddr>>,
        stop_tx: oneshot::Sender<()>,
        join: tokio::task::JoinHandle<TestResult<()>>,
    }

    fn build_nodes(keys: Vec<SecretKey>, peer_ids: Vec<PeerId>) -> TestResult<Vec<LocalNode>> {
        build_pluto_nodes(keys.into_iter().take(2).collect(), peer_ids)
    }

    fn build_pluto_nodes(
        keys: Vec<SecretKey>,
        peer_ids: Vec<PeerId>,
    ) -> TestResult<Vec<LocalNode>> {
        let mut nodes = Vec::with_capacity(keys.len());
        for (index, key) in keys.into_iter().enumerate() {
            let p2p_context = P2PContext::new(peer_ids.iter().copied());
            let consensus = Arc::new(consensus_for_cluster(index, peer_ids.len(), true)?);
            let mut recv_rx = Some(consensus.get_instance_io(duty()).take_recv_rx()?);
            let (behaviour, handle) = Behaviour::new(Config {
                consensus: Arc::clone(&consensus),
                p2p_context: p2p_context.clone(),
                local_peer_id: peer_ids[index],
                cancellation: CancellationToken::new(),
            })?;
            let node = Node::new_server(
                P2PConfig::default(),
                key,
                NodeType::TCP,
                false,
                p2p_context,
                None,
                move |builder, _keypair| builder.with_inner(behaviour),
            )?;

            nodes.push(LocalNode {
                node,
                consensus,
                handle,
                recv_rx: recv_rx.take(),
            });
        }

        Ok(nodes)
    }

    fn build_consensus_nodes(
        keys: Vec<SecretKey>,
        peer_ids: Vec<PeerId>,
        decided_tx: mpsc::UnboundedSender<(usize, Duty, pbcore::UnsignedDataSet)>,
    ) -> TestResult<Vec<LocalNode>> {
        let mut nodes = Vec::with_capacity(keys.len());
        for (index, key) in keys.into_iter().enumerate() {
            let p2p_context = P2PContext::new(peer_ids.iter().copied());
            let handle_slot = Arc::new(OnceLock::<Handle>::new());
            let broadcaster = {
                let handle_slot = Arc::clone(&handle_slot);
                Arc::new(move |_ct, msg| {
                    let handle = handle_slot
                        .get()
                        .expect("test p2p handle initialized")
                        .clone();
                    Box::pin(async move { handle.broadcast(msg).await })
                        as futures::future::BoxFuture<'static, BroadcastResult>
                })
            };
            let mut config = config_for_cluster(index, peer_ids.len(), true)?;
            config.broadcaster = broadcaster;
            let consensus = Arc::new(Consensus::new(config)?);
            let decided_tx = decided_tx.clone();
            consensus.subscribe(move |duty, value| {
                let _ = decided_tx.send((index, duty, value));
                Ok(())
            });

            let (behaviour, handle) = Behaviour::new(Config {
                consensus: Arc::clone(&consensus),
                p2p_context: p2p_context.clone(),
                local_peer_id: peer_ids[index],
                cancellation: CancellationToken::new(),
            })?;
            handle_slot
                .set(handle.clone())
                .map_err(|_| std::io::Error::other("test p2p handle set twice"))?;
            let node = Node::new_server(
                P2PConfig::default(),
                key,
                NodeType::TCP,
                false,
                p2p_context,
                None,
                move |builder, _keypair| builder.with_inner(behaviour),
            )?;

            nodes.push(LocalNode {
                node,
                consensus,
                handle,
                recv_rx: None,
            });
        }

        Ok(nodes)
    }

    fn consensus_for_cluster(
        local_peer_idx: usize,
        peer_count: usize,
        duty_allowed: bool,
    ) -> TestResult<Consensus> {
        Consensus::new(config_for_cluster(
            local_peer_idx,
            peer_count,
            duty_allowed,
        )?)
        .map_err(|error| Box::new(error) as _)
    }

    fn config_for_cluster(
        local_peer_idx: usize,
        peer_count: usize,
        duty_allowed: bool,
    ) -> TestResult<super::super::Config> {
        let mut config = config_base(false);
        config.peers = (0..peer_count)
            .map(|index| {
                let seed = u8::try_from(
                    index
                        .checked_add(1)
                        .ok_or_else(|| std::io::Error::other("peer index overflow"))?,
                )?;
                Ok(Peer {
                    index: i64::try_from(index)?,
                    name: format!("node-{index}"),
                    public_key: test_secret_key(seed)?.public_key(),
                })
            })
            .collect::<TestResult<Vec<_>>>()?;
        config.local_peer_idx = i64::try_from(local_peer_idx)?;
        let seed = u8::try_from(
            local_peer_idx
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("local peer index overflow"))?,
        )?;
        config.privkey = test_secret_key(seed)?;
        config.duty_gater = Arc::new(move |_| duty_allowed);

        Ok(config)
    }

    fn spawn_nodes(
        nodes: Vec<LocalNode>,
        listen_tx: mpsc::UnboundedSender<(usize, Multiaddr)>,
        conn_tx: mpsc::UnboundedSender<(usize, PeerId)>,
        event_tx: mpsc::UnboundedSender<(usize, Event)>,
        task_err_tx: mpsc::UnboundedSender<(usize, String)>,
    ) -> TestResult<Vec<RunningNode>> {
        let mut running = Vec::with_capacity(nodes.len());

        for (index, local) in nodes.into_iter().enumerate() {
            let mut node = local.node;
            let listen_tx = listen_tx.clone();
            let conn_tx = conn_tx.clone();
            let event_tx = event_tx.clone();
            let task_err_tx = task_err_tx.clone();
            let (dial_tx, mut dial_rx) = mpsc::unbounded_channel::<Vec<Multiaddr>>();
            let (stop_tx, mut stop_rx) = oneshot::channel();

            let join = tokio::spawn(async move {
                let result: TestResult<()> = async {
                    node.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;

                    loop {
                        tokio::select! {
                            _ = &mut stop_rx => break,
                            Some(targets) = dial_rx.recv() => {
                                for target in targets {
                                    node.dial(target)?;
                                }
                            }
                            event = node.next() => {
                                match event.ok_or_else(|| {
                                    std::io::Error::other("node swarm ended")
                                })? {
                                    SwarmEvent::NewListenAddr { address, .. } => {
                                        let _ = listen_tx.send((index, address));
                                    }
                                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                        let _ = conn_tx.send((index, peer_id));
                                    }
                                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(event)) => {
                                        let _ = event_tx.send((index, event));
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    Ok(())
                }
                .await;

                if let Err(error) = &result {
                    let _ = task_err_tx.send((index, format!("{error:?}")));
                }

                result
            });

            running.push(RunningNode {
                dial_tx,
                stop_tx,
                join,
            });
        }

        Ok(running)
    }

    async fn wait_for_listen_addrs(
        node_count: usize,
        listen_rx: &mut mpsc::UnboundedReceiver<(usize, Multiaddr)>,
        task_err_rx: &mut mpsc::UnboundedReceiver<(usize, String)>,
    ) -> TestResult<Vec<Multiaddr>> {
        tokio::time::timeout(LIBP2P_SETUP_TIMEOUT, async {
            let mut addrs = vec![None; node_count];
            while addrs.iter().any(Option::is_none) {
                tokio::select! {
                    result = listen_rx.recv() => {
                        let Some((index, addr)) = result else {
                            if let Ok((index, error)) = task_err_rx.try_recv() {
                                return Err(Box::new(std::io::Error::other(format!(
                                    "node {index} exited before listen: {error}"
                                ))) as Box<dyn StdError + Send + Sync>);
                            }
                            return Err(Box::new(std::io::Error::other("listen channel closed"))
                                as Box<dyn StdError + Send + Sync>);
                        };
                        if index < addrs.len() && addrs[index].is_none() {
                            addrs[index] = Some(addr);
                        }
                    }
                    result = task_err_rx.recv() => {
                        let (index, error) = result
                            .ok_or_else(|| std::io::Error::other("node task error channel closed"))?;
                        return Err(Box::new(std::io::Error::other(format!(
                            "node {index} exited before listen: {error}"
                        ))) as Box<dyn StdError + Send + Sync>);
                    }
                }
            }

            addrs
                .into_iter()
                .map(|addr| {
                    addr.ok_or_else(|| {
                        Box::new(std::io::Error::other("missing listen address"))
                            as Box<dyn StdError + Send + Sync>
                    })
                })
                .collect()
        })
        .await
        .map_err(|_| std::io::Error::other("timeout waiting for listen addresses"))?
    }

    fn dial_forward_pairs(running: &[RunningNode], addrs: &[Multiaddr]) -> TestResult<()> {
        for (index, node) in running.iter().enumerate() {
            let targets = addrs
                .iter()
                .enumerate()
                .filter(|(other, _)| *other > index)
                .map(|(_, addr)| addr.clone())
                .collect::<Vec<_>>();
            node.dial_tx.send(targets)?;
        }

        Ok(())
    }

    async fn wait_for_connections(
        conn_rx: &mut mpsc::UnboundedReceiver<(usize, PeerId)>,
        peer_ids: &[PeerId],
    ) -> TestResult<()> {
        tokio::time::timeout(LIBP2P_SETUP_TIMEOUT, async {
            let mut seen = vec![HashSet::new(); peer_ids.len()];
            let expected_connections = peer_ids.len().saturating_sub(1);
            while seen.iter().any(|peers| peers.len() < expected_connections) {
                let (index, peer_id) = conn_rx
                    .recv()
                    .await
                    .ok_or_else(|| std::io::Error::other("connection channel closed"))?;
                if index < seen.len() && peer_ids.contains(&peer_id) {
                    seen[index].insert(peer_id);
                }
            }

            Ok(())
        })
        .await
        .map_err(|_| std::io::Error::other("timeout waiting for loopback connections"))?
    }

    async fn wait_for_event(
        event_rx: &mut mpsc::UnboundedReceiver<(usize, Event)>,
        node_index: usize,
        predicate: impl Fn(&Event) -> bool,
    ) -> TestResult<()> {
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                let (index, event) = event_rx
                    .recv()
                    .await
                    .ok_or_else(|| std::io::Error::other("event channel closed"))?;
                if index == node_index && predicate(&event) {
                    return Ok(());
                }
            }
        })
        .await
        .map_err(|_| std::io::Error::other("timeout waiting for QBFT p2p event"))?
    }

    async fn stop_nodes(running: Vec<RunningNode>) -> TestResult<()> {
        for node in running {
            let _ = node.stop_tx.send(());
            node.join.await??;
        }

        Ok(())
    }

    fn drain_behaviour_events(
        behaviour: &mut Behaviour,
    ) -> Vec<ToSwarm<Event, THandlerInEvent<Behaviour>>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut events = Vec::new();

        while let Poll::Ready(event) = NetworkBehaviour::poll(behaviour, &mut cx) {
            events.push(event);
        }

        events
    }

    fn connected_context(peer_ids: &[PeerId]) -> TestResult<P2PContext> {
        let context = P2PContext::new(peer_ids.iter().copied());
        for (index, peer_id) in peer_ids.iter().copied().enumerate() {
            let connection_index = index
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("connection index overflow"))?;
            context.peer_store_write_lock().add_peer(StoredPeer {
                id: peer_id,
                connection_id: ConnectionId::new_unchecked(connection_index),
                remote_addr: Multiaddr::empty()
                    .with(Protocol::Memory(u64::try_from(connection_index)?)),
            });
        }

        Ok(context)
    }

    fn unsigned_value(seed: usize) -> pbcore::UnsignedDataSet {
        let mut set = BTreeMap::new();
        set.insert(
            format!("validator-{seed}"),
            Bytes::from(format!("unsigned-{seed}")),
        );
        pbcore::UnsignedDataSet { set }
    }

    fn test_keys() -> TestResult<Vec<SecretKey>> {
        test_keys_n(3)
    }

    fn test_keys_n(count: u8) -> TestResult<Vec<SecretKey>> {
        let mut keys = Vec::with_capacity(usize::from(count));
        for seed in 1..=count {
            keys.push(match seed {
                1 => secret_key(1),
                2 => secret_key(2),
                _ => test_secret_key(seed)?,
            });
        }

        Ok(keys)
    }

    fn test_secret_key(seed: u8) -> TestResult<SecretKey> {
        SecretKey::from_slice(&[seed; 32]).map_err(|error| Box::new(error) as _)
    }

    fn peer_ids(keys: &[SecretKey]) -> TestResult<Vec<PeerId>> {
        keys.iter().map(peer_id).collect()
    }

    fn peer_id(key: &SecretKey) -> TestResult<PeerId> {
        let mut der = key.to_sec1_der()?;
        Ok(Keypair::secp256k1_from_der(&mut der)?.public().to_peer_id())
    }

    fn build_reference_consensus_msg() -> pbconsensus::QbftConsensusMsg {
        let value = reference_value();
        let value_hash = msg::hash_proto(&value).expect("value should hash");
        let signed = msg::sign_msg(
            &pbconsensus::QbftMsg {
                r#type: i64::from(pluto_core::qbft::MSG_PREPARE),
                duty: Some(pbcore::Duty {
                    slot: 42,
                    r#type: 2,
                }),
                peer_idx: 0,
                round: 1,
                value_hash: value_hash.to_vec().into(),
                ..Default::default()
            },
            &secret_key(1),
        )
        .expect("message should sign");

        assert_eq!(hex::encode(&signed.signature), REFERENCE_SIGNATURE);

        pbconsensus::QbftConsensusMsg {
            msg: Some(signed),
            justification: vec![],
            values: vec![Any::from_msg(&value).expect("value should pack")],
        }
    }

    fn reference_consensus_msg() -> pbconsensus::QbftConsensusMsg {
        pbconsensus::QbftConsensusMsg::decode(
            hex::decode(REFERENCE_PAYLOAD)
                .expect("valid fixture hex")
                .as_slice(),
        )
        .expect("reference payload should decode")
    }

    fn reference_value() -> pbcore::UnsignedDataSet {
        let mut set = std::collections::BTreeMap::new();
        set.insert("0x99".to_string(), Bytes::from_static(&[1, 2, 3, 4]));
        pbcore::UnsignedDataSet { set }
    }

    fn signed_consensus_msg(
        duty: &pluto_core::types::Duty,
        peer_idx: i64,
    ) -> TestResult<pbconsensus::QbftConsensusMsg> {
        let value = reference_value();
        let value_hash = msg::hash_proto(&value)?;
        let key = match peer_idx {
            0 => secret_key(1),
            1 => secret_key(2),
            _ => test_secret_key(u8::try_from(
                peer_idx
                    .checked_add(1)
                    .ok_or_else(|| std::io::Error::other("peer index overflow"))?,
            )?)?,
        };
        let msg = pbconsensus::QbftMsg {
            r#type: i64::from(qbft::MSG_PREPARE),
            duty: Some(pbcore::Duty::try_from(duty)?),
            peer_idx,
            round: 1,
            value_hash: value_hash.to_vec().into(),
            prepared_value_hash: Bytes::new(),
            ..Default::default()
        };

        Ok(pbconsensus::QbftConsensusMsg {
            msg: Some(msg::sign_msg(&msg, &key)?),
            justification: Vec::new(),
            values: vec![Any::from_msg(&value)?],
        })
    }
}
