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
use tokio::{
    sync::mpsc,
    time::{error::Elapsed, timeout},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{protocols::QBFT_V2_PROTOCOL_ID, qbft::BroadcastResult};
use pluto_core::corepb::v1::consensus as pbconsensus;
use pluto_p2p::p2p_context::P2PContext;

use super::Consensus;

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
    /// Shared runtime P2P state for connection checks.
    pub p2p_context: P2PContext,
    /// Cluster peer IDs in consensus peer order.
    pub peers: Vec<PeerId>,
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
        error: String,
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
        error: String,
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
    pub async fn broadcast(
        &self,
        _ct: CancellationToken,
        msg: pbconsensus::QbftConsensusMsg,
    ) -> BroadcastResult {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.cmd_tx
            .send(BroadcastCommand { request_id, msg })
            .map_err(|_| Box::new(Error::BehaviourClosed) as _)
    }

    /// Returns a consensus broadcaster callback backed by this handle.
    pub fn broadcaster(&self) -> super::Broadcaster {
        let handle = self.clone();
        Arc::new(move |ct, msg| {
            let handle = handle.clone();
            Box::pin(async move { handle.broadcast(ct, msg).await })
        })
    }
}

#[derive(Debug)]
struct BroadcastCommand {
    request_id: u64,
    msg: pbconsensus::QbftConsensusMsg,
}

#[doc(hidden)]
#[derive(Debug)]
pub enum ToHandler {
    Send {
        request_id: u64,
        msg: pbconsensus::QbftConsensusMsg,
    },
}

#[doc(hidden)]
#[derive(Debug)]
pub enum FromHandler {
    Received,
    InboundError(String),
    Sent { request_id: u64 },
    SendError { request_id: u64, error: String },
}

type ActiveFuture = futures::future::BoxFuture<'static, Option<FromHandler>>;

/// Connection handler for the QBFT stream protocol.
pub struct Handler {
    consensus: Arc<Consensus>,
    cancellation: CancellationToken,
    pending_open: VecDeque<(u64, pbconsensus::QbftConsensusMsg)>,
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
        msg: pbconsensus::QbftConsensusMsg,
    ) {
        stream.ignore_for_keep_alive();
        self.active_futures.push(
            async move {
                Some(
                    match write_outbound(&mut stream, request_id, &msg, SEND_TIMEOUT).await {
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
            StreamUpgradeError::NegotiationFailed => "protocol negotiation failed".to_string(),
            StreamUpgradeError::Timeout => "operation timed out".to_string(),
            StreamUpgradeError::Io(error) => error.to_string(),
            StreamUpgradeError::Apply(error) => error.to_string(),
        };
        self.active_futures
            .push(async move { Some(FromHandler::SendError { request_id, error }) }.boxed());
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = ToHandler;
    type InboundOpenInfo = ();
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundOpenInfo = (u64, pbconsensus::QbftConsensusMsg);
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
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let result = timeout(receive_timeout, async {
        let msg =
            pluto_p2p::proto::read_protobuf_with_max_size::<pbconsensus::QbftConsensusMsg, _>(
                stream,
                pluto_p2p::proto::MAX_MESSAGE_SIZE,
            )
            .await
            .map_err(|error| error.to_string())?;

        consensus
            .handle(&cancellation, Some(msg))
            .await
            .map_err(|error| error.to_string())
    })
    .await;

    close_stream(stream).await;

    match result {
        Ok(result) => result,
        Err(error) => Err(timeout_error(error)),
    }
}

/// Writes one outbound protobuf frame and closes the stream.
async fn write_outbound<S>(
    stream: &mut S,
    request_id: u64,
    msg: &pbconsensus::QbftConsensusMsg,
    send_timeout: Duration,
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let result = timeout(send_timeout, async {
        pluto_p2p::proto::write_protobuf(stream, msg)
            .await
            .map_err(|error| error.to_string())?;
        match stream.close().await {
            Ok(()) => Ok(()),
            Err(error) if is_ignorable_close_error(&error) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(error) => Err(format!("request {request_id}: {}", timeout_error(error))),
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

/// Formats libp2p timeout errors consistently.
fn timeout_error(_error: Elapsed) -> String {
    "operation timed out".to_string()
}

#[derive(Debug)]
struct PendingSend {
    request_id: u64,
    msg: pbconsensus::QbftConsensusMsg,
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
        if !config.peers.contains(&config.local_peer_id) {
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
        if self.config.peers.contains(&peer_id) {
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
        !self
            .config
            .p2p_context
            .peer_store_lock()
            .connections_to_peer(peer_id)
            .is_empty()
    }

    /// Drains outbound broadcast commands queued through the public handle.
    fn drain_commands(&mut self, cx: &mut Context<'_>) {
        while let Poll::Ready(Some(command)) = self.cmd_rx.poll_recv(cx) {
            self.handle_broadcast(command);
        }
    }

    /// Fans a broadcast command out to every non-self peer.
    fn handle_broadcast(&mut self, command: BroadcastCommand) {
        let mut target_count = 0usize;
        for peer_id in self.config.peers.clone() {
            if peer_id == self.config.local_peer_id {
                continue;
            }

            target_count = target_count.saturating_add(1);
            self.enqueue_send(
                peer_id,
                PendingSend {
                    request_id: command.request_id,
                    msg: command.msg.clone(),
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
    fn fail_pending_for_peer(&mut self, peer_id: PeerId, error: String) {
        let Some(pending) = self.pending_by_peer.remove(&peer_id) else {
            return;
        };

        for pending in pending {
            self.pending_events
                .push_back(ToSwarm::GenerateEvent(Event::SendError {
                    request_id: pending.request_id,
                    peer: peer_id,
                    error: error.clone(),
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

        self.fail_pending_for_peer(peer_id, error.to_string());
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
        collections::HashSet,
        error::Error as StdError,
        fs,
        path::{Path, PathBuf},
        process::Stdio,
        task::{Context, Poll},
        time::{SystemTime, UNIX_EPOCH},
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
    use prost::bytes::Bytes;
    use tokio::{
        io::{AsyncBufReadExt, BufReader, Lines},
        process::{Child, ChildStdout, Command},
        sync::{mpsc, oneshot},
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
        qbft::{self, SomeMsg},
    };
    use pluto_p2p::{
        behaviours::pluto::PlutoBehaviourEvent,
        config::P2PConfig,
        p2p::{Node, NodeType},
        p2p_context::{P2PContext, Peer as StoredPeer},
    };

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);
    const GO_INTEROP_TIMEOUT: Duration = Duration::from_secs(60);

    type TestResult<T> = Result<T, Box<dyn StdError + Send + Sync>>;

    #[test]
    fn protocol_id_matches_qbft_v2() {
        assert_eq!(protocol_id().to_string(), QBFT_V2_PROTOCOL_ID);
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
    async fn outbound_broadcast_skips_self_and_targets_non_self_peers() -> TestResult<()> {
        let keys = test_keys()?;
        let peer_ids = peer_ids(&keys)?;
        let local_peer_id = peer_ids[1];
        let p2p_context = connected_context(&peer_ids)?;
        let (mut behaviour, handle) = Behaviour::new(Config {
            consensus: Arc::new(consensus(1, true)),
            p2p_context,
            peers: peer_ids.clone(),
            local_peer_id,
            cancellation: CancellationToken::new(),
        })?;

        handle
            .broadcast(CancellationToken::new(), signed_consensus_msg(&duty(), 1)?)
            .await?;

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
            peers: peer_ids,
            local_peer_id,
            cancellation: CancellationToken::new(),
        })?;
        handle
            .broadcast(CancellationToken::new(), signed_consensus_msg(&duty(), 0)?)
            .await?;
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
            peers: peer_ids,
            local_peer_id,
            cancellation: CancellationToken::new(),
        })?;
        handle
            .broadcast(CancellationToken::new(), signed_consensus_msg(&duty(), 0)?)
            .await?;
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
        let addrs = wait_for_listen_addrs(&mut listen_rx, &mut task_err_rx).await?;
        dial_forward_pairs(&running, &addrs)?;
        wait_for_connections(&mut conn_rx, &peer_ids).await?;

        let network_msg = signed_consensus_msg(&duty(), 0)?;
        handle
            .broadcast(CancellationToken::new(), network_msg.clone())
            .await?;

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
    #[ignore = "requires local Charon source, Go toolchain, and local TCP sockets"]
    async fn mixed_charon_pluto_libp2p_interop() -> TestResult<()> {
        let keys = test_keys_n(4)?;
        let peer_ids = peer_ids(&keys)?;
        let mut nodes = build_pluto_nodes(keys[..2].to_vec(), peer_ids.clone())?;
        let mut node0_recv = nodes
            .get_mut(0)
            .and_then(|node| node.recv_rx.take())
            .ok_or_else(|| std::io::Error::other("missing node 0 receiver"))?;
        let mut node1_recv = nodes
            .get_mut(1)
            .and_then(|node| node.recv_rx.take())
            .ok_or_else(|| std::io::Error::other("missing node 1 receiver"))?;
        let handle0 = nodes
            .first()
            .map(|node| node.handle.clone())
            .ok_or_else(|| std::io::Error::other("missing node 0 handle"))?;
        let handle1 = nodes
            .get(1)
            .map(|node| node.handle.clone())
            .ok_or_else(|| std::io::Error::other("missing node 1 handle"))?;

        let (listen_tx, mut listen_rx) = mpsc::unbounded_channel();
        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let (task_err_tx, mut task_err_rx) = mpsc::unbounded_channel();
        let running = spawn_nodes(nodes, listen_tx, conn_tx, event_tx, task_err_tx)?;
        let rust_addrs = wait_for_listen_addrs(&mut listen_rx, &mut task_err_rx).await?;

        let harness_dir = write_go_interop_harness()?;
        let mut child = spawn_go_interop(&harness_dir, &rust_addrs)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("missing go harness stdout"))?;
        let mut go_lines = BufReader::new(stdout).lines();

        let result =
            async {
                let go_addrs = wait_for_go_ready(&mut go_lines).await?;
                dial_go_peers(&running, &go_addrs)?;
                wait_for_specific_connections(&mut conn_rx, &[0, 1], &peer_ids[2..4]).await?;

                wait_for_sources(&mut node0_recv, &mut event_rx, 0, &[2, 3]).await?;
                wait_for_sources(&mut node1_recv, &mut event_rx, 1, &[2, 3]).await?;

                handle0
                    .broadcast(CancellationToken::new(), signed_consensus_msg(&duty(), 0)?)
                    .await?;
                handle1
                    .broadcast(CancellationToken::new(), signed_consensus_msg(&duty(), 1)?)
                    .await?;

                wait_for_event(&mut event_rx, 0, |event| {
                matches!(event, Event::Sent { peer, .. } if peer_ids[2..4].contains(peer))
            })
            .await?;
                wait_for_event(&mut event_rx, 1, |event| {
                matches!(event, Event::Sent { peer, .. } if peer_ids[2..4].contains(peer))
            })
            .await?;
                wait_for_go_done(&mut go_lines).await
            }
            .await;

        drop(go_lines);
        let status = finish_go_interop(&mut child, result.is_err()).await;
        let cleanup = fs::remove_dir_all(&harness_dir);
        stop_nodes(running).await?;
        result?;
        status?;
        cleanup?;
        Ok(())
    }

    struct LocalNode {
        node: Node<Behaviour>,
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
        let mut nodes = Vec::with_capacity(2);
        for (index, key) in keys.into_iter().enumerate() {
            let p2p_context = P2PContext::new(peer_ids.iter().copied());
            let consensus = Arc::new(consensus_for_cluster(index, peer_ids.len(), true)?);
            let mut recv_rx = Some(consensus.get_instance_io(duty()).take_recv_rx()?);
            let (behaviour, handle) = Behaviour::new(Config {
                consensus,
                p2p_context: p2p_context.clone(),
                peers: peer_ids.clone(),
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
                handle,
                recv_rx: recv_rx.take(),
            });
        }

        Ok(nodes)
    }

    fn consensus_for_cluster(
        local_peer_idx: usize,
        peer_count: usize,
        duty_allowed: bool,
    ) -> TestResult<Consensus> {
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

        Consensus::new(config).map_err(|error| Box::new(error) as _)
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
                            event = node.select_next_some() => {
                                match event {
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
        listen_rx: &mut mpsc::UnboundedReceiver<(usize, Multiaddr)>,
        task_err_rx: &mut mpsc::UnboundedReceiver<(usize, String)>,
    ) -> TestResult<Vec<Multiaddr>> {
        tokio::time::timeout(GO_INTEROP_TIMEOUT, async {
            let mut addrs = vec![None, None];
            while addrs.iter().any(Option::is_none) {
                tokio::select! {
                    result = listen_rx.recv() => {
                        let (index, addr) = result
                            .ok_or_else(|| std::io::Error::other("listen channel closed"))?;
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
        tokio::time::timeout(GO_INTEROP_TIMEOUT, async {
            let mut seen = [HashSet::new(), HashSet::new()];
            while seen.iter().any(|peers| peers.is_empty()) {
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

    async fn wait_for_specific_connections(
        conn_rx: &mut mpsc::UnboundedReceiver<(usize, PeerId)>,
        node_indices: &[usize],
        expected_peers: &[PeerId],
    ) -> TestResult<()> {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let mut seen = vec![HashSet::new(); node_indices.len()];
            while seen.iter().any(|peers| peers.len() < expected_peers.len()) {
                let (index, peer_id) = conn_rx
                    .recv()
                    .await
                    .ok_or_else(|| std::io::Error::other("connection channel closed"))?;
                if let Some(position) = node_indices.iter().position(|node| *node == index)
                    && expected_peers.contains(&peer_id)
                {
                    seen[position].insert(peer_id);
                }
            }

            Ok(())
        })
        .await
        .map_err(|_| std::io::Error::other("timeout waiting for Go peer connections"))?
    }

    async fn wait_for_sources(
        recv_rx: &mut mpsc::Receiver<super::super::msg::Msg>,
        event_rx: &mut mpsc::UnboundedReceiver<(usize, Event)>,
        node_index: usize,
        expected_sources: &[i64],
    ) -> TestResult<()> {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let mut seen = HashSet::new();
            while seen.len() < expected_sources.len() {
                tokio::select! {
                    msg = recv_rx.recv() => {
                        let msg = msg.ok_or_else(|| std::io::Error::other("receive buffer closed"))?;
                        if expected_sources.contains(&msg.source()) {
                            seen.insert(msg.source());
                        }
                    }
                    event = event_rx.recv() => {
                        let (index, event) = event.ok_or_else(|| std::io::Error::other("event channel closed"))?;
                        if index == node_index
                            && let Event::InboundError { error, .. } = event
                        {
                            return Err(Box::new(std::io::Error::other(error))
                                as Box<dyn StdError + Send + Sync>);
                        }
                    }
                }
            }

            Ok(())
        })
        .await
        .map_err(|_| std::io::Error::other("timeout waiting for Charon inbound messages"))?
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

    fn signed_consensus_msg(
        duty: &pluto_core::types::Duty,
        peer_idx: i64,
    ) -> TestResult<pbconsensus::QbftConsensusMsg> {
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
            value_hash: Bytes::new(),
            prepared_value_hash: Bytes::new(),
            ..Default::default()
        };

        Ok(pbconsensus::QbftConsensusMsg {
            msg: Some(msg::sign_msg(&msg, &key)?),
            justification: Vec::new(),
            values: Vec::new(),
        })
    }

    type GoLines = Lines<BufReader<ChildStdout>>;

    fn dial_go_peers(running: &[RunningNode], go_addrs: &[Multiaddr]) -> TestResult<()> {
        for node in running {
            node.dial_tx.send(go_addrs.to_vec())?;
        }

        Ok(())
    }

    async fn wait_for_go_ready(lines: &mut GoLines) -> TestResult<Vec<Multiaddr>> {
        let line = read_go_line(lines, "READY ").await?;
        line.strip_prefix("READY ")
            .ok_or_else(|| std::io::Error::other("missing go ready prefix"))?
            .split_whitespace()
            .map(|addr| addr.parse().map_err(|error| Box::new(error) as _))
            .collect()
    }

    async fn wait_for_go_done(lines: &mut GoLines) -> TestResult<()> {
        tokio::time::timeout(GO_INTEROP_TIMEOUT, async {
            loop {
                let line = lines
                    .next_line()
                    .await?
                    .ok_or_else(|| std::io::Error::other("go harness stdout closed"))?;
                if line == "DONE" {
                    return Ok(());
                }
            }
        })
        .await
        .map_err(|_| std::io::Error::other("timeout waiting for Go DONE"))?
    }

    async fn read_go_line(lines: &mut GoLines, prefix: &str) -> TestResult<String> {
        tokio::time::timeout(GO_INTEROP_TIMEOUT, async {
            loop {
                let line = lines
                    .next_line()
                    .await?
                    .ok_or_else(|| std::io::Error::other("go harness stdout closed"))?;
                if line.starts_with(prefix) {
                    return Ok(line);
                }
            }
        })
        .await
        .map_err(|_| std::io::Error::other("timeout waiting for Go harness output"))?
    }

    fn write_go_interop_harness() -> TestResult<PathBuf> {
        let charon_repo = charon_repo_path();
        if !charon_repo.join("go.mod").exists() {
            return Err(Box::new(std::io::Error::other(format!(
                "missing Charon repo at {}; set CHARON_REPO",
                charon_repo.display()
            ))));
        }

        let mut dir = std::env::temp_dir();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        dir.push(format!(
            "pluto-qbft-interop-{}-{timestamp}",
            std::process::id()
        ));
        fs::create_dir(&dir)?;
        fs::write(dir.join("main.go"), GO_INTEROP_HARNESS)?;

        Ok(dir)
    }

    fn charon_repo_path() -> PathBuf {
        std::env::var("CHARON_REPO")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/Users/quangle/Documents/nethermind/obol/charon"))
    }

    fn spawn_go_interop(harness_dir: &Path, rust_addrs: &[Multiaddr]) -> TestResult<Child> {
        if rust_addrs.len() != 2 {
            return Err(Box::new(std::io::Error::other("expected two rust addrs")));
        }

        Ok(Command::new("go")
            .arg("run")
            .arg(harness_dir.join("main.go"))
            .arg(rust_addrs[0].to_string())
            .arg(rust_addrs[1].to_string())
            .current_dir(charon_repo_path())
            .env("GOWORK", "off")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?)
    }

    async fn finish_go_interop(child: &mut Child, kill: bool) -> TestResult<()> {
        if kill {
            let _ = child.kill().await;
        }

        let status = tokio::time::timeout(GO_INTEROP_TIMEOUT, child.wait()).await??;
        if !status.success() {
            return Err(Box::new(std::io::Error::other(format!(
                "go harness exited with {status}"
            ))));
        }

        Ok(())
    }

    const GO_INTEROP_HARNESS: &str = r#"
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ssz "github.com/ferranbt/fastssz"
	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/multiformats/go-multiaddr"
	"github.com/obolnetwork/charon/app/k1util"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus/protocols"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	coreqbft "github.com/obolnetwork/charon/core/qbft"
	"github.com/obolnetwork/charon/p2p"
	"google.golang.org/protobuf/proto"
)

type received struct {
	node int
	from int64
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: go run . <rust-addr-0> <rust-addr-1>")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	keys := make([]*k1.PrivateKey, 4)
	peerIDs := make([]peer.ID, 4)
	pubkeys := make(map[int64]*k1.PublicKey, 4)
	for i := range keys {
		keyBytes := bytes.Repeat([]byte{byte(i + 1)}, 32)
		keys[i] = k1.PrivKeyFromBytes(keyBytes)
		priv := (*libp2pcrypto.Secp256k1PrivateKey)(keys[i])
		id, err := peer.IDFromPrivateKey(priv)
		if err != nil {
			panic(err)
		}
		peerIDs[i] = id
		pubkeys[int64(i)] = keys[i].PubKey()
	}

	rustAddrs := make([]multiaddr.Multiaddr, 2)
	for i, arg := range os.Args[1:] {
		addr, err := multiaddr.NewMultiaddr(arg)
		if err != nil {
			panic(err)
		}
		rustAddrs[i] = addr
	}

	recvCh := make(chan received, 16)
	hosts := make([]host.Host, 2)
	for i := range hosts {
		peerIdx := i + 2
		priv := (*libp2pcrypto.Secp256k1PrivateKey)(keys[peerIdx])
		h, err := libp2p.New(
			libp2p.Identity(priv),
			libp2p.Security(noise.ID, noise.New),
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		)
		if err != nil {
			panic(err)
		}
		defer h.Close()
		hosts[i] = h

		node := peerIdx
		p2p.RegisterHandler("qbft-interop", h, protocols.QBFTv2ProtocolID,
			func() proto.Message { return new(pbv1.QBFTConsensusMsg) },
			func(_ context.Context, _ peer.ID, req proto.Message) (proto.Message, bool, error) {
				msg, ok := req.(*pbv1.QBFTConsensusMsg)
				if !ok {
					return nil, false, fmt.Errorf("unexpected request %T", req)
				}
				if err := verifyMsg(msg.GetMsg(), pubkeys); err != nil {
					return nil, false, err
				}
				recvCh <- received{node: node, from: msg.GetMsg().GetPeerIdx()}
				return nil, false, nil
			})
	}

	goAddrs := make([]string, 2)
	for i, h := range hosts {
		if len(h.Addrs()) == 0 {
			panic("go host has no listen address")
		}
		peerPart, err := multiaddr.NewMultiaddr("/p2p/" + h.ID().String())
		if err != nil {
			panic(err)
		}
		goAddrs[i] = h.Addrs()[0].Encapsulate(peerPart).String()
	}
	fmt.Printf("READY %s %s\n", goAddrs[0], goAddrs[1])

	for _, h := range hosts {
		for i := range rustAddrs {
			h.Peerstore().AddAddrs(peerIDs[i], []multiaddr.Multiaddr{rustAddrs[i]}, peerstore.PermanentAddrTTL)
		}
	}

	for i, h := range hosts {
		peerIdx := int64(i + 2)
		for target := 0; target < 2; target++ {
			if err := p2p.Send(ctx, h, protocols.QBFTv2ProtocolID, peerIDs[target], signedConsensusMsg(peerIdx, keys[peerIdx])); err != nil {
				panic(err)
			}
		}
	}
	fmt.Println("SENT")

	seen := map[int]map[int64]bool{
		2: {},
		3: {},
	}
	for {
		if seen[2][0] && seen[2][1] && seen[3][0] && seen[3][1] {
			fmt.Println("DONE")
			return
		}

		select {
		case <-ctx.Done():
			panic(ctx.Err())
		case recv := <-recvCh:
			if recv.node == 2 || recv.node == 3 {
				seen[recv.node][recv.from] = true
				fmt.Printf("RECEIVED %d %d\n", recv.node, recv.from)
			}
		}
	}
}

func signedConsensusMsg(peerIdx int64, key *k1.PrivateKey) *pbv1.QBFTConsensusMsg {
	msg := &pbv1.QBFTMsg{
		Type:              int64(coreqbft.MsgPrepare),
		Duty:              &pbv1.Duty{Slot: 42, Type: int32(core.DutyAttester)},
		PeerIdx:           peerIdx,
		Round:             1,
		ValueHash:         nil,
		PreparedValueHash: nil,
	}
	signed, err := signMsg(msg, key)
	if err != nil {
		panic(err)
	}
	return &pbv1.QBFTConsensusMsg{Msg: signed}
}

func signMsg(msg *pbv1.QBFTMsg, privkey *k1.PrivateKey) (*pbv1.QBFTMsg, error) {
	clone := proto.Clone(msg).(*pbv1.QBFTMsg)
	clone.Signature = nil

	hash, err := hashProto(clone)
	if err != nil {
		return nil, err
	}

	clone.Signature, err = k1util.Sign(privkey, hash[:])
	if err != nil {
		return nil, err
	}

	return clone, nil
}

func verifyMsg(msg *pbv1.QBFTMsg, pubkeys map[int64]*k1.PublicKey) error {
	if msg == nil || msg.GetDuty() == nil {
		return fmt.Errorf("invalid consensus message")
	}
	if typ := coreqbft.MsgType(msg.GetType()); !typ.Valid() {
		return fmt.Errorf("invalid consensus message type: %d", typ)
	}
	if typ := core.DutyType(msg.GetDuty().GetType()); !typ.Valid() {
		return fmt.Errorf("invalid consensus message duty type: %d", typ)
	}
	if msg.GetRound() <= 0 {
		return fmt.Errorf("invalid consensus message round: %d", msg.GetRound())
	}
	if msg.GetPreparedRound() < 0 {
		return fmt.Errorf("invalid consensus message prepared round")
	}

	pubkey, ok := pubkeys[msg.GetPeerIdx()]
	if !ok {
		return fmt.Errorf("invalid peer index: %d", msg.GetPeerIdx())
	}
	ok, err := verifyMsgSig(msg, pubkey)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("invalid consensus message signature")
	}
	return nil
}

func verifyMsgSig(msg *pbv1.QBFTMsg, pubkey *k1.PublicKey) (bool, error) {
	clone := proto.Clone(msg).(*pbv1.QBFTMsg)
	signature := clone.GetSignature()
	if len(signature) == 0 {
		return false, fmt.Errorf("empty signature")
	}
	clone.Signature = nil

	hash, err := hashProto(clone)
	if err != nil {
		return false, err
	}
	recovered, err := k1util.Recover(hash[:], signature)
	if err != nil {
		return false, err
	}
	return hex.EncodeToString(recovered.SerializeCompressed()) == hex.EncodeToString(pubkey.SerializeCompressed()), nil
}

func hashProto(msg proto.Message) ([32]byte, error) {
	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	index := hh.Index()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return [32]byte{}, err
	}

	hh.PutBytes(b)
	hh.Merkleize(index)
	return hh.HashRoot()
}
"#;
}
