//! On-demand probes driving the peer tests.
//!
//! libp2p's ping behaviour only pings on its own interval, while Charon's peer
//! tests ping on demand (`ping.Ping`) and force direct dials
//! (`network.WithForceDirectDial`). [`PeerProbe`] adds both to the test node:
//! it opens outbound `/ipfs/ping/1.0.0` streams, answered by the remote's
//! regular ping behaviour, and dials a peer's direct addresses. It is driven
//! through a cloneable [`PeerProbeHandle`] so tests run concurrently with the
//! swarm event loop.

use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    task::{Context, Poll},
    time::Duration,
};

use futures::{AsyncReadExt as _, AsyncWriteExt as _};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol,
    core::{
        Endpoint,
        transport::PortUse,
        upgrade::{DeniedUpgrade, ReadyUpgrade},
    },
    ping,
    swarm::{
        ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, FromSwarm,
        NetworkBehaviour, NotifyHandler, Stream, SubstreamProtocol, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
        dial_opts::{DialOpts, PeerCondition},
        handler::{ConnectionEvent, DialUpgradeError, FullyNegotiatedOutbound},
    },
};
use pluto_p2p::{force_direct, p2p_context::P2PContext, utils};
use tokio::{
    sync::{mpsc, oneshot},
    time::Instant,
};

/// Upper bound for a single ping: stream negotiation plus the echo.
pub(super) const PING_TIMEOUT: Duration = pluto_p2p::config::DEFAULT_PING_TIMEOUT;

/// Size of a libp2p ping payload.
const PING_SIZE: usize = 32;

/// Errors returned by [`PeerProbeHandle`] probes.
#[derive(Debug, thiserror::Error)]
pub(super) enum ProbeError {
    /// There is no open connection to the peer to ping over.
    #[error("no connection to peer")]
    NotConnected,

    /// The peer store holds no direct address to dial.
    #[error("no direct addresses known for peer")]
    NoDirectAddrs,

    /// The ping stream could not be negotiated.
    #[error("open ping stream: {0}")]
    OpenStream(String),

    /// The connection closed before the ping stream was opened.
    #[error("connection closed before the ping stream opened")]
    ConnectionClosed,

    /// The direct dial failed.
    #[error("direct dial: {0}")]
    Dial(String),

    /// Reading or writing the ping stream failed.
    #[error("ping stream: {0}")]
    Io(#[from] std::io::Error),

    /// The remote echoed a different payload.
    #[error("ping payload mismatch")]
    PayloadMismatch,

    /// The ping did not complete within [`PING_TIMEOUT`].
    #[error("ping timed out")]
    Timeout,

    /// The node driving the probe has shut down.
    #[error("p2p node stopped")]
    NodeStopped,
}

impl ProbeError {
    /// Reports whether the error is a stream reset, which Charon
    /// (`p2p.IsRelayError`) treats as a relay failure not worth retrying.
    pub(super) fn is_relay_error(&self) -> bool {
        matches!(self, Self::Io(e) if e.kind() == std::io::ErrorKind::ConnectionReset)
    }
}

type StreamReply = oneshot::Sender<Result<Stream, ProbeError>>;
type DialReply = oneshot::Sender<Result<(), ProbeError>>;

#[derive(Debug)]
enum Command {
    OpenPingStream { peer: PeerId, reply: StreamReply },
    DialDirect { peer: PeerId, reply: DialReply },
}

/// Cloneable handle issuing probes to the [`PeerProbe`] behaviour.
#[derive(Debug, Clone)]
pub(super) struct PeerProbeHandle {
    commands: mpsc::UnboundedSender<Command>,
    p2p_context: P2PContext,
}

impl PeerProbeHandle {
    /// Pings `peer` once over an existing connection and returns the RTT.
    pub(super) async fn ping(&self, peer: PeerId) -> Result<Duration, ProbeError> {
        let ping = async {
            let (reply, stream) = oneshot::channel();
            self.commands
                .send(Command::OpenPingStream { peer, reply })
                .map_err(|_| ProbeError::NodeStopped)?;
            let stream = stream.await.map_err(|_| ProbeError::ConnectionClosed)??;
            ping_stream(stream).await
        };

        tokio::time::timeout(PING_TIMEOUT, ping)
            .await
            .map_err(|_| ProbeError::Timeout)?
    }

    /// Dials `peer` on its direct addresses, succeeding immediately when a
    /// direct connection already exists.
    pub(super) async fn dial_direct(&self, peer: PeerId) -> Result<(), ProbeError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command::DialDirect { peer, reply })
            .map_err(|_| ProbeError::NodeStopped)?;
        result.await.map_err(|_| ProbeError::NodeStopped)?
    }

    /// Returns the number of open connections to `peer`.
    pub(super) fn connection_count(&self, peer: &PeerId) -> usize {
        self.p2p_context
            .peer_store_lock()
            .connections_to_peer(peer)
            .len()
    }
}

/// Sends one ping on `stream` and measures the echo, as libp2p's
/// `ping::protocol::send_ping` does.
async fn ping_stream(mut stream: Stream) -> Result<Duration, ProbeError> {
    let payload: [u8; PING_SIZE] = rand::random();
    let started = Instant::now();
    stream.write_all(&payload).await?;
    stream.flush().await?;

    let mut echo = [0u8; PING_SIZE];
    stream.read_exact(&mut echo).await?;
    let rtt = started.elapsed();

    if echo != payload {
        return Err(ProbeError::PayloadMismatch);
    }

    // The RTT is already measured, so a failed close changes nothing.
    let _ = stream.close().await;

    Ok(rtt)
}

/// Behaviour serving [`PeerProbeHandle`] requests.
pub(super) struct PeerProbe {
    commands: mpsc::UnboundedReceiver<Command>,
    p2p_context: P2PContext,
    pending_dials: HashMap<ConnectionId, DialReply>,
    events: VecDeque<ToSwarm<Infallible, StreamReply>>,
}

impl PeerProbe {
    /// Creates the behaviour and the handle that drives it.
    ///
    /// `p2p_context` must be the node's context: connections and direct
    /// addresses are read from its peer store.
    pub(super) fn new(p2p_context: P2PContext) -> (Self, PeerProbeHandle) {
        let (tx, rx) = mpsc::unbounded_channel();
        let handle = PeerProbeHandle {
            commands: tx,
            p2p_context: p2p_context.clone(),
        };
        let behaviour = Self {
            commands: rx,
            p2p_context,
            pending_dials: HashMap::new(),
            events: VecDeque::new(),
        };
        (behaviour, handle)
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::OpenPingStream { peer, reply } => {
                // Prefer a direct connection, like go-libp2p's best-connection
                // choice for new streams.
                let connection = {
                    let store = self.p2p_context.peer_store_lock();
                    let conns = store.connections_to_peer(&peer);
                    conns
                        .iter()
                        .find(|c| utils::is_direct_addr(&c.remote_addr))
                        .or_else(|| conns.first())
                        .map(|c| c.connection_id)
                };

                match connection {
                    Some(connection) => self.events.push_back(ToSwarm::NotifyHandler {
                        peer_id: peer,
                        handler: NotifyHandler::One(connection),
                        event: reply,
                    }),
                    None => {
                        let _ = reply.send(Err(ProbeError::NotConnected));
                    }
                }
            }
            Command::DialDirect { peer, reply } => {
                let has_direct = self
                    .p2p_context
                    .peer_store_lock()
                    .connections_to_peer(&peer)
                    .iter()
                    .any(|c| utils::is_direct_addr(&c.remote_addr));
                if has_direct {
                    let _ = reply.send(Ok(()));
                    return;
                }

                let addrs = force_direct::direct_peer_addrs(&self.p2p_context, &peer);
                if addrs.is_empty() {
                    let _ = reply.send(Err(ProbeError::NoDirectAddrs));
                    return;
                }

                let opts = DialOpts::peer_id(peer)
                    .addresses(addrs)
                    .condition(PeerCondition::Always)
                    .build();
                self.pending_dials.insert(opts.connection_id(), reply);
                self.events.push_back(ToSwarm::Dial { opts });
            }
        }
    }
}

impl NetworkBehaviour for PeerProbe {
    type ConnectionHandler = Handler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::default())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::default())
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(e) => {
                if let Some(reply) = self.pending_dials.remove(&e.connection_id) {
                    let _ = reply.send(Ok(()));
                }
            }
            FromSwarm::DialFailure(e) => {
                if let Some(reply) = self.pending_dials.remove(&e.connection_id) {
                    let _ = reply.send(Err(ProbeError::Dial(e.error.to_string())));
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        while let Poll::Ready(Some(command)) = self.commands.poll_recv(cx) {
            self.handle_command(command);
        }

        match self.events.pop_front() {
            Some(event) => Poll::Ready(event),
            None => Poll::Pending,
        }
    }
}

/// Connection handler opening outbound ping streams on request.
///
/// Inbound ping streams are left to libp2p's ping behaviour.
#[derive(Default)]
pub(super) struct Handler {
    pending: VecDeque<StreamReply>,
}

impl ConnectionHandler for Handler {
    type FromBehaviour = StreamReply;
    type InboundOpenInfo = ();
    type InboundProtocol = DeniedUpgrade;
    type OutboundOpenInfo = StreamReply;
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type ToBehaviour = Infallible;

    fn listen_protocol(&self) -> SubstreamProtocol<DeniedUpgrade> {
        SubstreamProtocol::new(DeniedUpgrade, ())
    }

    fn on_behaviour_event(&mut self, reply: StreamReply) {
        self.pending.push_back(reply);
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, StreamReply, Infallible>> {
        match self.pending.pop_front() {
            Some(reply) => Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(ReadyUpgrade::new(ping::PROTOCOL_NAME), reply)
                    .with_timeout(PING_TIMEOUT),
            }),
            None => Poll::Pending,
        }
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol, (), StreamReply>,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: stream,
                info: reply,
            }) => {
                let _ = reply.send(Ok(stream));
            }
            ConnectionEvent::DialUpgradeError(DialUpgradeError { info: reply, error }) => {
                let _ = reply.send(Err(ProbeError::OpenStream(error.to_string())));
            }
            _ => {}
        }
    }
}
