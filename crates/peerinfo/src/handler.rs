//! Connection handler for the peerinfo protocol.
//!
//! This handler manages peer info exchanges for a single connection,
//! periodically sending requests and handling incoming requests.
//!
//! The implementation uses libp2p::protocol::ping as a reference

use std::{
    collections::VecDeque,
    convert::Infallible,
    task::{Context, Poll},
    time::Duration,
};

use futures::{future::BoxFuture, prelude::*};
use futures_timer::Delay;
use libp2p::{
    core::upgrade::ReadyUpgrade,
    swarm::{
        ConnectionHandler, ConnectionHandlerEvent, Stream, StreamProtocol, StreamUpgradeError,
        SubstreamProtocol,
        handler::{
            ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
        },
    },
};

use crate::{
    PROTOCOL_NAME, config::Config, failure::Failure, peerinfopb::v1::peerinfo::PeerInfo, protocol,
};

/// Result of a successful peer info exchange.
#[derive(Debug, Clone)]
pub struct Success {
    /// The peer info received from the remote peer.
    pub peer_info: PeerInfo,
}

/// Protocol handler that handles peer info exchange with a remote peer
/// at regular intervals and answers incoming peer info requests.
pub struct Handler {
    /// Configuration options.
    config: Config,
    /// The timer used for the delay to the next request.
    interval: Delay,
    /// Outbound failures that are pending to be processed by `poll()`.
    pending_errors: VecDeque<Failure>,
    /// The number of consecutive failures that occurred.
    ///
    /// Each successful exchange resets this counter to 0.
    failures: u32,
    /// The outbound request state.
    outbound: Option<OutboundState>,
    /// The inbound response handler.
    inbound: Option<InboundFuture>,
    /// Tracks the state of our handler.
    state: State,
}

/// Tracks the state of the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// We are inactive because the other peer doesn't support peerinfo.
    Inactive {
        /// Whether or not we've reported the missing support yet.
        reported: bool,
    },
    /// We are actively exchanging peer info.
    Active,
}

impl Handler {
    /// Builds a new [`Handler`] with the given configuration.
    pub fn new(config: Config) -> Self {
        let interval = config.interval();
        Handler {
            config,
            interval: Delay::new(interval),
            pending_errors: VecDeque::with_capacity(2),
            failures: 0,
            outbound: None,
            inbound: None,
            state: State::Active,
        }
    }

    fn on_dial_upgrade_error(
        &mut self,
        DialUpgradeError { error, .. }: DialUpgradeError<
            (),
            <Self as ConnectionHandler>::OutboundProtocol,
        >,
    ) {
        self.outbound = None; // Request a new substream on the next `poll`.

        // Reset the timer to avoid issues with WASM timer implementation.
        // See libp2p/rust-libp2p#5447 for more info.
        self.interval.reset(Duration::new(0, 0));

        let error = match error {
            StreamUpgradeError::NegotiationFailed => {
                debug_assert_eq!(self.state, State::Active);
                self.state = State::Inactive { reported: false };
                return;
            }
            StreamUpgradeError::Timeout => Failure::other(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "peerinfo protocol negotiation timed out",
            )),
            StreamUpgradeError::Apply(e) => libp2p::core::util::unreachable(e),
            StreamUpgradeError::Io(e) => Failure::other(e),
        };

        self.pending_errors.push_front(error);
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = Infallible;
    type InboundOpenInfo = ();
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundOpenInfo = ();
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type ToBehaviour = Result<Success, Failure>;

    fn listen_protocol(&self) -> SubstreamProtocol<ReadyUpgrade<StreamProtocol>> {
        SubstreamProtocol::new(ReadyUpgrade::new(PROTOCOL_NAME), ())
    }

    fn on_behaviour_event(&mut self, _: Infallible) {}

    #[tracing::instrument(level = "trace", name = "ConnectionHandler::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<ReadyUpgrade<StreamProtocol>, (), Result<Success, Failure>>>
    {
        match self.state {
            State::Inactive { reported: true } => {
                return Poll::Pending; // Nothing to do on this connection
            }
            State::Inactive { reported: false } => {
                self.state = State::Inactive { reported: true };
                return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(Err(
                    Failure::Unsupported,
                )));
            }
            State::Active => {}
        }

        // Handle inbound requests.
        if let Some(fut) = self.inbound.as_mut() {
            match fut.poll_unpin(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    tracing::debug!("Inbound peerinfo error: {:?}", e);
                    self.inbound = None;
                }
                Poll::Ready(Ok((stream, _request))) => {
                    tracing::trace!("Answered inbound peerinfo request from peer");
                    self.inbound =
                        Some(recv_peer_info(stream, self.config.local_info().to_proto()).boxed());
                }
            }
        }

        loop {
            // Check for outbound failures.
            if let Some(error) = self.pending_errors.pop_back() {
                tracing::debug!("PeerInfo failure: {:?}", error);

                self.failures = self.failures.saturating_add(1);

                // For backward-compatibility, the first failure is "free" and silent.
                // This allows peers using new substreams for each request to have
                // successful exchanges with peers using a single substream.
                if self.failures > 1 {
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(Err(error)));
                }
            }

            // Continue outbound requests.
            match self.outbound.take() {
                Some(OutboundState::Request(mut request)) => match request.poll_unpin(cx) {
                    Poll::Pending => {
                        self.outbound = Some(OutboundState::Request(request));
                        break;
                    }
                    Poll::Ready(Ok((stream, peer_info))) => {
                        self.failures = 0;
                        self.interval.reset(self.config.interval());
                        self.outbound = Some(OutboundState::Idle(stream));
                        return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(Ok(Success {
                            peer_info,
                        })));
                    }
                    Poll::Ready(Err(e)) => {
                        self.interval.reset(self.config.interval());
                        self.pending_errors.push_front(e);
                    }
                },
                Some(OutboundState::Idle(stream)) => match self.interval.poll_unpin(cx) {
                    Poll::Pending => {
                        self.outbound = Some(OutboundState::Idle(stream));
                        break;
                    }
                    Poll::Ready(_) => {
                        self.outbound = Some(OutboundState::Request(
                            send_peer_info(
                                stream,
                                self.config.local_info().to_proto(),
                                self.config.timeout(),
                            )
                            .boxed(),
                        ));
                    }
                },
                Some(OutboundState::OpenStream) => {
                    self.outbound = Some(OutboundState::OpenStream);
                    break;
                }
                None => match self.interval.poll_unpin(cx) {
                    Poll::Pending => break,
                    Poll::Ready(()) => {
                        self.outbound = Some(OutboundState::OpenStream);
                        let protocol = SubstreamProtocol::new(ReadyUpgrade::new(PROTOCOL_NAME), ());
                        return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                            protocol,
                        });
                    }
                },
            }
        }

        Poll::Pending
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol>,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: mut stream,
                ..
            }) => {
                stream.ignore_for_keep_alive();
                let local_info = self.config.local_info().to_proto();
                self.inbound = Some(recv_peer_info(stream, local_info).boxed());
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: mut stream,
                ..
            }) => {
                stream.ignore_for_keep_alive();
                self.interval.reset(Duration::new(0, 0));
                let request = self.config.local_info().to_proto();
                self.outbound = Some(OutboundState::Request(
                    send_peer_info(stream, request, self.config.timeout()).boxed(),
                ));
            }
            ConnectionEvent::DialUpgradeError(dial_upgrade_error) => {
                self.on_dial_upgrade_error(dial_upgrade_error)
            }
            _ => {}
        }
    }
}

type RequestFuture = BoxFuture<'static, Result<(Stream, PeerInfo), Failure>>;
type InboundFuture = BoxFuture<'static, Result<(Stream, PeerInfo), std::io::Error>>;

/// The current state w.r.t. outbound peer info requests.
enum OutboundState {
    /// A new substream is being negotiated for the peerinfo protocol.
    OpenStream,
    /// The stream is idle and waiting for the next request.
    Idle(Stream),
    /// A request is being sent and the response awaited.
    Request(RequestFuture),
}

/// A wrapper around [`protocol::send_peer_info`] that enforces a timeout.
async fn send_peer_info(
    stream: Stream,
    request: PeerInfo,
    timeout: Duration,
) -> Result<(Stream, PeerInfo), Failure> {
    let send = protocol::send_peer_info(stream, &request);
    futures::pin_mut!(send);

    match future::select(send, Delay::new(timeout)).await {
        future::Either::Left((Ok((stream, response)), _)) => Ok((stream, response)),
        future::Either::Left((Err(e), _)) => Err(Failure::other(e)),
        future::Either::Right(((), _)) => Err(Failure::Timeout),
    }
}

/// A wrapper around [`protocol::recv_peer_info`] that returns only the stream
/// and request (for use in inbound handling).
async fn recv_peer_info(
    stream: Stream,
    local_info: PeerInfo,
) -> Result<(Stream, PeerInfo), std::io::Error> {
    protocol::recv_peer_info(stream, &local_info).await
}
