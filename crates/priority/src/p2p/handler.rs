//! Connection handler for the priority protocol.
//!
//! Each handler serves one libp2p connection. Inbound streams read a request,
//! invoke the registered handler callback, and write the response; a failed
//! inbound exchange surfaces to the behaviour as an [`InboundFailure`] (rather
//! than being silently dropped) so the application can observe it. Outbound
//! requests are delivered from the behaviour as [`FromBehaviour`] commands;
//! each opens its own substream, sends the request, reads the response,
//! resolves the caller's oneshot, and closes the stream.

use std::{
    collections::VecDeque,
    convert::Infallible,
    task::{Context, Poll},
};

use futures::{AsyncWriteExt, FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use libp2p::{
    PeerId, Stream,
    swarm::{
        ConnectionHandler, ConnectionHandlerEvent, StreamUpgradeError, SubstreamProtocol,
        handler::{
            ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
        },
    },
};
use pluto_core::corepb::v1::priority::PriorityMsg;
use tokio::{sync::oneshot, time::timeout};
use tracing::{debug, warn};

use super::{InboundHandler, protocol};
use crate::error::Error;

/// A single outbound request awaiting a fresh substream.
#[derive(Debug)]
pub struct OutboundRequest {
    /// The request to send.
    pub(crate) request: PriorityMsg,
    /// Resolves with the peer's response or a transport error.
    pub(crate) response: oneshot::Sender<crate::Result<PriorityMsg>>,
}

/// Command delivered from the behaviour to a connection handler.
#[derive(Debug)]
pub enum FromBehaviour {
    /// Issue an outbound request/response exchange.
    SendReceive(OutboundRequest),
}

/// Reason an inbound priority exchange failed before completing.
///
/// Reported to the behaviour and re-emitted as
/// [`Event::InboundFailure`](super::Event) so a rejected, malformed, or
/// unreadable inbound request is observable by the application, not merely
/// logged. The outbound (caller) path reports its own failures through the
/// per-request oneshot instead.
#[derive(Debug)]
pub enum InboundFailure {
    /// No request arrived within [`protocol::RECEIVE_TIMEOUT`].
    Timeout,
    /// Reading or decoding the request frame failed.
    Read(std::io::Error),
    /// The decoded request omitted a required field.
    InvalidMessage,
    /// The registered handler rejected the request (e.g. unknown peer, invalid
    /// signature, expired duty).
    Handler(Error),
    /// Writing the response back to the peer failed.
    Write(std::io::Error),
}

/// In-flight exchange future. Resolves to `Some(failure)` for an inbound
/// exchange to surface, or `None` for a successful inbound exchange or any
/// completed outbound exchange (which resolves its caller's oneshot
/// internally).
type ExchangeFuture = BoxFuture<'static, Option<InboundFailure>>;

/// Per-connection priority protocol handler.
pub struct Handler {
    peer_id: PeerId,
    inbound_handler: InboundHandler,
    /// In-flight inbound and outbound exchange futures.
    active: FuturesUnordered<ExchangeFuture>,
    /// Outbound requests awaiting a substream, in arrival order.
    pending: VecDeque<OutboundRequest>,
}

impl Handler {
    pub(crate) fn new(peer_id: PeerId, inbound_handler: InboundHandler) -> Self {
        Self {
            peer_id,
            inbound_handler,
            active: FuturesUnordered::new(),
            pending: VecDeque::new(),
        }
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = FromBehaviour;
    type InboundOpenInfo = ();
    type InboundProtocol = protocol::PriorityUpgrade;
    // The originating request travels with the substream so a negotiated stream
    // is paired with the request that opened it, never by negotiation order.
    type OutboundOpenInfo = OutboundRequest;
    type OutboundProtocol = protocol::PriorityUpgrade;
    type ToBehaviour = InboundFailure;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(protocol::upgrade(), ())
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            FromBehaviour::SendReceive(request) => self.pending.push_back(request),
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if let Some(request) = self.pending.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(protocol::upgrade(), request),
            });
        }

        // Drain completed exchanges; surface the first inbound failure as a
        // behaviour event. Outbound completions and inbound successes yield
        // `None` and are simply dropped.
        while let Poll::Ready(Some(maybe_failure)) = self.active.poll_next_unpin(cx) {
            if let Some(failure) = maybe_failure {
                return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(failure));
            }
        }

        Poll::Pending
    }

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
                protocol: stream,
                ..
            }) => {
                self.active.push(
                    handle_inbound(self.peer_id, self.inbound_handler.clone(), stream).boxed(),
                );
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: stream,
                info: request,
            }) => {
                self.active.push(run_outbound(request, stream).boxed());
            }
            ConnectionEvent::DialUpgradeError(DialUpgradeError {
                info: request,
                error,
            }) => {
                let _ = request.response.send(Err(dial_error(error)));
            }
            _ => {}
        }
    }
}

/// Best-effort closes a stream after an exchange, matching the reference's
/// explicit stream close (the stream is otherwise reset on drop).
async fn close_stream(stream: &mut Stream) {
    if let Err(error) = stream.close().await {
        debug!(err = %error, "Error closing priority stream");
    }
}

/// Serves a single inbound request (read, validate, handle, respond) and then
/// closes the stream, returning the failure to surface, if any.
///
/// The request read is bounded so a peer that opens a stream but never writes
/// has its stream closed rather than pinned for the connection's lifetime.
async fn handle_inbound(
    peer_id: PeerId,
    inbound_handler: InboundHandler,
    mut stream: Stream,
) -> Option<InboundFailure> {
    let failure = run_inbound(peer_id, inbound_handler, &mut stream).await;
    close_stream(&mut stream).await;
    failure
}

async fn run_inbound(
    peer_id: PeerId,
    inbound_handler: InboundHandler,
    stream: &mut Stream,
) -> Option<InboundFailure> {
    let request = match timeout(protocol::RECEIVE_TIMEOUT, protocol::read_request(stream)).await {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            debug!(peer = %peer_id, err = %error, "Error reading priority request");
            return Some(InboundFailure::Read(error));
        }
        Err(_) => {
            debug!(peer = %peer_id, "Timed out reading priority request");
            return Some(InboundFailure::Timeout);
        }
    };

    if !protocol::check_required_fields(&request) {
        warn!(peer = %peer_id, "Received invalid priority message");
        return Some(InboundFailure::InvalidMessage);
    }

    let response = match inbound_handler(peer_id, request).await {
        Ok(Some(response)) => response,
        Ok(None) => return None,
        Err(error) => {
            warn!(peer = %peer_id, err = %error, "Error handling priority request");
            return Some(InboundFailure::Handler(error));
        }
    };

    if let Err(error) = protocol::write_response(stream, &response).await {
        debug!(peer = %peer_id, err = %error, "Error writing priority response");
        return Some(InboundFailure::Write(error));
    }

    None
}

/// Runs a single outbound exchange, resolves the caller's oneshot, then closes
/// the stream.
///
/// The whole write-and-read round-trip is bounded so an unresponsive peer fails
/// the exchange promptly instead of holding the substream open. Returns `None`:
/// outbound results travel through the oneshot, not the behaviour event
/// channel.
async fn run_outbound(request: OutboundRequest, mut stream: Stream) -> Option<InboundFailure> {
    let result = match timeout(
        protocol::SEND_TIMEOUT,
        protocol::send_receive(&mut stream, &request.request),
    )
    .await
    {
        Ok(result) => result.map_err(|error| Error::Transport(error.to_string())),
        Err(_) => Err(Error::Transport("exchange timed out".to_owned())),
    };
    close_stream(&mut stream).await;
    let _ = request.response.send(result);
    None
}

fn dial_error(error: StreamUpgradeError<Infallible>) -> Error {
    match error {
        StreamUpgradeError::NegotiationFailed => Error::Unsupported,
        StreamUpgradeError::Timeout => Error::Transport("negotiation timed out".to_owned()),
        StreamUpgradeError::Apply(never) => match never {},
        StreamUpgradeError::Io(error) => Error::Transport(error.to_string()),
    }
}
