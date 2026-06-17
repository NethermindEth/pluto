//! Connection handler for the priority protocol.
//!
//! Each handler serves one libp2p connection. Inbound streams read a request,
//! invoke the registered handler callback, and write the response. Outbound
//! requests are delivered from the behaviour as [`FromBehaviour`] commands;
//! each opens its own substream, sends the request, reads the response, and
//! resolves the caller's oneshot.

use std::{
    collections::VecDeque,
    convert::Infallible,
    task::{Context, Poll},
};

use futures::{FutureExt, future::BoxFuture};
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

type InboundFuture = BoxFuture<'static, ()>;
type OutboundFuture = BoxFuture<'static, ()>;

/// Per-connection priority protocol handler.
pub struct Handler {
    peer_id: PeerId,
    inbound_handler: InboundHandler,
    /// In-flight inbound stream futures.
    inbound: Vec<InboundFuture>,
    /// In-flight outbound exchange futures.
    outbound: Vec<OutboundFuture>,
    /// Outbound requests awaiting a substream, in arrival order.
    pending: VecDeque<OutboundRequest>,
}

impl Handler {
    pub(crate) fn new(peer_id: PeerId, inbound_handler: InboundHandler) -> Self {
        Self {
            peer_id,
            inbound_handler,
            inbound: Vec::new(),
            outbound: Vec::new(),
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
    type ToBehaviour = Infallible;

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
        self.inbound
            .retain_mut(|fut| fut.poll_unpin(cx).is_pending());
        self.outbound
            .retain_mut(|fut| fut.poll_unpin(cx).is_pending());

        if let Some(request) = self.pending.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(protocol::upgrade(), request),
            });
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
                self.inbound.push(
                    handle_inbound(self.peer_id, self.inbound_handler.clone(), stream).boxed(),
                );
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: stream,
                info: request,
            }) => {
                self.outbound.push(run_outbound(request, stream).boxed());
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

/// Serves a single inbound request: read, invoke handler, optionally respond.
///
/// The request read is bounded so a peer that opens a stream but never writes
/// has its stream dropped rather than pinned for the connection's lifetime.
async fn handle_inbound(peer_id: PeerId, inbound_handler: InboundHandler, mut stream: Stream) {
    let request = match timeout(
        protocol::RECEIVE_TIMEOUT,
        protocol::read_request(&mut stream),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            debug!(peer = %peer_id, err = %error, "Error reading priority request");
            return;
        }
        Err(_) => {
            debug!(peer = %peer_id, "Timed out reading priority request");
            return;
        }
    };

    if !protocol::check_required_fields(&request) {
        warn!(peer = %peer_id, "Received invalid priority message");
        return;
    }

    let response = match inbound_handler(peer_id, request).await {
        Ok(Some(response)) => response,
        Ok(None) => return,
        Err(error) => {
            warn!(peer = %peer_id, err = %error, "Error handling priority request");
            return;
        }
    };

    if let Err(error) = protocol::write_response(&mut stream, &response).await {
        debug!(peer = %peer_id, err = %error, "Error writing priority response");
    }
}

/// Runs a single outbound exchange and resolves the caller's oneshot.
///
/// The whole write-and-read round-trip is bounded so an unresponsive peer fails
/// the exchange promptly instead of holding the substream open.
async fn run_outbound(request: OutboundRequest, mut stream: Stream) {
    let result = match timeout(
        protocol::SEND_TIMEOUT,
        protocol::send_receive(&mut stream, &request.request),
    )
    .await
    {
        Ok(result) => result.map_err(|error| Error::Transport(error.to_string())),
        Err(_) => Err(Error::Transport("exchange timed out".to_owned())),
    };
    let _ = request.response.send(result);
}

fn dial_error(error: StreamUpgradeError<Infallible>) -> Error {
    match error {
        StreamUpgradeError::NegotiationFailed => Error::Unsupported,
        StreamUpgradeError::Timeout => Error::Transport("negotiation timed out".to_owned()),
        StreamUpgradeError::Apply(never) => match never {},
        StreamUpgradeError::Io(error) => Error::Transport(error.to_string()),
    }
}
