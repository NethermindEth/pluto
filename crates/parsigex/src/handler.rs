//! Connection handler for the partial signature exchange protocol.

use std::{
    collections::VecDeque,
    task::{Context, Poll},
    time::Duration,
};

use futures::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use libp2p::{
    core::upgrade::ReadyUpgrade,
    swarm::{
        ConnectionHandler, ConnectionHandlerEvent, StreamProtocol, StreamUpgradeError,
        SubstreamProtocol,
        handler::{
            ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
        },
    },
};
use tokio::time::timeout;

use pluto_core::types::{Duty, ParSignedDataSet};

use super::{DutyGater, PROTOCOL_NAME, Verifier, protocol};
use crate::error::Failure;

/// Command sent from the behaviour to a handler.
#[derive(Debug)]
pub enum ToHandler {
    /// Send the encoded payload to the remote peer.
    Send {
        /// Request identifier used to correlate broadcast completions.
        request_id: u64,
        /// Encoded protobuf payload.
        payload: Vec<u8>,
    },
}

/// Event sent from the handler back to the behaviour.
#[derive(Debug)]
pub enum FromHandler {
    /// A verified message was received.
    Received {
        /// Duty from the message.
        duty: Duty,
        /// Verified partial signature set.
        data_set: ParSignedDataSet,
    },
    /// An inbound message failed decoding, gating, or verification.
    InboundError(Failure),
    /// Outbound send completed successfully.
    OutboundSuccess {
        /// Request identifier.
        request_id: u64,
    },
    /// Outbound send failed.
    OutboundError {
        /// Request identifier.
        request_id: u64,
        /// Failure reason.
        error: Failure,
    },
}

/// Outbound open info that carries the request context through stream
/// negotiation.
pub struct PendingOpen {
    request_id: u64,
    payload: Vec<u8>,
}

type ActiveFuture = BoxFuture<'static, Option<FromHandler>>;

/// Connection handler for parsigex.
pub struct Handler {
    timeout: Duration,
    verifier: Verifier,
    duty_gater: DutyGater,
    pending_open: VecDeque<PendingOpen>,
    active_futures: FuturesUnordered<ActiveFuture>,
}

impl Handler {
    /// Creates a new handler for one connection.
    pub fn new(timeout: Duration, verifier: Verifier, duty_gater: DutyGater) -> Self {
        Self {
            timeout,
            verifier,
            duty_gater,
            pending_open: VecDeque::new(),
            active_futures: FuturesUnordered::new(),
        }
    }

    fn handle_fully_negotiated_inbound(&mut self, mut stream: libp2p::swarm::Stream) {
        stream.ignore_for_keep_alive();
        let verifier = self.verifier.clone();
        let duty_gater = self.duty_gater.clone();
        let t = self.timeout;

        self.active_futures.push(
            async move {
                Some(
                    match timeout(t, do_recv(stream, verifier, duty_gater)).await {
                        Ok(Ok((duty, data_set))) => FromHandler::Received { duty, data_set },
                        Ok(Err(e)) => FromHandler::InboundError(e),
                        Err(_) => FromHandler::InboundError(Failure::Timeout),
                    },
                )
            }
            .boxed(),
        );
    }

    fn handle_fully_negotiated_outbound(
        &mut self,
        mut stream: libp2p::swarm::Stream,
        info: PendingOpen,
    ) {
        stream.ignore_for_keep_alive();
        let PendingOpen {
            request_id,
            payload,
        } = info;
        let t = self.timeout;

        self.active_futures.push(
            async move {
                Some(match timeout(t, do_send(stream, payload)).await {
                    Ok(Ok(())) => FromHandler::OutboundSuccess { request_id },
                    Ok(Err(e)) => FromHandler::OutboundError {
                        request_id,
                        error: e,
                    },
                    Err(_) => FromHandler::OutboundError {
                        request_id,
                        error: Failure::Timeout,
                    },
                })
            }
            .boxed(),
        );
    }

    fn handle_dial_upgrade_error<E>(&mut self, info: PendingOpen, error: StreamUpgradeError<E>)
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        let request_id = info.request_id;
        let failure = match error {
            StreamUpgradeError::Timeout => Failure::Timeout,
            StreamUpgradeError::NegotiationFailed => Failure::io("protocol negotiation failed"),
            StreamUpgradeError::Apply(e) => Failure::io(e),
            StreamUpgradeError::Io(e) => Failure::io(e),
        };
        self.active_futures.push(
            async move {
                Some(FromHandler::OutboundError {
                    request_id,
                    error: failure,
                })
            }
            .boxed(),
        );
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = ToHandler;
    type InboundOpenInfo = ();
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundOpenInfo = PendingOpen;
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type ToBehaviour = FromHandler;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(ReadyUpgrade::new(PROTOCOL_NAME), ())
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            ToHandler::Send {
                request_id,
                payload,
            } => {
                self.pending_open.push_back(PendingOpen {
                    request_id,
                    payload,
                });
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if let Some(pending) = self.pending_open.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(ReadyUpgrade::new(PROTOCOL_NAME), pending),
            });
        }

        while let Poll::Ready(Some(event)) = self.active_futures.poll_next_unpin(cx) {
            if let Some(event) = event {
                return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
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
            }) => self.handle_fully_negotiated_inbound(stream),
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: stream,
                info,
                ..
            }) => self.handle_fully_negotiated_outbound(stream, info),
            ConnectionEvent::DialUpgradeError(DialUpgradeError { info, error }) => {
                self.handle_dial_upgrade_error(info, error);
            }
            _ => {}
        }
    }
}

async fn do_recv(
    mut stream: libp2p::swarm::Stream,
    verifier: Verifier,
    duty_gater: DutyGater,
) -> Result<(Duty, ParSignedDataSet), Failure> {
    let bytes = protocol::recv_message(&mut stream)
        .await
        .map_err(Failure::io)?;
    let (duty, data_set) = protocol::decode_message(&bytes).map_err(|_| Failure::InvalidPayload)?;
    if !duty_gater(&duty) {
        return Err(Failure::InvalidDuty);
    }
    for (pub_key, par_sig) in data_set.inner() {
        verifier(duty.clone(), *pub_key, par_sig.clone())
            .await
            .map_err(|_| Failure::InvalidPartialSignature)?;
    }
    Ok((duty, data_set))
}

async fn do_send(mut stream: libp2p::swarm::Stream, payload: Vec<u8>) -> Result<(), Failure> {
    protocol::send_message(&mut stream, &payload)
        .await
        .map_err(Failure::io)
}
