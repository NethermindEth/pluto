//! libp2p `ConnectionHandler` for the FROST round-1 direct P2P protocol.

use std::{
    collections::VecDeque,
    task::{Context, Poll},
};

use futures::{AsyncWriteExt, FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
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
use tokio::time::timeout;
use tracing::warn;

use super::{RECEIVE_TIMEOUT, ROUND1_P2P_PROTOCOL, SEND_TIMEOUT};
use crate::dkgpb::v1::frost::FrostRound1P2p;

#[derive(Debug)]
pub(crate) enum InEvent {
    Send { op_id: u64, msg: FrostRound1P2p },
    CancelAllPending,
}

#[derive(Debug)]
pub(crate) enum OutEvent {
    Received(FrostRound1P2p),
    Sent { op_id: u64 },
    Failed { op_id: u64, message: String },
}

type ActiveFuture = BoxFuture<'static, Option<OutEvent>>;

/// Connection handler for the FROST round-1 direct P2P protocol.
pub(crate) struct FrostP2PHandler {
    pending_open: VecDeque<(u64, FrostRound1P2p)>,
    active_futures: FuturesUnordered<ActiveFuture>,
}

impl FrostP2PHandler {
    pub(super) fn new() -> Self {
        Self {
            pending_open: VecDeque::new(),
            active_futures: FuturesUnordered::new(),
        }
    }

    fn handle_fully_negotiated_inbound(&mut self, mut stream: Stream) {
        self.active_futures.push(
            async move {
                read_inbound_message(&mut stream)
                    .await
                    .map(OutEvent::Received)
            }
            .boxed(),
        );
    }

    fn handle_fully_negotiated_outbound(
        &mut self,
        mut stream: Stream,
        (op_id, msg): (u64, FrostRound1P2p),
    ) {
        self.active_futures
            .push(async move { write_outbound_message(&mut stream, op_id, &msg).await }.boxed());
    }

    fn handle_dial_upgrade_error<E>(
        &mut self,
        (op_id, _): (u64, FrostRound1P2p),
        error: StreamUpgradeError<E>,
    ) where
        E: std::error::Error + Send + Sync + 'static,
    {
        let message = match error {
            StreamUpgradeError::NegotiationFailed => "protocol negotiation failed".to_string(),
            StreamUpgradeError::Timeout => "operation timed out".to_string(),
            StreamUpgradeError::Io(error) => error.to_string(),
            StreamUpgradeError::Apply(error) => error.to_string(),
        };
        self.active_futures
            .push(async move { Some(OutEvent::Failed { op_id, message }) }.boxed());
    }

    #[cfg(test)]
    pub(super) fn pending_open_len(&self) -> usize {
        self.pending_open.len()
    }
}

impl ConnectionHandler for FrostP2PHandler {
    type FromBehaviour = InEvent;
    type InboundOpenInfo = ();
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundOpenInfo = (u64, FrostRound1P2p);
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type ToBehaviour = OutEvent;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(ReadyUpgrade::new(ROUND1_P2P_PROTOCOL), ())
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            InEvent::Send { op_id, msg } => self.pending_open.push_back((op_id, msg)),
            InEvent::CancelAllPending => self.pending_open.clear(),
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if let Some(open_info) = self.pending_open.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(ReadyUpgrade::new(ROUND1_P2P_PROTOCOL), open_info),
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
                protocol, ..
            }) => self.handle_fully_negotiated_inbound(protocol),
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol,
                info,
                ..
            }) => self.handle_fully_negotiated_outbound(protocol, info),
            ConnectionEvent::DialUpgradeError(DialUpgradeError { info, error }) => {
                self.handle_dial_upgrade_error(info, error);
            }
            _ => {}
        }
    }
}

async fn read_inbound_message(stream: &mut Stream) -> Option<FrostRound1P2p> {
    let result = timeout(
        RECEIVE_TIMEOUT,
        pluto_p2p::proto::read_protobuf_with_max_size::<FrostRound1P2p, _>(
            stream,
            pluto_p2p::proto::MAX_MESSAGE_SIZE,
        ),
    )
    .await;
    let msg = match result {
        Ok(Ok(msg)) => Some(msg),
        Ok(Err(error)) => {
            warn!(%error, "failed to read frost p2p inbound message");
            None
        }
        Err(_) => {
            warn!("timed out reading frost p2p inbound message");
            None
        }
    };

    if let Err(error) = stream.close().await {
        warn!(%error, "failed to close frost p2p inbound stream");
    }

    msg
}

async fn write_outbound_message(
    stream: &mut Stream,
    op_id: u64,
    msg: &FrostRound1P2p,
) -> Option<OutEvent> {
    let result = timeout(SEND_TIMEOUT, async {
        pluto_p2p::proto::write_protobuf(stream, msg).await?;
        stream.close().await
    })
    .await;

    Some(match result {
        Ok(Ok(())) => OutEvent::Sent { op_id },
        Ok(Err(error)) => OutEvent::Failed {
            op_id,
            message: error.to_string(),
        },
        Err(_) => OutEvent::Failed {
            op_id,
            message: "operation timed out".to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_all_removes_handler_pending_open() {
        let mut handler = FrostP2PHandler::new();

        handler.on_behaviour_event(InEvent::Send {
            op_id: 7,
            msg: FrostRound1P2p::default(),
        });
        handler.on_behaviour_event(InEvent::CancelAllPending);

        assert_eq!(handler.pending_open_len(), 0);
    }
}
