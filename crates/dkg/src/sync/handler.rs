//! Connection handler for the DKG sync protocol.

use std::{
    convert::Infallible,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::{FutureExt, future::BoxFuture};
use libp2p::{
    PeerId, Stream,
    core::upgrade::ReadyUpgrade,
    swarm::{
        ConnectionHandler, ConnectionHandlerEvent, StreamProtocol, StreamUpgradeError,
        SubstreamProtocol,
        handler::{
            ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
        },
    },
};
use prost_types::Timestamp;
use tokio::{
    sync::mpsc,
    time::{Instant, Sleep},
};
use tracing::{debug, info, warn};

use crate::dkgpb::v1::sync::{MsgSync, MsgSyncResponse};

use super::{
    Event,
    client::Client,
    error::{Error, Result},
    protocol,
    server::Server,
};

const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(1);

type InboundFuture = BoxFuture<'static, Result<()>>;
type OutboundEvent = ConnectionHandlerEvent<ReadyUpgrade<StreamProtocol>, (), OutEvent>;

/// Protocol-level events emitted by the sync handler.
pub type OutEvent = Event;

enum OutboundState {
    Idle,
    OpenStream,
    Running(BoxFuture<'static, OutboundExit>),
    WaitingRetry(Pin<Box<Sleep>>),
    Disabled,
}

enum OutboundExit {
    GracefulShutdown,
    Reconnectable { error: Error, relay_reset: bool },
    Fatal(Error),
}

enum OutboundRequest {
    /// This handler claimed outbound ownership and requested a new substream.
    Requested(OutboundEvent),
    /// The client is active, but another handler already owns the outbound
    /// stream.
    Busy,
    /// The client is not active, or this connection has no outbound client.
    Inactive,
}

/// Sync connection handler.
pub struct Handler {
    peer_id: PeerId,
    server: Server,
    client: Option<Client>,
    inbound: Option<InboundFuture>,
    events_tx: mpsc::UnboundedSender<OutEvent>,
    events_rx: mpsc::UnboundedReceiver<OutEvent>,
    outbound: OutboundState,
    backoff: Duration,
}

impl Handler {
    /// Creates a new handler for a single connection.
    pub fn new(peer_id: PeerId, server: Server, client: Option<Client>) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        Self {
            peer_id,
            server,
            client,
            inbound: None,
            events_tx,
            events_rx,
            outbound: OutboundState::Idle,
            backoff: INITIAL_BACKOFF,
        }
    }

    fn substream_protocol(&self) -> SubstreamProtocol<ReadyUpgrade<StreamProtocol>> {
        SubstreamProtocol::new(ReadyUpgrade::new(protocol::PROTOCOL_NAME), ())
    }

    fn schedule_retry(&mut self) {
        let sleep = Box::pin(tokio::time::sleep(self.backoff));
        self.outbound = OutboundState::WaitingRetry(sleep);
        self.backoff = self.backoff.saturating_mul(2).min(MAX_BACKOFF);
    }

    fn schedule_retry_and_poll(&mut self, cx: &mut Context<'_>) {
        self.schedule_retry();
        if let OutboundState::WaitingRetry(delay) = &mut self.outbound {
            let _ = delay.as_mut().poll(cx);
        }
    }

    fn try_request_outbound(&mut self) -> OutboundRequest {
        let Some(client) = self.client.as_ref() else {
            return OutboundRequest::Inactive;
        };

        if !client.should_run() {
            return OutboundRequest::Inactive;
        }

        if !client.try_claim_outbound() {
            return OutboundRequest::Busy;
        }

        self.outbound = OutboundState::OpenStream;
        OutboundRequest::Requested(ConnectionHandlerEvent::OutboundSubstreamRequest {
            protocol: self.substream_protocol(),
        })
    }

    fn poll_idle_outbound(&mut self, cx: &mut Context<'_>) -> Option<OutboundEvent> {
        match self.try_request_outbound() {
            OutboundRequest::Requested(event) => Some(event),
            OutboundRequest::Busy => {
                self.schedule_retry_and_poll(cx);
                None
            }
            OutboundRequest::Inactive => None,
        }
    }

    fn on_dial_upgrade_error(
        &mut self,
        DialUpgradeError { error, .. }: DialUpgradeError<
            (),
            <Self as ConnectionHandler>::OutboundProtocol,
        >,
    ) {
        let Some(client) = self.client.as_ref() else {
            self.outbound = OutboundState::Disabled;
            return;
        };

        client.release_outbound();

        let (error, relay_reset) = match error {
            StreamUpgradeError::NegotiationFailed => {
                client.finish(Err(Error::Unsupported));
                self.outbound = OutboundState::Disabled;
                return;
            }
            StreamUpgradeError::Timeout => (
                Error::Io(
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "sync protocol negotiation timed out",
                    )
                    .to_string(),
                ),
                false,
            ),
            StreamUpgradeError::Apply(never) => match never {},
            StreamUpgradeError::Io(error) => {
                (Error::Io(error.to_string()), is_relay_io_error(&error))
            }
        };

        if relay_reset || client.should_reconnect() {
            self.schedule_retry();
        } else {
            client.finish(Err(error));
            self.outbound = OutboundState::Disabled;
        }
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = Infallible;
    type InboundOpenInfo = ();
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundOpenInfo = ();
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type ToBehaviour = OutEvent;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        self.substream_protocol()
    }

    fn on_behaviour_event(&mut self, never: Self::FromBehaviour) {
        match never {}
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if let Poll::Ready(Some(event)) = self.events_rx.poll_recv(cx) {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
        }

        if let Some(inbound) = self.inbound.as_mut() {
            match inbound.poll_unpin(cx) {
                Poll::Pending => {}
                Poll::Ready(Ok(())) => {
                    self.inbound = None;
                }
                Poll::Ready(Err(error)) => {
                    warn!(peer = %self.peer_id, err = %error, "Error serving inbound sync stream");
                    self.inbound = None;
                }
            }
        }

        match &mut self.outbound {
            OutboundState::Idle => {
                if let Some(event) = self.poll_idle_outbound(cx) {
                    return Poll::Ready(event);
                }
            }
            OutboundState::OpenStream => {}
            OutboundState::WaitingRetry(delay) => {
                if delay.as_mut().poll(cx).is_ready() {
                    match self.try_request_outbound() {
                        OutboundRequest::Requested(event) => return Poll::Ready(event),
                        OutboundRequest::Busy => self.schedule_retry_and_poll(cx),
                        OutboundRequest::Inactive => self.outbound = OutboundState::Idle,
                    }
                }
            }
            OutboundState::Running(fut) => match fut.poll_unpin(cx) {
                Poll::Pending => {}
                Poll::Ready(OutboundExit::GracefulShutdown) => {
                    if let Some(client) = self.client.as_ref() {
                        client.finish(Ok(()));
                    }
                    self.outbound = OutboundState::Disabled;
                }
                Poll::Ready(OutboundExit::Reconnectable { error, relay_reset }) => {
                    let Some(client) = self.client.as_ref() else {
                        self.outbound = OutboundState::Disabled;
                        return Poll::Pending;
                    };

                    client.set_connected(false);
                    client.release_outbound();

                    if relay_reset || client.should_reconnect() {
                        info!(peer = %self.peer_id, err = %error, "Disconnected from peer");
                        self.backoff = INITIAL_BACKOFF;
                        self.schedule_retry_and_poll(cx);
                    } else {
                        client.finish(Err(error));
                        self.outbound = OutboundState::Disabled;
                    }
                }
                Poll::Ready(OutboundExit::Fatal(error)) => {
                    if let Some(client) = self.client.as_ref() {
                        client.finish(Err(error));
                    }
                    self.outbound = OutboundState::Disabled;
                }
            },
            OutboundState::Disabled => {}
        }

        Poll::Pending
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol>,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: stream,
                ..
            }) => {
                if self.inbound.is_some() {
                    warn!(peer = %self.peer_id, "Dropping duplicate inbound sync stream");
                    return;
                }

                self.inbound = Some(
                    handle_inbound_stream(
                        self.peer_id,
                        self.server.clone(),
                        self.events_tx.clone(),
                        stream,
                    )
                    .boxed(),
                );
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: mut stream,
                ..
            }) => {
                let Some(client) = self.client.clone() else {
                    self.outbound = OutboundState::Disabled;
                    return;
                };

                stream.ignore_for_keep_alive();
                self.backoff = INITIAL_BACKOFF;
                self.outbound = OutboundState::Running(
                    run_outbound_stream(client, self.events_tx.clone(), stream).boxed(),
                );
            }
            ConnectionEvent::DialUpgradeError(error) => self.on_dial_upgrade_error(error),
            _ => {}
        }
    }
}

async fn run_outbound_stream(
    client: Client,
    events_tx: mpsc::UnboundedSender<OutEvent>,
    mut stream: Stream,
) -> OutboundExit {
    let mut interval = tokio::time::interval(client.period());
    let mut stop_rx = client.stop_requested_rx();
    let hash_signature = prost::bytes::Bytes::copy_from_slice(client.hash_sig());
    let version = client.version().to_string();

    client.set_connected(true);

    loop {
        if *stop_rx.borrow() {
            return OutboundExit::Fatal(Error::Canceled);
        }

        tokio::select! {
            _ = interval.tick() => {}
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    return OutboundExit::Fatal(Error::Canceled);
                }
                continue;
            }
        }

        let (shutdown, step) = client.outbound_message_state();
        let timestamp = Timestamp::from(std::time::SystemTime::now());
        let request = MsgSync {
            timestamp: Some(timestamp),
            hash_signature: hash_signature.clone(),
            shutdown,
            version: version.clone(),
            step,
        };
        let sent_at = Instant::now();

        let response: std::io::Result<MsgSyncResponse> = tokio::select! {
            response = async {
                match pluto_p2p::proto::write_fixed_size_protobuf(&mut stream, &request).await {
                    Ok(()) => {
                        pluto_p2p::proto::read_fixed_size_protobuf_with_max_size(
                            &mut stream,
                            protocol::MAX_MESSAGE_SIZE,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                }
            } => response,
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    return OutboundExit::Fatal(Error::Canceled);
                }
                continue;
            }
        };

        let response = match response {
            Ok(response) => response,
            Err(error) => {
                return OutboundExit::Reconnectable {
                    relay_reset: is_relay_io_error(&error),
                    error: Error::Io(error.to_string()),
                };
            }
        };

        if !response.error.is_empty() {
            return OutboundExit::Fatal(Error::PeerRespondedWithError(response.error));
        }

        send_event(
            &events_tx,
            OutEvent::PeerRttObserved {
                peer_id: client.peer_id(),
                rtt: sent_at.elapsed(),
            },
        );
        if let Some(sync_timestamp) = response.sync_timestamp {
            debug!(
                peer = %client.peer_id(),
                sync_timestamp = ?sync_timestamp,
                "Received sync response"
            );
        }

        if shutdown {
            return OutboundExit::GracefulShutdown;
        }
    }
}

async fn handle_inbound_stream(
    peer_id: PeerId,
    server: Server,
    events_tx: mpsc::UnboundedSender<OutEvent>,
    mut stream: Stream,
) -> Result<()> {
    let result = async {
        if !server.is_started() {
            return Err(Error::ServerNotStarted);
        }

        let public_key = pluto_p2p::peer::peer_id_to_libp2p_pk(&peer_id)
            .map_err(|error| Error::Peer(error.to_string()))?;

        loop {
            let message: MsgSync = pluto_p2p::proto::read_fixed_size_protobuf_with_max_size(
                &mut stream,
                protocol::MAX_MESSAGE_SIZE,
            )
            .await
            .map_err(|error| Error::Io(error.to_string()))?;
            let mut response = MsgSyncResponse {
                sync_timestamp: message.timestamp,
                error: String::new(),
            };

            if let Err(error) = protocol::validate_request_with_public_key(
                server.def_hash(),
                server.version(),
                &public_key,
                &message,
            ) {
                let error_string = error.to_string();
                send_event(&events_tx, OutEvent::SyncRejected { peer_id, error });
                server
                    .set_err(Error::InvalidSyncMessage {
                        peer: peer_id,
                        error: error_string.clone(),
                    })
                    .await;
                response.error = error_string;
            } else {
                let (inserted, count) = server.set_connected(peer_id).await;
                if inserted {
                    info!(
                        peer = %peer_id,
                        connected = count,
                        expected = server.expected_peer_count(),
                        "Connected to peer"
                    );
                }
            }

            // Record observed step even after validation failure.
            // Barrier waiters still fail fast on `server.err`
            let updated = match server.update_step(peer_id, message.step).await {
                Ok(updated) => updated,
                Err(error) => {
                    server.set_err(error.clone()).await;
                    return Err(error);
                }
            };
            if updated {
                send_event(
                    &events_tx,
                    OutEvent::PeerStepUpdated {
                        peer_id,
                        step: message.step,
                    },
                );
            }

            pluto_p2p::proto::write_fixed_size_protobuf(&mut stream, &response)
                .await
                .map_err(|error| Error::Io(error.to_string()))?;

            if message.shutdown {
                send_event(&events_tx, OutEvent::PeerShutdownObserved { peer_id });
                server.set_shutdown(peer_id).await;
                return Ok(());
            }
        }
    }
    .await;

    server.clear_connected(peer_id).await;
    result
}

fn send_event(events_tx: &mpsc::UnboundedSender<OutEvent>, event: OutEvent) {
    if let Err(error) = events_tx.send(event) {
        debug!(err = %error, "dropping sync event: handler event receiver closed");
    }
}

fn is_relay_io_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll};

    use futures::task::noop_waker_ref;
    use libp2p::swarm::{ConnectionHandler, ConnectionHandlerEvent};
    use pluto_core::version::SemVer;
    use tokio::{sync::mpsc, time::Duration};

    use super::*;
    use crate::sync::ClientConfig;

    #[test]
    fn relay_io_errors_match_rust_libp2p_relay_closure_paths() {
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
        ] {
            assert!(is_relay_io_error(&io::Error::from(kind)));
        }

        assert!(!is_relay_io_error(&io::Error::from(
            io::ErrorKind::TimedOut
        )));
    }

    #[tokio::test]
    async fn retry_stays_scheduled_while_outbound_claim_is_busy() {
        let peer_id = PeerId::random();
        let version = SemVer::parse("v1.7").expect("valid version");
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let client = Client::new(
            peer_id,
            vec![1, 2, 3],
            version.clone(),
            ClientConfig::default(),
            Some(command_tx),
        );
        client.activate().expect("client should activate");
        assert!(client.try_claim_outbound());

        let server = Server::new(1, vec![1, 2, 3], version);
        let mut handler = Handler::new(peer_id, server, Some(client.clone()));
        handler.backoff = Duration::from_millis(1);
        handler.schedule_retry();

        tokio::time::sleep(Duration::from_millis(2)).await;
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        let poll = ConnectionHandler::poll(&mut handler, &mut cx);
        assert!(matches!(poll, Poll::Pending));
        assert!(matches!(handler.outbound, OutboundState::WaitingRetry(_)));

        client.release_outbound();
        tokio::time::sleep(Duration::from_millis(3)).await;

        let poll = ConnectionHandler::poll(&mut handler, &mut cx);
        assert!(matches!(
            poll,
            Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { .. })
        ));
    }
}
