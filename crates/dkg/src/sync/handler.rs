//! Connection handler for the DKG sync protocol.

use std::{
    convert::Infallible,
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
use tokio::sync::mpsc;
use tokio::time::Sleep;
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

/// Sync connection handler.
pub struct Handler {
    peer_id: PeerId,
    server: Server,
    client: Option<Client>,
    inbound: Option<InboundFuture>,
    inbound_events_tx: mpsc::UnboundedSender<OutEvent>,
    inbound_events_rx: mpsc::UnboundedReceiver<OutEvent>,
    outbound: OutboundState,
    backoff: Duration,
}

impl Handler {
    /// Creates a new handler for a single connection.
    pub fn new(peer_id: PeerId, server: Server, client: Option<Client>) -> Self {
        let (inbound_events_tx, inbound_events_rx) = mpsc::unbounded_channel();
        Self {
            peer_id,
            server,
            client,
            inbound: None,
            inbound_events_tx,
            inbound_events_rx,
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

    fn try_request_outbound(
        &mut self,
    ) -> Option<ConnectionHandlerEvent<ReadyUpgrade<StreamProtocol>, (), OutEvent>> {
        let client = self.client.as_ref()?;
        if !client.should_run() || !client.try_claim_outbound() {
            return None;
        }

        self.outbound = OutboundState::OpenStream;
        Some(ConnectionHandlerEvent::OutboundSubstreamRequest {
            protocol: self.substream_protocol(),
        })
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
            StreamUpgradeError::NegotiationFailed => (Error::Unsupported, false),
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
            StreamUpgradeError::Io(error) => (
                Error::Io(error.to_string()),
                error.kind() == std::io::ErrorKind::ConnectionReset,
            ),
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
        if let Poll::Ready(Some(event)) = self.inbound_events_rx.poll_recv(cx) {
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
                if let Some(event) = self.try_request_outbound() {
                    return Poll::Ready(event);
                }
            }
            OutboundState::OpenStream => {}
            OutboundState::WaitingRetry(delay) => {
                if delay.as_mut().poll(cx).is_ready() {
                    if let Some(event) = self.try_request_outbound() {
                        return Poll::Ready(event);
                    }

                    self.outbound = OutboundState::Idle;
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
                        self.outbound = OutboundState::Idle;
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
                protocol: mut stream,
                ..
            }) => {
                stream.ignore_for_keep_alive();
                self.inbound = Some(
                    handle_inbound_stream(
                        self.peer_id,
                        self.server.clone(),
                        self.inbound_events_tx.clone(),
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
                self.outbound = OutboundState::Running(run_outbound_stream(client, stream).boxed());
            }
            ConnectionEvent::DialUpgradeError(error) => self.on_dial_upgrade_error(error),
            ConnectionEvent::AddressChange(_)
            | ConnectionEvent::LocalProtocolsChange(_)
            | ConnectionEvent::RemoteProtocolsChange(_) => {}
            ConnectionEvent::ListenUpgradeError(_) => {}
            _ => {}
        }
    }
}

async fn run_outbound_stream(client: Client, mut stream: Stream) -> OutboundExit {
    let mut interval = tokio::time::interval(client.period());
    let hash_signature = prost::bytes::Bytes::from(client.hash_sig().to_vec());
    let version = client.version().to_string();

    client.set_connected(true);

    loop {
        interval.tick().await;

        let shutdown = client.shutdown_requested();
        let timestamp = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(timestamp) => timestamp,
            Err(error) => return OutboundExit::Fatal(Error::Io(error.to_string())),
        };
        let nanos = timestamp.subsec_nanos();
        let timestamp = Timestamp {
            seconds: i64::try_from(timestamp.as_secs()).unwrap_or(i64::MAX),
            nanos: i32::try_from(nanos).unwrap_or(i32::MAX),
        };
        let request = MsgSync {
            timestamp: Some(timestamp),
            hash_signature: hash_signature.clone(),
            shutdown,
            version: version.clone(),
            step: client.step(),
        };

        let response: std::io::Result<MsgSyncResponse> =
            match pluto_p2p::proto::write_fixed_size_protobuf(&mut stream, &request).await {
                Ok(()) => pluto_p2p::proto::read_fixed_size_protobuf(&mut stream).await,
                Err(error) => Err(error),
            };

        let response = match response {
            Ok(response) => response,
            Err(error) => {
                return OutboundExit::Reconnectable {
                    relay_reset: error.kind() == std::io::ErrorKind::ConnectionReset,
                    error: Error::Io(error.to_string()),
                };
            }
        };

        if !response.error.is_empty() {
            return OutboundExit::Fatal(Error::PeerRespondedWithError(response.error));
        }

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
    inbound_events_tx: mpsc::UnboundedSender<OutEvent>,
    mut stream: Stream,
) -> Result<()> {
    let result = async {
        if !server.is_started() {
            return Err(Error::ServerNotStarted);
        }

        let public_key = pluto_p2p::peer::peer_id_to_libp2p_pk(&peer_id)
            .map_err(|error| Error::Peer(error.to_string()))?;

        loop {
            let message: MsgSync = pluto_p2p::proto::read_fixed_size_protobuf(&mut stream)
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
                send_inbound_event(
                    &inbound_events_tx,
                    OutEvent::SyncRejected {
                        peer_id,
                        error: error.clone(),
                    },
                );
                server
                    .set_err(Error::InvalidSyncMessage {
                        peer: peer_id,
                        error: error.to_string(),
                    })
                    .await;
                response.error = error.to_string();
            } else {
                let (inserted, count) = server.mark_connected(peer_id).await;
                if inserted {
                    info!(
                        peer = %peer_id,
                        connected = count,
                        expected = server.expected_peer_count(),
                        "Connected to peer"
                    );
                }
            }

            if server.update_step(peer_id, message.step).await? {
                send_inbound_event(
                    &inbound_events_tx,
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
                send_inbound_event(
                    &inbound_events_tx,
                    OutEvent::PeerShutdownObserved { peer_id },
                );
                server.set_shutdown(peer_id).await;
                return Ok(());
            }
        }
    }
    .await;

    server.clear_connected(peer_id).await;
    result
}

fn send_inbound_event(inbound_events_tx: &mpsc::UnboundedSender<OutEvent>, event: OutEvent) {
    if let Err(error) = inbound_events_tx.send(event) {
        tracing::error!(err = %error, "Failed to deliver inbound sync event");
    }
}
