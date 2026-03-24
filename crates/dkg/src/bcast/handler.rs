//! Connection handler for the DKG reliable-broadcast protocol.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    task::{Context, Poll},
};

use either::Either as UpgradeEither;
use futures::{
    AsyncWriteExt, FutureExt, StreamExt,
    future::{BoxFuture, Either as StreamEither},
    stream::FuturesUnordered,
};
use libp2p::{
    PeerId,
    core::upgrade::{ReadyUpgrade, SelectUpgrade},
    swarm::{
        ConnectionHandler, ConnectionHandlerEvent, Stream, StreamProtocol, StreamUpgradeError,
        SubstreamProtocol,
        handler::{
            ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
        },
    },
};
use prost::bytes::Bytes;
use tokio::{sync::RwLock, time::timeout};
use tracing::{debug, warn};

use crate::dkgpb::v1::bcast::{BCastMessage, BCastSigRequest, BCastSigResponse};

use super::{
    MSG_PROTOCOL_NAME, RECEIVE_TIMEOUT, SEND_TIMEOUT, SIG_PROTOCOL_NAME,
    component::Registry,
    error::{Error, Failure},
    protocol,
};

pub(crate) type DedupStore = Arc<RwLock<HashMap<DedupKey, Vec<u8>>>>;

/// Key used to deduplicate repeated signature requests from a peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DedupKey {
    /// The remote peer ID that requested a signature.
    pub(crate) peer_id: PeerId,
    /// The logical message ID.
    pub(crate) msg_id: String,
}

/// Behaviour-to-handler command.
#[derive(Debug)]
pub enum InEvent {
    /// Request a signature from the remote peer.
    RequestSignature {
        /// Operation identifier.
        op_id: u64,
        /// Registered message ID.
        msg_id: String,
        /// Wrapped protobuf payload.
        any_msg: prost_types::Any,
    },
    /// Fan out the final fully-signed message.
    BroadcastMessage {
        /// Operation identifier.
        op_id: u64,
        /// Fully-signed message payload.
        message: BCastMessage,
    },
}

/// Handler-to-behaviour event.
#[derive(Debug)]
pub enum OutEvent {
    /// A signature response was received.
    SigResponse {
        /// Operation identifier.
        op_id: u64,
        /// Signature bytes.
        signature: Vec<u8>,
    },
    /// A fully-signed message was sent successfully.
    MessageSent {
        /// Operation identifier.
        op_id: u64,
    },
    /// An outbound operation failed.
    OutboundFailure {
        /// Operation identifier.
        op_id: u64,
        /// Failure reason.
        failure: Failure,
    },
}

/// Internal outbound-open information used by the connection handler.
#[derive(Debug)]
pub enum PendingOpen {
    /// Open a `/sig` substream and send a signature request.
    Sig {
        /// Operation identifier.
        op_id: u64,
        /// Signature request to send.
        request: BCastSigRequest,
    },
    /// Open a `/msg` substream and send a fully-signed broadcast message.
    Msg {
        /// Operation identifier.
        op_id: u64,
        /// Broadcast message to send.
        message: BCastMessage,
    },
}

type ActiveFuture = BoxFuture<'static, Option<OutEvent>>;

/// Reliable-broadcast connection handler.
pub struct Handler {
    remote_peer_id: PeerId,
    registry: Registry,
    dedup: DedupStore,
    secret: Arc<k256::SecretKey>,
    peers: Arc<Vec<PeerId>>,
    pending_open: VecDeque<PendingOpen>,
    active_futures: FuturesUnordered<ActiveFuture>,
}

impl Handler {
    /// Creates a new handler for a single connection.
    pub(crate) fn new(
        remote_peer_id: PeerId,
        registry: Registry,
        dedup: DedupStore,
        secret: Arc<k256::SecretKey>,
        peers: Arc<Vec<PeerId>>,
    ) -> Self {
        Self {
            remote_peer_id,
            registry,
            dedup,
            secret,
            peers,
            pending_open: VecDeque::new(),
            active_futures: FuturesUnordered::new(),
        }
    }

    fn protocol_for_open(
        pending: &PendingOpen,
    ) -> SubstreamProtocol<
        UpgradeEither<ReadyUpgrade<StreamProtocol>, ReadyUpgrade<StreamProtocol>>,
        PendingOpen,
    > {
        match pending {
            PendingOpen::Sig { .. } => SubstreamProtocol::new(
                UpgradeEither::Left(ReadyUpgrade::new(SIG_PROTOCOL_NAME)),
                pending.clone(),
            ),
            PendingOpen::Msg { .. } => SubstreamProtocol::new(
                UpgradeEither::Right(ReadyUpgrade::new(MSG_PROTOCOL_NAME)),
                pending.clone(),
            ),
        }
    }
}

impl Clone for PendingOpen {
    fn clone(&self) -> Self {
        match self {
            Self::Sig { op_id, request } => Self::Sig {
                op_id: *op_id,
                request: request.clone(),
            },
            Self::Msg { op_id, message } => Self::Msg {
                op_id: *op_id,
                message: message.clone(),
            },
        }
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = InEvent;
    type InboundOpenInfo = ();
    type InboundProtocol =
        SelectUpgrade<ReadyUpgrade<StreamProtocol>, ReadyUpgrade<StreamProtocol>>;
    type OutboundOpenInfo = PendingOpen;
    type OutboundProtocol =
        UpgradeEither<ReadyUpgrade<StreamProtocol>, ReadyUpgrade<StreamProtocol>>;
    type ToBehaviour = OutEvent;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(
            SelectUpgrade::new(
                ReadyUpgrade::new(SIG_PROTOCOL_NAME),
                ReadyUpgrade::new(MSG_PROTOCOL_NAME),
            ),
            (),
        )
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            InEvent::RequestSignature {
                op_id,
                msg_id,
                any_msg,
            } => self.pending_open.push_back(PendingOpen::Sig {
                op_id,
                request: BCastSigRequest {
                    id: msg_id,
                    message: Some(any_msg),
                },
            }),
            InEvent::BroadcastMessage { op_id, message } => {
                self.pending_open
                    .push_back(PendingOpen::Msg { op_id, message });
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if let Some(event) = self.pending_open.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: Self::protocol_for_open(&event),
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
            }) => {
                let registry = self.registry.clone();
                let dedup = self.dedup.clone();
                let secret = self.secret.clone();
                let peers = self.peers.clone();
                let remote_peer_id = self.remote_peer_id;

                let future = async move {
                    let result = match protocol {
                        StreamEither::Left(stream) => {
                            handle_inbound_sig_request(
                                stream,
                                remote_peer_id,
                                registry,
                                dedup,
                                secret,
                            )
                            .await
                        }
                        StreamEither::Right(stream) => {
                            handle_inbound_broadcast(stream, remote_peer_id, registry, peers).await
                        }
                    };

                    if let Err(error) = result {
                        debug!(peer = %remote_peer_id, %error, "bcast inbound handling failed");
                    }

                    None
                };

                self.active_futures.push(future.boxed());
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol,
                info,
                ..
            }) => match (protocol, info) {
                (StreamEither::Left(stream), PendingOpen::Sig { op_id, request }) => {
                    let future = async move {
                        Some(
                            match timeout(SEND_TIMEOUT, protocol::send_sig_request(stream, request))
                                .await
                            {
                                Ok(Ok(signature)) => OutEvent::SigResponse { op_id, signature },
                                Ok(Err(error)) => OutEvent::OutboundFailure {
                                    op_id,
                                    failure: Failure::other(error),
                                },
                                Err(_) => OutEvent::OutboundFailure {
                                    op_id,
                                    failure: Failure::Timeout,
                                },
                            },
                        )
                    };

                    self.active_futures.push(future.boxed());
                }
                (StreamEither::Right(stream), PendingOpen::Msg { op_id, message }) => {
                    let future = async move {
                        Some(
                            match timeout(
                                SEND_TIMEOUT,
                                protocol::send_bcast_message(stream, message),
                            )
                            .await
                            {
                                Ok(Ok(())) => OutEvent::MessageSent { op_id },
                                Ok(Err(error)) => OutEvent::OutboundFailure {
                                    op_id,
                                    failure: Failure::other(error),
                                },
                                Err(_) => OutEvent::OutboundFailure {
                                    op_id,
                                    failure: Failure::Timeout,
                                },
                            },
                        )
                    };

                    self.active_futures.push(future.boxed());
                }
                (protocol, info) => {
                    warn!(
                        ?protocol,
                        ?info,
                        "unexpected outbound protocol/info combination"
                    );
                }
            },
            ConnectionEvent::DialUpgradeError(DialUpgradeError { info, error }) => {
                let op_id = match info {
                    PendingOpen::Sig { op_id, .. } | PendingOpen::Msg { op_id, .. } => op_id,
                };

                let failure = match error {
                    StreamUpgradeError::NegotiationFailed => Failure::Unsupported,
                    StreamUpgradeError::Timeout => Failure::Timeout,
                    StreamUpgradeError::Io(error) => Failure::io(error),
                    StreamUpgradeError::Apply(error) => Failure::other(error),
                };

                self.active_futures.push(
                    async move { Some(OutEvent::OutboundFailure { op_id, failure }) }.boxed(),
                );
            }
            _ => {}
        }
    }
}

async fn handle_inbound_sig_request(
    mut stream: Stream,
    peer_id: PeerId,
    registry: Registry,
    dedup: DedupStore,
    secret: Arc<k256::SecretKey>,
) -> Result<(), Error> {
    let request = timeout(
        RECEIVE_TIMEOUT,
        pluto_p2p::protobuf::read_protobuf::<BCastSigRequest, _>(
            &mut stream,
            protocol::MAX_MESSAGE_SIZE,
        ),
    )
    .await
    .map_err(|_| Error::Message("signature request timed out".to_string()))??;

    let any = request
        .message
        .ok_or(Error::MissingField { field: "message" })?;

    let handler = {
        let registry_guard = registry.read().await;
        registry_guard
            .get(&request.id)
            .cloned()
            .ok_or_else(|| Error::UnknownMessageId(request.id.clone()))?
    };

    handler.check(peer_id, &any)?;

    let hash = protocol::hash_any(&any);
    {
        let mut dedup_guard = dedup.write().await;
        let key = DedupKey {
            peer_id,
            msg_id: request.id.clone(),
        };
        if let Some(previous) = dedup_guard.get(&key) {
            if previous != &hash {
                return Err(Error::DuplicateMismatchingHash);
            }
        } else {
            dedup_guard.insert(key, hash);
        }
    }

    let signature = protocol::sign_any(&secret, &any)?;
    let response = BCastSigResponse {
        id: request.id,
        signature: Bytes::from(signature),
    };

    timeout(
        RECEIVE_TIMEOUT,
        pluto_p2p::protobuf::write_protobuf(&mut stream, &response),
    )
    .await
    .map_err(|_| Error::Message("signature response timed out".to_string()))??;

    stream.close().await?;
    Ok(())
}

async fn handle_inbound_broadcast(
    mut stream: Stream,
    peer_id: PeerId,
    registry: Registry,
    peers: Arc<Vec<PeerId>>,
) -> Result<(), Error> {
    let message = timeout(
        RECEIVE_TIMEOUT,
        pluto_p2p::protobuf::read_protobuf::<BCastMessage, _>(
            &mut stream,
            protocol::MAX_MESSAGE_SIZE,
        ),
    )
    .await
    .map_err(|_| Error::Message("broadcast receive timed out".to_string()))??;

    let any = message
        .message
        .ok_or(Error::MissingField { field: "message" })?;
    let signatures = message
        .signatures
        .iter()
        .map(|signature| signature.to_vec())
        .collect::<Vec<_>>();

    protocol::verify_signatures(&any, &signatures, &peers)?;

    let handler = {
        let registry_guard = registry.read().await;
        registry_guard
            .get(&message.id)
            .cloned()
            .ok_or_else(|| Error::UnknownMessageId(message.id.clone()))?
    };

    handler.callback(peer_id, &message.id, &any)?;
    stream.close().await?;
    Ok(())
}
