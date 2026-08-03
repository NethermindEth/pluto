//! Network behaviour and control handle for partial signature exchange.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use either::Either;
use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm, dummy,
    },
};
use tokio::sync::{RwLock, mpsc, oneshot};

use pluto_core::{
    eth2signeddata,
    gater::DutyGaterFn,
    types::{Duty, ParSignedData, ParSignedDataSet, PubKey},
};
use pluto_crypto::types::PublicKey;
use pluto_eth2api::EthBeaconNodeApiClient;
use pluto_p2p::p2p_context::P2PContext;

use super::{Handler, encode_message};
use crate::{
    error::{Error, Failure, Result, VerifyError},
    handler::{FromHandler, ToHandler},
};

/// Future returned by verifier callbacks.
pub type VerifyFuture =
    Pin<Box<dyn Future<Output = std::result::Result<(), VerifyError>> + Send + 'static>>;

/// Verifier callback type.
pub type Verifier =
    Arc<dyn Fn(Duty, PubKey, ParSignedData) -> VerifyFuture + Send + Sync + 'static>;

/// Returns a [`Verifier`] that verifies each inbound partial signature against
/// the sending peer's public share, looked up by the partial signature's share
/// index.
///
/// For a partial signature received for `pubkey`, it looks up the validator's
/// public shares (`pub_shares_by_key[pubkey]`), selects the share for the
/// partial signature's [`share_idx`](ParSignedData::share_idx), and delegates
/// to [`verify_eth2_signed_data`](eth2signeddata::verify_eth2_signed_data),
/// which derives the signing domain/epoch from
/// the [`SignedData`](pluto_core::types::SignedData) and verifies the eth2 BLS
/// signature.
/// A missing public key or share index is rejected.
///
/// Ports Charon's `parsigex.NewEth2Verifier`
pub fn new_eth2_verifier(
    eth2_cl: EthBeaconNodeApiClient,
    pub_shares_by_key: HashMap<PubKey, HashMap<u64, PublicKey>>,
) -> Verifier {
    let pub_shares_by_key = Arc::new(pub_shares_by_key);
    Arc::new(move |duty, pubkey, par_signed_data| {
        let eth2_cl = eth2_cl.clone();
        let pub_shares_by_key = pub_shares_by_key.clone();
        Box::pin(async move {
            let pubshares = pub_shares_by_key
                .get(&pubkey)
                .ok_or(VerifyError::UnknownPubKey)?;
            let pubshare = pubshares
                .get(&par_signed_data.share_idx)
                .ok_or(VerifyError::InvalidShareIndex)?;

            // `verify_eth2_signed_data` takes an already-upcast
            // `&dyn Eth2SignedData`; the upcast failure (Charon's
            // `data.(core.Eth2SignedData)` type assertion) maps to the
            // "invalid signed data family" error.
            let eth2_data =
                eth2signeddata::as_eth2_signed_data(par_signed_data.signed_data.as_ref())
                    .ok_or(VerifyError::InvalidSignedDataFamily)?;

            eth2signeddata::verify_eth2_signed_data(&eth2_cl, eth2_data, pubshare)
                .await
                .map_err(|source| VerifyError::InvalidSignature { duty, source })
        })
    })
}

/// Future returned by received subscriber callbacks.
pub type ReceivedSubFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Subscriber callback for received partial signature sets.
///
/// Called when a verified partial signature set is received from a peer.
pub type ReceivedSub =
    Arc<dyn Fn(Duty, ParSignedDataSet) -> ReceivedSubFuture + Send + Sync + 'static>;

/// Helper to create a received subscriber from a closure.
pub fn received_subscriber<F, Fut>(f: F) -> ReceivedSub
where
    F: Fn(Duty, ParSignedDataSet) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    Arc::new(move |duty, set| Box::pin(f(duty, set)))
}

/// Event emitted by the partial signature exchange behaviour.
#[derive(Debug)]
pub enum Event {
    /// A verified partial signature set was received from a peer.
    Received {
        /// The remote peer.
        peer: PeerId,
        /// Connection on which it was received.
        connection: ConnectionId,
        /// Duty associated with the data set.
        duty: Duty,
        /// Partial signature set.
        data_set: ParSignedDataSet,
    },
    /// A peer sent invalid data or verification failed.
    Error {
        /// The remote peer.
        peer: PeerId,
        /// Connection on which the error occurred.
        connection: ConnectionId,
        /// Failure reason.
        error: Failure,
    },
    /// Broadcast failed.
    BroadcastError {
        /// Request identifier.
        request_id: u64,
        /// Peer for which the broadcast failed, if known.
        peer: Option<PeerId>,
        /// Failure reason.
        error: Failure,
    },
    /// Broadcast completed successfully for all targeted peers.
    BroadcastComplete {
        /// Request identifier.
        request_id: u64,
    },
    /// Broadcast failed after one or more peer failures.
    BroadcastFailed {
        /// Request identifier.
        request_id: u64,
    },
}

#[derive(Debug)]
struct PendingBroadcast {
    pending_peers: HashSet<PeerId>,
    failure: Option<Failure>,
    result_tx: Option<oneshot::Sender<Result<u64>>>,
}

#[derive(Debug)]
struct BroadcastRequest {
    request_id: u64,
    duty: Duty,
    data_set: ParSignedDataSet,
    result_tx: Option<oneshot::Sender<Result<u64>>>,
}

/// Shared subscriber list between [`Handle`] and [`Behaviour`].
#[derive(Default)]
struct SharedSubs {
    subs: RwLock<Vec<ReceivedSub>>,
}

/// Async handle for outbound partial signature broadcasts.
#[derive(Clone)]
pub struct Handle {
    tx: mpsc::UnboundedSender<BroadcastRequest>,
    next_request_id: Arc<AtomicU64>,
    shared_subs: Arc<SharedSubs>,
}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle")
            .field("next_request_id", &self.next_request_id)
            .finish_non_exhaustive()
    }
}

impl Handle {
    /// Enqueues a partial signature set for broadcast to all peers except self.
    pub async fn broadcast(&self, duty: Duty, data_set: ParSignedDataSet) -> Result<u64> {
        self.enqueue(duty, data_set, None).await
    }

    /// Broadcasts a partial signature set and waits until the behaviour reports
    /// terminal success or failure.
    pub async fn broadcast_and_wait(&self, duty: Duty, data_set: ParSignedDataSet) -> Result<u64> {
        let (result_tx, result_rx) = oneshot::channel();
        self.enqueue(duty, data_set, Some(result_tx)).await?;
        result_rx.await.map_err(|_| Error::Closed)?
    }

    async fn enqueue(
        &self,
        duty: Duty,
        data_set: ParSignedDataSet,
        result_tx: Option<oneshot::Sender<Result<u64>>>,
    ) -> Result<u64> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.tx
            .send(BroadcastRequest {
                request_id,
                duty,
                data_set,
                result_tx,
            })
            .map_err(|_| Error::Closed)?;
        Ok(request_id)
    }

    /// Subscribers registered after the swarm begins polling may miss messages
    /// already in flight. Register all subscribers before starting the event
    /// loop.
    pub async fn subscribe(&self, sub: ReceivedSub) {
        self.shared_subs.subs.write().await.push(sub);
    }
}

/// Configuration for the partial signature exchange behaviour.
#[derive(Clone)]
pub struct Config {
    peer_id: PeerId,
    p2p_context: P2PContext,
    verifier: Verifier,
    duty_gater: DutyGaterFn,
    timeout: Duration,
}

impl Config {
    /// Creates a new configuration.
    pub fn new(
        peer_id: PeerId,
        p2p_context: P2PContext,
        verifier: Verifier,
        duty_gater: DutyGaterFn,
    ) -> Self {
        Self {
            peer_id,
            p2p_context,
            verifier,
            duty_gater,
            timeout: Duration::from_secs(20),
        }
    }

    /// Sets the send/receive timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Behaviour for partial signature exchange.
pub struct Behaviour {
    config: Config,
    rx: mpsc::UnboundedReceiver<BroadcastRequest>,
    pending_events: VecDeque<ToSwarm<Event, ToHandler>>,
    pending_broadcasts: HashMap<u64, PendingBroadcast>,
    shared_subs: Arc<SharedSubs>,
}

impl Behaviour {
    /// Creates a behaviour and a clonable broadcast handle.
    pub fn new(config: Config) -> (Self, Handle) {
        let (tx, rx) = mpsc::unbounded_channel();
        let shared_subs = Arc::new(SharedSubs::default());
        let handle = Handle {
            tx,
            next_request_id: Arc::new(AtomicU64::new(0)),
            shared_subs: shared_subs.clone(),
        };
        (
            Self {
                config,
                rx,
                pending_events: VecDeque::new(),
                pending_broadcasts: HashMap::new(),
                shared_subs,
            },
            handle,
        )
    }

    fn connection_handler_for_peer(&self, peer: PeerId) -> THandler<Self> {
        if !self.config.p2p_context.is_known_peer(&peer) {
            return Either::Right(dummy::ConnectionHandler);
        }
        Either::Left(Handler::new(
            self.config.timeout,
            self.config.verifier.clone(),
            self.config.duty_gater.clone(),
        ))
    }

    fn handle_command(&mut self, req: BroadcastRequest) {
        let BroadcastRequest {
            request_id,
            duty,
            data_set,
            result_tx,
        } = req;
        let message = match encode_message(&duty, &data_set) {
            Ok(message) => message,
            Err(err) => {
                let error = err.to_string();
                self.emit_broadcast_error(request_id, None, Failure::Codec(error.clone()));
                self.finish_broadcast_failure(result_tx, request_id, Failure::Codec(error));
                return;
            }
        };
        let message: Arc<[u8]> = Arc::from(message);

        let peers: Vec<_> = self
            .config
            .p2p_context
            .known_peers()
            .iter()
            .copied()
            .collect();
        let mut pending_peers = HashSet::new();
        let mut failure = None;
        // Clone the cheap `Arc`-backed context so the peer-store guard (held
        // once for the whole broadcast) does not keep `self` borrowed while the
        // loop mutably borrows other `self` fields via `emit_broadcast_error`.
        let p2p_context = self.config.p2p_context.clone();
        let peer_store = p2p_context.peer_store_lock();
        for peer in peers {
            if peer == self.config.peer_id {
                continue;
            }

            if !peer_store.has_connection(&peer) {
                let error = Failure::Io(std::io::Error::other(format!(
                    "peer {peer} is not connected"
                )));
                if failure.is_none() {
                    failure = Some(error.clone());
                }
                self.emit_broadcast_error(request_id, Some(peer), error);
                continue;
            }

            self.pending_events.push_back(ToSwarm::NotifyHandler {
                peer_id: peer,
                handler: NotifyHandler::Any,
                event: ToHandler::Send {
                    request_id,
                    payload: message.clone(),
                },
            });
            pending_peers.insert(peer);
        }
        drop(peer_store);
        drop(p2p_context);

        if pending_peers.is_empty() {
            self.pending_events
                .push_back(ToSwarm::GenerateEvent(Event::BroadcastFailed {
                    request_id,
                }));
            self.finish_broadcast_failure(
                result_tx,
                request_id,
                failure.unwrap_or_else(|| {
                    Failure::Io(std::io::Error::other("no peers available for broadcast"))
                }),
            );
            return;
        }

        self.pending_broadcasts.insert(
            request_id,
            PendingBroadcast {
                pending_peers,
                failure,
                result_tx,
            },
        );
    }

    fn finish_broadcast_result(
        &mut self,
        request_id: u64,
        peer_id: PeerId,
        failure: Option<Failure>,
    ) {
        let Some(entry) = self.pending_broadcasts.get_mut(&request_id) else {
            return;
        };

        if entry.failure.is_none() {
            entry.failure = failure;
        }
        entry.pending_peers.remove(&peer_id);
        if entry.pending_peers.is_empty() {
            let Some(entry) = self.pending_broadcasts.remove(&request_id) else {
                return;
            };
            if let Some(error) = entry.failure {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::BroadcastFailed {
                        request_id,
                    }));
                self.finish_broadcast_failure(entry.result_tx, request_id, error);
            } else {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::BroadcastComplete {
                        request_id,
                    }));
                self.finish_broadcast_request(entry.result_tx, Ok(request_id));
            }
        }
    }

    fn finish_broadcast_failure(
        &self,
        result_tx: Option<oneshot::Sender<Result<u64>>>,
        request_id: u64,
        error: Failure,
    ) {
        let Some(result_tx) = result_tx else {
            return;
        };
        let _ = result_tx.send(Err(Error::BroadcastFailed { request_id, error }));
    }

    fn finish_broadcast_request(
        &self,
        result_tx: Option<oneshot::Sender<Result<u64>>>,
        result: Result<u64>,
    ) {
        if let Some(result_tx) = result_tx {
            let _ = result_tx.send(result);
        }
    }

    fn emit_broadcast_error(&mut self, request_id: u64, peer: Option<PeerId>, error: Failure) {
        self.pending_events
            .push_back(ToSwarm::GenerateEvent(Event::BroadcastError {
                request_id,
                peer,
                error,
            }));
    }

    fn handle_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: FromHandler,
    ) {
        match event {
            FromHandler::Received { duty, data_set } => {
                self.notify_subscribers(duty.clone(), data_set.clone());
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::Received {
                        peer: peer_id,
                        connection: connection_id,
                        duty,
                        data_set,
                    }));
            }
            FromHandler::InboundError(error) => {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::Error {
                        peer: peer_id,
                        connection: connection_id,
                        error,
                    }));
            }
            FromHandler::OutboundSuccess { request_id } => {
                self.finish_broadcast_result(request_id, peer_id, None);
            }
            FromHandler::OutboundError { request_id, error } => {
                self.finish_broadcast_result(request_id, peer_id, Some(error.clone()));
                self.emit_broadcast_error(request_id, Some(peer_id), error);
            }
        }
    }

    /// Notifies all registered subscribers of a received partial signature set.
    ///
    /// Each subscriber is invoked in a spawned task since `poll()` is
    /// synchronous. This matches Go's intended behaviour (see Go TODO to call
    /// subscribers async).
    fn notify_subscribers(&self, duty: Duty, data_set: ParSignedDataSet) {
        let shared_subs = self.shared_subs.clone();
        tokio::spawn(async move {
            let subs = shared_subs.subs.read().await.clone();
            for sub in &subs {
                sub(duty.clone(), data_set.clone()).await;
            }
        });
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Either<Handler, dummy::ConnectionHandler>;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        Ok(self.connection_handler_for_peer(peer))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        Ok(self.connection_handler_for_peer(peer))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let FromSwarm::ConnectionClosed(e) = event
            && e.remaining_established == 0
        {
            let peer_id = e.peer_id;
            let affected: Vec<u64> = self
                .pending_broadcasts
                .iter()
                .filter(|(_, b)| b.pending_peers.contains(&peer_id))
                .map(|(id, _)| *id)
                .collect();
            for request_id in affected {
                let error = Failure::Io(std::io::Error::other("connection closed"));
                self.emit_broadcast_error(request_id, Some(peer_id), error.clone());
                self.finish_broadcast_result(request_id, peer_id, Some(error));
            }
        }
    }

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
        self.handle_handler_event(peer_id, connection_id, event);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event.map_in(Either::Left));
        }

        while let Poll::Ready(Some(command)) = self.rx.poll_recv(cx) {
            self.handle_command(command);
        }

        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event.map_in(Either::Left));
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod eth2_verifier_tests {
    use std::collections::HashMap;

    use pluto_core::{
        signeddata::Attestation,
        types::{Duty, ParSignedData, PubKey, SignedData},
    };
    use pluto_crypto::{
        blst_impl::BlstImpl,
        tbls::Tbls,
        types::{Index, PrivateKey, PublicKey},
    };
    use pluto_eth2api::{EthBeaconNodeApiClient, spec::phase0};
    use pluto_eth2util::signing::{DomainName, get_data_root};
    use pluto_testutil::BeaconMock;

    use super::new_eth2_verifier;
    use crate::error::VerifyError;

    const TOTAL_SHARES: Index = 4;
    const THRESHOLD: Index = 3;

    fn secret_key(hex_value: &str) -> PrivateKey {
        let bytes = hex::decode(hex_value).unwrap();
        bytes.as_slice().try_into().unwrap()
    }

    fn sample_attestation(target_epoch: phase0::Epoch) -> Attestation {
        let data = phase0::AttestationData {
            slot: 32,
            index: 2,
            beacon_block_root: [0x11; 32],
            source: phase0::Checkpoint {
                epoch: target_epoch.saturating_sub(1),
                root: [0x22; 32],
            },
            target: phase0::Checkpoint {
                epoch: target_epoch,
                root: [0x33; 32],
            },
        };

        Attestation::new(phase0::Attestation {
            aggregation_bits: serde_json::from_str("\"0x0101\"").unwrap(),
            data,
            signature: [0; 96],
        })
    }

    /// Signs the eth2 signing root of `data` for the given domain/epoch with
    /// `secret`, returning a copy of `data` carrying that signature.
    async fn sign<T>(
        client: &EthBeaconNodeApiClient,
        secret: &PrivateKey,
        data: &T,
        domain: DomainName,
        epoch: phase0::Epoch,
    ) -> T
    where
        T: SignedData + Sized,
    {
        let message_root = data.message_root().unwrap();
        let signing_root = get_data_root(client, domain, epoch, message_root)
            .await
            .unwrap();
        let signature = BlstImpl.sign(secret, &signing_root).unwrap();
        data.set_signature(signature).unwrap()
    }

    /// Splits `secret` into threshold BLS shares and returns each share's
    /// private key alongside the public-share map keyed by 1-indexed share id.
    fn split_shares(secret: &PrivateKey) -> (HashMap<Index, PrivateKey>, HashMap<u64, PublicKey>) {
        let shares = BlstImpl
            .threshold_split(secret, TOTAL_SHARES, THRESHOLD)
            .unwrap();
        let pub_shares = shares
            .iter()
            .map(|(idx, share)| (*idx, BlstImpl.secret_to_public_key(share).unwrap()))
            .collect();
        (shares, pub_shares)
    }

    fn attester_duty() -> Duty {
        Duty::new_attester_duty(32.into())
    }

    #[tokio::test]
    async fn accepts_partial_signature_against_correct_share() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let client = mock.client();

        let secret = secret_key("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b");
        let group_pubkey = PubKey::new(BlstImpl.secret_to_public_key(&secret).unwrap());
        let (shares, pub_shares) = split_shares(&secret);

        // Sign the attestation with the private share for index 2.
        let share_idx: Index = 2;
        let att = sample_attestation(4);
        let signed = sign(
            client,
            &shares[&share_idx],
            &att,
            DomainName::BeaconAttester,
            4,
        )
        .await;
        let par = ParSignedData::new(signed, share_idx);

        let mut pub_shares_by_key = HashMap::new();
        pub_shares_by_key.insert(group_pubkey, pub_shares);

        let verifier = new_eth2_verifier(client.clone(), pub_shares_by_key);
        verifier(attester_duty(), group_pubkey, par)
            .await
            .expect("partial signature against the correct public share verifies");
    }

    #[tokio::test]
    async fn rejects_partial_signature_against_wrong_share() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let client = mock.client();

        let secret = secret_key("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b");
        let group_pubkey = PubKey::new(BlstImpl.secret_to_public_key(&secret).unwrap());
        let (shares, pub_shares) = split_shares(&secret);

        // Sign with share 2's secret but claim share index 3, so the verifier
        // looks up share 3's public key and the signature fails to verify.
        let att = sample_attestation(4);
        let signed = sign(client, &shares[&2], &att, DomainName::BeaconAttester, 4).await;
        let par = ParSignedData::new(signed, 3);

        let mut pub_shares_by_key = HashMap::new();
        pub_shares_by_key.insert(group_pubkey, pub_shares);

        let verifier = new_eth2_verifier(client.clone(), pub_shares_by_key);
        let err = verifier(attester_duty(), group_pubkey, par)
            .await
            .expect_err("partial signature against the wrong public share is rejected");

        assert!(matches!(err, VerifyError::InvalidSignature { .. }));
    }

    #[tokio::test]
    async fn rejects_unknown_pubkey() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let client = mock.client();

        let secret = secret_key("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b");
        let group_pubkey = PubKey::new(BlstImpl.secret_to_public_key(&secret).unwrap());
        let (shares, _pub_shares) = split_shares(&secret);

        let att = sample_attestation(4);
        let signed = sign(client, &shares[&1], &att, DomainName::BeaconAttester, 4).await;
        let par = ParSignedData::new(signed, 1);

        // Empty map: the validator public key is not part of the cluster lock.
        let pub_shares_by_key = HashMap::new();

        let verifier = new_eth2_verifier(client.clone(), pub_shares_by_key);
        let err = verifier(attester_duty(), group_pubkey, par)
            .await
            .expect_err("partial signature for an unknown pubkey is rejected");

        assert!(matches!(err, VerifyError::UnknownPubKey));
    }

    #[tokio::test]
    async fn rejects_missing_share_index() {
        let mock = BeaconMock::builder().build().await.unwrap();
        let client = mock.client();

        let secret = secret_key("345768c0245f1dc702df9e50e811002f61ebb2680b3d5931527ef59f96cbaf9b");
        let group_pubkey = PubKey::new(BlstImpl.secret_to_public_key(&secret).unwrap());
        let (shares, pub_shares) = split_shares(&secret);

        let att = sample_attestation(4);
        let signed = sign(client, &shares[&1], &att, DomainName::BeaconAttester, 4).await;
        // Claim a share index that was never produced by the split.
        let par = ParSignedData::new(signed, TOTAL_SHARES + 1);

        let mut pub_shares_by_key = HashMap::new();
        pub_shares_by_key.insert(group_pubkey, pub_shares);

        let verifier = new_eth2_verifier(client.clone(), pub_shares_by_key);
        let err = verifier(attester_duty(), group_pubkey, par)
            .await
            .expect_err("partial signature with an unknown share index is rejected");

        assert!(matches!(err, VerifyError::InvalidShareIndex));
    }
}

#[cfg(test)]
mod broadcast_tests {
    use libp2p::{Multiaddr, PeerId, swarm::ConnectionId};

    use pluto_core::types::{Duty, ParSignedDataSet};
    use pluto_p2p::p2p_context::{P2PContext, Peer};

    use super::*;

    fn trivial_verifier() -> Verifier {
        Arc::new(|_duty, _pubkey, _par| Box::pin(async { Ok(()) }))
    }

    fn allow_all_gater() -> DutyGaterFn {
        Arc::new(|_duty| true)
    }

    fn connected_peer(context: &P2PContext, id: PeerId) {
        context.peer_store_write_lock().add_peer(Peer {
            id,
            connection_id: ConnectionId::new_unchecked(1),
            remote_addr: Multiaddr::empty(),
        });
    }

    /// A broadcast to multiple connected peers must share a single refcounted
    /// payload buffer across every `ToHandler::Send` instead of deep-copying
    /// the encoded bytes per target.
    #[test]
    fn broadcast_shares_single_payload_buffer() {
        let local = PeerId::random();
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();

        let context = P2PContext::new([local, peer_a, peer_b]);
        connected_peer(&context, peer_a);
        connected_peer(&context, peer_b);

        let config = Config::new(local, context, trivial_verifier(), allow_all_gater());
        let (mut behaviour, _handle) = Behaviour::new(config);

        behaviour.handle_command(BroadcastRequest {
            request_id: 1,
            duty: Duty::new_attester_duty(32.into()),
            data_set: ParSignedDataSet::new(),
            result_tx: None,
        });

        let payloads: Vec<Arc<[u8]>> = behaviour
            .pending_events
            .iter()
            .filter_map(|event| match event {
                ToSwarm::NotifyHandler {
                    event: ToHandler::Send { payload, .. },
                    ..
                } => Some(payload.clone()),
                _ => None,
            })
            .collect();

        assert_eq!(payloads.len(), 2, "one send per connected non-self peer");
        assert!(
            Arc::ptr_eq(&payloads[0], &payloads[1]),
            "all broadcast targets must share the same payload allocation"
        );
    }

    /// A known peer with no active connection still yields a single
    /// `BroadcastError` and is excluded from the pending broadcast.
    #[test]
    fn broadcast_reports_not_connected_peer() {
        let local = PeerId::random();
        let peer_a = PeerId::random();

        let context = P2PContext::new([local, peer_a]);
        // peer_a is known but never added to the peer store (not connected).

        let config = Config::new(local, context, trivial_verifier(), allow_all_gater());
        let (mut behaviour, _handle) = Behaviour::new(config);

        behaviour.handle_command(BroadcastRequest {
            request_id: 7,
            duty: Duty::new_attester_duty(32.into()),
            data_set: ParSignedDataSet::new(),
            result_tx: None,
        });

        let errors = behaviour
            .pending_events
            .iter()
            .filter(|event| matches!(event, ToSwarm::GenerateEvent(Event::BroadcastError { .. })))
            .count();
        assert_eq!(
            errors, 1,
            "the unconnected peer produces one BroadcastError"
        );

        // No send events, and the broadcast fails (no connected targets).
        assert!(behaviour.pending_events.iter().all(|event| !matches!(
            event,
            ToSwarm::NotifyHandler {
                event: ToHandler::Send { .. },
                ..
            }
        )));
    }
}
