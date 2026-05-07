#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use pluto_crypto::{
    tblsconv::{privkey_from_bytes, pubkey_from_bytes},
    types::PublicKey,
};
use pluto_frost::{
    G1Affine, G1Projective, KeyPackage,
    kryptology::{self, Round1Bcast, Round1Secret, Round2Bcast, ShamirShare},
    validate_num_of_signers,
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::share::Share;

type Round1Output = (HashMap<MsgKey, Round1Bcast>, HashMap<MsgKey, ShamirShare>);

/// Identifies the source and target nodes and validator index the message
/// belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct MsgKey {
    /// Identifies the distributed validator (Ith parallel participant) the
    /// message belongs to. It is 0-indexed.
    pub(crate) val_idx: u32,
    /// Identifies the source node/participant ID of the message.
    /// It is 1-indexed and equivalent to `cluster.NodeIdx.ShareIdx`.
    pub(crate) source_id: u32,
    /// Identifies the target node/participant ID of the message.
    /// It is 1-indexed and equivalent to `cluster.NodeIdx.ShareIdx`.
    /// The zero value indicates outgoing broadcast messages.
    pub(crate) target_id: u32,
}

/// Abstracts the transport of frost DKG messages.
#[async_trait]
pub(crate) trait FTransport: Send + Sync {
    /// Returns results of all round 1 communication: the received round 1
    /// broadcasts from all other nodes and the round 1 P2P sends to this
    /// node.
    async fn round1(
        &mut self,
        cancellation: &CancellationToken,
        bcast: HashMap<MsgKey, Round1Bcast>,
        shares: HashMap<MsgKey, ShamirShare>,
    ) -> Result<Round1Output, FrostError>;

    /// Returns results of all round 2 communication: the received round 2
    /// broadcasts from all other nodes.
    async fn round2(
        &mut self,
        cancellation: &CancellationToken,
        bcast: HashMap<MsgKey, Round2Bcast>,
    ) -> Result<HashMap<MsgKey, Round2Bcast>, FrostError>;
}

/// FROST DKG orchestration errors.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FrostError {
    /// Failed to construct a participant.
    #[error("new participant: {0}")]
    NewParticipant(#[source] pluto_frost::kryptology::KryptologyError),
    /// Failed during local round 1 execution.
    #[error("exec round 1: {0}")]
    ExecRound1(#[source] pluto_frost::kryptology::KryptologyError),
    /// Failed during local round 2 execution.
    #[error("exec round 2: {0}")]
    ExecRound2(#[source] pluto_frost::kryptology::KryptologyError),
    /// Reliable broadcast failed.
    #[error("bcast: {0}")]
    Bcast(#[from] crate::bcast::Error),
    /// Direct FROST P2P send failed.
    #[error("frost p2p send: {0}")]
    FrostP2P(#[from] crate::frostp2p::FrostP2PError),
    /// Too many round-1 broadcast messages were collected.
    #[error("too many round 1 casts messages")]
    TooManyRound1CastsMessages,
    /// Too many round-1 direct P2P messages were collected.
    #[error("too many round 1 p2p messages")]
    TooManyRound1P2PMessages,
    /// Too many round-2 broadcast messages were collected.
    #[error("too many round 2 casts messages")]
    TooManyRound2CastsMessages,
    /// A FROST message key was missing.
    #[error("frost msg key cannot be nil")]
    MissingMsgKey,
    /// A round-1 P2P message source ID was invalid.
    #[error("invalid round 1 p2p source ID")]
    InvalidRound1P2PSourceId,
    /// A round-1 P2P message target ID was invalid.
    #[error("invalid round 1 p2p target ID")]
    InvalidRound1P2PTargetId,
    /// A round-1 P2P message validator index was invalid.
    #[error("invalid round 1 p2p validator index")]
    InvalidRound1P2PValidatorIndex,
    /// A round-1 P2P message did not contain exactly one share per validator.
    #[error("invalid round 1 p2p shares count")]
    InvalidRound1P2PSharesCount,
    /// A round-1 P2P message repeated a validator index.
    #[error("duplicate round 1 p2p validator index")]
    DuplicateRound1P2PValidatorIndex,
    /// Failed to decode the round-1 Wi scalar.
    #[error("decode wi scalar")]
    DecodeWiScalar,
    /// Failed to decode the round-1 C_i scalar.
    #[error("decode c1 scalar")]
    DecodeC1Scalar,
    /// Failed to decode a round-1 commitment point.
    #[error("decode commitment")]
    DecodeCommitment,
    /// Failed to decode a round-1 Shamir share scalar.
    #[error("decode shamir scalar")]
    DecodeShamirScalar,
    /// Failed to decode a round-2 verification key point.
    #[error("decode verification key scalar")]
    DecodeVerificationKeyScalar,
    /// Failed to decode a round-2 verification key share point.
    #[error("decode vk share")]
    DecodeVkShare,
    /// FROST transport configuration is invalid.
    #[error("frost config: {0}")]
    ConfigError(&'static str),
    /// The FROST P2P inbound receiver was already taken.
    #[error("frost p2p inbound receiver already taken")]
    P2PInboundReceiverAlreadyTaken,
    /// The FROST broadcast event receiver was already taken.
    #[error("frost bcast event receiver already taken")]
    BcastEventReceiverAlreadyTaken,
    /// The round-1 casts receiver was dropped before local self-delivery.
    #[error("frost round 1 casts receiver dropped before self-delivery")]
    Round1CastsReceiverDropped,
    /// The round-2 casts receiver was dropped before local self-delivery.
    #[error("frost round 2 casts receiver dropped before self-delivery")]
    Round2CastsReceiverDropped,
    /// Round-1 P2P construction attempted to send a private share to self.
    #[error("unexpected p2p message to self")]
    UnexpectedP2PMessageToSelf,
    /// FROST transport channel closed unexpectedly.
    #[error("frost channel closed: {0}")]
    ChannelClosed(&'static str),
    /// Failed to convert public key bytes.
    #[error("public key conversion: {0}")]
    PublicKey(#[from] pluto_crypto::tblsconv::ConvError),
    /// Failed to decode a compressed G1 public key point.
    #[error("invalid compressed G1 public key point")]
    InvalidPublicKeyPoint,
    /// Generated key package was incomplete.
    #[error("participant missing round state")]
    MissingRoundState,
    /// Participant was called in the wrong DKG round.
    #[error("invalid participant round: expected {expected}, got {current}")]
    InvalidRound { expected: u8, current: u8 },
    /// Failed to convert a numeric value to the target representation.
    #[error(transparent)]
    IntConversion(#[from] std::num::TryFromIntError),
    /// Cancellation was requested while waiting for transport data.
    #[error("frost dkg cancelled")]
    Cancelled,
}

struct DkgParticipant {
    id: u32,
    round: u8,
    threshold: u16,
    max_signers: u16,
    other_ids: Vec<u32>,
    ctx: u8,
    round1_secret: Option<Round1Secret>,
    key_package: Option<KeyPackage>,
}

impl DkgParticipant {
    fn new(
        id: u32,
        threshold: u32,
        dkg_ctx: &str,
        other_ids: Vec<u32>,
    ) -> Result<Self, FrostError> {
        let threshold = u16::try_from(threshold)?;
        let max_signers = u16::try_from(
            other_ids
                .len()
                .checked_add(1)
                .ok_or(kryptology::KryptologyError::InvalidSignerCount)
                .map_err(FrostError::NewParticipant)?,
        )
        .map_err(|_| FrostError::NewParticipant(kryptology::KryptologyError::InvalidSignerCount))?;
        validate_participant_inputs(id, threshold, max_signers)
            .map_err(FrostError::NewParticipant)?;

        Ok(Self {
            id,
            round: 1,
            threshold,
            max_signers,
            other_ids,
            ctx: dkg_context_byte(dkg_ctx),
            round1_secret: None,
            key_package: None,
        })
    }

    fn round1(&mut self) -> Result<(Round1Bcast, BTreeMap<u32, ShamirShare>), FrostError> {
        if self.round != 1 {
            return Err(FrostError::InvalidRound {
                expected: 1,
                current: self.round,
            });
        }
        if self.round1_secret.is_some() || self.key_package.is_some() {
            return Err(FrostError::MissingRoundState);
        }
        let mut rng = rand::rngs::OsRng;
        let (cast, shares, secret) = kryptology::round1(
            self.id,
            self.threshold,
            self.max_signers,
            self.ctx,
            &mut rng,
        )
        .map_err(FrostError::ExecRound1)?;
        self.round1_secret = Some(secret);

        let shares = self
            .other_ids
            .iter()
            .map(|id| {
                shares
                    .get(id)
                    .cloned()
                    .map(|share| (*id, share))
                    .ok_or(FrostError::MissingRoundState)
            })
            .collect::<Result<_, _>>()?;
        self.round = 2;

        Ok((cast, shares))
    }

    fn round2(
        &mut self,
        bcasts: &BTreeMap<u32, Round1Bcast>,
        shares: &BTreeMap<u32, ShamirShare>,
    ) -> Result<Round2Bcast, FrostError> {
        if self.round != 2 {
            return Err(FrostError::InvalidRound {
                expected: 2,
                current: self.round,
            });
        }
        if self.round1_secret.is_none() || self.key_package.is_some() {
            return Err(FrostError::MissingRoundState);
        }
        let secret = self
            .round1_secret
            .take()
            .ok_or(FrostError::MissingRoundState)?;
        // get_round2_inputs keeps this node's broadcast. Strip it here to
        // match Charon's participant behavior; kryptology::round2 rejects self IDs.
        let bcasts = bcasts
            .iter()
            .filter(|(id, _)| **id != self.id)
            .map(|(id, bcast)| (*id, bcast.clone()))
            .collect();
        let shares = shares
            .iter()
            .filter(|(id, _)| **id != self.id)
            .map(|(id, share)| (*id, share.clone()))
            .collect();
        let (cast, key_package, _public_key_package) =
            kryptology::round2(secret, &bcasts, &shares).map_err(FrostError::ExecRound2)?;
        self.key_package = Some(key_package);
        self.round = 3;

        Ok(cast)
    }
}

/// Runs `num_validators` Frost DKG processes in parallel (sharing transport
/// rounds) and returns a list of shares (one for each distributed validator).
pub(crate) async fn run_frost_parallel<T: FTransport>(
    cancellation: CancellationToken,
    tp: &mut T,
    num_validators: u32,
    num_nodes: u32,
    threshold: u32,
    share_idx: u32,
    dkg_ctx: &str,
) -> Result<Vec<Share>, FrostError> {
    debug!(
        num_validators,
        num_nodes, threshold, share_idx, "Starting FROST DKG"
    );
    let mut validators =
        new_frost_participants(num_validators, num_nodes, threshold, share_idx, dkg_ctx)?;

    let (cast_r1, p2p_r1) = round1(&mut validators)?;
    debug!(
        bcasts = cast_r1.len(),
        p2p = p2p_r1.len(),
        "Completed local FROST DKG round 1"
    );
    let (cast_r1_result, p2p_r1_result) = tp.round1(&cancellation, cast_r1, p2p_r1).await?;
    debug!(
        bcasts = cast_r1_result.len(),
        p2p = p2p_r1_result.len(),
        "Completed FROST DKG round 1 transport"
    );

    let cast_r2 = round2(&mut validators, &cast_r1_result, &p2p_r1_result)?;
    debug!(bcasts = cast_r2.len(), "Completed local FROST DKG round 2");
    let cast_r2_result = tp.round2(&cancellation, cast_r2).await?;
    debug!(
        bcasts = cast_r2_result.len(),
        "Completed FROST DKG round 2 transport"
    );

    let shares = make_shares(&validators, &cast_r2_result)?;
    debug!(shares = shares.len(), "Completed FROST DKG");

    Ok(shares)
}

/// Returns multiple frost DKG participants (one for each parallel validator).
fn new_frost_participants(
    num_validators: u32,
    num_nodes: u32,
    threshold: u32,
    share_idx: u32,
    dkg_ctx: &str,
) -> Result<BTreeMap<u32, DkgParticipant>, FrostError> {
    let other_ids = other_ids(num_nodes, share_idx);
    let mut participants = BTreeMap::new();

    for v_idx in 0..num_validators {
        participants.insert(
            v_idx,
            DkgParticipant::new(share_idx, threshold, dkg_ctx, other_ids.clone())?,
        );
    }

    Ok(participants)
}

fn other_ids(num_nodes: u32, share_idx: u32) -> Vec<u32> {
    (1..=num_nodes).filter(|id| *id != share_idx).collect()
}

/// Executes round 1 for each validator and returns all round 1
/// broadcast and p2p messages for all validators.
fn round1(validators: &mut BTreeMap<u32, DkgParticipant>) -> Result<Round1Output, FrostError> {
    let mut cast_results = HashMap::new();
    let mut p2p_results = HashMap::new();

    for (&v_idx, validator) in validators {
        let (cast, p2p) = validator.round1()?;
        cast_results.insert(
            MsgKey {
                val_idx: v_idx,
                source_id: validator.id,
                target_id: 0, // Broadcast
            },
            cast,
        );

        for (target_id, shamir_share) in p2p {
            p2p_results.insert(
                MsgKey {
                    val_idx: v_idx,
                    source_id: validator.id,
                    target_id,
                },
                shamir_share,
            );
        }
    }

    Ok((cast_results, p2p_results))
}

/// Executes round 2 for each validator and returns all round 2
/// broadcast messages for all validators.
fn round2(
    validators: &mut BTreeMap<u32, DkgParticipant>,
    cast_r1: &HashMap<MsgKey, Round1Bcast>,
    p2p_r1: &HashMap<MsgKey, ShamirShare>,
) -> Result<HashMap<MsgKey, Round2Bcast>, FrostError> {
    let mut cast_results = HashMap::new();

    for (&v_idx, validator) in validators {
        let (casts, shares) = get_round2_inputs(cast_r1, p2p_r1, v_idx);
        let cast_r2 = validator.round2(&casts, &shares)?;
        cast_results.insert(
            MsgKey {
                val_idx: v_idx,
                source_id: validator.id,
                target_id: 0, // Broadcast
            },
            cast_r2,
        );
    }

    Ok(cast_results)
}

/// Returns the round 2 inputs of the `v_idx`th validator.
fn get_round2_inputs(
    cast_r1: &HashMap<MsgKey, Round1Bcast>,
    p2p_r1: &HashMap<MsgKey, ShamirShare>,
    v_idx: u32,
) -> (BTreeMap<u32, Round1Bcast>, BTreeMap<u32, ShamirShare>) {
    let cast_map = cast_r1
        .iter()
        .filter(|(key, _)| key.val_idx == v_idx)
        .map(|(key, cast)| (key.source_id, cast.clone()))
        .collect();
    let share_map = p2p_r1
        .iter()
        .filter(|(key, _)| key.val_idx == v_idx)
        .map(|(key, share)| (key.source_id, share.clone()))
        .collect();

    (cast_map, share_map)
}

/// Returns a slice of shares (one for each validator) from the DKG participants
/// and round 2 results.
fn make_shares(
    validators: &BTreeMap<u32, DkgParticipant>,
    r2_result: &HashMap<MsgKey, Round2Bcast>,
) -> Result<Vec<Share>, FrostError> {
    // Get set of public shares for each validator.
    let pub_shares = r2_result.iter().try_fold(
        BTreeMap::<u32, HashMap<u64, PublicKey>>::new(),
        |mut pub_shares, (key, result)| {
            let pub_share = point_to_pubkey(result.vk_share)?;
            pub_shares
                .entry(key.val_idx)
                .or_default()
                .insert(u64::from(key.source_id), pub_share);
            Ok::<_, FrostError>(pub_shares)
        },
    )?;

    // Construct DKG result shares.
    let mut shares = Vec::with_capacity(validators.len());
    for (&v_idx, validator) in validators {
        let key_package = validator
            .key_package
            .as_ref()
            .ok_or(FrostError::MissingRoundState)?;
        let pub_key = key_package.verifying_key().to_element();
        let secret_share = key_package.signing_share().to_scalar();

        shares.push(Share {
            pub_key: point_to_pubkey(G1Affine::from(pub_key).to_compressed())?,
            secret_share: privkey_from_bytes(&kryptology::scalar_to_be(&secret_share))?,
            public_shares: pub_shares.get(&v_idx).cloned().unwrap_or_default(),
        });
    }

    Ok(shares)
}

fn point_to_pubkey(point: [u8; 48]) -> Result<PublicKey, FrostError> {
    // `pubkey_from_bytes` only checks length; transport bytes still need G1
    // validation.
    G1Projective::from_compressed(&point).ok_or(FrostError::InvalidPublicKeyPoint)?;
    Ok(pubkey_from_bytes(&point)?)
}

fn validate_participant_inputs(
    id: u32,
    threshold: u16,
    max_signers: u16,
) -> Result<(), pluto_frost::kryptology::KryptologyError> {
    if max_signers > u16::from(u8::MAX) {
        return Err(kryptology::KryptologyError::InvalidSignerCount);
    }
    validate_num_of_signers(threshold, max_signers)?;
    if id == 0 || id > u32::from(max_signers) {
        return Err(kryptology::KryptologyError::InvalidParticipantId(id));
    }

    Ok(())
}

fn dkg_context_byte(dkg_ctx: &str) -> u8 {
    // Match Charon's strconv.Atoi(ctx) with ignored errors. Production passes a
    // hex definition hash ("0x..."), so this intentionally becomes 0.
    dkg_ctx
        .parse::<isize>()
        .map(|value| value.to_le_bytes()[0])
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls, types::Index};
    use tokio::sync::{Mutex, Notify};

    use super::*;

    struct FrostMemTransport {
        nodes: usize,
        inner: Mutex<FrostMemTransportInner>,
        notify: Notify,
    }

    #[derive(Default)]
    struct FrostMemTransportInner {
        round1: usize,
        round1_bcast: HashMap<MsgKey, Round1Bcast>,
        round1_shares: HashMap<u32, HashMap<MsgKey, ShamirShare>>,
        round2: usize,
        round2_bcast: HashMap<MsgKey, Round2Bcast>,
    }

    impl FrostMemTransport {
        fn new(nodes: usize) -> Self {
            Self {
                nodes,
                inner: Mutex::new(FrostMemTransportInner::default()),
                notify: Notify::new(),
            }
        }
    }

    #[async_trait]
    impl FTransport for Arc<FrostMemTransport> {
        async fn round1(
            &mut self,
            cancellation: &CancellationToken,
            bcast: HashMap<MsgKey, Round1Bcast>,
            shares: HashMap<MsgKey, ShamirShare>,
        ) -> Result<Round1Output, FrostError> {
            let source_id = bcast
                .keys()
                .next()
                .map(|key| key.source_id)
                .ok_or(FrostError::MissingRoundState)?;
            debug_assert!(bcast.keys().all(|key| key.source_id == source_id));

            {
                let mut inner = self.inner.lock().await;
                if inner.round1 == self.nodes {
                    inner.round1 = 0;
                    inner.round1_bcast.clear();
                    inner.round1_shares.clear();
                }
                for (key, round1_bcast) in bcast {
                    inner.round1_bcast.insert(
                        MsgKey {
                            val_idx: key.val_idx,
                            source_id: key.source_id,
                            target_id: 0,
                        },
                        round1_bcast,
                    );
                }
                for (key, share) in shares {
                    inner
                        .round1_shares
                        .entry(key.target_id)
                        .or_default()
                        .insert(key, share);
                }
                inner.round1 = inner
                    .round1
                    .checked_add(1)
                    .expect("test round counter should not overflow");
            }
            self.notify.notify_waiters();

            loop {
                let notified = self.notify.notified();
                {
                    let inner = self.inner.lock().await;
                    if inner.round1 == self.nodes {
                        return Ok((
                            inner.round1_bcast.clone(),
                            inner
                                .round1_shares
                                .get(&source_id)
                                .cloned()
                                .unwrap_or_default(),
                        ));
                    }
                }

                tokio::select! {
                    _ = cancellation.cancelled() => return Err(FrostError::Cancelled),
                    _ = notified => {}
                }
            }
        }

        async fn round2(
            &mut self,
            cancellation: &CancellationToken,
            bcast: HashMap<MsgKey, Round2Bcast>,
        ) -> Result<HashMap<MsgKey, Round2Bcast>, FrostError> {
            {
                let mut inner = self.inner.lock().await;
                if inner.round2 == self.nodes {
                    inner.round2 = 0;
                    inner.round2_bcast.clear();
                }
                for (key, round2_bcast) in bcast {
                    inner.round2_bcast.insert(
                        MsgKey {
                            val_idx: key.val_idx,
                            source_id: key.source_id,
                            target_id: 0,
                        },
                        round2_bcast,
                    );
                }
                inner.round2 = inner
                    .round2
                    .checked_add(1)
                    .expect("test round counter should not overflow");
            }
            self.notify.notify_waiters();

            loop {
                let notified = self.notify.notified();
                {
                    let inner = self.inner.lock().await;
                    if inner.round2 == self.nodes {
                        return Ok(inner.round2_bcast.clone());
                    }
                }

                tokio::select! {
                    _ = cancellation.cancelled() => return Err(FrostError::Cancelled),
                    _ = notified => {}
                }
            }
        }
    }

    #[tokio::test]
    async fn frost_dkg() {
        const NODES: u32 = 3;
        const THRESHOLD: u32 = 3;
        const VALS: u32 = 2;

        let node_shares = run_mem_dkg(NODES, THRESHOLD, VALS).await;
        verify_returned_shares(
            &node_shares,
            usize::try_from(THRESHOLD).expect("threshold should fit"),
        );
    }

    #[tokio::test]
    async fn frost_dkg_partial_quorum() {
        const NODES: u32 = 3;
        const THRESHOLD: u32 = 2;
        const VALS: u32 = 2;

        let node_shares = run_mem_dkg(NODES, THRESHOLD, VALS).await;
        verify_returned_shares(
            &node_shares,
            usize::try_from(THRESHOLD).expect("threshold should fit"),
        );
    }

    async fn run_mem_dkg(nodes: u32, threshold: u32, vals: u32) -> Vec<Vec<Share>> {
        let cancellation = CancellationToken::new();
        let tp = Arc::new(FrostMemTransport::new(
            usize::try_from(nodes).expect("nodes should fit"),
        ));

        let mut tasks = Vec::new();
        for i in 0..nodes {
            let mut tp = Arc::clone(&tp);
            let cancellation = cancellation.clone();
            tasks.push(tokio::spawn(async move {
                run_frost_parallel(
                    cancellation,
                    &mut tp,
                    vals,
                    nodes,
                    threshold,
                    i.checked_add(1).expect("share index should not overflow"),
                    "0",
                )
                .await
            }));
        }

        let mut node_shares = Vec::new();
        for task in tasks {
            let shares = task
                .await
                .expect("task should not panic")
                .expect("DKG should run");
            assert_eq!(
                shares.len(),
                usize::try_from(vals).expect("vals should fit")
            );
            node_shares.push(shares);
        }

        node_shares
    }

    #[tokio::test]
    async fn transport_returns_cancelled_while_waiting() {
        let cancellation = CancellationToken::new();
        let tp = Arc::new(FrostMemTransport::new(2));

        let task = {
            let mut tp = Arc::clone(&tp);
            let cancellation = cancellation.clone();
            tokio::spawn(
                async move { run_frost_parallel(cancellation, &mut tp, 1, 2, 2, 1, "0").await },
            )
        };

        tokio::task::yield_now().await;
        cancellation.cancel();

        let err = task
            .await
            .expect("task should not panic")
            .expect_err("DKG should be cancelled");
        assert!(matches!(err, FrostError::Cancelled));
    }

    #[test]
    fn round1_emits_expected_msg_key_layout() {
        let mut validators =
            new_frost_participants(2, 3, 3, 2, "0").expect("participants should build");

        let (casts, shares) = round1(&mut validators).expect("round1 should run");

        assert_eq!(casts.len(), 2);
        assert!(
            casts
                .keys()
                .all(|key| key.source_id == 2 && key.target_id == 0)
        );
        assert_eq!(shares.len(), 4);
        assert!(shares.keys().all(|key| key.source_id == 2));
        let mut share_keys = shares
            .keys()
            .map(|key| (key.val_idx, key.target_id))
            .collect::<Vec<_>>();
        share_keys.sort_unstable();
        assert_eq!(share_keys, vec![(0, 1), (0, 3), (1, 1), (1, 3)]);
    }

    #[test]
    fn participant_rejects_repeated_round1() {
        let mut validator =
            DkgParticipant::new(1, 2, "0", vec![2, 3]).expect("participant should build");

        validator.round1().expect("round1 should run");
        assert!(matches!(
            validator.round1(),
            Err(FrostError::InvalidRound {
                expected: 1,
                current: 2
            })
        ));
    }

    #[test]
    fn participant_rejects_round1_with_existing_secret() {
        let mut source =
            DkgParticipant::new(1, 2, "0", vec![2, 3]).expect("participant should build");
        let (_, _, secret) = kryptology::round1(1, 2, 3, 0, &mut rand::rngs::OsRng)
            .expect("round1 should produce a secret");
        source.round1_secret = Some(secret);

        assert!(matches!(
            source.round1(),
            Err(FrostError::MissingRoundState)
        ));
    }

    #[test]
    fn participant_rejects_round2_before_round1() {
        let mut validator =
            DkgParticipant::new(1, 2, "0", vec![2, 3]).expect("participant should build");

        assert!(matches!(
            validator.round2(&BTreeMap::new(), &BTreeMap::new()),
            Err(FrostError::InvalidRound {
                expected: 2,
                current: 1
            })
        ));
    }

    #[test]
    fn participant_rejects_round2_with_existing_key_package() {
        let mut node1 = new_frost_participants(1, 3, 2, 1, "0").expect("participants should build");
        let (mut casts, _) = round1(&mut node1).expect("round1 should run");
        let mut shares = HashMap::new();
        for share_idx in 2..=3 {
            let mut validators =
                new_frost_participants(1, 3, 2, share_idx, "0").expect("participants should build");
            let (node_casts, node_shares) = round1(&mut validators).expect("round1 should run");
            casts.extend(node_casts);
            shares.extend(
                node_shares
                    .into_iter()
                    .filter(|(key, _)| key.target_id == 1),
            );
        }
        let (v0_casts, v0_shares) = get_round2_inputs(&casts, &shares, 0);
        let validator = node1.get_mut(&0).expect("validator should exist");
        validator
            .round2(&v0_casts, &v0_shares)
            .expect("round2 should run");
        validator.round = 2;
        let (_, _, secret) = kryptology::round1(1, 2, 3, 0, &mut rand::rngs::OsRng)
            .expect("round1 should produce a secret");
        validator.round1_secret = Some(secret);

        assert!(matches!(
            validator.round2(&v0_casts, &v0_shares),
            Err(FrostError::MissingRoundState)
        ));
    }

    #[test]
    fn participant_rejects_repeated_round2() {
        let mut node1 = new_frost_participants(1, 3, 2, 1, "0").expect("participants should build");
        let (mut casts, _) = round1(&mut node1).expect("round1 should run");
        let mut shares = HashMap::new();
        for share_idx in 2..=3 {
            let mut validators =
                new_frost_participants(1, 3, 2, share_idx, "0").expect("participants should build");
            let (node_casts, node_shares) = round1(&mut validators).expect("round1 should run");
            casts.extend(node_casts);
            shares.extend(
                node_shares
                    .into_iter()
                    .filter(|(key, _)| key.target_id == 1),
            );
        }
        let (v0_casts, v0_shares) = get_round2_inputs(&casts, &shares, 0);
        let validator = node1.get_mut(&0).expect("validator should exist");

        validator
            .round2(&v0_casts, &v0_shares)
            .expect("round2 should run");
        assert!(matches!(
            validator.round2(&v0_casts, &v0_shares),
            Err(FrostError::InvalidRound {
                expected: 2,
                current: 3
            })
        ));
    }

    #[test]
    fn dkg_context_byte_defaults_invalid_context_to_zero() {
        assert_eq!(dkg_context_byte("test context"), 0);
        assert_eq!(dkg_context_byte("0x1234"), 0);
        assert_eq!(dkg_context_byte("0"), 0);
        assert_eq!(dkg_context_byte("1"), 1);
        assert_eq!(dkg_context_byte("257"), 1);
        assert_eq!(dkg_context_byte("-1"), 255);
    }

    #[test]
    fn point_to_pubkey_rejects_invalid_compressed_point() {
        let invalid_but_correct_length = [42u8; 48];

        assert!(matches!(
            point_to_pubkey(invalid_but_correct_length),
            Err(FrostError::InvalidPublicKeyPoint)
        ));
    }

    #[test]
    fn get_round2_inputs_filters_by_validator_index() {
        let mut casts = HashMap::new();
        let mut shares = HashMap::new();

        for share_idx in 2..=3 {
            let mut validators =
                new_frost_participants(2, 3, 3, share_idx, "0").expect("participants should build");
            let (node_casts, node_shares) = round1(&mut validators).expect("round1 should run");
            casts.extend(node_casts);
            shares.extend(
                node_shares
                    .into_iter()
                    .filter(|(key, _)| key.target_id == 1),
            );
        }

        let (v0_casts, v0_shares) = get_round2_inputs(&casts, &shares, 0);
        let (v1_casts, v1_shares) = get_round2_inputs(&casts, &shares, 1);

        assert_eq!(v0_casts.keys().copied().collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(v0_shares.keys().copied().collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(v1_casts.keys().copied().collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(v1_shares.keys().copied().collect::<Vec<_>>(), vec![2, 3]);
        assert_ne!(v0_casts, v1_casts);
    }

    #[tokio::test]
    async fn make_shares_sorts_by_validator_index_and_maps_public_shares() {
        let cancellation = CancellationToken::new();
        let tp = Arc::new(FrostMemTransport::new(3));
        let mut tasks = Vec::new();

        for share_idx in 1..=3 {
            let mut tp = Arc::clone(&tp);
            let cancellation = cancellation.clone();
            tasks.push(tokio::spawn(async move {
                run_frost_parallel(cancellation, &mut tp, 3, 3, 3, share_idx, "0").await
            }));
        }

        let mut node_shares = Vec::new();
        for task in tasks {
            node_shares.push(
                task.await
                    .expect("task should not panic")
                    .expect("DKG should run"),
            );
        }

        assert_eq!(node_shares.len(), 3);
        for shares in node_shares {
            assert_eq!(shares.len(), 3);
            for share in shares {
                let mut share_ids = share.public_shares.keys().copied().collect::<Vec<_>>();
                share_ids.sort_unstable();
                assert_eq!(share_ids, vec![1, 2, 3]);
            }
        }
    }

    fn verify_returned_shares(node_shares: &[Vec<Share>], threshold: usize) {
        let msg = b"frost dkg parity test";
        let validator_count = node_shares
            .first()
            .expect("there should be node shares")
            .len();

        for val_idx in 0..validator_count {
            let pub_key = node_shares[0][val_idx].pub_key;
            let mut partials = HashMap::new();
            for (node_idx, shares) in node_shares.iter().take(threshold).enumerate() {
                assert_eq!(shares[val_idx].pub_key, pub_key);
                let share_id = Index::try_from(
                    node_idx
                        .checked_add(1)
                        .expect("node index should not overflow"),
                )
                .expect("node index should fit in Index");
                let sig = BlstImpl
                    .sign(&shares[val_idx].secret_share, msg)
                    .expect("partial signature should succeed");
                partials.insert(share_id, sig);
            }

            let sig = BlstImpl
                .threshold_aggregate(&partials)
                .expect("threshold aggregation should succeed");
            BlstImpl
                .verify(&pub_key, msg, &sig)
                .expect("aggregated signature should verify");
        }
    }
}
