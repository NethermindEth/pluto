//! FROST DKG orchestration and P2P transport.
//!
//! [`run_frost_parallel`] runs `num_validators` FROST DKG ceremonies in
//! parallel, sharing the two broadcast rounds.  It is the Rust equivalent of
//! Charon's `runFrostParallel` + `frostP2P` (charon/dkg/frost.go:50,
//! charon/dkg/frostp2p.go:40).

use std::collections::{BTreeMap, HashMap};

use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls};
use pluto_frost::{
    G1Affine,
    kryptology::{self, Round1Bcast, Round1Secret, Round2Bcast, ShamirShare, scalar_to_be},
};
use pluto_p2p::peer::Peer;
use prost::bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    bcast::Component as BcastComponent,
    dkgpb::v1::frost::{
        FrostMsgKey, FrostRound1Cast, FrostRound1Casts, FrostRound1P2p, FrostRound1ShamirShare,
        FrostRound2Cast, FrostRound2Casts,
    },
    frostp2p::FrostP2PHandle,
    share::Share,
};

/// bcast message ID for FROST round-1 broadcast.  Must match Charon.
pub const ROUND1_CAST_ID: &str = "/charon/dkg/frost/2.0.0/round1/cast";
/// bcast message ID for FROST round-2 broadcast.  Must match Charon.
pub const ROUND2_CAST_ID: &str = "/charon/dkg/frost/2.0.0/round2/cast";

/// Identifies source, target, and validator for a FROST wire message.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct MsgKey {
    /// Distributed-validator index (0-indexed).
    pub val_idx: u32,
    /// Sending participant share index (1-indexed).
    pub source_id: u32,
    /// Receiving participant share index (1-indexed); 0 = broadcast.
    pub target_id: u32,
}

/// Errors from the FROST ceremony.
#[derive(Debug, thiserror::Error)]
pub enum FrostError {
    /// Kryptology FROST DKG algorithm failed.
    #[error("kryptology DKG error: {0:?}")]
    Kryptology(pluto_frost::kryptology::DkgError),
    /// Broadcast component error.
    #[error("bcast error: {0}")]
    Bcast(#[from] crate::bcast::Error),
    /// DKG was cancelled externally.
    #[error("DKG cancelled")]
    Cancelled,
    /// Proto message could not be decoded.
    #[error("proto decode error: {0}")]
    ProtoDecode(String),
    /// A protobuf message key field was absent.
    #[error("missing message key")]
    MissingKey,
    /// A numeric value was out of its valid range.
    #[error("value out of range")]
    Overflow,
    /// Neither secret-share byte encoding matched the FROST verifying share.
    #[error("failed to encode secret share for BLST signing")]
    SecretShareEncoding,
}

impl From<pluto_frost::kryptology::DkgError> for FrostError {
    fn from(e: pluto_frost::kryptology::DkgError) -> Self {
        FrostError::Kryptology(e)
    }
}

// ── FrostP2P transport ──────────────────────────────────────────────────────

/// P2P transport for FROST rounds: channels and bcast handles.
///
/// Created via [`new_frost_p2p`] which also registers bcast callbacks.
pub struct FrostP2P {
    bcast_comp: BcastComponent,
    frost_handle: FrostP2PHandle,
    round1_casts_tx: mpsc::UnboundedSender<FrostRound1Casts>,
    round1_casts_rx: mpsc::UnboundedReceiver<FrostRound1Casts>,
    round2_casts_tx: mpsc::UnboundedSender<FrostRound2Casts>,
    round2_casts_rx: mpsc::UnboundedReceiver<FrostRound2Casts>,
    /// share_idx (1-indexed) → PeerId (excludes self).
    peers_by_share_idx: HashMap<u32, libp2p::PeerId>,
    num_peers: usize,
}

/// Creates a [`FrostP2P`] and registers its bcast callbacks.
///
/// `peers` is in definition order (0-indexed), so share_idx = i + 1.
pub async fn new_frost_p2p(
    bcast_comp: BcastComponent,
    frost_handle: FrostP2PHandle,
    peers: &[Peer],
    local_share_idx: u32,
) -> Result<FrostP2P, FrostError> {
    let (round1_casts_tx, round1_casts_rx) = mpsc::unbounded_channel();
    let (round2_casts_tx, round2_casts_rx) = mpsc::unbounded_channel();

    let mut peers_by_share_idx: HashMap<u32, libp2p::PeerId> = HashMap::new();
    for (i, peer) in peers.iter().enumerate() {
        let share_idx = u32::try_from(i.checked_add(1).ok_or(FrostError::Overflow)?)
            .map_err(|_| FrostError::Overflow)?;
        if share_idx != local_share_idx {
            peers_by_share_idx.insert(share_idx, peer.id);
        }
    }

    // Register round-1 cast callback.
    {
        let tx = round1_casts_tx.clone();
        bcast_comp
            .register_message::<FrostRound1Casts>(
                ROUND1_CAST_ID,
                Box::new(|_peer_id, _msg| Ok(())),
                Box::new(move |peer_id, _msg_id, msg| {
                    let tx = tx.clone();
                    Box::pin(async move {
                        debug!(%peer_id, "Frost: received round1 cast");
                        let _ = tx.send(msg);
                        Ok(())
                    })
                }),
            )
            .await?;
    }

    // Register round-2 cast callback.
    {
        let tx = round2_casts_tx.clone();
        bcast_comp
            .register_message::<FrostRound2Casts>(
                ROUND2_CAST_ID,
                Box::new(|_peer_id, _msg| Ok(())),
                Box::new(move |peer_id, _msg_id, msg| {
                    let tx = tx.clone();
                    Box::pin(async move {
                        debug!(%peer_id, "Frost: received round2 cast");
                        let _ = tx.send(msg);
                        Ok(())
                    })
                }),
            )
            .await?;
    }

    Ok(FrostP2P {
        bcast_comp,
        frost_handle,
        round1_casts_tx,
        round1_casts_rx,
        round2_casts_tx,
        round2_casts_rx,
        peers_by_share_idx,
        num_peers: peers.len(),
    })
}

impl FrostP2P {
    /// Broadcasts own round-1 casts, sends P2P Shamir shares, and waits for
    /// all peers' casts and shares.
    pub async fn round1(
        &mut self,
        ct: &CancellationToken,
        cast_r1: &HashMap<MsgKey, Round1Bcast>,
        p2p_r1: &HashMap<MsgKey, ShamirShare>,
    ) -> Result<(HashMap<MsgKey, Round1Bcast>, HashMap<MsgKey, ShamirShare>), FrostError> {
        let casts_msg = build_round1_casts(cast_r1);
        self.bcast_comp
            .broadcast(ROUND1_CAST_ID, &casts_msg)
            .await?;
        let _ = self.round1_casts_tx.send(casts_msg); // self-inject

        // Group Shamir shares by target peer and send directly.
        let mut p2p_by_target: HashMap<u32, Vec<FrostRound1ShamirShare>> = HashMap::new();
        for (key, share) in p2p_r1 {
            p2p_by_target
                .entry(key.target_id)
                .or_default()
                .push(shamir_share_to_proto(*key, share));
        }
        for (target_share_idx, share_protos) in &p2p_by_target {
            let peer_id = self
                .peers_by_share_idx
                .get(target_share_idx)
                .copied()
                .ok_or(FrostError::Overflow)?;
            self.frost_handle.send(
                peer_id,
                &FrostRound1P2p {
                    shares: share_protos.clone(),
                },
            );
        }

        // Collect from peers until we have all round-1 data.
        let num_peers = self.num_peers;
        let mut cast_msgs: Vec<FrostRound1Casts> = Vec::with_capacity(num_peers);
        let mut p2p_msgs: Vec<FrostRound1P2p> = Vec::with_capacity(num_peers.saturating_sub(1));

        loop {
            if cast_msgs.len() == num_peers && p2p_msgs.len() == num_peers.saturating_sub(1) {
                break;
            }
            tokio::select! {
                _ = ct.cancelled() => return Err(FrostError::Cancelled),
                Some(msg) = self.round1_casts_rx.recv() => {
                    if cast_msgs.len() < num_peers {
                        cast_msgs.push(msg);
                    } else {
                        warn!("Frost: discarding extra round1 cast");
                    }
                }
                Some((_peer_id, msg)) = self.frost_handle.inbound_rx.recv() => {
                    if p2p_msgs.len() < num_peers.saturating_sub(1) {
                        p2p_msgs.push(msg);
                    } else {
                        warn!("Frost: discarding extra round1 p2p");
                    }
                }
            }
        }

        make_round1_response(cast_msgs, p2p_msgs)
    }

    /// Broadcasts own round-2 casts and waits for all peers' casts.
    pub async fn round2(
        &mut self,
        ct: &CancellationToken,
        cast_r2: &HashMap<MsgKey, Round2Bcast>,
    ) -> Result<HashMap<MsgKey, Round2Bcast>, FrostError> {
        let casts_msg = build_round2_casts(cast_r2);
        self.bcast_comp
            .broadcast(ROUND2_CAST_ID, &casts_msg)
            .await?;
        let _ = self.round2_casts_tx.send(casts_msg); // self-inject

        let num_peers = self.num_peers;
        let mut cast_msgs: Vec<FrostRound2Casts> = Vec::with_capacity(num_peers);
        loop {
            if cast_msgs.len() == num_peers {
                break;
            }
            tokio::select! {
                _ = ct.cancelled() => return Err(FrostError::Cancelled),
                Some(msg) = self.round2_casts_rx.recv() => {
                    cast_msgs.push(msg);
                }
            }
        }

        make_round2_response(cast_msgs)
    }
}

// ── run_frost_parallel ──────────────────────────────────────────────────────

/// Runs `num_validators` FROST DKG ceremonies in parallel and returns one
/// [`Share`] per distributed validator.
///
/// Reference: charon/dkg/frost.go:50 `runFrostParallel`.
pub async fn run_frost_parallel(
    ct: &CancellationToken,
    tp: &mut FrostP2P,
    num_validators: u32,
    num_nodes: u32,
    threshold: u32,
    share_idx: u32,
    dkg_ctx: &str,
) -> Result<Vec<Share>, FrostError> {
    let ctx_byte = kryptology_context_byte(dkg_ctx);
    let threshold_u16 = u16::try_from(threshold).map_err(|_| FrostError::Overflow)?;
    let max_signers_u16 = u16::try_from(num_nodes).map_err(|_| FrostError::Overflow)?;
    let mut rng = rand::rngs::OsRng;

    // ── Round 1 ──────────────────────────────────────────────────────────────

    let mut r1_bcasts: HashMap<MsgKey, Round1Bcast> = HashMap::new();
    let mut r1_p2p: HashMap<MsgKey, ShamirShare> = HashMap::new();
    let mut r1_secrets: Vec<Option<Round1Secret>> = (0..num_validators).map(|_| None).collect();

    for v_idx in 0..num_validators {
        let (bcast, shares, secret) = kryptology::round1(
            share_idx,
            threshold_u16,
            max_signers_u16,
            ctx_byte,
            &mut rng,
        )?;

        r1_bcasts.insert(
            MsgKey {
                val_idx: v_idx,
                source_id: share_idx,
                target_id: 0,
            },
            bcast,
        );

        for (target_id, shamir) in shares {
            r1_p2p.insert(
                MsgKey {
                    val_idx: v_idx,
                    source_id: share_idx,
                    target_id,
                },
                shamir,
            );
        }
        r1_secrets[v_idx as usize] = Some(secret);
    }

    debug!("Frost: sending round 1");
    let (r1_casts_result, r1_p2p_result) = tp.round1(ct, &r1_bcasts, &r1_p2p).await?;
    debug!("Frost: round 1 complete");

    // ── Round 2 ──────────────────────────────────────────────────────────────

    let mut r2_bcasts: HashMap<MsgKey, Round2Bcast> = HashMap::new();
    // val_idx → (KeyPackage, round2_bcast) for building Shares after collecting.
    let mut key_packages: HashMap<u32, pluto_frost::KeyPackage> = HashMap::new();

    for v_idx in 0..num_validators {
        let secret = r1_secrets[v_idx as usize]
            .take()
            .expect("secret populated above");

        let mut recv_bcasts: BTreeMap<u32, Round1Bcast> = BTreeMap::new();
        let mut recv_shares: BTreeMap<u32, ShamirShare> = BTreeMap::new();

        for (key, bcast) in &r1_casts_result {
            if key.val_idx == v_idx && key.source_id != share_idx {
                recv_bcasts.insert(key.source_id, bcast.clone());
            }
        }
        for (key, s) in &r1_p2p_result {
            if key.val_idx == v_idx {
                recv_shares.insert(key.source_id, s.clone());
            }
        }

        let (r2_bcast, key_pkg, _pub_pkg) = kryptology::round2(secret, &recv_bcasts, &recv_shares)?;

        r2_bcasts.insert(
            MsgKey {
                val_idx: v_idx,
                source_id: share_idx,
                target_id: 0,
            },
            r2_bcast,
        );
        key_packages.insert(v_idx, key_pkg);
    }

    debug!("Frost: sending round 2");
    let r2_result = tp.round2(ct, &r2_bcasts).await?;
    debug!("Frost: round 2 complete");

    // ── Build Shares ──────────────────────────────────────────────────────────

    // Collect public shares per validator: source_id → vk_share_bytes.
    let mut pub_shares_by_val: HashMap<u32, HashMap<u64, pluto_crypto::types::PublicKey>> =
        HashMap::new();
    for (key, r2_bcast) in &r2_result {
        let entry = pub_shares_by_val.entry(key.val_idx).or_default();
        let vk_bytes: pluto_crypto::types::PublicKey = r2_bcast.vk_share;
        entry.insert(u64::from(key.source_id), vk_bytes);
    }

    let mut shares = Vec::with_capacity(num_validators as usize);
    for v_idx in 0..num_validators {
        let key_pkg = key_packages
            .remove(&v_idx)
            .expect("key_package populated above");

        // Group verification key (compressed G1, 48 bytes).
        let pub_key: pluto_crypto::types::PublicKey =
            G1Affine::from(key_pkg.verifying_key().to_element()).to_compressed();

        let secret_share = encode_secret_share(&key_pkg)?;

        let public_shares = pub_shares_by_val.remove(&v_idx).unwrap_or_default();

        shares.push(Share {
            pub_key,
            secret_share,
            public_shares,
        });
    }

    Ok(shares)
}

fn encode_secret_share(
    key_pkg: &pluto_frost::KeyPackage,
) -> Result<pluto_crypto::types::PrivateKey, FrostError> {
    let scalar = key_pkg.signing_share().to_scalar();
    let expected_pubshare: pluto_crypto::types::PublicKey =
        G1Affine::from(key_pkg.verifying_share().to_element()).to_compressed();

    let candidates = [scalar_to_be(&scalar), scalar.to_bytes()];
    for candidate in candidates {
        if BlstImpl
            .secret_to_public_key(&candidate)
            .is_ok_and(|pubshare| pubshare == expected_pubshare)
        {
            return Ok(candidate);
        }
    }

    Err(FrostError::SecretShareEncoding)
}

fn kryptology_context_byte(dkg_ctx: &str) -> u8 {
    // Match Obol kryptology's `strconv.Atoi(ctx)` + `byte(ctxV)` behavior.
    // Invalid decimal strings (such as "0x<definition-hash>") become 0.
    dkg_ctx
        .parse::<i64>()
        .ok()
        .and_then(|value| u8::try_from(value.rem_euclid(256)).ok())
        .unwrap_or(0)
}

// ── Proto conversion helpers ────────────────────────────────────────────────

fn key_to_proto(key: MsgKey) -> FrostMsgKey {
    FrostMsgKey {
        val_idx: key.val_idx,
        source_id: key.source_id,
        target_id: key.target_id,
    }
}

fn key_from_proto(k: Option<&FrostMsgKey>) -> Result<MsgKey, FrostError> {
    let k = k.ok_or(FrostError::MissingKey)?;
    Ok(MsgKey {
        val_idx: k.val_idx,
        source_id: k.source_id,
        target_id: k.target_id,
    })
}

fn round1_cast_to_proto(key: MsgKey, cast: &Round1Bcast) -> FrostRound1Cast {
    FrostRound1Cast {
        key: Some(key_to_proto(key)),
        wi: Bytes::copy_from_slice(&cast.wi),
        ci: Bytes::copy_from_slice(&cast.ci),
        commitments: cast
            .commitments
            .iter()
            .map(|c| Bytes::copy_from_slice(c))
            .collect(),
    }
}

fn round1_cast_from_proto(cast: &FrostRound1Cast) -> Result<(MsgKey, Round1Bcast), FrostError> {
    let key = key_from_proto(cast.key.as_ref())?;
    let wi: [u8; 32] = cast
        .wi
        .as_ref()
        .try_into()
        .map_err(|_| FrostError::ProtoDecode("wi length".into()))?;
    let ci: [u8; 32] = cast
        .ci
        .as_ref()
        .try_into()
        .map_err(|_| FrostError::ProtoDecode("ci length".into()))?;
    let commitments: Result<Vec<[u8; 48]>, _> = cast
        .commitments
        .iter()
        .map(|c| <[u8; 48]>::try_from(c.as_ref()))
        .collect();
    let commitments =
        commitments.map_err(|_| FrostError::ProtoDecode("commitment length".into()))?;
    Ok((
        key,
        Round1Bcast {
            wi,
            ci,
            commitments,
        },
    ))
}

fn shamir_share_to_proto(key: MsgKey, share: &ShamirShare) -> FrostRound1ShamirShare {
    FrostRound1ShamirShare {
        key: Some(key_to_proto(key)),
        id: share.id,
        value: Bytes::copy_from_slice(&share.value),
    }
}

fn shamir_share_from_proto(
    share: &FrostRound1ShamirShare,
) -> Result<(MsgKey, ShamirShare), FrostError> {
    let key = key_from_proto(share.key.as_ref())?;
    let value: [u8; 32] = share
        .value
        .as_ref()
        .try_into()
        .map_err(|_| FrostError::ProtoDecode("shamir value length".into()))?;
    Ok((
        key,
        ShamirShare {
            id: share.id,
            value,
        },
    ))
}

fn round2_cast_to_proto(key: MsgKey, cast: &Round2Bcast) -> FrostRound2Cast {
    FrostRound2Cast {
        key: Some(key_to_proto(key)),
        verification_key: Bytes::copy_from_slice(&cast.verification_key),
        vk_share: Bytes::copy_from_slice(&cast.vk_share),
    }
}

fn round2_cast_from_proto(cast: &FrostRound2Cast) -> Result<(MsgKey, Round2Bcast), FrostError> {
    let key = key_from_proto(cast.key.as_ref())?;
    let verification_key: [u8; 48] = cast
        .verification_key
        .as_ref()
        .try_into()
        .map_err(|_| FrostError::ProtoDecode("verification_key length".into()))?;
    let vk_share: [u8; 48] = cast
        .vk_share
        .as_ref()
        .try_into()
        .map_err(|_| FrostError::ProtoDecode("vk_share length".into()))?;
    Ok((
        key,
        Round2Bcast {
            verification_key,
            vk_share,
        },
    ))
}

fn build_round1_casts(cast_r1: &HashMap<MsgKey, Round1Bcast>) -> FrostRound1Casts {
    FrostRound1Casts {
        casts: cast_r1
            .iter()
            .map(|(&key, cast)| round1_cast_to_proto(key, cast))
            .collect(),
    }
}

fn build_round2_casts(cast_r2: &HashMap<MsgKey, Round2Bcast>) -> FrostRound2Casts {
    FrostRound2Casts {
        casts: cast_r2
            .iter()
            .map(|(&key, cast)| round2_cast_to_proto(key, cast))
            .collect(),
    }
}

/// Maps keyed by [`MsgKey`] returned from round-1 collection.
type Round1Response = (HashMap<MsgKey, Round1Bcast>, HashMap<MsgKey, ShamirShare>);

fn make_round1_response(
    cast_msgs: Vec<FrostRound1Casts>,
    p2p_msgs: Vec<FrostRound1P2p>,
) -> Result<Round1Response, FrostError> {
    let mut cast_map = HashMap::new();
    let mut p2p_map = HashMap::new();

    for msg in &cast_msgs {
        for cast in &msg.casts {
            let (key, bcast) = round1_cast_from_proto(cast)?;
            cast_map.insert(key, bcast);
        }
    }
    for msg in &p2p_msgs {
        for share in &msg.shares {
            let (key, shamir) = shamir_share_from_proto(share)?;
            p2p_map.insert(key, shamir);
        }
    }

    Ok((cast_map, p2p_map))
}

fn make_round2_response(
    cast_msgs: Vec<FrostRound2Casts>,
) -> Result<HashMap<MsgKey, Round2Bcast>, FrostError> {
    let mut cast_map = HashMap::new();
    for msg in &cast_msgs {
        for cast in &msg.casts {
            let (key, bcast) = round2_cast_from_proto(cast)?;
            cast_map.insert(key, bcast);
        }
    }
    Ok(cast_map)
}

#[cfg(test)]
mod tests {
    use super::{encode_secret_share, kryptology_context_byte};
    use std::collections::BTreeMap;

    use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls};
    use pluto_frost::{G1Affine, kryptology};

    #[test]
    fn kryptology_context_byte_matches_go_atoi_semantics() {
        assert_eq!(kryptology_context_byte("0xdeadbeef"), 0);
        assert_eq!(kryptology_context_byte("48"), 48);
        assert_eq!(kryptology_context_byte("-1"), 255);
    }

    #[test]
    fn secret_share_encoding_matches_verifying_share() {
        let (_bcast_1, shares_1, secret_1) =
            kryptology::round1(1, 3, 4, 0, &mut rand::rngs::OsRng).expect("round1");
        let (bcast_2, shares_2, _secret_2) =
            kryptology::round1(2, 3, 4, 0, &mut rand::rngs::OsRng).expect("round1");
        let (bcast_3, shares_3, _secret_3) =
            kryptology::round1(3, 3, 4, 0, &mut rand::rngs::OsRng).expect("round1");
        let (bcast_4, shares_4, _secret_4) =
            kryptology::round1(4, 3, 4, 0, &mut rand::rngs::OsRng).expect("round1");

        let received_bcasts = BTreeMap::from([(2, bcast_2), (3, bcast_3), (4, bcast_4)]);
        let received_shares = BTreeMap::from([
            (2, shares_2.get(&1).expect("share").clone()),
            (3, shares_3.get(&1).expect("share").clone()),
            (4, shares_4.get(&1).expect("share").clone()),
        ]);
        let (_round2_bcast, key_pkg, _pub_pkg) =
            kryptology::round2(secret_1, &received_bcasts, &received_shares).expect("round2");

        let secret_share = encode_secret_share(&key_pkg).expect("secret share encoding");
        let pubshare = BlstImpl
            .secret_to_public_key(&secret_share)
            .expect("public share");
        let expected_pubshare =
            G1Affine::from(key_pkg.verifying_share().to_element()).to_compressed();

        assert_eq!(pubshare, expected_pubshare);
        drop(shares_1);
    }
}
