//! Bridges the async FROST `FTransport` API to libp2p direct P2P and the bcast
//! component.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use libp2p::PeerId;
use pluto_frost::kryptology::{Round1Bcast, Round2Bcast, ShamirShare};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use super::{
    FrostP2PEvent, FrostP2PHandle, FrostP2PSender, ROUND1_CAST_ID, ROUND2_CAST_ID,
    codec::{
        Round1Response, build_round1_casts, build_round2_casts, make_round1_response,
        make_round2_response, shamir_share_to_proto,
    },
};
use crate::{
    bcast,
    dkgpb::v1::frost::{FrostRound1Casts, FrostRound1P2p, FrostRound2Casts},
    frost::{FTransport, FrostError, MsgKey},
};

struct PeerShareIndices {
    peers_by_share_idx: HashMap<u32, PeerId>,
    share_idx_by_peer: HashMap<PeerId, u32>,
}

/// P2P transport for FROST rounds. Registers bcast callbacks on construction.
pub(crate) struct FrostP2P {
    bcast_comp: bcast::Component,
    frost_sender: FrostP2PSender,
    round1_casts_tx: mpsc::UnboundedSender<FrostRound1Casts>,
    round1_casts_rx: mpsc::UnboundedReceiver<FrostRound1Casts>,
    round1_p2p_rx: mpsc::UnboundedReceiver<(PeerId, FrostRound1P2p)>,
    round2_casts_tx: mpsc::UnboundedSender<FrostRound2Casts>,
    round2_casts_rx: mpsc::UnboundedReceiver<FrostRound2Casts>,
    peers_by_share_idx: HashMap<u32, PeerId>,
    local_share_idx: u32,
    num_peers: usize,
}

/// Creates a FROST P2P transport and registers its bcast callbacks.
///
/// The `frost_handle` must come from the
/// [`FrostP2PBehaviour`](super::FrostP2PBehaviour) installed in the same outer
/// network behaviour that owns `bcast_comp`.
pub(crate) async fn new_frost_p2p(
    bcast_comp: bcast::Component,
    frost_handle: &mut FrostP2PHandle,
    peers: &HashMap<PeerId, u32>,
    local_share_idx: u32,
    threshold: usize,
    num_validators: usize,
) -> Result<FrostP2P, FrostError> {
    let peer_share_indices = validate_peer_share_indices(peers, local_share_idx)?;

    let (round1_casts_tx, round1_casts_rx) = mpsc::unbounded_channel();
    let (round2_casts_tx, round2_casts_rx) = mpsc::unbounded_channel();
    let round1_p2p_rx = frost_handle.take_inbound_rx()?;

    register_round1_bcast(
        &bcast_comp,
        peer_share_indices.share_idx_by_peer.clone(),
        round1_casts_tx.clone(),
        threshold,
        num_validators,
    )
    .await?;
    register_round2_bcast(
        &bcast_comp,
        peer_share_indices.share_idx_by_peer.clone(),
        round2_casts_tx.clone(),
        num_validators,
    )
    .await?;

    Ok(FrostP2P {
        bcast_comp,
        frost_sender: frost_handle.sender.clone(),
        round1_casts_tx,
        round1_casts_rx,
        round1_p2p_rx,
        round2_casts_tx,
        round2_casts_rx,
        peers_by_share_idx: peer_share_indices.peers_by_share_idx,
        local_share_idx,
        num_peers: peers.len(),
    })
}

fn validate_peer_share_indices(
    peers: &HashMap<PeerId, u32>,
    local_share_idx: u32,
) -> Result<PeerShareIndices, FrostError> {
    let mut peers_by_share_idx = HashMap::new();
    let mut share_idx_by_peer = HashMap::new();

    for (&peer_id, &share_idx) in peers {
        if share_idx == 0 {
            return Err(FrostError::ConfigError(
                "frost peer share index cannot be zero",
            ));
        }
        if peers_by_share_idx.insert(share_idx, peer_id).is_some() {
            return Err(FrostError::ConfigError("duplicate frost peer share index"));
        }
        share_idx_by_peer.insert(peer_id, share_idx);
    }

    if !peers_by_share_idx.contains_key(&local_share_idx) {
        return Err(FrostError::ConfigError(
            "local frost share index missing from peer map",
        ));
    }

    Ok(PeerShareIndices {
        peers_by_share_idx,
        share_idx_by_peer,
    })
}

async fn register_round1_bcast(
    bcast_comp: &bcast::Component,
    share_idx_by_peer: HashMap<PeerId, u32>,
    tx: mpsc::UnboundedSender<FrostRound1Casts>,
    threshold: usize,
    num_validators: usize,
) -> Result<(), FrostError> {
    // Bcast dedup for this DKG run; create a fresh `FrostP2P` per DKG.
    let dedup = Arc::new(Mutex::new(HashSet::<PeerId>::new()));
    let share_idx_by_peer = Arc::new(share_idx_by_peer);
    let check_share_idx_by_peer = share_idx_by_peer.clone();
    bcast_comp
        .register_message::<FrostRound1Casts>(
            ROUND1_CAST_ID,
            Box::new(move |peer_id, msg| {
                validate_round1_casts(
                    peer_id,
                    &check_share_idx_by_peer,
                    threshold,
                    num_validators,
                    msg,
                )
            }),
            Box::new(move |peer_id, _, msg| {
                let tx = tx.clone();
                let dedup = dedup.clone();
                let share_idx_by_peer = share_idx_by_peer.clone();
                Box::pin(async move {
                    validate_round1_casts(
                        peer_id,
                        &share_idx_by_peer,
                        threshold,
                        num_validators,
                        &msg,
                    )?;
                    {
                        let mut dedup = dedup.lock().map_err(|_| bcast::Error::BehaviourClosed)?;
                        if !dedup.insert(peer_id) {
                            debug!(%peer_id, "ignoring duplicate round 1 message");
                            return Ok(());
                        }
                    }

                    tx.send(msg).map_err(|_| bcast::Error::BehaviourClosed)?;
                    Ok(())
                })
            }),
        )
        .await?;
    Ok(())
}

async fn register_round2_bcast(
    bcast_comp: &bcast::Component,
    share_idx_by_peer: HashMap<PeerId, u32>,
    tx: mpsc::UnboundedSender<FrostRound2Casts>,
    num_validators: usize,
) -> Result<(), FrostError> {
    // Bcast dedup for this DKG run; create a fresh `FrostP2P` per DKG.
    let dedup = Arc::new(Mutex::new(HashSet::<PeerId>::new()));
    let share_idx_by_peer = Arc::new(share_idx_by_peer);
    let check_share_idx_by_peer = share_idx_by_peer.clone();
    bcast_comp
        .register_message::<FrostRound2Casts>(
            ROUND2_CAST_ID,
            Box::new(move |peer_id, msg| {
                validate_round2_casts(peer_id, &check_share_idx_by_peer, num_validators, msg)
            }),
            Box::new(move |peer_id, _, msg| {
                let tx = tx.clone();
                let dedup = dedup.clone();
                let share_idx_by_peer = share_idx_by_peer.clone();
                Box::pin(async move {
                    validate_round2_casts(peer_id, &share_idx_by_peer, num_validators, &msg)?;
                    {
                        let mut dedup = dedup.lock().map_err(|_| bcast::Error::BehaviourClosed)?;
                        if !dedup.insert(peer_id) {
                            debug!(%peer_id, "ignoring duplicate round 2 message");
                            return Ok(());
                        }
                    }

                    tx.send(msg).map_err(|_| bcast::Error::BehaviourClosed)?;
                    Ok(())
                })
            }),
        )
        .await?;
    Ok(())
}

fn validate_round1_casts(
    peer_id: PeerId,
    share_idx_by_peer: &HashMap<PeerId, u32>,
    threshold: usize,
    num_validators: usize,
    msg: &FrostRound1Casts,
) -> Result<(), bcast::Error> {
    let source_id = *share_idx_by_peer
        .get(&peer_id)
        .ok_or(bcast::Error::InvalidPeerIndex(peer_id))?;
    // Stricter than Charon: reject malformed batches before point decoding.
    if msg.casts.len() != num_validators {
        return Err(bcast::Error::InvalidSignatureCount {
            expected: num_validators,
            actual: msg.casts.len(),
        });
    }
    let mut seen_validators = HashSet::with_capacity(msg.casts.len());
    for cast in &msg.casts {
        let Some(key) = cast.key.as_ref() else {
            return Err(bcast::Error::MissingField("key"));
        };
        if key.source_id != source_id {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        if key.target_id != 0 {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        let val_idx =
            usize::try_from(key.val_idx).map_err(|_| bcast::Error::InvalidPeerIndex(peer_id))?;
        if val_idx >= num_validators {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        if !seen_validators.insert(key.val_idx) {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        if cast.commitments.len() != threshold {
            return Err(bcast::Error::InvalidSignatureCount {
                expected: threshold,
                actual: cast.commitments.len(),
            });
        }
    }

    Ok(())
}

fn validate_round2_casts(
    peer_id: PeerId,
    share_idx_by_peer: &HashMap<PeerId, u32>,
    num_validators: usize,
    msg: &FrostRound2Casts,
) -> Result<(), bcast::Error> {
    let source_id = *share_idx_by_peer
        .get(&peer_id)
        .ok_or(bcast::Error::InvalidPeerIndex(peer_id))?;
    // Stricter than Charon: reject malformed batches before point decoding.
    if msg.casts.len() != num_validators {
        return Err(bcast::Error::InvalidSignatureCount {
            expected: num_validators,
            actual: msg.casts.len(),
        });
    }
    let mut seen_validators = HashSet::with_capacity(msg.casts.len());
    for cast in &msg.casts {
        let Some(key) = cast.key.as_ref() else {
            return Err(bcast::Error::MissingField("key"));
        };
        if key.source_id != source_id {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        if key.target_id != 0 {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        let val_idx =
            usize::try_from(key.val_idx).map_err(|_| bcast::Error::InvalidPeerIndex(peer_id))?;
        if val_idx >= num_validators {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
        if !seen_validators.insert(key.val_idx) {
            return Err(bcast::Error::InvalidPeerIndex(peer_id));
        }
    }

    Ok(())
}

#[async_trait]
impl FTransport for FrostP2P {
    async fn round1(
        &mut self,
        cancellation: &CancellationToken,
        bcast: HashMap<MsgKey, Round1Bcast>,
        shares: HashMap<MsgKey, ShamirShare>,
    ) -> Result<Round1Response, FrostError> {
        self.emit_event(FrostP2PEvent::RoundStarted { round: 1 });
        let casts_msg = build_round1_casts(&bcast);
        self.emit_event(FrostP2PEvent::BroadcastStarted { round: 1 });
        self.broadcast_round(ROUND1_CAST_ID, &casts_msg, cancellation)
            .await?;
        if let Err(error) = self.round1_casts_tx.send(casts_msg) {
            error!(%error, "frost round 1 casts receiver dropped before self-delivery");
            return Err(FrostError::Round1CastsReceiverDropped);
        }

        let p2p_msgs = self.build_round1_p2p_by_peer(&shares)?;
        self.emit_event(FrostP2PEvent::DirectSendStarted {
            peer_count: p2p_msgs.len(),
        });
        for (peer_id, msg) in p2p_msgs {
            self.frost_sender.send(peer_id, &msg, cancellation).await?;
        }

        let mut cast_msgs = Vec::with_capacity(self.num_peers);
        let mut p2p_msgs = Vec::with_capacity(self.num_peers.saturating_sub(1));

        loop {
            if cast_msgs.len() == self.num_peers
                && p2p_msgs.len() == self.num_peers.saturating_sub(1)
            {
                break;
            }

            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(FrostError::Cancelled),
                msg = self.round1_casts_rx.recv() => {
                    let msg = msg.ok_or(FrostError::ChannelClosed("round 1 casts channel"))?;
                    cast_msgs.push(msg);
                    if cast_msgs.len() > self.num_peers {
                        return Err(FrostError::TooManyRound1CastsMessages);
                    }
                }
                msg = self.round1_p2p_rx.recv() => {
                    let (_peer_id, msg) = msg.ok_or(FrostError::ChannelClosed("round 1 p2p channel"))?;
                    p2p_msgs.push(msg);
                    if p2p_msgs.len() > self.num_peers.saturating_sub(1) {
                        return Err(FrostError::TooManyRound1P2PMessages);
                    }
                }
            }
        }

        let response = make_round1_response(cast_msgs, p2p_msgs)?;
        self.emit_event(FrostP2PEvent::RoundCompleted { round: 1 });
        Ok(response)
    }

    async fn round2(
        &mut self,
        cancellation: &CancellationToken,
        bcast: HashMap<MsgKey, Round2Bcast>,
    ) -> Result<HashMap<MsgKey, Round2Bcast>, FrostError> {
        self.emit_event(FrostP2PEvent::RoundStarted { round: 2 });
        let casts_msg = build_round2_casts(&bcast);
        self.emit_event(FrostP2PEvent::BroadcastStarted { round: 2 });
        self.broadcast_round(ROUND2_CAST_ID, &casts_msg, cancellation)
            .await?;
        if let Err(error) = self.round2_casts_tx.send(casts_msg) {
            error!(%error, "frost round 2 casts receiver dropped before self-delivery");
            return Err(FrostError::Round2CastsReceiverDropped);
        }

        let mut cast_msgs = Vec::with_capacity(self.num_peers);

        while cast_msgs.len() != self.num_peers {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(FrostError::Cancelled),
                msg = self.round2_casts_rx.recv() => {
                    let msg = msg.ok_or(FrostError::ChannelClosed("round 2 casts channel"))?;
                    cast_msgs.push(msg);
                    if cast_msgs.len() > self.num_peers {
                        return Err(FrostError::TooManyRound2CastsMessages);
                    }
                }
            }
        }

        let response = make_round2_response(cast_msgs)?;
        self.emit_event(FrostP2PEvent::RoundCompleted { round: 2 });
        self.emit_event(FrostP2PEvent::ProtocolCompleted);
        Ok(response)
    }
}

impl FrostP2P {
    fn emit_event(&self, event: FrostP2PEvent) {
        self.frost_sender.emit_event(event);
    }

    /// Broadcasts a FROST round message and waits for terminal bcast status.
    async fn broadcast_round<M>(
        &self,
        msg_id: &'static str,
        msg: &M,
        cancellation: &CancellationToken,
    ) -> Result<(), FrostError>
    where
        M: prost::Message + prost::Name + Default + Clone + Send + Sync + 'static,
    {
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(FrostError::Cancelled),
            result = self.bcast_comp.broadcast_and_wait(msg_id, msg) => result,
        };

        match result {
            Ok(()) => {
                self.emit_event(FrostP2PEvent::BroadcastCompleted {
                    round: round_for_msg_id(msg_id),
                });
                Ok(())
            }
            Err(error) => {
                self.emit_event(FrostP2PEvent::BroadcastFailed {
                    round: round_for_msg_id(msg_id),
                    error: error.to_string(),
                });
                Err(error.into())
            }
        }
    }

    fn build_round1_p2p_by_peer(
        &self,
        shares: &HashMap<MsgKey, ShamirShare>,
    ) -> Result<HashMap<PeerId, FrostRound1P2p>, FrostError> {
        let mut p2p_msgs =
            HashMap::<PeerId, FrostRound1P2p>::with_capacity(self.num_peers.saturating_sub(1));

        for (key, share) in shares {
            if key.target_id == self.local_share_idx {
                return Err(FrostError::UnexpectedP2PMessageToSelf);
            }
            let peer_id = *self
                .peers_by_share_idx
                .get(&key.target_id)
                .ok_or(FrostError::ConfigError("unknown target"))?;
            p2p_msgs
                .entry(peer_id)
                .or_default()
                .shares
                .push(shamir_share_to_proto(*key, share));
        }

        Ok(p2p_msgs)
    }
}

fn round_for_msg_id(msg_id: &'static str) -> u8 {
    match msg_id {
        ROUND1_CAST_ID => 1,
        ROUND2_CAST_ID => 2,
        _ => 0,
    }
}

pub(super) fn validate_round1_p2p(
    peer_id: PeerId,
    share_idx_by_peer: &HashMap<PeerId, u32>,
    local_share_idx: u32,
    msg: &FrostRound1P2p,
    num_validators: usize,
) -> Result<(), FrostError> {
    let source_id = *share_idx_by_peer
        .get(&peer_id)
        .ok_or(FrostError::InvalidRound1P2PSourceId)?;
    // Stricter than Charon's handler: valid senders emit exactly one share per
    // validator, so reject malformed batches before later map overwrites.
    if msg.shares.len() != num_validators {
        return Err(FrostError::InvalidRound1P2PSharesCount);
    }
    let mut seen_validators = HashSet::with_capacity(msg.shares.len());
    for share in &msg.shares {
        let key = share.key.as_ref().ok_or(FrostError::MissingMsgKey)?;
        if key.source_id != source_id {
            return Err(FrostError::InvalidRound1P2PSourceId);
        }
        if key.target_id != local_share_idx {
            return Err(FrostError::InvalidRound1P2PTargetId);
        }
        let val_idx =
            usize::try_from(key.val_idx).map_err(|_| FrostError::InvalidRound1P2PValidatorIndex)?;
        if val_idx >= num_validators {
            return Err(FrostError::InvalidRound1P2PValidatorIndex);
        }
        if !seen_validators.insert(key.val_idx) {
            return Err(FrostError::DuplicateRound1P2PValidatorIndex);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use prost::bytes::Bytes;

    use super::*;
    use crate::{
        dkgpb::v1::frost::{FrostRound1Cast, FrostRound1ShamirShare, FrostRound2Cast},
        frostp2p::codec::key_to_proto,
    };

    #[test]
    fn validate_round1_casts_rejects_invalid_fields() {
        let peer_id = PeerId::random();
        let share_idx_by_peer = HashMap::from([(peer_id, 1)]);
        let cast = |key: MsgKey, commitments| FrostRound1Casts {
            casts: vec![FrostRound1Cast {
                key: Some(key_to_proto(key)),
                wi: Bytes::new(),
                ci: Bytes::new(),
                commitments,
            }],
        };

        assert!(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                1,
                &cast(
                    MsgKey {
                        val_idx: 0,
                        source_id: 1,
                        target_id: 0,
                    },
                    vec![Bytes::new()],
                ),
            )
            .is_ok()
        );
        assert_invalid_peer_index(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                1,
                &cast(
                    MsgKey {
                        val_idx: 0,
                        source_id: 2,
                        target_id: 0,
                    },
                    vec![Bytes::new()],
                ),
            ),
            peer_id,
        );
        let unknown_peer = PeerId::random();
        assert_invalid_peer_index(
            validate_round1_casts(
                unknown_peer,
                &share_idx_by_peer,
                1,
                1,
                &cast(
                    MsgKey {
                        val_idx: 0,
                        source_id: 1,
                        target_id: 0,
                    },
                    vec![Bytes::new()],
                ),
            ),
            unknown_peer,
        );
        assert_invalid_peer_index(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                1,
                &cast(
                    MsgKey {
                        val_idx: 0,
                        source_id: 1,
                        target_id: 1,
                    },
                    vec![Bytes::new()],
                ),
            ),
            peer_id,
        );
        assert_invalid_peer_index(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                1,
                &cast(
                    MsgKey {
                        val_idx: 1,
                        source_id: 1,
                        target_id: 0,
                    },
                    vec![Bytes::new()],
                ),
            ),
            peer_id,
        );
        assert_invalid_signature_count(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                1,
                &cast(
                    MsgKey {
                        val_idx: 0,
                        source_id: 1,
                        target_id: 0,
                    },
                    vec![],
                ),
            ),
            1,
            0,
        );
        assert_invalid_signature_count(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                2,
                &cast(
                    MsgKey {
                        val_idx: 0,
                        source_id: 1,
                        target_id: 0,
                    },
                    vec![Bytes::new()],
                ),
            ),
            2,
            1,
        );
        assert_invalid_peer_index(
            validate_round1_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                2,
                &FrostRound1Casts {
                    casts: vec![
                        FrostRound1Cast {
                            key: Some(key_to_proto(MsgKey {
                                val_idx: 0,
                                source_id: 1,
                                target_id: 0,
                            })),
                            wi: Bytes::new(),
                            ci: Bytes::new(),
                            commitments: vec![Bytes::new()],
                        },
                        FrostRound1Cast {
                            key: Some(key_to_proto(MsgKey {
                                val_idx: 0,
                                source_id: 1,
                                target_id: 0,
                            })),
                            wi: Bytes::new(),
                            ci: Bytes::new(),
                            commitments: vec![Bytes::new()],
                        },
                    ],
                },
            ),
            peer_id,
        );
    }

    #[test]
    fn validate_round2_casts_rejects_invalid_fields() {
        let peer_id = PeerId::random();
        let share_idx_by_peer = HashMap::from([(peer_id, 1)]);
        let cast = |key: MsgKey| FrostRound2Casts {
            casts: vec![FrostRound2Cast {
                key: Some(key_to_proto(key)),
                verification_key: Bytes::new(),
                vk_share: Bytes::new(),
            }],
        };

        assert!(
            validate_round2_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                &cast(MsgKey {
                    val_idx: 0,
                    source_id: 1,
                    target_id: 0,
                }),
            )
            .is_ok()
        );
        assert_invalid_peer_index(
            validate_round2_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                &cast(MsgKey {
                    val_idx: 0,
                    source_id: 2,
                    target_id: 0,
                }),
            ),
            peer_id,
        );
        let unknown_peer = PeerId::random();
        assert_invalid_peer_index(
            validate_round2_casts(
                unknown_peer,
                &share_idx_by_peer,
                1,
                &cast(MsgKey {
                    val_idx: 0,
                    source_id: 1,
                    target_id: 0,
                }),
            ),
            unknown_peer,
        );
        assert_invalid_peer_index(
            validate_round2_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                &cast(MsgKey {
                    val_idx: 0,
                    source_id: 1,
                    target_id: 1,
                }),
            ),
            peer_id,
        );
        assert_invalid_peer_index(
            validate_round2_casts(
                peer_id,
                &share_idx_by_peer,
                1,
                &cast(MsgKey {
                    val_idx: 1,
                    source_id: 1,
                    target_id: 0,
                }),
            ),
            peer_id,
        );
        assert_invalid_signature_count(
            validate_round2_casts(
                peer_id,
                &share_idx_by_peer,
                2,
                &cast(MsgKey {
                    val_idx: 0,
                    source_id: 1,
                    target_id: 0,
                }),
            ),
            2,
            1,
        );
        assert_invalid_peer_index(
            validate_round2_casts(
                peer_id,
                &share_idx_by_peer,
                2,
                &FrostRound2Casts {
                    casts: vec![
                        FrostRound2Cast {
                            key: Some(key_to_proto(MsgKey {
                                val_idx: 0,
                                source_id: 1,
                                target_id: 0,
                            })),
                            verification_key: Bytes::new(),
                            vk_share: Bytes::new(),
                        },
                        FrostRound2Cast {
                            key: Some(key_to_proto(MsgKey {
                                val_idx: 0,
                                source_id: 1,
                                target_id: 0,
                            })),
                            verification_key: Bytes::new(),
                            vk_share: Bytes::new(),
                        },
                    ],
                },
            ),
            peer_id,
        );
    }

    #[test]
    fn bcast_check_rejects_invalid_round_casts_before_signing() {
        let peer_id = PeerId::random();
        let share_idx_by_peer = Arc::new(HashMap::from([(peer_id, 1)]));
        let round1_check_share_idx_by_peer = share_idx_by_peer.clone();
        let round1_check: bcast::CheckFn<FrostRound1Casts> = Box::new(move |peer_id, msg| {
            validate_round1_casts(peer_id, &round1_check_share_idx_by_peer, 1, 2, msg)
        });
        let round2_check_share_idx_by_peer = share_idx_by_peer.clone();
        let round2_check: bcast::CheckFn<FrostRound2Casts> = Box::new(move |peer_id, msg| {
            validate_round2_casts(peer_id, &round2_check_share_idx_by_peer, 2, msg)
        });

        let invalid_round1 = FrostRound1Casts {
            casts: vec![FrostRound1Cast {
                key: Some(key_to_proto(MsgKey {
                    val_idx: 0,
                    source_id: 1,
                    target_id: 0,
                })),
                wi: Bytes::new(),
                ci: Bytes::new(),
                commitments: vec![Bytes::new()],
            }],
        };
        let invalid_round2 = FrostRound2Casts {
            casts: vec![FrostRound2Cast {
                key: Some(key_to_proto(MsgKey {
                    val_idx: 0,
                    source_id: 1,
                    target_id: 0,
                })),
                verification_key: Bytes::new(),
                vk_share: Bytes::new(),
            }],
        };

        assert_invalid_signature_count(round1_check(peer_id, &invalid_round1), 2, 1);
        assert_invalid_signature_count(round2_check(peer_id, &invalid_round2), 2, 1);
    }

    #[test]
    fn validate_round1_p2p_requires_all_validator_shares_once() {
        let peer_id = PeerId::random();
        let share_idx_by_peer = HashMap::from([(peer_id, 1)]);
        let share = |val_idx| FrostRound1ShamirShare {
            key: Some(key_to_proto(MsgKey {
                val_idx,
                source_id: 1,
                target_id: 2,
            })),
            id: 1,
            value: Bytes::from_static(&[7]),
        };

        assert!(
            validate_round1_p2p(
                peer_id,
                &share_idx_by_peer,
                2,
                &FrostRound1P2p {
                    shares: vec![share(0), share(1)]
                },
                2,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_round1_p2p(
                peer_id,
                &share_idx_by_peer,
                2,
                &FrostRound1P2p {
                    shares: vec![share(0)]
                },
                2,
            ),
            Err(FrostError::InvalidRound1P2PSharesCount)
        ));
        assert!(matches!(
            validate_round1_p2p(
                peer_id,
                &share_idx_by_peer,
                2,
                &FrostRound1P2p {
                    shares: vec![share(0), share(0)]
                },
                2,
            ),
            Err(FrostError::DuplicateRound1P2PValidatorIndex)
        ));
    }

    #[test]
    fn peer_share_index_validation_rejects_invalid_maps() {
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();

        assert!(matches!(
            validate_peer_share_indices(&HashMap::from([(peer_a, 0)]), 1),
            Err(FrostError::ConfigError(
                "frost peer share index cannot be zero"
            ))
        ));
        assert!(matches!(
            validate_peer_share_indices(&HashMap::from([(peer_a, 1), (peer_b, 1)]), 1),
            Err(FrostError::ConfigError("duplicate frost peer share index"))
        ));
        assert!(matches!(
            validate_peer_share_indices(&HashMap::from([(peer_a, 1)]), 2),
            Err(FrostError::ConfigError(
                "local frost share index missing from peer map"
            ))
        ));
    }

    fn assert_invalid_peer_index<T>(result: Result<T, bcast::Error>, expected: PeerId) {
        assert!(matches!(
            result,
            Err(bcast::Error::InvalidPeerIndex(peer_id)) if peer_id == expected
        ));
    }

    fn assert_invalid_signature_count<T>(
        result: Result<T, bcast::Error>,
        expected: usize,
        actual: usize,
    ) {
        assert!(matches!(
            result,
            Err(bcast::Error::InvalidSignatureCount {
                expected: got_expected,
                actual: got_actual,
            }) if got_expected == expected && got_actual == actual
        ));
    }
}
