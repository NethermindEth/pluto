//! Partial signature exchange codec helpers used by core types.
//!
//! Implements Charon-compatible `marshal`/`unmarshal` semantics: SSZ-capable
//! types are serialized as SSZ binary; all other types use JSON.  On
//! deserialization the codec checks for a JSON `{` prefix first — if present,
//! it decodes as JSON.  Otherwise it tries SSZ for SSZ-capable types.

use std::any::Any;

use crate::{
    signeddata::{
        Attestation, BeaconCommitteeSelection, SignedAggregateAndProof, SignedRandao,
        SignedSyncContributionAndProof, SignedSyncMessage, SignedVoluntaryExit,
        SyncCommitteeSelection, VersionedAttestation, VersionedSignedAggregateAndProof,
        VersionedSignedProposal, VersionedSignedValidatorRegistration,
    },
    ssz_codec,
    types::{DutyType, Signature, SignedData},
};

/// Error type for partial signature exchange codec operations.
#[derive(Debug, thiserror::Error)]
pub enum ParSigExCodecError {
    /// Missing duty or data set fields.
    #[error("invalid parsigex msg fields")]
    InvalidMessageFields,

    /// Invalid partial signed data set proto.
    #[error("invalid partial signed data set proto fields")]
    InvalidParSignedDataSetFields,

    /// Invalid partial signed proto.
    #[error("invalid partial signed proto")]
    InvalidParSignedProto,

    /// Invalid duty type.
    #[error("invalid duty")]
    InvalidDuty,

    /// Unsupported duty type.
    #[error("unsupported duty type")]
    UnsupportedDutyType,

    /// Deprecated builder proposer duty.
    #[error("deprecated duty builder proposer")]
    DeprecatedBuilderProposer,

    /// Failed to parse a public key.
    #[error("invalid public key: {0}")]
    InvalidPubKey(String),

    /// Invalid share index.
    #[error("invalid share index")]
    InvalidShareIndex,

    /// JSON serialization failed.
    #[error("marshal signed data: {0}")]
    Serialize(#[from] serde_json::Error),

    /// SSZ codec error.
    #[error("ssz codec: {0}")]
    SszCodec(#[from] ssz_codec::SszCodecError),

    /// Signed data construction error.
    #[error("signed data: {0}")]
    SignedData(String),

    /// Failed to extract the signature from signed data.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
}

pub(crate) fn serialize_signed_data(data: &dyn SignedData) -> Result<Vec<u8>, ParSigExCodecError> {
    let any = data as &dyn Any;

    // ---------------------------------------------------------------
    // SSZ-capable types — encode as SSZ binary (matching Go `marshal`)
    // ---------------------------------------------------------------

    // phase0::Attestation (non-versioned, raw SSZ)
    if let Some(value) = any.downcast_ref::<Attestation>() {
        return Ok(ssz_codec::encode_phase0_attestation(&value.0)?);
    }

    // VersionedAttestation (versioned header + inner SSZ)
    if let Some(value) = any.downcast_ref::<VersionedAttestation>() {
        return Ok(ssz_codec::encode_versioned_attestation(&value.0)?);
    }

    // phase0::SignedAggregateAndProof (non-versioned, raw SSZ)
    if let Some(value) = any.downcast_ref::<SignedAggregateAndProof>() {
        return Ok(ssz_codec::encode_phase0_signed_aggregate_and_proof(
            &value.0,
        )?);
    }

    // VersionedSignedAggregateAndProof (versioned header + inner SSZ)
    if let Some(value) = any.downcast_ref::<VersionedSignedAggregateAndProof>() {
        return Ok(ssz_codec::encode_versioned_signed_aggregate_and_proof(
            &value.0,
        )?);
    }

    // altair::SyncCommitteeMessage (non-versioned, all fixed)
    if let Some(value) = any.downcast_ref::<SignedSyncMessage>() {
        return Ok(ssz_codec::encode_sync_committee_message(&value.0)?);
    }

    // altair::SignedContributionAndProof (non-versioned, all fixed)
    if let Some(value) = any.downcast_ref::<SignedSyncContributionAndProof>() {
        return Ok(ssz_codec::encode_signed_contribution_and_proof(&value.0)?);
    }

    // ---------------------------------------------------------------
    // JSON-only types
    // ---------------------------------------------------------------

    macro_rules! serialize_json {
        ($ty:ty) => {
            if let Some(value) = any.downcast_ref::<$ty>() {
                return Ok(serde_json::to_vec(value)?);
            }
        };
    }

    // VersionedSignedProposal (versioned header + inner SSZ)
    if let Some(value) = any.downcast_ref::<VersionedSignedProposal>() {
        return Ok(ssz_codec::encode_versioned_signed_proposal(&value.0)?);
    }

    serialize_json!(VersionedSignedValidatorRegistration);
    serialize_json!(SignedVoluntaryExit);
    serialize_json!(SignedRandao);
    serialize_json!(Signature);
    serialize_json!(BeaconCommitteeSelection);
    serialize_json!(SyncCommitteeSelection);

    Err(ParSigExCodecError::UnsupportedDutyType)
}

pub(crate) fn deserialize_signed_data(
    duty_type: &DutyType,
    bytes: &[u8],
) -> Result<Box<dyn SignedData>, ParSigExCodecError> {
    /// Returns `true` when the trimmed byte slice starts with `{`, indicating
    /// JSON data.
    fn looks_like_json(bytes: &[u8]) -> bool {
        bytes.iter().find(|b| !b.is_ascii_whitespace()).copied() == Some(b'{')
    }

    macro_rules! deserialize_json {
        ($ty:ty) => {
            serde_json::from_slice::<$ty>(bytes)
                .map(|value| Box::new(value) as Box<dyn SignedData>)
                .map_err(ParSigExCodecError::from)
        };
    }

    // Core logic matching Go's `unmarshal`:
    // - If data starts with `{`, it is JSON — skip SSZ, decode as JSON.
    // - Otherwise, try SSZ decode for SSZ-capable types.
    let is_json = looks_like_json(bytes);

    match duty_type {
        // -- Attester: SSZ-capable (non-versioned + versioned) --
        DutyType::Attester => {
            if is_json {
                return deserialize_json!(Attestation)
                    .or_else(|_| deserialize_json!(VersionedAttestation));
            }
            // Try SSZ non-versioned Attestation first.
            if let Ok(att) = ssz_codec::decode_phase0_attestation(bytes) {
                return Ok(Box::new(Attestation::new(att)));
            }
            // Try SSZ versioned Attestation.
            if let Ok(va) = ssz_codec::decode_versioned_attestation(bytes) {
                let wrapped = VersionedAttestation::new(va)
                    .map_err(|e| ParSigExCodecError::SignedData(e.to_string()))?;
                return Ok(Box::new(wrapped));
            }
            Err(ParSigExCodecError::UnsupportedDutyType)
        }

        // -- Proposer: SSZ-capable (versioned header + inner SSZ) --
        DutyType::Proposer => {
            if is_json {
                return deserialize_json!(VersionedSignedProposal);
            }
            if let Ok(vp) = ssz_codec::decode_versioned_signed_proposal(bytes) {
                let wrapped = VersionedSignedProposal::new(vp)
                    .map_err(|e| ParSigExCodecError::SignedData(e.to_string()))?;
                return Ok(Box::new(wrapped));
            }
            Err(ParSigExCodecError::UnsupportedDutyType)
        }

        DutyType::BuilderProposer => Err(ParSigExCodecError::DeprecatedBuilderProposer),

        // -- BuilderRegistration: JSON-only --
        DutyType::BuilderRegistration => deserialize_json!(VersionedSignedValidatorRegistration),

        // -- Exit: JSON-only --
        DutyType::Exit => deserialize_json!(SignedVoluntaryExit),

        // -- Randao: JSON-only --
        DutyType::Randao => deserialize_json!(SignedRandao),

        // -- Signature: JSON-only --
        DutyType::Signature => deserialize_json!(Signature),

        // -- PrepareAggregator: JSON-only --
        DutyType::PrepareAggregator => deserialize_json!(BeaconCommitteeSelection),

        // -- Aggregator: SSZ-capable (non-versioned + versioned) --
        DutyType::Aggregator => {
            if is_json {
                return deserialize_json!(SignedAggregateAndProof)
                    .or_else(|_| deserialize_json!(VersionedSignedAggregateAndProof));
            }
            // Try SSZ non-versioned SignedAggregateAndProof first.
            if let Ok(sap) = ssz_codec::decode_phase0_signed_aggregate_and_proof(bytes) {
                return Ok(Box::new(SignedAggregateAndProof::new(sap)));
            }
            // Try SSZ versioned.
            if let Ok(va) = ssz_codec::decode_versioned_signed_aggregate_and_proof(bytes) {
                return Ok(Box::new(VersionedSignedAggregateAndProof::new(va)));
            }
            Err(ParSigExCodecError::UnsupportedDutyType)
        }

        // -- SyncMessage: SSZ-capable --
        DutyType::SyncMessage => {
            if is_json {
                return deserialize_json!(SignedSyncMessage);
            }
            if let Ok(msg) = ssz_codec::decode_sync_committee_message(bytes) {
                return Ok(Box::new(SignedSyncMessage::new(msg)));
            }
            Err(ParSigExCodecError::UnsupportedDutyType)
        }

        // -- PrepareSyncContribution: JSON-only --
        DutyType::PrepareSyncContribution => deserialize_json!(SyncCommitteeSelection),

        // -- SyncContribution: SSZ-capable --
        DutyType::SyncContribution => {
            if is_json {
                return deserialize_json!(SignedSyncContributionAndProof);
            }
            if let Ok(scp) = ssz_codec::decode_signed_contribution_and_proof(bytes) {
                return Ok(Box::new(SignedSyncContributionAndProof::new(scp)));
            }
            Err(ParSigExCodecError::UnsupportedDutyType)
        }

        DutyType::Unknown | DutyType::InfoSync | DutyType::DutySentinel(_) => {
            Err(ParSigExCodecError::UnsupportedDutyType)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_eth2api::{
        spec::{altair, phase0},
        versioned,
    };
    use pluto_ssz::{BitList, BitVector};

    fn sample_attestation_data() -> phase0::AttestationData {
        phase0::AttestationData {
            slot: 42,
            index: 7,
            beacon_block_root: [0xaa; 32],
            source: phase0::Checkpoint {
                epoch: 10,
                root: [0xbb; 32],
            },
            target: phase0::Checkpoint {
                epoch: 11,
                root: [0xcc; 32],
            },
        }
    }

    /// Helper: downcast a `Box<dyn SignedData>` to a concrete type.
    fn downcast<T: SignedData + 'static>(boxed: Box<dyn SignedData>) -> T {
        let any = boxed as Box<dyn std::any::Any>;
        *any.downcast::<T>().expect("type mismatch in downcast")
    }

    /// SSZ-capable types serialize as SSZ binary and can be deserialized back.
    #[test]
    fn marshal_unmarshal_ssz_attestation() {
        let att = Attestation::new(phase0::Attestation {
            aggregation_bits: BitList::with_bits(8, &[0, 2]),
            data: sample_attestation_data(),
            signature: [0x11; 96],
        });
        let bytes = serialize_signed_data(&att).unwrap();
        // SSZ bytes should NOT start with '{'.
        assert_ne!(bytes.first(), Some(&b'{'));
        let decoded: Attestation =
            downcast(deserialize_signed_data(&DutyType::Attester, &bytes).unwrap());
        assert_eq!(att, decoded);
    }

    /// SSZ-capable types: versioned attestation round-trip.
    #[test]
    fn marshal_unmarshal_ssz_versioned_attestation() {
        let inner = versioned::VersionedAttestation {
            version: versioned::DataVersion::Deneb,
            validator_index: None,
            attestation: Some(versioned::AttestationPayload::Deneb(phase0::Attestation {
                aggregation_bits: BitList::with_bits(16, &[1, 3]),
                data: sample_attestation_data(),
                signature: [0x22; 96],
            })),
        };
        let va = VersionedAttestation::new(inner).unwrap();
        let bytes = serialize_signed_data(&va).unwrap();
        assert_ne!(bytes.first(), Some(&b'{'));
        let decoded: VersionedAttestation =
            downcast(deserialize_signed_data(&DutyType::Attester, &bytes).unwrap());
        assert_eq!(va, decoded);
    }

    /// SSZ-capable types: SyncMessage round-trip.
    #[test]
    fn marshal_unmarshal_ssz_sync_message() {
        let msg = SignedSyncMessage::new(altair::SyncCommitteeMessage {
            slot: 100,
            beacon_block_root: [0xdd; 32],
            validator_index: 50,
            signature: [0xee; 96],
        });
        let bytes = serialize_signed_data(&msg).unwrap();
        assert_ne!(bytes.first(), Some(&b'{'));
        let decoded: SignedSyncMessage =
            downcast(deserialize_signed_data(&DutyType::SyncMessage, &bytes).unwrap());
        assert_eq!(msg, decoded);
    }

    /// SSZ-capable types: SignedSyncContributionAndProof round-trip.
    #[test]
    fn marshal_unmarshal_ssz_signed_sync_contribution() {
        let scp = SignedSyncContributionAndProof::new(altair::SignedContributionAndProof {
            message: altair::ContributionAndProof {
                aggregator_index: 33,
                contribution: altair::SyncCommitteeContribution {
                    slot: 200,
                    beacon_block_root: [0xab; 32],
                    subcommittee_index: 2,
                    aggregation_bits: BitVector::with_bits(&[0, 5]),
                    signature: [0xcd; 96],
                },
                selection_proof: [0xef; 96],
            },
            signature: [0xfa; 96],
        });
        let bytes = serialize_signed_data(&scp).unwrap();
        assert_ne!(bytes.first(), Some(&b'{'));
        let decoded: SignedSyncContributionAndProof =
            downcast(deserialize_signed_data(&DutyType::SyncContribution, &bytes).unwrap());
        assert_eq!(scp, decoded);
    }

    /// SSZ-capable types: SignedAggregateAndProof round-trip.
    #[test]
    fn marshal_unmarshal_ssz_signed_aggregate_and_proof() {
        let sap = SignedAggregateAndProof::new(phase0::SignedAggregateAndProof {
            message: phase0::AggregateAndProof {
                aggregator_index: 99,
                aggregate: phase0::Attestation {
                    aggregation_bits: BitList::with_bits(8, &[2]),
                    data: sample_attestation_data(),
                    signature: [0x33; 96],
                },
                selection_proof: [0x44; 96],
            },
            signature: [0x55; 96],
        });
        let bytes = serialize_signed_data(&sap).unwrap();
        assert_ne!(bytes.first(), Some(&b'{'));
        let decoded: SignedAggregateAndProof =
            downcast(deserialize_signed_data(&DutyType::Aggregator, &bytes).unwrap());
        assert_eq!(sap, decoded);
    }

    /// JSON-only types still serialize as JSON.
    #[test]
    fn marshal_unmarshal_json_randao() {
        let randao = SignedRandao::new(10, [0x99; 96]);
        let bytes = serialize_signed_data(&randao).unwrap();
        // JSON bytes should start with '{'.
        assert_eq!(bytes.first(), Some(&b'{'));
        let decoded: SignedRandao =
            downcast(deserialize_signed_data(&DutyType::Randao, &bytes).unwrap());
        assert_eq!(randao, decoded);
    }

    /// JSON data can still be deserialized for SSZ-capable types (fallback).
    #[test]
    fn json_fallback_for_ssz_capable_attestation() {
        let att = Attestation::new(phase0::Attestation {
            aggregation_bits: BitList::with_bits(8, &[0]),
            data: sample_attestation_data(),
            signature: [0x11; 96],
        });
        // Force JSON encoding.
        let json_bytes = serde_json::to_vec(&att).unwrap();
        assert_eq!(json_bytes.first(), Some(&b'{'));
        // Deserialize should fall back to JSON and succeed.
        let decoded: Attestation =
            downcast(deserialize_signed_data(&DutyType::Attester, &json_bytes).unwrap());
        assert_eq!(att, decoded);
    }

    /// JSON data can still be deserialized for SSZ-capable SyncMessage
    /// (fallback).
    #[test]
    fn json_fallback_for_ssz_capable_sync_message() {
        let msg = SignedSyncMessage::new(altair::SyncCommitteeMessage {
            slot: 5,
            beacon_block_root: [0xaa; 32],
            validator_index: 3,
            signature: [0xbb; 96],
        });
        let json_bytes = serde_json::to_vec(&msg).unwrap();
        let decoded: SignedSyncMessage =
            downcast(deserialize_signed_data(&DutyType::SyncMessage, &json_bytes).unwrap());
        assert_eq!(msg, decoded);
    }

    /// JSON data can still be deserialized for SSZ-capable Aggregator
    /// (fallback).
    #[test]
    fn json_fallback_for_ssz_capable_aggregator() {
        let sap = SignedAggregateAndProof::new(phase0::SignedAggregateAndProof {
            message: phase0::AggregateAndProof {
                aggregator_index: 1,
                aggregate: phase0::Attestation {
                    aggregation_bits: BitList::with_bits(4, &[0]),
                    data: sample_attestation_data(),
                    signature: [0x11; 96],
                },
                selection_proof: [0x22; 96],
            },
            signature: [0x33; 96],
        });
        let json_bytes = serde_json::to_vec(&sap).unwrap();
        assert_eq!(json_bytes.first(), Some(&b'{'));
        let decoded: SignedAggregateAndProof =
            downcast(deserialize_signed_data(&DutyType::Aggregator, &json_bytes).unwrap());
        assert_eq!(sap, decoded);
    }
}
