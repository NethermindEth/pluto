//! Partial signature exchange codec helpers used by core types.
//!
//! Implements Charon-compatible `marshal`/`unmarshal` semantics: SSZ-capable
//! types are serialized as SSZ binary; all other types use JSON.  On
//! deserialization the codec tries SSZ first for SSZ-capable types and only
//! falls back to JSON when the SSZ decode fails *and* the payload looks like
//! JSON (a `{` prefix) — matching charon's `unmarshal` (`core/proto.go`). The
//! `{` prefix is never used to skip SSZ, since valid SSZ can begin with `0x7B`.

use base64::Engine as _;

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

    /// Invalid unsigned data set proto.
    #[error("invalid unsigned data set fields")]
    InvalidUnsignedDataSetFields,

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

    /// Unsigned data construction error.
    #[error("unsigned data: {0}")]
    UnsignedData(String),

    /// Failed to extract the signature from signed data.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
}

fn serialize_signature(sig: &Signature) -> Result<Vec<u8>, ParSigExCodecError> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(sig);
    Ok(serde_json::to_vec(&encoded)?)
}

fn deserialize_signature(bytes: &[u8]) -> Result<SignedData, ParSigExCodecError> {
    let encoded: String = serde_json::from_slice(bytes)?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| ParSigExCodecError::SignedData(format!("invalid base64: {e}")))?;
    let sig: Signature = pluto_crypto::types::signature_from_bytes(&raw)
        .map_err(|e| ParSigExCodecError::InvalidSignature(e.to_string()))?;
    Ok(SignedData::Signature(sig))
}

pub(crate) fn serialize_signed_data(data: &SignedData) -> Result<Vec<u8>, ParSigExCodecError> {
    match data {
        // ---------------------------------------------------------------
        // SSZ-capable types — encode as SSZ binary (matching Go `marshal`)
        // ---------------------------------------------------------------

        // phase0::Attestation (non-versioned, raw SSZ)
        SignedData::Attestation(value) => Ok(ssz_codec::encode_phase0_attestation(&value.0)?),

        // VersionedAttestation (versioned header + inner SSZ)
        SignedData::VersionedAttestation(value) => {
            Ok(ssz_codec::encode_versioned_attestation(&value.0)?)
        }

        // phase0::SignedAggregateAndProof (non-versioned, raw SSZ)
        SignedData::SignedAggregateAndProof(value) => Ok(
            ssz_codec::encode_phase0_signed_aggregate_and_proof(&value.0)?,
        ),

        // VersionedSignedAggregateAndProof (versioned header + inner SSZ)
        SignedData::VersionedSignedAggregateAndProof(value) => Ok(
            ssz_codec::encode_versioned_signed_aggregate_and_proof(&value.0)?,
        ),

        // altair::SyncCommitteeMessage (non-versioned, all fixed)
        SignedData::SignedSyncMessage(value) => {
            Ok(ssz_codec::encode_sync_committee_message(&value.0)?)
        }

        // altair::SignedContributionAndProof (non-versioned, all fixed)
        SignedData::SignedSyncContributionAndProof(value) => {
            Ok(ssz_codec::encode_signed_contribution_and_proof(&value.0)?)
        }

        // VersionedSignedProposal (versioned header + inner SSZ)
        SignedData::VersionedSignedProposal(value) => {
            Ok(ssz_codec::encode_versioned_signed_proposal(&value.0)?)
        }

        // ---------------------------------------------------------------
        // JSON-only types
        // ---------------------------------------------------------------
        SignedData::VersionedSignedValidatorRegistration(value) => Ok(serde_json::to_vec(value)?),
        SignedData::SignedVoluntaryExit(value) => Ok(serde_json::to_vec(value)?),
        SignedData::SignedRandao(value) => Ok(serde_json::to_vec(value)?),
        SignedData::Signature(value) => serialize_signature(value),
        SignedData::BeaconCommitteeSelection(value) => Ok(serde_json::to_vec(value)?),
        SignedData::SyncCommitteeSelection(value) => Ok(serde_json::to_vec(value)?),

        // ---------------------------------------------------------------
        // Never exchanged on the wire: the unsigned contribution-and-proof is
        // only signed locally (charon exchanges the *signed* variant), so it
        // has no `marshal` counterpart.
        // ---------------------------------------------------------------
        SignedData::SyncContributionAndProof(_) => Err(ParSigExCodecError::UnsupportedDutyType),
        #[cfg(test)]
        SignedData::Mock(_) => Err(ParSigExCodecError::UnsupportedDutyType),
    }
}

/// Returns `true` when the first non-whitespace byte is `{`, indicating JSON
/// data. Charon's `unmarshal` (`core/proto.go`) uses this prefix check only to
/// gate the JSON fallback *after* an SSZ decode has failed — never to skip SSZ.
/// A valid SSZ payload can legitimately begin with `0x7B` (e.g. a fixed-size
/// container whose leading `u64` has low byte 123), so it must not be treated
/// as a positive "this is JSON" signal.
pub(crate) fn looks_like_json(bytes: &[u8]) -> bool {
    bytes.iter().find(|b| !b.is_ascii_whitespace()).copied() == Some(b'{')
}

pub(crate) fn deserialize_signed_data(
    duty_type: &DutyType,
    bytes: &[u8],
) -> Result<SignedData, ParSigExCodecError> {
    macro_rules! deserialize_json {
        ($ty:ty) => {
            serde_json::from_slice::<$ty>(bytes)
                .map(SignedData::from)
                .map_err(ParSigExCodecError::from)
        };
    }

    match duty_type {
        // -- Attester: SSZ-capable (non-versioned + versioned) --
        DutyType::Attester => {
            // Try SSZ non-versioned Attestation first.
            if let Ok(att) = ssz_codec::decode_phase0_attestation(bytes) {
                return Ok(Attestation::new(att).into());
            }
            // Try SSZ versioned Attestation.
            if let Ok(va) = ssz_codec::decode_versioned_attestation(bytes) {
                let wrapped = VersionedAttestation::new(va)
                    .map_err(|e| ParSigExCodecError::SignedData(e.to_string()))?;
                return Ok(wrapped.into());
            }
            if looks_like_json(bytes) {
                return deserialize_json!(Attestation)
                    .or_else(|_| deserialize_json!(VersionedAttestation));
            }
            Err(ParSigExCodecError::UnsupportedDutyType)
        }

        // -- Proposer: SSZ-capable (versioned header + inner SSZ) --
        DutyType::Proposer => {
            if let Ok(vp) = ssz_codec::decode_versioned_signed_proposal(bytes) {
                let wrapped = VersionedSignedProposal::new(vp)
                    .map_err(|e| ParSigExCodecError::SignedData(e.to_string()))?;
                return Ok(wrapped.into());
            }
            if looks_like_json(bytes) {
                return deserialize_json!(VersionedSignedProposal);
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
        DutyType::Signature => deserialize_signature(bytes),

        // -- PrepareAggregator: JSON-only --
        DutyType::PrepareAggregator => deserialize_json!(BeaconCommitteeSelection),

        // -- Aggregator: SSZ-capable (non-versioned + versioned) --
        DutyType::Aggregator => {
            // Try SSZ non-versioned SignedAggregateAndProof first.
            if let Ok(sap) = ssz_codec::decode_phase0_signed_aggregate_and_proof(bytes) {
                return Ok(SignedAggregateAndProof::new(sap).into());
            }
            // Try SSZ versioned.
            if let Ok(va) = ssz_codec::decode_versioned_signed_aggregate_and_proof(bytes) {
                return Ok(VersionedSignedAggregateAndProof::new(va).into());
            }
            if looks_like_json(bytes) {
                return deserialize_json!(SignedAggregateAndProof)
                    .or_else(|_| deserialize_json!(VersionedSignedAggregateAndProof));
            }
            Err(ParSigExCodecError::UnsupportedDutyType)
        }

        // -- SyncMessage: SSZ-capable --
        DutyType::SyncMessage => {
            if let Ok(msg) = ssz_codec::decode_sync_committee_message(bytes) {
                return Ok(SignedSyncMessage::new(msg).into());
            }
            if looks_like_json(bytes) {
                return deserialize_json!(SignedSyncMessage);
            }
            Err(ParSigExCodecError::UnsupportedDutyType)
        }

        // -- PrepareSyncContribution: JSON-only --
        DutyType::PrepareSyncContribution => deserialize_json!(SyncCommitteeSelection),

        // -- SyncContribution: SSZ-capable --
        DutyType::SyncContribution => {
            if let Ok(scp) = ssz_codec::decode_signed_contribution_and_proof(bytes) {
                return Ok(SignedSyncContributionAndProof::new(scp).into());
            }
            if looks_like_json(bytes) {
                return deserialize_json!(SignedSyncContributionAndProof);
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
    use crate::types::SIGNATURE_LENGTH;
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

    /// SSZ-capable types serialize as SSZ binary and can be deserialized back.
    #[test]
    fn marshal_unmarshal_ssz_attestation() {
        let att = Attestation::new(phase0::Attestation {
            aggregation_bits: BitList::with_bits(8, &[0, 2]),
            data: sample_attestation_data(),
            signature: [0x11; 96],
        });
        let bytes = serialize_signed_data(&SignedData::from(att.clone())).unwrap();
        // SSZ bytes should NOT start with '{'.
        assert_ne!(bytes.first(), Some(&b'{'));
        let decoded = deserialize_signed_data(&DutyType::Attester, &bytes).unwrap();
        assert_eq!(SignedData::from(att), decoded);
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
        let bytes = serialize_signed_data(&SignedData::from(va.clone())).unwrap();
        assert_ne!(bytes.first(), Some(&b'{'));
        let decoded = deserialize_signed_data(&DutyType::Attester, &bytes).unwrap();
        assert_eq!(SignedData::from(va), decoded);
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
        let bytes = serialize_signed_data(&SignedData::from(msg.clone())).unwrap();
        assert_ne!(bytes.first(), Some(&b'{'));
        let decoded = deserialize_signed_data(&DutyType::SyncMessage, &bytes).unwrap();
        assert_eq!(SignedData::from(msg), decoded);
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
        let bytes = serialize_signed_data(&SignedData::from(scp.clone())).unwrap();
        assert_ne!(bytes.first(), Some(&b'{'));
        let decoded = deserialize_signed_data(&DutyType::SyncContribution, &bytes).unwrap();
        assert_eq!(SignedData::from(scp), decoded);
    }

    /// Regression: `SyncCommitteeMessage`'s leading `u64` slot makes its SSZ
    /// begin with `0x7B` (`{`) when `slot % 256 == 123`. SSZ must still win
    /// over the JSON fallback (charon `unmarshal` tries SSZ first).
    #[test]
    fn ssz_sync_message_with_leading_brace_decodes_as_ssz() {
        let msg = SignedSyncMessage::new(altair::SyncCommitteeMessage {
            slot: 0x7B, // little-endian u64 → first SSZ byte is `{`
            beacon_block_root: [0xdd; 32],
            validator_index: 50,
            signature: [0xee; 96],
        });
        let bytes = serialize_signed_data(&SignedData::from(msg.clone())).unwrap();
        assert_eq!(
            bytes.first(),
            Some(&b'{'),
            "leading SSZ byte should be 0x7B"
        );
        let decoded = deserialize_signed_data(&DutyType::SyncMessage, &bytes).unwrap();
        assert_eq!(SignedData::from(msg), decoded);
    }

    /// Regression: `SignedContributionAndProof`'s leading `u64` aggregator
    /// index makes its SSZ begin with `0x7B` (`{`) when `index % 256 ==
    /// 123`. SSZ must still win over the JSON fallback.
    #[test]
    fn ssz_signed_sync_contribution_with_leading_brace_decodes_as_ssz() {
        let scp = SignedSyncContributionAndProof::new(altair::SignedContributionAndProof {
            message: altair::ContributionAndProof {
                aggregator_index: 0x7B, // little-endian u64 → first SSZ byte is `{`
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
        let bytes = serialize_signed_data(&SignedData::from(scp.clone())).unwrap();
        assert_eq!(
            bytes.first(),
            Some(&b'{'),
            "leading SSZ byte should be 0x7B"
        );
        let decoded = deserialize_signed_data(&DutyType::SyncContribution, &bytes).unwrap();
        assert_eq!(SignedData::from(scp), decoded);
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
        let bytes = serialize_signed_data(&SignedData::from(sap.clone())).unwrap();
        assert_ne!(bytes.first(), Some(&b'{'));
        let decoded = deserialize_signed_data(&DutyType::Aggregator, &bytes).unwrap();
        assert_eq!(SignedData::from(sap), decoded);
    }

    /// JSON-only types still serialize as JSON.
    #[test]
    fn marshal_unmarshal_json_randao() {
        let randao = SignedRandao::new(10, [0x99; 96]);
        let bytes = serialize_signed_data(&SignedData::from(randao.clone())).unwrap();
        // JSON bytes should start with '{'.
        assert_eq!(bytes.first(), Some(&b'{'));
        let decoded = deserialize_signed_data(&DutyType::Randao, &bytes).unwrap();
        assert_eq!(SignedData::from(randao), decoded);
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
        let decoded = deserialize_signed_data(&DutyType::Attester, &json_bytes).unwrap();
        assert_eq!(SignedData::from(att), decoded);
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
        let decoded = deserialize_signed_data(&DutyType::SyncMessage, &json_bytes).unwrap();
        assert_eq!(SignedData::from(msg), decoded);
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
        let decoded = deserialize_signed_data(&DutyType::Aggregator, &json_bytes).unwrap();
        assert_eq!(SignedData::from(sap), decoded);
    }

    #[test]
    fn marshal_unmarshal_signature() {
        let sig: Signature = [0xab; SIGNATURE_LENGTH];
        let bytes = serialize_signed_data(&SignedData::from(sig)).unwrap();

        // Snapshot: Signature serializes as a base64-encoded JSON string.
        // Changing this breaks wire compatibility with Charon.
        const EXPECTED: &str = "\"q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6ur\"";
        assert_eq!(bytes, EXPECTED.as_bytes());

        let decoded = deserialize_signed_data(&DutyType::Signature, &bytes).unwrap();
        assert_eq!(SignedData::from(sig), decoded);
    }

    #[test]
    fn deserialize_signature_invalid_base64() {
        let err = deserialize_signed_data(&DutyType::Signature, br#""%%%""#).unwrap_err();
        assert!(
            matches!(err, ParSigExCodecError::SignedData(_)),
            "expected SignedData error, got {err:?}"
        );
    }

    #[test]
    fn deserialize_signature_wrong_length() {
        let short =
            base64::engine::general_purpose::STANDARD.encode([0x11_u8; SIGNATURE_LENGTH - 1]);
        let input = format!("\"{short}\"");
        let err = deserialize_signed_data(&DutyType::Signature, input.as_bytes()).unwrap_err();
        assert!(
            matches!(err, ParSigExCodecError::InvalidSignature(_)),
            "expected InvalidSignature error, got {err:?}"
        );
    }
}
