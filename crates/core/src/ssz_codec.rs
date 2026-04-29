//! SSZ binary encode/decode for SignedData types, matching Charon's
//! `marshal`/`unmarshal` behaviour.
//!
//! Charon serializes SSZ-capable types using SSZ binary encoding with custom
//! headers for versioned types. JSON-only types are handled elsewhere (see
//! [`parsigex_codec`](super::parsigex_codec)).

use pluto_eth2api::{
    spec::{altair, bellatrix, capella, deneb, electra, fulu, phase0},
    versioned::{self, AttestationPayload, DataVersion, SignedAggregateAndProofPayload},
};
use pluto_ssz::{
    decode::{decode_u32, decode_u64},
    encode::{encode_u32, encode_u64},
};
use ssz::{Decode, Encode};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Error type for SSZ codec operations.
#[derive(Debug, thiserror::Error)]
pub enum SszCodecError {
    /// Byte slice is too short.
    #[error("ssz too short: need {need} bytes, got {got}")]
    TooShort {
        /// Minimum required bytes.
        need: usize,
        /// Actual bytes available.
        got: usize,
    },
    /// An offset field has an unexpected value.
    #[error("ssz invalid offset: expected {expected}, got {got}")]
    InvalidOffset {
        /// Expected offset value.
        expected: u32,
        /// Actual offset value.
        got: u32,
    },
    /// Unknown or unsupported data version.
    #[error("ssz unknown version: {0}")]
    UnknownVersion(u64),
    /// Inner SSZ binary decoding failed.
    #[error("ssz decode: {0}")]
    Decode(String),
}

impl From<pluto_ssz::SszBinaryError> for SszCodecError {
    fn from(e: pluto_ssz::SszBinaryError) -> Self {
        Self::Decode(e.to_string())
    }
}

impl From<ssz::DecodeError> for SszCodecError {
    fn from(e: ssz::DecodeError) -> Self {
        Self::Decode(format!("{e:?}"))
    }
}

fn require(bytes: &[u8], need: usize) -> Result<(), SszCodecError> {
    if bytes.len() < need {
        Err(SszCodecError::TooShort {
            need,
            got: bytes.len(),
        })
    } else {
        Ok(())
    }
}

// ===========================================================================
// Non-versioned SSZ-capable types
// ===========================================================================

// Using ethereum_ssz derived Encode/Decode: just delegate to `as_ssz_bytes`
// and `from_ssz_bytes`.

/// Encodes a `phase0::Attestation` to SSZ binary.
pub fn encode_phase0_attestation(att: &phase0::Attestation) -> Result<Vec<u8>, SszCodecError> {
    Ok(att.as_ssz_bytes())
}

/// Decodes a `phase0::Attestation` from SSZ binary.
pub fn decode_phase0_attestation(bytes: &[u8]) -> Result<phase0::Attestation, SszCodecError> {
    Ok(phase0::Attestation::from_ssz_bytes(bytes)?)
}

/// Encodes a `phase0::SignedAggregateAndProof` to SSZ binary.
pub fn encode_phase0_signed_aggregate_and_proof(
    sap: &phase0::SignedAggregateAndProof,
) -> Result<Vec<u8>, SszCodecError> {
    Ok(sap.as_ssz_bytes())
}

/// Decodes a `phase0::SignedAggregateAndProof` from SSZ binary.
pub fn decode_phase0_signed_aggregate_and_proof(
    bytes: &[u8],
) -> Result<phase0::SignedAggregateAndProof, SszCodecError> {
    Ok(phase0::SignedAggregateAndProof::from_ssz_bytes(bytes)?)
}

/// Encodes an `altair::SyncCommitteeMessage` to SSZ binary.
pub fn encode_sync_committee_message(
    msg: &altair::SyncCommitteeMessage,
) -> Result<Vec<u8>, SszCodecError> {
    Ok(msg.as_ssz_bytes())
}

/// Decodes an `altair::SyncCommitteeMessage` from SSZ binary.
pub fn decode_sync_committee_message(
    bytes: &[u8],
) -> Result<altair::SyncCommitteeMessage, SszCodecError> {
    Ok(altair::SyncCommitteeMessage::from_ssz_bytes(bytes)?)
}

/// Encodes an `altair::ContributionAndProof` to SSZ binary.
pub fn encode_contribution_and_proof(
    cap: &altair::ContributionAndProof,
) -> Result<Vec<u8>, SszCodecError> {
    Ok(cap.as_ssz_bytes())
}

/// Decodes an `altair::ContributionAndProof` from SSZ binary.
#[cfg(test)]
pub fn decode_contribution_and_proof(
    bytes: &[u8],
) -> Result<altair::ContributionAndProof, SszCodecError> {
    Ok(altair::ContributionAndProof::from_ssz_bytes(bytes)?)
}

/// Encodes an `altair::SignedContributionAndProof` to SSZ binary.
pub fn encode_signed_contribution_and_proof(
    scp: &altair::SignedContributionAndProof,
) -> Result<Vec<u8>, SszCodecError> {
    Ok(scp.as_ssz_bytes())
}

/// Decodes an `altair::SignedContributionAndProof` from SSZ binary.
pub fn decode_signed_contribution_and_proof(
    bytes: &[u8],
) -> Result<altair::SignedContributionAndProof, SszCodecError> {
    Ok(altair::SignedContributionAndProof::from_ssz_bytes(bytes)?)
}

// ===========================================================================
// Versioned type helpers
// ===========================================================================

fn encode_version(version: DataVersion) -> Result<[u8; 8], SszCodecError> {
    version
        .to_legacy_u64()
        .map(encode_u64)
        .map_err(|_| SszCodecError::Decode(format!("unsupported data version: {version}")))
}

fn decode_version(bytes: &[u8]) -> Result<DataVersion, SszCodecError> {
    let raw = decode_u64(bytes)?;
    DataVersion::from_legacy_u64(raw).map_err(|_| SszCodecError::UnknownVersion(raw))
}

// ---------------------------------------------------------------------------
// VersionedAttestation
// Two header formats (Charon added validator_index in a later version):
//   - Without validator_index: version(8) + offset(4) = 12 bytes
//   - With validator_index:    version(8) + validator_index(8) + offset(4) = 20
//     bytes
// ---------------------------------------------------------------------------

const VERSIONED_ATTESTATION_VAL_IDX_HEADER: u32 = 20;

/// Encodes a `VersionedAttestation` to SSZ binary with Charon versioned
/// header. Uses the 20-byte header when `validator_index` is set, otherwise
/// falls back to the legacy 12-byte header.
pub fn encode_versioned_attestation(
    va: &versioned::VersionedAttestation,
) -> Result<Vec<u8>, SszCodecError> {
    let version = encode_version(va.version)?;
    let inner = encode_attestation_payload(va.attestation.as_ref())?;

    if let Some(val_idx) = va.validator_index {
        let mut buf =
            Vec::with_capacity(VERSIONED_ATTESTATION_VAL_IDX_HEADER as usize + inner.len());
        buf.extend_from_slice(&version);
        buf.extend_from_slice(&encode_u64(val_idx));
        buf.extend_from_slice(&encode_u32(VERSIONED_ATTESTATION_VAL_IDX_HEADER));
        buf.extend_from_slice(&inner);
        Ok(buf)
    } else {
        let mut buf = Vec::with_capacity(VERSIONED_SIGNED_AGGREGATE_HEADER as usize + inner.len());
        buf.extend_from_slice(&version);
        buf.extend_from_slice(&encode_u32(VERSIONED_SIGNED_AGGREGATE_HEADER));
        buf.extend_from_slice(&inner);
        Ok(buf)
    }
}

/// Decodes a `VersionedAttestation` from SSZ binary with Charon versioned
/// header. Tries the 20-byte validator_index format first, falling back to the
/// legacy 12-byte format when the offset field doesn't match.
pub fn decode_versioned_attestation(
    bytes: &[u8],
) -> Result<versioned::VersionedAttestation, SszCodecError> {
    match try_decode_versioned_attestation_with_val_idx(bytes) {
        Ok(result) => return Ok(result),
        Err(SszCodecError::InvalidOffset { .. }) => {}
        Err(e) => return Err(e),
    }
    decode_versioned_attestation_no_val_idx(bytes)
}

fn try_decode_versioned_attestation_with_val_idx(
    bytes: &[u8],
) -> Result<versioned::VersionedAttestation, SszCodecError> {
    require(bytes, VERSIONED_ATTESTATION_VAL_IDX_HEADER as usize)?;
    let version = decode_version(&bytes[0..8])?;
    let val_idx = decode_u64(&bytes[8..16])?;
    let offset = decode_u32(&bytes[16..20])?;
    if offset != VERSIONED_ATTESTATION_VAL_IDX_HEADER {
        return Err(SszCodecError::InvalidOffset {
            expected: VERSIONED_ATTESTATION_VAL_IDX_HEADER,
            got: offset,
        });
    }
    let inner = &bytes[VERSIONED_ATTESTATION_VAL_IDX_HEADER as usize..];
    let attestation = decode_attestation_payload(version, inner)?;
    Ok(versioned::VersionedAttestation {
        version,
        validator_index: Some(val_idx),
        attestation: Some(attestation),
    })
}

fn decode_versioned_attestation_no_val_idx(
    bytes: &[u8],
) -> Result<versioned::VersionedAttestation, SszCodecError> {
    require(bytes, VERSIONED_SIGNED_AGGREGATE_HEADER as usize)?;
    let version = decode_version(&bytes[0..8])?;
    let offset = decode_u32(&bytes[8..12])?;
    if offset != VERSIONED_SIGNED_AGGREGATE_HEADER {
        return Err(SszCodecError::InvalidOffset {
            expected: VERSIONED_SIGNED_AGGREGATE_HEADER,
            got: offset,
        });
    }
    let inner = &bytes[VERSIONED_SIGNED_AGGREGATE_HEADER as usize..];
    let attestation = decode_attestation_payload(version, inner)?;
    Ok(versioned::VersionedAttestation {
        version,
        validator_index: None,
        attestation: Some(attestation),
    })
}

fn encode_attestation_payload(
    attestation: Option<&AttestationPayload>,
) -> Result<Vec<u8>, SszCodecError> {
    match attestation {
        Some(
            AttestationPayload::Phase0(att)
            | AttestationPayload::Altair(att)
            | AttestationPayload::Bellatrix(att)
            | AttestationPayload::Capella(att)
            | AttestationPayload::Deneb(att),
        ) => Ok(att.as_ssz_bytes()),
        Some(AttestationPayload::Electra(att) | AttestationPayload::Fulu(att)) => {
            Ok(att.as_ssz_bytes())
        }
        None => Err(SszCodecError::Decode(
            "missing attestation payload".to_string(),
        )),
    }
}

fn decode_attestation_payload(
    version: DataVersion,
    inner: &[u8],
) -> Result<AttestationPayload, SszCodecError> {
    match version {
        DataVersion::Phase0 => Ok(AttestationPayload::Phase0(
            phase0::Attestation::from_ssz_bytes(inner)?,
        )),
        DataVersion::Altair => Ok(AttestationPayload::Altair(
            phase0::Attestation::from_ssz_bytes(inner)?,
        )),
        DataVersion::Bellatrix => Ok(AttestationPayload::Bellatrix(
            phase0::Attestation::from_ssz_bytes(inner)?,
        )),
        DataVersion::Capella => Ok(AttestationPayload::Capella(
            phase0::Attestation::from_ssz_bytes(inner)?,
        )),
        DataVersion::Deneb => Ok(AttestationPayload::Deneb(
            phase0::Attestation::from_ssz_bytes(inner)?,
        )),
        DataVersion::Electra => Ok(AttestationPayload::Electra(
            electra::Attestation::from_ssz_bytes(inner)?,
        )),
        DataVersion::Fulu => Ok(AttestationPayload::Fulu(
            electra::Attestation::from_ssz_bytes(inner)?,
        )),
        DataVersion::Unknown => Err(SszCodecError::UnknownVersion(0)),
    }
}

// ---------------------------------------------------------------------------
// VersionedSignedAggregateAndProof
// Header: version(8) + offset(4) = 12 bytes
// ---------------------------------------------------------------------------

const VERSIONED_SIGNED_AGGREGATE_HEADER: u32 = 12;

/// Encodes a `VersionedSignedAggregateAndProof` to SSZ binary with Charon
/// versioned header.
pub fn encode_versioned_signed_aggregate_and_proof(
    va: &versioned::VersionedSignedAggregateAndProof,
) -> Result<Vec<u8>, SszCodecError> {
    let version = encode_version(va.version)?;
    let inner = match &va.aggregate_and_proof {
        SignedAggregateAndProofPayload::Phase0(p)
        | SignedAggregateAndProofPayload::Altair(p)
        | SignedAggregateAndProofPayload::Bellatrix(p)
        | SignedAggregateAndProofPayload::Capella(p)
        | SignedAggregateAndProofPayload::Deneb(p) => p.as_ssz_bytes(),
        SignedAggregateAndProofPayload::Electra(p) | SignedAggregateAndProofPayload::Fulu(p) => {
            p.as_ssz_bytes()
        }
    };

    let mut buf = Vec::with_capacity(VERSIONED_SIGNED_AGGREGATE_HEADER as usize + inner.len());
    buf.extend_from_slice(&version);
    buf.extend_from_slice(&encode_u32(VERSIONED_SIGNED_AGGREGATE_HEADER));
    buf.extend_from_slice(&inner);
    Ok(buf)
}

/// Decodes a `VersionedSignedAggregateAndProof` from SSZ binary with Charon
/// versioned header.
pub fn decode_versioned_signed_aggregate_and_proof(
    bytes: &[u8],
) -> Result<versioned::VersionedSignedAggregateAndProof, SszCodecError> {
    require(bytes, VERSIONED_SIGNED_AGGREGATE_HEADER as usize)?;
    let version = decode_version(&bytes[0..8])?;
    let offset = decode_u32(&bytes[8..12])?;
    if offset != VERSIONED_SIGNED_AGGREGATE_HEADER {
        return Err(SszCodecError::InvalidOffset {
            expected: VERSIONED_SIGNED_AGGREGATE_HEADER,
            got: offset,
        });
    }

    let inner = &bytes[VERSIONED_SIGNED_AGGREGATE_HEADER as usize..];
    let payload = match version {
        DataVersion::Phase0 => SignedAggregateAndProofPayload::Phase0(
            phase0::SignedAggregateAndProof::from_ssz_bytes(inner)?,
        ),
        DataVersion::Altair => SignedAggregateAndProofPayload::Altair(
            phase0::SignedAggregateAndProof::from_ssz_bytes(inner)?,
        ),
        DataVersion::Bellatrix => SignedAggregateAndProofPayload::Bellatrix(
            phase0::SignedAggregateAndProof::from_ssz_bytes(inner)?,
        ),
        DataVersion::Capella => SignedAggregateAndProofPayload::Capella(
            phase0::SignedAggregateAndProof::from_ssz_bytes(inner)?,
        ),
        DataVersion::Deneb => SignedAggregateAndProofPayload::Deneb(
            phase0::SignedAggregateAndProof::from_ssz_bytes(inner)?,
        ),
        DataVersion::Electra => SignedAggregateAndProofPayload::Electra(
            electra::SignedAggregateAndProof::from_ssz_bytes(inner)?,
        ),
        DataVersion::Fulu => SignedAggregateAndProofPayload::Fulu(
            electra::SignedAggregateAndProof::from_ssz_bytes(inner)?,
        ),
        DataVersion::Unknown => return Err(SszCodecError::UnknownVersion(0)),
    };

    Ok(versioned::VersionedSignedAggregateAndProof {
        version,
        aggregate_and_proof: payload,
    })
}

// ---------------------------------------------------------------------------
// VersionedSignedProposal
// Header: version(8) + blinded(1) + offset(4) = 13 bytes
// ---------------------------------------------------------------------------

const VERSIONED_SIGNED_PROPOSAL_HEADER: u32 = 13;

/// Encodes a `VersionedSignedProposal` to SSZ binary with Charon versioned
/// header.
pub fn encode_versioned_signed_proposal(
    vp: &versioned::VersionedSignedProposal,
) -> Result<Vec<u8>, SszCodecError> {
    let version = encode_version(vp.version)?;
    let blinded: u8 = u8::from(vp.blinded);
    let inner = encode_proposal_block(&vp.block)?;

    let mut buf = Vec::with_capacity(VERSIONED_SIGNED_PROPOSAL_HEADER as usize + inner.len());
    buf.extend_from_slice(&version);
    buf.push(blinded);
    buf.extend_from_slice(&encode_u32(VERSIONED_SIGNED_PROPOSAL_HEADER));
    buf.extend_from_slice(&inner);
    Ok(buf)
}

/// Decodes a `VersionedSignedProposal` from SSZ binary with Charon versioned
/// header.
pub fn decode_versioned_signed_proposal(
    bytes: &[u8],
) -> Result<versioned::VersionedSignedProposal, SszCodecError> {
    require(bytes, VERSIONED_SIGNED_PROPOSAL_HEADER as usize)?;
    let version = decode_version(&bytes[0..8])?;
    let blinded = bytes[8] != 0;
    let offset = decode_u32(&bytes[9..13])?;
    if offset != VERSIONED_SIGNED_PROPOSAL_HEADER {
        return Err(SszCodecError::InvalidOffset {
            expected: VERSIONED_SIGNED_PROPOSAL_HEADER,
            got: offset,
        });
    }

    let inner = &bytes[VERSIONED_SIGNED_PROPOSAL_HEADER as usize..];
    let block = decode_proposal_block(version, blinded, inner)?;

    Ok(versioned::VersionedSignedProposal {
        version,
        blinded,
        block,
    })
}

fn encode_proposal_block(block: &versioned::SignedProposalBlock) -> Result<Vec<u8>, SszCodecError> {
    use versioned::SignedProposalBlock;
    Ok(match block {
        SignedProposalBlock::Phase0(b) => b.as_ssz_bytes(),
        SignedProposalBlock::Altair(b) => b.as_ssz_bytes(),
        SignedProposalBlock::Bellatrix(b) => b.as_ssz_bytes(),
        SignedProposalBlock::BellatrixBlinded(b) => b.as_ssz_bytes(),
        SignedProposalBlock::Capella(b) => b.as_ssz_bytes(),
        SignedProposalBlock::CapellaBlinded(b) => b.as_ssz_bytes(),
        SignedProposalBlock::Deneb(b) => b.as_ssz_bytes(),
        SignedProposalBlock::DenebBlinded(b) => b.as_ssz_bytes(),
        SignedProposalBlock::Electra(b) => b.as_ssz_bytes(),
        SignedProposalBlock::ElectraBlinded(b) => b.as_ssz_bytes(),
        SignedProposalBlock::Fulu(b) => b.as_ssz_bytes(),
        SignedProposalBlock::FuluBlinded(b) => b.as_ssz_bytes(),
    })
}

fn decode_proposal_block(
    version: DataVersion,
    blinded: bool,
    bytes: &[u8],
) -> Result<versioned::SignedProposalBlock, SszCodecError> {
    use versioned::SignedProposalBlock;
    Ok(match (version, blinded) {
        (DataVersion::Phase0, _) => {
            SignedProposalBlock::Phase0(phase0::SignedBeaconBlock::from_ssz_bytes(bytes)?)
        }
        (DataVersion::Altair, _) => {
            SignedProposalBlock::Altair(altair::SignedBeaconBlock::from_ssz_bytes(bytes)?)
        }
        (DataVersion::Bellatrix, false) => {
            SignedProposalBlock::Bellatrix(bellatrix::SignedBeaconBlock::from_ssz_bytes(bytes)?)
        }
        (DataVersion::Bellatrix, true) => SignedProposalBlock::BellatrixBlinded(
            bellatrix::SignedBlindedBeaconBlock::from_ssz_bytes(bytes)?,
        ),
        (DataVersion::Capella, false) => {
            SignedProposalBlock::Capella(capella::SignedBeaconBlock::from_ssz_bytes(bytes)?)
        }
        (DataVersion::Capella, true) => SignedProposalBlock::CapellaBlinded(
            capella::SignedBlindedBeaconBlock::from_ssz_bytes(bytes)?,
        ),
        (DataVersion::Deneb, false) => {
            SignedProposalBlock::Deneb(deneb::SignedBlockContents::from_ssz_bytes(bytes)?)
        }
        (DataVersion::Deneb, true) => SignedProposalBlock::DenebBlinded(
            deneb::SignedBlindedBeaconBlock::from_ssz_bytes(bytes)?,
        ),
        (DataVersion::Electra, false) => {
            SignedProposalBlock::Electra(electra::SignedBlockContents::from_ssz_bytes(bytes)?)
        }
        (DataVersion::Electra, true) => SignedProposalBlock::ElectraBlinded(
            electra::SignedBlindedBeaconBlock::from_ssz_bytes(bytes)?,
        ),
        (DataVersion::Fulu, false) => {
            SignedProposalBlock::Fulu(fulu::SignedBlockContents::from_ssz_bytes(bytes)?)
        }
        (DataVersion::Fulu, true) => SignedProposalBlock::FuluBlinded(
            electra::SignedBlindedBeaconBlock::from_ssz_bytes(bytes)?,
        ),
        (DataVersion::Unknown, _) => return Err(SszCodecError::UnknownVersion(0)),
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn roundtrip_phase0_attestation() {
        let att = phase0::Attestation {
            aggregation_bits: BitList::with_bits(16, &[0, 3, 7]),
            data: sample_attestation_data(),
            signature: [0x11; 96],
        };
        let encoded = encode_phase0_attestation(&att).unwrap();
        let decoded = decode_phase0_attestation(&encoded).unwrap();
        assert_eq!(att, decoded);
    }

    #[test]
    fn roundtrip_electra_attestation() {
        let att = electra::Attestation {
            aggregation_bits: BitList::with_bits(32, &[1, 5, 10]),
            data: sample_attestation_data(),
            signature: [0x22; 96],
            committee_bits: BitVector::with_bits(&[0, 3]),
        };
        let encoded = att.as_ssz_bytes();
        let decoded = electra::Attestation::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(att, decoded);
    }

    #[test]
    fn roundtrip_phase0_signed_aggregate_and_proof() {
        let sap = phase0::SignedAggregateAndProof {
            message: phase0::AggregateAndProof {
                aggregator_index: 99,
                aggregate: phase0::Attestation {
                    aggregation_bits: BitList::with_bits(8, &[2, 4]),
                    data: sample_attestation_data(),
                    signature: [0x33; 96],
                },
                selection_proof: [0x44; 96],
            },
            signature: [0x55; 96],
        };
        let encoded = encode_phase0_signed_aggregate_and_proof(&sap).unwrap();
        let decoded = decode_phase0_signed_aggregate_and_proof(&encoded).unwrap();
        assert_eq!(sap, decoded);
    }

    #[test]
    fn roundtrip_sync_committee_message() {
        let msg = altair::SyncCommitteeMessage {
            slot: 100,
            beacon_block_root: [0xdd; 32],
            validator_index: 50,
            signature: [0xee; 96],
        };
        let encoded = encode_sync_committee_message(&msg).unwrap();
        let decoded = decode_sync_committee_message(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_contribution_and_proof() {
        let cap = altair::ContributionAndProof {
            aggregator_index: 33,
            contribution: altair::SyncCommitteeContribution {
                slot: 200,
                beacon_block_root: [0xab; 32],
                subcommittee_index: 2,
                aggregation_bits: BitVector::with_bits(&[0, 5]),
                signature: [0xcd; 96],
            },
            selection_proof: [0xef; 96],
        };
        let encoded = encode_contribution_and_proof(&cap).unwrap();
        let decoded = decode_contribution_and_proof(&encoded).unwrap();
        assert_eq!(cap, decoded);
    }

    #[test]
    fn roundtrip_signed_contribution_and_proof() {
        let scp = altair::SignedContributionAndProof {
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
        };
        let encoded = encode_signed_contribution_and_proof(&scp).unwrap();
        let decoded = decode_signed_contribution_and_proof(&encoded).unwrap();
        assert_eq!(scp, decoded);
    }

    #[test]
    fn roundtrip_versioned_attestation_phase0() {
        let va = versioned::VersionedAttestation {
            version: DataVersion::Phase0,
            validator_index: None,
            attestation: Some(AttestationPayload::Phase0(phase0::Attestation {
                aggregation_bits: BitList::with_bits(8, &[1, 3]),
                data: sample_attestation_data(),
                signature: [0x11; 96],
            })),
        };
        let encoded = encode_versioned_attestation(&va).unwrap();
        let decoded = decode_versioned_attestation(&encoded).unwrap();
        assert_eq!(va, decoded);
    }

    #[test]
    fn roundtrip_versioned_attestation_with_validator_index() {
        let va = versioned::VersionedAttestation {
            version: DataVersion::Phase0,
            validator_index: Some(7),
            attestation: Some(AttestationPayload::Phase0(phase0::Attestation {
                aggregation_bits: BitList::with_bits(8, &[1, 3]),
                data: sample_attestation_data(),
                signature: [0x11; 96],
            })),
        };
        let encoded = encode_versioned_attestation(&va).unwrap();
        let decoded = decode_versioned_attestation(&encoded).unwrap();
        assert_eq!(va, decoded);
    }

    #[test]
    fn roundtrip_versioned_attestation_electra() {
        let va = versioned::VersionedAttestation {
            version: DataVersion::Electra,
            validator_index: None,
            attestation: Some(AttestationPayload::Electra(electra::Attestation {
                aggregation_bits: BitList::with_bits(16, &[0, 4]),
                data: sample_attestation_data(),
                signature: [0x22; 96],
                committee_bits: BitVector::with_bits(&[1]),
            })),
        };
        let encoded = encode_versioned_attestation(&va).unwrap();
        let decoded = decode_versioned_attestation(&encoded).unwrap();
        assert_eq!(va, decoded);
    }

    #[test]
    fn roundtrip_versioned_signed_aggregate_phase0() {
        let va = versioned::VersionedSignedAggregateAndProof {
            version: DataVersion::Phase0,
            aggregate_and_proof: SignedAggregateAndProofPayload::Phase0(
                phase0::SignedAggregateAndProof {
                    message: phase0::AggregateAndProof {
                        aggregator_index: 55,
                        aggregate: phase0::Attestation {
                            aggregation_bits: BitList::with_bits(4, &[0]),
                            data: sample_attestation_data(),
                            signature: [0xaa; 96],
                        },
                        selection_proof: [0xbb; 96],
                    },
                    signature: [0xcc; 96],
                },
            ),
        };
        let encoded = encode_versioned_signed_aggregate_and_proof(&va).unwrap();
        let decoded = decode_versioned_signed_aggregate_and_proof(&encoded).unwrap();
        assert_eq!(va, decoded);
    }

    #[test]
    fn roundtrip_versioned_signed_proposal_phase0() {
        let block = phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot: 1,
                proposer_index: 2,
                parent_root: [0x11; 32],
                state_root: [0x22; 32],
                body: phase0::BeaconBlockBody {
                    randao_reveal: [0x33; 96],
                    eth1_data: phase0::ETH1Data {
                        deposit_root: [0x44; 32],
                        deposit_count: 0,
                        block_hash: [0x55; 32],
                    },
                    graffiti: [0x66; 32],
                    proposer_slashings: vec![].into(),
                    attester_slashings: vec![].into(),
                    attestations: vec![].into(),
                    deposits: vec![].into(),
                    voluntary_exits: vec![].into(),
                },
            },
            signature: [0x77; 96],
        };
        let vp = versioned::VersionedSignedProposal {
            version: DataVersion::Phase0,
            blinded: false,
            block: versioned::SignedProposalBlock::Phase0(block),
        };
        let encoded = encode_versioned_signed_proposal(&vp).unwrap();
        let decoded = decode_versioned_signed_proposal(&encoded).unwrap();
        assert_eq!(vp, decoded);
    }

    // =======================================================================
    // Go Charon fixture compatibility tests
    // =======================================================================

    /// Reads a hex-encoded SSZ fixture generated by Go Charon.
    fn read_go_fixture(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/testdata/ssz/{}.ssz.hex",
            env!("CARGO_MANIFEST_DIR"),
            name
        );
        let hex_str = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"));
        hex::decode(hex_str.trim()).unwrap_or_else(|e| panic!("invalid hex in {path}: {e}"))
    }

    #[test]
    fn go_fixture_attestation_phase0() {
        let go_bytes = read_go_fixture("attestation_phase0");

        // Decode Go SSZ bytes -> Rust type.
        let decoded = decode_phase0_attestation(&go_bytes).expect("decode Go attestation fixture");

        // Verify fields match expected values.
        assert_eq!(decoded.data.slot, 42);
        assert_eq!(decoded.data.index, 7);
        assert_eq!(decoded.data.beacon_block_root, [0xaa; 32]);
        assert_eq!(decoded.data.source.epoch, 10);
        assert_eq!(decoded.data.target.epoch, 11);
        assert_eq!(decoded.signature, [0x11; 96]);

        // Re-encode and verify byte-for-byte match.
        let rust_bytes = encode_phase0_attestation(&decoded).unwrap();
        assert_eq!(
            rust_bytes, go_bytes,
            "Rust SSZ output must match Go SSZ output"
        );
    }

    #[test]
    fn go_fixture_signed_aggregate_and_proof() {
        let go_bytes = read_go_fixture("signed_aggregate_and_proof");

        let decoded = decode_phase0_signed_aggregate_and_proof(&go_bytes)
            .expect("decode Go signed_aggregate_and_proof fixture");

        assert_eq!(decoded.message.aggregator_index, 99);
        assert_eq!(decoded.signature, [0x55; 96]);
        assert_eq!(decoded.message.selection_proof, [0x44; 96]);
        assert_eq!(decoded.message.aggregate.signature, [0x33; 96]);

        let rust_bytes = encode_phase0_signed_aggregate_and_proof(&decoded).unwrap();
        assert_eq!(
            rust_bytes, go_bytes,
            "Rust SSZ output must match Go SSZ output"
        );
    }

    #[test]
    fn go_fixture_versioned_attestation_phase0() {
        let go_bytes = read_go_fixture("versioned_attestation_phase0");

        let decoded = decode_versioned_attestation(&go_bytes)
            .expect("decode Go versioned_attestation fixture");

        assert_eq!(decoded.version, DataVersion::Phase0);
        assert_eq!(decoded.validator_index, None);
        let att = decoded.attestation.as_ref().unwrap();
        match att {
            AttestationPayload::Phase0(a) => {
                assert_eq!(a.data.slot, 42);
                assert_eq!(a.signature, [0x11; 96]);
            }
            _ => panic!("expected Phase0 attestation"),
        }

        let rust_bytes = encode_versioned_attestation(&decoded).unwrap();
        assert_eq!(
            rust_bytes, go_bytes,
            "Rust SSZ output must match Go SSZ output"
        );
    }

    #[test]
    fn go_fixture_versioned_attestation_phase0_with_validator_index() {
        let go_bytes = read_go_fixture("versioned_attestation_phase0_with_validator_index");

        let decoded = decode_versioned_attestation(&go_bytes)
            .expect("decode Go versioned_attestation_with_validator_index fixture");

        assert_eq!(decoded.version, DataVersion::Phase0);
        assert_eq!(decoded.validator_index, Some(123));
        let att = decoded.attestation.as_ref().unwrap();
        match att {
            AttestationPayload::Phase0(a) => {
                assert_eq!(a.data.slot, 42);
                assert_eq!(a.signature, [0x11; 96]);
            }
            _ => panic!("expected Phase0 attestation"),
        }

        let rust_bytes = encode_versioned_attestation(&decoded).unwrap();
        assert_eq!(
            rust_bytes, go_bytes,
            "Rust SSZ output must match Go SSZ output"
        );
    }

    #[test]
    fn go_fixture_versioned_agg_proof_phase0() {
        let go_bytes = read_go_fixture("versioned_agg_proof_phase0");

        let decoded = decode_versioned_signed_aggregate_and_proof(&go_bytes)
            .expect("decode Go versioned_agg_proof fixture");

        assert_eq!(decoded.version, DataVersion::Phase0);

        let rust_bytes = encode_versioned_signed_aggregate_and_proof(&decoded).unwrap();
        assert_eq!(
            rust_bytes, go_bytes,
            "Rust SSZ output must match Go SSZ output"
        );
    }

    #[test]
    fn go_fixture_versioned_proposal_phase0() {
        let go_bytes = read_go_fixture("versioned_proposal_phase0");

        let decoded = decode_versioned_signed_proposal(&go_bytes)
            .expect("decode Go versioned_proposal fixture");

        assert_eq!(decoded.version, DataVersion::Phase0);
        assert!(!decoded.blinded);

        let rust_bytes = encode_versioned_signed_proposal(&decoded).unwrap();
        assert_eq!(
            rust_bytes, go_bytes,
            "Rust SSZ output must match Go SSZ output"
        );
    }
}
