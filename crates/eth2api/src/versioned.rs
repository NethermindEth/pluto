//! Versioned wrappers and version enums used by signeddata flows.

use serde::{Deserialize, Serialize};

pub use crate::spec::{BuilderVersion, DataVersion};
use crate::{
    spec::{altair, bellatrix, capella, deneb, electra, fulu, phase0},
    v1,
};

/// Signed proposal wrapper across all supported forks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionedSignedProposal {
    /// Fork version of the payload.
    pub version: DataVersion,
    /// True if this proposal is blinded.
    pub blinded: bool,
    /// Proposal payload selected by version and blinded mode.
    pub block: Option<SignedProposalBlock>,
}

/// Signed proposal payload across all supported forks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignedProposalBlock {
    /// Phase0 proposal payload.
    Phase0(phase0::SignedBeaconBlock),
    /// Altair proposal payload.
    Altair(altair::SignedBeaconBlock),
    /// Bellatrix proposal payload.
    Bellatrix(bellatrix::SignedBeaconBlock),
    /// Bellatrix blinded proposal payload.
    BellatrixBlinded(bellatrix::SignedBlindedBeaconBlock),
    /// Capella proposal payload.
    Capella(capella::SignedBeaconBlock),
    /// Capella blinded proposal payload.
    CapellaBlinded(capella::SignedBlindedBeaconBlock),
    /// Deneb proposal payload.
    Deneb(deneb::SignedBlockContents),
    /// Deneb blinded proposal payload.
    DenebBlinded(deneb::SignedBlindedBeaconBlock),
    /// Electra proposal payload.
    Electra(electra::SignedBlockContents),
    /// Electra blinded proposal payload.
    ElectraBlinded(electra::SignedBlindedBeaconBlock),
    /// Fulu proposal payload.
    Fulu(fulu::SignedBlockContents),
    /// Fulu blinded proposal payload.
    FuluBlinded(electra::SignedBlindedBeaconBlock),
}

impl SignedProposalBlock {
    /// Returns the BLS signature embedded in this payload.
    pub fn signature(&self) -> phase0::BLSSignature {
        match self {
            Self::Phase0(block) => block.signature,
            Self::Altair(block) => block.signature,
            Self::Bellatrix(block) => block.signature,
            Self::BellatrixBlinded(block) => block.signature,
            Self::Capella(block) => block.signature,
            Self::CapellaBlinded(block) => block.signature,
            Self::Deneb(block) => block.signed_block.signature,
            Self::DenebBlinded(block) => block.signature,
            Self::Electra(block) => block.signed_block.signature,
            Self::ElectraBlinded(block) => block.signature,
            Self::Fulu(block) => block.signed_block.signature,
            Self::FuluBlinded(block) => block.signature,
        }
    }

    /// Sets the BLS signature embedded in this payload.
    pub fn set_signature(&mut self, signature: phase0::BLSSignature) {
        match self {
            Self::Phase0(block) => block.signature = signature,
            Self::Altair(block) => block.signature = signature,
            Self::Bellatrix(block) => block.signature = signature,
            Self::BellatrixBlinded(block) => block.signature = signature,
            Self::Capella(block) => block.signature = signature,
            Self::CapellaBlinded(block) => block.signature = signature,
            Self::Deneb(block) => block.signed_block.signature = signature,
            Self::DenebBlinded(block) => block.signature = signature,
            Self::Electra(block) => block.signed_block.signature = signature,
            Self::ElectraBlinded(block) => block.signature = signature,
            Self::Fulu(block) => block.signed_block.signature = signature,
            Self::FuluBlinded(block) => block.signature = signature,
        }
    }

    /// Converts blinded payload variants into blinded-wrapper payloads.
    pub fn into_blinded(self) -> Option<SignedBlindedProposalBlock> {
        match self {
            Self::BellatrixBlinded(block) => Some(SignedBlindedProposalBlock::Bellatrix(block)),
            Self::CapellaBlinded(block) => Some(SignedBlindedProposalBlock::Capella(block)),
            Self::DenebBlinded(block) => Some(SignedBlindedProposalBlock::Deneb(block)),
            Self::ElectraBlinded(block) => Some(SignedBlindedProposalBlock::Electra(block)),
            Self::FuluBlinded(block) => Some(SignedBlindedProposalBlock::Fulu(block)),
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_)
            | Self::Electra(_)
            | Self::Fulu(_) => None,
        }
    }
}

/// Signed blinded proposal wrapper across all supported forks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionedSignedBlindedProposal {
    /// Fork version of the payload.
    pub version: DataVersion,
    /// Blinded proposal payload selected by version.
    pub block: Option<SignedBlindedProposalBlock>,
}

/// Signed blinded proposal payload across all supported forks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignedBlindedProposalBlock {
    /// Bellatrix blinded proposal payload.
    Bellatrix(bellatrix::SignedBlindedBeaconBlock),
    /// Capella blinded proposal payload.
    Capella(capella::SignedBlindedBeaconBlock),
    /// Deneb blinded proposal payload.
    Deneb(deneb::SignedBlindedBeaconBlock),
    /// Electra blinded proposal payload.
    Electra(electra::SignedBlindedBeaconBlock),
    /// Fulu blinded proposal payload.
    Fulu(electra::SignedBlindedBeaconBlock),
}

impl SignedBlindedProposalBlock {
    /// Converts blinded-wrapper payloads into signed proposal payloads.
    pub fn into_signed(self) -> SignedProposalBlock {
        match self {
            Self::Bellatrix(block) => SignedProposalBlock::BellatrixBlinded(block),
            Self::Capella(block) => SignedProposalBlock::CapellaBlinded(block),
            Self::Deneb(block) => SignedProposalBlock::DenebBlinded(block),
            Self::Electra(block) => SignedProposalBlock::ElectraBlinded(block),
            Self::Fulu(block) => SignedProposalBlock::FuluBlinded(block),
        }
    }
}

/// Versioned attestation wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionedAttestation {
    /// Fork version of the payload.
    pub version: DataVersion,
    /// Optional validator index associated with the attestation.
    pub validator_index: Option<phase0::ValidatorIndex>,
    /// Attestation payload selected by version.
    pub attestation: Option<AttestationPayload>,
}

/// Attestation payload across all supported forks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttestationPayload {
    /// Phase0 attestation payload.
    Phase0(phase0::Attestation),
    /// Altair attestation payload.
    Altair(phase0::Attestation),
    /// Bellatrix attestation payload.
    Bellatrix(phase0::Attestation),
    /// Capella attestation payload.
    Capella(phase0::Attestation),
    /// Deneb attestation payload.
    Deneb(phase0::Attestation),
    /// Electra attestation payload.
    Electra(electra::Attestation),
    /// Fulu attestation payload.
    Fulu(electra::Attestation),
}

impl AttestationPayload {
    /// Returns the BLS signature embedded in this payload.
    pub fn signature(&self) -> phase0::BLSSignature {
        match self {
            Self::Phase0(attestation)
            | Self::Altair(attestation)
            | Self::Bellatrix(attestation)
            | Self::Capella(attestation)
            | Self::Deneb(attestation) => attestation.signature,
            Self::Electra(attestation) | Self::Fulu(attestation) => attestation.signature,
        }
    }

    /// Sets the BLS signature embedded in this payload.
    pub fn set_signature(&mut self, signature: phase0::BLSSignature) {
        match self {
            Self::Phase0(attestation)
            | Self::Altair(attestation)
            | Self::Bellatrix(attestation)
            | Self::Capella(attestation)
            | Self::Deneb(attestation) => attestation.signature = signature,
            Self::Electra(attestation) | Self::Fulu(attestation) => {
                attestation.signature = signature
            }
        }
    }

    /// Returns the attestation data embedded in this payload.
    pub fn data(&self) -> &phase0::AttestationData {
        match self {
            Self::Phase0(attestation)
            | Self::Altair(attestation)
            | Self::Bellatrix(attestation)
            | Self::Capella(attestation)
            | Self::Deneb(attestation) => &attestation.data,
            Self::Electra(attestation) | Self::Fulu(attestation) => &attestation.data,
        }
    }

    /// Returns aggregation bits for this payload.
    pub fn aggregation_bits(&self) -> Vec<u8> {
        let bytes = match self {
            Self::Phase0(attestation)
            | Self::Altair(attestation)
            | Self::Bellatrix(attestation)
            | Self::Capella(attestation)
            | Self::Deneb(attestation) => attestation.aggregation_bits.clone().into_bytes(),
            Self::Electra(attestation) | Self::Fulu(attestation) => {
                attestation.aggregation_bits.clone().into_bytes()
            }
        };

        bytes.to_vec()
    }
}

/// Versioned signed aggregate-and-proof wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionedSignedAggregateAndProof {
    /// Fork version of the payload.
    pub version: DataVersion,
    /// Signed aggregate-and-proof payload selected by version.
    pub aggregate_and_proof: Option<SignedAggregateAndProofPayload>,
}

/// Signed aggregate-and-proof payload across all supported forks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignedAggregateAndProofPayload {
    /// Phase0 payload.
    Phase0(phase0::SignedAggregateAndProof),
    /// Altair payload.
    Altair(phase0::SignedAggregateAndProof),
    /// Bellatrix payload.
    Bellatrix(phase0::SignedAggregateAndProof),
    /// Capella payload.
    Capella(phase0::SignedAggregateAndProof),
    /// Deneb payload.
    Deneb(phase0::SignedAggregateAndProof),
    /// Electra payload.
    Electra(electra::SignedAggregateAndProof),
    /// Fulu payload.
    Fulu(electra::SignedAggregateAndProof),
}

impl SignedAggregateAndProofPayload {
    /// Returns the BLS signature embedded in this payload.
    pub fn signature(&self) -> phase0::BLSSignature {
        match self {
            Self::Phase0(payload)
            | Self::Altair(payload)
            | Self::Bellatrix(payload)
            | Self::Capella(payload)
            | Self::Deneb(payload) => payload.signature,
            Self::Electra(payload) | Self::Fulu(payload) => payload.signature,
        }
    }

    /// Sets the BLS signature embedded in this payload.
    pub fn set_signature(&mut self, signature: phase0::BLSSignature) {
        match self {
            Self::Phase0(payload)
            | Self::Altair(payload)
            | Self::Bellatrix(payload)
            | Self::Capella(payload)
            | Self::Deneb(payload) => payload.signature = signature,
            Self::Electra(payload) | Self::Fulu(payload) => payload.signature = signature,
        }
    }

    /// Returns the attestation data embedded in this payload.
    pub fn data(&self) -> &phase0::AttestationData {
        match self {
            Self::Phase0(payload)
            | Self::Altair(payload)
            | Self::Bellatrix(payload)
            | Self::Capella(payload)
            | Self::Deneb(payload) => &payload.message.aggregate.data,
            Self::Electra(payload) | Self::Fulu(payload) => &payload.message.aggregate.data,
        }
    }

    /// Returns aggregation bits for this payload.
    pub fn aggregation_bits(&self) -> Vec<u8> {
        let bytes = match self {
            Self::Phase0(payload)
            | Self::Altair(payload)
            | Self::Bellatrix(payload)
            | Self::Capella(payload)
            | Self::Deneb(payload) => payload
                .message
                .aggregate
                .aggregation_bits
                .clone()
                .into_bytes(),
            Self::Electra(payload) | Self::Fulu(payload) => payload
                .message
                .aggregate
                .aggregation_bits
                .clone()
                .into_bytes(),
        };

        bytes.to_vec()
    }
}

/// Versioned signed validator registration wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VersionedSignedValidatorRegistration {
    /// Builder API version of the payload.
    pub version: BuilderVersion,
    /// V1 payload.
    pub v1: Option<v1::SignedValidatorRegistration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_version_serde_uses_spec_strings() {
        assert_eq!(
            serde_json::to_string(&DataVersion::Phase0).expect("serialize phase0"),
            "\"phase0\""
        );
        assert_eq!(
            serde_json::to_string(&DataVersion::Fulu).expect("serialize fulu"),
            "\"fulu\""
        );

        let deneb: DataVersion = serde_json::from_str("\"deneb\"").expect("deserialize deneb");
        assert_eq!(deneb, DataVersion::Deneb);

        let err =
            serde_json::from_str::<DataVersion>("\"unknown-fork\"").expect_err("invalid version");
        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn builder_version_serde_uses_spec_strings() {
        assert_eq!(
            serde_json::to_string(&BuilderVersion::V1).expect("serialize v1"),
            "\"v1\""
        );

        let v1: BuilderVersion = serde_json::from_str("\"v1\"").expect("deserialize v1");
        assert_eq!(v1, BuilderVersion::V1);

        let err =
            serde_json::from_str::<BuilderVersion>("\"v2\"").expect_err("invalid builder version");
        assert!(err.to_string().contains("unknown variant"));
    }
}
