//! Versioned wrappers and version enums used by signeddata flows.

use alloy::primitives::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use tree_hash::TreeHash;

pub use crate::spec::{BuilderVersion, DataVersion};
use crate::{
    spec::{altair, bellatrix, capella, deneb, electra, fulu, phase0},
    v1,
};

/// Unsigned proposal block across all supported forks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalBlock {
    /// Phase0 beacon block.
    Phase0(phase0::BeaconBlock),
    /// Altair beacon block.
    Altair(altair::BeaconBlock),
    /// Bellatrix beacon block.
    Bellatrix(bellatrix::BeaconBlock),
    /// Bellatrix blinded beacon block.
    BellatrixBlinded(bellatrix::BlindedBeaconBlock),
    /// Capella beacon block.
    Capella(capella::BeaconBlock),
    /// Capella blinded beacon block.
    CapellaBlinded(capella::BlindedBeaconBlock),
    /// Deneb beacon block with KZG proofs and blobs.
    Deneb {
        /// Beacon block.
        block: Box<deneb::BeaconBlock>,
        /// KZG proofs.
        kzg_proofs: Vec<deneb::KZGProof>,
        /// Blobs.
        blobs: Vec<deneb::Blob>,
    },
    /// Deneb blinded beacon block.
    DenebBlinded(deneb::BlindedBeaconBlock),
    /// Electra beacon block with KZG proofs and blobs.
    Electra {
        /// Beacon block.
        block: Box<electra::BeaconBlock>,
        /// KZG proofs.
        kzg_proofs: Vec<deneb::KZGProof>,
        /// Blobs.
        blobs: Vec<deneb::Blob>,
    },
    /// Electra blinded beacon block.
    ElectraBlinded(electra::BlindedBeaconBlock),
    /// Fulu beacon block with KZG proofs and blobs (uses electra block type).
    Fulu {
        /// Beacon block.
        block: Box<electra::BeaconBlock>,
        /// KZG proofs.
        kzg_proofs: Vec<deneb::KZGProof>,
        /// Blobs.
        blobs: Vec<deneb::Blob>,
    },
    /// Fulu blinded beacon block (uses electra block type).
    FuluBlinded(electra::BlindedBeaconBlock),
}

/// Deneb and later unsigned block contents, `{block, kzg_proofs, blobs}`.
/// The lists tolerate `null`.
#[derive(Deserialize)]
struct BlockContents<B> {
    block: B,
    #[serde(default)]
    kzg_proofs: Option<Vec<deneb::KZGProof>>,
    #[serde(default)]
    blobs: Option<Vec<deneb::Blob>>,
}

/// Borrowed form of [`BlockContents`] for serialization.
#[derive(Serialize)]
struct BlockContentsRef<'a, B> {
    block: &'a B,
    kzg_proofs: &'a [deneb::KZGProof],
    blobs: &'a [deneb::Blob],
}

impl<B> BlockContents<B> {
    fn into_parts(self) -> (Box<B>, Vec<deneb::KZGProof>, Vec<deneb::Blob>) {
        (
            Box::new(self.block),
            self.kzg_proofs.unwrap_or_default(),
            self.blobs.unwrap_or_default(),
        )
    }
}

/// The Beacon API JSON form: the bare block, or `{block, kzg_proofs, blobs}`
/// for Deneb and later full blocks.
impl Serialize for ProposalBlock {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        fn contents<S: Serializer, B: Serialize>(
            serializer: S,
            block: &B,
            kzg_proofs: &[deneb::KZGProof],
            blobs: &[deneb::Blob],
        ) -> Result<S::Ok, S::Error> {
            BlockContentsRef {
                block,
                kzg_proofs,
                blobs,
            }
            .serialize(serializer)
        }

        match self {
            Self::Phase0(block) => block.serialize(serializer),
            Self::Altair(block) => block.serialize(serializer),
            Self::Bellatrix(block) => block.serialize(serializer),
            Self::BellatrixBlinded(block) => block.serialize(serializer),
            Self::Capella(block) => block.serialize(serializer),
            Self::CapellaBlinded(block) => block.serialize(serializer),
            Self::DenebBlinded(block) => block.serialize(serializer),
            Self::ElectraBlinded(block) => block.serialize(serializer),
            Self::FuluBlinded(block) => block.serialize(serializer),
            Self::Deneb {
                block,
                kzg_proofs,
                blobs,
            } => contents(serializer, block, kzg_proofs, blobs),
            Self::Electra {
                block,
                kzg_proofs,
                blobs,
            }
            | Self::Fulu {
                block,
                kzg_proofs,
                blobs,
            } => contents(serializer, block, kzg_proofs, blobs),
        }
    }
}

impl ProposalBlock {
    /// Decodes the Beacon API JSON form of a `version` block: the bare block,
    /// or `{block, kzg_proofs, blobs}` for Deneb and later full blocks.
    pub fn from_json<'de, D: Deserializer<'de>>(
        version: DataVersion,
        blinded: bool,
        deserializer: D,
    ) -> Result<Self, D::Error> {
        Ok(match (version, blinded) {
            (DataVersion::Phase0, false) => Self::Phase0(Deserialize::deserialize(deserializer)?),
            (DataVersion::Altair, false) => Self::Altair(Deserialize::deserialize(deserializer)?),
            (DataVersion::Bellatrix, false) => {
                Self::Bellatrix(Deserialize::deserialize(deserializer)?)
            }
            (DataVersion::Bellatrix, true) => {
                Self::BellatrixBlinded(Deserialize::deserialize(deserializer)?)
            }
            (DataVersion::Capella, false) => Self::Capella(Deserialize::deserialize(deserializer)?),
            (DataVersion::Capella, true) => {
                Self::CapellaBlinded(Deserialize::deserialize(deserializer)?)
            }
            (DataVersion::Deneb, false) => {
                let (block, kzg_proofs, blobs) =
                    BlockContents::deserialize(deserializer)?.into_parts();
                Self::Deneb {
                    block,
                    kzg_proofs,
                    blobs,
                }
            }
            (DataVersion::Deneb, true) => {
                Self::DenebBlinded(Deserialize::deserialize(deserializer)?)
            }
            (DataVersion::Electra, false) => {
                let (block, kzg_proofs, blobs) =
                    BlockContents::deserialize(deserializer)?.into_parts();
                Self::Electra {
                    block,
                    kzg_proofs,
                    blobs,
                }
            }
            (DataVersion::Electra, true) => {
                Self::ElectraBlinded(Deserialize::deserialize(deserializer)?)
            }
            (DataVersion::Fulu, false) => {
                let (block, kzg_proofs, blobs) =
                    BlockContents::deserialize(deserializer)?.into_parts();
                Self::Fulu {
                    block,
                    kzg_proofs,
                    blobs,
                }
            }
            (DataVersion::Fulu, true) => Self::FuluBlinded(Deserialize::deserialize(deserializer)?),
            (DataVersion::Phase0 | DataVersion::Altair, true) => {
                return Err(D::Error::custom(format!(
                    "{version} proposal cannot be blinded"
                )));
            }
            (DataVersion::Unknown, _) => {
                return Err(D::Error::custom(
                    "proposal has an unknown consensus version",
                ));
            }
        })
    }

    /// Returns the fork version of this block.
    pub fn version(&self) -> DataVersion {
        match self {
            Self::Phase0(_) => DataVersion::Phase0,
            Self::Altair(_) => DataVersion::Altair,
            Self::Bellatrix(_) | Self::BellatrixBlinded(_) => DataVersion::Bellatrix,
            Self::Capella(_) | Self::CapellaBlinded(_) => DataVersion::Capella,
            Self::Deneb { .. } | Self::DenebBlinded(_) => DataVersion::Deneb,
            Self::Electra { .. } | Self::ElectraBlinded(_) => DataVersion::Electra,
            Self::Fulu { .. } | Self::FuluBlinded(_) => DataVersion::Fulu,
        }
    }

    /// Returns true if this is a blinded block.
    pub fn is_blinded(&self) -> bool {
        matches!(
            self,
            Self::BellatrixBlinded(_)
                | Self::CapellaBlinded(_)
                | Self::DenebBlinded(_)
                | Self::ElectraBlinded(_)
                | Self::FuluBlinded(_)
        )
    }

    /// Returns the slot of this block.
    pub fn slot(&self) -> phase0::Slot {
        match self {
            Self::Phase0(b) => b.slot,
            Self::Altair(b) => b.slot,
            Self::Bellatrix(b) => b.slot,
            Self::BellatrixBlinded(b) => b.slot,
            Self::Capella(b) => b.slot,
            Self::CapellaBlinded(b) => b.slot,
            Self::Deneb { block, .. } => block.slot,
            Self::DenebBlinded(b) => b.slot,
            Self::Electra { block, .. } => block.slot,
            Self::ElectraBlinded(b) => b.slot,
            Self::Fulu { block, .. } => block.slot,
            Self::FuluBlinded(b) => b.slot,
        }
    }

    /// Returns the tree-hash root of this block.
    pub fn root(&self) -> phase0::Root {
        match self {
            Self::Phase0(b) => b.tree_hash_root().0,
            Self::Altair(b) => b.tree_hash_root().0,
            Self::Bellatrix(b) => b.tree_hash_root().0,
            Self::BellatrixBlinded(b) => b.tree_hash_root().0,
            Self::Capella(b) => b.tree_hash_root().0,
            Self::CapellaBlinded(b) => b.tree_hash_root().0,
            Self::Deneb { block, .. } => block.tree_hash_root().0,
            Self::DenebBlinded(b) => b.tree_hash_root().0,
            Self::Electra { block, .. } => block.tree_hash_root().0,
            Self::ElectraBlinded(b) => b.tree_hash_root().0,
            Self::Fulu { block, .. } => block.tree_hash_root().0,
            Self::FuluBlinded(b) => b.tree_hash_root().0,
        }
    }
}

/// Unsigned versioned proposal across all supported forks, as produced by
/// `GET /eth/v3/validator/blocks/{slot}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedProposal {
    /// Unsigned block payload.
    pub block: ProposalBlock,
    /// Consensus block reward, in Wei.
    pub consensus_block_value: U256,
    /// Execution payload value, in Wei.
    pub execution_payload_value: U256,
}

impl VersionedProposal {
    /// Returns the fork version, derived from the block variant.
    pub fn version(&self) -> DataVersion {
        self.block.version()
    }

    /// Returns true if this is a blinded proposal, derived from the block
    /// variant.
    pub fn is_blinded(&self) -> bool {
        self.block.is_blinded()
    }

    /// Returns the slot of the proposal block.
    pub fn slot(&self) -> phase0::Slot {
        self.block.slot()
    }

    /// Returns the tree-hash root of the proposal block.
    pub fn root(&self) -> phase0::Root {
        self.block.root()
    }
}

/// Signed beacon block across all supported forks, as returned by
/// `GET /eth/v2/beacon/blocks/{block_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum SignedBeaconBlock {
    /// Phase0 signed block.
    Phase0(phase0::SignedBeaconBlock),
    /// Altair signed block.
    Altair(altair::SignedBeaconBlock),
    /// Bellatrix signed block.
    Bellatrix(bellatrix::SignedBeaconBlock),
    /// Capella signed block.
    Capella(capella::SignedBeaconBlock),
    /// Deneb signed block.
    Deneb(deneb::SignedBeaconBlock),
    /// Electra signed block.
    Electra(electra::SignedBeaconBlock),
    /// Fulu signed block (uses the electra block type).
    Fulu(electra::SignedBeaconBlock),
}

impl SignedBeaconBlock {
    /// Returns the fork version of this block.
    pub fn version(&self) -> DataVersion {
        match self {
            Self::Phase0(_) => DataVersion::Phase0,
            Self::Altair(_) => DataVersion::Altair,
            Self::Bellatrix(_) => DataVersion::Bellatrix,
            Self::Capella(_) => DataVersion::Capella,
            Self::Deneb(_) => DataVersion::Deneb,
            Self::Electra(_) => DataVersion::Electra,
            Self::Fulu(_) => DataVersion::Fulu,
        }
    }

    /// Returns the slot of this block.
    pub fn slot(&self) -> phase0::Slot {
        match self {
            Self::Phase0(b) => b.message.slot,
            Self::Altair(b) => b.message.slot,
            Self::Bellatrix(b) => b.message.slot,
            Self::Capella(b) => b.message.slot,
            Self::Deneb(b) => b.message.slot,
            Self::Electra(b) | Self::Fulu(b) => b.message.slot,
        }
    }
}

/// Graffiti string used to mark synthetic blocks that must never be submitted.
pub const SYNTHETIC_BLOCK_GRAFFITI: &str = "SYNTHETIC BLOCK: DO NOT SUBMIT";

/// 32-byte graffiti used to mark synthetic blocks, left-aligned with zero
/// padding.
pub const SYNTHETIC_GRAFFITI: phase0::Root = {
    let mut graffiti = [0u8; 32];
    let src = SYNTHETIC_BLOCK_GRAFFITI.as_bytes();
    let mut i = 0;
    while i < src.len() {
        graffiti[i] = src[i];
        i += 1;
    }
    graffiti
};

/// Signed proposal wrapper across all supported forks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedSignedProposal {
    /// Fork version of the payload.
    pub version: DataVersion,
    /// True if this proposal is blinded.
    pub blinded: bool,
    /// Proposal payload selected by version and blinded mode.
    pub block: SignedProposalBlock,
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
    /// Decodes the Beacon API JSON form of a signed `version` block.
    pub fn from_json<'de, D: Deserializer<'de>>(
        version: DataVersion,
        blinded: bool,
        deserializer: D,
    ) -> Result<Self, D::Error> {
        Ok(match (version, blinded) {
            (DataVersion::Phase0, false) => Self::Phase0(Deserialize::deserialize(deserializer)?),
            (DataVersion::Altair, false) => Self::Altair(Deserialize::deserialize(deserializer)?),
            (DataVersion::Bellatrix, false) => {
                Self::Bellatrix(Deserialize::deserialize(deserializer)?)
            }
            (DataVersion::Bellatrix, true) => {
                Self::BellatrixBlinded(Deserialize::deserialize(deserializer)?)
            }
            (DataVersion::Capella, false) => Self::Capella(Deserialize::deserialize(deserializer)?),
            (DataVersion::Capella, true) => {
                Self::CapellaBlinded(Deserialize::deserialize(deserializer)?)
            }
            (DataVersion::Deneb, false) => Self::Deneb(Deserialize::deserialize(deserializer)?),
            (DataVersion::Deneb, true) => {
                Self::DenebBlinded(Deserialize::deserialize(deserializer)?)
            }
            (DataVersion::Electra, false) => Self::Electra(Deserialize::deserialize(deserializer)?),
            (DataVersion::Electra, true) => {
                Self::ElectraBlinded(Deserialize::deserialize(deserializer)?)
            }
            (DataVersion::Fulu, false) => Self::Fulu(Deserialize::deserialize(deserializer)?),
            (DataVersion::Fulu, true) => Self::FuluBlinded(Deserialize::deserialize(deserializer)?),
            (DataVersion::Phase0 | DataVersion::Altair, true) => {
                return Err(D::Error::custom(format!(
                    "{version} proposal cannot be blinded"
                )));
            }
            (DataVersion::Unknown, _) => {
                return Err(D::Error::custom(
                    "proposal has an unknown consensus version",
                ));
            }
        })
    }

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

    /// Returns the graffiti embedded in this proposal's block body.
    pub fn graffiti(&self) -> phase0::Root {
        match self {
            Self::Phase0(block) => block.message.body.graffiti,
            Self::Altair(block) => block.message.body.graffiti,
            Self::Bellatrix(block) => block.message.body.graffiti,
            Self::BellatrixBlinded(block) => block.message.body.graffiti,
            Self::Capella(block) => block.message.body.graffiti,
            Self::CapellaBlinded(block) => block.message.body.graffiti,
            Self::Deneb(block) => block.signed_block.message.body.graffiti,
            Self::DenebBlinded(block) => block.message.body.graffiti,
            Self::Electra(block) => block.signed_block.message.body.graffiti,
            Self::ElectraBlinded(block) => block.message.body.graffiti,
            Self::Fulu(block) => block.signed_block.message.body.graffiti,
            Self::FuluBlinded(block) => block.message.body.graffiti,
        }
    }

    /// Returns the slot embedded in this proposal's block.
    pub fn slot(&self) -> phase0::Slot {
        match self {
            Self::Phase0(block) => block.message.slot,
            Self::Altair(block) => block.message.slot,
            Self::Bellatrix(block) => block.message.slot,
            Self::BellatrixBlinded(block) => block.message.slot,
            Self::Capella(block) => block.message.slot,
            Self::CapellaBlinded(block) => block.message.slot,
            Self::Deneb(block) => block.signed_block.message.slot,
            Self::DenebBlinded(block) => block.message.slot,
            Self::Electra(block) => block.signed_block.message.slot,
            Self::ElectraBlinded(block) => block.message.slot,
            Self::Fulu(block) => block.signed_block.message.slot,
            Self::FuluBlinded(block) => block.message.slot,
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

impl VersionedSignedProposal {
    /// Returns `true` if this is a synthetic proposal, i.e. its block body
    /// graffiti matches [`SYNTHETIC_GRAFFITI`].
    ///
    /// Unifies Go's separate blinded/full checks: the payload enum already
    /// carries both blinded and full variants, so a single graffiti comparison
    /// covers every case.
    pub fn is_synthetic(&self) -> bool {
        self.block.graffiti() == SYNTHETIC_GRAFFITI
    }
}

/// Signed blinded proposal wrapper across all supported forks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedSignedBlindedProposal {
    /// Fork version of the payload.
    pub version: DataVersion,
    /// Blinded proposal payload selected by version.
    pub block: SignedBlindedProposalBlock,
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
        match self {
            Self::Phase0(attestation)
            | Self::Altair(attestation)
            | Self::Bellatrix(attestation)
            | Self::Capella(attestation)
            | Self::Deneb(attestation) => attestation.aggregation_bits.clone().into_bytes(),
            Self::Electra(attestation) | Self::Fulu(attestation) => {
                attestation.aggregation_bits.clone().into_bytes()
            }
        }
    }
}

/// Versioned signed aggregate-and-proof wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedSignedAggregateAndProof {
    /// Fork version of the payload.
    pub version: DataVersion,
    /// Signed aggregate-and-proof payload selected by version.
    pub aggregate_and_proof: SignedAggregateAndProofPayload,
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
    /// Returns the attestation slot embedded in this payload.
    pub fn slot(&self) -> phase0::Slot {
        self.data().slot
    }

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
        match self {
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
        }
    }

    /// Returns the selection proof embedded in this payload.
    pub fn selection_proof(&self) -> phase0::BLSSignature {
        match self {
            Self::Phase0(payload)
            | Self::Altair(payload)
            | Self::Bellatrix(payload)
            | Self::Capella(payload)
            | Self::Deneb(payload) => payload.message.selection_proof,
            Self::Electra(payload) | Self::Fulu(payload) => payload.message.selection_proof,
        }
    }

    /// Returns the SSZ message root of the unsigned aggregate-and-proof
    /// payload.
    pub fn message_root(&self) -> phase0::Root {
        match self {
            Self::Phase0(payload)
            | Self::Altair(payload)
            | Self::Bellatrix(payload)
            | Self::Capella(payload)
            | Self::Deneb(payload) => payload.message.tree_hash_root().0,
            Self::Electra(payload) | Self::Fulu(payload) => payload.message.tree_hash_root().0,
        }
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

impl VersionedSignedAggregateAndProof {
    /// Returns the attestation slot of the wrapped payload.
    pub fn slot(&self) -> Option<phase0::Slot> {
        if self.version == DataVersion::Unknown {
            return None;
        }

        Some(self.aggregate_and_proof.slot())
    }

    /// Returns the selection proof of the wrapped payload.
    pub fn selection_proof(&self) -> Option<phase0::BLSSignature> {
        if self.version == DataVersion::Unknown {
            return None;
        }

        Some(self.aggregate_and_proof.selection_proof())
    }

    /// Returns the SSZ message root of the wrapped payload.
    pub fn message_root(&self) -> Option<phase0::Root> {
        if self.version == DataVersion::Unknown {
            return None;
        }

        Some(self.aggregate_and_proof.message_root())
    }
}

impl VersionedSignedValidatorRegistration {
    /// Returns the SSZ message root of the wrapped builder registration.
    pub fn message_root(&self) -> Option<phase0::Root> {
        match self.version {
            BuilderVersion::V1 => self.v1.as_ref().map(|value| value.message.message_root()),
            BuilderVersion::Unknown => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures;

    #[test]
    fn synthetic_graffiti_layout() {
        let marker = SYNTHETIC_BLOCK_GRAFFITI.as_bytes();
        assert_eq!(&SYNTHETIC_GRAFFITI[..marker.len()], marker);
        // Remaining bytes are zero-padded.
        assert!(SYNTHETIC_GRAFFITI[marker.len()..].iter().all(|&b| b == 0));
    }

    #[test]
    fn versioned_signed_aggregate_and_proof_message_root_delegates_to_payload() {
        let signed = electra::SignedAggregateAndProof {
            message: electra::AggregateAndProof {
                aggregator_index: 456,
                aggregate: serde_json::from_str(
                    test_fixtures::VECTORS.electra_oversized_attestation_json,
                )
                .expect("electra attestation"),
                selection_proof: test_fixtures::seq::<96>(0xE0),
            },
            signature: test_fixtures::seq::<96>(0xE1),
        };
        let expected = signed.message.tree_hash_root().0;

        let wrapped = VersionedSignedAggregateAndProof {
            version: DataVersion::Electra,
            aggregate_and_proof: SignedAggregateAndProofPayload::Electra(signed),
        };

        assert_eq!(wrapped.message_root(), Some(expected));
    }

    #[test]
    fn versioned_signed_validator_registration_message_root_matches_v1_message() {
        let message = v1::ValidatorRegistration {
            fee_recipient: test_fixtures::seq::<20>(0xD1),
            gas_limit: 30_000_000,
            timestamp: 1_700_000_789,
            pubkey: test_fixtures::seq::<48>(0xD2),
        };
        let signed = v1::SignedValidatorRegistration {
            message: message.clone(),
            signature: test_fixtures::seq::<96>(0xD3),
        };
        let expected = message.message_root();

        assert_eq!(
            VersionedSignedValidatorRegistration {
                version: BuilderVersion::V1,
                v1: Some(signed),
            }
            .message_root(),
            Some(expected)
        );
    }
}
