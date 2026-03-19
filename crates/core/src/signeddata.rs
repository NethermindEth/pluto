//! Signed data types and helpers.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tree_hash::TreeHash;

use base64::Engine as _;
use pluto_eth2api::{
    spec::{altair, phase0},
    v1, versioned,
};
use pluto_eth2util::types::SignedEpoch;

use crate::types::{ParSignedData, Signature, SignedData};

/// Error type for signed data operations.
#[derive(Debug, thiserror::Error)]
pub enum SignedDataError {
    /// JSON error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Signature values do not support signed message roots.
    #[error("signed message root not supported by signature type")]
    UnsupportedSignatureMessageRoot,
    /// Missing V1 builder registration payload.
    #[error("no V1 registration")]
    MissingV1Registration,
    /// Unknown data or builder version.
    #[error("unknown version")]
    UnknownVersion,
    /// Unknown signed-data variant.
    #[error("unknown type")]
    UnknownType,
    /// Missing attestation payload for the selected fork.
    #[error("no {0} attestation")]
    MissingAttestation(versioned::DataVersion),
    /// Missing aggregate-and-proof payload for the selected fork.
    #[error("no {0} aggregate and proof")]
    MissingAggregateAndProof(versioned::DataVersion),
    /// Missing unblinded proposal payload for the selected fork.
    #[error("no {0} proposal")]
    MissingProposal(versioned::DataVersion),
    /// Missing blinded proposal payload for the selected fork.
    #[error("no {0} blinded proposal")]
    MissingBlindedProposal(versioned::DataVersion),
    /// Proposal cannot be converted to a blinded proposal.
    #[error("proposal is not blinded")]
    ProposalNotBlinded,
    /// Invalid attestation wrapper JSON.
    #[error("unmarshal attestation")]
    AttestationJson,
}

fn hash_root<T: TreeHash>(value: &T) -> [u8; 32] {
    value.tree_hash_root().0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VersionedRawBlockJson<T> {
    version: pluto_eth2util::types::DataVersion,
    block: T,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    blinded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VersionedRawAttestationJson<T> {
    version: pluto_eth2util::types::DataVersion,
    #[serde(default)]
    validator_index: Option<serde_json::Value>,
    attestation: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VersionedRawValidatorRegistrationJson<T> {
    version: pluto_eth2util::types::BuilderVersion,
    registration: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VersionedRawAggregateAndProofJson<T> {
    version: pluto_eth2util::types::DataVersion,
    aggregate_and_proof: T,
}

/// Converts an ETH2 signature to a core signature.
pub fn sig_from_eth2(sig: phase0::BLSSignature) -> Signature {
    Signature::new(sig)
}

fn sig_to_eth2(sig: &Signature) -> phase0::BLSSignature {
    *sig.as_ref()
}

impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = base64::engine::general_purpose::STANDARD.encode(self.as_ref());
        serializer.serialize_str(&encoded)
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|err| serde::de::Error::custom(format!("invalid base64 signature: {err}")))?;
        let sig: [u8; 96] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            serde::de::Error::custom(format!(
                "invalid signature length: got {}, want 96",
                bytes.len()
            ))
        })?;
        Ok(Signature::new(sig))
    }
}

impl Signature {
    /// Converts the signature to an ETH2 signature.
    pub fn to_eth2(&self) -> phase0::BLSSignature {
        sig_to_eth2(self)
    }

    /// Creates a partially signed signature wrapper.
    pub fn new_partial(sig: Self, share_idx: u64) -> ParSignedData<Self> {
        ParSignedData::new(sig, share_idx)
    }
}

impl SignedData for Signature {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        Ok(self.clone())
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        Ok(signature)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        Err(SignedDataError::UnsupportedSignatureMessageRoot)
    }
}

/// Versioned signed proposal wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedSignedProposal(
    /// Wrapped payload.
    pub versioned::VersionedSignedProposal,
);

fn proposal_payload_error(version: versioned::DataVersion, blinded: bool) -> SignedDataError {
    match version {
        versioned::DataVersion::Unknown => SignedDataError::UnknownVersion,
        versioned::DataVersion::Phase0 | versioned::DataVersion::Altair => {
            SignedDataError::MissingProposal(version)
        }
        _ if blinded => SignedDataError::MissingBlindedProposal(version),
        _ => SignedDataError::MissingProposal(version),
    }
}

impl VersionedSignedProposal {
    /// Creates a validated versioned signed proposal wrapper.
    pub fn new(proposal: versioned::VersionedSignedProposal) -> Result<Self, SignedDataError> {
        if proposal.version == versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion);
        }
        Ok(Self(proposal))
    }

    /// Creates a partial versioned signed proposal wrapper.
    pub fn new_partial(
        proposal: versioned::VersionedSignedProposal,
        share_idx: u64,
    ) -> Result<ParSignedData<Self>, SignedDataError> {
        Ok(ParSignedData::new(Self::new(proposal)?, share_idx))
    }

    /// Converts a blinded proposal wrapper into a generic versioned signed
    /// proposal wrapper.
    pub fn from_blinded_proposal(
        proposal: versioned::VersionedSignedBlindedProposal,
    ) -> Result<Self, SignedDataError> {
        Self::new(versioned::VersionedSignedProposal {
            version: proposal.version,
            blinded: true,
            block: proposal.block.into_signed(),
        })
    }

    /// Converts a generic versioned signed proposal wrapper into a blinded
    /// proposal wrapper.
    pub fn to_blinded(self) -> Result<versioned::VersionedSignedBlindedProposal, SignedDataError> {
        let versioned::VersionedSignedProposal {
            version,
            blinded,
            block,
        } = self.0;

        if !blinded {
            return Err(SignedDataError::ProposalNotBlinded);
        }

        let blinded_block = block
            .into_blinded()
            .ok_or_else(|| proposal_payload_error(version, true))?;

        Ok(versioned::VersionedSignedBlindedProposal {
            version,
            block: blinded_block,
        })
    }

    /// Creates a partial proposal wrapper from a blinded proposal wrapper.
    pub fn new_partial_from_blinded_proposal(
        proposal: versioned::VersionedSignedBlindedProposal,
        share_idx: u64,
    ) -> Result<ParSignedData<Self>, SignedDataError> {
        Ok(ParSignedData::new(
            Self::from_blinded_proposal(proposal)?,
            share_idx,
        ))
    }
}

impl SignedData for VersionedSignedProposal {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        let proposal = &self.0;
        if proposal.version == versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion);
        }
        Ok(sig_from_eth2(proposal.block.signature()))
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        let mut out = self.clone();
        let proposal = &mut out.0;
        if proposal.version == versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion);
        }
        let eth2_sig = sig_to_eth2(&signature);
        proposal.block.set_signature(eth2_sig);

        Ok(out)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        let proposal = &self.0;
        if proposal.version == versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion);
        }

        Ok(match &proposal.block {
            versioned::SignedProposalBlock::Phase0(block) => hash_root(&block.message),
            versioned::SignedProposalBlock::Altair(block) => hash_root(&block.message),
            versioned::SignedProposalBlock::Bellatrix(block) => hash_root(&block.message),
            versioned::SignedProposalBlock::BellatrixBlinded(block) => hash_root(&block.message),
            versioned::SignedProposalBlock::Capella(block) => hash_root(&block.message),
            versioned::SignedProposalBlock::CapellaBlinded(block) => hash_root(&block.message),
            versioned::SignedProposalBlock::Deneb(block) => hash_root(&block.signed_block.message),
            versioned::SignedProposalBlock::DenebBlinded(block) => hash_root(&block.message),
            versioned::SignedProposalBlock::Electra(block) => {
                hash_root(&block.signed_block.message)
            }
            versioned::SignedProposalBlock::ElectraBlinded(block) => hash_root(&block.message),
            versioned::SignedProposalBlock::Fulu(block) => hash_root(&block.signed_block.message),
            versioned::SignedProposalBlock::FuluBlinded(block) => hash_root(&block.message),
        })
    }
}

impl Serialize for VersionedSignedProposal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let proposal = &self.0;
        if proposal.version == versioned::DataVersion::Unknown {
            return Err(serde::ser::Error::custom(SignedDataError::UnknownVersion));
        }
        let version_eth2 = proposal.version;
        let blinded = proposal.blinded;
        let version = pluto_eth2util::types::DataVersion::from_eth2(version_eth2)
            .map_err(serde::ser::Error::custom)?;

        VersionedRawBlockJson {
            version,
            block: &proposal.block,
            blinded,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VersionedSignedProposal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = VersionedRawBlockJson::<serde_json::Value>::deserialize(deserializer)?;
        let version = raw.version;
        let blinded = raw.blinded;
        use pluto_eth2util::types::DataVersion;
        use versioned::SignedProposalBlock;
        let block = match (version, blinded) {
            (DataVersion::Unknown, _) => {
                return Err(serde::de::Error::custom(SignedDataError::UnknownVersion));
            }
            (DataVersion::Phase0, _) => {
                serde_json::from_value(raw.block).map(SignedProposalBlock::Phase0)
            }
            (DataVersion::Altair, _) => {
                serde_json::from_value(raw.block).map(SignedProposalBlock::Altair)
            }
            (DataVersion::Bellatrix, true) => {
                serde_json::from_value(raw.block).map(SignedProposalBlock::BellatrixBlinded)
            }
            (DataVersion::Bellatrix, false) => {
                serde_json::from_value(raw.block).map(SignedProposalBlock::Bellatrix)
            }
            (DataVersion::Capella, true) => {
                serde_json::from_value(raw.block).map(SignedProposalBlock::CapellaBlinded)
            }
            (DataVersion::Capella, false) => {
                serde_json::from_value(raw.block).map(SignedProposalBlock::Capella)
            }
            (DataVersion::Deneb, true) => {
                serde_json::from_value(raw.block).map(SignedProposalBlock::DenebBlinded)
            }
            (DataVersion::Deneb, false) => {
                serde_json::from_value(raw.block).map(SignedProposalBlock::Deneb)
            }
            (DataVersion::Electra, true) => {
                serde_json::from_value(raw.block).map(SignedProposalBlock::ElectraBlinded)
            }
            (DataVersion::Electra, false) => {
                serde_json::from_value(raw.block).map(SignedProposalBlock::Electra)
            }
            (DataVersion::Fulu, true) => {
                serde_json::from_value(raw.block).map(SignedProposalBlock::FuluBlinded)
            }
            (DataVersion::Fulu, false) => {
                serde_json::from_value(raw.block).map(SignedProposalBlock::Fulu)
            }
        }
        .map_err(serde::de::Error::custom)?;

        Self::new(versioned::VersionedSignedProposal {
            version: version.to_eth2(),
            blinded,
            block,
        })
        .map_err(serde::de::Error::custom)
    }
}

/// Signed attestation wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Attestation(
    /// Wrapped payload.
    pub phase0::Attestation,
);

impl Attestation {
    /// Creates a signed attestation wrapper.
    pub fn new(attestation: phase0::Attestation) -> Self {
        Self(attestation)
    }

    /// Creates a partial signed attestation wrapper.
    pub fn new_partial(attestation: phase0::Attestation, share_idx: u64) -> ParSignedData<Self> {
        ParSignedData::new(Self::new(attestation), share_idx)
    }
}

impl SignedData for Attestation {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        Ok(sig_from_eth2(self.0.signature))
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        let mut out = self.clone();
        out.0.signature = sig_to_eth2(&signature);
        Ok(out)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        Ok(hash_root(&self.0.data))
    }
}

/// Versioned attestation wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedAttestation(
    /// Wrapped payload.
    pub versioned::VersionedAttestation,
);

impl VersionedAttestation {
    /// Creates a validated versioned attestation wrapper.
    pub fn new(attestation: versioned::VersionedAttestation) -> Result<Self, SignedDataError> {
        let version = attestation.version;
        if version == versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion);
        }
        attestation
            .attestation
            .as_ref()
            .ok_or(SignedDataError::MissingAttestation(version))?;

        Ok(Self(attestation))
    }

    /// Creates a partial versioned attestation wrapper.
    pub fn new_partial(
        attestation: versioned::VersionedAttestation,
        share_idx: u64,
    ) -> Result<ParSignedData<Self>, SignedDataError> {
        Ok(ParSignedData::new(Self::new(attestation)?, share_idx))
    }

    /// Returns aggregation bits for the wrapped attestation payload.
    pub fn aggregation_bits(&self) -> Result<Vec<u8>, SignedDataError> {
        let version = self.0.version;
        if version == versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion);
        }

        self.0
            .attestation
            .as_ref()
            .map(versioned::AttestationPayload::aggregation_bits)
            .ok_or(SignedDataError::MissingAttestation(version))
    }
}

impl SignedData for VersionedAttestation {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        let version = self.0.version;
        if version == versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion);
        }
        self.0
            .attestation
            .as_ref()
            .map(|a| sig_from_eth2(versioned::AttestationPayload::signature(a)))
            .ok_or(SignedDataError::MissingAttestation(version))
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        let mut out = self.clone();
        let version = out.0.version;
        if version == versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion);
        }
        out.0
            .attestation
            .as_mut()
            .ok_or(SignedDataError::MissingAttestation(version))?
            .set_signature(sig_to_eth2(&signature));

        Ok(out)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        let version = self.0.version;
        if version == versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion);
        }

        self.0
            .attestation
            .as_ref()
            .map(|attestation| hash_root(attestation.data()))
            .ok_or(SignedDataError::MissingAttestation(version))
    }
}

impl Serialize for VersionedAttestation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let version_eth2 = self.0.version;
        if version_eth2 == versioned::DataVersion::Unknown {
            return Err(serde::ser::Error::custom(SignedDataError::UnknownVersion));
        }
        let version = pluto_eth2util::types::DataVersion::from_eth2(version_eth2)
            .map_err(serde::ser::Error::custom)?;
        let validator_index = self
            .0
            .validator_index
            .map(|value| serde_json::Value::String(value.to_string()));
        let attestation = self.0.attestation.as_ref().ok_or_else(|| {
            serde::ser::Error::custom(SignedDataError::MissingAttestation(version_eth2))
        })?;

        VersionedRawAttestationJson {
            version,
            validator_index,
            attestation,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VersionedAttestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = VersionedRawAttestationJson::<serde_json::Value>::deserialize(deserializer)?;
        let validator_index = match raw.validator_index {
            Some(serde_json::Value::String(encoded)) => Some(
                encoded
                    .parse::<phase0::ValidatorIndex>()
                    .map_err(|_| serde::de::Error::custom(SignedDataError::AttestationJson))?,
            ),
            Some(serde_json::Value::Null) | None => None,
            Some(other) => Some(serde_json::from_value(other).map_err(serde::de::Error::custom)?),
        };

        let version = raw.version;

        use pluto_eth2util::types::DataVersion;
        use versioned::AttestationPayload;
        let attestation = match version {
            DataVersion::Phase0 => {
                serde_json::from_value(raw.attestation).map(AttestationPayload::Phase0)
            }
            DataVersion::Altair => {
                serde_json::from_value(raw.attestation).map(AttestationPayload::Altair)
            }
            DataVersion::Bellatrix => {
                serde_json::from_value(raw.attestation).map(AttestationPayload::Bellatrix)
            }
            DataVersion::Capella => {
                serde_json::from_value(raw.attestation).map(AttestationPayload::Capella)
            }
            DataVersion::Deneb => {
                serde_json::from_value(raw.attestation).map(AttestationPayload::Deneb)
            }
            DataVersion::Electra => {
                serde_json::from_value(raw.attestation).map(AttestationPayload::Electra)
            }
            DataVersion::Fulu => {
                serde_json::from_value(raw.attestation).map(AttestationPayload::Fulu)
            }
            DataVersion::Unknown => {
                return Err(serde::de::Error::custom(SignedDataError::UnknownVersion));
            }
        }
        .map_err(serde::de::Error::custom)?;

        Self::new(versioned::VersionedAttestation {
            version: version.to_eth2(),
            validator_index,
            attestation: Some(attestation),
        })
        .map_err(serde::de::Error::custom)
    }
}

/// Signed voluntary exit wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedVoluntaryExit(
    /// Wrapped payload.
    pub phase0::SignedVoluntaryExit,
);

impl SignedData for SignedVoluntaryExit {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        Ok(sig_from_eth2(self.0.signature))
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        let mut out = self.clone();
        out.0.signature = sig_to_eth2(&signature);
        Ok(out)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        Ok(hash_root(&self.0.message))
    }
}

impl SignedVoluntaryExit {
    /// Creates a signed voluntary exit wrapper.
    pub fn new(exit: phase0::SignedVoluntaryExit) -> Self {
        Self(exit)
    }

    /// Creates a partially signed voluntary exit wrapper.
    pub fn new_partial(exit: phase0::SignedVoluntaryExit, share_idx: u64) -> ParSignedData<Self> {
        ParSignedData::new(Self::new(exit), share_idx)
    }
}

/// Versioned signed validator registration wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedSignedValidatorRegistration(
    /// Wrapped payload.
    pub versioned::VersionedSignedValidatorRegistration,
);

impl VersionedSignedValidatorRegistration {
    /// Creates a validated versioned signed validator registration wrapper.
    pub fn new(
        registration: versioned::VersionedSignedValidatorRegistration,
    ) -> Result<Self, SignedDataError> {
        match registration.version {
            versioned::BuilderVersion::V1 => {
                if registration.v1.is_none() {
                    return Err(SignedDataError::MissingV1Registration);
                }
            }
            versioned::BuilderVersion::Unknown => {
                return Err(SignedDataError::UnknownVersion);
            }
        }

        Ok(Self(registration))
    }

    /// Creates a partial versioned signed validator registration wrapper.
    pub fn new_partial(
        registration: versioned::VersionedSignedValidatorRegistration,
        share_idx: u64,
    ) -> Result<ParSignedData<Self>, SignedDataError> {
        Ok(ParSignedData::new(Self::new(registration)?, share_idx))
    }
}

impl SignedData for VersionedSignedValidatorRegistration {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        match self.0.version {
            versioned::BuilderVersion::V1 => self
                .0
                .v1
                .as_ref()
                .map(|value| sig_from_eth2(value.signature))
                .ok_or(SignedDataError::MissingV1Registration),
            versioned::BuilderVersion::Unknown => Err(SignedDataError::UnknownVersion),
        }
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        let mut out = self.clone();
        match out.0.version {
            versioned::BuilderVersion::V1 => {
                let Some(v1) = out.0.v1.as_mut() else {
                    return Err(SignedDataError::MissingV1Registration);
                };
                v1.signature = sig_to_eth2(&signature);
            }
            versioned::BuilderVersion::Unknown => {
                return Err(SignedDataError::UnknownVersion);
            }
        }

        Ok(out)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        match self.0.version {
            versioned::BuilderVersion::V1 => {
                let Some(v1) = self.0.v1.as_ref() else {
                    return Err(SignedDataError::MissingV1Registration);
                };
                Ok(hash_root(&v1.message))
            }
            versioned::BuilderVersion::Unknown => Err(SignedDataError::UnknownVersion),
        }
    }
}

impl Serialize for VersionedSignedValidatorRegistration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0.version {
            versioned::BuilderVersion::V1 => VersionedRawValidatorRegistrationJson {
                version: pluto_eth2util::types::BuilderVersion::V1,
                registration: self
                    .0
                    .v1
                    .as_ref()
                    .ok_or(SignedDataError::MissingV1Registration)
                    .map_err(serde::ser::Error::custom)?,
            }
            .serialize(serializer),
            versioned::BuilderVersion::Unknown => {
                Err(serde::ser::Error::custom(SignedDataError::UnknownVersion))
            }
        }
    }
}

impl<'de> Deserialize<'de> for VersionedSignedValidatorRegistration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw =
            VersionedRawValidatorRegistrationJson::<v1::SignedValidatorRegistration>::deserialize(
                deserializer,
            )?;
        match raw.version {
            pluto_eth2util::types::BuilderVersion::V1 => {
                Ok(Self(versioned::VersionedSignedValidatorRegistration {
                    version: versioned::BuilderVersion::V1,
                    v1: Some(raw.registration),
                }))
            }
            pluto_eth2util::types::BuilderVersion::Unknown => {
                Err(serde::de::Error::custom(SignedDataError::UnknownVersion))
            }
        }
    }
}

/// Signed randao reveal wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedRandao(
    /// Signed epoch payload.
    pub SignedEpoch,
);

impl SignedData for SignedRandao {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        Ok(sig_from_eth2(self.0.signature))
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        let mut out = self.clone();
        out.0.signature = sig_to_eth2(&signature);
        Ok(out)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        Ok(hash_root(&self.0))
    }
}

impl SignedRandao {
    /// Creates a signed randao wrapper.
    pub fn new(epoch: phase0::Epoch, randao: phase0::BLSSignature) -> Self {
        Self(SignedEpoch {
            epoch,
            signature: randao,
        })
    }

    /// Creates a partially signed randao wrapper.
    pub fn new_partial(
        epoch: phase0::Epoch,
        randao: phase0::BLSSignature,
        share_idx: u64,
    ) -> ParSignedData<Self> {
        ParSignedData::new(Self::new(epoch, randao), share_idx)
    }
}

/// Beacon committee selection wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BeaconCommitteeSelection(
    /// Wrapped payload.
    pub v1::BeaconCommitteeSelection,
);

impl SignedData for BeaconCommitteeSelection {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        Ok(sig_from_eth2(self.0.selection_proof))
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        let mut out = self.clone();
        out.0.selection_proof = sig_to_eth2(&signature);
        Ok(out)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        Ok(hash_root(&self.0.slot))
    }
}

impl BeaconCommitteeSelection {
    /// Creates a beacon committee selection wrapper.
    pub fn new(selection: v1::BeaconCommitteeSelection) -> Self {
        Self(selection)
    }

    /// Creates a partial beacon committee selection wrapper.
    pub fn new_partial(
        selection: v1::BeaconCommitteeSelection,
        share_idx: u64,
    ) -> ParSignedData<Self> {
        ParSignedData::new(Self::new(selection), share_idx)
    }
}

/// Sync committee selection wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SyncCommitteeSelection(
    /// Wrapped payload.
    pub v1::SyncCommitteeSelection,
);

impl SignedData for SyncCommitteeSelection {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        Ok(sig_from_eth2(self.0.selection_proof))
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        let mut out = self.clone();
        out.0.selection_proof = sig_to_eth2(&signature);
        Ok(out)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        let data = altair::SyncAggregatorSelectionData {
            slot: self.0.slot,
            subcommittee_index: self.0.subcommittee_index,
        };

        Ok(hash_root(&data))
    }
}

impl SyncCommitteeSelection {
    /// Creates a sync committee selection wrapper.
    pub fn new(selection: v1::SyncCommitteeSelection) -> Self {
        Self(selection)
    }

    /// Creates a partial sync committee selection wrapper.
    pub fn new_partial(
        selection: v1::SyncCommitteeSelection,
        share_idx: u64,
    ) -> ParSignedData<Self> {
        ParSignedData::new(Self::new(selection), share_idx)
    }
}

/// Signed aggregate-and-proof wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedAggregateAndProof(
    /// Wrapped payload.
    pub phase0::SignedAggregateAndProof,
);

impl SignedData for SignedAggregateAndProof {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        Ok(sig_from_eth2(self.0.signature))
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        let mut out = self.clone();
        out.0.signature = sig_to_eth2(&signature);
        Ok(out)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        Ok(hash_root(&self.0.message))
    }
}

impl SignedAggregateAndProof {
    /// Creates a signed aggregate-and-proof wrapper.
    pub fn new(data: phase0::SignedAggregateAndProof) -> Self {
        Self(data)
    }

    /// Creates a partial signed aggregate-and-proof wrapper.
    pub fn new_partial(
        data: phase0::SignedAggregateAndProof,
        share_idx: u64,
    ) -> ParSignedData<Self> {
        ParSignedData::new(Self::new(data), share_idx)
    }
}

/// Versioned signed aggregate-and-proof wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedSignedAggregateAndProof(
    /// Wrapped payload.
    pub versioned::VersionedSignedAggregateAndProof,
);

impl VersionedSignedAggregateAndProof {
    /// Returns the attestation data for the wrapped payload.
    pub fn data(&self) -> Option<&phase0::AttestationData> {
        if self.0.version == versioned::DataVersion::Unknown {
            return None;
        }

        Some(self.0.aggregate_and_proof.data())
    }

    /// Returns aggregation bits for the wrapped payload.
    pub fn aggregation_bits(&self) -> Option<Vec<u8>> {
        if self.0.version == versioned::DataVersion::Unknown {
            return None;
        }

        Some(self.0.aggregate_and_proof.aggregation_bits())
    }

    /// Creates a versioned signed aggregate-and-proof wrapper.
    pub fn new(data: versioned::VersionedSignedAggregateAndProof) -> Self {
        Self(data)
    }

    /// Creates a partial versioned signed aggregate-and-proof wrapper.
    pub fn new_partial(
        data: versioned::VersionedSignedAggregateAndProof,
        share_idx: u64,
    ) -> ParSignedData<Self> {
        ParSignedData::new(Self::new(data), share_idx)
    }
}

impl SignedData for VersionedSignedAggregateAndProof {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        let version = self.0.version;
        if version == versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion);
        }

        Ok(sig_from_eth2(self.0.aggregate_and_proof.signature()))
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        let mut out = self.clone();
        let version = out.0.version;
        if version == versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion);
        }
        out.0
            .aggregate_and_proof
            .set_signature(sig_to_eth2(&signature));

        Ok(out)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        let version = self.0.version;
        if version == versioned::DataVersion::Unknown {
            return Err(SignedDataError::UnknownVersion);
        }

        Ok(match &self.0.aggregate_and_proof {
            versioned::SignedAggregateAndProofPayload::Phase0(payload)
            | versioned::SignedAggregateAndProofPayload::Altair(payload)
            | versioned::SignedAggregateAndProofPayload::Bellatrix(payload)
            | versioned::SignedAggregateAndProofPayload::Capella(payload)
            | versioned::SignedAggregateAndProofPayload::Deneb(payload) => {
                hash_root(&payload.message)
            }
            versioned::SignedAggregateAndProofPayload::Electra(payload)
            | versioned::SignedAggregateAndProofPayload::Fulu(payload) => {
                hash_root(&payload.message)
            }
        })
    }
}

impl Serialize for VersionedSignedAggregateAndProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let version_eth2 = self.0.version;
        if version_eth2 == versioned::DataVersion::Unknown {
            return Err(serde::ser::Error::custom(SignedDataError::UnknownVersion));
        }
        let version = pluto_eth2util::types::DataVersion::from_eth2(version_eth2)
            .map_err(serde::ser::Error::custom)?;

        VersionedRawAggregateAndProofJson {
            version,
            aggregate_and_proof: &self.0.aggregate_and_proof,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VersionedSignedAggregateAndProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw =
            VersionedRawAggregateAndProofJson::<serde_json::Value>::deserialize(deserializer)?;
        let version = raw.version;

        use pluto_eth2util::types::DataVersion;
        use versioned::SignedAggregateAndProofPayload;

        let aggregate_and_proof = match version {
            DataVersion::Phase0 => serde_json::from_value(raw.aggregate_and_proof)
                .map(SignedAggregateAndProofPayload::Phase0),
            DataVersion::Altair => serde_json::from_value(raw.aggregate_and_proof)
                .map(SignedAggregateAndProofPayload::Altair),
            DataVersion::Bellatrix => serde_json::from_value(raw.aggregate_and_proof)
                .map(SignedAggregateAndProofPayload::Bellatrix),
            DataVersion::Capella => serde_json::from_value(raw.aggregate_and_proof)
                .map(SignedAggregateAndProofPayload::Capella),
            DataVersion::Deneb => serde_json::from_value(raw.aggregate_and_proof)
                .map(SignedAggregateAndProofPayload::Deneb),
            DataVersion::Electra => serde_json::from_value(raw.aggregate_and_proof)
                .map(SignedAggregateAndProofPayload::Electra),
            DataVersion::Fulu => serde_json::from_value(raw.aggregate_and_proof)
                .map(SignedAggregateAndProofPayload::Fulu),
            DataVersion::Unknown => {
                return Err(serde::de::Error::custom(SignedDataError::UnknownVersion));
            }
        }
        .map_err(serde::de::Error::custom)?;

        Ok(Self(versioned::VersionedSignedAggregateAndProof {
            version: version.to_eth2(),
            aggregate_and_proof,
        }))
    }
}

/// Signed sync committee message wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedSyncMessage(
    /// Wrapped payload.
    pub altair::SyncCommitteeMessage,
);

impl SignedData for SignedSyncMessage {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        Ok(sig_from_eth2(self.0.signature))
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        let mut out = self.clone();
        out.0.signature = sig_to_eth2(&signature);
        Ok(out)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        Ok(self.0.beacon_block_root)
    }
}

impl SignedSyncMessage {
    /// Creates a signed sync committee message wrapper.
    pub fn new(data: altair::SyncCommitteeMessage) -> Self {
        Self(data)
    }

    /// Creates a partial signed sync committee message wrapper.
    pub fn new_partial(data: altair::SyncCommitteeMessage, share_idx: u64) -> ParSignedData<Self> {
        ParSignedData::new(Self::new(data), share_idx)
    }
}

/// Sync contribution-and-proof wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SyncContributionAndProof(
    /// Wrapped payload.
    pub altair::ContributionAndProof,
);

impl SignedData for SyncContributionAndProof {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        Ok(sig_from_eth2(self.0.selection_proof))
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        let mut out = self.clone();
        out.0.selection_proof = sig_to_eth2(&signature);
        Ok(out)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        let data = altair::SyncAggregatorSelectionData {
            slot: self.0.contribution.slot,
            subcommittee_index: self.0.contribution.subcommittee_index,
        };

        Ok(hash_root(&data))
    }
}

impl SyncContributionAndProof {
    /// Creates a sync contribution-and-proof wrapper.
    pub fn new(proof: altair::ContributionAndProof) -> Self {
        Self(proof)
    }

    /// Creates a partial sync contribution-and-proof wrapper.
    pub fn new_partial(proof: altair::ContributionAndProof, share_idx: u64) -> ParSignedData<Self> {
        ParSignedData::new(Self::new(proof), share_idx)
    }
}

/// Signed sync contribution-and-proof wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedSyncContributionAndProof(
    /// Wrapped payload.
    pub altair::SignedContributionAndProof,
);

impl SignedData for SignedSyncContributionAndProof {
    type Error = SignedDataError;

    fn signature(&self) -> Result<Signature, Self::Error> {
        Ok(sig_from_eth2(self.0.signature))
    }

    fn set_signature(&self, signature: Signature) -> Result<Self, Self::Error> {
        let mut out = self.clone();
        out.0.signature = sig_to_eth2(&signature);
        Ok(out)
    }

    fn message_root(&self) -> Result<[u8; 32], Self::Error> {
        Ok(hash_root(&self.0.message))
    }
}

impl SignedSyncContributionAndProof {
    /// Creates a signed sync contribution-and-proof wrapper.
    pub fn new(proof: altair::SignedContributionAndProof) -> Self {
        Self(proof)
    }

    /// Creates a partial signed sync contribution-and-proof wrapper.
    pub fn new_partial(
        proof: altair::SignedContributionAndProof,
        share_idx: u64,
    ) -> ParSignedData<Self> {
        ParSignedData::new(Self::new(proof), share_idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
    use pluto_eth2api::spec::{altair, bellatrix, capella, deneb, electra, fulu};
    use pluto_ssz::{BitList, BitVector};
    use serde::{Serialize, de::DeserializeOwned};
    use std::{fs, path::PathBuf};
    use test_case::test_case;

    fn signeddata_fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("signeddata")
            .join(name)
    }

    fn load_signeddata_fixture(name: &str) -> serde_json::Value {
        let data = fs::read_to_string(signeddata_fixture_path(name)).unwrap();
        serde_json::from_str(&data).unwrap()
    }

    /// Golden test helper — checks typed JSON roundtrip and a caller-provided
    /// hash root.
    fn assert_golden_fixture<J>(
        fixture_name: &str,
        expected_root: &str,
        hash_value: fn(&J) -> Result<[u8; 32], SignedDataError>,
    ) where
        J: DeserializeOwned + PartialEq + std::fmt::Debug + Serialize,
    {
        let entry = load_signeddata_fixture(fixture_name);

        let value: J = serde_json::from_value(entry.clone()).unwrap();
        assert_eq!(serde_json::to_value(&value).unwrap(), entry);

        let serialized = serde_json::to_vec(&value).unwrap();
        let serialized_json: serde_json::Value = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(serialized_json, entry);

        let roundtrip: J = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(roundtrip, value);
        assert_eq!(hex::encode(hash_value(&value).unwrap()), expected_root);
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct AttestationDataJson {
        attestation_data: phase0::AttestationData,
        attestation_duty: serde_json::Value,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct FuluBlockContentsJson {
        block: electra::BeaconBlock,
        kzg_proofs: serde_json::Value,
        blobs: serde_json::Value,
    }

    fn sample_signature(byte: u8) -> Signature {
        Signature::new([byte; 96])
    }

    fn sample_root(byte: u8) -> phase0::Root {
        [byte; 32]
    }

    fn sample_hash32(byte: u8) -> phase0::Hash32 {
        [byte; 32]
    }

    fn sample_eth1_data(byte: u8) -> phase0::ETH1Data {
        phase0::ETH1Data {
            deposit_root: sample_root(byte),
            deposit_count: u64::from(byte),
            block_hash: sample_hash32(byte.wrapping_add(1)),
        }
    }

    fn sample_bitvector_one<const SIZE: usize>() -> BitVector<SIZE> {
        let encoded = format!(
            "\"0x01{}\"",
            "00".repeat(SIZE.div_ceil(8).saturating_sub(1))
        );
        serde_json::from_str(&encoded).unwrap()
    }

    fn sample_bitlist_one_sized<const MAX: usize>() -> BitList<MAX> {
        serde_json::from_str("\"0x0101\"").unwrap()
    }

    fn sample_sync_aggregate(byte: u8) -> altair::SyncAggregate {
        altair::SyncAggregate {
            sync_committee_bits: sample_bitvector_one::<512>(),
            sync_committee_signature: [byte; 96],
        }
    }

    fn sample_signed_bls_to_execution_change(byte: u8) -> capella::SignedBLSToExecutionChange {
        capella::SignedBLSToExecutionChange {
            message: capella::BLSToExecutionChange {
                validator_index: u64::from(byte),
                from_bls_pubkey: [byte; 48],
                to_execution_address: [byte; 20],
            },
            signature: [byte; 96],
        }
    }

    fn sample_bellatrix_execution_payload(byte: u8) -> bellatrix::ExecutionPayload {
        bellatrix::ExecutionPayload {
            parent_hash: sample_hash32(byte),
            fee_recipient: [byte; 20],
            state_root: sample_root(byte.wrapping_add(1)),
            receipts_root: sample_root(byte.wrapping_add(2)),
            logs_bloom: [byte; 256],
            prev_randao: [byte; 32],
            block_number: u64::from(byte),
            gas_limit: 30_000_000,
            gas_used: 10_000_000,
            timestamp: u64::from(byte),
            extra_data: vec![byte].into(),
            base_fee_per_gas: U256::from(u64::from(byte)),
            block_hash: sample_hash32(byte.wrapping_add(3)),
            transactions: vec![vec![byte].into()].into(),
        }
    }

    fn sample_bellatrix_execution_payload_header(byte: u8) -> bellatrix::ExecutionPayloadHeader {
        bellatrix::ExecutionPayloadHeader {
            parent_hash: sample_hash32(byte),
            fee_recipient: [byte; 20],
            state_root: sample_root(byte.wrapping_add(1)),
            receipts_root: sample_root(byte.wrapping_add(2)),
            logs_bloom: [byte; 256],
            prev_randao: [byte; 32],
            block_number: u64::from(byte),
            gas_limit: 30_000_000,
            gas_used: 10_000_000,
            timestamp: u64::from(byte),
            extra_data: vec![byte].into(),
            base_fee_per_gas: U256::from(u64::from(byte)),
            block_hash: sample_hash32(byte.wrapping_add(3)),
            transactions_root: sample_root(byte.wrapping_add(4)),
        }
    }

    fn sample_capella_execution_payload(byte: u8) -> capella::ExecutionPayload {
        capella::ExecutionPayload {
            parent_hash: sample_hash32(byte),
            fee_recipient: [byte; 20],
            state_root: sample_root(byte.wrapping_add(1)),
            receipts_root: sample_root(byte.wrapping_add(2)),
            logs_bloom: [byte; 256],
            prev_randao: [byte; 32],
            block_number: u64::from(byte),
            gas_limit: 30_000_000,
            gas_used: 10_000_000,
            timestamp: u64::from(byte),
            extra_data: vec![byte].into(),
            base_fee_per_gas: U256::from(u64::from(byte)),
            block_hash: sample_hash32(byte.wrapping_add(3)),
            transactions: vec![vec![byte].into()].into(),
            withdrawals: vec![capella::Withdrawal {
                index: u64::from(byte),
                validator_index: u64::from(byte),
                address: [byte; 20],
                amount: u64::from(byte),
            }]
            .into(),
        }
    }

    fn sample_capella_execution_payload_header(byte: u8) -> capella::ExecutionPayloadHeader {
        capella::ExecutionPayloadHeader {
            parent_hash: sample_hash32(byte),
            fee_recipient: [byte; 20],
            state_root: sample_root(byte.wrapping_add(1)),
            receipts_root: sample_root(byte.wrapping_add(2)),
            logs_bloom: [byte; 256],
            prev_randao: [byte; 32],
            block_number: u64::from(byte),
            gas_limit: 30_000_000,
            gas_used: 10_000_000,
            timestamp: u64::from(byte),
            extra_data: vec![byte].into(),
            base_fee_per_gas: U256::from(u64::from(byte)),
            block_hash: sample_hash32(byte.wrapping_add(3)),
            transactions_root: sample_root(byte.wrapping_add(4)),
            withdrawals_root: sample_root(byte.wrapping_add(5)),
        }
    }

    fn sample_deneb_execution_payload(byte: u8) -> deneb::ExecutionPayload {
        deneb::ExecutionPayload {
            parent_hash: sample_hash32(byte),
            fee_recipient: [byte; 20],
            state_root: sample_root(byte.wrapping_add(1)),
            receipts_root: sample_root(byte.wrapping_add(2)),
            logs_bloom: [byte; 256],
            prev_randao: [byte; 32],
            block_number: u64::from(byte),
            gas_limit: 30_000_000,
            gas_used: 10_000_000,
            timestamp: u64::from(byte),
            extra_data: vec![byte].into(),
            base_fee_per_gas: U256::from(u64::from(byte)),
            block_hash: sample_hash32(byte.wrapping_add(3)),
            transactions: vec![vec![byte].into()].into(),
            withdrawals: vec![capella::Withdrawal {
                index: u64::from(byte),
                validator_index: u64::from(byte),
                address: [byte; 20],
                amount: u64::from(byte),
            }]
            .into(),
            blob_gas_used: u64::from(byte),
            excess_blob_gas: u64::from(byte.wrapping_add(1)),
        }
    }

    fn sample_deneb_execution_payload_header(byte: u8) -> deneb::ExecutionPayloadHeader {
        deneb::ExecutionPayloadHeader {
            parent_hash: sample_hash32(byte),
            fee_recipient: [byte; 20],
            state_root: sample_root(byte.wrapping_add(1)),
            receipts_root: sample_root(byte.wrapping_add(2)),
            logs_bloom: [byte; 256],
            prev_randao: [byte; 32],
            block_number: u64::from(byte),
            gas_limit: 30_000_000,
            gas_used: 10_000_000,
            timestamp: u64::from(byte),
            extra_data: vec![byte].into(),
            base_fee_per_gas: U256::from(u64::from(byte)),
            block_hash: sample_hash32(byte.wrapping_add(3)),
            transactions_root: sample_root(byte.wrapping_add(4)),
            withdrawals_root: sample_root(byte.wrapping_add(5)),
            blob_gas_used: u64::from(byte),
            excess_blob_gas: u64::from(byte.wrapping_add(1)),
        }
    }

    fn sample_execution_requests(byte: u8) -> electra::ExecutionRequests {
        electra::ExecutionRequests {
            deposits: vec![electra::DepositRequest {
                pubkey: [byte; 48],
                withdrawal_credentials: [byte; 32],
                amount: u64::from(byte),
                signature: [byte; 96],
                index: u64::from(byte),
            }]
            .into(),
            withdrawals: vec![electra::WithdrawalRequest {
                source_address: [byte; 20],
                validator_pubkey: [byte; 48],
                amount: u64::from(byte),
            }]
            .into(),
            consolidations: vec![electra::ConsolidationRequest {
                source_address: [byte; 20],
                source_pubkey: [byte; 48],
                target_pubkey: [byte; 48],
            }]
            .into(),
        }
    }

    fn sample_phase0_body(byte: u8) -> phase0::BeaconBlockBody {
        phase0::BeaconBlockBody {
            randao_reveal: [byte; 96],
            eth1_data: sample_eth1_data(byte),
            graffiti: sample_root(byte),
            proposer_slashings: vec![].into(),
            attester_slashings: vec![].into(),
            attestations: vec![].into(),
            deposits: vec![].into(),
            voluntary_exits: vec![].into(),
        }
    }

    fn sample_altair_body(byte: u8) -> altair::BeaconBlockBody {
        altair::BeaconBlockBody {
            randao_reveal: [byte; 96],
            eth1_data: sample_eth1_data(byte),
            graffiti: sample_root(byte),
            proposer_slashings: vec![].into(),
            attester_slashings: vec![].into(),
            attestations: vec![].into(),
            deposits: vec![].into(),
            voluntary_exits: vec![].into(),
            sync_aggregate: sample_sync_aggregate(byte),
        }
    }

    fn sample_bellatrix_body(byte: u8) -> bellatrix::BeaconBlockBody {
        bellatrix::BeaconBlockBody {
            randao_reveal: [byte; 96],
            eth1_data: sample_eth1_data(byte),
            graffiti: sample_root(byte),
            proposer_slashings: vec![].into(),
            attester_slashings: vec![].into(),
            attestations: vec![].into(),
            deposits: vec![].into(),
            voluntary_exits: vec![].into(),
            sync_aggregate: sample_sync_aggregate(byte),
            execution_payload: sample_bellatrix_execution_payload(byte),
        }
    }

    fn sample_bellatrix_blinded_body(byte: u8) -> bellatrix::BlindedBeaconBlockBody {
        bellatrix::BlindedBeaconBlockBody {
            randao_reveal: [byte; 96],
            eth1_data: sample_eth1_data(byte),
            graffiti: sample_root(byte),
            proposer_slashings: vec![].into(),
            attester_slashings: vec![].into(),
            attestations: vec![].into(),
            deposits: vec![].into(),
            voluntary_exits: vec![].into(),
            sync_aggregate: sample_sync_aggregate(byte),
            execution_payload_header: sample_bellatrix_execution_payload_header(byte),
        }
    }

    fn sample_capella_body(byte: u8) -> capella::BeaconBlockBody {
        capella::BeaconBlockBody {
            randao_reveal: [byte; 96],
            eth1_data: sample_eth1_data(byte),
            graffiti: sample_root(byte),
            proposer_slashings: vec![].into(),
            attester_slashings: vec![].into(),
            attestations: vec![].into(),
            deposits: vec![].into(),
            voluntary_exits: vec![].into(),
            sync_aggregate: sample_sync_aggregate(byte),
            execution_payload: sample_capella_execution_payload(byte),
            bls_to_execution_changes: vec![sample_signed_bls_to_execution_change(byte)].into(),
        }
    }

    fn sample_capella_blinded_body(byte: u8) -> capella::BlindedBeaconBlockBody {
        capella::BlindedBeaconBlockBody {
            randao_reveal: [byte; 96],
            eth1_data: sample_eth1_data(byte),
            graffiti: sample_root(byte),
            proposer_slashings: vec![].into(),
            attester_slashings: vec![].into(),
            attestations: vec![].into(),
            deposits: vec![].into(),
            voluntary_exits: vec![].into(),
            sync_aggregate: sample_sync_aggregate(byte),
            execution_payload_header: sample_capella_execution_payload_header(byte),
            bls_to_execution_changes: vec![sample_signed_bls_to_execution_change(byte)].into(),
        }
    }

    fn sample_deneb_body(byte: u8) -> deneb::BeaconBlockBody {
        deneb::BeaconBlockBody {
            randao_reveal: [byte; 96],
            eth1_data: sample_eth1_data(byte),
            graffiti: sample_root(byte),
            proposer_slashings: vec![].into(),
            attester_slashings: vec![].into(),
            attestations: vec![].into(),
            deposits: vec![].into(),
            voluntary_exits: vec![].into(),
            sync_aggregate: sample_sync_aggregate(byte),
            execution_payload: sample_deneb_execution_payload(byte),
            bls_to_execution_changes: vec![sample_signed_bls_to_execution_change(byte)].into(),
            blob_kzg_commitments: vec![deneb::KZGCommitment { bytes: [byte; 48] }].into(),
        }
    }

    fn sample_deneb_blinded_body(byte: u8) -> deneb::BlindedBeaconBlockBody {
        deneb::BlindedBeaconBlockBody {
            randao_reveal: [byte; 96],
            eth1_data: sample_eth1_data(byte),
            graffiti: sample_root(byte),
            proposer_slashings: vec![].into(),
            attester_slashings: vec![].into(),
            attestations: vec![].into(),
            deposits: vec![].into(),
            voluntary_exits: vec![].into(),
            sync_aggregate: sample_sync_aggregate(byte),
            execution_payload_header: sample_deneb_execution_payload_header(byte),
            bls_to_execution_changes: vec![sample_signed_bls_to_execution_change(byte)].into(),
            blob_kzg_commitments: vec![deneb::KZGCommitment { bytes: [byte; 48] }].into(),
        }
    }

    fn sample_electra_body(byte: u8) -> electra::BeaconBlockBody {
        electra::BeaconBlockBody {
            randao_reveal: [byte; 96],
            eth1_data: sample_eth1_data(byte),
            graffiti: sample_root(byte),
            proposer_slashings: vec![].into(),
            attester_slashings: vec![].into(),
            attestations: vec![].into(),
            deposits: vec![].into(),
            voluntary_exits: vec![].into(),
            sync_aggregate: sample_sync_aggregate(byte),
            execution_payload: sample_deneb_execution_payload(byte),
            bls_to_execution_changes: vec![sample_signed_bls_to_execution_change(byte)].into(),
            blob_kzg_commitments: vec![deneb::KZGCommitment { bytes: [byte; 48] }].into(),
            execution_requests: sample_execution_requests(byte),
        }
    }

    fn sample_electra_blinded_body(byte: u8) -> electra::BlindedBeaconBlockBody {
        electra::BlindedBeaconBlockBody {
            randao_reveal: [byte; 96],
            eth1_data: sample_eth1_data(byte),
            graffiti: sample_root(byte),
            proposer_slashings: vec![].into(),
            attester_slashings: vec![].into(),
            attestations: vec![].into(),
            deposits: vec![].into(),
            voluntary_exits: vec![].into(),
            sync_aggregate: sample_sync_aggregate(byte),
            execution_payload_header: sample_deneb_execution_payload_header(byte),
            bls_to_execution_changes: vec![sample_signed_bls_to_execution_change(byte)].into(),
            blob_kzg_commitments: vec![deneb::KZGCommitment { bytes: [byte; 48] }].into(),
            execution_requests: sample_execution_requests(byte),
        }
    }

    fn sample_fulu_body(byte: u8) -> electra::BeaconBlockBody {
        sample_electra_body(byte)
    }

    fn sample_fulu_blinded_body(byte: u8) -> electra::BlindedBeaconBlockBody {
        sample_electra_blinded_body(byte)
    }

    fn sample_phase0_block(byte: u8) -> phase0::SignedBeaconBlock {
        phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot: u64::from(byte),
                proposer_index: 1,
                parent_root: sample_root(0x01),
                state_root: sample_root(0x02),
                body: sample_phase0_body(0x03),
            },
            signature: [byte; 96],
        }
    }

    fn sample_altair_block(byte: u8) -> altair::SignedBeaconBlock {
        altair::SignedBeaconBlock {
            message: altair::BeaconBlock {
                slot: u64::from(byte),
                proposer_index: 11,
                parent_root: sample_root(0x31),
                state_root: sample_root(0x32),
                body: sample_altair_body(0x33),
            },
            signature: [byte; 96],
        }
    }

    fn sample_bellatrix_block(byte: u8) -> bellatrix::SignedBeaconBlock {
        bellatrix::SignedBeaconBlock {
            message: bellatrix::BeaconBlock {
                slot: u64::from(byte),
                proposer_index: 2,
                parent_root: sample_root(0x04),
                state_root: sample_root(0x05),
                body: sample_bellatrix_body(0x06),
            },
            signature: [byte; 96],
        }
    }

    fn sample_bellatrix_blinded_block(byte: u8) -> bellatrix::SignedBlindedBeaconBlock {
        bellatrix::SignedBlindedBeaconBlock {
            message: bellatrix::BlindedBeaconBlock {
                slot: u64::from(byte),
                proposer_index: 3,
                parent_root: sample_root(0x07),
                state_root: sample_root(0x08),
                body: sample_bellatrix_blinded_body(0x09),
            },
            signature: [byte; 96],
        }
    }

    fn sample_capella_block(byte: u8) -> capella::SignedBeaconBlock {
        capella::SignedBeaconBlock {
            message: capella::BeaconBlock {
                slot: u64::from(byte),
                proposer_index: 4,
                parent_root: sample_root(0x0A),
                state_root: sample_root(0x0B),
                body: sample_capella_body(0x0C),
            },
            signature: [byte; 96],
        }
    }

    fn sample_capella_blinded_block(byte: u8) -> capella::SignedBlindedBeaconBlock {
        capella::SignedBlindedBeaconBlock {
            message: capella::BlindedBeaconBlock {
                slot: u64::from(byte),
                proposer_index: 5,
                parent_root: sample_root(0x0D),
                state_root: sample_root(0x0E),
                body: sample_capella_blinded_body(0x0F),
            },
            signature: [byte; 96],
        }
    }

    fn sample_deneb_block(byte: u8) -> deneb::SignedBlockContents {
        deneb::SignedBlockContents {
            signed_block: deneb::SignedBeaconBlock {
                message: deneb::BeaconBlock {
                    slot: u64::from(byte),
                    proposer_index: 6,
                    parent_root: sample_root(0x10),
                    state_root: sample_root(0x11),
                    body: sample_deneb_body(0x12),
                },
                signature: [byte; 96],
            },
            kzg_proofs: vec![deneb::KZGProof([byte; 48])],
            blobs: vec![],
        }
    }

    fn sample_deneb_blinded_block(byte: u8) -> deneb::SignedBlindedBeaconBlock {
        deneb::SignedBlindedBeaconBlock {
            message: deneb::BlindedBeaconBlock {
                slot: u64::from(byte),
                proposer_index: 7,
                parent_root: sample_root(0x13),
                state_root: sample_root(0x14),
                body: sample_deneb_blinded_body(0x15),
            },
            signature: [byte; 96],
        }
    }

    fn sample_electra_block(byte: u8) -> electra::SignedBlockContents {
        electra::SignedBlockContents {
            signed_block: electra::SignedBeaconBlock {
                message: electra::BeaconBlock {
                    slot: u64::from(byte),
                    proposer_index: 8,
                    parent_root: sample_root(0x16),
                    state_root: sample_root(0x17),
                    body: sample_electra_body(0x18),
                },
                signature: [byte; 96],
            },
            kzg_proofs: vec![deneb::KZGProof([byte; 48])],
            blobs: vec![],
        }
    }

    fn sample_electra_blinded_block(byte: u8) -> electra::SignedBlindedBeaconBlock {
        electra::SignedBlindedBeaconBlock {
            message: electra::BlindedBeaconBlock {
                slot: u64::from(byte),
                proposer_index: 9,
                parent_root: sample_root(0x19),
                state_root: sample_root(0x1A),
                body: sample_electra_blinded_body(0x1B),
            },
            signature: [byte; 96],
        }
    }

    fn sample_fulu_block(byte: u8) -> fulu::SignedBlockContents {
        fulu::SignedBlockContents {
            signed_block: electra::SignedBeaconBlock {
                message: electra::BeaconBlock {
                    slot: u64::from(byte),
                    proposer_index: 10,
                    parent_root: sample_root(0x1C),
                    state_root: sample_root(0x1D),
                    body: sample_fulu_body(0x1E),
                },
                signature: [byte; 96],
            },
            kzg_proofs: vec![deneb::KZGProof([byte; 48])],
            blobs: vec![],
        }
    }

    fn sample_fulu_blinded_block(byte: u8) -> electra::SignedBlindedBeaconBlock {
        electra::SignedBlindedBeaconBlock {
            message: electra::BlindedBeaconBlock {
                slot: u64::from(byte),
                proposer_index: 12,
                parent_root: sample_root(0x34),
                state_root: sample_root(0x35),
                body: sample_fulu_blinded_body(0x36),
            },
            signature: [byte; 96],
        }
    }

    fn sample_attestation_data() -> phase0::AttestationData {
        phase0::AttestationData {
            slot: 1,
            index: 2,
            beacon_block_root: sample_root(0x11),
            source: phase0::Checkpoint {
                epoch: 3,
                root: sample_root(0x22),
            },
            target: phase0::Checkpoint {
                epoch: 4,
                root: sample_root(0x33),
            },
        }
    }

    fn sample_bitlist_one() -> BitList<2048> {
        sample_bitlist_one_sized::<2048>()
    }

    fn sample_electra_bitlist_one() -> BitList<131_072> {
        sample_bitlist_one_sized::<131_072>()
    }

    fn sample_phase0_attestation() -> phase0::Attestation {
        phase0::Attestation {
            aggregation_bits: sample_bitlist_one(),
            data: sample_attestation_data(),
            signature: [0x34; 96],
        }
    }

    fn sample_electra_attestation() -> electra::Attestation {
        electra::Attestation {
            aggregation_bits: sample_electra_bitlist_one(),
            data: sample_attestation_data(),
            signature: [0x35; 96],
            committee_bits: sample_bitvector_one::<64>(),
        }
    }

    fn sample_phase0_signed_aggregate_and_proof() -> phase0::SignedAggregateAndProof {
        phase0::SignedAggregateAndProof {
            message: phase0::AggregateAndProof {
                aggregator_index: 7,
                aggregate: sample_phase0_attestation(),
                selection_proof: [0x55; 96],
            },
            signature: [0x66; 96],
        }
    }

    fn sample_electra_signed_aggregate_and_proof() -> electra::SignedAggregateAndProof {
        electra::SignedAggregateAndProof {
            message: electra::AggregateAndProof {
                aggregator_index: 8,
                aggregate: sample_electra_attestation(),
                selection_proof: [0x77; 96],
            },
            signature: [0x88; 96],
        }
    }

    fn sample_versioned_signed_proposal(
        version: versioned::DataVersion,
        blinded: bool,
    ) -> versioned::VersionedSignedProposal {
        match (version, blinded) {
            (versioned::DataVersion::Phase0, _) => versioned::VersionedSignedProposal {
                version,
                blinded,
                block: versioned::SignedProposalBlock::Phase0(sample_phase0_block(0x10)),
            },
            (versioned::DataVersion::Altair, _) => versioned::VersionedSignedProposal {
                version,
                blinded,
                block: versioned::SignedProposalBlock::Altair(sample_altair_block(0x11)),
            },
            (versioned::DataVersion::Bellatrix, false) => versioned::VersionedSignedProposal {
                version,
                blinded: false,
                block: versioned::SignedProposalBlock::Bellatrix(sample_bellatrix_block(0x12)),
            },
            (versioned::DataVersion::Bellatrix, true) => versioned::VersionedSignedProposal {
                version,
                blinded,
                block: versioned::SignedProposalBlock::BellatrixBlinded(
                    sample_bellatrix_blinded_block(0x13),
                ),
            },
            (versioned::DataVersion::Capella, false) => versioned::VersionedSignedProposal {
                version,
                blinded: false,
                block: versioned::SignedProposalBlock::Capella(sample_capella_block(0x14)),
            },
            (versioned::DataVersion::Capella, true) => versioned::VersionedSignedProposal {
                version,
                blinded,
                block: versioned::SignedProposalBlock::CapellaBlinded(
                    sample_capella_blinded_block(0x15),
                ),
            },
            (versioned::DataVersion::Deneb, false) => versioned::VersionedSignedProposal {
                version,
                blinded: false,
                block: versioned::SignedProposalBlock::Deneb(sample_deneb_block(0x16)),
            },
            (versioned::DataVersion::Deneb, true) => versioned::VersionedSignedProposal {
                version,
                blinded,
                block: versioned::SignedProposalBlock::DenebBlinded(sample_deneb_blinded_block(
                    0x17,
                )),
            },
            (versioned::DataVersion::Electra, false) => versioned::VersionedSignedProposal {
                version,
                blinded: false,
                block: versioned::SignedProposalBlock::Electra(sample_electra_block(0x18)),
            },
            (versioned::DataVersion::Electra, true) => versioned::VersionedSignedProposal {
                version,
                blinded,
                block: versioned::SignedProposalBlock::ElectraBlinded(
                    sample_electra_blinded_block(0x19),
                ),
            },
            (versioned::DataVersion::Fulu, false) => versioned::VersionedSignedProposal {
                version,
                blinded: false,
                block: versioned::SignedProposalBlock::Fulu(sample_fulu_block(0x1A)),
            },
            (versioned::DataVersion::Fulu, true) => versioned::VersionedSignedProposal {
                version,
                blinded,
                block: versioned::SignedProposalBlock::FuluBlinded(sample_fulu_blinded_block(0x1B)),
            },
            _ => panic!("unsupported proposal version"),
        }
    }

    fn sample_versioned_attestation(
        version: versioned::DataVersion,
    ) -> versioned::VersionedAttestation {
        match version {
            versioned::DataVersion::Phase0 => versioned::VersionedAttestation {
                version,
                attestation: Some(versioned::AttestationPayload::Phase0(
                    sample_phase0_attestation(),
                )),
                ..Default::default()
            },
            versioned::DataVersion::Altair => versioned::VersionedAttestation {
                version,
                attestation: Some(versioned::AttestationPayload::Altair(
                    sample_phase0_attestation(),
                )),
                ..Default::default()
            },
            versioned::DataVersion::Bellatrix => versioned::VersionedAttestation {
                version,
                attestation: Some(versioned::AttestationPayload::Bellatrix(
                    sample_phase0_attestation(),
                )),
                ..Default::default()
            },
            versioned::DataVersion::Capella => versioned::VersionedAttestation {
                version,
                attestation: Some(versioned::AttestationPayload::Capella(
                    sample_phase0_attestation(),
                )),
                ..Default::default()
            },
            versioned::DataVersion::Deneb => versioned::VersionedAttestation {
                version,
                attestation: Some(versioned::AttestationPayload::Deneb(
                    sample_phase0_attestation(),
                )),
                ..Default::default()
            },
            versioned::DataVersion::Electra => versioned::VersionedAttestation {
                version,
                attestation: Some(versioned::AttestationPayload::Electra(
                    sample_electra_attestation(),
                )),
                ..Default::default()
            },
            versioned::DataVersion::Fulu => versioned::VersionedAttestation {
                version,
                attestation: Some(versioned::AttestationPayload::Fulu(
                    sample_electra_attestation(),
                )),
                ..Default::default()
            },
            versioned::DataVersion::Unknown => versioned::VersionedAttestation::default(),
        }
    }

    fn sample_versioned_signed_aggregate_and_proof(
        version: versioned::DataVersion,
    ) -> versioned::VersionedSignedAggregateAndProof {
        match version {
            versioned::DataVersion::Phase0 => versioned::VersionedSignedAggregateAndProof {
                version,
                aggregate_and_proof: versioned::SignedAggregateAndProofPayload::Phase0(
                    sample_phase0_signed_aggregate_and_proof(),
                ),
            },
            versioned::DataVersion::Altair => versioned::VersionedSignedAggregateAndProof {
                version,
                aggregate_and_proof: versioned::SignedAggregateAndProofPayload::Altair(
                    sample_phase0_signed_aggregate_and_proof(),
                ),
            },
            versioned::DataVersion::Bellatrix => versioned::VersionedSignedAggregateAndProof {
                version,
                aggregate_and_proof: versioned::SignedAggregateAndProofPayload::Bellatrix(
                    sample_phase0_signed_aggregate_and_proof(),
                ),
            },
            versioned::DataVersion::Capella => versioned::VersionedSignedAggregateAndProof {
                version,
                aggregate_and_proof: versioned::SignedAggregateAndProofPayload::Capella(
                    sample_phase0_signed_aggregate_and_proof(),
                ),
            },
            versioned::DataVersion::Deneb => versioned::VersionedSignedAggregateAndProof {
                version,
                aggregate_and_proof: versioned::SignedAggregateAndProofPayload::Deneb(
                    sample_phase0_signed_aggregate_and_proof(),
                ),
            },
            versioned::DataVersion::Electra => versioned::VersionedSignedAggregateAndProof {
                version,
                aggregate_and_proof: versioned::SignedAggregateAndProofPayload::Electra(
                    sample_electra_signed_aggregate_and_proof(),
                ),
            },
            versioned::DataVersion::Fulu => versioned::VersionedSignedAggregateAndProof {
                version,
                aggregate_and_proof: versioned::SignedAggregateAndProofPayload::Fulu(
                    sample_electra_signed_aggregate_and_proof(),
                ),
            },
            versioned::DataVersion::Unknown => panic!("unsupported aggregate-and-proof version"),
        }
    }

    fn sample_versioned_signed_blinded_proposal(
        version: versioned::DataVersion,
    ) -> versioned::VersionedSignedBlindedProposal {
        match version {
            versioned::DataVersion::Electra => versioned::VersionedSignedBlindedProposal {
                version,
                block: versioned::SignedBlindedProposalBlock::Electra(
                    sample_electra_blinded_block(0x11),
                ),
            },
            versioned::DataVersion::Fulu => versioned::VersionedSignedBlindedProposal {
                version,
                block: versioned::SignedBlindedProposalBlock::Fulu(sample_fulu_blinded_block(0x11)),
            },
            _ => panic!("unsupported blinded proposal version"),
        }
    }

    fn assert_set_signature<T>(data: T)
    where
        T: SignedData<Error = SignedDataError> + std::fmt::Debug + PartialEq,
    {
        let clone = data.set_signature(sample_signature(0xAB)).unwrap();
        let clone_sig = clone.signature().unwrap();
        let data_sig = data.signature().unwrap();
        assert_ne!(clone_sig, data_sig);
        assert!(clone_sig.as_ref().iter().any(|byte| *byte != 0));

        let msg_root = data.message_root().unwrap();
        let clone_root = clone.message_root().unwrap();
        assert_eq!(msg_root, clone_root);
    }

    #[test]
    fn signed_data_set_signature() {
        assert_set_signature(
            VersionedSignedProposal::new(sample_versioned_signed_proposal(
                versioned::DataVersion::Phase0,
                false,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedSignedProposal::new(sample_versioned_signed_proposal(
                versioned::DataVersion::Altair,
                false,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedSignedProposal::new(sample_versioned_signed_proposal(
                versioned::DataVersion::Bellatrix,
                false,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedSignedProposal::new(sample_versioned_signed_proposal(
                versioned::DataVersion::Bellatrix,
                true,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedSignedProposal::new(sample_versioned_signed_proposal(
                versioned::DataVersion::Capella,
                false,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedSignedProposal::new(sample_versioned_signed_proposal(
                versioned::DataVersion::Capella,
                true,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedSignedProposal::new(sample_versioned_signed_proposal(
                versioned::DataVersion::Deneb,
                false,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedSignedProposal::new(sample_versioned_signed_proposal(
                versioned::DataVersion::Deneb,
                true,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedSignedProposal::new(sample_versioned_signed_proposal(
                versioned::DataVersion::Electra,
                false,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedSignedProposal::new(sample_versioned_signed_proposal(
                versioned::DataVersion::Electra,
                true,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedSignedProposal::new(sample_versioned_signed_proposal(
                versioned::DataVersion::Fulu,
                false,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedSignedProposal::new(sample_versioned_signed_proposal(
                versioned::DataVersion::Fulu,
                true,
            ))
            .unwrap(),
        );

        assert_set_signature(BeaconCommitteeSelection::new(
            v1::BeaconCommitteeSelection {
                slot: 1,
                validator_index: 2,
                selection_proof: [0x44; 96],
            },
        ));

        assert_set_signature(VersionedSignedAggregateAndProof::new(
            sample_versioned_signed_aggregate_and_proof(versioned::DataVersion::Phase0),
        ));
        assert_set_signature(VersionedSignedAggregateAndProof::new(
            sample_versioned_signed_aggregate_and_proof(versioned::DataVersion::Altair),
        ));
        assert_set_signature(VersionedSignedAggregateAndProof::new(
            sample_versioned_signed_aggregate_and_proof(versioned::DataVersion::Bellatrix),
        ));
        assert_set_signature(VersionedSignedAggregateAndProof::new(
            sample_versioned_signed_aggregate_and_proof(versioned::DataVersion::Capella),
        ));
        assert_set_signature(VersionedSignedAggregateAndProof::new(
            sample_versioned_signed_aggregate_and_proof(versioned::DataVersion::Deneb),
        ));
        assert_set_signature(VersionedSignedAggregateAndProof::new(
            sample_versioned_signed_aggregate_and_proof(versioned::DataVersion::Electra),
        ));
        assert_set_signature(VersionedSignedAggregateAndProof::new(
            sample_versioned_signed_aggregate_and_proof(versioned::DataVersion::Fulu),
        ));

        assert_set_signature(
            VersionedAttestation::new(sample_versioned_attestation(versioned::DataVersion::Phase0))
                .unwrap(),
        );
        assert_set_signature(
            VersionedAttestation::new(sample_versioned_attestation(versioned::DataVersion::Altair))
                .unwrap(),
        );
        assert_set_signature(
            VersionedAttestation::new(sample_versioned_attestation(
                versioned::DataVersion::Bellatrix,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedAttestation::new(sample_versioned_attestation(
                versioned::DataVersion::Capella,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedAttestation::new(sample_versioned_attestation(versioned::DataVersion::Deneb))
                .unwrap(),
        );
        assert_set_signature(
            VersionedAttestation::new(sample_versioned_attestation(
                versioned::DataVersion::Electra,
            ))
            .unwrap(),
        );
        assert_set_signature(
            VersionedAttestation::new(sample_versioned_attestation(versioned::DataVersion::Fulu))
                .unwrap(),
        );

        assert_set_signature(SignedSyncMessage::new(altair::SyncCommitteeMessage {
            slot: 1,
            beacon_block_root: sample_root(0x22),
            validator_index: 2,
            signature: [0x33; 96],
        }));

        let bits = sample_bitvector_one::<128>();
        assert_set_signature(SignedSyncContributionAndProof::new(
            altair::SignedContributionAndProof {
                message: altair::ContributionAndProof {
                    aggregator_index: 1,
                    contribution: altair::SyncCommitteeContribution {
                        slot: 3,
                        beacon_block_root: sample_root(0x44),
                        subcommittee_index: 2,
                        aggregation_bits: bits.clone(),
                        signature: [0x55; 96],
                    },
                    selection_proof: [0x66; 96],
                },
                signature: [0x77; 96],
            },
        ));

        assert_set_signature(SyncCommitteeSelection::new(v1::SyncCommitteeSelection {
            slot: 1,
            validator_index: 2,
            subcommittee_index: 3,
            selection_proof: [0x88; 96],
        }));
    }

    // ── golden fixture tests ──────────────────────────────────────────

    #[test]
    fn golden_attestation_data() {
        assert_golden_fixture::<AttestationDataJson>(
            "TestJSONSerialisation_AttestationData.json.golden",
            "48a36feed7959ae71dc32f007eea50f81a17747e73f1d297dd134b7a70eef138",
            |d| Ok(hash_root(&d.attestation_data)),
        );
    }

    #[test]
    fn golden_beacon_committee_selection() {
        assert_golden_fixture::<BeaconCommitteeSelection>(
            "TestJSONSerialisation_BeaconCommitteeSelection.json.golden",
            "76090e708e9b20aa000000000000000000000000000000000000000000000000",
            SignedData::message_root,
        );
    }

    #[test]
    fn golden_signed_randao() {
        assert_golden_fixture::<SignedRandao>(
            "TestJSONSerialisation_SignedRandao.json.golden",
            "1e34c5f04204cb9a000000000000000000000000000000000000000000000000",
            SignedData::message_root,
        );
    }

    #[test]
    fn golden_signed_sync_contribution_and_proof() {
        assert_golden_fixture::<SignedSyncContributionAndProof>(
            "TestJSONSerialisation_SignedSyncContributionAndProof.json.golden",
            "a9114ab23ddeca5729536b5f7132b0845653b235f11e10195659cd8b88ca48e4",
            SignedData::message_root,
        );
    }

    #[test]
    fn golden_signed_sync_message() {
        assert_golden_fixture::<SignedSyncMessage>(
            "TestJSONSerialisation_SignedSyncMessage.json.golden",
            "0272908d45b0164a1ed1fe5f6c6bb64a52fa1a95e2bdff2aea5190ce067ad5d2",
            SignedData::message_root,
        );
    }

    #[test]
    fn golden_signed_voluntary_exit() {
        assert_golden_fixture::<SignedVoluntaryExit>(
            "TestJSONSerialisation_SignedVoluntaryExit.json.golden",
            "d5fe7392cad0d8cd8cf3a3b29e14f6e687bc2e64141973099c60d3097d26629b",
            SignedData::message_root,
        );
    }

    #[test]
    fn golden_sync_committee_selection() {
        assert_golden_fixture::<SyncCommitteeSelection>(
            "TestJSONSerialisation_SyncCommitteeSelection.json.golden",
            "af587f1aea1ba20c11450b28da5905c861bdce697ea67d3ba23f62f8ffcffd25",
            SignedData::message_root,
        );
    }

    #[test]
    fn golden_sync_contribution() {
        assert_golden_fixture::<altair::SyncCommitteeContribution>(
            "TestJSONSerialisation_SyncContribution.json.golden",
            "cd2d3d4f8fbdfead4dd3e8df37851ca17d213e20926e22a2af95de60c4cd77c9",
            |d| Ok(hash_root(d)),
        );
    }

    #[test]
    fn golden_sync_contribution_and_proof() {
        assert_golden_fixture::<SyncContributionAndProof>(
            "TestJSONSerialisation_SyncContributionAndProof.json.golden",
            "7d175134bb90ae74308d78c559b8ae6e5280fee44de77209361305f8cc56e5df",
            SignedData::message_root,
        );
    }

    #[test]
    fn golden_versioned_aggregated_attestation() {
        assert_golden_fixture::<VersionedRawAttestationJson<electra::Attestation>>(
            "TestJSONSerialisation_VersionedAggregatedAttestation.json.golden",
            "d3a1b03a2d2be3f7c36323c6bd5b16b71a243c7d483245b816d670899f3fdc4f",
            |d| Ok(hash_root(&d.attestation)),
        );
    }

    #[test]
    fn golden_versioned_attestation() {
        assert_golden_fixture::<VersionedAttestation>(
            "TestJSONSerialisation_VersionedAttestation.json.golden",
            "a36b13159845b8afc947ea7f9ffd74ceb1178e9882533ee767b6a6578501771c",
            SignedData::message_root,
        );
    }

    #[test]
    fn golden_versioned_beacon_block() {
        assert_golden_fixture::<VersionedRawBlockJson<altair::BeaconBlock>>(
            "TestJSONSerialisation_VersionedBeaconBlock.json.golden",
            "8017bbdd58e803f567bc572224feaad3e74d0e828dc1442456d296a47435242c",
            |d| Ok(hash_root(&d.block)),
        );
    }

    #[test]
    fn golden_versioned_blinded_beacon_block() {
        assert_golden_fixture::<VersionedRawBlockJson<deneb::BlindedBeaconBlock>>(
            "TestJSONSerialisation_VersionedBlindedBeaconBlock.json.golden",
            "a55342eb3956bc429801615178a31395322a0e1608b7b1c9ff63c586e9260044",
            |d| Ok(hash_root(&d.block)),
        );
    }

    #[test]
    fn golden_versioned_blinded_proposal() {
        assert_golden_fixture::<VersionedRawBlockJson<deneb::BlindedBeaconBlock>>(
            "TestJSONSerialisation_VersionedBlindedProposal.json.golden",
            "a55342eb3956bc429801615178a31395322a0e1608b7b1c9ff63c586e9260044",
            |d| Ok(hash_root(&d.block)),
        );
    }

    #[test]
    fn golden_versioned_proposal() {
        assert_golden_fixture::<VersionedRawBlockJson<FuluBlockContentsJson>>(
            "TestJSONSerialisation_VersionedProposal.json.golden",
            "f7251cae23410c7454437e8e52dc16d1b4fbec965288923a0daad08659c2be86",
            |d| Ok(hash_root(&d.block.block)),
        );
    }

    #[test]
    fn golden_versioned_signed_aggregate_and_proof() {
        assert_golden_fixture::<VersionedSignedAggregateAndProof>(
            "TestJSONSerialisation_VersionedSignedAggregateAndProof.json.golden",
            "b583185cb9587e89300afca09c2052bd6e75b885fbdccdcea9d7bcdaa80646f0",
            SignedData::message_root,
        );
    }

    #[test]
    fn golden_versioned_signed_blinded_beacon_block() {
        assert_golden_fixture::<VersionedRawBlockJson<deneb::SignedBlindedBeaconBlock>>(
            "TestJSONSerialisation_VersionedSignedBlindedBeaconBlock.json.golden",
            "886e0f9eac32f3cb18ccc93bfb98677e7c3584f20b950e70a578f68a5118ba52",
            |d| Ok(hash_root(&d.block.message)),
        );
    }

    #[test]
    fn golden_versioned_signed_blinded_proposal() {
        assert_golden_fixture::<VersionedRawBlockJson<deneb::SignedBlindedBeaconBlock>>(
            "TestJSONSerialisation_VersionedSignedBlindedProposal.json.golden",
            "886e0f9eac32f3cb18ccc93bfb98677e7c3584f20b950e70a578f68a5118ba52",
            |d| Ok(hash_root(&d.block.message)),
        );
    }

    #[test]
    fn golden_versioned_signed_proposal_blinded() {
        assert_golden_fixture::<VersionedSignedProposal>(
            "TestJSONSerialisation_VersionedSignedProposal.json#01.golden",
            "4bf04729550ce290f32088070ae5dead2940c4350620a4bb85e04b0b1f3c2177",
            SignedData::message_root,
        );
    }

    #[test]
    fn golden_versioned_signed_proposal() {
        assert_golden_fixture::<VersionedSignedProposal>(
            "TestJSONSerialisation_VersionedSignedProposal.json.golden",
            "cd3d0d0abc5d9ba7a85b8c3388a6d4ebe2ee6367e20bf3c77a8d4977c657c0e1",
            SignedData::message_root,
        );
    }

    #[test]
    fn golden_versioned_signed_validator_registration() {
        assert_golden_fixture::<VersionedSignedValidatorRegistration>(
            "VersionedSignedValidatorRegistration.v1.json",
            "e342f29f5f6bb692ec8fae5ab27854afbb2a40296497001b31987a8587e70b8e",
            SignedData::message_root,
        );
    }

    #[test]
    fn signature() {
        let sig1 = sample_signature(0x22);
        let sig2 = sig1.clone();

        assert!(matches!(
            sig1.message_root(),
            Err(SignedDataError::UnsupportedSignatureMessageRoot)
        ));
        assert_eq!(sig1, sig1.signature().unwrap());
        assert_eq!(sig1.to_eth2(), sig2.signature().unwrap().to_eth2());

        let ss = sig1.set_signature(sig2.signature().unwrap()).unwrap();
        assert_eq!(sig2, ss);

        let js = serde_json::to_vec(&sig1).unwrap();
        let sig3: Signature = serde_json::from_slice(&js).unwrap();
        assert_eq!(sig1, sig3);
    }

    #[test]
    fn signature_json_errors() {
        let invalid_base64 = serde_json::from_slice::<Signature>(br#""%%%""#);
        assert!(matches!(
            invalid_base64,
            Err(err) if matches!(err.classify(), serde_json::error::Category::Data)
        ));

        let short = base64::engine::general_purpose::STANDARD.encode([0x11_u8; 95]);
        let wrong_len = serde_json::from_slice::<Signature>(format!("\"{short}\"").as_bytes());
        assert!(matches!(
            wrong_len,
            Err(err) if matches!(err.classify(), serde_json::error::Category::Data)
        ));
    }

    #[test_case(false ; "unblinded")]
    #[test_case(true ; "blinded")]
    fn test_new_versioned_signed_proposal_unknown_version_error(blinded: bool) {
        let result = VersionedSignedProposal::new(versioned::VersionedSignedProposal {
            version: versioned::DataVersion::Unknown,
            blinded,
            block: versioned::SignedProposalBlock::Phase0(sample_phase0_block(0x21)),
        });

        assert!(matches!(result, Err(SignedDataError::UnknownVersion)));
    }

    #[test_case(versioned::DataVersion::Electra ; "electra")]
    #[test_case(versioned::DataVersion::Fulu ; "fulu")]
    fn new_versioned_signed_proposal_from_blinded_proposal(version: versioned::DataVersion) {
        let proposal = sample_versioned_signed_blinded_proposal(version);
        let wrapped = VersionedSignedProposal::from_blinded_proposal(proposal).unwrap();
        assert!(matches!(
            (version, &wrapped.0.block),
            (
                versioned::DataVersion::Electra,
                versioned::SignedProposalBlock::ElectraBlinded(_)
            ) | (
                versioned::DataVersion::Fulu,
                versioned::SignedProposalBlock::FuluBlinded(_)
            )
        ));
    }

    #[test]
    fn versioned_signed_proposal_to_blinded() {
        let proposal = sample_versioned_signed_proposal(versioned::DataVersion::Electra, true);
        let expected = versioned::VersionedSignedBlindedProposal {
            version: proposal.version,
            block: proposal.block.clone().into_blinded().unwrap(),
        };

        let wrapped = VersionedSignedProposal::new(proposal).unwrap();
        assert_eq!(expected, wrapped.to_blinded().unwrap());
    }

    #[test]
    fn versioned_signed_proposal_to_blinded_requires_blinded_proposal() {
        let proposal = sample_versioned_signed_proposal(versioned::DataVersion::Bellatrix, false);
        let wrapped = VersionedSignedProposal::new(proposal).unwrap();

        assert!(matches!(
            wrapped.to_blinded(),
            Err(SignedDataError::ProposalNotBlinded)
        ));
    }

    #[test]
    fn versioned_signed_proposal_signature_unknown_version_error() {
        let proposal = VersionedSignedProposal(versioned::VersionedSignedProposal {
            version: versioned::DataVersion::Unknown,
            blinded: false,
            block: versioned::SignedProposalBlock::Phase0(sample_phase0_block(0x22)),
        });

        assert!(matches!(
            proposal.signature(),
            Err(SignedDataError::UnknownVersion)
        ));
    }

    #[test_case(versioned::DataVersion::Unknown ; "unknown")]
    #[test_case(versioned::DataVersion::Phase0 ; "phase0_missing")]
    #[test_case(versioned::DataVersion::Altair ; "altair_missing")]
    #[test_case(versioned::DataVersion::Bellatrix ; "bellatrix_missing")]
    #[test_case(versioned::DataVersion::Capella ; "capella_missing")]
    #[test_case(versioned::DataVersion::Deneb ; "deneb_missing")]
    #[test_case(versioned::DataVersion::Electra ; "electra_missing")]
    #[test_case(versioned::DataVersion::Fulu ; "fulu_missing")]
    fn test_new_versioned_attestation_errors(version: versioned::DataVersion) {
        let result = VersionedAttestation::new(versioned::VersionedAttestation {
            version,
            ..Default::default()
        });

        if version == versioned::DataVersion::Unknown {
            assert!(matches!(result, Err(SignedDataError::UnknownVersion)));
        } else {
            assert!(matches!(
                result,
                Err(SignedDataError::MissingAttestation(v)) if v == version
            ));
        }
    }

    #[test_case(versioned::DataVersion::Phase0 ; "phase0")]
    #[test_case(versioned::DataVersion::Altair ; "altair")]
    #[test_case(versioned::DataVersion::Bellatrix ; "bellatrix")]
    #[test_case(versioned::DataVersion::Capella ; "capella")]
    #[test_case(versioned::DataVersion::Deneb ; "deneb")]
    #[test_case(versioned::DataVersion::Electra ; "electra")]
    #[test_case(versioned::DataVersion::Fulu ; "fulu")]
    fn versioned_attestation_aggregation_bits(version: versioned::DataVersion) {
        let wrapped = VersionedAttestation::new(sample_versioned_attestation(version)).unwrap();
        let expected = sample_bitlist_one().into_bytes().to_vec();
        assert_eq!(expected, wrapped.aggregation_bits().unwrap());
    }

    #[test]
    fn versioned_attestation_aggregation_bits_unknown_version_error() {
        let wrapped = VersionedAttestation(versioned::VersionedAttestation {
            version: versioned::DataVersion::Unknown,
            ..Default::default()
        });

        assert!(matches!(
            wrapped.aggregation_bits(),
            Err(SignedDataError::UnknownVersion)
        ));
    }

    #[test_case(versioned::DataVersion::Phase0 ; "phase0")]
    #[test_case(versioned::DataVersion::Altair ; "altair")]
    #[test_case(versioned::DataVersion::Bellatrix ; "bellatrix")]
    #[test_case(versioned::DataVersion::Capella ; "capella")]
    #[test_case(versioned::DataVersion::Deneb ; "deneb")]
    #[test_case(versioned::DataVersion::Electra ; "electra")]
    #[test_case(versioned::DataVersion::Fulu ; "fulu")]
    fn versioned_attestation_aggregation_bits_missing_payload_error(
        version: versioned::DataVersion,
    ) {
        let wrapped = VersionedAttestation(versioned::VersionedAttestation {
            version,
            ..Default::default()
        });

        assert!(matches!(
            wrapped.aggregation_bits(),
            Err(SignedDataError::MissingAttestation(v)) if v == version
        ));
    }

    #[test_case(versioned::DataVersion::Phase0, false ; "phase0")]
    #[test_case(versioned::DataVersion::Altair, false ; "altair")]
    #[test_case(versioned::DataVersion::Bellatrix, false ; "bellatrix")]
    #[test_case(versioned::DataVersion::Bellatrix, true ; "bellatrix_blinded")]
    #[test_case(versioned::DataVersion::Capella, false ; "capella")]
    #[test_case(versioned::DataVersion::Capella, true ; "capella_blinded")]
    #[test_case(versioned::DataVersion::Deneb, false ; "deneb")]
    #[test_case(versioned::DataVersion::Electra, false ; "electra")]
    #[test_case(versioned::DataVersion::Electra, true ; "electra_blinded")]
    #[test_case(versioned::DataVersion::Fulu, true ; "fulu_blinded")]
    fn versioned_signed_proposal(version: versioned::DataVersion, blinded: bool) {
        let proposal = sample_versioned_signed_proposal(version, blinded);
        let wrapped = VersionedSignedProposal::new(proposal.clone()).unwrap();

        let msg_root = wrapped.message_root().unwrap();
        assert_ne!(msg_root, [0_u8; 32]);

        let signature = sample_signature(0x99);
        let updated = wrapped.set_signature(signature.clone()).unwrap();
        assert_eq!(signature, updated.signature().unwrap());

        let js = serde_json::to_vec(&wrapped).unwrap();
        let wrapped2: VersionedSignedProposal = serde_json::from_slice(&js).unwrap();
        assert_eq!(wrapped, wrapped2);
    }

    #[test]
    fn versioned_signed_aggregate_and_proof_util_functions() {
        let data = sample_attestation_data();
        let aggregation_bits = sample_bitlist_one().into_bytes().to_vec();

        for version in [
            versioned::DataVersion::Phase0,
            versioned::DataVersion::Altair,
            versioned::DataVersion::Bellatrix,
            versioned::DataVersion::Capella,
            versioned::DataVersion::Deneb,
            versioned::DataVersion::Electra,
            versioned::DataVersion::Fulu,
        ] {
            let wrapped = VersionedSignedAggregateAndProof::new(
                sample_versioned_signed_aggregate_and_proof(version),
            );
            assert_eq!(Some(&data), wrapped.data());
            assert_eq!(Some(aggregation_bits.clone()), wrapped.aggregation_bits());
        }
    }
}
