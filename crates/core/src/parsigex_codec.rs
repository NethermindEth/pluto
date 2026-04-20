//! Partial signature exchange codec helpers used by core types.

use std::any::Any;

use crate::{
    signeddata::{
        Attestation, BeaconCommitteeSelection, SignedAggregateAndProof, SignedRandao,
        SignedSyncContributionAndProof, SignedSyncMessage, SignedVoluntaryExit,
        SyncCommitteeSelection, VersionedAttestation, VersionedSignedAggregateAndProof,
        VersionedSignedProposal, VersionedSignedValidatorRegistration,
    },
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

    /// Serialization failed.
    #[error("marshal signed data: {0}")]
    Serialize(#[from] serde_json::Error),
}

pub(crate) fn serialize_signed_data(data: &dyn SignedData) -> Result<Vec<u8>, ParSigExCodecError> {
    let any = data as &dyn Any;

    macro_rules! serialize_as {
        ($ty:ty) => {
            if let Some(value) = any.downcast_ref::<$ty>() {
                return Ok(serde_json::to_vec(value)?);
            }
        };
    }

    serialize_as!(Attestation);
    serialize_as!(VersionedAttestation);
    serialize_as!(VersionedSignedProposal);
    serialize_as!(VersionedSignedValidatorRegistration);
    serialize_as!(SignedVoluntaryExit);
    serialize_as!(SignedRandao);
    serialize_as!(Signature);
    serialize_as!(BeaconCommitteeSelection);
    serialize_as!(SignedAggregateAndProof);
    serialize_as!(VersionedSignedAggregateAndProof);
    serialize_as!(SignedSyncMessage);
    serialize_as!(SyncCommitteeSelection);
    serialize_as!(SignedSyncContributionAndProof);

    Err(ParSigExCodecError::UnsupportedDutyType)
}

pub(crate) fn deserialize_signed_data(
    duty_type: &DutyType,
    bytes: &[u8],
) -> Result<Box<dyn SignedData>, ParSigExCodecError> {
    macro_rules! deserialize_json {
        ($ty:ty) => {
            serde_json::from_slice::<$ty>(bytes)
                .map(|value| Box::new(value) as Box<dyn SignedData>)
                .map_err(ParSigExCodecError::from)
        };
    }

    match duty_type {
        // Match Go order: old Attestation format first, then VersionedAttestation.
        DutyType::Attester => deserialize_json!(Attestation)
            .or_else(|_| deserialize_json!(VersionedAttestation))
            .map_err(|_| ParSigExCodecError::UnsupportedDutyType),
        DutyType::Proposer => deserialize_json!(VersionedSignedProposal),
        DutyType::BuilderProposer => Err(ParSigExCodecError::DeprecatedBuilderProposer),
        DutyType::BuilderRegistration => deserialize_json!(VersionedSignedValidatorRegistration),
        DutyType::Exit => deserialize_json!(SignedVoluntaryExit),
        DutyType::Randao => deserialize_json!(SignedRandao),
        DutyType::Signature => deserialize_json!(Signature),
        DutyType::PrepareAggregator => deserialize_json!(BeaconCommitteeSelection),
        // Match Go order: old SignedAggregateAndProof format first, then versioned.
        DutyType::Aggregator => deserialize_json!(SignedAggregateAndProof)
            .or_else(|_| deserialize_json!(VersionedSignedAggregateAndProof))
            .map_err(|_| ParSigExCodecError::UnsupportedDutyType),
        DutyType::SyncMessage => deserialize_json!(SignedSyncMessage),
        DutyType::PrepareSyncContribution => deserialize_json!(SyncCommitteeSelection),
        DutyType::SyncContribution => deserialize_json!(SignedSyncContributionAndProof),
        // InfoSync is not used in parsigex in Go (handled via a separate channel);
        // Unknown and DutySentinel are sentinel/invalid values that are never transmitted.
        DutyType::Unknown | DutyType::DutySentinel(_) | DutyType::InfoSync => {
            Err(ParSigExCodecError::UnsupportedDutyType)
        }
    }
}
