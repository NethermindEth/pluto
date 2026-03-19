//! Message and type conversion helpers for partial signature exchange.

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

use super::Error;

pub(crate) fn serialize_signed_data(data: &dyn SignedData) -> Result<Vec<u8>, Error> {
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

    Err(Error::UnsupportedDutyType)
}

pub(crate) fn deserialize_signed_data(
    duty_type: &DutyType,
    bytes: &[u8],
) -> Result<Box<dyn SignedData>, Error> {
    macro_rules! deserialize_json {
        ($ty:ty) => {
            serde_json::from_slice::<$ty>(bytes)
                .map(|value| Box::new(value) as Box<dyn SignedData>)
                .map_err(Error::from)
        };
    }

    match duty_type {
        DutyType::Attester => deserialize_json!(VersionedAttestation)
            .or_else(|_| deserialize_json!(Attestation))
            .map_err(|_| Error::UnsupportedDutyType),
        DutyType::Proposer => deserialize_json!(VersionedSignedProposal),
        DutyType::BuilderProposer => Err(Error::DeprecatedBuilderProposer),
        DutyType::BuilderRegistration => deserialize_json!(VersionedSignedValidatorRegistration),
        DutyType::Exit => deserialize_json!(SignedVoluntaryExit),
        DutyType::Randao => deserialize_json!(SignedRandao),
        DutyType::Signature => deserialize_json!(Signature),
        DutyType::PrepareAggregator => deserialize_json!(BeaconCommitteeSelection),
        DutyType::Aggregator => deserialize_json!(VersionedSignedAggregateAndProof)
            .or_else(|_| deserialize_json!(SignedAggregateAndProof))
            .map_err(|_| Error::UnsupportedDutyType),
        DutyType::SyncMessage => deserialize_json!(SignedSyncMessage),
        DutyType::PrepareSyncContribution => deserialize_json!(SyncCommitteeSelection),
        DutyType::SyncContribution => deserialize_json!(SignedSyncContributionAndProof),
        DutyType::Unknown | DutyType::InfoSync | DutyType::DutySentinel(_) => {
            Err(Error::UnsupportedDutyType)
        }
    }
}
