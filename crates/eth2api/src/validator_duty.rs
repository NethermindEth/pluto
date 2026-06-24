//! Beacon API helpers used by validator duty flows.

use serde::Serialize;
use serde_json::Value;

use crate::{
    EthBeaconNodeApiClient,
    spec::{altair, phase0},
    versioned,
};

type Result<T> = std::result::Result<T, ValidatorDutyError>;

/// Error returned by validator duty beacon API helpers.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ValidatorDutyError(String);

/// Attester duty data needed by validator duty flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttesterDuty {
    /// Duty slot.
    pub slot: phase0::Slot,
    /// Validator index.
    pub validator_index: phase0::ValidatorIndex,
    /// Validator public key.
    pub pubkey: phase0::BLSPubKey,
}

impl EthBeaconNodeApiClient {
    /// Fetches attester duties for the provided validator indices.
    pub async fn fetch_attester_duties_for_indices(
        &self,
        epoch: phase0::Epoch,
        indices: Vec<phase0::ValidatorIndex>,
    ) -> Result<Vec<AttesterDuty>> {
        let request = crate::GetAttesterDutiesRequest {
            path: crate::GetAttesterDutiesRequestPath {
                epoch: epoch.to_string(),
            },
            body: indices.into_iter().map(|index| index.to_string()).collect(),
        };

        match self
            .get_attester_duties(request)
            .await
            .map_err(error_message)?
        {
            crate::GetAttesterDutiesResponse::Ok(response) => response
                .data
                .into_iter()
                .map(|duty| {
                    Ok(AttesterDuty {
                        slot: parse_u64(&duty.slot, "attester duty slot")?,
                        validator_index: parse_u64(
                            &duty.validator_index,
                            "attester duty validator_index",
                        )?,
                        pubkey: crate::extensions::decode_fixed_hex(&duty.pubkey, || {
                            "decode attester duty pubkey".to_string()
                        })
                        .map_err(error_message)?,
                    })
                })
                .collect(),
            other => Err(unexpected_response(
                "get attester duties",
                format!("{other:?}"),
            )),
        }
    }

    /// Fetches the beacon attester signing domain.
    pub async fn fetch_beacon_attester_domain(
        &self,
        epoch: phase0::Epoch,
    ) -> Result<phase0::Domain> {
        let domain_type = self
            .fetch_domain_type("DOMAIN_BEACON_ATTESTER")
            .await
            .map_err(error_message)?;

        self.fetch_domain(domain_type, epoch)
            .await
            .map_err(error_message)
    }

    /// Submits signed attestations to the beacon node.
    pub async fn submit_attestations(
        &self,
        attestations: Vec<versioned::VersionedAttestation>,
    ) -> Result<()> {
        let data_version = attestations
            .first()
            .map(|attestation| attestation.version)
            .unwrap_or(versioned::DataVersion::Phase0);
        let version: crate::ConsensusVersion =
            crate::ConsensusVersion::try_from(&data_version).map_err(error_message)?;
        let body = attestations_request_body(attestations)?;
        let request = crate::SubmitPoolAttestationsV2Request {
            header: crate::SubmitPoolAttestationsV2RequestHeader {
                eth_consensus_version: version,
            },
            body,
        };

        match self
            .submit_pool_attestations_v2(request)
            .await
            .map_err(error_message)?
        {
            crate::SubmitPoolAttestationsV2Response::Ok => Ok(()),
            crate::SubmitPoolAttestationsV2Response::BadRequest(response) => Err(failure_response(
                "submit attestations",
                response.message,
                response.failures,
            )),
            other => Err(unexpected_response(
                "submit attestations",
                format!("{other:?}"),
            )),
        }
    }

    /// Submits a signed block proposal to the beacon node.
    pub async fn submit_signed_proposal(
        &self,
        proposal: versioned::VersionedSignedProposal,
    ) -> Result<()> {
        let version =
            crate::ConsensusVersion::try_from(&proposal.version).map_err(error_message)?;
        let body = proposal_request_body(proposal)?;
        let request = crate::PublishBlockV2Request {
            query: crate::PublishBlockV2RequestQuery {
                broadcast_validation: None,
            },
            header: crate::PublishBlockV2RequestHeader {
                eth_consensus_version: version,
            },
            body,
        };

        match self
            .publish_block_v2(request)
            .await
            .map_err(error_message)?
        {
            crate::PublishBlockV2Response::Ok | crate::PublishBlockV2Response::Accepted => Ok(()),
            other => Err(unexpected_response("submit proposal", format!("{other:?}"))),
        }
    }

    /// Submits a signed blinded block proposal to the beacon node.
    pub async fn submit_signed_blinded_proposal(
        &self,
        proposal: versioned::VersionedSignedBlindedProposal,
    ) -> Result<()> {
        let version =
            crate::ConsensusVersion::try_from(&proposal.version).map_err(error_message)?;
        let body = blinded_proposal_request_body(proposal)?;
        let request = crate::PublishBlindedBlockV2Request {
            query: crate::PublishBlindedBlockV2RequestQuery {
                broadcast_validation: None,
            },
            header: crate::PublishBlindedBlockV2RequestHeader {
                eth_consensus_version: version,
            },
            body,
        };

        match self
            .publish_blinded_block_v2(request)
            .await
            .map_err(error_message)?
        {
            crate::PublishBlockV2Response::Ok | crate::PublishBlockV2Response::Accepted => Ok(()),
            other => Err(unexpected_response(
                "submit blinded proposal",
                format!("{other:?}"),
            )),
        }
    }

    /// Submits signed validator registrations to the beacon node.
    pub async fn submit_validator_registrations(
        &self,
        registrations: Vec<versioned::VersionedSignedValidatorRegistration>,
    ) -> Result<()> {
        let body = registrations
            .into_iter()
            .map(registration_request_item)
            .collect::<Result<Vec<_>>>()?;
        let request = crate::RegisterValidatorRequest { body };

        match self
            .register_validator(request)
            .await
            .map_err(error_message)?
        {
            crate::RegisterValidatorResponse::Ok => Ok(()),
            other => Err(unexpected_response(
                "submit validator registrations",
                format!("{other:?}"),
            )),
        }
    }

    /// Submits a signed voluntary exit to the beacon node.
    pub async fn submit_voluntary_exit(&self, exit: phase0::SignedVoluntaryExit) -> Result<()> {
        let request = crate::SubmitPoolVoluntaryExitRequest {
            body: voluntary_exit_request_body(exit),
        };

        match self
            .submit_pool_voluntary_exit(request)
            .await
            .map_err(error_message)?
        {
            crate::SubmitPoolVoluntaryExitResponse::Ok => Ok(()),
            other => Err(unexpected_response(
                "submit voluntary exit",
                format!("{other:?}"),
            )),
        }
    }

    /// Submits signed aggregate-and-proof messages to the beacon node.
    pub async fn submit_aggregate_attestations(
        &self,
        aggregate_and_proofs: Vec<versioned::VersionedSignedAggregateAndProof>,
    ) -> Result<()> {
        let data_version = aggregate_and_proofs
            .first()
            .map(|aggregate| aggregate.version)
            .unwrap_or(versioned::DataVersion::Phase0);
        let version = crate::ConsensusVersion::try_from(&data_version).map_err(error_message)?;
        let body = aggregate_and_proofs_request_body(aggregate_and_proofs)?;
        let request = crate::PublishAggregateAndProofsV2Request {
            header: crate::PublishAggregateAndProofsV2RequestHeader {
                eth_consensus_version: version,
            },
            body,
        };

        match self
            .publish_aggregate_and_proofs_v2(request)
            .await
            .map_err(error_message)?
        {
            crate::SubmitPoolAttestationsV2Response::Ok => Ok(()),
            crate::SubmitPoolAttestationsV2Response::BadRequest(response) => Err(failure_response(
                "submit aggregate attestations",
                response.message,
                response.failures,
            )),
            other => Err(unexpected_response(
                "submit aggregate attestations",
                format!("{other:?}"),
            )),
        }
    }

    /// Submits sync committee messages to the beacon node.
    pub async fn submit_sync_committee_messages(
        &self,
        messages: Vec<altair::SyncCommitteeMessage>,
    ) -> Result<()> {
        let body = messages
            .into_iter()
            .map(sync_committee_message_request_item)
            .collect();
        let request = crate::SubmitPoolSyncCommitteeSignaturesRequest { body };

        match self
            .submit_pool_sync_committee_signatures(request)
            .await
            .map_err(error_message)?
        {
            crate::PublishContributionAndProofsResponse::Ok => Ok(()),
            other => Err(unexpected_response(
                "submit sync committee messages",
                format!("{other:?}"),
            )),
        }
    }

    /// Submits sync committee contributions to the beacon node.
    pub async fn submit_sync_committee_contributions(
        &self,
        contributions: Vec<altair::SignedContributionAndProof>,
    ) -> Result<()> {
        let body = contributions
            .into_iter()
            .map(sync_contribution_request_item)
            .collect();
        let request = crate::PublishContributionAndProofsRequest { body };

        match self
            .publish_contribution_and_proofs(request)
            .await
            .map_err(error_message)?
        {
            crate::PublishContributionAndProofsResponse::Ok => Ok(()),
            other => Err(unexpected_response(
                "submit sync committee contributions",
                format!("{other:?}"),
            )),
        }
    }
}

/// Returns true for data versions that use pre-Electra attestation wire shape.
pub fn data_version_is_before_electra(version: versioned::DataVersion) -> bool {
    matches!(
        version,
        versioned::DataVersion::Unknown
            | versioned::DataVersion::Phase0
            | versioned::DataVersion::Altair
            | versioned::DataVersion::Bellatrix
            | versioned::DataVersion::Capella
            | versioned::DataVersion::Deneb
    )
}

fn attestations_request_body(
    attestations: Vec<versioned::VersionedAttestation>,
) -> Result<crate::AttestationRequestBody2> {
    if attestations
        .first()
        .is_some_and(|attestation| !data_version_is_before_electra(attestation.version))
    {
        let mut items = Vec::with_capacity(attestations.len());
        for attestation in attestations {
            let Some(payload) = attestation.attestation else {
                return Err(unexpected_response(
                    "attestation request body",
                    "missing payload",
                ));
            };
            let validator_index = attestation.validator_index.ok_or_else(|| {
                unexpected_response("attestation request body", "missing validator index")
            })?;

            match payload {
                versioned::AttestationPayload::Electra(attestation)
                | versioned::AttestationPayload::Fulu(attestation) => {
                    items.push(crate::AttestationRequestBody2Array {
                        attester_index: validator_index.to_string(),
                        committee_index: first_set_bit(&attestation.committee_bits.bytes)
                            .ok_or_else(|| {
                                unexpected_response(
                                    "attestation request body",
                                    "missing committee index",
                                )
                            })?
                            .to_string(),
                        data: data_request_body(&attestation.data)?,
                        signature: hex0x(attestation.signature),
                    });
                }
                _ => {
                    return Err(unexpected_response(
                        "attestation request body",
                        "pre-electra payload in electra request",
                    ));
                }
            }
        }

        return Ok(crate::AttestationRequestBody2::Array(items));
    }

    let mut items = Vec::with_capacity(attestations.len());
    for attestation in attestations {
        let Some(payload) = attestation.attestation else {
            return Err(unexpected_response(
                "attestation request body",
                "missing payload",
            ));
        };
        let attestation = match payload {
            versioned::AttestationPayload::Phase0(attestation)
            | versioned::AttestationPayload::Altair(attestation)
            | versioned::AttestationPayload::Bellatrix(attestation)
            | versioned::AttestationPayload::Capella(attestation)
            | versioned::AttestationPayload::Deneb(attestation) => attestation,
            versioned::AttestationPayload::Electra(_) | versioned::AttestationPayload::Fulu(_) => {
                return Err(unexpected_response(
                    "attestation request body",
                    "electra payload in pre-electra request",
                ));
            }
        };
        items.push(crate::GetBlockAttestationsV2ResponseResponseDataArray2 {
            aggregation_bits: hex0x(attestation.aggregation_bits.to_ssz_bytes()),
            data: data_request_body(&attestation.data)?,
            signature: hex0x(attestation.signature),
        });
    }

    Ok(crate::AttestationRequestBody2::Array2(items))
}

fn proposal_request_body(
    proposal: versioned::VersionedSignedProposal,
) -> Result<crate::BlockRequestBody> {
    match proposal.block {
        versioned::SignedProposalBlock::Phase0(block) => {
            let (message, signature) = signed_envelope(block)?;
            Ok(crate::BlockRequestBody::Object7(
                crate::GetBlindedBlockResponseResponseDataObject6 { message, signature },
            ))
        }
        versioned::SignedProposalBlock::Altair(block) => {
            let (message, signature) = signed_envelope(block)?;
            Ok(crate::BlockRequestBody::Object6(
                crate::GetBlindedBlockResponseResponseDataObject5 { message, signature },
            ))
        }
        versioned::SignedProposalBlock::Bellatrix(block) => {
            let (message, signature) = signed_envelope(block)?;
            Ok(crate::BlockRequestBody::Object5(
                crate::BlockRequestBodyObject5 { message, signature },
            ))
        }
        versioned::SignedProposalBlock::Capella(block) => {
            let (message, signature) = signed_envelope(block)?;
            Ok(crate::BlockRequestBody::Object4(
                crate::BlockRequestBodyObject4 { message, signature },
            ))
        }
        versioned::SignedProposalBlock::Deneb(contents) => {
            let (message, signature) = signed_envelope(contents.signed_block)?;
            Ok(crate::BlockRequestBody::Object3(
                crate::BlockRequestBodyObject3 {
                    blobs: hex_values(contents.blobs)?,
                    kzg_proofs: hex_values(contents.kzg_proofs)?,
                    signed_block: crate::DenebSignedBlockContentsSignedBlock { message, signature },
                },
            ))
        }
        versioned::SignedProposalBlock::Electra(contents) => {
            let (message, signature) = signed_envelope(contents.signed_block)?;
            Ok(crate::BlockRequestBody::Object2(
                crate::BlockRequestBodyObject2 {
                    blobs: hex_values(contents.blobs)?,
                    kzg_proofs: hex_values(contents.kzg_proofs)?,
                    signed_block: crate::SignedBlockContentsSignedBlock { message, signature },
                },
            ))
        }
        versioned::SignedProposalBlock::Fulu(contents) => {
            let (message, signature) = signed_envelope(contents.signed_block)?;
            Ok(crate::BlockRequestBody::Object(
                crate::BlockRequestBodyObject {
                    blobs: hex_values(contents.blobs)?,
                    kzg_proofs: hex_values(contents.kzg_proofs)?,
                    signed_block: crate::SignedBlockContentsSignedBlock { message, signature },
                },
            ))
        }
        versioned::SignedProposalBlock::BellatrixBlinded(_)
        | versioned::SignedProposalBlock::CapellaBlinded(_)
        | versioned::SignedProposalBlock::DenebBlinded(_)
        | versioned::SignedProposalBlock::ElectraBlinded(_)
        | versioned::SignedProposalBlock::FuluBlinded(_) => Err(unexpected_response(
            "proposal request body",
            "blinded proposal on unblinded endpoint",
        )),
    }
}

fn blinded_proposal_request_body(
    proposal: versioned::VersionedSignedBlindedProposal,
) -> Result<crate::GetBlindedBlockResponseResponseData> {
    match proposal.block {
        versioned::SignedBlindedProposalBlock::Bellatrix(block) => {
            let (message, signature) = signed_envelope(block)?;
            Ok(crate::GetBlindedBlockResponseResponseData::Object4(
                crate::GetBlindedBlockResponseResponseDataObject4 { message, signature },
            ))
        }
        versioned::SignedBlindedProposalBlock::Capella(block) => {
            let (message, signature) = signed_envelope(block)?;
            Ok(crate::GetBlindedBlockResponseResponseData::Object3(
                crate::GetBlindedBlockResponseResponseDataObject3 { message, signature },
            ))
        }
        versioned::SignedBlindedProposalBlock::Deneb(block) => {
            let (message, signature) = signed_envelope(block)?;
            Ok(crate::GetBlindedBlockResponseResponseData::Object2(
                crate::GetBlindedBlockResponseResponseDataObject2 { message, signature },
            ))
        }
        versioned::SignedBlindedProposalBlock::Electra(block)
        | versioned::SignedBlindedProposalBlock::Fulu(block) => {
            let (message, signature) = signed_envelope(block)?;
            Ok(crate::GetBlindedBlockResponseResponseData::Object(
                crate::GetBlindedBlockResponseResponseDataObject { message, signature },
            ))
        }
    }
}

fn registration_request_item(
    registration: versioned::VersionedSignedValidatorRegistration,
) -> Result<crate::RegisterValidatorRequestBodyItem> {
    match (registration.version, registration.v1) {
        (versioned::BuilderVersion::V1, Some(registration)) => {
            Ok(crate::RegisterValidatorRequestBodyItem {
                message: crate::SignedValidatorRegistrationMessage {
                    fee_recipient: hex0x(registration.message.fee_recipient),
                    gas_limit: registration.message.gas_limit.to_string(),
                    pubkey: hex0x(registration.message.pubkey),
                    timestamp: registration.message.timestamp.to_string(),
                },
                signature: hex0x(registration.signature),
            })
        }
        _ => Err(unexpected_response(
            "validator registration request body",
            "unsupported builder registration version",
        )),
    }
}

fn voluntary_exit_request_body(
    exit: phase0::SignedVoluntaryExit,
) -> crate::GetPoolVoluntaryExitsResponseResponseDatum {
    crate::GetPoolVoluntaryExitsResponseResponseDatum {
        message: crate::Phase0SignedVoluntaryExitMessage {
            epoch: exit.message.epoch.to_string(),
            validator_index: exit.message.validator_index.to_string(),
        },
        signature: hex0x(exit.signature),
    }
}

fn aggregate_and_proofs_request_body(
    aggregate_and_proofs: Vec<versioned::VersionedSignedAggregateAndProof>,
) -> Result<crate::AggregateAndProofRequestBody> {
    let is_electra = aggregate_and_proofs
        .first()
        .is_some_and(|aggregate| !data_version_is_before_electra(aggregate.version));

    let envelopes = aggregate_and_proofs
        .into_iter()
        .map(signed_aggregate_envelope)
        .collect::<Result<Vec<_>>>()?;

    Ok(if is_electra {
        crate::AggregateAndProofRequestBody::Array(
            envelopes
                .into_iter()
                .map(
                    |(message, signature)| crate::AggregateAndProofRequestBodyArray {
                        message,
                        signature,
                    },
                )
                .collect(),
        )
    } else {
        crate::AggregateAndProofRequestBody::Array2(
            envelopes
                .into_iter()
                .map(
                    |(message, signature)| crate::AggregateAndProofRequestBodyArray2 {
                        message,
                        signature,
                    },
                )
                .collect(),
        )
    })
}

fn signed_aggregate_envelope(
    aggregate: versioned::VersionedSignedAggregateAndProof,
) -> Result<(Value, String)> {
    match aggregate.aggregate_and_proof {
        versioned::SignedAggregateAndProofPayload::Phase0(payload)
        | versioned::SignedAggregateAndProofPayload::Altair(payload)
        | versioned::SignedAggregateAndProofPayload::Bellatrix(payload)
        | versioned::SignedAggregateAndProofPayload::Capella(payload)
        | versioned::SignedAggregateAndProofPayload::Deneb(payload) => signed_envelope(payload),
        versioned::SignedAggregateAndProofPayload::Electra(payload)
        | versioned::SignedAggregateAndProofPayload::Fulu(payload) => signed_envelope(payload),
    }
}

fn sync_committee_message_request_item(
    message: altair::SyncCommitteeMessage,
) -> crate::SyncCommitteeRequestBodyItem {
    crate::SyncCommitteeRequestBodyItem {
        beacon_block_root: hex0x(message.beacon_block_root),
        signature: hex0x(message.signature),
        slot: message.slot.to_string(),
        validator_index: message.validator_index.to_string(),
    }
}

fn sync_contribution_request_item(
    contribution: altair::SignedContributionAndProof,
) -> crate::ContributionAndProofRequestBodyItem {
    let message = contribution.message;
    let contribution_data = message.contribution;

    crate::ContributionAndProofRequestBodyItem {
        message: crate::AltairSignedContributionAndProofMessage {
            aggregator_index: message.aggregator_index.to_string(),
            contribution: crate::Contribution {
                aggregation_bits: hex0x(contribution_data.aggregation_bits.bytes),
                beacon_block_root: hex0x(contribution_data.beacon_block_root),
                signature: hex0x(contribution_data.signature),
                slot: contribution_data.slot.to_string(),
                subcommittee_index: contribution_data.subcommittee_index.to_string(),
            },
            selection_proof: hex0x(message.selection_proof),
        },
        signature: hex0x(contribution.signature),
    }
}

fn data_request_body(data: &phase0::AttestationData) -> Result<crate::Data> {
    serde_json::from_value(serde_json::to_value(data).map_err(error_message)?)
        .map_err(error_message)
}

fn signed_envelope<T: Serialize>(value: T) -> Result<(Value, String)> {
    let mut value = serde_json::to_value(value).map_err(error_message)?;
    let object = value.as_object_mut().ok_or_else(|| {
        unexpected_response("signed envelope", "serialized signed data is not an object")
    })?;
    let message = object
        .remove("message")
        .ok_or_else(|| unexpected_response("signed envelope", "missing message"))?;
    let signature = object
        .remove("signature")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| unexpected_response("signed envelope", "missing signature"))?;

    Ok((message, signature))
}

fn hex_values<T: Serialize>(values: Vec<T>) -> Result<Vec<String>> {
    values
        .into_iter()
        .map(|value| {
            serde_json::to_value(value)
                .map_err(error_message)?
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| unexpected_response("hex value", "serialized value is not hex"))
        })
        .collect()
}

fn first_set_bit(bytes: &[u8]) -> Option<usize> {
    bytes.iter().enumerate().find_map(|(byte_index, byte)| {
        if *byte == 0 {
            None
        } else {
            byte_index.checked_mul(8).and_then(|offset| {
                usize::try_from(byte.trailing_zeros())
                    .ok()
                    .and_then(|bit| offset.checked_add(bit))
            })
        }
    })
}

fn parse_u64(value: &str, field: &'static str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| unexpected_response(field, format!("invalid u64 {value}")))
}

fn hex0x(bytes: impl AsRef<[u8]>) -> String {
    pluto_ssz::to_0x_hex(bytes.as_ref())
}

fn error_message(source: impl ToString) -> ValidatorDutyError {
    ValidatorDutyError(source.to_string())
}

fn unexpected_response(context: &'static str, response: impl Into<String>) -> ValidatorDutyError {
    ValidatorDutyError(format!("{context}: {}", response.into()))
}

fn failure_response(
    context: &'static str,
    message: String,
    failures: Vec<crate::BlsToExecutionChange400ResponseFailure>,
) -> ValidatorDutyError {
    let details = failures
        .into_iter()
        .map(|failure| failure.message)
        .collect::<Vec<_>>()
        .join("; ");
    if details.is_empty() {
        unexpected_response(context, message)
    } else {
        unexpected_response(context, format!("{message}: {details}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{electra, phase0};

    fn attestation_data(slot: u64, epoch: u64) -> phase0::AttestationData {
        phase0::AttestationData {
            slot,
            index: 3,
            beacon_block_root: [1; 32],
            source: phase0::Checkpoint {
                epoch: epoch.saturating_sub(1),
                root: [2; 32],
            },
            target: phase0::Checkpoint {
                epoch,
                root: [3; 32],
            },
        }
    }

    #[test]
    fn electra_attestation_request_body_requires_validator_and_committee_index() {
        let body = attestations_request_body(vec![versioned::VersionedAttestation {
            version: versioned::DataVersion::Electra,
            validator_index: Some(99),
            attestation: Some(versioned::AttestationPayload::Electra(
                electra::Attestation {
                    aggregation_bits: phase0::BitList::with_bits(8, &[0]),
                    data: attestation_data(12, 3),
                    signature: [4; 96],
                    committee_bits: pluto_ssz::BitVector::with_bits(&[3]),
                },
            )),
        }])
        .expect("body");
        let value = serde_json::to_value(body).expect("json body");

        assert_eq!(value[0]["attester_index"], "99");
        assert_eq!(value[0]["committee_index"], "3");
    }
}
