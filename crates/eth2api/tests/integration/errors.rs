//! Requests the node rejects, and payloads the client refuses to send.

use crate::{
    BLS_INFINITY, BeaconNodeContainer, GENESIS_BLOCK_ROOT, GENESIS_TIME, VALIDATOR_0_PUBKEY,
};
use alloy::primitives::U256;
use pluto_eth2api::{
    EthBeaconNodeApiClientError, HttpError, PayloadError, ProduceBlockOpts,
    spec::{
        BuilderVersion, DataVersion, altair, bellatrix, electra,
        phase0::{self, SszList},
    },
    v1,
    versioned::{
        AttestationPayload, SignedAggregateAndProofPayload, SignedBlindedProposalBlock,
        SignedProposalBlock, VersionedAttestation, VersionedSignedAggregateAndProof,
        VersionedSignedBlindedProposal, VersionedSignedProposal,
        VersionedSignedValidatorRegistration,
    },
};
use pluto_ssz::{BitList, BitVector};
use reqwest::{Method, StatusCode};
use std::fmt;

const UNKNOWN_ROOT: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

/// The [`HttpError`] of a request the node rejected.
fn http_error<T: fmt::Debug>(result: Result<T, EthBeaconNodeApiClientError>) -> HttpError {
    match result {
        Err(EthBeaconNodeApiClientError::Http(error)) => error,
        other => panic!("expected an HTTP error, got {other:?}"),
    }
}

/// The attestation data the node produces for slot 1, committee 0.
fn slot_one_attestation_data() -> phase0::AttestationData {
    phase0::AttestationData {
        slot: 1,
        index: 0,
        beacon_block_root: crate::hex_bytes(GENESIS_BLOCK_ROOT),
        source: phase0::Checkpoint {
            epoch: 0,
            root: [0; 32],
        },
        target: phase0::Checkpoint {
            epoch: 0,
            root: crate::hex_bytes(GENESIS_BLOCK_ROOT),
        },
    }
}

fn validator_zero_registration() -> v1::SignedValidatorRegistration {
    v1::SignedValidatorRegistration {
        message: v1::ValidatorRegistration {
            fee_recipient: [0; 20],
            gas_limit: 30000000,
            timestamp: GENESIS_TIME,
            pubkey: crate::hex_bytes(VALIDATOR_0_PUBKEY),
        },
        signature: BLS_INFINITY,
    }
}

#[tokio::test]
async fn get_block_v2_of_an_unknown_root_is_none() {
    let node = BeaconNodeContainer::shared().await;

    let response = node
        .client()
        .get_block_v2(UNKNOWN_ROOT)
        .await
        .expect("get unknown block");

    assert_eq!(response, None);
}

#[tokio::test]
async fn get_block_header_of_an_unknown_root_is_not_found() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(node.client().get_block_header(UNKNOWN_ROOT).await);

    assert_eq!(error.status, StatusCode::NOT_FOUND);
    assert_eq!(error.method, Method::GET);
    assert_eq!(
        error.endpoint,
        format!("/eth/v1/beacon/headers/{UNKNOWN_ROOT}")
    );
    assert_eq!(error.body.code, Some(404));
}

#[tokio::test]
async fn get_block_root_of_an_empty_slot_is_not_found() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(node.client().get_block_root("5").await);

    assert_eq!(error.status, StatusCode::NOT_FOUND);
    assert_eq!(error.method, Method::GET);
    assert_eq!(error.endpoint, "/eth/v1/beacon/blocks/5/root");
    assert_eq!(error.body.code, Some(404));
}

#[tokio::test]
async fn get_aggregated_attestation_v2_of_an_unknown_data_root_is_not_found() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(
        node.client()
            .get_aggregated_attestation_v2(1, 0, [0; 32])
            .await,
    );

    assert_eq!(error.status, StatusCode::NOT_FOUND);
    assert_eq!(error.method, Method::GET);
    assert_eq!(error.endpoint, "/eth/v2/validator/aggregate_attestation");
    assert_eq!(error.body.code, Some(404));
}

#[tokio::test]
async fn produce_sync_committee_contribution_at_slot_one_is_not_found() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(
        node.client()
            .produce_sync_committee_contribution(1, 0, crate::hex_bytes(GENESIS_BLOCK_ROOT))
            .await,
    );

    assert_eq!(error.status, StatusCode::NOT_FOUND);
    assert_eq!(error.method, Method::GET);
    assert_eq!(
        error.endpoint,
        "/eth/v1/validator/sync_committee_contribution"
    );
    assert_eq!(error.body.code, Some(404));
}

#[tokio::test]
async fn get_sync_committee_duties_beyond_the_horizon_is_a_bad_request() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(
        node.client()
            .get_sync_committee_duties(10_000_000, &[0])
            .await,
    );

    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.method, Method::POST);
    assert_eq!(error.endpoint, "/eth/v1/validator/duties/sync/10000000");
    assert_eq!(error.body.code, Some(400));
}

#[tokio::test]
async fn get_attester_duties_beyond_the_next_epoch_is_a_bad_request() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(node.client().get_attester_duties(10_000_000, &[0]).await);

    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.method, Method::POST);
    assert_eq!(error.endpoint, "/eth/v1/validator/duties/attester/10000000");
    assert_eq!(error.body.code, Some(400));
}

#[tokio::test]
async fn register_validator_without_a_builder_is_a_server_error() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(
        node.client()
            .register_validator(&[validator_zero_registration()])
            .await,
    );

    assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error.method, Method::POST);
    assert_eq!(error.endpoint, "/eth/v1/validator/register_validator");
    assert_eq!(error.body.code, Some(500));
}

#[tokio::test]
async fn submit_validator_registrations_without_a_builder_is_a_server_error() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(
        node.client()
            .submit_validator_registrations(vec![VersionedSignedValidatorRegistration {
                version: BuilderVersion::V1,
                v1: Some(validator_zero_registration()),
            }])
            .await,
    );

    assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error.method, Method::POST);
    assert_eq!(error.endpoint, "/eth/v1/validator/register_validator");
    assert_eq!(error.body.code, Some(500));
}

#[tokio::test]
async fn publish_blinded_block_v2_cannot_reconstruct_a_payload_with_a_zero_block_hash() {
    let node = BeaconNodeContainer::shared().await;
    let block = bellatrix::SignedBlindedBeaconBlock {
        message: bellatrix::BlindedBeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: crate::hex_bytes(GENESIS_BLOCK_ROOT),
            state_root: [0; 32],
            body: bellatrix::BlindedBeaconBlockBody {
                randao_reveal: BLS_INFINITY,
                eth1_data: phase0::ETH1Data {
                    deposit_root: [0; 32],
                    deposit_count: 0,
                    block_hash: [0; 32],
                },
                graffiti: [0; 32],
                proposer_slashings: SszList(Vec::new()),
                attester_slashings: SszList(Vec::new()),
                attestations: SszList(Vec::new()),
                deposits: SszList(Vec::new()),
                voluntary_exits: SszList(Vec::new()),
                sync_aggregate: altair::SyncAggregate {
                    sync_committee_bits: BitVector::new(),
                    sync_committee_signature: BLS_INFINITY,
                },
                execution_payload_header: bellatrix::ExecutionPayloadHeader {
                    parent_hash: [0; 32],
                    fee_recipient: [0; 20],
                    state_root: [0; 32],
                    receipts_root: [0; 32],
                    logs_bloom: [0; 256],
                    prev_randao: [0; 32],
                    block_number: 0,
                    gas_limit: 0,
                    gas_used: 0,
                    timestamp: 0,
                    extra_data: SszList(Vec::new()),
                    base_fee_per_gas: U256::ZERO,
                    block_hash: [0; 32],
                    transactions_root: [0; 32],
                },
            },
        },
        signature: BLS_INFINITY,
    };

    let error = http_error(
        node.client()
            .publish_blinded_block_v2(
                &VersionedSignedBlindedProposal {
                    version: DataVersion::Bellatrix,
                    block: SignedBlindedProposalBlock::Bellatrix(block),
                },
                None,
            )
            .await,
    );

    assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error.method, Method::POST);
    assert_eq!(error.endpoint, "/eth/v2/beacon/blinded_blocks");
    assert_eq!(error.body.code, Some(500));
}

#[tokio::test]
async fn publish_block_v2_rejects_a_block_signed_with_the_infinity_point() {
    let node = BeaconNodeContainer::shared().await;
    let block = phase0::SignedBeaconBlock {
        message: phase0::BeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: crate::hex_bytes(GENESIS_BLOCK_ROOT),
            state_root: [0; 32],
            body: phase0::BeaconBlockBody {
                randao_reveal: BLS_INFINITY,
                eth1_data: phase0::ETH1Data {
                    deposit_root: [0; 32],
                    deposit_count: 0,
                    block_hash: [0; 32],
                },
                graffiti: [0; 32],
                proposer_slashings: SszList(Vec::new()),
                attester_slashings: SszList(Vec::new()),
                attestations: SszList(Vec::new()),
                deposits: SszList(Vec::new()),
                voluntary_exits: SszList(Vec::new()),
            },
        },
        signature: BLS_INFINITY,
    };

    let error = http_error(
        node.client()
            .publish_block_v2(
                &VersionedSignedProposal {
                    version: DataVersion::Phase0,
                    blinded: false,
                    block: SignedProposalBlock::Phase0(block),
                },
                None,
            )
            .await,
    );

    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.method, Method::POST);
    assert_eq!(error.endpoint, "/eth/v2/beacon/blocks");
    assert_eq!(error.body.code, Some(400));
}

#[tokio::test]
async fn submit_pool_voluntary_exit_rejects_an_exit_signed_with_the_infinity_point() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(
        node.client()
            .submit_pool_voluntary_exit(&phase0::SignedVoluntaryExit {
                message: phase0::VoluntaryExit {
                    epoch: 0,
                    validator_index: 0,
                },
                signature: BLS_INFINITY,
            })
            .await,
    );

    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.method, Method::POST);
    assert_eq!(error.endpoint, "/eth/v1/beacon/pool/voluntary_exits");
    assert_eq!(error.body.code, Some(400));
}

#[tokio::test]
async fn submit_beacon_committee_selections_is_a_bad_request_on_lighthouse() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(
        node.client()
            .submit_beacon_committee_selections(&[v1::BeaconCommitteeSelection {
                slot: 1,
                validator_index: 0,
                selection_proof: BLS_INFINITY,
            }])
            .await,
    );

    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.method, Method::POST);
    assert_eq!(
        error.endpoint,
        "/eth/v1/validator/beacon_committee_selections"
    );
    assert_eq!(error.body.code, Some(400));
}

#[tokio::test]
async fn submit_sync_committee_selections_is_a_bad_request_on_lighthouse() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(
        node.client()
            .submit_sync_committee_selections(&[v1::SyncCommitteeSelection {
                slot: 1,
                validator_index: 0,
                subcommittee_index: 0,
                selection_proof: BLS_INFINITY,
            }])
            .await,
    );

    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.method, Method::POST);
    assert_eq!(
        error.endpoint,
        "/eth/v1/validator/sync_committee_selections"
    );
    assert_eq!(error.body.code, Some(400));
}

#[tokio::test]
async fn produce_block_v3_rejects_the_infinity_reveal_when_verifying_randao() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(
        node.client()
            .produce_block_v3(&ProduceBlockOpts {
                slot: 1,
                randao_reveal: BLS_INFINITY,
                graffiti: None,
                skip_randao_verification: false,
                builder_boost_factor: None,
            })
            .await,
    );

    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.method, Method::GET);
    assert_eq!(error.endpoint, "/eth/v3/validator/blocks/1");
    assert_eq!(error.body.code, Some(400));
}

#[tokio::test]
async fn submit_pool_attestations_v2_fails_a_single_attestation_by_index() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(
        node.client()
            .submit_pool_attestations_v2(&[VersionedAttestation {
                version: DataVersion::Electra,
                validator_index: Some(0),
                attestation: Some(AttestationPayload::Electra(electra::Attestation {
                    aggregation_bits: BitList::with_bits(8, &[0]),
                    data: slot_one_attestation_data(),
                    signature: BLS_INFINITY,
                    committee_bits: BitVector::with_bits(&[0]),
                })),
            }])
            .await,
    );

    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.method, Method::POST);
    assert_eq!(error.endpoint, "/eth/v2/beacon/pool/attestations");
    assert_eq!(error.body.code, Some(400));
    assert_eq!(error.body.failures.len(), 1);
    assert_eq!(error.body.failures[0].index, 0);
}

#[tokio::test]
async fn publish_contribution_and_proofs_fails_a_single_contribution_by_index() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(
        node.client()
            .publish_contribution_and_proofs(&[altair::SignedContributionAndProof {
                message: altair::ContributionAndProof {
                    aggregator_index: 0,
                    contribution: altair::SyncCommitteeContribution {
                        slot: 1,
                        beacon_block_root: crate::hex_bytes(GENESIS_BLOCK_ROOT),
                        subcommittee_index: 0,
                        aggregation_bits: BitVector::new(),
                        signature: BLS_INFINITY,
                    },
                    selection_proof: BLS_INFINITY,
                },
                signature: BLS_INFINITY,
            }])
            .await,
    );

    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.method, Method::POST);
    assert_eq!(error.endpoint, "/eth/v1/validator/contribution_and_proofs");
    assert_eq!(error.body.code, Some(400));
    assert_eq!(error.body.failures.len(), 1);
    assert_eq!(error.body.failures[0].index, 0);
}

#[tokio::test]
async fn publish_aggregate_and_proofs_v2_fails_a_single_aggregate_by_index() {
    let node = BeaconNodeContainer::shared().await;

    let error = http_error(
        node.client()
            .publish_aggregate_and_proofs_v2(&[VersionedSignedAggregateAndProof {
                version: DataVersion::Phase0,
                aggregate_and_proof: SignedAggregateAndProofPayload::Phase0(
                    phase0::SignedAggregateAndProof {
                        message: phase0::AggregateAndProof {
                            aggregator_index: 0,
                            aggregate: phase0::Attestation {
                                aggregation_bits: BitList::with_bits(8, &[0]),
                                data: slot_one_attestation_data(),
                                signature: BLS_INFINITY,
                            },
                            selection_proof: BLS_INFINITY,
                        },
                        signature: BLS_INFINITY,
                    },
                ),
            }])
            .await,
    );

    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.method, Method::POST);
    assert_eq!(error.endpoint, "/eth/v2/validator/aggregate_and_proofs");
    assert_eq!(error.body.code, Some(400));
    assert_eq!(error.body.failures.len(), 1);
    assert_eq!(error.body.failures[0].index, 0);
}

#[tokio::test]
async fn publish_aggregate_and_proofs_v2_refuses_an_empty_batch_before_sending() {
    let node = BeaconNodeContainer::shared().await;

    let result = node.client().publish_aggregate_and_proofs_v2(&[]).await;

    assert!(
        matches!(
            result,
            Err(EthBeaconNodeApiClientError::Payload(PayloadError::Empty))
        ),
        "unexpected result {result:?}"
    );
}
