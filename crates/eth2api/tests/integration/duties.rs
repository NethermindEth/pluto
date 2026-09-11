//! Attester and proposer duties of the first two epochs.

use crate::{BeaconNodeContainer, GENESIS_BLOCK_ROOT, VALIDATOR_0_PUBKEY, VALIDATOR_1_PUBKEY};
use pluto_eth2api::{AttesterDutiesResponse, v1};
use std::collections::HashSet;

#[tokio::test]
async fn get_attester_duties_at_epoch_zero_depend_on_the_genesis_root() {
    let node = BeaconNodeContainer::shared().await;

    let response = node
        .client()
        .get_attester_duties(0, &[0, 1])
        .await
        .expect("get attester duties");

    assert_eq!(
        response,
        AttesterDutiesResponse {
            dependent_root: crate::hex_bytes(GENESIS_BLOCK_ROOT),
            execution_optimistic: false,
            data: vec![
                v1::AttesterDuty {
                    pubkey: crate::hex_bytes(VALIDATOR_0_PUBKEY),
                    validator_index: 0,
                    committee_index: 4,
                    committee_length: 132,
                    committees_at_slot: 5,
                    validator_committee_index: 79,
                    slot: 15,
                },
                v1::AttesterDuty {
                    pubkey: crate::hex_bytes(VALIDATOR_1_PUBKEY),
                    validator_index: 1,
                    committee_index: 1,
                    committee_length: 132,
                    committees_at_slot: 5,
                    validator_committee_index: 7,
                    slot: 19,
                },
            ],
        }
    );
}

#[tokio::test]
async fn fetch_attester_duties_for_indices_at_epoch_one_returns_the_requested_validator() {
    let node = BeaconNodeContainer::shared().await;

    let duties = node
        .client()
        .fetch_attester_duties_for_indices(1, vec![0])
        .await
        .expect("fetch attester duties");

    assert_eq!(
        duties,
        vec![v1::AttesterDuty {
            pubkey: crate::hex_bytes(VALIDATOR_0_PUBKEY),
            validator_index: 0,
            committee_index: 3,
            committee_length: 131,
            committees_at_slot: 5,
            validator_committee_index: 29,
            slot: 52,
        }]
    );
}

#[tokio::test]
async fn get_proposer_duties_at_epoch_zero_cover_every_slot() {
    let node = BeaconNodeContainer::shared().await;

    let response = node
        .client()
        .get_proposer_duties(0)
        .await
        .expect("get proposer duties");

    assert_eq!(
        response.dependent_root,
        crate::hex_bytes::<32>(GENESIS_BLOCK_ROOT)
    );
    assert!(!response.execution_optimistic);
    let slots: Vec<_> = response.data.iter().map(|duty| duty.slot).collect();
    assert_eq!(slots, (0..32).collect::<Vec<_>>());
    assert_eq!(
        response.data[0],
        v1::ProposerDuty {
            pubkey: crate::hex_bytes(
                "0x884926cbd1ed5cbc0f76f314fbf09fcede01463aa4b93715fb430b8d1e48099c1b272b8ee094acb01701549274a50f9a"
            ),
            validator_index: 10453,
            slot: 0,
        }
    );
    assert_eq!(response.data[1].validator_index, 19026);
    assert_eq!(response.data[2].validator_index, 11516);
}

#[tokio::test]
async fn fetch_proposer_duties_keeps_only_the_requested_validators() {
    let node = BeaconNodeContainer::shared().await;

    let duties = node
        .client()
        .fetch_proposer_duties(0, 32, &HashSet::from([19026]))
        .await
        .expect("fetch proposer duties");

    assert_eq!(
        duties,
        vec![v1::ProposerDuty {
            pubkey: crate::hex_bytes(
                "0xa7cea918946b15a8b02f8af93992cfc012d8f88677b6c2785aeac1d7b2f13366e47a8aab2a8850be0375d7851742a1ab"
            ),
            validator_index: 19026,
            slot: 1,
        }]
    );
}

#[tokio::test]
async fn get_proposer_duties_at_epoch_one_start_at_slot_thirty_two() {
    let node = BeaconNodeContainer::shared().await;

    let response = node
        .client()
        .get_proposer_duties(1)
        .await
        .expect("get proposer duties");

    let slots: Vec<_> = response.data.iter().map(|duty| duty.slot).collect();
    assert_eq!(slots, (32..64).collect::<Vec<_>>());
    assert_eq!(response.data[0].validator_index, 17407);
}
