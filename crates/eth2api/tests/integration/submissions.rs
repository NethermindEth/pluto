//! Submissions the node accepts on a head fixed at genesis.

use crate::BeaconNodeContainer;
use pluto_eth2api::v1;

#[tokio::test]
async fn prepare_beacon_proposer_accepts_a_zero_fee_recipient() {
    let node = BeaconNodeContainer::shared().await;

    node.client()
        .prepare_beacon_proposer(&[v1::ProposalPreparation {
            validator_index: 0,
            fee_recipient: [0; 20],
        }])
        .await
        .expect("prepare beacon proposer");
}

#[tokio::test]
async fn prepare_sync_committee_subnets_accepts_a_subscription_for_validator_zero() {
    let node = BeaconNodeContainer::shared().await;

    node.client()
        .prepare_sync_committee_subnets(&[v1::SyncCommitteeSubscription {
            validator_index: 0,
            sync_committee_indices: vec![0],
            until_epoch: 1,
        }])
        .await
        .expect("prepare sync committee subnets");
}

#[tokio::test]
async fn submit_pool_attestations_v2_accepts_an_empty_batch() {
    let node = BeaconNodeContainer::shared().await;

    node.client()
        .submit_pool_attestations_v2(&[])
        .await
        .expect("submit no attestations");
}

#[tokio::test]
async fn submit_pool_sync_committee_signatures_accepts_an_empty_batch() {
    let node = BeaconNodeContainer::shared().await;

    node.client()
        .submit_pool_sync_committee_signatures(&[])
        .await
        .expect("submit no sync committee messages");
}

#[tokio::test]
async fn publish_contribution_and_proofs_accepts_an_empty_batch() {
    let node = BeaconNodeContainer::shared().await;

    node.client()
        .publish_contribution_and_proofs(&[])
        .await
        .expect("publish no contributions");
}
