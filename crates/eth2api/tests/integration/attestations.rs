//! Attestation data produced on a head fixed at genesis.

use crate::{BeaconNodeContainer, GENESIS_BLOCK_ROOT};
use pluto_eth2api::spec::phase0;

#[tokio::test]
async fn produce_attestation_data_at_slot_one_targets_the_genesis_block() {
    let node = BeaconNodeContainer::shared().await;

    let data = node
        .client()
        .produce_attestation_data(1, 0)
        .await
        .expect("produce attestation data");

    assert_eq!(
        data,
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
    );
}

#[tokio::test]
async fn produce_attestation_data_in_epoch_one_targets_epoch_one_at_the_genesis_root() {
    let node = BeaconNodeContainer::shared().await;

    let data = node
        .client()
        .produce_attestation_data(33, 0)
        .await
        .expect("produce attestation data");

    assert_eq!(
        data,
        phase0::AttestationData {
            slot: 33,
            index: 0,
            beacon_block_root: crate::hex_bytes(GENESIS_BLOCK_ROOT),
            source: phase0::Checkpoint {
                epoch: 0,
                root: [0; 32],
            },
            target: phase0::Checkpoint {
                epoch: 1,
                root: crate::hex_bytes(GENESIS_BLOCK_ROOT),
            },
        }
    );
}
