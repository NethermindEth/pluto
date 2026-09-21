//! Block roots, headers and full blocks of the genesis block.

use crate::{BeaconNodeContainer, GENESIS_BLOCK_ROOT, GENESIS_STATE_ROOT};
use pluto_eth2api::{
    BlockHeaderResponse, BlockRootResponse, SignedBlockResponse,
    spec::{
        DataVersion,
        phase0::{self, SszList},
    },
    v1, versioned,
};
use tree_hash::TreeHash;

#[tokio::test]
async fn get_block_root_of_genesis_is_finalized() {
    let node = BeaconNodeContainer::shared().await;

    let response = node
        .client()
        .get_block_root("genesis")
        .await
        .expect("get genesis block root");

    assert_eq!(
        response,
        BlockRootResponse {
            execution_optimistic: false,
            finalized: true,
            data: crate::hex_bytes(GENESIS_BLOCK_ROOT),
        }
    );
}

#[tokio::test]
async fn get_block_root_of_head_is_the_genesis_root() {
    let node = BeaconNodeContainer::shared().await;

    let response = node
        .client()
        .get_block_root("head")
        .await
        .expect("get head block root");

    assert_eq!(response.data, crate::hex_bytes::<32>(GENESIS_BLOCK_ROOT));
}

#[tokio::test]
async fn get_block_header_of_genesis_hashes_to_its_root() {
    let node = BeaconNodeContainer::shared().await;

    let response = node
        .client()
        .get_block_header("genesis")
        .await
        .expect("get genesis block header");

    assert_eq!(
        response,
        BlockHeaderResponse {
            execution_optimistic: false,
            finalized: true,
            data: v1::BeaconBlockHeader {
                root: crate::hex_bytes(GENESIS_BLOCK_ROOT),
                canonical: true,
                header: phase0::SignedBeaconBlockHeader {
                    message: phase0::BeaconBlockHeader {
                        slot: 0,
                        proposer_index: 0,
                        parent_root: [0; 32],
                        state_root: crate::hex_bytes(GENESIS_STATE_ROOT),
                        body_root: crate::hex_bytes(
                            "0xccb62460692be0ec813b56be97f68a82cf57abc102e27bf49ebf4190ff22eedd"
                        ),
                    },
                    signature: [0; 96],
                },
            },
        }
    );
    assert_eq!(
        response.data.header.message.tree_hash_root().0,
        response.data.root
    );
}

#[tokio::test]
async fn get_block_v2_of_genesis_is_the_empty_phase0_block() {
    let node = BeaconNodeContainer::shared().await;

    let response = node
        .client()
        .get_block_v2("genesis")
        .await
        .expect("get genesis block")
        .expect("genesis block exists");

    assert_eq!(
        response,
        SignedBlockResponse {
            version: DataVersion::Phase0,
            execution_optimistic: false,
            finalized: true,
            data: versioned::SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
                message: phase0::BeaconBlock {
                    slot: 0,
                    proposer_index: 0,
                    parent_root: [0; 32],
                    state_root: crate::hex_bytes(GENESIS_STATE_ROOT),
                    body: phase0::BeaconBlockBody {
                        randao_reveal: [0; 96],
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
                signature: [0; 96],
            }),
        }
    );
    let versioned::SignedBeaconBlock::Phase0(signed) = &response.data else {
        panic!("expected a phase0 block, got {:?}", response.data);
    };
    assert_eq!(
        signed.message.tree_hash_root().0,
        crate::hex_bytes::<32>(GENESIS_BLOCK_ROOT)
    );
}
