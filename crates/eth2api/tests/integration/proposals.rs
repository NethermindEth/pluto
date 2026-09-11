//! Block production on a head fixed at genesis.

use crate::{BLS_INFINITY, BeaconNodeContainer, GENESIS_BLOCK_ROOT};
use alloy::primitives::U256;
use pluto_eth2api::{
    ProduceBlockOpts,
    spec::{DataVersion, phase0},
    versioned::ProposalBlock,
};

fn produce_block_opts(graffiti: Option<phase0::Root>) -> ProduceBlockOpts {
    ProduceBlockOpts {
        slot: 1,
        randao_reveal: BLS_INFINITY,
        graffiti,
        skip_randao_verification: true,
        builder_boost_factor: None,
    }
}

fn phase0_block(block: &ProposalBlock) -> &phase0::BeaconBlock {
    let ProposalBlock::Phase0(block) = block else {
        panic!("expected a phase0 block, got {block:?}");
    };
    block
}

#[tokio::test]
async fn produce_block_v3_builds_an_empty_phase0_block_on_genesis() {
    let node = BeaconNodeContainer::shared().await;

    let proposal = node
        .client()
        .produce_block_v3(&produce_block_opts(None))
        .await
        .expect("produce block");

    assert_eq!(proposal.version(), DataVersion::Phase0);
    assert_eq!(proposal.consensus_block_value, U256::ZERO);
    assert_eq!(proposal.execution_payload_value, U256::ZERO);
    let block = phase0_block(&proposal.block);
    assert_eq!(block.slot, 1);
    assert_eq!(block.proposer_index, 19026);
    assert_eq!(
        block.parent_root,
        crate::hex_bytes::<32>(GENESIS_BLOCK_ROOT)
    );
    assert_eq!(block.body.randao_reveal, BLS_INFINITY);
    assert!(block.body.proposer_slashings.0.is_empty());
    assert!(block.body.attester_slashings.0.is_empty());
    assert!(block.body.attestations.0.is_empty());
    assert!(block.body.deposits.0.is_empty());
    assert!(block.body.voluntary_exits.0.is_empty());
}

#[tokio::test]
async fn produce_block_v3_embeds_the_requested_graffiti() {
    let node = BeaconNodeContainer::shared().await;
    let graffiti =
        crate::hex_bytes("0x0102030000000000000000000000000000000000000000000000000000000000");

    let proposal = node
        .client()
        .produce_block_v3(&produce_block_opts(Some(graffiti)))
        .await
        .expect("produce block");

    assert_eq!(phase0_block(&proposal.block).body.graffiti, graffiti);
}
