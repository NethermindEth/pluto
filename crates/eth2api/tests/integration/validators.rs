//! Validators of the genesis state.

use crate::{BeaconNodeContainer, VALIDATOR_0_PUBKEY, VALIDATOR_1_PUBKEY};
use pluto_eth2api::{
    ValidatorId, ValidatorsFilter, ValidatorsResponse,
    spec::phase0,
    v1::{self, ValidatorStatus},
};

#[tokio::test]
async fn post_state_validators_by_index_returns_the_first_two_genesis_validators() {
    let node = BeaconNodeContainer::shared().await;

    let response = node
        .client()
        .post_state_validators(
            "genesis",
            &ValidatorsFilter {
                ids: vec![ValidatorId::Index(0), ValidatorId::Index(1)],
                statuses: Vec::new(),
            },
        )
        .await
        .expect("post state validators");

    let validator = |index, pubkey, withdrawal_credentials| v1::Validator {
        index,
        balance: 32000000000,
        status: ValidatorStatus::ActiveOngoing,
        validator: phase0::Validator {
            pubkey: crate::hex_bytes(pubkey),
            withdrawal_credentials: crate::hex_bytes(withdrawal_credentials),
            effective_balance: 32000000000,
            slashed: false,
            activation_eligibility_epoch: 0,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            withdrawable_epoch: u64::MAX,
        },
    };
    assert_eq!(
        response,
        ValidatorsResponse {
            execution_optimistic: false,
            finalized: true,
            data: vec![
                validator(
                    0,
                    VALIDATOR_0_PUBKEY,
                    "0x00f50428677c60f997aadeab24aabf7fceaef491c96a52b463ae91f95611cf71",
                ),
                validator(
                    1,
                    VALIDATOR_1_PUBKEY,
                    "0x0092c20062cee70389f1cb4fa566a2be5e2319ff43965db26dbaa3ce90b9df99",
                ),
            ],
        }
    );
}

#[tokio::test]
async fn post_state_validators_by_pubkey_returns_the_matching_index() {
    let node = BeaconNodeContainer::shared().await;

    let response = node
        .client()
        .post_state_validators(
            "genesis",
            &ValidatorsFilter {
                ids: vec![ValidatorId::PubKey(crate::hex_bytes(VALIDATOR_0_PUBKEY))],
                statuses: Vec::new(),
            },
        )
        .await
        .expect("post state validators");

    let indices: Vec<_> = response
        .data
        .iter()
        .map(|validator| validator.index)
        .collect();
    assert_eq!(indices, vec![0]);
}

#[tokio::test]
async fn post_state_validators_with_an_unmatched_status_returns_nothing() {
    let node = BeaconNodeContainer::shared().await;

    let response = node
        .client()
        .post_state_validators(
            "genesis",
            &ValidatorsFilter {
                ids: vec![ValidatorId::Index(0)],
                statuses: vec![ValidatorStatus::ExitedUnslashed],
            },
        )
        .await
        .expect("post state validators");

    assert_eq!(response.data, Vec::new());
}
