#![allow(missing_docs)]

use eth2api::ValidatorStatus;

#[derive(Debug, thiserror::Error)]
pub enum EthBeaconNodeApiClientError {
    #[error("Request error: {0}")]
    RequestError(#[from] anyhow::Error),

    #[error("Unexpected response")]
    UnexpectedResponse,

    #[error("Unexpected type in response")]
    UnexpectedType,
}

pub type ValidatorIndex = u64;

pub type Gwei = u64;

pub trait ValidatorStatusExt {
    fn is_active(&self) -> bool;
}

impl ValidatorStatusExt for ValidatorStatus {
    fn is_active(&self) -> bool {
        matches!(
            self,
            ValidatorStatus::ActiveOngoing
                | ValidatorStatus::ActiveExiting
                | ValidatorStatus::ActiveSlashed
        )
    }
}
