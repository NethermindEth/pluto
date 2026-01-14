#![allow(missing_docs)]

use eth2api::{
    GetStateValidatorsResponseResponseDatum, ValidatorResponseValidator, ValidatorStatus,
};

type Result<T> = std::result::Result<T, EthBeaconNodeApiClientError>;

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

#[derive(Debug, Clone)]
pub struct Validator {
    pub index: ValidatorIndex,
    pub balance: Gwei,
    pub status: ValidatorStatus,
    pub validator: ValidatorResponseValidator,
}

impl TryFrom<GetStateValidatorsResponseResponseDatum> for Validator {
    type Error = EthBeaconNodeApiClientError;

    fn try_from(datum: GetStateValidatorsResponseResponseDatum) -> Result<Self> {
        Ok(Self {
            index: datum
                .index
                .parse()
                .map_err(|_| EthBeaconNodeApiClientError::UnexpectedType)?,
            balance: datum
                .balance
                .parse()
                .map_err(|_| EthBeaconNodeApiClientError::UnexpectedType)?,
            status: datum.status,
            validator: datum.validator,
        })
    }
}
