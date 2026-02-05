// TODO (refactor): move to `pluto_eth2api` crate

use pluto_eth2api::{
    EthBeaconNodeApiClient, GetGenesisRequest, GetGenesisResponse, ValidatorStatus,
};

/// Error that can occur when using the
/// [`EthBeaconNodeApiClient`].
#[derive(Debug, thiserror::Error)]
pub enum EthBeaconNodeApiClientError {
    /// Underlying error from [`EthBeaconNodeApiClient`] when
    /// making a request.
    #[error("Request error: {0}")]
    RequestError(#[from] anyhow::Error),

    /// Unexpected response, e.g, got an error when an Ok response was expected
    #[error("Unexpected response")]
    UnexpectedResponse,

    /// Unexpected type in response
    #[error("Unexpected type in response")]
    UnexpectedType,

    /// Zero slot duration or slots per epoch in network spec
    #[error("Zero slot duration or slots per epoch in network spec")]
    ZeroSlotDurationOrSlotsPerEpoch,
}

/// Type alias for validator index.
pub type ValidatorIndex = u64;

/// Extension methods on [`ValidatorStatus`].
pub trait ValidatorStatusExt {
    /// Returns true if the validator is in one of the active states.
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

/// Extension methods on [`EthBeaconNodeApiClient`].
pub trait EthBeaconNodeApiClientExt {
    /// Fetches the genesis time.
    fn fetch_genesis_time(
        &self,
    ) -> impl std::future::Future<
        Output = Result<chrono::DateTime<chrono::Utc>, EthBeaconNodeApiClientError>,
    > + Send;
}

impl EthBeaconNodeApiClientExt for EthBeaconNodeApiClient {
    async fn fetch_genesis_time(
        &self,
    ) -> Result<chrono::DateTime<chrono::Utc>, EthBeaconNodeApiClientError> {
        let genesis = self
            .get_genesis(GetGenesisRequest {})
            .await
            .and_then(|res| match res {
                GetGenesisResponse::Ok(genesis) => Ok(genesis),
                _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse.into()),
            })?;

        genesis
            .data
            .genesis_time
            .parse()
            .map_err(|_| EthBeaconNodeApiClientError::UnexpectedType)
            .and_then(|timestamp| {
                chrono::DateTime::from_timestamp(timestamp, 0)
                    .ok_or(EthBeaconNodeApiClientError::UnexpectedType)
            })
    }
}
