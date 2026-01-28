use pluto_eth2api::ValidatorStatus;

/// Error that can occur when using the [`eth2api::EthBeaconNodeApiClient`].
#[derive(Debug, thiserror::Error)]
pub enum EthBeaconNodeApiClientError {
    /// Underlying error from [`eth2api::EthBeaconNodeApiClient`] when making a
    /// request.
    #[error("Request error: {0}")]
    RequestError(#[from] anyhow::Error),

    /// Unexpected response, e.g, got an error when an Ok response was expected
    #[error("Unexpected response")]
    UnexpectedResponse,

    /// Unexpected type in response
    #[error("Unexpected type in response")]
    UnexpectedType,
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
