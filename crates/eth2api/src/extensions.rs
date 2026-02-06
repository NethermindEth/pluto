use crate::{
    ConsensusVersion, EthBeaconNodeApiClient, GetGenesisRequest, GetGenesisResponse,
    GetSpecRequest, GetSpecResponse, ValidatorStatus,
};
use chrono::{DateTime, Utc};
use std::{collections::HashMap, time};

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

const FORKS: [ConsensusVersion; 6] = [
    ConsensusVersion::Altair,
    ConsensusVersion::Bellatrix,
    ConsensusVersion::Capella,
    ConsensusVersion::Deneb,
    ConsensusVersion::Electra,
    ConsensusVersion::Fulu,
];

/// The schedule of given fork, containing the fork version and the epoch at
/// which it activates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSchedule {
    /// The fork version, as a 4-byte array.
    pub version: [u8; 4],
    /// The epoch at which the fork activates.
    pub epoch: u64,
}

impl ValidatorStatus {
    /// Returns true if the validator is in one of the active states.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            ValidatorStatus::ActiveOngoing
                | ValidatorStatus::ActiveExiting
                | ValidatorStatus::ActiveSlashed
        )
    }
}

impl EthBeaconNodeApiClient {
    /// Fetches the genesis time.
    pub async fn fetch_genesis_time(&self) -> Result<DateTime<Utc>, EthBeaconNodeApiClientError> {
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
                DateTime::from_timestamp(timestamp, 0)
                    .ok_or(EthBeaconNodeApiClientError::UnexpectedType)
            })
    }

    /// Fetches the slot duration and slots per epoch.
    pub async fn fetch_slots_config(
        &self,
    ) -> Result<(time::Duration, u64), EthBeaconNodeApiClientError> {
        let spec = self
            .get_spec(GetSpecRequest {})
            .await
            .and_then(|res| match res {
                GetSpecResponse::Ok(spec) => Ok(spec),
                _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse.into()),
            })?;

        let slot_duration = spec
            .data
            .as_object()
            .and_then(|o| o.get("SECONDS_PER_SLOT"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or(EthBeaconNodeApiClientError::UnexpectedType)
            .map(|secs| time::Duration::from_secs(secs))?;

        let slots_per_epoch = spec
            .data
            .as_object()
            .and_then(|o| o.get("SLOTS_PER_EPOCH"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or(EthBeaconNodeApiClientError::UnexpectedType)?;

        if slot_duration == time::Duration::ZERO || slots_per_epoch == 0 {
            return Err(EthBeaconNodeApiClientError::ZeroSlotDurationOrSlotsPerEpoch);
        }

        Ok((slot_duration, slots_per_epoch))
    }

    /// Fetches the fork schedule for all known forks.
    pub async fn fetch_fork_config(
        &self,
    ) -> Result<HashMap<ConsensusVersion, ForkSchedule>, EthBeaconNodeApiClientError> {
        fn fetch_fork(
            fork: &ConsensusVersion,
            spec_data: &serde_json::Value,
        ) -> Result<ForkSchedule, EthBeaconNodeApiClientError> {
            let version_field = format!("{}_FORK_VERSION", fork.to_string().to_uppercase());
            let version = spec_data
                .as_object()
                .and_then(|o| o.get(&version_field))
                .and_then(|f| f.as_str())
                .and_then(|hex| {
                    let hex = hex.strip_prefix("0x").unwrap_or(hex);
                    hex::decode(hex).ok()
                })
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(EthBeaconNodeApiClientError::UnexpectedType)?;

            let epoch_field = format!("{}_FORK_EPOCH", fork.to_string().to_uppercase());
            let epoch = spec_data
                .as_object()
                .and_then(|o| o.get(&epoch_field))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or(EthBeaconNodeApiClientError::UnexpectedType)?;

            Ok(ForkSchedule { version, epoch })
        }

        let spec = self
            .get_spec(GetSpecRequest {})
            .await
            .and_then(|res| match res {
                GetSpecResponse::Ok(spec) => Ok(spec),
                _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse.into()),
            })?;

        let mut result = HashMap::new();
        for fork in FORKS.into_iter() {
            let fork_schedule = fetch_fork(&fork, &spec.data)?;
            result.insert(fork, fork_schedule);
        }

        Ok(result)
    }
}
