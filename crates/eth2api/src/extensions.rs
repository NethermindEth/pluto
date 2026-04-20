use crate::{
    ConsensusVersion, EthBeaconNodeApiClient, GetGenesisRequest, GetGenesisResponse,
    GetSpecRequest, GetSpecResponse, ValidatorStatus, spec::phase0,
};
use chrono::{DateTime, Utc};
use std::{collections::HashMap, time};
use tree_hash::TreeHash;

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

    /// Domain type not found in the beacon spec response
    #[error("Domain type not found: {0}")]
    DomainTypeNotFound(String),
}

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
    pub version: phase0::Version,
    /// The epoch at which the fork activates.
    pub epoch: phase0::Epoch,
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], EthBeaconNodeApiClientError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).map_err(|_| EthBeaconNodeApiClientError::UnexpectedType)?;

    bytes
        .try_into()
        .map_err(|_| EthBeaconNodeApiClientError::UnexpectedType)
}

fn fork_schedule_from_spec(
    spec_data: &serde_json::Value,
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
            .ok_or(EthBeaconNodeApiClientError::UnexpectedType)
            .and_then(decode_fixed_hex)?;

        let epoch_field = format!("{}_FORK_EPOCH", fork.to_string().to_uppercase());
        let epoch = spec_data
            .as_object()
            .and_then(|o| o.get(&epoch_field))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or(EthBeaconNodeApiClientError::UnexpectedType)?;

        Ok(ForkSchedule { version, epoch })
    }

    let mut result = HashMap::new();
    for fork in FORKS {
        let fork_schedule = fetch_fork(&fork, spec_data)?;
        result.insert(fork, fork_schedule);
    }

    Ok(result)
}

/// Computes the final 32-byte beacon domain from domain type, fork version, and genesis root.
pub fn compute_domain(
    domain_type: phase0::DomainType,
    fork_version: phase0::Version,
    genesis_validators_root: phase0::Root,
) -> phase0::Domain {
    let fork_data = phase0::ForkData {
        current_version: fork_version,
        genesis_validators_root,
    };
    let fork_data_root = fork_data.tree_hash_root();

    let mut domain = phase0::Domain::default();
    domain[..phase0::DOMAIN_TYPE_LEN].copy_from_slice(&domain_type);
    domain[phase0::DOMAIN_TYPE_LEN..]
        .copy_from_slice(&fork_data_root.0[..(phase0::DOMAIN_LEN - phase0::DOMAIN_TYPE_LEN)]);

    domain
}

/// Computes the builder domain using `GENESIS_FORK_VERSION` and a zero
/// validators root.
///
/// Builder registrations do not use the fork-at-epoch beacon domain.
/// References:
/// - <https://github.com/ethereum/builder-specs/blob/100d4faf32e5dc672c963741769390ff09ab194a/specs/bellatrix/builder.md#signing>
/// - <https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#compute_domain>
pub fn compute_builder_domain(
    domain_type: phase0::DomainType,
    genesis_fork_version: phase0::Version,
) -> phase0::Domain {
    compute_domain(domain_type, genesis_fork_version, phase0::Root::default())
}

/// Resolves the domain type from the beacon spec.
pub fn resolve_domain_type(
    spec_data: &serde_json::Value,
    spec_key: &str,
) -> Result<phase0::DomainType, EthBeaconNodeApiClientError> {
    let raw = spec_data
        .as_object()
        .and_then(|o| o.get(spec_key))
        .and_then(|value| value.as_str())
        .ok_or_else(|| EthBeaconNodeApiClientError::DomainTypeNotFound(spec_key.to_string()))?;

    decode_fixed_hex(raw)
}

/// Resolves the active fork version at the given epoch.
pub fn resolve_fork_version(
    epoch: phase0::Epoch,
    genesis_fork_version: phase0::Version,
    fork_schedule: &HashMap<ConsensusVersion, ForkSchedule>,
) -> phase0::Version {
    fork_schedule
        .values()
        .filter(|fork| fork.epoch <= epoch)
        .max_by_key(|fork| fork.epoch)
        .map(|fork| fork.version)
        .unwrap_or(genesis_fork_version)
}

fn resolve_domain(
    domain_type: phase0::DomainType,
    voluntary_exit_domain_type: phase0::DomainType,
    fork_schedule: &HashMap<ConsensusVersion, ForkSchedule>,
    genesis_fork_version: phase0::Version,
    genesis_validators_root: phase0::Root,
    epoch: phase0::Epoch,
) -> phase0::Domain {
    let fork_version = if domain_type == voluntary_exit_domain_type {
        // EIP-7044: voluntary exits always use the Capella domain.
        fork_schedule
            .get(&ConsensusVersion::Capella)
            .map(|fork| fork.version)
            .unwrap_or(genesis_fork_version)
    } else {
        resolve_fork_version(epoch, genesis_fork_version, fork_schedule)
    };

    compute_domain(domain_type, fork_version, genesis_validators_root)
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
    async fn fetch_spec_data(&self) -> Result<serde_json::Value, EthBeaconNodeApiClientError> {
        match self.get_spec(GetSpecRequest {}).await? {
            GetSpecResponse::Ok(spec) => Ok(spec.data),
            _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
        }
    }

    async fn fetch_genesis_data(&self) -> Result<serde_json::Value, EthBeaconNodeApiClientError> {
        match self.get_genesis(GetGenesisRequest {}).await? {
            GetGenesisResponse::Ok(genesis) => Ok(serde_json::json!({
                "genesis_time": genesis.data.genesis_time,
                "genesis_validators_root": genesis.data.genesis_validators_root,
                "genesis_fork_version": genesis.data.genesis_fork_version,
            })),
            _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
        }
    }

    /// Fetches the genesis time.
    pub async fn fetch_genesis_time(&self) -> Result<DateTime<Utc>, EthBeaconNodeApiClientError> {
        let genesis = self.fetch_genesis_data().await?;
        let genesis_time = genesis
            .get("genesis_time")
            .and_then(serde_json::Value::as_str)
            .ok_or(EthBeaconNodeApiClientError::UnexpectedType)?;

        genesis_time
            .parse()
            .map_err(|_| EthBeaconNodeApiClientError::UnexpectedType)
            .and_then(|timestamp| {
                DateTime::from_timestamp(timestamp, 0)
                    .ok_or(EthBeaconNodeApiClientError::UnexpectedType)
            })
    }

    /// Fetches the raw chain spec as a JSON object.
    pub async fn fetch_spec(&self) -> Result<serde_json::Value, EthBeaconNodeApiClientError> {
        match self.get_spec(GetSpecRequest {}).await? {
            GetSpecResponse::Ok(resp) => Ok(resp.data),
            _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
        }
    }

    /// Fetches the slot duration and slots per epoch.
    pub async fn fetch_slots_config(
        &self,
    ) -> Result<(time::Duration, u64), EthBeaconNodeApiClientError> {
        let spec = self.fetch_spec_data().await?;

        let slot_duration = spec
            .as_object()
            .and_then(|o| o.get("SECONDS_PER_SLOT"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or(EthBeaconNodeApiClientError::UnexpectedType)
            .map(time::Duration::from_secs)?;

        let slots_per_epoch = spec
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
        let spec = self.fetch_spec_data().await?;
        fork_schedule_from_spec(&spec)
    }

    /// Fetches the domain type with the provided config/spec key.
    pub async fn fetch_domain_type(
        &self,
        spec_key: &str,
    ) -> Result<phase0::DomainType, EthBeaconNodeApiClientError> {
        let spec = self.fetch_spec_data().await?;
        resolve_domain_type(&spec, spec_key)
    }

    /// Fetches the genesis domain for the provided domain type.
    pub async fn fetch_genesis_domain(
        &self,
        domain_type: phase0::DomainType,
    ) -> Result<phase0::Domain, EthBeaconNodeApiClientError> {
        Ok(compute_domain(
            domain_type,
            self.fetch_genesis_fork_version().await?,
            phase0::Root::default(),
        ))
    }

    /// Fetches the genesis validators root from the beacon node.
    pub async fn fetch_genesis_validators_root(
        &self,
    ) -> Result<phase0::Root, EthBeaconNodeApiClientError> {
        let genesis = self.fetch_genesis_data().await?;
        let root = genesis
            .get("genesis_validators_root")
            .and_then(serde_json::Value::as_str)
            .ok_or(EthBeaconNodeApiClientError::UnexpectedType)?;

        decode_fixed_hex(root)
    }

    /// Fetches the genesis fork version from the beacon node.
    pub async fn fetch_genesis_fork_version(
        &self,
    ) -> Result<phase0::Version, EthBeaconNodeApiClientError> {
        let genesis = self.fetch_genesis_data().await?;
        let version = genesis
            .get("genesis_fork_version")
            .and_then(serde_json::Value::as_str)
            .ok_or(EthBeaconNodeApiClientError::UnexpectedType)?;

        decode_fixed_hex(version)
    }

    /// Fetches the resolved beacon domain for the provided domain type and epoch.
    pub async fn fetch_domain(
        &self,
        domain_type: phase0::DomainType,
        epoch: phase0::Epoch,
    ) -> Result<phase0::Domain, EthBeaconNodeApiClientError> {
        let spec = self.fetch_spec_data().await?;
        let fork_schedule = fork_schedule_from_spec(&spec)?;
        let genesis_fork_version = self.fetch_genesis_fork_version().await?;
        let genesis_validators_root = self.fetch_genesis_validators_root().await?;
        let voluntary_exit_domain_type = resolve_domain_type(&spec, "DOMAIN_VOLUNTARY_EXIT")?;

        Ok(resolve_domain(
            domain_type,
            voluntary_exit_domain_type,
            &fork_schedule,
            genesis_fork_version,
            genesis_validators_root,
            epoch,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec_fixture() -> serde_json::Value {
        json!({
            "DOMAIN_BEACON_PROPOSER": "0x00000000",
            "DOMAIN_VOLUNTARY_EXIT": "0x04000000",
            "DOMAIN_APPLICATION_BUILDER": "0x00000001",
            "ALTAIR_FORK_VERSION": "0x01020304",
            "ALTAIR_FORK_EPOCH": "10",
            "BELLATRIX_FORK_VERSION": "0x02030405",
            "BELLATRIX_FORK_EPOCH": "20",
            "CAPELLA_FORK_VERSION": "0x03040506",
            "CAPELLA_FORK_EPOCH": "30",
            "DENEB_FORK_VERSION": "0x04050607",
            "DENEB_FORK_EPOCH": "40",
            "ELECTRA_FORK_VERSION": "0x05060708",
            "ELECTRA_FORK_EPOCH": "50",
            "FULU_FORK_VERSION": "0x06070809",
            "FULU_FORK_EPOCH": "60"
        })
    }

    #[test]
    fn resolve_fork_version_uses_genesis_version_before_first_fork() {
        let spec = spec_fixture();
        let fork_schedule = fork_schedule_from_spec(&spec).unwrap();
        let genesis_fork_version = [0x11, 0x22, 0x33, 0x44];

        assert_eq!(
            resolve_fork_version(0, genesis_fork_version, &fork_schedule),
            genesis_fork_version
        );
    }

    #[test]
    fn resolve_fork_version_uses_latest_active_fork_version() {
        let spec = spec_fixture();
        let fork_schedule = fork_schedule_from_spec(&spec).unwrap();
        let genesis_fork_version = [0x11, 0x22, 0x33, 0x44];

        assert_eq!(
            resolve_fork_version(25, genesis_fork_version, &fork_schedule),
            [0x02, 0x03, 0x04, 0x05]
        );
    }

    #[test]
    fn compute_builder_domain_stays_constant() {
        let genesis_fork_version = [0x01, 0x01, 0x70, 0x00];

        let at_genesis = compute_builder_domain([0x00, 0x00, 0x00, 0x01], genesis_fork_version);
        let post_forks = compute_builder_domain([0x00, 0x00, 0x00, 0x01], genesis_fork_version);

        assert_eq!(at_genesis, post_forks);
        assert_eq!(
            hex::encode(at_genesis),
            "000000015b83a23759c560b2d0c64576e1dcfc34ea94c4988f3e0d9f77f05387"
        );
    }

    #[test]
    fn resolve_domain_uses_capella_for_voluntary_exit_domain_type() {
        let spec = spec_fixture();
        let fork_schedule = fork_schedule_from_spec(&spec).unwrap();
        let genesis_fork_version = [0x11, 0x22, 0x33, 0x44];
        let genesis_validators_root = [0xEE; 32];
        let voluntary_exit_domain_type =
            resolve_domain_type(&spec, "DOMAIN_VOLUNTARY_EXIT").unwrap();

        let domain = resolve_domain(
            voluntary_exit_domain_type,
            voluntary_exit_domain_type,
            &fork_schedule,
            genesis_fork_version,
            genesis_validators_root,
            1_000,
        );

        assert_eq!(
            domain,
            compute_domain(
                [0x04, 0x00, 0x00, 0x00],
                [0x03, 0x04, 0x05, 0x06],
                genesis_validators_root,
            )
        );
    }
}
