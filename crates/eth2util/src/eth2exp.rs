//! Aggregator selection for attestation and sync committee duties.

use k256::sha2::{Digest, Sha256};
use pluto_eth2api::{
    EthBeaconNodeApiClient, EthBeaconNodeApiClientError, GetSpecRequest, GetSpecResponse,
    spec::phase0::BLSSignature,
};

/// Error type for aggregator selection operations.
#[derive(Debug, thiserror::Error)]
pub enum Eth2ExpError {
    /// Failed to fetch the chain spec from the beacon node.
    #[error("get eth2 spec: {0}")]
    GetSpec(#[from] EthBeaconNodeApiClientError),

    /// The `TARGET_AGGREGATORS_PER_COMMITTEE` spec field is missing or not a
    /// valid u64.
    #[error("invalid TARGET_AGGREGATORS_PER_COMMITTEE")]
    InvalidTargetAggregatorsPerCommittee,

    /// The `SYNC_COMMITTEE_SIZE` spec field is missing or not a valid u64.
    #[error("invalid SYNC_COMMITTEE_SIZE")]
    InvalidSyncCommitteeSize,

    /// The `SYNC_COMMITTEE_SUBNET_COUNT` spec field is missing or not a valid
    /// u64.
    #[error("invalid SYNC_COMMITTEE_SUBNET_COUNT")]
    InvalidSyncCommitteeSubnetCount,

    /// The `TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE` spec field is missing or
    /// not a valid u64.
    #[error("invalid TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE")]
    InvalidTargetAggregatorsPerSyncSubcommittee,

    /// The `TARGET_AGGREGATORS_PER_COMMITTEE` spec field is zero.
    #[error("zero TARGET_AGGREGATORS_PER_COMMITTEE")]
    ZeroTargetAggregatorsPerCommittee,

    /// The `SYNC_COMMITTEE_SUBNET_COUNT` spec field is zero.
    #[error("zero SYNC_COMMITTEE_SUBNET_COUNT")]
    ZeroSyncCommitteeSubnetCount,

    /// The `TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE` spec field is zero.
    #[error("zero TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE")]
    ZeroTargetAggregatorsPerSyncSubcommittee,
}

/// Provides chain spec parameters from a beacon node.
#[allow(async_fn_in_trait)]
pub trait SpecProvider {
    /// Returns the raw beacon node chain spec as a JSON object.
    async fn spec(&self) -> Result<serde_json::Value, EthBeaconNodeApiClientError>;
}

impl SpecProvider for EthBeaconNodeApiClient {
    async fn spec(&self) -> Result<serde_json::Value, EthBeaconNodeApiClientError> {
        match self.get_spec(GetSpecRequest {}).await? {
            GetSpecResponse::Ok(resp) => Ok(resp.data),
            _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
        }
    }
}

/// Returns true if the validator is the attestation aggregator for the given
/// committee. Refer: <https://github.com/ethereum/consensus-specs/blob/0fe57a94ca543f02cb5eee4d8aab8495e36c0b86/specs/phase0/validator.md#aggregation-selection>
pub async fn is_att_aggregator<S: SpecProvider>(
    spec_provider: &S,
    comm_len: u64,
    slot_sig: BLSSignature,
) -> Result<bool, Eth2ExpError> {
    let spec = spec_provider.spec().await?;

    let aggs_per_comm = spec
        .as_object()
        .and_then(|o| o.get("TARGET_AGGREGATORS_PER_COMMITTEE"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(Eth2ExpError::InvalidTargetAggregatorsPerCommittee)?;

    let modulo = comm_len
        .checked_div(aggs_per_comm)
        .ok_or(Eth2ExpError::ZeroTargetAggregatorsPerCommittee)?
        .max(1);

    Ok(hash_modulo(&slot_sig, modulo))
}

/// Returns true if the validator is the aggregator for the provided sync
/// subcommittee. Refer: <https://github.com/ethereum/consensus-specs/blob/0fe57a94ca543f02cb5eee4d8aab8495e36c0b86/specs/altair/validator.md#aggregation-selection>
pub async fn is_sync_comm_aggregator<S: SpecProvider>(
    spec_provider: &S,
    sig: BLSSignature,
) -> Result<bool, Eth2ExpError> {
    let spec = spec_provider.spec().await?;

    let comm_size = spec
        .as_object()
        .and_then(|o| o.get("SYNC_COMMITTEE_SIZE"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(Eth2ExpError::InvalidSyncCommitteeSize)?;

    let comm_subnet_count = spec
        .as_object()
        .and_then(|o| o.get("SYNC_COMMITTEE_SUBNET_COUNT"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(Eth2ExpError::InvalidSyncCommitteeSubnetCount)?;

    let aggs_per_comm = spec
        .as_object()
        .and_then(|o| o.get("TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(Eth2ExpError::InvalidTargetAggregatorsPerSyncSubcommittee)?;

    let modulo = comm_size
        .checked_div(comm_subnet_count)
        .ok_or(Eth2ExpError::ZeroSyncCommitteeSubnetCount)?
        .checked_div(aggs_per_comm)
        .ok_or(Eth2ExpError::ZeroTargetAggregatorsPerSyncSubcommittee)?
        .max(1);

    Ok(hash_modulo(&sig, modulo))
}

fn hash_modulo(sig: &BLSSignature, modulo: u64) -> bool {
    let hash = Sha256::digest(sig);
    let lowest_8_bytes: [u8; 8] = hash[0..8].try_into().expect("sha256 output is 32 bytes");
    let as_u64 = u64::from_le_bytes(lowest_8_bytes);
    as_u64.is_multiple_of(modulo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use test_case::test_case;

    struct MockSpecProvider {
        spec: serde_json::Value,
    }

    fn default_mock() -> MockSpecProvider {
        MockSpecProvider {
            spec: json!({
                "TARGET_AGGREGATORS_PER_COMMITTEE": "16",
                "SYNC_COMMITTEE_SIZE": "512",
                "SYNC_COMMITTEE_SUBNET_COUNT": "4",
                "TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE": "16"
            }),
        }
    }

    impl SpecProvider for MockSpecProvider {
        async fn spec(&self) -> Result<serde_json::Value, EthBeaconNodeApiClientError> {
            Ok(self.spec.clone())
        }
    }

    fn decode_sig(hex_str: &str) -> BLSSignature {
        hex::decode(hex_str)
            .expect("valid hex")
            .try_into()
            .expect("sig must be 96 bytes")
    }

    // sig from https://github.com/prysmaticlabs/prysm/blob/8627fe72e80009ae162430140bcfff6f209d7a32/beacon-chain/core/helpers/attestation_test.go#L28
    const ATT_SIG_HEX: &str = "8776a37d6802c4797d113169c5fcfda50e68a32058eb6356a6f00d06d7da64c841a00c7c38b9b94a204751eca53707bd03523ce4797827d9bacff116a6e776a20bbccff4b683bf5201b610797ed0502557a58a65c8395f8a1649b976c3112d15";

    #[tokio::test]
    async fn test_is_att_aggregator_aggregator() {
        // comm_len=3, TARGET_AGGREGATORS_PER_COMMITTEE=16 → modulo=max(3/16,1)=1 →
        // always true
        let result = is_att_aggregator(&default_mock(), 3, decode_sig(ATT_SIG_HEX))
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_is_att_aggregator_not_aggregator() {
        // comm_len=64, TARGET_AGGREGATORS_PER_COMMITTEE=16 → modulo=4 → false
        let result = is_att_aggregator(&default_mock(), 64, decode_sig(ATT_SIG_HEX))
            .await
            .unwrap();
        assert!(!result);
    }

    // Non-aggregator test vectors from https://github.com/prysmaticlabs/prysm/blob/39a7988e9edbed5b517229b4d66c2a8aab7c7b4d/beacon-chain/sync/validate_sync_contribution_proof_test.go#L336
    // Aggregator test vectors from https://github.com/prysmaticlabs/prysm/blob/39a7988e9edbed5b517229b4d66c2a8aab7c7b4d/beacon-chain/sync/validate_sync_contribution_proof_test.go#L460
    #[test_case("b9251a82040d4620b8c5665f328ee6c2eaa02d31d71d153f4abba31a7922a981e541e85283f0ced387d26e86aef9386d18c6982b9b5f8759882fe7f25a328180d86e146994ef19d28bc1432baf29751dec12b5f3d65dbbe224d72cf900c6831a", false ; "not_aggregator_0")]
    #[test_case("af8ab34c2858244899fd858042f46e05d703933c9882fc2214a860042a51b3e1260d31cb81f250dd13f801ac58cea517133ee06c817cc2fa965844d2ec1c6d07ca7e00cdda1ab381fa2968bcfe03cb7bb9c15a004b1e7ac2ed9bb0090d271556", false ; "not_aggregator_1")]
    #[test_case("b5600ab2d7ba84f3eaab5f747b1528b78d33b7077508e5e180adfd5ac694ac64be5eb7932658e20243f39f67fcaca7410040495a2a676dcee5a7d7fe7d8958fbb3e1149a28f7d0488e39689c5a899f1b282d9b65f4d95bb38a52a0d83dafa98f", false ; "not_aggregator_2")]
    #[test_case("b2c6aac9ea2ba773d0b0a1a8426a6beceee5ea24ba353dc37058e5cee0fa7373f91ecdce94e87656856878c051da413f178385b6254e86c47cc3f57080d2e946c7e9438f6b942bfeecaed8be8bff994d7c4e8611854b2dde90055ae9ad7d4464", false ; "not_aggregator_3")]
    #[test_case("a2dffa81808dd9718efa3316f081b7db2649d6c11947591b264b5dc45e94bbd98ed6c07f7418f6af2be73d0ab8d1b75a1797bf2e5fcb440f985db37c57c418e2ed8270d0e326aa54ff4bff2950cbfd6603b1ae07c6bd2b6c4137cd2ee17fd250", true ; "aggregator_0")]
    #[test_case("95c6d8706688a96b1e2d825ffe3eea3dbaa34941580204fd6a5179e8124ef8ec38654c74ea042526a22d819a52030572025a16ecd38d3c975ffd72be2a4378265c5b996c14e50f8bbddd670e17618e498607b5ca85c14a136546bc1f02dce0bb", true ; "aggregator_1")]
    #[test_case("a9dbd88a49a7269e91b8ef1296f1e07f87fed919d51a446b67122bfdfd61d23f3f929fc1cd5209bd6862fd60f739b27213fb0a8d339f7f081fc84281f554b190bb49cc97a6b3364e622af9e7ca96a97fe2b766f9e746dead0b33b58473d91562", true ; "aggregator_2")]
    #[test_case("99e60f20dde4d4872b048d703f1943071c20213d504012e7e520c229da87661803b9f139b9a0c5be31de3cef6821c080125aed38ebaf51ba9a2e9d21d7fbf2903577983109d097a8599610a92c0305408d97c1fd4b0b2d1743fb4eedf5443f99", true ; "aggregator_3")]
    #[tokio::test]
    async fn test_is_sync_comm_aggregator(sig_hex: &str, expected: bool) {
        let result = is_sync_comm_aggregator(&default_mock(), decode_sig(sig_hex))
            .await
            .unwrap();
        assert_eq!(result, expected);
    }
}
