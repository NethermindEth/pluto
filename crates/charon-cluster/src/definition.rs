use crate::helpers::EthHex;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, PickFirst, serde_as};
use uuid::Uuid;

use crate::operator::Operator;

/// Definition defines an intended charon cluster configuration excluding
/// validators. Note the following struct tag meanings:
///   - json: json field name. Suffix 0xhex indicates bytes are formatted as 0x
///     prefixed hex strings.
///   - ssz: ssz equivalent. Either uint64 for numbers, BytesN for fixed length
///     bytes, ByteList[MaxN] for variable length strings, or
///     CompositeList[MaxN] for nested object arrays.
///   - config_hash: field ordering when calculating config hash. Some fields
///     are excluded indicated by `-`.
///   - definition_hash: field ordering when calculating definition hash. Some
///     fields are excluded indicated by `-`.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Definition {
    /// UUID is a human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Name is a human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Version is the schema version of this definition. Max 16 chars.
    pub version: String,
    /// Timestamp is the human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// NumValidators is the number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u32,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u32,
    /// DKGAlgorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// ForkVersion defines the cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    #[serde_as(as = "EthHex")]
    pub fork_version: Vec<u8>,
    /// Operators define the charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<Operator>,
    /// Creator identifies the creator of a cluster definition. They may also be
    /// an operator.
    pub creator: Creator,
    /// ValidatorAddresses define addresses of each validator.
    #[serde(rename = "validators")]
    pub validator_addresses: Vec<ValidatorAddresses>,
    /// DepositAmounts specifies partial deposit amounts that sum up to at least
    /// 32ETH.
    #[serde_as(as = "Vec<PickFirst<(_, DisplayFromStr)>>")]
    pub deposit_amounts: Vec<u64>,
    /// ConsensusProtocol is the consensus protocol name preferred by the
    /// cluster, e.g. "abft".
    pub consensus_protocol: String,
    /// TargetGasLimit is the target block gas limit for the cluster.
    pub target_gas_limit: u32,
    /// Compounding flag enables compounding rewards for validators by using
    /// 0x02 withdrawal credentials.
    pub compounding: bool,
    /// ConfigHash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub config_hash: Vec<u8>,
    /// DefinitionHash uniquely identifies a cluster definition including
    /// operator ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub definition_hash: Vec<u8>,
}

/// Creator identifies the creator of a cluster definition. They may also be an
/// operator.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Creator {
    /// The Ethereum address of the creator
    pub address: String,
    /// The creator's signature over the config hash
    #[serde_as(as = "EthHex")]
    pub config_signature: Vec<u8>,
}

/// ValidatorAddresses define addresses for a validator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorAddresses {
    /// The fee recipient address for the validator
    pub fee_recipient_address: String,
    /// The withdrawal address for the validator
    pub withdrawal_address: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_definition_v1_10_0() {
        let definition = serde_json::from_str::<Definition>(include_str!(
            "testdata/cluster_definition_v1_10_0.json"
        ))
        .unwrap();

        // Verify basic metadata
        assert_eq!(definition.name, "test definition");
        assert_eq!(definition.version, "v1.10.0");
        assert_eq!(
            definition.uuid.to_string().to_uppercase(),
            "0194FDC2-FA2F-4CC0-81D3-FF12045B73C8"
        );
        assert_eq!(definition.num_validators, 2);
        assert_eq!(definition.threshold, 3);
        assert_eq!(definition.dkg_algorithm, "default");

        // Verify creator
        assert_eq!(
            definition.creator.address,
            "0x6325253fec738dd7a9e28bf921119c160f070244"
        );
        assert_eq!(
            definition.creator.config_signature,
            hex::decode("0bf5059875921e668a5bdf2c7fc4844592d2572bcd0668d2d6c52f5054e2d0836bf84c7174cb7476364cc3dbd968b0f7172ed85794bb358b0c3b525da1786f9f1c").unwrap()
        );

        // Verify operators
        assert_eq!(definition.operators.len(), 2);
        assert_eq!(
            definition.operators[0].address,
            "0x094279db1944ebd7a19d0f7bbacbe0255aa5b7d4"
        );
        assert_eq!(
            definition.operators[0].enr,
            "enr://b0223beea5f4f74391f445d15afd4294040374f6924b98cbf8713f8d962d7c8d"
        );
        assert_eq!(
            definition.operators[0].config_signature,
            hex::decode("019192c24224e2cafccae3a61fb586b14323a6bc8f9e7df1d929333ff993933bea6f5b3af6de0374366c4719e43a1b067d89bc7f01f1f573981659a44ff17a4c1c").unwrap()
        );
        assert_eq!(
            definition.operators[0].enr_signature,
            hex::decode("15a3b539eb1e5849c6077dbb5722f5717a289a266f97647981998ebea89c0b4b373970115e82ed6f4125c8fa7311e4d7defa922daae7786667f7e936cd4f24ab1c").unwrap()
        );
        assert_eq!(
            definition.operators[1].address,
            "0xdf866baa56038367ad6145de1ee8f4a8b0993ebd"
        );
        assert_eq!(
            definition.operators[1].enr,
            "enr://e56a156a8de563afa467d49dec6a40e9a1d007f033c2823061bdd0eaa59f8e4d"
        );
        assert_eq!(
            definition.operators[1].config_signature,
            hex::decode("a6430105220d0b29688b734b8ea0f3ca9936e8461f10d77c96ea80a7a665f606f6a63b7f3dfd2567c18979e4d60f26686d9bf2fb26c901ff354cde1607ee294b1b").unwrap()
        );
        assert_eq!(
            definition.operators[1].enr_signature,
            hex::decode("f32b7c7822ba64f84ab43ca0c6e6b91c1fd3be8990434179d3af4491a369012db92d184fc39d1734ff5716428953bb6865fcf92b0c3a17c9028be9914eb7649c1c").unwrap()
        );

        // Verify validator addresses
        assert_eq!(definition.validator_addresses.len(), 2);
        assert_eq!(
            definition.validator_addresses[0].fee_recipient_address,
            "0x52fdfc072182654f163f5f0f9a621d729566c74d"
        );
        assert_eq!(
            definition.validator_addresses[0].withdrawal_address,
            "0x81855ad8681d0d86d1e91e00167939cb6694d2c4"
        );
        assert_eq!(
            definition.validator_addresses[1].fee_recipient_address,
            "0xeb9d18a44784045d87f3c67cf22746e995af5a25"
        );
        assert_eq!(
            definition.validator_addresses[1].withdrawal_address,
            "0x5fb90badb37c5821b6d95526a41a9504680b4e7c"
        );

        // Verify deposit amounts
        assert_eq!(definition.deposit_amounts.len(), 2);
        assert_eq!(definition.deposit_amounts[0], 16000000000);
        assert_eq!(definition.deposit_amounts[1], 16000000000);

        // Verify v1.10.0 specific fields
        assert_eq!(definition.consensus_protocol, "abft");
        assert_eq!(definition.target_gas_limit, 30000000);
        assert!(!definition.compounding);

        // Verify hashes are present
        assert_eq!(
            definition.config_hash,
            hex::decode("19f6e5753f05c9b662b54959fbe5b0c265d6f571ea414310b84c5fe2e0851f61")
                .unwrap()
        );
        assert_eq!(
            definition.definition_hash,
            hex::decode("59a8d3ffa9010f54965a11248e2835e716049d508f4f64bf43bd5a6ca56037c0")
                .unwrap()
        );
    }
}
