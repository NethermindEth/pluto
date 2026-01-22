use charon_crypto::types::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use tree_hash_derive::TreeHash;

use super::constants::{Domain, Gwei, Root, Version};

/// DepositMessage represents the deposit message to be signed.
/// See: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositmessage
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct DepositMessage {
    /// Validator's BLS public key (48 bytes)
    pub pub_key: PublicKey,
    /// Withdrawal credentials (32 bytes)
    pub withdrawal_credentials: [u8; 32],
    /// Amount in Gwei to be deposited
    pub amount: Gwei,
}

/// DepositData defines the deposit data to activate a validator.
/// See: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositdata
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct DepositData {
    /// Validator's BLS public key (48 bytes)
    pub pub_key: PublicKey,
    /// Withdrawal credentials (32 bytes)
    pub withdrawal_credentials: [u8; 32],
    /// Amount in Gwei to be deposited
    pub amount: Gwei,
    /// BLS signature of the deposit message (96 bytes)
    pub signature: Signature,
}

/// ForkData is used for computing the deposit domain.
/// See: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#forkdata
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub(crate) struct ForkData {
    /// Current fork version
    pub current_version: Version,
    /// Genesis validators root (zero for deposit domain)
    pub genesis_validators_root: Root,
}

/// SigningData is used for computing the signing root.
/// See: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#signingdata
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub(crate) struct SigningData {
    /// Object root being signed
    pub object_root: Root,
    /// Domain for the signature
    pub domain: Domain,
}

/// DepositDataJson is the JSON representation of deposit data for file
/// serialization. This matches the format expected by the Ethereum deposit CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositDataJson {
    /// Validator public key as hex string (without 0x prefix)
    pub pubkey: String,
    /// Withdrawal credentials as hex string (without 0x prefix)
    pub withdrawal_credentials: String,
    /// Amount in Gwei
    pub amount: u64,
    /// Signature as hex string (without 0x prefix)
    pub signature: String,
    /// Deposit message root as hex string (without 0x prefix)
    pub deposit_message_root: String,
    /// Deposit data root as hex string (without 0x prefix)
    pub deposit_data_root: String,
    /// Fork version as hex string (without 0x prefix)
    pub fork_version: String,
    /// Network name (e.g., "mainnet", "goerli")
    pub network_name: String,
    /// Deposit CLI version
    pub deposit_cli_version: String,
}

impl From<&DepositData> for DepositMessage {
    fn from(data: &DepositData) -> Self {
        DepositMessage {
            pub_key: data.pub_key,
            withdrawal_credentials: data.withdrawal_credentials,
            amount: data.amount,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;

    /// Test against known good values from Go implementation golden file.
    /// Data from: charon/eth2util/deposit/testdata/TestMarshalDepositData.golden
    #[test]
    fn test_deposit_data_tree_hash_against_go_golden() {
        // First entry from TestMarshalDepositData.golden
        let pub_key = hex::decode(
            "80d0436ccacd2b263f5e9e7ebaa14015fe5c80d3e57dc7c37bcbda783895e3491019d3ed694ecbb49c8c80a0480c0392"
        ).unwrap();
        let withdrawal_credentials = hex::decode(
            "02000000000000000000000005f9f73f74c205f2b9267c04296e3069767531fb"
        ).unwrap();
        let signature = hex::decode(
            "aed3c99949ab93622f2d1baaeb047d30cb33e744e1a8464eebe1a2a634f0f23529ce753c54035968e9f3f683bca02f6704c933ca9ff2b181897de4eb27b0b2568721fe625084d5cc9030be55ceb1bc573df61a8a67bad87d94187ee4d28fc36f"
        ).unwrap();
        let expected_root = hex::decode(
            "10e0a77c03f4420198571cf957ce3cd7cc85ae310664c77ff9556eba18ec8689"
        ).unwrap();

        let deposit_data = DepositData {
            pub_key: pub_key.as_slice().try_into().unwrap(),
            withdrawal_credentials: withdrawal_credentials.as_slice().try_into().unwrap(),
            amount: Gwei::new(32_000_000_000),
            signature: signature.as_slice().try_into().unwrap(),
        };

        let root = deposit_data.tree_hash_root();

        assert_eq!(
            root.as_slice(),
            expected_root.as_slice(),
            "TreeHash implementation doesn't match Go golden file!"
        );
    }

    /// Test DepositMessage tree hash against Go golden file
    #[test]
    fn test_deposit_message_tree_hash_against_go_golden() {
        // First entry from TestMarshalDepositData.golden
        let pub_key = hex::decode(
            "80d0436ccacd2b263f5e9e7ebaa14015fe5c80d3e57dc7c37bcbda783895e3491019d3ed694ecbb49c8c80a0480c0392"
        ).unwrap();
        let withdrawal_credentials = hex::decode(
            "02000000000000000000000005f9f73f74c205f2b9267c04296e3069767531fb"
        ).unwrap();
        let expected_root = hex::decode(
            "0ed9775278db27ab7ef0efeea0861750d1f0e917deecfe68398321468201f2f8"
        ).unwrap();

        let deposit_message = DepositMessage {
            pub_key: pub_key.as_slice().try_into().unwrap(),
            withdrawal_credentials: withdrawal_credentials.as_slice().try_into().unwrap(),
            amount: Gwei::new(32_000_000_000),
        };

        let root = deposit_message.tree_hash_root();

        assert_eq!(
            root.as_slice(),
            expected_root.as_slice(),
            "DepositMessage TreeHash implementation doesn't match Go golden file!"
        );
    }
}
