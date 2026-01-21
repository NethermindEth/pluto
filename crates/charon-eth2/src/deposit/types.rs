use charon_crypto::types::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use tree_hash::TreeHash;

use super::constants::{Domain, Gwei, Root, Version};

/// DepositMessage represents the deposit message to be signed.
/// See: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositmessage
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForkData {
    /// Current fork version
    pub current_version: Version,
    /// Genesis validators root (zero for deposit domain)
    pub genesis_validators_root: Root,
}

/// SigningData is used for computing the signing root.
/// See: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#signingdata
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SigningData {
    /// Object root being signed
    pub object_root: Root,
    /// Domain for the signature
    pub domain: Domain,
}

// Manual TreeHash implementations for SSZ compatibility
impl TreeHash for DepositMessage {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        let mut hasher = tree_hash::MerkleHasher::with_leaves(3);

        hasher.write(&self.pub_key).expect("pub_key hash");
        hasher
            .write(&self.withdrawal_credentials)
            .expect("withdrawal_credentials hash");
        hasher
            .write(&self.amount.tree_hash_root().0)
            .expect("amount hash");

        hasher.finish().expect("hasher finish")
    }
}

impl TreeHash for DepositData {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        let mut hasher = tree_hash::MerkleHasher::with_leaves(4);

        hasher.write(&self.pub_key).expect("pub_key hash");
        hasher
            .write(&self.withdrawal_credentials)
            .expect("withdrawal_credentials hash");
        hasher
            .write(&self.amount.tree_hash_root().0)
            .expect("amount hash");
        hasher.write(&self.signature).expect("signature hash");

        hasher.finish().expect("hasher finish")
    }
}

impl TreeHash for ForkData {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        let mut hasher = tree_hash::MerkleHasher::with_leaves(2);

        hasher
            .write(&self.current_version)
            .expect("current_version hash");
        hasher
            .write(&self.genesis_validators_root)
            .expect("genesis_validators_root hash");

        hasher.finish().expect("hasher finish")
    }
}

impl TreeHash for SigningData {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        let mut hasher = tree_hash::MerkleHasher::with_leaves(2);

        hasher.write(&self.object_root).expect("object_root hash");
        hasher.write(&self.domain).expect("domain hash");

        hasher.finish().expect("hasher finish")
    }
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

impl DepositData {
    /// Convert DepositData to DepositMessage (drops signature)
    pub fn to_message(&self) -> DepositMessage {
        DepositMessage {
            pub_key: self.pub_key,
            withdrawal_credentials: self.withdrawal_credentials,
            amount: self.amount,
        }
    }
}

impl From<&DepositData> for DepositMessage {
    fn from(data: &DepositData) -> Self {
        data.to_message()
    }
}
