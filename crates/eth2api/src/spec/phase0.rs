//! Phase 0 consensus types from the Ethereum beacon chain specification.
//!
//! See: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md>
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tree_hash_derive::TreeHash;

/// Fork version length in bytes.
pub const VERSION_LEN: usize = 4;
/// Signature domain length in bytes.
pub const DOMAIN_LEN: usize = 32;
/// Domain type length in bytes.
pub const DOMAIN_TYPE_LEN: usize = 4;
/// Merkle root length in bytes.
pub const ROOT_LEN: usize = 32;
/// Withdrawal credentials length in bytes.
pub const WITHDRAWAL_CREDENTIALS_LEN: usize = 32;
/// BLS public key length in bytes.
pub const BLS_PUBKEY_LEN: usize = 48;
/// BLS signature length in bytes.
pub const BLS_SIGNATURE_LEN: usize = 96;

/// An amount in Gwei.
pub type Gwei = u64;

/// A validator registry index.
pub type ValidatorIndex = u64;

/// An epoch number.
pub type Epoch = u64;

/// A slot number.
pub type Slot = u64;

/// A fork version number.
pub type Version = [u8; VERSION_LEN];

/// A signature domain.
pub type Domain = [u8; DOMAIN_LEN];

/// A domain type.
pub type DomainType = [u8; DOMAIN_TYPE_LEN];

/// A Merkle root.
pub type Root = [u8; ROOT_LEN];

/// Withdrawal credentials.
pub type WithdrawalCredentials = [u8; WITHDRAWAL_CREDENTIALS_LEN];

/// A BLS12-381 public key.
pub type BLSPubKey = [u8; BLS_PUBKEY_LEN];

/// A BLS12-381 signature.
pub type BLSSignature = [u8; BLS_SIGNATURE_LEN];

/// Deposit message.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#depositmessage>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct DepositMessage {
    /// BLS public key.
    #[serde_as(as = "serde_with::hex::Hex")]
    pub pubkey: BLSPubKey,
    /// Withdrawal credentials.
    #[serde_as(as = "serde_with::hex::Hex")]
    pub withdrawal_credentials: WithdrawalCredentials,
    /// Amount in Gwei.
    pub amount: Gwei,
}

impl From<&DepositData> for DepositMessage {
    fn from(data: &DepositData) -> Self {
        DepositMessage {
            pubkey: data.pubkey,
            withdrawal_credentials: data.withdrawal_credentials,
            amount: data.amount,
        }
    }
}

/// Deposit data.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#depositdata>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct DepositData {
    /// BLS public key.
    #[serde_as(as = "serde_with::hex::Hex")]
    pub pubkey: BLSPubKey,
    /// Withdrawal credentials.
    #[serde_as(as = "serde_with::hex::Hex")]
    pub withdrawal_credentials: WithdrawalCredentials,
    /// Amount in Gwei.
    pub amount: Gwei,
    /// BLS signature.
    #[serde_as(as = "serde_with::hex::Hex")]
    pub signature: BLSSignature,
}

/// Fork data.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#forkdata>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct ForkData {
    /// Current fork version.
    #[serde_as(as = "serde_with::hex::Hex")]
    pub current_version: Version,
    /// Genesis validators root.
    #[serde_as(as = "serde_with::hex::Hex")]
    pub genesis_validators_root: Root,
}

/// Signing data.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#signingdata>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SigningData {
    /// Object root.
    #[serde_as(as = "serde_with::hex::Hex")]
    pub object_root: Root,
    /// Signature domain.
    #[serde_as(as = "serde_with::hex::Hex")]
    pub domain: Domain,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;

    fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = hex::decode(hex).expect("invalid hex");
        bytes.try_into().expect("wrong length")
    }

    fn assert_tree_hash<T: TreeHash>(value: &T, expected_hex: &str) {
        let expected = hex_to_bytes::<32>(expected_hex);
        let actual = value.tree_hash_root();
        assert_eq!(actual, expected, "tree hash mismatch");
    }

    #[test]
    fn type_sizes() {
        assert_eq!(std::mem::size_of::<BLSPubKey>(), BLS_PUBKEY_LEN);
        assert_eq!(std::mem::size_of::<BLSSignature>(), BLS_SIGNATURE_LEN);
        assert_eq!(std::mem::size_of::<Domain>(), DOMAIN_LEN);
        assert_eq!(std::mem::size_of::<Root>(), ROOT_LEN);
        assert_eq!(std::mem::size_of::<Version>(), VERSION_LEN);
        assert_eq!(
            std::mem::size_of::<WithdrawalCredentials>(),
            WITHDRAWAL_CREDENTIALS_LEN
        );
        assert_eq!(std::mem::size_of::<Gwei>(), 8);
    }

    #[test]
    fn deposit_message_conversion() {
        let deposit_data = DepositData {
            pubkey: [1u8; BLS_PUBKEY_LEN],
            withdrawal_credentials: [2u8; WITHDRAWAL_CREDENTIALS_LEN],
            amount: 32_000_000_000,
            signature: [3u8; BLS_SIGNATURE_LEN],
        };

        let deposit_message = DepositMessage::from(&deposit_data);

        assert_eq!(deposit_message.pubkey, deposit_data.pubkey);
        assert_eq!(
            deposit_message.withdrawal_credentials,
            deposit_data.withdrawal_credentials
        );
        assert_eq!(deposit_message.amount, deposit_data.amount);
    }

    #[test]
    fn deposit_data_tree_hash() {
        let deposit_data = DepositData {
            pubkey: hex_to_bytes(
                "8bb5476559fc3ef444be1a5b4d6f5d1f8c8b6f8e8c8a8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f9a9b9c9d9e9fa0a1a2a3",
            ),
            withdrawal_credentials: hex_to_bytes(
                "010000000000000000000000abcdef1234567890abcdef1234567890abcdef12",
            ),
            amount: 32_000_000_000,
            signature: hex_to_bytes(
                "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5f6a7b8c9d0e1f2a3b4c5d6",
            ),
        };

        assert_tree_hash(
            &deposit_data,
            "d194c30f5e55f27b0896c6d66ad40cc72e093a71c0afc35bfa7cc6d0ec13417c",
        );
    }

    #[test]
    fn deposit_message_tree_hash() {
        let deposit_message = DepositMessage {
            pubkey: hex_to_bytes(
                "8bb5476559fc3ef444be1a5b4d6f5d1f8c8b6f8e8c8a8c8d8e8f8a8b8c8d8e8f8a8b8c8d8e8f9a9b9c9d9e9fa0a1a2a3",
            ),
            withdrawal_credentials: hex_to_bytes(
                "010000000000000000000000abcdef1234567890abcdef1234567890abcdef12",
            ),
            amount: 32_000_000_000,
        };

        assert_tree_hash(
            &deposit_message,
            "89ce9bfbbba12f5f3c8939186623506852eb49122d5c18af80165d41a7947a82",
        );
    }

    #[test]
    fn fork_data_tree_hash() {
        let fork_data = ForkData {
            current_version: hex_to_bytes("01020304"),
            genesis_validators_root: hex_to_bytes(
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            ),
        };

        assert_tree_hash(
            &fork_data,
            "35f90ce5dd9afeb16dde0939ca9c9d22ab35f3c4b88749048ff87bdf654ddfbf",
        );
    }

    #[test]
    fn signing_data_tree_hash() {
        let signing_data = SigningData {
            object_root: hex_to_bytes(
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            ),
            domain: hex_to_bytes(
                "0300000001020304000000000000000000000000000000000000000000000000",
            ),
        };

        assert_tree_hash(
            &signing_data,
            "6ad6de7d10b1bfddd4dccb3835df79f08a3fbe478a9894e817e48f24545ae2ec",
        );
    }
}
