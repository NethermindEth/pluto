use charon_crypto::types::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// Gwei represents an amount in Gwei (1 ETH = 1,000,000,000 Gwei)
pub type Gwei = u64;

/// Fork version type (4 bytes).
pub type Version = [u8; 4];

/// Domain type (32 bytes).
pub type Domain = [u8; 32];

/// Root type (32 bytes).
pub type Root = [u8; 32];

/// Withdrawal credentials type (32 bytes).
pub type WithdrawalCredentials = [u8; 32];

/// DepositMessage represents the deposit message to be signed.
/// See: https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#depositmessage
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct DepositMessage {
    /// Validator's BLS public key (48 bytes)
    pub pub_key: PublicKey,
    /// Withdrawal credentials (32 bytes)
    pub withdrawal_credentials: WithdrawalCredentials,
    /// Amount in Gwei to be deposited
    pub amount: Gwei,
}

/// DepositData defines the deposit data to activate a validator.
/// See: https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#depositdata
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct DepositData {
    /// Validator's BLS public key (48 bytes)
    pub pub_key: PublicKey,
    /// Withdrawal credentials (32 bytes)
    pub withdrawal_credentials: WithdrawalCredentials,
    /// Amount in Gwei to be deposited
    pub amount: Gwei,
    /// BLS signature of the deposit message (96 bytes)
    pub signature: Signature,
}

/// ForkData is used for computing the deposit domain.
/// See: https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#forkdata
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub(crate) struct ForkData {
    /// Current fork version
    pub current_version: Version,
    /// Genesis validators root (zero for deposit domain)
    pub genesis_validators_root: Root,
}

/// SigningData is used for computing the signing root.
/// See: https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#signingdata
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub(crate) struct SigningData {
    /// Object root being signed
    pub object_root: Root,
    /// Domain for the signature
    pub domain: Domain,
}

/// DepositDataJson is the json representation of Deposit Data.
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

impl DepositMessage {
    /// Creates a new deposit message with the given parameters.
    pub fn new(
        pubkey: PublicKey,
        withdrawal_addr: &str,
        amount: Gwei,
        compounding: bool,
    ) -> super::Result<Self> {
        let withdrawal_credentials =
            super::withdrawal_creds_from_addr(withdrawal_addr, compounding)?;

        if amount < super::MIN_DEPOSIT_AMOUNT {
            return Err(super::DepositError::MinimumAmountNotMet(amount));
        }

        let max_amount = super::max_deposit_amount(compounding);
        if amount > max_amount {
            return Err(super::DepositError::MaximumAmountExceeded {
                amount,
                max: max_amount,
            });
        }

        Ok(Self {
            pub_key: pubkey,
            withdrawal_credentials,
            amount,
        })
    }

    /// Returns the signing root for this deposit message on the given network.
    pub fn get_message_signing_root(&self, network: &str) -> super::Result<Root> {
        let msg_root = self.tree_hash_root();

        let fork_version_bytes = super::network::network_to_fork_version_bytes(network)?;

        let fork_version: Version = fork_version_bytes.as_slice().try_into().map_err(|_| {
            super::DepositError::NetworkError(super::network::NetworkError::InvalidForkVersion {
                fork_version: hex::encode(&fork_version_bytes),
            })
        })?;

        let domain = super::get_deposit_domain(fork_version);

        let signing_data = SigningData {
            object_root: msg_root.0,
            domain,
        };

        Ok(signing_data.tree_hash_root().0)
    }
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

    #[test]
    fn deposit_data_tree_hash() {
        let pub_key = hex::decode(
            "80d0436ccacd2b263f5e9e7ebaa14015fe5c80d3e57dc7c37bcbda783895e3491019d3ed694ecbb49c8c80a0480c0392"
        ).unwrap();
        let withdrawal_credentials =
            hex::decode("02000000000000000000000005f9f73f74c205f2b9267c04296e3069767531fb")
                .unwrap();
        let signature = hex::decode(
            "aed3c99949ab93622f2d1baaeb047d30cb33e744e1a8464eebe1a2a634f0f23529ce753c54035968e9f3f683bca02f6704c933ca9ff2b181897de4eb27b0b2568721fe625084d5cc9030be55ceb1bc573df61a8a67bad87d94187ee4d28fc36f"
        ).unwrap();
        let expected_root =
            hex::decode("10e0a77c03f4420198571cf957ce3cd7cc85ae310664c77ff9556eba18ec8689")
                .unwrap();

        let deposit_data = DepositData {
            pub_key: pub_key.as_slice().try_into().unwrap(),
            withdrawal_credentials: withdrawal_credentials.as_slice().try_into().unwrap(),
            amount: 32_000_000_000,
            signature: signature.as_slice().try_into().unwrap(),
        };

        let root = deposit_data.tree_hash_root();

        assert_eq!(
            root.as_slice(),
            expected_root.as_slice(),
            "TreeHash implementation doesn't match!"
        );
    }

    #[test]
    fn deposit_message_tree_hash() {
        let pub_key = hex::decode(
            "80d0436ccacd2b263f5e9e7ebaa14015fe5c80d3e57dc7c37bcbda783895e3491019d3ed694ecbb49c8c80a0480c0392"
        ).unwrap();
        let withdrawal_credentials =
            hex::decode("02000000000000000000000005f9f73f74c205f2b9267c04296e3069767531fb")
                .unwrap();
        let expected_root =
            hex::decode("0ed9775278db27ab7ef0efeea0861750d1f0e917deecfe68398321468201f2f8")
                .unwrap();

        let deposit_message = DepositMessage {
            pub_key: pub_key.as_slice().try_into().unwrap(),
            withdrawal_credentials: withdrawal_credentials.as_slice().try_into().unwrap(),
            amount: 32_000_000_000,
        };

        let root = deposit_message.tree_hash_root();

        assert_eq!(
            root.as_slice(),
            expected_root.as_slice(),
            "DepositMessage TreeHash implementation doesn't match!"
        );
    }
}
