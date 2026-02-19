use crate::helpers::EthHex;
use pluto_eth2api::spec::phase0;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

/// DepositData defines the deposit data to activate a validator.
///
/// This is a cluster-specific wrapper around the canonical
/// `phase0::DepositData` that uses EthHex serialization (with 0x prefix) to
/// maintain lock file JSON compatibility.
///
/// Specification: <https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositdata>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositData {
    /// Validator's public key (48 bytes).
    #[serde_as(as = "EthHex")]
    #[serde(rename = "pubkey")]
    pub pub_key: phase0::BLSPubKey,

    /// Withdrawal credentials included in the deposit (32 bytes).
    #[serde_as(as = "EthHex")]
    pub withdrawal_credentials: phase0::WithdrawalCredentials,

    /// Amount in Gwei to be deposited [1ETH..2048ETH].
    /// We use DisplayFromStr to allow for easy conversion from string to u64
    #[serde_as(as = "DisplayFromStr")]
    pub amount: phase0::Gwei,

    /// Signature is the BLS signature of the deposit message (96 bytes).
    #[serde_as(as = "EthHex")]
    pub signature: phase0::BLSSignature,
}

impl Default for DepositData {
    fn default() -> Self {
        Self {
            pub_key: [0u8; 48],
            withdrawal_credentials: [0u8; 32],
            amount: 0,
            signature: [0u8; 96],
        }
    }
}
