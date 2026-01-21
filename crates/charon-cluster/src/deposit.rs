use crate::helpers::EthHex;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

/// DepositData defines the deposit data to activate a validator.
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#depositdata
/// TODO: unify it with eth2/deposit
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DepositData {
    /// Validator's public key.
    #[serde_as(as = "EthHex")]
    #[serde(rename = "pubkey")]
    pub pub_key: Vec<u8>,

    /// Withdrawal credentials included in the deposit.
    #[serde_as(as = "EthHex")]
    pub withdrawal_credentials: Vec<u8>,

    /// Amount in Gwei to be deposited [1ETH..2048ETH].
    /// We use DisplayFromStr to allow for easy conversion from string to u64.
    #[serde_as(as = "DisplayFromStr")]
    pub amount: u64,

    /// Signature is the BLS signature of the deposit message (above three
    /// fields).
    #[serde_as(as = "EthHex")]
    pub signature: Vec<u8>,
}
