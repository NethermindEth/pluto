use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::helpers::{EthHex, TimestampSeconds};

/// BuilderRegistration defines pre-generated signed validator builder
/// registration to be sent to builder network.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuilderRegistration {
    /// Message is the registration message.
    pub message: Registration,

    /// Signature is the BLS signature of the registration message.
    #[serde_as(as = "EthHex")]
    pub signature: Vec<u8>,
}

/// Registration defines unsigned validator registration message.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    /// FeeRecipient is the fee recipient address for the registration.
    #[serde_as(as = "EthHex")]
    pub fee_recipient: Vec<u8>,

    /// GasLimit is the gas limit for the registration.
    pub gas_limit: u64,

    /// Timestamp is the timestamp of the registration.
    #[serde_as(as = "TimestampSeconds")]
    pub timestamp: DateTime<Utc>,

    /// PubKey is the validator's public key.
    #[serde(rename = "pubkey")]
    #[serde_as(as = "EthHex")]
    pub pub_key: Vec<u8>,
}
