use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::helpers::{EthHex, TimestampSeconds};

/// `BuilderRegistration` defines pre-generated signed validator builder
/// registration to be sent to builder network.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BuilderRegistration {
    /// Registration message.
    pub message: Registration,

    /// BLS signature of the registration message.
    #[serde_as(as = "EthHex")]
    pub signature: Vec<u8>,
}

/// Registration defines unsigned validator registration message.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Registration {
    /// Fee recipient address for the registration.
    #[serde_as(as = "EthHex")]
    pub fee_recipient: Vec<u8>,

    /// Gas limit for the registration.
    pub gas_limit: u64,

    /// Timestamp of the registration.
    #[serde_as(as = "TimestampSeconds")]
    pub timestamp: DateTime<Utc>,

    /// Validator's public key.
    #[serde(rename = "pubkey")]
    #[serde_as(as = "EthHex")]
    pub pub_key: Vec<u8>,
}
