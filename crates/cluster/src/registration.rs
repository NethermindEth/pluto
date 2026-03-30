use chrono::{DateTime, Utc};
use pluto_eth2api::spec::phase0;
use pluto_ssz::serde_utils::Hex0x;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::helpers::TimestampSeconds;

/// BuilderRegistration defines pre-generated signed validator builder
/// registration to be sent to builder network.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuilderRegistration {
    /// Registration message.
    pub message: Registration,

    /// BLS signature of the registration message (96 bytes).
    #[serde_as(as = "Hex0x")]
    pub signature: phase0::BLSSignature,
}

/// Registration defines unsigned validator registration message.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    /// Fee recipient address for the registration.
    #[serde_as(as = "Hex0x")]
    pub fee_recipient: [u8; 20],

    /// Gas limit for the registration.
    pub gas_limit: u64,

    /// Timestamp of the registration.
    #[serde_as(as = "TimestampSeconds")]
    pub timestamp: DateTime<Utc>,

    /// Validator's public key (48 bytes).
    #[serde(rename = "pubkey")]
    #[serde_as(as = "Hex0x")]
    pub pub_key: phase0::BLSPubKey,
}

impl Default for BuilderRegistration {
    fn default() -> Self {
        Self {
            message: Registration::default(),
            signature: [0u8; 96],
        }
    }
}

impl Default for Registration {
    fn default() -> Self {
        Self {
            fee_recipient: [0u8; 20],
            gas_limit: 0,
            timestamp: DateTime::<Utc>::default(),
            pub_key: [0u8; 48],
        }
    }
}
