use crate::{definition::DefinitionError, helpers::EthHex, version::ZERO_NONCE};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use ssz_derive::{Decode, Encode};

/// Operator represents a charon node operator.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub struct Operator {
    /// The Ethereum address of the operator
    pub address: String,
    /// The ENR of the operator
    pub enr: String,
    /// The config signature of the operator
    #[serde_as(as = "EthHex")]
    pub config_signature: Vec<u8>,
    /// The ENR signature of the operator
    #[serde_as(as = "EthHex")]
    pub enr_signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub(crate) struct OperatorSSZ {
    /// The Ethereum address of the operator
    pub address: [u8; 20],
    /// The ENR of the operator
    pub enr: Vec<u8>,
    /// The config signature of the operator
    pub config_signature: [u8; 65],
    /// The ENR signature of the operator
    pub enr_signature: [u8; 65],
}

impl From<Operator> for OperatorSSZ {
    fn from(operator: Operator) -> Self {
        Self {
            address: operator.address.as_bytes().to_vec().try_into().unwrap(),
            enr: operator.enr.as_bytes().to_vec(),
            config_signature: operator.config_signature.try_into().unwrap(),
            enr_signature: operator.enr_signature.try_into().unwrap(),
        }
    }
}

impl TryFrom<OperatorSSZ> for Operator {
    type Error = DefinitionError;

    fn try_from(operator: OperatorSSZ) -> Result<Self, Self::Error> {
        Ok(Self {
            address: String::from_utf8(operator.address.to_vec()).unwrap(),
            enr: String::from_utf8(operator.enr.to_vec()).unwrap(),
            config_signature: operator.config_signature.to_vec(),
            enr_signature: operator.enr_signature.to_vec(),
        })
    }
}

/// operatorJSONv1x1 is the json formatter of Operator for versions v1.0.0 and
/// v1.1.0.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct OperatorV1X1 {
    /// The Ethereum address of the operator
    address: String,
    /// The ENR of the operator
    enr: String,
    /// The nonce of the operator (always 0)
    nonce: u64,
    /// The config signature of the operator
    #[serde_as(as = "EthHex")]
    pub config_signature: Vec<u8>,
    /// The ENR signature of the operator
    #[serde_as(as = "EthHex")]
    pub enr_signature: Vec<u8>,
}

/// OperatorV1X2OrLater is the json formatter of Operator for versions v1.2.0
/// and later.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct OperatorV1X2OrLater {
    /// The Ethereum address of the operator
    address: String,
    /// The ENR of the operator
    enr: String,
    /// The config signature of the operator
    config_signature: EthHex,
    /// The ENR signature of the operator
    enr_signature: EthHex,
}

impl From<OperatorV1X1> for Operator {
    fn from(operator: OperatorV1X1) -> Self {
        Self {
            address: operator.address,
            enr: operator.enr,
            config_signature: operator.config_signature,
            enr_signature: operator.enr_signature,
        }
    }
}

impl From<Operator> for OperatorV1X1 {
    fn from(operator: Operator) -> Self {
        Self {
            address: operator.address,
            enr: operator.enr,
            nonce: ZERO_NONCE,
            config_signature: operator.config_signature,
            enr_signature: operator.enr_signature,
        }
    }
}

impl From<OperatorV1X2OrLater> for Operator {
    fn from(operator: OperatorV1X2OrLater) -> Self {
        Self {
            address: operator.address,
            enr: operator.enr,
            config_signature: operator.config_signature.into(),
            enr_signature: operator.enr_signature.into(),
        }
    }
}

impl From<Operator> for OperatorV1X2OrLater {
    fn from(operator: Operator) -> Self {
        Self {
            address: operator.address,
            enr: operator.enr,
            config_signature: operator.config_signature.into(),
            enr_signature: operator.enr_signature.into(),
        }
    }
}
