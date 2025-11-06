use charon_crypto::types::{PUBLIC_KEY_LENGTH, PublicKey};
use serde::{Deserialize, Serialize};

use crate::{deposit::DepositData, helpers::EthHex, registration::BuilderRegistration};
use serde_with::{
    base64::{Base64, Standard},
    serde_as,
};

/// DistValidator is a distributed validator managed by the cluster.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistValidator {
    /// Distributed validator group public key.
    #[serde(rename = "distributed_public_key")]
    #[serde_as(as = "EthHex")]
    pub pub_key: Vec<u8>,

    /// Public shares are the public keys corresponding to each node's secret key
    /// share. It can be used to verify a partial signature created by any
    /// node in the cluster.
    #[serde(rename = "public_shares")]
    #[serde_as(as = "Vec<EthHex>")]
    pub pub_shares: Vec<Vec<u8>>,

    /// Partial deposit data is the list of partial deposit data.
    pub partial_deposit_data: Vec<DepositData>,

    /// Builder registration is the pre-generated signed validator builder
    /// registration.
    pub builder_registration: BuilderRegistration,
}

/// DistValidatorError is an error type for DistValidator operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DistValidatorError {
    /// Invalid public key length.
    #[error("invalid public key length: got {0}, want {1}")]
    InvalidPublicKeyLength(usize, usize),
    /// Invalid public share index.
    #[error("invalid public share index: got {0}, want less than {1}")]
    InvalidPublicShareIndex(usize, usize),
}

impl DistValidator {
    /// Distributed validator group public key.
    pub fn public_key(&self) -> Result<PublicKey, DistValidatorError> {
        if self.pub_key.len() != PUBLIC_KEY_LENGTH {
            return Err(DistValidatorError::InvalidPublicKeyLength(
                self.pub_key.len(),
                PUBLIC_KEY_LENGTH,
            ));
        }
        let mut pub_key = [0u8; PUBLIC_KEY_LENGTH];
        pub_key.copy_from_slice(&self.pub_key);
        Ok(pub_key)
    }

    /// Validator hex group public key.
    pub fn public_key_hex(&self) -> Result<String, DistValidatorError> {
        let pub_key = self.public_key()?;
        Ok(format!("0x{}", hex::encode(pub_key)))
    }

    /// Peer's threshold BLS public share.
    pub fn public_share(&self, index: usize) -> Result<PublicKey, DistValidatorError> {
        if index >= self.pub_shares.len() {
            return Err(DistValidatorError::InvalidPublicShareIndex(
                index,
                self.pub_shares.len(),
            ));
        }
        if self.pub_shares[index].len() != PUBLIC_KEY_LENGTH {
            return Err(DistValidatorError::InvalidPublicKeyLength(
                self.pub_shares[index].len(),
                PUBLIC_KEY_LENGTH,
            ));
        }
        let mut pub_share = [0u8; PUBLIC_KEY_LENGTH];
        pub_share.copy_from_slice(&self.pub_shares[index]);
        Ok(pub_share)
    }

    /// True if the validator has zero valued registration.
    /// registration.
    pub fn zero_registration(&self) -> bool {
        self.builder_registration.signature.is_empty()
            && self.builder_registration.message.fee_recipient.is_empty()
            && self.builder_registration.message.gas_limit == 0
            && self.builder_registration.message.timestamp.timestamp() == 0
            && self.builder_registration.message.pub_key.is_empty()
    }

    /// Validator's Eth2 registration.
    pub fn eth2_registration(&self) -> Result<(), DistValidatorError> {
        unimplemented!(
            "Eth2 registration requires to have ethereum types library which is not yet integrated in charon-cluster"
        )
    }
}

/// DistValidatorV1x1 is a distributed validator managed by the cluster for
/// version v1.0.0 or v1.1.0.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistValidatorV1x0or1 {
    /// Distributed validator group public key.
    #[serde(rename = "distributed_public_key")]
    #[serde_as(as = "EthHex")]
    pub pub_key: Vec<u8>,

    /// Public shares are the public keys corresponding to each node's secret key
    /// share. It can be used to verify a partial signature created by any
    /// node in the cluster.
    #[serde(rename = "public_shares")]
    #[serde_as(as = "Vec<Base64<Standard>>")]
    pub pub_shares: Vec<Vec<u8>>,

    /// Fee recipient address for the validator.
    #[serde(default)]
    #[serde_as(as = "EthHex")]
    pub fee_recipient_address: Vec<u8>,
}

impl From<DistValidator> for DistValidatorV1x0or1 {
    fn from(dist_validator: DistValidator) -> Self {
        Self {
            pub_key: dist_validator.pub_key,
            pub_shares: dist_validator.pub_shares,
            fee_recipient_address: Default::default(),
        }
    }
}

impl From<DistValidatorV1x0or1> for DistValidator {
    fn from(dist_validator: DistValidatorV1x0or1) -> Self {
        Self {
            pub_key: dist_validator.pub_key,
            pub_shares: dist_validator.pub_shares,
            partial_deposit_data: Vec::new(),
            builder_registration: BuilderRegistration::default(),
        }
    }
}
/// DistValidatorV1x2to5 is a distributed validator managed by the cluster for
/// version v1.2.0 to v1.5.0.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistValidatorV1x2to5 {
    /// Distributed validator group public key.
    #[serde(rename = "distributed_public_key")]
    #[serde_as(as = "EthHex")]
    pub pub_key: Vec<u8>,

    /// Public shares are the public keys corresponding to each node's secret key
    /// share. It can be used to verify a partial signature created by any
    /// node in the cluster.
    #[serde(rename = "public_shares")]
    #[serde_as(as = "Vec<EthHex>")]
    pub pub_shares: Vec<Vec<u8>>,

    /// Fee recipient address for the validator.
    #[serde(default)]
    #[serde_as(as = "EthHex")]
    pub fee_recipient_address: Vec<u8>,
}

impl From<DistValidator> for DistValidatorV1x2to5 {
    fn from(dist_validator: DistValidator) -> Self {
        Self {
            pub_key: dist_validator.pub_key,
            pub_shares: dist_validator.pub_shares,
            fee_recipient_address: Default::default(),
        }
    }
}

impl From<DistValidatorV1x2to5> for DistValidator {
    fn from(dist_validator: DistValidatorV1x2to5) -> Self {
        Self {
            pub_key: dist_validator.pub_key,
            pub_shares: dist_validator.pub_shares,
            partial_deposit_data: Vec::new(),
            builder_registration: BuilderRegistration::default(),
        }
    }
}
/// DistValidatorV1x6 is a distributed validator managed by the cluster for
/// version v1.6.0.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistValidatorV1x6 {
    /// Distributed validator group public key.
    #[serde(rename = "distributed_public_key")]
    #[serde_as(as = "EthHex")]
    pub pub_key: Vec<u8>,

    /// Public shares are the public keys corresponding to each node's secret key
    /// share. It can be used to verify a partial signature created by any
    /// node in the cluster.
    #[serde(rename = "public_shares")]
    #[serde_as(as = "Vec<EthHex>")]
    pub pub_shares: Vec<Vec<u8>>,

    /// Deposit data defines the deposit data to activate a validator.
    pub deposit_data: DepositData,
}

impl From<DistValidator> for DistValidatorV1x6 {
    fn from(dist_validator: DistValidator) -> Self {
        Self {
            pub_key: dist_validator.pub_key,
            pub_shares: dist_validator.pub_shares,
            deposit_data: dist_validator
                .partial_deposit_data
                .into_iter()
                .next()
                .unwrap_or_default(),
        }
    }
}

impl From<DistValidatorV1x6> for DistValidator {
    fn from(dist_validator: DistValidatorV1x6) -> Self {
        Self {
            pub_key: dist_validator.pub_key,
            pub_shares: dist_validator.pub_shares,
            partial_deposit_data: vec![dist_validator.deposit_data],
            builder_registration: BuilderRegistration::default(),
        }
    }
}

/// DistValidatorV1x7 is a distributed validator managed by the cluster for
/// version v1.7.0.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistValidatorV1x7 {
    /// Distributed validator group public key.
    #[serde(rename = "distributed_public_key")]
    #[serde_as(as = "EthHex")]
    pub pub_key: Vec<u8>,

    /// Public shares are the public keys corresponding to each node's secret key
    /// share. It can be used to verify a partial signature created by any
    /// node in the cluster.
    #[serde(rename = "public_shares")]
    #[serde_as(as = "Vec<EthHex>")]
    pub pub_shares: Vec<Vec<u8>>,

    /// Deposit data defines the deposit data to activate a validator.
    pub deposit_data: DepositData,

    /// Builder registration is the pre-generated signed validator builder
    /// registration.
    pub builder_registration: BuilderRegistration,
}

impl From<DistValidator> for DistValidatorV1x7 {
    fn from(dist_validator: DistValidator) -> Self {
        Self {
            pub_key: dist_validator.pub_key,
            pub_shares: dist_validator.pub_shares,
            deposit_data: dist_validator
                .partial_deposit_data
                .into_iter()
                .next()
                .unwrap_or_default(),
            builder_registration: dist_validator.builder_registration,
        }
    }
}

impl From<DistValidatorV1x7> for DistValidator {
    fn from(dist_validator: DistValidatorV1x7) -> Self {
        Self {
            pub_key: dist_validator.pub_key,
            pub_shares: dist_validator.pub_shares,
            partial_deposit_data: vec![dist_validator.deposit_data],
            builder_registration: dist_validator.builder_registration,
        }
    }
}
/// DistValidatorV1x8orLater is a distributed validator managed by the cluster
/// for version v1.8.0 or later.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistValidatorV1x8orLater {
    /// Distributed validator group public key.
    #[serde(rename = "distributed_public_key")]
    #[serde_as(as = "EthHex")]
    pub pub_key: Vec<u8>,

    /// Public shares are the public keys corresponding to each node's secret key
    /// share. It can be used to verify a partial signature created by any
    /// node in the cluster.
    #[serde(rename = "public_shares")]
    #[serde_as(as = "Vec<EthHex>")]
    pub pub_shares: Vec<Vec<u8>>,

    /// Deposit data defines the deposit data to activate a validator.
    pub partial_deposit_data: Vec<DepositData>,

    /// Builder registration is the pre-generated signed validator builder
    /// registration.
    pub builder_registration: BuilderRegistration,
}

impl From<DistValidator> for DistValidatorV1x8orLater {
    fn from(dist_validator: DistValidator) -> Self {
        Self {
            pub_key: dist_validator.pub_key,
            pub_shares: dist_validator.pub_shares,
            partial_deposit_data: dist_validator.partial_deposit_data,
            builder_registration: dist_validator.builder_registration,
        }
    }
}

impl From<DistValidatorV1x8orLater> for DistValidator {
    fn from(dist_validator: DistValidatorV1x8orLater) -> Self {
        Self {
            pub_key: dist_validator.pub_key,
            pub_shares: dist_validator.pub_shares,
            partial_deposit_data: dist_validator.partial_deposit_data,
            builder_registration: dist_validator.builder_registration,
        }
    }
}
