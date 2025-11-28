use charon_crypto::types::{PUBLIC_KEY_LENGTH, PublicKey};
use serde::{Deserialize, Serialize};

use crate::{deposit::DepositData, helpers::EthHex, registration::BuilderRegistration};
use serde_with::serde_as;

/// DistValidator is a distributed validator managed by the cluster.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistValidator {
    /// PubKey is the distributed validator group public key.
    #[serde(rename = "distributed_public_key")]
    #[serde_as(as = "EthHex")]
    pub pub_key: Vec<u8>,

    /// PubShares are the public keys corresponding to each node's secret key
    /// share. It can be used to verify a partial signature created by any
    /// node in the cluster.
    #[serde(rename = "public_shares")]
    #[serde_as(as = "Vec<EthHex>")]
    pub pub_shares: Vec<Vec<u8>>,

    /// PartialDepositData is the list of partial deposit data.
    pub partial_deposit_data: Vec<DepositData>,

    /// BuilderRegistration is the pre-generated signed validator builder
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
    /// PublicKey returns the distributed validator group public key.
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

    /// PublicKeyHex returns the validator hex group public key.
    pub fn public_key_hex(&self) -> Result<String, DistValidatorError> {
        let pub_key = self.public_key()?;
        Ok(format!("0x{}", hex::encode(pub_key)))
    }

    /// PublicShare returns a peer's threshold BLS public share.
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

    /// ZeroRegistration returns a true if the validator has zero valued
    /// registration.
    pub fn zero_registration(&self) -> bool {
        self.builder_registration.signature.is_empty()
            && self.builder_registration.message.fee_recipient.is_empty()
            && self.builder_registration.message.gas_limit == 0
            && self.builder_registration.message.timestamp.timestamp() == 0
            && self.builder_registration.message.pub_key.is_empty()
    }

    /// Eth2Registration returns the validator's Eth2 registration.
    pub fn eth2_registration(&self) -> Result<(), DistValidatorError> {
        unimplemented!(
            "Eth2 registration requires to have ethereum types library which is not yet integrated in charon-cluster"
        )
    }
}
