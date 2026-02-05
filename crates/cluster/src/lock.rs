use std::ops::Deref;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    definition::{Definition, DefinitionError},
    distvalidator::{
        DistValidator, DistValidatorV1x0or1, DistValidatorV1x2to5, DistValidatorV1x6,
        DistValidatorV1x7, DistValidatorV1x8orLater,
    },
    helpers::EthHex,
    ssz::{SSZError, hash_lock},
    ssz_hasher::Hasher,
    version::versions::{V1_0, V1_1, V1_2, V1_3, V1_4, V1_5, V1_6, V1_7, V1_8, V1_9, V1_10},
};
use pluto_eth2util::enr::{Record, RecordError};
use pluto_k1util::K1UtilError;
use serde_with::{
    base64::{Base64, Standard},
    serde_as,
};

/// `LockError` is the error type for Lock errors.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// Unexpected validator registration
    #[error("Unexpected validator registration")]
    UnexpectedValidatorRegistration {
        /// Operator index
        operator_idx: usize,
    },

    /// Missing validator registration
    #[error("Missing validator registration")]
    MissingValidatorRegistration {
        /// Operator index
        operator_idx: usize,
    },

    /// Definition hashes verification failed
    #[error("Definition hashes verification failed: {0}")]
    DefinitionHashesVerificationFailed(#[from] DefinitionError),

    /// SSZ error
    #[error("Lock hash verification failed: {0}")]
    SSZError(#[from] SSZError<Hasher>),

    /// Invalid lock hash
    #[error("Invalid lock hash")]
    InvalidLockHash {
        /// Expected lock hash
        expected: Vec<u8>,
        /// Actual lock hash
        actual: Vec<u8>,
    },

    /// Unexpected node signatures
    #[error("Unexpected node signatures")]
    UnexpectedNodeSignatures,

    /// Invalid node signatures count
    #[error("Invalid node signatures count: expected {expected}, actual {actual}")]
    InvalidNodeSignaturesCount {
        /// Expected count of node signatures
        expected: usize,
        /// Actual count of node signatures
        actual: usize,
    },

    /// Failed to parse ENR
    #[error("Failed to parse ENR: {0}")]
    FailedToParseENR(#[from] RecordError),

    /// Missing public key
    #[error("Missing public key")]
    MissingPublicKey,

    /// Node signature verification failed
    #[error("Node signature verification failed")]
    NodeSignatureVerificationFailed {
        /// Operator index
        operator_idx: usize,
        /// Signature
        signature: Vec<u8>,
    },

    /// Failed to verify node signature
    #[error("Failed to verify node signature: {0}")]
    FailedToVerifyNodeSignature(#[from] K1UtilError),
}

type Result<T> = std::result::Result<T, LockError>;

/// Lock extends the cluster config Definition with bls threshold public keys
/// and checksums.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lock {
    /// Definition is embedded and extended by Lock.
    pub definition: Definition,

    /// Validators are the distributed validators managed by the cluster.
    pub distributed_validators: Vec<DistValidator>,

    /// Lock hash uniquely identifies a cluster lock.
    pub lock_hash: Vec<u8>,

    /// BLS aggregate signature of the lock hash
    /// signed by all the private key shares of all the distributed
    /// validators. It acts as an attestation by all the distributed
    /// validators of the charon cluster they are part of.
    pub signature_aggregate: Vec<u8>,

    /// Signatures of the lock hash for each operator
    /// defined in the Definition.
    pub node_signatures: Vec<Vec<u8>>,
}

/// Deref for Lock to allow access to the definition field.
impl Deref for Lock {
    type Target = Definition;

    fn deref(&self) -> &Self::Target {
        &self.definition
    }
}

impl Serialize for Lock {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.definition.version.as_str() {
            V1_0 | V1_1 => LockV1x0or1::from(self.clone()).serialize(serializer),
            V1_2 | V1_3 | V1_4 | V1_5 => LockV1x2to5::from(self.clone()).serialize(serializer),
            V1_6 => LockV1x6::from(self.clone()).serialize(serializer),
            V1_7 => LockV1x7::from(self.clone()).serialize(serializer),
            V1_8 | V1_9 | V1_10 => LockV1x8orLater::from(self.clone()).serialize(serializer),
            _ => Err(serde::ser::Error::custom(format!(
                "Unsupported version: {}",
                self.definition.version
            ))),
        }
    }
}

impl<'de> Deserialize<'de> for Lock {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let value = serde_json::Value::deserialize(deserializer)?;

        let version = value
            .get("cluster_definition")
            .and_then(|v| v.get("version"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::custom("Missing 'version' field"))?;

        match version {
            V1_0 | V1_1 => {
                let lock: LockV1x0or1 = serde_json::from_value(value).map_err(Error::custom)?;
                Ok(lock.into())
            }
            V1_2 | V1_3 | V1_4 | V1_5 => {
                let lock: LockV1x2to5 = serde_json::from_value(value).map_err(Error::custom)?;
                Ok(lock.into())
            }
            V1_6 => {
                let lock: LockV1x6 = serde_json::from_value(value).map_err(Error::custom)?;
                Ok(lock.into())
            }
            V1_7 => {
                let lock: LockV1x7 = serde_json::from_value(value).map_err(Error::custom)?;
                Ok(lock.into())
            }
            V1_8 | V1_9 | V1_10 => {
                let lock: LockV1x8orLater = serde_json::from_value(value).map_err(Error::custom)?;
                Ok(lock.into())
            }
            _ => Err(Error::custom(format!("Unsupported version: {version}"))),
        }
    }
}

impl Lock {
    /// `set_lock_hash` sets the lock hash for the lock.
    pub fn set_lock_hash(&mut self) -> Result<()> {
        let lock_hash = hash_lock(self)?;

        self.lock_hash = lock_hash.to_vec();

        Ok(())
    }

    /// `verify_hashes` returns an error if hashes populated from json object
    /// doesn't matches actual hashes.
    pub fn verify_hashes(&self) -> Result<()> {
        self.definition.verify_hashes()?;

        let lock_hash = hash_lock(self)?;

        if lock_hash.to_vec() != self.lock_hash {
            return Err(LockError::InvalidLockHash {
                expected: self.lock_hash.clone(),
                actual: lock_hash.to_vec(),
            });
        }

        Ok(())
    }

    /// `verify_signatures` returns true if all config signatures are fully
    /// populated and valid. A verified lock is ready for use in charon run.
    pub fn verify_signatures(&self) -> Result<()> {
        todo!("Implement this after eth1wrap.EthClientRunner is implemented");
    }

    /// `verify_node_signatures` returns true an error if the node signatures
    /// field is not correctly populated or otherwise invalid.
    #[allow(dead_code)] // todo: remove this once we use this function
    fn verify_node_signatures(&self) -> Result<()> {
        if matches!(
            self.version.as_str(),
            V1_0 | V1_1 | V1_2 | V1_3 | V1_4 | V1_5 | V1_6
        ) {
            if self.node_signatures.is_empty() {
                return Err(LockError::UnexpectedNodeSignatures);
            }

            return Ok(());
        }

        // Ensure correct count of node signatures
        if self.node_signatures.len() != self.operators.len() {
            return Err(LockError::InvalidNodeSignaturesCount {
                expected: self.operators.len(),
                actual: self.node_signatures.len(),
            });
        }

        // Verify the node signatures
        for idx in 0..self.operators.len() {
            let record = Record::try_from(self.operators[idx].enr.as_str())
                .map_err(LockError::FailedToParseENR)?;

            let pub_key = record
                .public_key
                .ok_or_else(|| LockError::MissingPublicKey)?;

            let verified =
                pluto_k1util::verify_65(&pub_key, &self.lock_hash, &self.node_signatures[idx])?;

            if !verified {
                return Err(LockError::NodeSignatureVerificationFailed {
                    operator_idx: idx,
                    signature: self.node_signatures[idx].clone(),
                });
            }
        }

        Ok(())
    }

    /// `verify_builder_registrations` returns an error if the populated builder
    /// registrations are invalid.
    pub fn verify_builder_registrations(&self) -> Result<()> {
        todo!("Implement this after eth2util.registration is implemented");
    }
}

/// Lock extends the cluster config Definition with bls threshold public keys
/// and checksums.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockV1x0or1 {
    /// Definition is embedded and extended by Lock.
    #[serde(rename = "cluster_definition")]
    pub definition: Definition,

    /// Validators are the distributed validators managed by the cluster.
    #[serde(rename = "distributed_validators")]
    pub distributed_validators: Vec<DistValidatorV1x0or1>,

    /// Lock hash uniquely identifies a cluster lock.
    #[serde_as(as = "Base64<Standard>")]
    pub lock_hash: Vec<u8>,

    /// BLS aggregate signature of the lock hash
    /// signed by all the private key shares of all the distributed
    /// validators. It acts as an attestation by all the distributed
    /// validators of the charon cluster they are part of.
    #[serde_as(as = "Base64<Standard>")]
    pub signature_aggregate: Vec<u8>,
}

impl From<Lock> for LockV1x0or1 {
    fn from(lock: Lock) -> Self {
        Self {
            definition: lock.definition,
            distributed_validators: lock
                .distributed_validators
                .into_iter()
                .map(DistValidatorV1x0or1::from)
                .collect(),
            lock_hash: lock.lock_hash,
            signature_aggregate: lock.signature_aggregate,
        }
    }
}

impl From<LockV1x0or1> for Lock {
    fn from(lock: LockV1x0or1) -> Self {
        Self {
            definition: lock.definition,
            distributed_validators: lock
                .distributed_validators
                .into_iter()
                .map(DistValidator::from)
                .collect(),
            lock_hash: lock.lock_hash,
            signature_aggregate: lock.signature_aggregate,
            node_signatures: Vec::new(),
        }
    }
}
/// Lock extends the cluster config Definition with bls threshold public keys
/// and checksums.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockV1x2to5 {
    /// Definition is embedded and extended by Lock.
    #[serde(rename = "cluster_definition")]
    pub definition: Definition,

    /// Validators are the distributed validators managed by the cluster.
    #[serde(rename = "distributed_validators")]
    pub distributed_validators: Vec<DistValidatorV1x2to5>,

    /// `LockHash` uniquely identifies a cluster lock.
    #[serde_as(as = "EthHex")]
    pub lock_hash: Vec<u8>,

    /// BLS aggregate signature of the lock hash
    /// signed by all the private key shares of all the distributed
    /// validators. It acts as an attestation by all the distributed
    /// validators of the charon cluster they are part of.
    #[serde_as(as = "EthHex")]
    pub signature_aggregate: Vec<u8>,
}

impl From<Lock> for LockV1x2to5 {
    fn from(lock: Lock) -> Self {
        Self {
            definition: lock.definition,
            distributed_validators: lock
                .distributed_validators
                .into_iter()
                .map(DistValidatorV1x2to5::from)
                .collect(),
            lock_hash: lock.lock_hash,
            signature_aggregate: lock.signature_aggregate,
        }
    }
}

impl From<LockV1x2to5> for Lock {
    fn from(lock: LockV1x2to5) -> Self {
        Self {
            definition: lock.definition,
            distributed_validators: lock
                .distributed_validators
                .into_iter()
                .map(DistValidator::from)
                .collect(),
            lock_hash: lock.lock_hash,
            signature_aggregate: lock.signature_aggregate,
            node_signatures: Vec::new(),
        }
    }
}
/// Lock extends the cluster config Definition with bls threshold public keys
/// and checksums.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockV1x6 {
    /// Definition is embedded and extended by Lock.
    #[serde(rename = "cluster_definition")]
    pub definition: Definition,

    /// Validators are the distributed validators managed by the cluster.
    #[serde(rename = "distributed_validators")]
    pub distributed_validators: Vec<DistValidatorV1x6>,

    /// Lock hash uniquely identifies a cluster lock.
    #[serde_as(as = "EthHex")]
    pub lock_hash: Vec<u8>,

    /// BLS aggregate signature of the lock hash
    /// signed by all the private key shares of all the distributed
    /// validators. It acts as an attestation by all the distributed
    /// validators of the charon cluster they are part of.
    #[serde_as(as = "EthHex")]
    pub signature_aggregate: Vec<u8>,
}

impl From<Lock> for LockV1x6 {
    fn from(lock: Lock) -> Self {
        Self {
            definition: lock.definition,
            distributed_validators: lock
                .distributed_validators
                .into_iter()
                .map(DistValidatorV1x6::from)
                .collect(),
            lock_hash: lock.lock_hash,
            signature_aggregate: lock.signature_aggregate,
        }
    }
}

impl From<LockV1x6> for Lock {
    fn from(lock: LockV1x6) -> Self {
        Self {
            definition: lock.definition,
            distributed_validators: lock
                .distributed_validators
                .into_iter()
                .map(DistValidator::from)
                .collect(),
            lock_hash: lock.lock_hash,
            signature_aggregate: lock.signature_aggregate,
            node_signatures: Vec::new(),
        }
    }
}
/// Lock extends the cluster config Definition with bls threshold public keys
/// and checksums.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockV1x7 {
    /// Definition is embedded and extended by Lock.
    #[serde(rename = "cluster_definition")]
    pub definition: Definition,

    /// Validators are the distributed validators managed by the cluster.
    #[serde(rename = "distributed_validators")]
    pub distributed_validators: Vec<DistValidatorV1x7>,

    /// Lock hash uniquely identifies a cluster lock.
    #[serde_as(as = "EthHex")]
    pub lock_hash: Vec<u8>,

    /// BLS aggregate signature of the lock hash
    /// signed by all the private key shares of all the distributed
    /// validators. It acts as an attestation by all the distributed
    /// validators of the charon cluster they are part of.
    #[serde_as(as = "EthHex")]
    pub signature_aggregate: Vec<u8>,

    /// Signatures of the lock hash for each operator
    /// defined in the Definition.
    #[serde_as(as = "Vec<EthHex>")]
    pub node_signatures: Vec<Vec<u8>>,
}

impl From<Lock> for LockV1x7 {
    fn from(lock: Lock) -> Self {
        Self {
            definition: lock.definition,
            distributed_validators: lock
                .distributed_validators
                .into_iter()
                .map(DistValidatorV1x7::from)
                .collect(),
            lock_hash: lock.lock_hash,
            signature_aggregate: lock.signature_aggregate,
            node_signatures: lock.node_signatures,
        }
    }
}

impl From<LockV1x7> for Lock {
    fn from(lock: LockV1x7) -> Self {
        Self {
            definition: lock.definition,
            distributed_validators: lock
                .distributed_validators
                .into_iter()
                .map(DistValidator::from)
                .collect(),
            lock_hash: lock.lock_hash,
            signature_aggregate: lock.signature_aggregate,
            node_signatures: lock.node_signatures,
        }
    }
}
/// Lock extends the cluster config Definition with bls threshold public keys
/// and checksums.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockV1x8orLater {
    /// Definition is embedded and extended by Lock.
    #[serde(rename = "cluster_definition")]
    pub definition: Definition,

    /// Validators are the distributed validators managed by the cluster.
    #[serde(rename = "distributed_validators")]
    pub distributed_validators: Vec<DistValidatorV1x8orLater>,

    /// Lock hash uniquely identifies a cluster lock.
    #[serde_as(as = "EthHex")]
    pub lock_hash: Vec<u8>,

    /// BLS aggregate signature of the lock hash
    /// signed by all the private key shares of all the distributed
    /// validators. It acts as an attestation by all the distributed
    /// validators of the charon cluster they are part of.
    #[serde_as(as = "EthHex")]
    pub signature_aggregate: Vec<u8>,

    /// Signatures of the lock hash for each operator
    /// defined in the Definition.
    #[serde_as(as = "Vec<EthHex>")]
    pub node_signatures: Vec<Vec<u8>>,
}

impl From<Lock> for LockV1x8orLater {
    fn from(lock: Lock) -> Self {
        Self {
            definition: lock.definition,
            distributed_validators: lock
                .distributed_validators
                .into_iter()
                .map(DistValidatorV1x8orLater::from)
                .collect(),
            lock_hash: lock.lock_hash,
            signature_aggregate: lock.signature_aggregate,
            node_signatures: lock.node_signatures,
        }
    }
}

impl From<LockV1x8orLater> for Lock {
    fn from(lock: LockV1x8orLater) -> Self {
        Self {
            definition: lock.definition,
            distributed_validators: lock
                .distributed_validators
                .into_iter()
                .map(DistValidator::from)
                .collect(),
            lock_hash: lock.lock_hash,
            signature_aggregate: lock.signature_aggregate,
            node_signatures: lock.node_signatures,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_v1_10_0() {
        let lock = serde_json::from_str::<Lock>(include_str!("testdata/cluster_lock_v1_10_0.json"))
            .unwrap();

        assert_eq!(lock.definition.name, "test definition");
        assert_eq!(lock.definition.version, "v1.10.0");
        assert_eq!(
            lock.definition.uuid.to_string().to_uppercase(),
            "0194FDC2-FA2F-4CC0-81D3-FF12045B73C8"
        );
        // skip rest of definition verification as it is already tested in definition
        // tests

        // Test distributed_validators length
        assert_eq!(lock.distributed_validators.len(), 2);

        // Test first validator (index 0)
        assert_eq!(lock.distributed_validators[0].pub_key, hex::decode("1814be823350eab13935f31d84484517e924aef78ae151c00755925836b7075885650c30ec29a3703934bf50a28da102").unwrap());
        assert_eq!(lock.distributed_validators[0].pub_shares.len(), 2);
        assert_eq!(lock.distributed_validators[0].pub_shares[0], hex::decode("975deda77e758579ea3dfe4136abf752b3b8271d03e944b3c9db366b75045f8efd69d22ae5411947cb553d7694267aef").unwrap());
        assert_eq!(lock.distributed_validators[0].pub_shares[1], hex::decode("4ebcea406b32d6108bd68584f57e37caac6e33feaa3263a399437024ba9c9b14678a274f01a910ae295f6efbfe5f5abf").unwrap());

        // Test first validator builder_registration
        assert_eq!(
            lock.distributed_validators[0]
                .builder_registration
                .message
                .fee_recipient,
            hex::decode("89b79bf504cfb57c7601232d589baccea9d6e263").unwrap()
        );
        assert_eq!(
            lock.distributed_validators[0]
                .builder_registration
                .message
                .gas_limit,
            30000000
        );
        assert_eq!(
            lock.distributed_validators[0]
                .builder_registration
                .message
                .timestamp
                .timestamp(),
            1655733600
        );
        assert_eq!(lock.distributed_validators[0].builder_registration.message.pub_key, hex::decode("1814be823350eab13935f31d84484517e924aef78ae151c00755925836b7075885650c30ec29a3703934bf50a28da102").unwrap());
        assert_eq!(lock.distributed_validators[0].builder_registration.signature, hex::decode("d313c8a3b4c1c0e05447f4ba370eb36dbcfdec90b302dcdc3b9ef522e2a6f1ed0afec1f8e20faabedf6b162e717d3a748a58677a0c56348f8921a266b11d0f334c62fe52ba53af19779cb2948b6570ffa0b773963c130ad797ddeafe4e3ad29b").unwrap());

        // Test first validator partial_deposit_data
        assert_eq!(lock.distributed_validators[0].partial_deposit_data.len(), 2);
        assert_eq!(lock.distributed_validators[0].partial_deposit_data[0].pub_key, hex::decode("1814be823350eab13935f31d84484517e924aef78ae151c00755925836b7075885650c30ec29a3703934bf50a28da102").unwrap());
        assert_eq!(
            lock.distributed_validators[0].partial_deposit_data[0].withdrawal_credentials,
            hex::decode("76b0620556304a3e3eae14c28d0cea39d2901a52720da85ca1e4b38eaf3f44c6")
                .unwrap()
        );
        assert_eq!(
            lock.distributed_validators[0].partial_deposit_data[0].amount,
            5919415281453547599
        );
        assert_eq!(lock.distributed_validators[0].partial_deposit_data[1].pub_key, hex::decode("1814be823350eab13935f31d84484517e924aef78ae151c00755925836b7075885650c30ec29a3703934bf50a28da102").unwrap());
        assert_eq!(
            lock.distributed_validators[0].partial_deposit_data[1].withdrawal_credentials,
            hex::decode("c7ae77ba1d259b188a4b21c86fbc23d728b45347eada650af24c56d0800a8691")
                .unwrap()
        );
        assert_eq!(
            lock.distributed_validators[0].partial_deposit_data[1].amount,
            8817733914007551237
        );
        assert_eq!(lock.distributed_validators[0].partial_deposit_data[1].signature, hex::decode("332088a8b07590bafcccbec6177536401d9a2b7f512b54bfc9d00532adf5aaa7c3a96bc59b489f77d9042c5bce26b163defde5ee6a0fbb3e9346cef81f0ae9515ef30fa47a364e75aea9e111d596e685a591121966e031650d510354aa845580").unwrap());

        // Test second validator (index 1)
        assert_eq!(lock.distributed_validators[1].pub_key, hex::decode("5125210f0ef1c314090f07c79a6f571c246f3e9ac0b7413ef110bd58b00ce73bff706f7ff4b6f44090a32711f3208e4e").unwrap());
        assert_eq!(lock.distributed_validators[1].pub_shares.len(), 2);
        assert_eq!(lock.distributed_validators[1].pub_shares[0], hex::decode("4b89cb5165ce64002cbd9c2887aa113df2468928d5a23b9ca740f80c9382d9c6034ad2960c796503e1ce221725f50caf").unwrap());
        assert_eq!(lock.distributed_validators[1].pub_shares[1], hex::decode("1fbfe831b10b7bf5b15c47a53dbf8e7dcafc9e138647a4b44ed4bce964ed47f74aa594468ced323cb76f0d3fac476c9f").unwrap());

        // Test second validator builder_registration
        assert_eq!(
            lock.distributed_validators[1]
                .builder_registration
                .message
                .fee_recipient,
            hex::decode("72e6415a761f03abaa40abc9448fddeb2191d945").unwrap()
        );
        assert_eq!(
            lock.distributed_validators[1]
                .builder_registration
                .message
                .gas_limit,
            30000000
        );
        assert_eq!(
            lock.distributed_validators[1]
                .builder_registration
                .message
                .timestamp
                .timestamp(),
            1655733600
        );
        assert_eq!(lock.distributed_validators[1].builder_registration.message.pub_key, hex::decode("5125210f0ef1c314090f07c79a6f571c246f3e9ac0b7413ef110bd58b00ce73bff706f7ff4b6f44090a32711f3208e4e").unwrap());
        assert_eq!(lock.distributed_validators[1].builder_registration.signature, hex::decode("e65a31bd5d41e2d2ce9c2b17892f0fea1931a290220777a93143dfdcbfa68406e877073ff08834e197a4034aa48afa3f85b8a62708caebbac880b5b89b93da53810164402104e648b6226a1b78021851f5d9ac0f313a89ddfc454c5f8f72ac89").unwrap());

        // Test second validator partial_deposit_data
        assert_eq!(lock.distributed_validators[1].partial_deposit_data.len(), 2);
        assert_eq!(lock.distributed_validators[1].partial_deposit_data[0].pub_key, hex::decode("5125210f0ef1c314090f07c79a6f571c246f3e9ac0b7413ef110bd58b00ce73bff706f7ff4b6f44090a32711f3208e4e").unwrap());
        assert_eq!(
            lock.distributed_validators[1].partial_deposit_data[0].withdrawal_credentials,
            hex::decode("0152e5d49435807f9d4b97be6fb77970466a5626fe33408cf9e88e2c797408a3")
                .unwrap()
        );
        assert_eq!(
            lock.distributed_validators[1].partial_deposit_data[0].amount,
            534275443587623213
        );
        assert_eq!(lock.distributed_validators[1].partial_deposit_data[0].signature, hex::decode("329cfffd4a75e498320982c85aad70384859c05a4b13a1d5b2f5bfef5a6ed92da482caa9568e5b6fe9d8a9ddd9eb09277b92cef9046efa18500944cbe800a0b1527ea64729a861d2f6497a3235c37f4192779ec1d96b3b1c5424fce0b727b030").unwrap());

        assert_eq!(lock.distributed_validators[1].partial_deposit_data[1].pub_key, hex::decode("5125210f0ef1c314090f07c79a6f571c246f3e9ac0b7413ef110bd58b00ce73bff706f7ff4b6f44090a32711f3208e4e").unwrap());
        assert_eq!(
            lock.distributed_validators[1].partial_deposit_data[1].withdrawal_credentials,
            hex::decode("078143ee26a586ad23139d5041723470bf24a865837c9123461c41f5ff99aa99")
                .unwrap()
        );
        assert_eq!(
            lock.distributed_validators[1].partial_deposit_data[1].amount,
            2408919902728845389
        );
        assert_eq!(lock.distributed_validators[1].partial_deposit_data[1].signature, hex::decode("ce24eb65491622558fdf297b9fa007864bafd7cd4ca1b2fb5766ab431a032b72b9a7e937ed648d0801f29055d3090d2463718254f9442483c7b98b938045da519843854b0ed3f7ba951a493f321f0966603022c1dfc579b99ed9d20d573ad531").unwrap());

        // Test signature_aggregate
        assert_eq!(
            lock.signature_aggregate,
            hex::decode("9347800979d1830356f2a54c3deab2a4b4475d63afbe8fb56987c77f5818526f")
                .unwrap()
        );

        // Test lock_hash
        assert_eq!(
            lock.lock_hash,
            hex::decode("015036f659bd05894dfb531bf0ab3fdb32a05584ec037fc8262843d14e1aae60")
                .unwrap()
        );

        // Test node_signatures
        assert_eq!(lock.node_signatures.len(), 2);
        assert_eq!(
            lock.node_signatures[0],
            hex::decode("b38b19f53784c19e9beac03c875a27db029de37ae37a42318813487685929359")
                .unwrap()
        );
        assert_eq!(
            lock.node_signatures[1],
            hex::decode("ca8c5eb94e152dc1af42ea3d1676c1bdd19ab8e2925c6daee4de5ef9f9dcf08d")
                .unwrap()
        );
    }

    #[test]
    fn deserialize_serialize_lock_v1_10_0() {
        let lock = serde_json::from_str::<Lock>(include_str!("testdata/cluster_lock_v1_10_0.json"))
            .unwrap();

        let serialized = serde_json::to_string(&lock).unwrap();
        let deserialized: Lock = serde_json::from_str(&serialized).unwrap();
        assert_eq!(lock, deserialized);
    }

    #[test]
    fn test_cluster_lock_v1_10_0() {
        let json_str = include_str!("testdata/cluster_lock_v1_10_0.json");
        let _ = serde_json::from_str::<LockV1x8orLater>(json_str).unwrap();
        let lock = serde_json::from_str::<Lock>(include_str!("testdata/cluster_lock_v1_10_0.json"))
            .unwrap();

        assert!(lock.verify_hashes().is_ok());
    }

    #[test]
    fn test_cluster_lock_v1_9_0() {
        let json_str = include_str!("testdata/cluster_lock_v1_9_0.json");
        let _ = serde_json::from_str::<LockV1x8orLater>(json_str).unwrap();
        let lock = serde_json::from_str::<Lock>(json_str).unwrap();
        assert!(lock.verify_hashes().is_ok());
    }

    #[test]
    fn test_cluster_lock_v1_8_0() {
        let json_str = include_str!("testdata/cluster_lock_v1_8_0.json");
        let _ = serde_json::from_str::<LockV1x8orLater>(json_str).unwrap();
        let lock = serde_json::from_str::<Lock>(json_str).unwrap();
        assert!(lock.verify_hashes().is_ok());
    }

    #[test]
    fn test_cluster_lock_v1_7_0() {
        let json_str = include_str!("testdata/cluster_lock_v1_7_0.json");
        let _ = serde_json::from_str::<LockV1x7>(json_str).unwrap();
        let lock = serde_json::from_str::<Lock>(json_str).unwrap();
        assert!(lock.verify_hashes().is_ok());
    }

    #[test]
    fn test_cluster_lock_v1_6_0() {
        let json_str = include_str!("testdata/cluster_lock_v1_6_0.json");
        let _ = serde_json::from_str::<LockV1x6>(json_str).unwrap();
        let lock = serde_json::from_str::<Lock>(json_str).unwrap();
        assert!(lock.verify_hashes().is_ok());
    }

    #[test]
    fn test_cluster_lock_v1_5_0() {
        let json_str = include_str!("testdata/cluster_lock_v1_5_0.json");
        let _ = serde_json::from_str::<LockV1x2to5>(json_str).unwrap();
        let lock = serde_json::from_str::<Lock>(json_str).unwrap();
        assert!(lock.verify_hashes().is_ok());
    }

    #[test]
    fn test_cluster_lock_v1_4_0() {
        let json_str = include_str!("testdata/cluster_lock_v1_4_0.json");
        let _ = serde_json::from_str::<LockV1x2to5>(json_str).unwrap();
        let lock = serde_json::from_str::<Lock>(json_str).unwrap();
        assert!(lock.verify_hashes().is_ok());
    }

    #[test]
    fn test_cluster_lock_v1_3_0() {
        let json_str = include_str!("testdata/cluster_lock_v1_3_0.json");
        let _ = serde_json::from_str::<LockV1x2to5>(json_str).unwrap();
        let lock = serde_json::from_str::<Lock>(json_str).unwrap();
        assert!(lock.verify_hashes().is_ok());
    }

    #[test]
    fn test_cluster_lock_v1_2_0() {
        let json_str = include_str!("testdata/cluster_lock_v1_2_0.json");
        let _ = serde_json::from_str::<LockV1x2to5>(json_str).unwrap();
        let lock = serde_json::from_str::<Lock>(json_str).unwrap();
        assert!(lock.verify_hashes().is_ok());
    }

    #[test]
    fn test_cluster_lock_v1_1_0() {
        let json_str = include_str!("testdata/cluster_lock_v1_1_0.json");
        let _ = serde_json::from_str::<LockV1x0or1>(json_str).unwrap();
        let lock = serde_json::from_str::<Lock>(json_str).unwrap();
        assert!(lock.verify_hashes().is_ok());
    }

    #[test]
    fn test_cluster_lock_v1_0_0() {
        let json_str = include_str!("testdata/cluster_lock_v1_0_0.json");
        let _ = serde_json::from_str::<LockV1x0or1>(json_str).unwrap();
        let lock = serde_json::from_str::<Lock>(json_str).unwrap();
        assert!(lock.verify_hashes().is_ok());
    }
}
