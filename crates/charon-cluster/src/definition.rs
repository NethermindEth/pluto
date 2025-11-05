use crate::{
    helpers::EthHex,
    operator::{Operator, OperatorV1X1, OperatorV1X2OrLater},
    version::versions::*,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{
    DisplayFromStr, PickFirst,
    base64::{Base64, Standard},
    serde_as,
};
use uuid::Uuid;

/// Definition defines an intended charon cluster configuration excluding
/// validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// UUID is a human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Name is a human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Version is the schema version of this definition. Max 16 chars.
    pub version: String,
    /// Timestamp is the human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// NumValidators is the number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// DKGAlgorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// ForkVersion defines the cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    pub fork_version: Vec<u8>,
    /// Operators define the charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<Operator>,
    /// Creator identifies the creator of a cluster definition. They may also be
    /// an operator.
    pub creator: Creator,
    /// ValidatorAddresses define addresses of each validator.
    pub validator_addresses: Vec<ValidatorAddresses>,
    /// DepositAmounts specifies partial deposit amounts that sum up to at least
    /// 32ETH.
    pub deposit_amounts: Vec<u64>,
    /// ConsensusProtocol is the consensus protocol name preferred by the
    /// cluster, e.g. "abft".
    pub consensus_protocol: String,
    /// TargetGasLimit is the target block gas limit for the cluster.
    pub target_gas_limit: u64,
    /// Compounding flag enables compounding rewards for validators by using
    /// 0x02 withdrawal credentials.
    pub compounding: bool,
    /// ConfigHash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    pub config_hash: Vec<u8>,
    /// DefinitionHash uniquely identifies a cluster definition including
    /// operator ENRs and signatures.
    pub definition_hash: Vec<u8>,
}

impl Serialize for Definition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.version.as_str() {
            V1_0 | V1_1 => DefinitionV1x0or1::try_from(self.clone())
                .map_err(|e| serde::ser::Error::custom(format!("Conversion error: {:?}", e)))?
                .serialize(serializer),
            V1_2 | V1_3 => DefinitionV1x2or3::try_from(self.clone())
                .map_err(|e| serde::ser::Error::custom(format!("Conversion error: {:?}", e)))?
                .serialize(serializer),
            V1_4 => DefinitionV1x4::try_from(self.clone())
                .map_err(|e| serde::ser::Error::custom(format!("Conversion error: {:?}", e)))?
                .serialize(serializer),
            V1_5 | V1_6 | V1_7 => DefinitionV1x5to7::from(self.clone()).serialize(serializer),
            V1_8 => DefinitionV1x8::from(self.clone()).serialize(serializer),
            V1_9 => DefinitionV1x9::from(self.clone()).serialize(serializer),
            V1_10 => DefinitionV1x10::from(self.clone()).serialize(serializer),
            _ => Err(serde::ser::Error::custom(format!(
                "Unsupported version: {}",
                self.version
            ))),
        }
    }
}

impl<'de> Deserialize<'de> for Definition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let value = serde_json::Value::deserialize(deserializer)?;

        let version = value
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::custom("Missing 'version' field"))?;

        match version {
            V1_0 | V1_1 => {
                let definition: DefinitionV1x0or1 =
                    serde_json::from_value(value).map_err(Error::custom)?;
                definition
                    .try_into()
                    .map_err(|e| Error::custom(format!("Conversion error: {:?}", e)))
            }
            V1_2 | V1_3 => {
                let definition: DefinitionV1x2or3 =
                    serde_json::from_value(value).map_err(Error::custom)?;
                definition
                    .try_into()
                    .map_err(|e| Error::custom(format!("Conversion error: {:?}", e)))
            }
            V1_4 => {
                let definition: DefinitionV1x4 =
                    serde_json::from_value(value).map_err(Error::custom)?;
                definition
                    .try_into()
                    .map_err(|e| Error::custom(format!("Conversion error: {:?}", e)))
            }
            V1_5 | V1_6 | V1_7 => {
                let definition: DefinitionV1x5to7 =
                    serde_json::from_value(value).map_err(Error::custom)?;
                Ok(definition.into())
            }
            V1_8 => {
                let definition: DefinitionV1x8 =
                    serde_json::from_value(value).map_err(Error::custom)?;
                Ok(definition.into())
            }
            V1_9 => {
                let definition: DefinitionV1x9 =
                    serde_json::from_value(value).map_err(Error::custom)?;
                Ok(definition.into())
            }
            V1_10 => {
                let definition: DefinitionV1x10 =
                    serde_json::from_value(value).map_err(Error::custom)?;
                Ok(definition.into())
            }
            _ => Err(Error::custom(format!("Unsupported version: {}", version))),
        }
    }
}

/// DefinitionError is an error type for definition errors.
#[derive(Debug, thiserror::Error)]
pub enum DefinitionError {
    /// InvalidValidatorAddresses is returned when multiple validator addresses
    /// are found.
    #[error("Multiple withdrawal or fee recipient addresses found")]
    InvalidValidatorAddresses,
}

impl Definition {
    /// LegacyValidatorAddresses returns the legacy single withdrawal and single
    /// fee recipient addresses or an error if multiple addresses are found.
    pub fn legacy_validator_addresses(&self) -> Result<ValidatorAddresses, DefinitionError> {
        let mut result_validator_addresses = ValidatorAddresses::default();

        for (i, validator_addresses) in self.validator_addresses.iter().enumerate() {
            if i == 0 {
                result_validator_addresses = validator_addresses.clone();
            } else {
                if validator_addresses != &result_validator_addresses {
                    return Err(DefinitionError::InvalidValidatorAddresses);
                }
            }
        }

        Ok(result_validator_addresses)
    }
}

/// Creator identifies the creator of a cluster definition. They may also be an
/// operator.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Creator {
    /// The Ethereum address of the creator
    pub address: String,
    /// The creator's signature over the config hash
    #[serde_as(as = "EthHex")]
    pub config_signature: Vec<u8>,
}

/// ValidatorAddresses define addresses for a validator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ValidatorAddresses {
    /// The fee recipient address for the validator
    pub fee_recipient_address: String,
    /// The withdrawal address for the validator
    pub withdrawal_address: String,
}

/// DefinitionV1x0or1 is a cluster definition for version 1.0.0 or 1.1.0
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionV1x0or1 {
    /// Name is a human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Operators define the charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<OperatorV1X1>,
    /// UUID is a human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Version is the schema version of this definition. Max 16 chars.
    pub version: String,
    /// Timestamp is the human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// NumValidators is the number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// FeeRecipientAddress is the address of the fee recipient for the
    /// validator.
    pub fee_recipient_address: String,
    /// WithdrawalAddress is the address of the withdrawal address for the
    /// validator.
    pub withdrawal_address: String,
    /// DKGAlgorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// ForkVersion defines the cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    #[serde_as(as = "EthHex")]
    pub fork_version: Vec<u8>,
    /// ConfigHash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    #[serde_as(as = "Base64<Standard>")]
    pub config_hash: Vec<u8>,
    /// DefinitionHash uniquely identifies a cluster definition including
    /// operator ENRs and signatures.
    #[serde_as(as = "Base64<Standard>")]
    pub definition_hash: Vec<u8>,
}

impl TryFrom<Definition> for DefinitionV1x0or1 {
    type Error = DefinitionError;

    fn try_from(definition: Definition) -> Result<Self, Self::Error> {
        let validator_addresses = definition.legacy_validator_addresses()?;

        Ok(Self {
            name: definition.name,
            operators: definition
                .operators
                .into_iter()
                .map(OperatorV1X1::from)
                .collect(),
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            fee_recipient_address: validator_addresses.fee_recipient_address,
            withdrawal_address: validator_addresses.withdrawal_address,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        })
    }
}

impl TryFrom<DefinitionV1x0or1> for Definition {
    type Error = DefinitionError;

    fn try_from(definition: DefinitionV1x0or1) -> Result<Self, Self::Error> {
        let validator_addresses = ValidatorAddresses {
            fee_recipient_address: definition.fee_recipient_address,
            withdrawal_address: definition.withdrawal_address,
        };

        let validator_addresses =
            repeat_v_addresses(validator_addresses, definition.num_validators);

        Ok(Self {
            name: definition.name,
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            operators: definition
                .operators
                .into_iter()
                .map(Operator::from)
                .collect(),
            creator: Creator::default(),
            validator_addresses,
            deposit_amounts: Vec::new(),
            consensus_protocol: String::new(),
            target_gas_limit: 0,
            compounding: false,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        })
    }
}

/// DefinitionV1x2or3 is a cluster definition for version 1.2.0 or 1.3.0
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionV1x2or3 {
    /// Name is a human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Operators define the charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<OperatorV1X2OrLater>,
    /// UUID is a human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Version is the schema version of this definition. Max 16 chars.
    pub version: String,
    /// Timestamp is the human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// NumValidators is the number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// FeeRecipientAddress is the address of the fee recipient for the
    /// validator.
    pub fee_recipient_address: String,
    /// WithdrawalAddress is the address of the withdrawal address for the
    /// validator.
    pub withdrawal_address: String,
    /// DKGAlgorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// ForkVersion defines the cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    #[serde_as(as = "EthHex")]
    pub fork_version: Vec<u8>,
    /// ConfigHash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub config_hash: Vec<u8>,
    /// DefinitionHash uniquely identifies a cluster definition including
    /// operator ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub definition_hash: Vec<u8>,
}

impl TryFrom<Definition> for DefinitionV1x2or3 {
    type Error = DefinitionError;

    fn try_from(definition: Definition) -> Result<Self, Self::Error> {
        let validator_addresses = definition.legacy_validator_addresses()?;

        Ok(Self {
            name: definition.name,
            operators: definition
                .operators
                .into_iter()
                .map(OperatorV1X2OrLater::from)
                .collect(),
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            fee_recipient_address: validator_addresses.fee_recipient_address,
            withdrawal_address: validator_addresses.withdrawal_address,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        })
    }
}

impl TryFrom<DefinitionV1x2or3> for Definition {
    type Error = DefinitionError;

    fn try_from(definition: DefinitionV1x2or3) -> Result<Self, Self::Error> {
        let validator_addresses = ValidatorAddresses {
            fee_recipient_address: definition.fee_recipient_address,
            withdrawal_address: definition.withdrawal_address,
        };

        let validator_addresses =
            repeat_v_addresses(validator_addresses, definition.num_validators);

        Ok(Self {
            name: definition.name,
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            operators: definition
                .operators
                .into_iter()
                .map(Operator::from)
                .collect(),
            creator: Creator::default(),
            validator_addresses,
            deposit_amounts: Vec::new(),
            consensus_protocol: String::new(),
            target_gas_limit: 0,
            compounding: false,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        })
    }
}

/// DefinitionV1x4 is a cluster definition for version 1.4.0
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionV1x4 {
    /// Name is a human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Creator identifies the creator of a cluster definition. They may also be
    /// an operator.
    pub creator: Creator,
    /// Operators define the charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<OperatorV1X2OrLater>,
    /// UUID is a human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Version is the schema version of this definition. Max 16 chars.
    pub version: String,
    /// Timestamp is the human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// NumValidators is the number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// FeeRecipientAddress is the address of the fee recipient for the
    /// validator.
    pub fee_recipient_address: String,
    /// WithdrawalAddress is the address of the withdrawal address for the
    /// validator.
    pub withdrawal_address: String,
    /// DKGAlgorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// ForkVersion defines the cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    #[serde_as(as = "EthHex")]
    pub fork_version: Vec<u8>,
    /// ConfigHash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub config_hash: Vec<u8>,
    /// DefinitionHash uniquely identifies a cluster definition including
    /// operator ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub definition_hash: Vec<u8>,
}

impl TryFrom<Definition> for DefinitionV1x4 {
    type Error = DefinitionError;

    fn try_from(definition: Definition) -> Result<Self, Self::Error> {
        let validator_addresses = definition.legacy_validator_addresses()?;

        Ok(Self {
            name: definition.name,
            creator: definition.creator,
            operators: definition
                .operators
                .into_iter()
                .map(OperatorV1X2OrLater::from)
                .collect(),
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            fee_recipient_address: validator_addresses.fee_recipient_address,
            withdrawal_address: validator_addresses.withdrawal_address,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        })
    }
}

impl TryFrom<DefinitionV1x4> for Definition {
    type Error = DefinitionError;

    fn try_from(definition: DefinitionV1x4) -> Result<Self, Self::Error> {
        let validator_addresses = ValidatorAddresses {
            fee_recipient_address: definition.fee_recipient_address,
            withdrawal_address: definition.withdrawal_address,
        };

        let validator_addresses =
            repeat_v_addresses(validator_addresses, definition.num_validators);

        Ok(Self {
            name: definition.name,
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            operators: definition
                .operators
                .into_iter()
                .map(Operator::from)
                .collect(),
            creator: definition.creator,
            validator_addresses,
            deposit_amounts: Vec::new(),
            consensus_protocol: String::new(),
            target_gas_limit: 0,
            compounding: false,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        })
    }
}

/// DefinitionV1x5 is a cluster definition for version 1.5.0-1.7.0
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionV1x5to7 {
    /// Name is a human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Creator identifies the creator of a cluster definition. They may also be
    /// an operator.
    pub creator: Creator,
    /// Operators define the charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<OperatorV1X2OrLater>,
    /// UUID is a human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Version is the schema version of this definition. Max 16 chars.
    pub version: String,
    /// Timestamp is the human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// NumValidators is the number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// ValidatorAddresses define addresses of each validator.
    #[serde(rename = "validators")]
    pub validator_addresses: Vec<ValidatorAddresses>,
    /// DKGAlgorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// ForkVersion defines the cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    #[serde_as(as = "EthHex")]
    pub fork_version: Vec<u8>,
    /// ConfigHash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub config_hash: Vec<u8>,
    /// DefinitionHash uniquely identifies a cluster definition including
    /// operator ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub definition_hash: Vec<u8>,
}

impl From<Definition> for DefinitionV1x5to7 {
    fn from(definition: Definition) -> Self {
        Self {
            name: definition.name,
            creator: definition.creator,
            operators: definition
                .operators
                .into_iter()
                .map(OperatorV1X2OrLater::from)
                .collect(),
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            validator_addresses: definition.validator_addresses,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        }
    }
}

impl From<DefinitionV1x5to7> for Definition {
    fn from(definition: DefinitionV1x5to7) -> Self {
        Self {
            name: definition.name,
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            operators: definition
                .operators
                .into_iter()
                .map(Operator::from)
                .collect(),
            creator: definition.creator,
            validator_addresses: definition.validator_addresses,
            deposit_amounts: Vec::new(),
            consensus_protocol: String::new(),
            target_gas_limit: 0,
            compounding: false,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        }
    }
}

/// DefinitionV1x8 is a cluster definition for version 1.8.0
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionV1x8 {
    /// Name is a human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Creator identifies the creator of a cluster definition. They may also be
    /// an operator.
    pub creator: Creator,
    /// Operators define the charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<OperatorV1X2OrLater>,
    /// UUID is a human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Version is the schema version of this definition. Max 16 chars.
    pub version: String,
    /// Timestamp is the human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// NumValidators is the number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// ValidatorAddresses define addresses of each validator.
    #[serde(rename = "validators")]
    pub validator_addresses: Vec<ValidatorAddresses>,
    /// DKGAlgorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// ForkVersion defines the cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    #[serde_as(as = "EthHex")]
    pub fork_version: Vec<u8>,
    /// DepositAmounts specifies partial deposit amounts that sum up to at least
    /// 32ETH.
    #[serde_as(as = "Vec<PickFirst<(DisplayFromStr, _)>>")]
    pub deposit_amounts: Vec<u64>,
    /// ConfigHash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub config_hash: Vec<u8>,
    /// DefinitionHash uniquely identifies a cluster definition including
    /// operator ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub definition_hash: Vec<u8>,
}

impl From<Definition> for DefinitionV1x8 {
    fn from(definition: Definition) -> Self {
        Self {
            name: definition.name,
            creator: definition.creator,
            operators: definition
                .operators
                .into_iter()
                .map(OperatorV1X2OrLater::from)
                .collect(),
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            validator_addresses: definition.validator_addresses,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            deposit_amounts: definition.deposit_amounts,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        }
    }
}

impl From<DefinitionV1x8> for Definition {
    fn from(definition: DefinitionV1x8) -> Self {
        Self {
            name: definition.name,
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            operators: definition
                .operators
                .into_iter()
                .map(Operator::from)
                .collect(),
            creator: definition.creator,
            validator_addresses: definition.validator_addresses,
            deposit_amounts: definition.deposit_amounts,
            consensus_protocol: String::new(),
            target_gas_limit: 0,
            compounding: false,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        }
    }
}

/// DefinitionV1x9 is a cluster definition for version 1.9.0
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionV1x9 {
    /// Name is a human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Creator identifies the creator of a cluster definition. They may also be
    /// an operator.
    pub creator: Creator,
    /// Operators define the charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<OperatorV1X2OrLater>,
    /// UUID is a human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Version is the schema version of this definition. Max 16 chars.
    pub version: String,
    /// Timestamp is the human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// NumValidators is the number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// ValidatorAddresses define addresses of each validator.
    #[serde(rename = "validators")]
    pub validator_addresses: Vec<ValidatorAddresses>,
    /// DKGAlgorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// ForkVersion defines the cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    #[serde_as(as = "EthHex")]
    pub fork_version: Vec<u8>,
    /// DepositAmounts specifies partial deposit amounts that sum up to at least
    /// 32ETH.
    #[serde_as(as = "Vec<PickFirst<(DisplayFromStr, _)>>")]
    pub deposit_amounts: Vec<u64>,
    /// ConsensusProtocol is the consensus protocol name preferred by the
    /// cluster, e.g. "abft".
    pub consensus_protocol: String,
    /// ConfigHash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub config_hash: Vec<u8>,
    /// DefinitionHash uniquely identifies a cluster definition including
    /// operator ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub definition_hash: Vec<u8>,
}

impl From<Definition> for DefinitionV1x9 {
    fn from(definition: Definition) -> Self {
        Self {
            name: definition.name,
            creator: definition.creator,
            operators: definition
                .operators
                .into_iter()
                .map(OperatorV1X2OrLater::from)
                .collect(),
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            validator_addresses: definition.validator_addresses,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            deposit_amounts: definition.deposit_amounts,
            consensus_protocol: definition.consensus_protocol,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        }
    }
}

impl From<DefinitionV1x9> for Definition {
    fn from(definition: DefinitionV1x9) -> Self {
        Self {
            name: definition.name,
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            operators: definition
                .operators
                .into_iter()
                .map(Operator::from)
                .collect(),
            creator: definition.creator,
            validator_addresses: definition.validator_addresses,
            deposit_amounts: definition.deposit_amounts,
            consensus_protocol: definition.consensus_protocol,
            target_gas_limit: 0,
            compounding: false,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        }
    }
}

/// DefinitionV1x10 is a cluster definition for version 1.10.0
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionV1x10 {
    /// Name is a human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Creator identifies the creator of a cluster definition. They may also be
    /// an operator.
    pub creator: Creator,
    /// Operators define the charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<OperatorV1X2OrLater>,
    /// UUID is a human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Version is the schema version of this definition. Max 16 chars.
    pub version: String,
    /// Timestamp is the human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// NumValidators is the number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// ValidatorAddresses define addresses of each validator.
    #[serde(rename = "validators")]
    pub validator_addresses: Vec<ValidatorAddresses>,
    /// DKGAlgorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// ForkVersion defines the cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    #[serde_as(as = "EthHex")]
    pub fork_version: Vec<u8>,
    /// DepositAmounts specifies partial deposit amounts that sum up to at least
    /// 32ETH.
    #[serde_as(as = "Vec<PickFirst<(DisplayFromStr, _)>>")]
    pub deposit_amounts: Vec<u64>,
    /// ConsensusProtocol is the consensus protocol name preferred by the
    /// cluster, e.g. "abft".
    pub consensus_protocol: String,
    /// TargetGasLimit is the target block gas limit for the cluster.
    pub target_gas_limit: u64,
    /// Compounding flag enables compounding rewards for validators by using
    /// 0x02 withdrawal credentials.
    pub compounding: bool,
    /// ConfigHash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub config_hash: Vec<u8>,
    /// DefinitionHash uniquely identifies a cluster definition including
    /// operator ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub definition_hash: Vec<u8>,
}

impl From<Definition> for DefinitionV1x10 {
    fn from(definition: Definition) -> Self {
        Self {
            name: definition.name,
            creator: definition.creator,
            operators: definition
                .operators
                .into_iter()
                .map(OperatorV1X2OrLater::from)
                .collect(),
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            validator_addresses: definition.validator_addresses,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            deposit_amounts: definition.deposit_amounts,
            consensus_protocol: definition.consensus_protocol,
            target_gas_limit: definition.target_gas_limit,
            compounding: definition.compounding,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        }
    }
}

impl From<DefinitionV1x10> for Definition {
    fn from(definition: DefinitionV1x10) -> Self {
        Self {
            name: definition.name,
            creator: definition.creator,
            operators: definition
                .operators
                .into_iter()
                .map(Operator::from)
                .collect(),
            uuid: definition.uuid,
            version: definition.version,
            timestamp: definition.timestamp,
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            dkg_algorithm: definition.dkg_algorithm,
            fork_version: definition.fork_version,
            validator_addresses: definition.validator_addresses,
            deposit_amounts: definition.deposit_amounts,
            consensus_protocol: definition.consensus_protocol,
            target_gas_limit: definition.target_gas_limit,
            compounding: definition.compounding,
            config_hash: definition.config_hash,
            definition_hash: definition.definition_hash,
        }
    }
}

fn repeat_v_addresses(addr: ValidatorAddresses, num_validators: u64) -> Vec<ValidatorAddresses> {
    let mut validator_addresses = Vec::new();
    for _ in 0..num_validators {
        validator_addresses.push(addr.clone());
    }
    validator_addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_definition_v1_10_0_fields() {
        let definition = serde_json::from_str::<Definition>(include_str!(
            "testdata/cluster_definition_v1_10_0.json"
        ))
        .unwrap();

        // Verify basic metadata
        assert_eq!(definition.name, "test definition");
        assert_eq!(definition.version, "v1.10.0");
        assert_eq!(
            definition.uuid.to_string().to_uppercase(),
            "0194FDC2-FA2F-4CC0-81D3-FF12045B73C8"
        );
        assert_eq!(definition.num_validators, 2);
        assert_eq!(definition.threshold, 3);
        assert_eq!(definition.dkg_algorithm, "default");

        // Verify creator
        assert_eq!(
            definition.creator.address,
            "0x6325253fec738dd7a9e28bf921119c160f070244"
        );
        assert_eq!(
            definition.creator.config_signature,
            hex::decode("0bf5059875921e668a5bdf2c7fc4844592d2572bcd0668d2d6c52f5054e2d0836bf84c7174cb7476364cc3dbd968b0f7172ed85794bb358b0c3b525da1786f9f1c").unwrap()
        );

        // Verify operators
        assert_eq!(definition.operators.len(), 2);
        assert_eq!(
            definition.operators[0].address,
            "0x094279db1944ebd7a19d0f7bbacbe0255aa5b7d4"
        );
        assert_eq!(
            definition.operators[0].enr,
            "enr://b0223beea5f4f74391f445d15afd4294040374f6924b98cbf8713f8d962d7c8d"
        );
        assert_eq!(
            definition.operators[0].config_signature,
            hex::decode("019192c24224e2cafccae3a61fb586b14323a6bc8f9e7df1d929333ff993933bea6f5b3af6de0374366c4719e43a1b067d89bc7f01f1f573981659a44ff17a4c1c").unwrap()
        );
        assert_eq!(
            definition.operators[0].enr_signature,
            hex::decode("15a3b539eb1e5849c6077dbb5722f5717a289a266f97647981998ebea89c0b4b373970115e82ed6f4125c8fa7311e4d7defa922daae7786667f7e936cd4f24ab1c").unwrap()
        );
        assert_eq!(
            definition.operators[1].address,
            "0xdf866baa56038367ad6145de1ee8f4a8b0993ebd"
        );
        assert_eq!(
            definition.operators[1].enr,
            "enr://e56a156a8de563afa467d49dec6a40e9a1d007f033c2823061bdd0eaa59f8e4d"
        );
        assert_eq!(
            definition.operators[1].config_signature,
            hex::decode("a6430105220d0b29688b734b8ea0f3ca9936e8461f10d77c96ea80a7a665f606f6a63b7f3dfd2567c18979e4d60f26686d9bf2fb26c901ff354cde1607ee294b1b").unwrap()
        );
        assert_eq!(
            definition.operators[1].enr_signature,
            hex::decode("f32b7c7822ba64f84ab43ca0c6e6b91c1fd3be8990434179d3af4491a369012db92d184fc39d1734ff5716428953bb6865fcf92b0c3a17c9028be9914eb7649c1c").unwrap()
        );

        // Verify validator addresses
        assert_eq!(definition.validator_addresses.len(), 2);
        assert_eq!(
            definition.validator_addresses[0].fee_recipient_address,
            "0x52fdfc072182654f163f5f0f9a621d729566c74d"
        );
        assert_eq!(
            definition.validator_addresses[0].withdrawal_address,
            "0x81855ad8681d0d86d1e91e00167939cb6694d2c4"
        );
        assert_eq!(
            definition.validator_addresses[1].fee_recipient_address,
            "0xeb9d18a44784045d87f3c67cf22746e995af5a25"
        );
        assert_eq!(
            definition.validator_addresses[1].withdrawal_address,
            "0x5fb90badb37c5821b6d95526a41a9504680b4e7c"
        );

        // Verify deposit amounts
        assert_eq!(definition.deposit_amounts.len(), 2);
        assert_eq!(definition.deposit_amounts[0], 16000000000);
        assert_eq!(definition.deposit_amounts[1], 16000000000);

        // Verify v1.10.0 specific fields
        assert_eq!(definition.consensus_protocol, "abft");
        assert_eq!(definition.target_gas_limit, 30000000);
        assert!(!definition.compounding);

        // Verify hashes are present
        assert_eq!(
            definition.config_hash,
            hex::decode("19f6e5753f05c9b662b54959fbe5b0c265d6f571ea414310b84c5fe2e0851f61")
                .unwrap()
        );
        assert_eq!(
            definition.definition_hash,
            hex::decode("59a8d3ffa9010f54965a11248e2835e716049d508f4f64bf43bd5a6ca56037c0")
                .unwrap()
        );
    }

    #[test]
    fn test_cluster_definition_v1_0_0() {
        let json_str = include_str!("testdata/cluster_definition_v1_0_0.json");

        let _ = serde_json::from_str::<DefinitionV1x0or1>(json_str).unwrap();

        let _ = serde_json::from_str::<Definition>(json_str).unwrap();
    }

    #[test]
    fn test_cluster_definition_v1_1_0() {
        let json_str = include_str!("testdata/cluster_definition_v1_1_0.json");

        let _ = serde_json::from_str::<DefinitionV1x0or1>(json_str).unwrap();

        let _ = serde_json::from_str::<Definition>(json_str).unwrap();
    }

    #[test]
    fn test_cluster_definition_v1_2_0() {
        let json_str = include_str!("testdata/cluster_definition_v1_2_0.json");

        let _ = serde_json::from_str::<DefinitionV1x2or3>(json_str).unwrap();

        let _ = serde_json::from_str::<Definition>(json_str).unwrap();
    }

    #[test]
    fn test_cluster_definition_v1_3_0() {
        let json_str = include_str!("testdata/cluster_definition_v1_3_0.json");

        let _ = serde_json::from_str::<DefinitionV1x2or3>(json_str).unwrap();

        let _ = serde_json::from_str::<Definition>(json_str).unwrap();
    }

    #[test]
    fn test_cluster_definition_v1_4_0() {
        let json_str = include_str!("testdata/cluster_definition_v1_4_0.json");

        let _ = serde_json::from_str::<DefinitionV1x4>(json_str).unwrap();

        let _ = serde_json::from_str::<Definition>(json_str).unwrap();
    }

    #[test]
    fn test_cluster_definition_v1_5_0() {
        let json_str = include_str!("testdata/cluster_definition_v1_5_0.json");

        let _ = serde_json::from_str::<DefinitionV1x5to7>(json_str).unwrap();

        let _ = serde_json::from_str::<Definition>(json_str).unwrap();
    }

    #[test]
    fn test_cluster_definition_v1_6_0() {
        let json_str = include_str!("testdata/cluster_definition_v1_6_0.json");

        let _ = serde_json::from_str::<DefinitionV1x5to7>(json_str).unwrap();

        let _ = serde_json::from_str::<Definition>(json_str).unwrap();
    }

    #[test]
    fn test_cluster_definition_v1_7_0() {
        let json_str = include_str!("testdata/cluster_definition_v1_7_0.json");

        let _ = serde_json::from_str::<DefinitionV1x5to7>(json_str).unwrap();

        let _ = serde_json::from_str::<Definition>(json_str).unwrap();
    }

    #[test]
    fn test_cluster_definition_v1_8_0() {
        let json_str = include_str!("testdata/cluster_definition_v1_8_0.json");

        let _ = serde_json::from_str::<DefinitionV1x8>(json_str).unwrap();

        let _ = serde_json::from_str::<Definition>(json_str).unwrap();
    }

    #[test]
    fn test_cluster_definition_v1_9_0() {
        let json_str = include_str!("testdata/cluster_definition_v1_9_0.json");

        let _ = serde_json::from_str::<DefinitionV1x9>(json_str).unwrap();

        let _ = serde_json::from_str::<Definition>(json_str).unwrap();
    }

    #[test]
    fn test_cluster_definition_v1_10_0() {
        let json_str = include_str!("testdata/cluster_definition_v1_10_0.json");

        let _ = serde_json::from_str::<DefinitionV1x10>(json_str).unwrap();

        let _ = serde_json::from_str::<Definition>(json_str).unwrap();
    }

    // test incorrect version
    #[test]
    fn test_cluster_definition_incorrect_version() {
        let json_str = include_str!("testdata/cluster_definition_incorrect_version.json");

        let result = serde_json::from_str::<Definition>(json_str);
        assert!(result.is_err());
    }
}
