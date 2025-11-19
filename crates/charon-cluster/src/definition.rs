use std::collections::HashSet;

use crate::{
    helpers::{EthHex, from_0x_hex_str},
    operator::{Operator, OperatorSSZ, OperatorV1X1, OperatorV1X2OrLater},
    version::{CURRENT_VERSION, DKG_ALGO, versions::*},
};
use charon_eth2::enr::{Record, RecordError};
use charon_p2p::peer::{Peer, PeerError};
use chrono::{DateTime, Utc};
use libp2p::PeerId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{
    DisplayFromStr, PickFirst,
    base64::{Base64, Standard},
    serde_as,
};
use ssz_derive::{Decode, Encode};
use uuid::Uuid;

/// Length of the fork version in bytes.
pub const FORK_VERSION_LEN: usize = 4;

/// Length of the address in bytes.
pub const ADDRESS_LEN: usize = 20;

/// NodeIdx represents the index of a node/peer/share in the cluster as operator
/// order in cluster definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdx {
    /// Index of a peer in the peer list (it's 0-indexed).
    pub peer_idx: usize,
    /// tbls share identifier (it is 1-indexed).
    pub share_idx: usize,
}

/// Definition defines an intended charon cluster configuration excluding
/// validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// Human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Schema version of this definition. Max 16 chars.
    pub version: String,
    /// Human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// Number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// DKG algorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// Cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    pub fork_version: Vec<u8>,
    /// Charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<Operator>,
    /// Creator identifies the creator of a cluster definition. They may also be
    /// an operator.
    pub creator: Creator,
    /// Addresses of each validator.
    pub validator_addresses: Vec<ValidatorAddresses>,
    /// Partial deposit amounts that sum up to at least
    /// 32ETH.
    pub deposit_amounts: Vec<u64>,
    /// Consensus protocol name preferred by the
    /// cluster, e.g. "abft".
    pub consensus_protocol: String,
    /// Target block gas limit for the cluster.
    pub target_gas_limit: u64,
    /// Compounding flag enables compounding rewards for validators by using
    /// 0x02 withdrawal credentials.
    pub compounding: bool,
    /// Config hash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    pub config_hash: Vec<u8>,
    /// Definition hash uniquely identifies a cluster definition including
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
    /// Multiple withdrawal or fee recipient addresses found
    /// are found.
    #[error("Multiple withdrawal or fee recipient addresses found")]
    InvalidValidatorAddresses,

    /// Insufficient fee-recipient addresses
    #[error("Insufficient fee-recipient addresses")]
    InsufficientFeeRecipientAddresses,

    /// Insufficient withdrawal addresses
    #[error("Insufficient withdrawal addresses")]
    InsufficientWithdrawalAddresses,

    /// Failed to convert length
    #[error("Failed to convert length")]
    FailedToConvertLength,

    /// Failed to convert hex string
    #[error("Failed to convert hex string")]
    FailedToConvertHexString(#[from] hex::FromHexError),

    /// Invalid target gas limit
    #[error("Invalid target gas limit: {0}")]
    InvalidTargetGasLimit(#[from] InvalidGasLimitError),

    /// Invalid deposit amounts
    #[error("Invalid deposit amounts: the version does not support partial deposits")]
    InvalidDepositAmounts,

    /// Invalid compounding
    #[error("Invalid compounding: the version does not support compounding")]
    InvalidCompounding,

    /// Peer not found
    #[error("Peer not in definition: {peer_id}")]
    PeerNotFound {
        /// The peer ID
        peer_id: PeerId,
    },

    /// Duplicate peer ENRs
    #[error("Duplicate peer ENRs: {0}")]
    DuplicatePeerENRs(String),

    /// Failed to parse ENR
    #[error("Failed to parse ENR: {0}")]
    FailedToParseENR(#[from] RecordError),

    /// Failed to create peer
    #[error("Failed to create peer: {0}")]
    FailedToCreatePeer(#[from] PeerError),
}

/// InvalidGasLimitError is an error type for invalid gas limit errors.
#[derive(Debug, thiserror::Error)]
pub enum InvalidGasLimitError {
    /// The version does not support custom target gas limit
    #[error("the version does not support custom target gas limit")]
    VersionDoesNotSupportCustomTargetGasLimit,

    /// The gas limit is not set
    #[error("target gas limit should be set")]
    GasLimitNotSet,
}

impl Definition {
    /// Create a new cluster definition.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        num_validators: u64,
        threshold: u64,
        fee_recipient_addresses: Vec<String>,
        withdrawal_addresses: Vec<String>,
        fork_version_hex: String,
        creator: Creator,
        operators: Vec<Operator>,
        deposit_amounts: Vec<u64>,
        consensus_protocol: String,
        target_gas_limit: u64,
        compounding: bool,
        opts: Vec<fn(&mut Self) -> Self>,
    ) -> Result<Self, DefinitionError> {
        if u64::try_from(fee_recipient_addresses.len())
            .map_err(|_| DefinitionError::FailedToConvertLength)?
            != num_validators
        {
            return Err(DefinitionError::InsufficientFeeRecipientAddresses);
        }

        if u64::try_from(withdrawal_addresses.len())
            .map_err(|_| DefinitionError::FailedToConvertLength)?
            != num_validators
        {
            return Err(DefinitionError::InsufficientWithdrawalAddresses);
        }

        let uuid = Uuid::new_v4();

        let mut def = Definition {
            uuid,
            name,
            version: CURRENT_VERSION.to_string(),
            timestamp: Utc::now(),
            num_validators,
            threshold,
            dkg_algorithm: DKG_ALGO.to_string(),
            fork_version: Default::default(),
            operators,
            creator,
            validator_addresses: Vec::new(),
            deposit_amounts,
            consensus_protocol,
            target_gas_limit,
            compounding,
            config_hash: Default::default(),
            definition_hash: Default::default(),
        };

        def.validator_addresses = fee_recipient_addresses
            .into_iter()
            .enumerate()
            .map(|(i, address)| ValidatorAddresses {
                fee_recipient_address: address,
                withdrawal_address: withdrawal_addresses[i].clone(),
            })
            .collect();

        def.fork_version = from_0x_hex_str(&fork_version_hex, FORK_VERSION_LEN)?;

        for opt in opts {
            opt(&mut def);
        }

        if def.deposit_amounts.len() > 1 && !Self::support_partial_deposits(&def.version) {
            return Err(DefinitionError::InvalidDepositAmounts);
        }

        if def.target_gas_limit != 0 && !Self::support_target_gas_limit(&def.version) {
            return Err(InvalidGasLimitError::VersionDoesNotSupportCustomTargetGasLimit.into());
        }

        if def.compounding && !Self::support_compounding(&def.version) {
            return Err(DefinitionError::InvalidCompounding);
        }

        if def.target_gas_limit == 0 && Self::support_target_gas_limit(&def.version) {
            return Err(InvalidGasLimitError::GasLimitNotSet.into());
        }

        // TODO: Construct and return a Definition. Placeholder for now.
        def.set_definition_hashes()
    }

    /// Returns the node index for a given peer ID.
    pub fn node_idx(&self, pid: &PeerId) -> Result<NodeIdx, DefinitionError> {
        let peers = self.peers()?;

        for (i, peer) in peers.iter().enumerate() {
            if peer.id == *pid {
                return Ok(NodeIdx {
                    peer_idx: i,
                    share_idx: peer.share_idx(),
                });
            }
        }

        Err(DefinitionError::PeerNotFound { peer_id: *pid })
    }

    /// VerifySignatures returns nil if all config signatures are fully
    /// populated and valid. A verified definition is ready for use in DKG.
    pub fn verify_signatures(&self) -> Result<(), DefinitionError> {
        todo!("implement this after eth1wrap.EthClientRunner is implemented");
    }

    /// Returns the peers in the cluster.
    pub fn peers(&self) -> Result<Vec<Peer>, DefinitionError> {
        let mut peers = Vec::new();

        let mut dedup: HashSet<String> = HashSet::new();

        for (i, operator) in self.operators.iter().enumerate() {
            if dedup.contains(&operator.enr) {
                return Err(DefinitionError::DuplicatePeerENRs(operator.enr.clone()));
            }

            dedup.insert(operator.enr.clone());

            let enr = Record::try_from(operator.enr.as_str())?;

            let peer = Peer::from_enr(&enr, i)?;

            peers.push(peer);
        }

        Ok(peers)
    }

    /// `peer_ids` is a convenience function that returns the operators p2p peer
    /// IDs.
    pub fn peer_ids(&self) -> Result<Vec<PeerId>, DefinitionError> {
        let peers = self.peers()?;
        Ok(peers.iter().map(|p| p.id).collect())
    }

    /// Legacy single withdrawal and single
    /// fee recipient addresses or an error if multiple addresses are found.
    pub fn legacy_validator_addresses(&self) -> Result<ValidatorAddresses, DefinitionError> {
        let mut result_validator_addresses = ValidatorAddresses::default();

        for (i, validator_addresses) in self.validator_addresses.iter().enumerate() {
            if i == 0 {
                result_validator_addresses = validator_addresses.clone();
            } else if validator_addresses != &result_validator_addresses {
                return Err(DefinitionError::InvalidValidatorAddresses);
            }
        }

        Ok(result_validator_addresses)
    }

    /// `withdrawal_addresses` is a convenience function to return all
    /// withdrawal address from the validator addresses slice.
    pub fn withdrawal_addresses(&self) -> Vec<String> {
        self.validator_addresses
            .iter()
            .map(|v| v.withdrawal_address.clone())
            .collect()
    }

    /// `fee_recipient_addresses` is a convenience function to return all fee
    /// recipient address from the validator addresses slice.
    pub fn fee_recipient_addresses(&self) -> Vec<String> {
        self.validator_addresses
            .iter()
            .map(|v| v.fee_recipient_address.clone())
            .collect()
    }

    /// Sets the definition hashes.
    pub fn set_definition_hashes(self) -> Result<Self, DefinitionError> {
        // todo
        Ok(self)
    }

    /// `verify_hashes` returns an error if hashes populated from json object
    /// doesn't matches actual hashes.
    pub fn verify_hashes(self) -> Result<Self, DefinitionError> {
        // todo
        Ok(self)
    }

    /// Returns true if the provided definition version supports EIP712
    /// signatures. Note that Definition versions prior to v1.3.0 don't
    /// support EIP712 signatures.
    pub(crate) fn support_eip712_sigs(version: &str) -> bool {
        !matches!(version, V1_0 | V1_1 | V1_2)
    }

    /// Returns true if the provided definition version supports partial
    /// deposits.
    fn support_partial_deposits(version: &str) -> bool {
        !matches!(
            version,
            V1_0 | V1_1 | V1_2 | V1_3 | V1_4 | V1_5 | V1_6 | V1_7
        )
    }

    /// Returns true if the provided definition version supports custom target
    /// gas limit.
    fn support_target_gas_limit(version: &str) -> bool {
        !matches!(
            version,
            V1_0 | V1_1 | V1_2 | V1_3 | V1_4 | V1_5 | V1_6 | V1_7 | V1_8 | V1_9
        )
    }

    /// Returns true if the provided definition version supports compounding.
    fn support_compounding(version: &str) -> bool {
        !matches!(
            version,
            V1_0 | V1_1 | V1_2 | V1_3 | V1_4 | V1_5 | V1_6 | V1_7 | V1_8 | V1_9
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub(crate) struct DefinitionSSZ {
    /// Human-readable random unique identifier. Max 64 chars.
    pub uuid: Vec<u8>,
    /// Human-readable cosmetic identifier. Max 256 chars.
    pub name: Vec<u8>,
    /// Schema version of this definition. Max 16 chars.
    pub version: Vec<u8>,
    /// Human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: Vec<u8>,
    /// Number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// DKG algorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: Vec<u8>,
    /// Cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    pub fork_version: [u8; 4],
    /// Charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<OperatorSSZ>,
    /// Creator identifies the creator of a cluster definition. They may also be
    /// an operator.
    pub creator: CreatorSSZ,
    /// Addresses of each validator.
    pub validator_addresses: Vec<ValidatorAddressesSSZ>,
    /// Partial deposit amounts that sum up to at least
    /// 32ETH.
    /// todo: check type
    pub deposit_amounts: Vec<u64>,
    /// Consensus protocol name preferred by the
    /// cluster, e.g. "abft".
    pub consensus_protocol: Vec<u8>,
    /// Target block gas limit for the cluster.
    pub target_gas_limit: u64,
    /// Compounding flag enables compounding rewards for validators by using
    /// 0x02 withdrawal credentials.
    pub compounding: bool,
    /// Config hash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    pub config_hash: [u8; 32],
    /// Definition hash uniquely identifies a cluster definition including
    /// operator ENRs and signatures.
    pub definition_hash: [u8; 32],
}

impl From<Definition> for DefinitionSSZ {
    fn from(definition: Definition) -> Self {
        Self {
            uuid: definition.uuid.to_string().as_bytes().to_vec(),
            name: definition.name.as_bytes().to_vec(),
            version: definition.version.as_bytes().to_vec(),
            timestamp: definition.timestamp.timestamp().to_be_bytes().to_vec(),
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            dkg_algorithm: definition.dkg_algorithm.as_bytes().to_vec(),
            fork_version: definition.fork_version.try_into().unwrap(),
            operators: definition
                .operators
                .into_iter()
                .map(OperatorSSZ::from)
                .collect(),
            creator: CreatorSSZ::from(definition.creator),
            validator_addresses: definition
                .validator_addresses
                .into_iter()
                .map(ValidatorAddressesSSZ::from)
                .collect(),
            deposit_amounts: definition.deposit_amounts,
            consensus_protocol: definition.consensus_protocol.as_bytes().to_vec(),
            target_gas_limit: definition.target_gas_limit,
            compounding: definition.compounding,
            config_hash: definition.config_hash.try_into().unwrap(),
            definition_hash: definition.definition_hash.try_into().unwrap(),
        }
    }
}

impl TryFrom<DefinitionSSZ> for Definition {
    type Error = DefinitionError;

    fn try_from(definition: DefinitionSSZ) -> Result<Self, Self::Error> {
        Ok(Self {
            uuid: Uuid::from_slice(&definition.uuid).unwrap(),
            name: String::from_utf8(definition.name).unwrap(),
            version: String::from_utf8(definition.version).unwrap(),
            timestamp: DateTime::from_timestamp(
                i64::from_be_bytes(definition.timestamp.try_into().unwrap()),
                0,
            )
            .unwrap(),
            num_validators: definition.num_validators,
            threshold: definition.threshold,
            dkg_algorithm: String::from_utf8(definition.dkg_algorithm).unwrap(),
            fork_version: definition.fork_version.to_vec(),
            operators: definition
                .operators
                .into_iter()
                .map(Operator::try_from)
                .collect::<Result<Vec<Operator>, DefinitionError>>()
                .unwrap(),
            creator: Creator::try_from(definition.creator).unwrap(),
            validator_addresses: definition
                .validator_addresses
                .into_iter()
                .map(ValidatorAddresses::try_from)
                .collect::<Result<Vec<ValidatorAddresses>, DefinitionError>>()
                .unwrap(),
            deposit_amounts: definition.deposit_amounts,
            consensus_protocol: String::from_utf8(definition.consensus_protocol).unwrap(),
            target_gas_limit: definition.target_gas_limit,
            compounding: definition.compounding,
            config_hash: definition.config_hash.to_vec(),
            definition_hash: definition.definition_hash.to_vec(),
        })
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

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub(crate) struct CreatorSSZ {
    /// The Ethereum address of the creator
    pub address: [u8; 20],
    /// The creator's signature over the config hash
    pub config_signature: [u8; 65],
}

impl From<Creator> for CreatorSSZ {
    fn from(creator: Creator) -> Self {
        Self {
            address: creator.address.as_bytes().to_vec().try_into().unwrap(),
            config_signature: creator.config_signature.try_into().unwrap(),
        }
    }
}

impl TryFrom<CreatorSSZ> for Creator {
    type Error = DefinitionError;

    fn try_from(creator: CreatorSSZ) -> Result<Self, Self::Error> {
        Ok(Self {
            address: String::from_utf8(creator.address.to_vec()).unwrap(),
            config_signature: creator.config_signature.to_vec(),
        })
    }
}

/// Addresses for a validator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ValidatorAddresses {
    /// The fee recipient address for the validator
    pub fee_recipient_address: String,
    /// The withdrawal address for the validator
    pub withdrawal_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub(crate) struct ValidatorAddressesSSZ {
    /// The fee recipient address for the validator
    pub fee_recipient_address: [u8; 20],
    /// The withdrawal address for the validator
    pub withdrawal_address: [u8; 20],
}

impl From<ValidatorAddresses> for ValidatorAddressesSSZ {
    fn from(validator_addresses: ValidatorAddresses) -> Self {
        Self {
            fee_recipient_address: validator_addresses
                .fee_recipient_address
                .as_bytes()
                .to_vec()
                .try_into()
                .unwrap(),
            withdrawal_address: validator_addresses
                .withdrawal_address
                .as_bytes()
                .to_vec()
                .try_into()
                .unwrap(),
        }
    }
}

impl TryFrom<ValidatorAddressesSSZ> for ValidatorAddresses {
    type Error = DefinitionError;

    fn try_from(validator_addresses: ValidatorAddressesSSZ) -> Result<Self, Self::Error> {
        Ok(Self {
            fee_recipient_address: String::from_utf8(
                validator_addresses.fee_recipient_address.to_vec(),
            )
            .unwrap(),
            withdrawal_address: String::from_utf8(validator_addresses.withdrawal_address.to_vec())
                .unwrap(),
        })
    }
}

/// DefinitionV1x0or1 is a cluster definition for version 1.0.0 or 1.1.0
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionV1x0or1 {
    /// Human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<OperatorV1X1>,
    /// Human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Schema version of this definition. Max 16 chars.
    pub version: String,
    /// Human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// Number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// Fee recipient address for the
    /// validator.
    pub fee_recipient_address: String,
    /// Withdrawal address for the
    /// validator.
    pub withdrawal_address: String,
    /// DKG algorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// Cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    #[serde_as(as = "EthHex")]
    pub fork_version: Vec<u8>,
    /// Config hash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    #[serde_as(as = "Base64<Standard>")]
    pub config_hash: Vec<u8>,
    /// Definition hash uniquely identifies a cluster definition including
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
    /// Human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<OperatorV1X2OrLater>,
    /// Human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Schema version of this definition. Max 16 chars.
    pub version: String,
    /// Human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// Number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// Fee recipient address for the
    /// validator.
    pub fee_recipient_address: String,
    /// Withdrawal address for the
    /// validator.
    pub withdrawal_address: String,
    /// DKGAlgorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// Cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    #[serde_as(as = "EthHex")]
    pub fork_version: Vec<u8>,
    /// Config hash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub config_hash: Vec<u8>,
    /// Definition hash uniquely identifies a cluster definition including
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
    /// Human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Creator identifies the creator of a cluster definition. They may also be
    /// an operator.
    pub creator: Creator,
    /// Operators define the charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<OperatorV1X2OrLater>,
    /// Human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Schema version of this definition. Max 16 chars.
    pub version: String,
    /// Human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// Number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// Fee recipient address for the
    /// validator.
    pub fee_recipient_address: String,
    /// Withdrawal address for the
    /// validator.
    pub withdrawal_address: String,
    /// DKG algorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// Cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    #[serde_as(as = "EthHex")]
    pub fork_version: Vec<u8>,
    /// Config hash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub config_hash: Vec<u8>,
    /// Definition hash uniquely identifies a cluster definition including
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
    /// Human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Creator identifies the creator of a cluster definition. They may also be
    /// an operator.
    pub creator: Creator,
    /// Charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<OperatorV1X2OrLater>,
    /// Human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Schema version of this definition. Max 16 chars.
    pub version: String,
    /// Human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// Number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// Addresses of each validator.
    #[serde(rename = "validators")]
    pub validator_addresses: Vec<ValidatorAddresses>,
    /// DKG algorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// Cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    #[serde_as(as = "EthHex")]
    pub fork_version: Vec<u8>,
    /// Config hash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub config_hash: Vec<u8>,
    /// Definition hash uniquely identifies a cluster definition including
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
    /// Human-readable cosmetic identifier. Max 256 chars.
    pub name: String,
    /// Creator identifies the creator of a cluster definition. They may also be
    /// an operator.
    pub creator: Creator,
    /// Charon nodes in the cluster and their operators.
    /// Max 256 operators.
    pub operators: Vec<OperatorV1X2OrLater>,
    /// Human-readable random unique identifier. Max 64 chars.
    pub uuid: Uuid,
    /// Schema version of this definition. Max 16 chars.
    pub version: String,
    /// Human-readable timestamp of this definition. Max 32
    /// chars. Note that this was added in v1.1.0, so may be empty for older
    /// versions.
    pub timestamp: DateTime<Utc>,
    /// Number of DVs to be created in the cluster lock
    /// file.
    pub num_validators: u64,
    /// Threshold required for signature reconstruction. Defaults to safe value
    /// for number of nodes/peers.
    pub threshold: u64,
    /// Addresses of each validator.
    #[serde(rename = "validators")]
    pub validator_addresses: Vec<ValidatorAddresses>,
    /// DKG algorithm to use for key generation. Max 32 chars.
    pub dkg_algorithm: String,
    /// Cluster's 4 byte beacon chain fork version
    /// (network/chain identifier).
    #[serde_as(as = "EthHex")]
    pub fork_version: Vec<u8>,
    /// Partial deposit amounts that sum up to at least
    /// 32ETH.
    #[serde_as(as = "Vec<PickFirst<(DisplayFromStr, _)>>")]
    pub deposit_amounts: Vec<u64>,
    /// Consensus protocol name preferred by the
    /// cluster, e.g. "abft".
    pub consensus_protocol: String,
    /// Target block gas limit for the cluster.
    pub target_gas_limit: u64,
    /// Compounding flag enables compounding rewards for validators by using
    /// 0x02 withdrawal credentials.
    pub compounding: bool,
    /// Config hash uniquely identifies a cluster definition excluding operator
    /// ENRs and signatures.
    #[serde_as(as = "EthHex")]
    pub config_hash: Vec<u8>,
    /// Definition hash uniquely identifies a cluster definition including
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
