//! Types for the Charon core.

use std::{any::Any, collections::HashMap, fmt::Display, iter};

use chrono::{DateTime, Duration, Utc};
use dyn_clone::DynClone;
use dyn_eq::DynEq;
use pluto_ssz::HashRoot;
use serde::{Deserialize, Serialize};
use std::fmt::Debug as StdDebug;

use crate::{
    ParSigExCodecError,
    corepb::v1::core as pbcore,
    parsigex_codec::{deserialize_signed_data, serialize_signed_data},
    signeddata::{AttesterDuty, SignedDataError},
};

/// The type of duty.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DutyType {
    /// Unknown duty type.
    Unknown,
    /// Proposer duty type.
    Proposer,
    /// Attester duty type.
    Attester,
    /// Signature duty type.
    Signature,
    /// Exit duty type.
    Exit,
    /// Builder proposer duty type.
    BuilderProposer,
    /// Builder registration duty type.
    BuilderRegistration,
    /// Randao duty type.
    Randao,
    /// Prepare aggregator duty type.
    PrepareAggregator,
    /// Aggregator duty type.
    Aggregator,
    /// Sync message duty type.
    SyncMessage,
    /// Prepare sync contribution duty type.
    PrepareSyncContribution,
    /// Sync contribution duty type.
    SyncContribution,
    /// Info sync duty type.
    InfoSync,
    /// Duty sentinel duty type. Must always be last.
    DutySentinel(Box<DutyType>),
}

impl Display for DutyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // safe to unwrap because we know the duty type is valid
        let v = serde_json::to_value(self).expect("failed to serialize duty type");
        if let Some(s) = v.as_str() {
            write!(f, "{}", s)
        } else {
            // fallback for non-string variants (structs, numbers, etc.)
            write!(f, "{}", v)
        }
    }
}

impl DutyType {
    /// Returns true if the duty type is valid.
    pub fn is_valid(&self) -> bool {
        !matches!(self, DutyType::Unknown | DutyType::DutySentinel(_))
    }

    /// Returns true if duties of this type have no deadline (e.g. voluntary
    /// exits, builder registrations).
    pub fn never_expires(&self) -> bool {
        matches!(self, DutyType::Exit | DutyType::BuilderRegistration)
    }

    /// All valid duty types.
    pub fn all() -> [DutyType; 13] {
        [
            DutyType::Proposer,
            DutyType::Attester,
            DutyType::Signature,
            DutyType::Exit,
            DutyType::BuilderProposer,
            DutyType::BuilderRegistration,
            DutyType::Randao,
            DutyType::PrepareAggregator,
            DutyType::Aggregator,
            DutyType::SyncMessage,
            DutyType::PrepareSyncContribution,
            DutyType::SyncContribution,
            DutyType::InfoSync,
        ]
    }
}

/// Error type for duty type conversion.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DutyTypeError {
    /// Invalid duty type.
    #[error("invalid duty type")]
    InvalidDutyType,
}

impl TryFrom<&DutyType> for i32 {
    type Error = DutyTypeError;

    fn try_from(duty_type: &DutyType) -> Result<Self, Self::Error> {
        Ok(match duty_type {
            DutyType::Unknown => 0,
            DutyType::Proposer => 1,
            DutyType::Attester => 2,
            DutyType::Signature => 3,
            DutyType::Exit => 4,
            DutyType::BuilderProposer => 5,
            DutyType::BuilderRegistration => 6,
            DutyType::Randao => 7,
            DutyType::PrepareAggregator => 8,
            DutyType::Aggregator => 9,
            DutyType::SyncMessage => 10,
            DutyType::PrepareSyncContribution => 11,
            DutyType::SyncContribution => 12,
            DutyType::InfoSync => 13,
            _ => return Err(DutyTypeError::InvalidDutyType),
        })
    }
}

impl TryFrom<i32> for DutyType {
    type Error = ParSigExCodecError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DutyType::Unknown),
            1 => Ok(DutyType::Proposer),
            2 => Ok(DutyType::Attester),
            3 => Ok(DutyType::Signature),
            4 => Ok(DutyType::Exit),
            5 => Ok(DutyType::BuilderProposer),
            6 => Ok(DutyType::BuilderRegistration),
            7 => Ok(DutyType::Randao),
            8 => Ok(DutyType::PrepareAggregator),
            9 => Ok(DutyType::Aggregator),
            10 => Ok(DutyType::SyncMessage),
            11 => Ok(DutyType::PrepareSyncContribution),
            12 => Ok(DutyType::SyncContribution),
            13 => Ok(DutyType::InfoSync),
            _ => Err(ParSigExCodecError::InvalidDuty),
        }
    }
}

/// SlotNumber struct
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SlotNumber(u64);

impl Display for SlotNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for SlotNumber {
    fn from(slot: u64) -> Self {
        Self::new(slot)
    }
}

impl From<SlotNumber> for u64 {
    fn from(slot: SlotNumber) -> Self {
        slot.inner()
    }
}

impl SlotNumber {
    /// Create a new slot number.
    pub fn new(slot: u64) -> Self {
        SlotNumber(slot)
    }

    /// Inner slot number.
    pub fn inner(&self) -> u64 {
        self.0
    }

    /// Next slot number.
    pub fn next(&self) -> Self {
        Self::new(self.inner().saturating_add(1))
    }
}

/// Duty struct
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Duty {
    /// Ethereum consensus layer slot.
    pub slot: SlotNumber,
    /// Duty type performed in the slot.
    pub duty_type: DutyType,
}

impl Display for Duty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.slot, self.duty_type)
    }
}

impl Duty {
    /// Create a new duty.
    pub fn new(slot: SlotNumber, duty_type: DutyType) -> Self {
        Self { slot, duty_type }
    }

    /// Create a new attester duty.
    pub fn new_attester_duty(slot: SlotNumber) -> Self {
        Self::new(slot, DutyType::Attester)
    }

    /// Create a new randao duty.
    pub fn new_randao_duty(slot: SlotNumber) -> Self {
        Self::new(slot, DutyType::Randao)
    }

    /// Create a new voluntary exit duty.
    pub fn new_voluntary_exit_duty(slot: SlotNumber) -> Self {
        Self::new(slot, DutyType::Exit)
    }

    /// Create a new proposer duty.
    pub fn new_proposer_duty(slot: SlotNumber) -> Self {
        Self::new(slot, DutyType::Proposer)
    }

    /// Create a new builder proposer duty.
    pub fn new_builder_proposer_duty(slot: SlotNumber) -> Self {
        Self::new(slot, DutyType::BuilderProposer)
    }

    /// Create a new builder registration duty.
    pub fn new_builder_registration_duty(slot: SlotNumber) -> Self {
        Self::new(slot, DutyType::BuilderRegistration)
    }

    /// Create a new sync contribution duty.
    pub fn new_sync_contribution_duty(slot: SlotNumber) -> Self {
        Self::new(slot, DutyType::SyncContribution)
    }

    /// Create a new signature duty.
    pub fn new_signature_duty(slot: SlotNumber) -> Self {
        Self::new(slot, DutyType::Signature)
    }

    /// Create a new prepare aggregator duty.
    pub fn new_prepare_aggregator_duty(slot: SlotNumber) -> Self {
        Self::new(slot, DutyType::PrepareAggregator)
    }

    /// Create a new aggregator duty.
    pub fn new_aggregator_duty(slot: SlotNumber) -> Self {
        Self::new(slot, DutyType::Aggregator)
    }

    /// Create a new sync message duty.
    pub fn new_sync_message_duty(slot: SlotNumber) -> Self {
        Self::new(slot, DutyType::SyncMessage)
    }

    /// Create a new prepare sync contribution duty.
    pub fn new_prepare_sync_contribution_duty(slot: SlotNumber) -> Self {
        Self::new(slot, DutyType::PrepareSyncContribution)
    }

    /// Create a new info sync duty.
    pub fn new_info_sync_duty(slot: SlotNumber) -> Self {
        Self::new(slot, DutyType::InfoSync)
    }
}

impl TryFrom<&Duty> for pbcore::Duty {
    type Error = DutyTypeError;

    fn try_from(duty: &Duty) -> Result<Self, Self::Error> {
        Ok(Self {
            slot: duty.slot.inner(),
            r#type: i32::try_from(&duty.duty_type)?,
        })
    }
}

impl TryFrom<&pbcore::Duty> for Duty {
    type Error = ParSigExCodecError;

    fn try_from(duty: &pbcore::Duty) -> Result<Self, Self::Error> {
        let duty_type = DutyType::try_from(duty.r#type)?;
        if !duty_type.is_valid() {
            return Err(ParSigExCodecError::InvalidDuty);
        }

        Ok(Self::new(duty.slot.into(), duty_type))
    }
}

/// The type of proposal.
///
/// An open set: values not recognised by this binary are preserved as
/// [`ProposalType::Unknown`] rather than dropped, so cluster-agreed proposal
/// types from newer peers survive round-trips.
///
/// (De)serialized as its wire-format string via the `String` conversions below,
/// so unknown values round-trip verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum ProposalType {
    /// Full proposal type.
    Full,
    /// Builder proposal type.
    Builder,
    /// Synthetic proposal type.
    Synthetic,
    /// A proposal type not recognised by this binary, holding its raw wire
    /// string.
    Unknown(String),
}

impl ProposalType {
    /// Returns the wire-format string for this proposal type.
    ///
    /// The strings for the known variants MUST NOT change: they are exchanged
    /// on the wire (e.g. by the priority/infosync protocols) and changing
    /// them breaks compatibility.
    pub fn as_str(&self) -> &str {
        match self {
            ProposalType::Full => "full",
            ProposalType::Builder => "builder",
            ProposalType::Synthetic => "synthetic",
            ProposalType::Unknown(s) => s,
        }
    }
}

impl From<String> for ProposalType {
    /// Parses a wire string, mapping unrecognised values to
    /// [`ProposalType::Unknown`] and reusing the allocation.
    fn from(value: String) -> Self {
        match value.as_str() {
            "full" => ProposalType::Full,
            "builder" => ProposalType::Builder,
            "synthetic" => ProposalType::Synthetic,
            _ => ProposalType::Unknown(value),
        }
    }
}

impl From<&str> for ProposalType {
    fn from(value: &str) -> Self {
        ProposalType::from(value.to_owned())
    }
}

impl From<ProposalType> for String {
    /// Returns the wire-format string, reusing the [`ProposalType::Unknown`]
    /// allocation.
    fn from(value: ProposalType) -> Self {
        match value {
            ProposalType::Unknown(s) => s,
            other => other.as_str().to_owned(),
        }
    }
}

// In golang implementation they use pk_len = 98, which is 0x + [48 bytes]
// We use pk_len = 48, which is [48 bytes], the main difference is that we store
// the pub key as [u8; 48] instead of string.
// [original implementation](https://github.com/ObolNetwork/charon/blob/b3008103c5429b031b63518195f4c49db4e9a68d/core/types.go#L264)
const PK_LEN: usize = 48;

pub use pluto_crypto::types::{SIGNATURE_LENGTH, Signature};

/// Public key struct
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PubKey(pub(crate) [u8; PK_LEN]);

impl Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl TryFrom<&str> for PubKey {
    type Error = PubKeyError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value.strip_prefix("0x").unwrap_or(value);
        let hex_value = hex::decode(value).map_err(|_| PubKeyError::InvalidString)?;
        PubKey::try_from(hex_value.as_slice())
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);

        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;

        if bytes.len() != PK_LEN {
            return Err(serde::de::Error::custom(format!(
                "invalid public key length: got {}, want {}",
                bytes.len(),
                PK_LEN
            )));
        }

        let mut pk = [0u8; PK_LEN];
        pk.copy_from_slice(&bytes);
        Ok(PubKey(pk))
    }
}

impl From<[u8; PK_LEN]> for PubKey {
    fn from(pk: [u8; PK_LEN]) -> Self {
        PubKey(pk)
    }
}

/// Public key error type
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PubKeyError {
    /// Invalid public key length.
    #[error("Invalid public key length")]
    InvalidLength,

    /// Invalid public key string.
    #[error("Invalid public key string")]
    InvalidString,
}

impl PubKey {
    /// Create a new public key.
    pub fn new(pk: [u8; PK_LEN]) -> Self {
        PubKey(pk)
    }

    /// Returns logging-friendly abbreviated form: "b82_97f"
    pub fn abbreviated(&self) -> String {
        let hex = hex::encode(self.0);
        format!("{}_{}", &hex[0..3], &hex[93..96])
    }
}

impl TryFrom<&[u8]> for PubKey {
    type Error = PubKeyError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != PK_LEN {
            return Err(PubKeyError::InvalidLength);
        }
        let mut arr = [0u8; PK_LEN];
        arr.copy_from_slice(bytes);
        Ok(PubKey(arr))
    }
}

impl Display for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

/// Implement AsRef<[u8]> for PubKey to allow for easy conversion to bytes.
impl AsRef<[u8]> for PubKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Attestation duties to be performed by validators for a particular epoch.
///
/// Mirrors Charon's `core.AttesterDefinition`, which embeds the eth2
/// `v1.AttesterDuty`. Pluto's [`AttesterDuty`] omits the validator public key,
/// so it is carried alongside the embedded duty.
#[derive(Debug, Clone, PartialEq)]
pub struct AttesterDutyDefinition {
    /// The validator's BLS public key.
    pub pubkey: PubKey,
    /// The attester duty to perform.
    pub duty: AttesterDuty,
}

impl TryFrom<pluto_eth2api::types::GetAttesterDutiesResponseResponseDatum>
    for AttesterDutyDefinition
{
    type Error = pluto_eth2api::EthBeaconNodeApiClientError;

    fn try_from(
        value: pluto_eth2api::types::GetAttesterDutiesResponseResponseDatum,
    ) -> Result<Self, Self::Error> {
        let pubkey = PubKey::try_from(value.pubkey.as_str())
            .map_err(|_| pluto_eth2api::EthBeaconNodeApiClientError::ParseError("pubkey".into()))?;
        let validator_index = value.validator_index.parse::<u64>().map_err(|_| {
            pluto_eth2api::EthBeaconNodeApiClientError::ParseError("validator_index".into())
        })?;
        let slot = value
            .slot
            .parse::<u64>()
            .map_err(|_| pluto_eth2api::EthBeaconNodeApiClientError::ParseError("slot".into()))?;
        let committee_index = value.committee_index.parse::<u64>().map_err(|_| {
            pluto_eth2api::EthBeaconNodeApiClientError::ParseError("committee_index".into())
        })?;
        let committee_length = value.committee_length.parse::<u64>().map_err(|_| {
            pluto_eth2api::EthBeaconNodeApiClientError::ParseError("committee_length".into())
        })?;
        let committees_at_slot = value.committees_at_slot.parse::<u64>().map_err(|_| {
            pluto_eth2api::EthBeaconNodeApiClientError::ParseError("committees_at_slot".into())
        })?;
        let validator_committee_index =
            value
                .validator_committee_index
                .parse::<u64>()
                .map_err(|_| {
                    pluto_eth2api::EthBeaconNodeApiClientError::ParseError(
                        "validator_committee_index".into(),
                    )
                })?;

        Ok(AttesterDutyDefinition {
            pubkey,
            duty: AttesterDuty {
                slot,
                validator_index,
                committee_index,
                committee_length,
                committees_at_slot,
                validator_committee_index,
            },
        })
    }
}

/// Indicates that a validator must propose a block in a given epoch
#[derive(Debug, Clone, PartialEq)]
pub struct ProposerDutyDefinition {
    /// The validator's BLS public key
    pub pubkey: PubKey,
    ///Index of validator in validator registry.
    pub v_idx: u64,
    /// The slot at which the validator must propose a block.
    pub slot: SlotNumber,
}

impl TryFrom<pluto_eth2api::types::GetProposerDutiesResponseResponseDatum>
    for ProposerDutyDefinition
{
    type Error = pluto_eth2api::EthBeaconNodeApiClientError;

    fn try_from(
        value: pluto_eth2api::types::GetProposerDutiesResponseResponseDatum,
    ) -> Result<ProposerDutyDefinition, Self::Error> {
        let pubkey = PubKey::try_from(value.pubkey.as_str())
            .map_err(|_| pluto_eth2api::EthBeaconNodeApiClientError::ParseError("pubkey".into()))?;
        let v_idx = value.validator_index.parse::<u64>().map_err(|_| {
            pluto_eth2api::EthBeaconNodeApiClientError::ParseError("validator_index".into())
        })?;
        let slot =
            SlotNumber::from(value.slot.parse::<u64>().map_err(|_| {
                pluto_eth2api::EthBeaconNodeApiClientError::ParseError("slot".into())
            })?);

        Ok(ProposerDutyDefinition {
            pubkey,
            v_idx,
            slot,
        })
    }
}

/// Sync committee duties for a particular epoch
#[derive(Debug, Clone, PartialEq)]
pub struct SyncCommitteeDutyDefinition {
    /// The validator's BLS public key
    pub pubkey: PubKey,
    /// Index of validator in validator registry.
    pub validator_index: u64,
    /// The indices of the validator in the sync committee.
    pub validator_sync_committee_indices: Vec<u64>,
}

impl TryFrom<pluto_eth2api::types::GetSyncCommitteeDutiesResponseResponseDatum>
    for SyncCommitteeDutyDefinition
{
    type Error = pluto_eth2api::EthBeaconNodeApiClientError;

    fn try_from(
        value: pluto_eth2api::types::GetSyncCommitteeDutiesResponseResponseDatum,
    ) -> Result<Self, Self::Error> {
        let pubkey = PubKey::try_from(value.pubkey.as_str())
            .map_err(|_| pluto_eth2api::EthBeaconNodeApiClientError::ParseError("pubkey".into()))?;
        let validator_index = value.validator_index.parse::<u64>().map_err(|_| {
            pluto_eth2api::EthBeaconNodeApiClientError::ParseError("validator_index".into())
        })?;
        let validator_sync_committee_indices = value
            .validator_sync_committee_indices
            .iter()
            .map(|idx| {
                idx.parse::<u64>().map_err(|_| {
                    pluto_eth2api::EthBeaconNodeApiClientError::ParseError(
                        "validator_sync_committee_indices".into(),
                    )
                })
            })
            .collect::<Result<Vec<u64>, _>>()?;

        Ok(SyncCommitteeDutyDefinition {
            pubkey,
            validator_index,
            validator_sync_committee_indices,
        })
    }
}

/// All duty definitions for a validator in a given epoch.
#[derive(Debug, Clone, PartialEq)]
pub enum DutyDefinition {
    /// Attester duty definition.
    Attester(AttesterDutyDefinition),
    /// Proposer duty definition.
    Proposer(ProposerDutyDefinition),
    /// Sync committee duty definition.
    SyncCommittee(SyncCommitteeDutyDefinition),
}

/// A set of duty definitions for all validators in a given epoch, indexed by
/// public key.
pub type DutyDefinitionSet = HashMap<PubKey, DutyDefinition>;

/// Signed data type
pub trait SignedData: Any + DynClone + DynEq + StdDebug + Send + Sync {
    /// signature returns the signed duty data's signature.
    fn signature(&self) -> Result<Signature, SignedDataError>;

    /// Returns a copy of signed duty data with the signature replaced.
    fn set_signature(&self, signature: Signature) -> Result<Self, SignedDataError>
    where
        Self: Sized;

    /// Object-safe equivalent of [`SignedData::set_signature`].
    fn set_signature_boxed(
        &self,
        signature: Signature,
    ) -> Result<Box<dyn SignedData>, SignedDataError>;

    /// message_root returns the message root for the unsigned data.
    fn message_root(&self) -> Result<HashRoot, SignedDataError>;
}

dyn_eq::eq_trait_object!(SignedData);
dyn_clone::clone_trait_object!(SignedData);

// todo: add Eth2SignedData type
// https://github.com/ObolNetwork/charon/blob/b3008103c5429b031b63518195f4c49db4e9a68d/core/types.go#L396

/// ParSignedData is a partially signed duty data only signed by a single
/// threshold BLS share.
#[derive(Debug)]
pub struct ParSignedData {
    /// Partially signed duty data.
    pub signed_data: Box<dyn SignedData>,

    /// Threshold BLS share index.
    pub share_idx: u64,
}

impl Clone for ParSignedData {
    fn clone(&self) -> Self {
        Self {
            signed_data: self.signed_data.clone(),
            share_idx: self.share_idx,
        }
    }
}

impl PartialEq for ParSignedData {
    fn eq(&self, other: &Self) -> bool {
        self.share_idx == other.share_idx && self.signed_data == other.signed_data
    }
}

impl Eq for ParSignedData {}

impl ParSignedData {
    /// Create a new partially signed data.
    pub fn new<T: SignedData>(partially_signed_data: T, share_idx: u64) -> Self {
        Self {
            signed_data: Box::new(partially_signed_data),
            share_idx,
        }
    }

    /// Create a new partially signed data from a boxed signed data.
    pub fn new_boxed(partially_signed_data: Box<dyn SignedData>, share_idx: u64) -> Self {
        Self {
            signed_data: partially_signed_data,
            share_idx,
        }
    }
}

impl TryFrom<&ParSignedData> for pbcore::ParSignedData {
    type Error = ParSigExCodecError;

    fn try_from(data: &ParSignedData) -> Result<Self, Self::Error> {
        let encoded = serialize_signed_data(data.signed_data.as_ref())?;
        let share_idx =
            i32::try_from(data.share_idx).map_err(|_| ParSigExCodecError::InvalidShareIndex)?;
        let signature = data
            .signed_data
            .signature()
            .map_err(|err| ParSigExCodecError::InvalidSignature(err.to_string()))?;

        Ok(Self {
            data: encoded.into(),
            signature: signature.as_ref().to_vec().into(),
            share_idx,
        })
    }
}

impl TryFrom<(&DutyType, &pbcore::ParSignedData)> for ParSignedData {
    type Error = ParSigExCodecError;

    fn try_from(value: (&DutyType, &pbcore::ParSignedData)) -> Result<Self, Self::Error> {
        let (duty_type, data) = value;
        let share_idx =
            u64::try_from(data.share_idx).map_err(|_| ParSigExCodecError::InvalidShareIndex)?;
        let signed_data = deserialize_signed_data(duty_type, &data.data)?;
        Ok(Self::new_boxed(signed_data, share_idx))
    }
}

/// ParSignedDataSet is a set of partially signed duty data only signed by a
/// single threshold BLS share.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParSignedDataSet(HashMap<PubKey, ParSignedData>);

impl ParSignedDataSet {
    /// Create a new partially signed data set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a partially signed data by public key.
    pub fn get(&self, pub_key: &PubKey) -> Option<&ParSignedData> {
        self.inner().get(pub_key)
    }

    /// Insert a partially signed data.
    pub fn insert(&mut self, pub_key: PubKey, partially_signed_data: ParSignedData) {
        self.inner_mut().insert(pub_key, partially_signed_data);
    }

    /// Remove a partially signed data by public key.
    pub fn remove(&mut self, pub_key: &PubKey) -> Option<ParSignedData> {
        self.inner_mut().remove(pub_key)
    }

    /// Inner partially signed data set.
    pub fn inner(&self) -> &HashMap<PubKey, ParSignedData> {
        &self.0
    }

    /// Inner partially signed data set.
    pub fn inner_mut(&mut self) -> &mut HashMap<PubKey, ParSignedData> {
        &mut self.0
    }
}

impl TryFrom<&ParSignedDataSet> for pbcore::ParSignedDataSet {
    type Error = ParSigExCodecError;

    fn try_from(set: &ParSignedDataSet) -> Result<Self, Self::Error> {
        let mut out = std::collections::BTreeMap::new();
        for (pub_key, value) in set.inner() {
            out.insert(pub_key.to_string(), pbcore::ParSignedData::try_from(value)?);
        }

        Ok(Self { set: out })
    }
}

impl TryFrom<(&DutyType, &pbcore::ParSignedDataSet)> for ParSignedDataSet {
    type Error = ParSigExCodecError;

    fn try_from(value: (&DutyType, &pbcore::ParSignedDataSet)) -> Result<Self, Self::Error> {
        let (duty_type, set) = value;
        if set.set.is_empty() {
            return Err(ParSigExCodecError::InvalidParSignedDataSetFields);
        }

        let mut out = Self::new();
        for (pub_key, value) in &set.set {
            let pub_key = PubKey::try_from(pub_key.as_str())
                .map_err(|_| ParSigExCodecError::InvalidPubKey(pub_key.clone()))?;
            out.insert(pub_key, ParSignedData::try_from((duty_type, value))?);
        }

        Ok(out)
    }
}

/// A set of signed duty data.
pub type SignedDataSet = HashMap<PubKey, Box<dyn SignedData>>;

/// Slot struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    /// The slot number.
    pub slot: SlotNumber,

    /// The time.
    pub time: DateTime<Utc>,

    /// The slot duration.
    pub slot_duration: Duration,

    /// Slots per epoch.
    pub slots_per_epoch: u64,
}

impl Slot {
    /// Get the epoch of the slot
    pub fn epoch(&self) -> u64 {
        #[allow(clippy::arithmetic_side_effects)]
        self.slot.inner().saturating_div(self.slots_per_epoch)
    }

    /// Returns true if this is the last slot in the epoch.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn last_in_epoch(&self) -> bool {
        self.slot.inner().wrapping_rem(self.slots_per_epoch)
            == self.slots_per_epoch.saturating_sub(1)
    }

    /// Returns true if this is the first slot in the epoch.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn first_in_epoch(&self) -> bool {
        self.slot.inner().wrapping_rem(self.slots_per_epoch) == 0
    }

    /// Returns the next slot
    #[allow(clippy::arithmetic_side_effects)]
    pub fn next_slot(&self) -> Slot {
        Slot {
            slot: self.slot.next(),
            time: self.time + self.slot_duration,
            slot_duration: self.slot_duration,
            slots_per_epoch: self.slots_per_epoch,
        }
    }

    /// Returns an iterator over slots starting from this one
    pub fn iter(&self) -> impl Iterator<Item = Slot> {
        iter::successors(Some(self.clone()), |slot| Some(slot.next_slot()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pub_key_to_string() {
        const ORIGINAL_PK_LEN: usize = 98;

        let key = PubKey::new([0; PK_LEN]);

        // Check whether the string representation is the same as the go's public key
        // length
        assert_eq!(key.to_string().len(), ORIGINAL_PK_LEN);
        assert_eq!(
            key.to_string(),
            "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn new_builder_registration_duty() {
        let duty = Duty::new_builder_registration_duty(SlotNumber(1));
        assert_eq!(duty.duty_type, DutyType::BuilderRegistration);
        assert_eq!(duty.to_string(), "1/builder_registration");
        assert_eq!(u64::from(duty.slot), 1);
    }

    #[test]
    fn new_signature_duty() {
        let duty = Duty::new_signature_duty(SlotNumber(1));
        assert_eq!(duty.duty_type, DutyType::Signature);
        assert_eq!(duty.to_string(), "1/signature");
        assert_eq!(u64::from(duty.slot), 1);
    }

    #[test]
    fn new_prepare_aggregator_duty() {
        let duty = Duty::new_prepare_aggregator_duty(SlotNumber(1));
        assert_eq!(duty.duty_type, DutyType::PrepareAggregator);
        assert_eq!(duty.to_string(), "1/prepare_aggregator");
        assert_eq!(u64::from(duty.slot), 1);
    }

    #[test]
    fn new_aggregator_duty() {
        let duty = Duty::new_aggregator_duty(SlotNumber(1));
        assert_eq!(duty.duty_type, DutyType::Aggregator);
        assert_eq!(duty.to_string(), "1/aggregator");
        assert_eq!(u64::from(duty.slot), 1);
    }

    #[test]
    fn new_sync_contribution_duty() {
        let duty = Duty::new_sync_contribution_duty(SlotNumber(1));
        assert_eq!(duty.duty_type, DutyType::SyncContribution);
        assert_eq!(duty.to_string(), "1/sync_contribution");
        assert_eq!(u64::from(duty.slot), 1);
    }

    #[test]
    fn new_sync_message_duty() {
        let duty = Duty::new_sync_message_duty(SlotNumber(1));
        assert_eq!(duty.duty_type, DutyType::SyncMessage);
        assert_eq!(duty.to_string(), "1/sync_message");
        assert_eq!(u64::from(duty.slot), 1);
    }

    #[test]
    fn new_prepare_sync_contribution_duty() {
        let duty = Duty::new_prepare_sync_contribution_duty(SlotNumber(1));
        assert_eq!(duty.duty_type, DutyType::PrepareSyncContribution);
        assert_eq!(duty.to_string(), "1/prepare_sync_contribution");
        assert_eq!(u64::from(duty.slot), 1);
    }

    #[test]
    fn new_info_sync_duty() {
        let duty = Duty::new_info_sync_duty(SlotNumber(1));
        assert_eq!(duty.duty_type, DutyType::InfoSync);
        assert_eq!(duty.to_string(), "1/info_sync");
        assert_eq!(u64::from(duty.slot), 1);
    }

    #[test]
    fn slot() {
        let slot = Slot {
            slot: SlotNumber(123),
            time: DateTime::from_timestamp(100, 100).unwrap(),
            slot_duration: Duration::seconds(4),
            slots_per_epoch: 32,
        };

        assert_eq!(u64::from(slot.slot), 0x7b);
        assert_eq!(slot.epoch(), 3);
        assert!(!slot.last_in_epoch());
        assert!(!slot.first_in_epoch());

        let next = slot.next_slot();
        assert_eq!(next.slot, SlotNumber(124));
        assert_eq!(next.time, DateTime::from_timestamp(104, 100).unwrap());
        assert_eq!(next.slot_duration, Duration::seconds(4));
        assert_eq!(next.slots_per_epoch, 32);
    }

    #[test]
    fn serialize_pubkey() {
        let pk = PubKey::new([42u8; PK_LEN]);
        let serialized = serde_json::to_string(&pk).unwrap();
        assert_eq!(serialized, format!("\"0x{}\"", hex::encode([42u8; PK_LEN])));
    }

    #[test]
    fn deserialize_pubkey() {
        let serialized = format!("\"0x{}\"", hex::encode([42u8; PK_LEN]));
        let deserialized: PubKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, PubKey::new([42u8; PK_LEN]));
    }

    #[test]
    fn slot_iter() {
        let slot = Slot {
            slot: SlotNumber(123),
            time: DateTime::from_timestamp(100, 100).unwrap(),
            slot_duration: Duration::seconds(4),
            slots_per_epoch: 32,
        };

        assert_eq!(slot.iter().nth(10).unwrap().slot, SlotNumber(133));
        assert_eq!(slot.iter().nth(31).unwrap().slot, SlotNumber(154));
        assert_eq!(slot.iter().nth(32).unwrap().slot, SlotNumber(155));
        assert_eq!(slot.iter().nth(33).unwrap().slot, SlotNumber(156));
    }

    #[test]
    fn display_duty_type() {
        assert_eq!(DutyType::Unknown.to_string(), "unknown");
        assert_eq!(DutyType::Proposer.to_string(), "proposer");
        assert_eq!(DutyType::Attester.to_string(), "attester");
        assert_eq!(DutyType::Signature.to_string(), "signature");
        assert_eq!(DutyType::Exit.to_string(), "exit");
        assert_eq!(DutyType::BuilderProposer.to_string(), "builder_proposer");
        assert_eq!(
            DutyType::BuilderRegistration.to_string(),
            "builder_registration"
        );
        assert_eq!(DutyType::Randao.to_string(), "randao");
        assert_eq!(
            DutyType::PrepareAggregator.to_string(),
            "prepare_aggregator"
        );
        assert_eq!(DutyType::Aggregator.to_string(), "aggregator");
        assert_eq!(DutyType::SyncMessage.to_string(), "sync_message");
        assert_eq!(
            DutyType::PrepareSyncContribution.to_string(),
            "prepare_sync_contribution"
        );
        assert_eq!(DutyType::SyncContribution.to_string(), "sync_contribution");
        assert_eq!(DutyType::InfoSync.to_string(), "info_sync");
    }

    #[test]
    fn proposal_type_wire_round_trip() {
        for (pt, s) in [
            (ProposalType::Full, "full"),
            (ProposalType::Builder, "builder"),
            (ProposalType::Synthetic, "synthetic"),
        ] {
            assert_eq!(pt.as_str(), s);
            assert_eq!(ProposalType::from(s), pt);
        }

        // Unrecognised wire strings are preserved as Unknown, not dropped.
        let unknown = ProposalType::from("future_type");
        assert_eq!(unknown, ProposalType::Unknown("future_type".to_owned()));
        assert_eq!(unknown.as_str(), "future_type");
    }

    #[test]
    fn proposal_type_serde_is_wire_string() {
        assert_eq!(
            serde_json::to_string(&ProposalType::Builder).expect("serialize"),
            "\"builder\""
        );
        assert_eq!(
            serde_json::from_str::<ProposalType>("\"future_type\"").expect("deserialize"),
            ProposalType::Unknown("future_type".to_owned())
        );
    }

    #[test]
    fn duty_type_is_valid() {
        assert!(!DutyType::Unknown.is_valid());
        assert!(DutyType::Proposer.is_valid());
        assert!(DutyType::Attester.is_valid());
        assert!(DutyType::Signature.is_valid());
        assert!(DutyType::Exit.is_valid());
        assert!(!DutyType::DutySentinel(Box::new(DutyType::Unknown)).is_valid());
        assert!(!DutyType::DutySentinel(Box::new(DutyType::Attester)).is_valid());
    }

    #[test]
    fn pub_key_from_bytes() {
        let bytes = [42u8; PK_LEN];
        let pk = PubKey::try_from(&bytes[..]).unwrap();
        assert_eq!(pk, PubKey::new(bytes));
    }

    #[test]
    fn pub_key_from_bytes_invalid_length() {
        let bytes = [42u8; PK_LEN + 1];
        let result = PubKey::try_from(&bytes[..]);
        assert!(result.is_err());
    }

    #[test]
    fn pub_key_abbreviated() {
        let pk = PubKey::new([42u8; PK_LEN]);
        assert_eq!(pk.abbreviated(), "2a2_a2a");
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct MockSignedData;

    impl MockSignedData {
        fn boxed(&self) -> Box<dyn SignedData> {
            Box::new(self.clone())
        }
    }

    impl SignedData for MockSignedData {
        fn signature(&self) -> Result<Signature, SignedDataError> {
            Ok([42u8; SIGNATURE_LENGTH])
        }

        fn set_signature(&self, _signature: Signature) -> Result<Self, SignedDataError> {
            Ok(self.clone())
        }

        fn set_signature_boxed(
            &self,
            signature: Signature,
        ) -> Result<Box<dyn SignedData>, SignedDataError> {
            Ok(Box::new(self.set_signature(signature)?))
        }

        fn message_root(&self) -> Result<HashRoot, SignedDataError> {
            Ok([42u8; 32])
        }
    }

    #[test]
    fn partially_signed_data_set() {
        let mut partially_signed_data_set = ParSignedDataSet::new();
        let par_signed = ParSignedData::new(MockSignedData, 0);
        partially_signed_data_set.insert(PubKey::new([42u8; PK_LEN]), par_signed.clone());
        let retrieved = partially_signed_data_set.get(&PubKey::new([42u8; PK_LEN]));
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.share_idx, 0);
        assert_eq!(
            retrieved.signed_data.signature().unwrap(),
            [42u8; SIGNATURE_LENGTH]
        );
    }

    #[test]
    fn signed_data_set() {
        let mut signed_data_set = SignedDataSet::new();
        signed_data_set.insert(PubKey::new([42u8; PK_LEN]), MockSignedData.boxed());
        let expected = MockSignedData.boxed();
        assert_eq!(
            signed_data_set.get(&PubKey::new([42u8; PK_LEN])),
            Some(&expected)
        );
    }

    #[test]
    fn pub_key_from_string() {
        let pk_str = "0x7f790ba343adf8891fac21a94b02d6ca93d0bc2199a5ec083ff6676e8c2f9f78b08bb122f1093675f9d24c8b5e7af241".to_string();
        let pk = PubKey::try_from(pk_str.as_str()).unwrap();
        assert_eq!(
            pk,
            PubKey::new([
                127, 121, 11, 163, 67, 173, 248, 137, 31, 172, 33, 169, 75, 2, 214, 202, 147, 208,
                188, 33, 153, 165, 236, 8, 63, 246, 103, 110, 140, 47, 159, 120, 176, 139, 177, 34,
                241, 9, 54, 117, 249, 210, 76, 139, 94, 122, 242, 65
            ])
        );
    }

    #[test]
    fn pub_key_from_string_invalid_length() {
        let pk_str = "0x7f790ba343adf8891fac21a94b02d6ca93d0bc2199a5ec083ff6676e8c2f9f78b08bb121093675f9d24c8b5e7af241".to_string();
        let result = PubKey::try_from(pk_str.as_str());
        assert!(result.is_err());
    }
}
