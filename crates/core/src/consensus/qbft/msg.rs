//! QBFT protobuf message adapter.
//!
//! This module bridges the domain-specific consensus protobuf messages with
//! the generic [`crate::qbft`] state machine.
//!
//! [`QbftMsg`](pbconsensus::QbftMsg) carries only consensus metadata and value
//! hashes. The concrete proposal values are transported beside it in
//! [`QbftConsensusMsg`](pbconsensus::QbftConsensusMsg) as protobuf `Any`
//! payloads. [`Msg`] ties those two pieces back together by:
//!
//! - converting `value_hash` and `prepared_value_hash` into fixed `[u8; 32]`
//!   values for the generic QBFT core;
//! - checking that every non-zero hash referenced by the message exists in the
//!   supplied [`ValueMap`];
//! - recursively wrapping raw justification messages so the core can validate
//!   PRE-PREPARE and ROUND-CHANGE justifications;
//! - preserving the raw protobufs so the transport layer can rebuild the
//!   original consensus message with [`Msg::to_consensus_msg`].
//!
//! Do not hash `Any` directly. The consensus hash is over the deterministic
//! protobuf bytes of the inner message.
//!
//! Inbound callers validate message type, duty type, peer membership, rounds,
//! and signatures before constructing [`Msg`]. This adapter preserves raw
//! message types, while invalid duty wire values project to
//! [`DutyType::Unknown`].

// TODO: Remove once component/transport wiring uses the crate-visible helpers.
#![allow(dead_code)]

use std::{any, collections::HashMap, fmt, sync};

use k256::{PublicKey, SecretKey};
use pluto_ssz::{HashWalker, Hasher, HasherError};
use prost_types::Any;

use crate::{
    corepb::v1::{consensus as pbconsensus, core as pbcore},
    qbft::{self, MessageType, SomeMsg},
    types::{Duty, DutyType, SlotNumber},
};

/// Type mapping used by the consensus adapter when invoking generic QBFT.
///
/// - Instance: [`Duty`]
/// - Value: `[u8; 32]` hash of the concrete proposal value
/// - Compare: original `Any` payload passed to the application compare callback
pub struct ConsensusQbftTypes;

impl qbft::QbftTypes for ConsensusQbftTypes {
    type Compare = Any;
    type Instance = Duty;
    type Value = [u8; 32];
}

/// Concrete values carried beside QBFT hash messages.
///
/// The key is the [`hash_proto`] result of the decoded inner protobuf message.
/// The value remains the original `Any` envelope so later layers can forward or
/// compare the same payload without losing type-url information.
pub type ValueMap = HashMap<[u8; 32], Any>;

type Result<T> = std::result::Result<T, Error>;

/// Errors returned by QBFT message wrapping.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Value hash did not exist in the values map.
    #[error("value hash not found in values")]
    ValueHashNotFound,

    /// Prepared value hash did not exist in the values map.
    #[error("prepared value hash not found in values")]
    PreparedValueHashNotFound,

    /// Value did not exist in the values map.
    #[error("value not found")]
    ValueNotFound,

    /// Callers must hash the concrete inner message, not `Any`.
    #[error("cannot hash any proto, must hash inner value")]
    CannotHashAnyProto,

    /// Protobuf marshal failed.
    #[error("marshal proto: {0}")]
    MarshalProto(#[source] prost::EncodeError),

    /// SSZ hash failed.
    #[error("hash proto: {0}")]
    HashProto(#[source] HasherError),

    /// QBFT message signature was empty.
    #[error("empty signature")]
    EmptySignature,

    /// Public key recovery failed.
    #[error("recover pubkey: {0}")]
    RecoverPubkey(#[source] pluto_k1util::K1UtilError),

    /// Signing failed.
    #[error("sign: {0}")]
    Sign(#[source] pluto_k1util::K1UtilError),
}

/// Wrapped consensus message consumed by the generic QBFT core.
///
/// The raw protobuf remains available for re-broadcasting. The hash fields are
/// cached as `[u8; 32]` because the core treats consensus values as comparable
/// hashes, not full protobuf payloads.
#[derive(Clone)]
pub struct Msg {
    msg: pbconsensus::QbftMsg,
    value_hash: [u8; 32],
    prepared_value_hash: [u8; 32],
    values: sync::Arc<ValueMap>,
    justification_protos: Vec<pbconsensus::QbftMsg>,
    justification: Vec<qbft::Msg<ConsensusQbftTypes>>,
}

impl fmt::Debug for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Msg")
            .field("type", &MessageType::from_wire(self.msg.r#type).to_string())
            .field(
                "duty",
                &self.msg.duty.as_ref().map(|duty| (duty.slot, duty.r#type)),
            )
            .field("peer_idx", &self.msg.peer_idx)
            .field("round", &self.msg.round)
            .field("prepared_round", &self.msg.prepared_round)
            .field("value_hash", &self.value_hash)
            .field("prepared_value_hash", &self.prepared_value_hash)
            .field("values_len", &self.values.len())
            .field("justification_len", &self.justification.len())
            .finish()
    }
}

impl Msg {
    /// Wraps a raw QBFT protobuf message for the generic core.
    ///
    /// Non-zero `value_hash` and `prepared_value_hash` fields must both exist
    /// in `values`. Invalid hash encodings, including zero hashes, are
    /// treated as the nil value and do not require a map entry.
    ///
    /// Justifications are raw protobuf messages from the same consensus
    /// envelope. They are recursively wrapped with the same shared value map.
    pub(crate) fn new(
        msg: pbconsensus::QbftMsg,
        justification: Vec<pbconsensus::QbftMsg>,
        values: sync::Arc<ValueMap>,
    ) -> Result<Self> {
        let value_hash = match to_hash32(&msg.value_hash) {
            Some(hash) if values.contains_key(&hash) => hash,
            Some(_) => return Err(Error::ValueHashNotFound),
            None => [0u8; 32],
        };
        let prepared_value_hash = match to_hash32(&msg.prepared_value_hash) {
            Some(hash) if values.contains_key(&hash) => hash,
            Some(_) => return Err(Error::PreparedValueHashNotFound),
            None => [0u8; 32],
        };

        let mut justification_impls: Vec<qbft::Msg<ConsensusQbftTypes>> =
            Vec::with_capacity(justification.len());

        for justification_msg in &justification {
            let impl_msg = Self::new(justification_msg.clone(), vec![], values.clone())?;
            justification_impls.push(sync::Arc::new(impl_msg));
        }

        Ok(Self {
            msg,
            value_hash,
            prepared_value_hash,
            values,
            justification_protos: justification,
            justification: justification_impls,
        })
    }

    /// Returns the raw protobuf message.
    pub fn msg(&self) -> &pbconsensus::QbftMsg {
        &self.msg
    }

    /// Returns the values map shared by this message and nested justifications.
    pub fn values(&self) -> &ValueMap {
        &self.values
    }

    /// Returns the `Any` payload for this message's `value_hash`.
    pub fn value_source(&self) -> Result<Any> {
        self.values
            .get(&self.value_hash)
            .cloned()
            .ok_or(Error::ValueNotFound)
    }

    /// Rebuilds the protobuf consensus envelope for transport.
    pub fn to_consensus_msg(&self) -> pbconsensus::QbftConsensusMsg {
        pbconsensus::QbftConsensusMsg {
            msg: Some(self.msg.clone()),
            justification: self.justification_protos.clone(),
            values: self.values.values().cloned().collect(),
        }
    }
}

impl SomeMsg<ConsensusQbftTypes> for Msg {
    fn type_(&self) -> MessageType {
        MessageType::from_wire(self.msg.r#type)
    }

    fn instance(&self) -> Duty {
        duty_from_proto(self.msg.duty.as_ref())
    }

    fn source(&self) -> i64 {
        self.msg.peer_idx
    }

    fn round(&self) -> i64 {
        self.msg.round
    }

    fn value(&self) -> [u8; 32] {
        self.value_hash
    }

    fn value_source(&self) -> std::result::Result<Any, qbft::QbftError> {
        self.values
            .get(&self.value_hash)
            .cloned()
            .ok_or(qbft::QbftError::ValueNotFound)
    }

    fn prepared_round(&self) -> i64 {
        self.msg.prepared_round
    }

    fn prepared_value(&self) -> [u8; 32] {
        self.prepared_value_hash
    }

    fn justification(&self) -> Vec<qbft::Msg<ConsensusQbftTypes>> {
        self.justification.clone()
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}

/// Returns a deterministic SSZ hash root of a concrete protobuf message.
///
/// The hash input is deterministic protobuf encoding, then SSZ `PutBytes`
/// merkleization. `Any` is rejected because the consensus value hash must bind
/// to the inner message bytes, not the transport envelope.
pub(crate) fn hash_proto<M>(msg: &M) -> Result<[u8; 32]>
where
    M: prost::Message + prost::Name,
{
    if M::PACKAGE == "google.protobuf" && M::NAME == "Any" {
        return Err(Error::CannotHashAnyProto);
    }

    let mut encoded = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut encoded).map_err(Error::MarshalProto)?;

    hash_proto_bytes(&encoded)
}

/// Returns the consensus hash for deterministic inner-protobuf bytes.
///
/// This helper hashes the bytes exactly as provided; it does not decode or
/// canonicalize a protobuf envelope. Callers must pass bytes produced from the
/// concrete inner message with deterministic field/map ordering.
pub(crate) fn hash_proto_bytes(encoded: &[u8]) -> Result<[u8; 32]> {
    let mut hasher = Hasher::default();
    let index = hasher.index();
    hasher.put_bytes(encoded).map_err(Error::HashProto)?;
    hasher.merkleize(index).map_err(Error::HashProto)?;
    hasher.hash_root().map_err(Error::HashProto)
}

/// Returns a signed copy of a QBFT protobuf message.
///
/// The signature field is cleared before hashing, so callers may pass either an
/// unsigned message or an already-signed message to re-sign.
pub(crate) fn sign_msg(
    msg: &pbconsensus::QbftMsg,
    privkey: &SecretKey,
) -> Result<pbconsensus::QbftMsg> {
    let mut clone = msg.clone();
    clone.signature.clear();

    let hash = hash_proto(&clone)?;
    let signature = pluto_k1util::sign(privkey, &hash).map_err(Error::Sign)?;
    clone.signature = signature.to_vec().into();

    Ok(clone)
}

/// Verifies that a QBFT protobuf message was signed by `pubkey`.
///
/// The signature is recoverable secp256k1 over [`hash_proto`] of the message
/// with its signature field cleared.
pub(crate) fn verify_msg_sig(msg: &pbconsensus::QbftMsg, pubkey: &PublicKey) -> Result<bool> {
    // Protobuf `bytes` fields decode both absent and explicit-empty values as
    // empty bytes in prost.
    if msg.signature.is_empty() {
        return Err(Error::EmptySignature);
    }

    let mut clone = msg.clone();
    clone.signature.clear();

    let hash = hash_proto(&clone)?;
    let recovered = pluto_k1util::recover(&hash, &msg.signature).map_err(Error::RecoverPubkey)?;

    Ok(recovered == *pubkey)
}

fn to_hash32(value: &[u8]) -> Option<[u8; 32]> {
    let value: [u8; 32] = value.try_into().ok()?;
    if value == [0u8; 32] {
        return None;
    }

    Some(value)
}

fn duty_from_proto(duty: Option<&pbcore::Duty>) -> Duty {
    let Some(duty) = duty else {
        return Duty::new(SlotNumber::new(0), DutyType::Unknown);
    };

    // Message receive validation rejects invalid duty types before this adapter
    // is used by the consensus runner. If an invalid value reaches this local
    // projection, Rust's closed enum maps it to Unknown instead of preserving
    // the raw wire value.
    let duty_type: DutyType = DutyType::try_from(duty.r#type).unwrap_or(DutyType::Unknown);
    Duty::new(SlotNumber::new(duty.slot), duty_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qbft::{MSG_PRE_PREPARE, MSG_PREPARE};
    use prost::bytes::Bytes;
    use prost_types::Timestamp;
    use test_case::test_case;

    const UNSIGNED_DATASET_HASH: &str =
        "d8f9bc3de8b0cb0e3eb1f773c14a96d58f7acaf0f09192ce6562d84ea315e67b";
    const UNSIGNED_DATASET_KEY: &str = "0xe5301bb68d031b01ef7f35613a77f05f6134983fedd8b0107ec2e45c9bb480eb52accb3174a9a936f255f96410d2eb03";
    const UNSIGNED_DATASET_VALUE_HEX: &str = "0800000088000000394651850fd4010078892ee285ec0100511455780875d64ee2d3d0d0de6bf8f9b44ce85ff044c6b1f83b8e883bbf857ac354f3ede2d61e0067cfe242cf3ccc4ea3ae5e88526a9f4a578bcb9ef2d4a65314768d6d299761ea045c3f000f8a1900ddcdd01d756bce6c512c3801aacaeedfad5b506664e8c0e4a771ece0b8b7c196a5512e043e9b9aa687907adf5dba61350991daef80dd5c470c90650aaf7b5fd90022215ae7966bb600191b1825f88d4273c86e4ff95f160062a5eee82abd14004a2d0b75fb180d0000010000000000000001000000000000e000000000000000";
    const TIMESTAMP_HASH: &str = "0880e2cfaa0610959aef3a000000000000000000000000000000000000000000";
    const QBFT_MSG_HASH: &str = "9423898db5f4fc224e07cd775a03d7dc89dafe6aedfda9f75cccb1f17c3ba803";
    const SIGNING_PRIVKEY: &str =
        "41d3ff12045b73c870529fe44f70dca2745bafbe1698ffc3c8759eef3cfbaee1";
    const WRONG_PRIVKEY: &str = "42d3ff12045b73c870529fe44f70dca2745bafbe1698ffc3c8759eef3cfbaee1";
    const QBFT_MSG_SIGNATURE: &str = "8a3d48258325037ce680c0bfd40ebc95ff53865b9a7ea391308f27dd1be324791647d3814dc40e9c1edbf6b50e62b99dbc7401724c975ffc0673d034fb9bb0df01";

    #[test_case(vec![] ; "empty")]
    #[test_case(vec![1; 31] ; "short")]
    #[test_case(vec![1; 33] ; "long")]
    #[test_case(vec![0; 32] ; "zero_hash")]
    fn to_hash32_rejects_invalid_hashes(value: Vec<u8>) {
        assert_eq!(to_hash32(&value), None);
    }

    #[test]
    fn to_hash32_accepts_nonzero_32_bytes() {
        assert_eq!(to_hash32(&[1u8; 32]), Some([1u8; 32]));
    }

    #[test]
    fn hash_proto_matches_seeded_unsigned_dataset() {
        let mut set = std::collections::BTreeMap::new();
        set.insert(
            UNSIGNED_DATASET_KEY.to_string(),
            Bytes::from(hex::decode(UNSIGNED_DATASET_VALUE_HEX).unwrap()),
        );

        let hash = hash_proto(&pbcore::UnsignedDataSet { set }).unwrap();

        assert_eq!(hex::encode(hash), UNSIGNED_DATASET_HASH);
    }

    #[test]
    fn hash_proto_matches_timestamp() {
        let hash = hash_proto(&Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_789,
        })
        .unwrap();

        assert_eq!(hex::encode(hash), TIMESTAMP_HASH);
    }

    #[test]
    fn hash_proto_matches_qbft_msg() {
        let hash = hash_proto(&fixed_qbft_msg()).unwrap();

        assert_eq!(hex::encode(hash), QBFT_MSG_HASH);
    }

    #[test]
    fn hash_proto_uses_btree_map_for_deterministic_encoding() {
        let mut forward = std::collections::BTreeMap::new();
        forward.insert("a".to_string(), Bytes::from_static(b"first"));
        forward.insert("b".to_string(), Bytes::from_static(b"second"));

        let mut reverse = std::collections::BTreeMap::new();
        reverse.insert("b".to_string(), Bytes::from_static(b"second"));
        reverse.insert("a".to_string(), Bytes::from_static(b"first"));

        assert_eq!(
            hash_proto(&pbcore::UnsignedDataSet { set: forward }).unwrap(),
            hash_proto(&pbcore::UnsignedDataSet { set: reverse }).unwrap()
        );
    }

    #[test]
    fn hash_proto_rejects_any() {
        let any = Any::from_msg(&Timestamp {
            seconds: 1,
            nanos: 2,
        })
        .unwrap();

        let err = hash_proto(&any).unwrap_err();

        assert_eq!(
            err.to_string(),
            "cannot hash any proto, must hash inner value"
        );
    }

    #[test]
    fn debug_unknown_message_type() {
        let msg = Msg::new(
            pbconsensus::QbftMsg {
                r#type: 99,
                ..Default::default()
            },
            vec![],
            sync::Arc::default(),
        )
        .unwrap();

        let debug = format!("{msg:?}");

        assert!(debug.contains("type: \"\""));
    }

    #[test]
    fn new_maps_valid_value_and_prepared_hashes() {
        let value_hash = hash_proto(&timestamp(1)).unwrap();
        let prepared_hash = hash_proto(&timestamp(2)).unwrap();
        let values = sync::Arc::new(value_map(vec![
            (value_hash, any_timestamp(1)),
            (prepared_hash, any_timestamp(2)),
        ]));

        let msg = Msg::new(
            pbconsensus::QbftMsg {
                r#type: 1,
                duty: Some(pbcore::Duty {
                    slot: 42,
                    r#type: 2,
                }),
                peer_idx: 7,
                round: 3,
                prepared_round: 2,
                value_hash: value_hash.to_vec().into(),
                prepared_value_hash: prepared_hash.to_vec().into(),
                ..Default::default()
            },
            vec![],
            values,
        )
        .unwrap();

        assert_eq!(msg.type_(), MSG_PRE_PREPARE);
        assert_eq!(
            msg.instance(),
            Duty::new(SlotNumber::new(42), DutyType::Attester)
        );
        assert_eq!(msg.source(), 7);
        assert_eq!(msg.round(), 3);
        assert_eq!(msg.value(), value_hash);
        assert_eq!(msg.prepared_round(), 2);
        assert_eq!(msg.prepared_value(), prepared_hash);
        assert_eq!(msg.value_source().unwrap(), any_timestamp(1));
        assert_eq!(msg.values().len(), 2);
    }

    #[test_case(vec![1; 31] ; "invalid_length")]
    #[test_case(vec![0; 32] ; "zero_hash")]
    fn new_treats_invalid_value_hash_as_nil(hash: Vec<u8>) {
        let msg = Msg::new(
            pbconsensus::QbftMsg {
                value_hash: hash.into(),
                ..Default::default()
            },
            vec![],
            sync::Arc::default(),
        )
        .unwrap();

        assert_eq!(msg.value(), [0u8; 32]);
    }

    #[test_case(vec![1; 31] ; "invalid_length")]
    #[test_case(vec![0; 32] ; "zero_hash")]
    fn new_treats_invalid_prepared_value_hash_as_nil(hash: Vec<u8>) {
        let msg = Msg::new(
            pbconsensus::QbftMsg {
                prepared_value_hash: hash.into(),
                ..Default::default()
            },
            vec![],
            sync::Arc::default(),
        )
        .unwrap();

        assert_eq!(msg.prepared_value(), [0u8; 32]);
    }

    #[test]
    fn new_errors_on_missing_value_hash() {
        let err = Msg::new(
            pbconsensus::QbftMsg {
                value_hash: [1u8; 32].to_vec().into(),
                ..Default::default()
            },
            vec![],
            sync::Arc::default(),
        )
        .unwrap_err();

        assert_eq!(err.to_string(), "value hash not found in values");
    }

    #[test]
    fn new_errors_on_missing_prepared_value_hash() {
        let err = Msg::new(
            pbconsensus::QbftMsg {
                prepared_value_hash: [2u8; 32].to_vec().into(),
                ..Default::default()
            },
            vec![],
            sync::Arc::default(),
        )
        .unwrap_err();

        assert_eq!(err.to_string(), "prepared value hash not found in values");
    }

    #[test]
    fn new_errors_on_nested_justification_missing_value() {
        let err = Msg::new(
            pbconsensus::QbftMsg::default(),
            vec![pbconsensus::QbftMsg {
                value_hash: [3u8; 32].to_vec().into(),
                ..Default::default()
            }],
            sync::Arc::default(),
        )
        .unwrap_err();

        assert_eq!(err.to_string(), "value hash not found in values");
    }

    #[test]
    fn value_source_errors_when_value_missing() {
        let msg = Msg::new(
            pbconsensus::QbftMsg::default(),
            vec![],
            sync::Arc::default(),
        )
        .unwrap();

        let err = msg.value_source().unwrap_err();

        assert_eq!(err.to_string(), "value not found");
    }

    #[test]
    fn new_maps_justification() {
        let value_hash = hash_proto(&timestamp(1)).unwrap();
        let values = sync::Arc::new(value_map(vec![(value_hash, any_timestamp(1))]));

        let msg = Msg::new(
            pbconsensus::QbftMsg::default(),
            vec![pbconsensus::QbftMsg {
                r#type: 2,
                value_hash: value_hash.to_vec().into(),
                ..Default::default()
            }],
            values,
        )
        .unwrap();

        let justification = msg.justification();

        assert_eq!(justification.len(), 1);
        assert_eq!(justification[0].type_(), MSG_PREPARE);
        assert_eq!(justification[0].value(), value_hash);
    }

    #[test]
    fn to_consensus_msg_preserves_raw_message_justification_and_values() {
        let value_hash = hash_proto(&timestamp(1)).unwrap();
        let prepared_hash = hash_proto(&timestamp(2)).unwrap();
        let value_1 = any_timestamp(1);
        let value_2 = any_timestamp(2);
        let values = sync::Arc::new(value_map(vec![
            (value_hash, value_1.clone()),
            (prepared_hash, value_2.clone()),
        ]));
        let raw_msg = pbconsensus::QbftMsg {
            r#type: 1,
            value_hash: value_hash.to_vec().into(),
            ..Default::default()
        };
        let raw_justification = pbconsensus::QbftMsg {
            r#type: 2,
            prepared_value_hash: prepared_hash.to_vec().into(),
            ..Default::default()
        };

        let msg = Msg::new(raw_msg.clone(), vec![raw_justification.clone()], values).unwrap();
        let consensus_msg = msg.to_consensus_msg();

        assert_eq!(msg.msg(), &raw_msg);
        assert_eq!(consensus_msg.msg, Some(raw_msg));
        assert_eq!(consensus_msg.justification, vec![raw_justification]);
        assert_eq!(consensus_msg.values.len(), 2);
        assert_eq!(
            sorted_any(consensus_msg.values),
            sorted_any(vec![value_1, value_2])
        );
    }

    #[test]
    fn sign_msg_matches_expected_signature_and_verifies() {
        let key = secret_key(SIGNING_PRIVKEY);

        let signed = sign_msg(&fixed_qbft_msg(), &key).unwrap();

        assert_eq!(hex::encode(&signed.signature), QBFT_MSG_SIGNATURE);
        assert!(verify_msg_sig(&signed, &key.public_key()).unwrap());
    }

    #[test]
    fn sign_msg_resigns_already_signed_message() {
        let key = secret_key(SIGNING_PRIVKEY);
        let signed = sign_msg(&fixed_qbft_msg(), &key).unwrap();

        let resigned = sign_msg(&signed, &key).unwrap();

        assert_eq!(resigned, signed);
    }

    #[test]
    fn verify_msg_sig_wrong_key_returns_false() {
        let key = secret_key(SIGNING_PRIVKEY);
        let wrong_key = secret_key(WRONG_PRIVKEY);
        let signed = sign_msg(&fixed_qbft_msg(), &key).unwrap();

        let ok = verify_msg_sig(&signed, &wrong_key.public_key()).unwrap();

        assert!(!ok);
    }

    #[test]
    fn verify_msg_sig_tampered_message_returns_false() {
        let key = secret_key(SIGNING_PRIVKEY);
        let mut signed = sign_msg(&fixed_qbft_msg(), &key).unwrap();
        signed.round += 1;

        let ok = verify_msg_sig(&signed, &key.public_key()).unwrap();

        assert!(!ok);
    }

    #[test]
    fn verify_msg_sig_errors_on_empty_signature() {
        let err = verify_msg_sig(&fixed_qbft_msg(), &secret_key(SIGNING_PRIVKEY).public_key())
            .unwrap_err();

        assert_eq!(err.to_string(), "empty signature");
    }

    #[test]
    fn verify_msg_sig_errors_on_malformed_signature() {
        let key = secret_key(SIGNING_PRIVKEY);
        let mut msg = fixed_qbft_msg();
        msg.signature = vec![0x42u8; 64].into();

        let err = verify_msg_sig(&msg, &key.public_key()).unwrap_err();

        assert!(matches!(err, Error::RecoverPubkey(_)));
        assert!(std::error::Error::source(&err).is_some());
    }

    fn timestamp(seconds: i64) -> Timestamp {
        Timestamp { seconds, nanos: 0 }
    }

    fn any_timestamp(seconds: i64) -> Any {
        Any::from_msg(&timestamp(seconds)).unwrap()
    }

    fn value_map(values: Vec<([u8; 32], Any)>) -> ValueMap {
        values.into_iter().collect()
    }

    fn sorted_any(values: Vec<Any>) -> Vec<(String, Vec<u8>)> {
        let mut values = values
            .into_iter()
            .map(|value| (value.type_url, value.value.to_vec()))
            .collect::<Vec<_>>();
        values.sort();
        values
    }

    fn secret_key(hex_key: &str) -> SecretKey {
        SecretKey::from_slice(&hex::decode(hex_key).unwrap()).unwrap()
    }

    fn fixed_qbft_msg() -> pbconsensus::QbftMsg {
        pbconsensus::QbftMsg {
            r#type: 1,
            duty: Some(pbcore::Duty {
                slot: 42,
                r#type: 2,
            }),
            peer_idx: 7,
            round: 3,
            prepared_round: 2,
            value_hash: [0x11u8; 32].to_vec().into(),
            prepared_value_hash: [0x22u8; 32].to_vec().into(),
            ..Default::default()
        }
    }
}
