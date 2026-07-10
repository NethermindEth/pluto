//! QBFT protobuf message adapter.
//!
//! This module bridges the domain-specific consensus protobuf messages with
//! the generic [`pluto_core::qbft`] state machine.
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

use std::{any, collections::HashMap, fmt, sync};

use k256::{PublicKey, SecretKey};
use pluto_ssz::{HashRoot, HashWalker, Hasher, HasherError};
use prost_types::Any;

use pluto_core::{
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
    type Value = HashRoot;
}

/// Concrete values carried beside QBFT hash messages.
///
/// The key is the [`hash_proto`] result of the decoded inner protobuf message.
/// The value remains the original `Any` envelope so later layers can forward or
/// compare the same payload without losing type-url information.
pub type ValueMap = HashMap<HashRoot, Any>;

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
    value_hash: HashRoot,
    prepared_value_hash: HashRoot,
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
    /// Admission mirrors Charon's `newMsg`: a `value_hash` /
    /// `prepared_value_hash` that is absent, all-zero, or not exactly 32 bytes
    /// collapses to the nil hash `[0u8; 32]` with no error. A well-formed,
    /// non-zero 32-byte hash must be present in `values`, otherwise this
    /// returns [`Error::ValueHashNotFound`] /
    /// [`Error::PreparedValueHashNotFound`]. There is no message-type or
    /// prepared-round requirement here; round consistency and value presence
    /// at decision time are enforced by the generic QBFT core's justification
    /// rules.
    ///
    /// Justifications are raw protobuf messages from the same consensus
    /// envelope. They are recursively wrapped with the same shared value map.
    pub(crate) fn new(
        msg: pbconsensus::QbftMsg,
        justification: Vec<pbconsensus::QbftMsg>,
        values: sync::Arc<ValueMap>,
    ) -> Result<Self> {
        let value_hash = value_hash(&msg, &values)?;
        let prepared_value_hash = prepared_value_hash(&msg, &values)?;

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
    /// Returns the QBFT message type preserved from the wire value.
    fn type_(&self) -> MessageType {
        MessageType::from_wire(self.msg.r#type)
    }

    /// Returns the duty instance this message belongs to.
    fn instance(&self) -> Duty {
        duty_from_proto(self.msg.duty.as_ref())
    }

    /// Returns the sender's zero-based peer index.
    fn source(&self) -> i64 {
        self.msg.peer_idx
    }

    /// Returns the QBFT round carried by the message.
    fn round(&self) -> i64 {
        self.msg.round
    }

    /// Returns the cached proposal value hash.
    fn value(&self) -> HashRoot {
        self.value_hash
    }

    /// Returns the original value payload for core compare callbacks.
    fn value_source(&self) -> std::result::Result<Any, qbft::QbftError> {
        self.values
            .get(&self.value_hash)
            .cloned()
            .ok_or(qbft::QbftError::ValueNotFound)
    }

    /// Returns the prepared round carried by a round-change message.
    fn prepared_round(&self) -> i64 {
        self.msg.prepared_round
    }

    /// Returns the cached prepared value hash.
    fn prepared_value(&self) -> HashRoot {
        self.prepared_value_hash
    }

    /// Returns wrapped justification messages for core validation.
    fn justification(&self) -> Vec<qbft::Msg<ConsensusQbftTypes>> {
        self.justification.clone()
    }

    /// Exposes the concrete wrapper for transport downcasts.
    fn as_any(&self) -> &dyn any::Any {
        self
    }
}

/// Returns a deterministic SSZ hash root of a concrete protobuf message.
///
/// The hash input is deterministic protobuf encoding, then SSZ `PutBytes`
/// merkleization. `Any` is rejected because the consensus value hash must bind
/// to the inner message bytes, not the transport envelope.
pub fn hash_proto<M>(msg: &M) -> Result<HashRoot>
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
pub fn hash_proto_bytes(encoded: &[u8]) -> Result<HashRoot> {
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

/// Converts a protobuf bytes field into a non-zero 32-byte hash.
fn to_hash32(value: &[u8]) -> Option<HashRoot> {
    let value: HashRoot = value.try_into().ok()?;
    if value == [0u8; 32] {
        return None;
    }

    Some(value)
}

fn value_hash(msg: &pbconsensus::QbftMsg, values: &ValueMap) -> Result<HashRoot> {
    // Mirror Charon newMsg: an absent / zero / non-32-byte value_hash collapses
    // to the nil hash with no error; a well-formed non-zero 32-byte hash must
    // be present in `values`.
    let Some(hash) = to_hash32(&msg.value_hash) else {
        return Ok([0u8; 32]);
    };

    if values.contains_key(&hash) {
        return Ok(hash);
    }

    Err(Error::ValueHashNotFound)
}

fn prepared_value_hash(msg: &pbconsensus::QbftMsg, values: &ValueMap) -> Result<HashRoot> {
    // Mirror Charon newMsg: the prepared hash is admitted on the same rule as
    // value_hash and is independent of prepared_round.
    let Some(hash) = to_hash32(&msg.prepared_value_hash) else {
        return Ok([0u8; 32]);
    };

    if values.contains_key(&hash) {
        return Ok(hash);
    }

    Err(Error::PreparedValueHashNotFound)
}

/// Converts an optional protobuf duty into the domain duty type.
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
    use pluto_core::qbft::{
        MSG_COMMIT, MSG_DECIDED, MSG_PRE_PREPARE, MSG_PREPARE, MSG_ROUND_CHANGE,
    };
    use prost::bytes::Bytes;
    use prost_types::Timestamp;
    use test_case::test_case;

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

    /// Cross-impl golden vectors from charon v1.7.1 (the source of truth). For
    /// each consensus duty, pluto must hash the exact `UnsignedDataSet` bytes
    /// charon sends on the wire to the same 32-byte root, or QBFT never forms
    /// quorum in a mixed cluster. The `attester_seed0` vector
    /// equals charon's own `TestHashProto` golden, so a match also proves the
    /// vectors were captured faithfully.
    #[test]
    fn hash_proto_matches_charon_golden_vectors() {
        #[derive(serde::Deserialize)]
        struct Entry {
            pubkey: String,
            data_hex: String,
        }
        #[derive(serde::Deserialize)]
        struct Vector {
            name: String,
            duty: String,
            entries: Vec<Entry>,
            hash_hex: String,
        }
        #[derive(serde::Deserialize)]
        struct File {
            charon_ref: String,
            vectors: Vec<Vector>,
        }

        let file: File =
            serde_json::from_str(include_str!("../../testdata/vectors/hashproto.json")).unwrap();

        // Drift guard: vectors are pinned to a specific charon release.
        assert_eq!(
            file.charon_ref, "v1.7.1",
            "golden vectors are pinned to charon v1.7.1"
        );
        assert!(
            !file.vectors.is_empty(),
            "expected at least one golden vector"
        );

        for v in &file.vectors {
            // Rebuild the exact {pubkey -> bytes} set charon serialised — 0..N
            // entries covers single-DV, multi-DV cluster shape, and the empty
            // boundary.
            let mut set = std::collections::BTreeMap::new();
            for e in &v.entries {
                set.insert(
                    e.pubkey.clone(),
                    Bytes::from(hex::decode(&e.data_hex).unwrap()),
                );
            }

            let hash = hash_proto(&pbcore::UnsignedDataSet { set }).unwrap();

            assert_eq!(
                hex::encode(hash),
                v.hash_hex,
                "hashProto mismatch for vector '{}' (duty={})",
                v.name,
                v.duty,
            );
        }
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

    // Parity with charon core/consensus/qbft/msg.go newMsg @ v1.7.1: an
    // absent, all-zero, or non-32-byte value hash is admitted and collapses to
    // the nil hash for every message type — there is no type-gating and no
    // malformed-length rejection in the reference wrapper.
    #[test_case(MSG_PRE_PREPARE, vec![] ; "pre_prepare_empty")]
    #[test_case(MSG_PREPARE, vec![0; 32] ; "prepare_zero")]
    #[test_case(MSG_COMMIT, vec![1; 31] ; "commit_short")]
    #[test_case(MSG_DECIDED, vec![1; 33] ; "decided_long")]
    fn new_admits_malformed_value_hash_as_nil(type_: MessageType, hash: Vec<u8>) {
        let msg = Msg::new(
            pbconsensus::QbftMsg {
                r#type: i64::from(type_),
                value_hash: hash.into(),
                ..Default::default()
            },
            vec![],
            sync::Arc::default(),
        )
        .unwrap();

        assert_eq!(msg.value(), [0u8; 32]);
    }

    #[test_case(vec![] ; "empty")]
    #[test_case(vec![0; 32] ; "zero_hash")]
    fn new_allows_nil_value_hash_for_round_change(hash: Vec<u8>) {
        let msg = Msg::new(
            pbconsensus::QbftMsg {
                r#type: i64::from(MSG_ROUND_CHANGE),
                value_hash: hash.into(),
                ..Default::default()
            },
            vec![],
            sync::Arc::default(),
        )
        .unwrap();

        assert_eq!(msg.value(), [0u8; 32]);
    }

    // Parity with charon newMsg @ v1.7.1: the prepared hash is admitted on the
    // same rule as value_hash and is independent of prepared_round — even a
    // ROUND-CHANGE claiming `prepared_round > 0` with an absent/zero/malformed
    // prepared hash constructs with the nil hash. Round/prepared-round
    // consistency is enforced by the generic core's justification rules.
    #[test_case(0, vec![] ; "unprepared_empty")]
    #[test_case(0, vec![0; 32] ; "unprepared_zero")]
    #[test_case(0, vec![1; 31] ; "unprepared_short")]
    #[test_case(0, vec![1; 33] ; "unprepared_long")]
    #[test_case(1, vec![] ; "prepared_empty")]
    #[test_case(1, vec![0; 32] ; "prepared_zero")]
    #[test_case(1, vec![1; 31] ; "prepared_short")]
    #[test_case(1, vec![1; 33] ; "prepared_long")]
    fn new_admits_malformed_prepared_value_hash_as_nil(prepared_round: i64, hash: Vec<u8>) {
        let msg = Msg::new(
            pbconsensus::QbftMsg {
                prepared_round,
                prepared_value_hash: hash.into(),
                ..Default::default()
            },
            vec![],
            sync::Arc::default(),
        )
        .unwrap();

        assert_eq!(msg.prepared_value(), [0u8; 32]);
    }

    /// The two hash helpers are independent: a malformed `value_hash` collapses
    /// to nil while a valid present `prepared_value_hash` still maps, and vice
    /// versa.
    #[test]
    fn new_maps_valid_hash_beside_malformed_other_hash() {
        let valid_hash = hash_proto(&timestamp(1)).unwrap();
        let values = sync::Arc::new(value_map(vec![(valid_hash, any_timestamp(1))]));

        let msg = Msg::new(
            pbconsensus::QbftMsg {
                value_hash: vec![1; 31].into(),
                prepared_value_hash: valid_hash.to_vec().into(),
                ..Default::default()
            },
            vec![],
            values.clone(),
        )
        .unwrap();
        assert_eq!(msg.value(), [0u8; 32]);
        assert_eq!(msg.prepared_value(), valid_hash);

        let msg = Msg::new(
            pbconsensus::QbftMsg {
                value_hash: valid_hash.to_vec().into(),
                prepared_value_hash: vec![1; 33].into(),
                ..Default::default()
            },
            vec![],
            values,
        )
        .unwrap();
        assert_eq!(msg.value(), valid_hash);
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
            r#type: i64::from(MSG_ROUND_CHANGE),
            prepared_round: 1,
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

    fn value_map(values: Vec<(HashRoot, Any)>) -> ValueMap {
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
