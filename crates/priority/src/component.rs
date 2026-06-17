//! Friendly priority API: domain types, message signing/verification, and
//! conversions between the domain types and their protobuf representations.
//!
//! Topics and priorities are arbitrary strings exposed to callers, wrapped on
//! the wire as `google.protobuf.Any`-packed structpb string values.

use std::{collections::HashMap, sync::Arc, time::Duration};

use chrono::Utc;
use k256::{PublicKey, SecretKey};
use libp2p::PeerId;
use pluto_consensus::qbft::msg::hash_proto;
use pluto_core::{
    corepb::v1::priority::{PriorityMsg, PriorityTopicProposal, PriorityTopicResult},
    deadline::{DeadlineCalculator, DeadlinerTask},
    types::Duty,
};
use pluto_p2p::peer::peer_id_to_public_key;
use prost::Message;
use prost_types::{Any, Value, value::Kind};
use tokio_util::sync::CancellationToken;

use crate::{
    consensus::{Consensus, PrioritySubscriber},
    error::{Error, Result},
    p2p::Behaviour,
    prioritiser::{Prioritiser, duty_to_proto},
};

/// Protobuf `type_url` for `google.protobuf.Value`.
///
/// `prost_types::Value` has no `prost::Name` impl, so the canonical type URL is
/// set explicitly when packing into `Any`.
const VALUE_TYPE_URL: &str = "type.googleapis.com/google.protobuf.Value";

/// Proposed priorities for a single prioritise topic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopicProposal {
    /// Topic identifier.
    pub topic: String,
    /// Proposed priorities in decreasing preference.
    pub priorities: Vec<String>,
}

/// Cluster-agreed resulting priorities for a single prioritise topic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopicResult {
    /// Topic identifier.
    pub topic: String,
    /// Resulting scored priorities in decreasing score.
    pub priorities: Vec<ScoredPriority>,
}

impl TopicResult {
    /// Returns the priorities without their scores.
    pub fn priorities_only(&self) -> Vec<String> {
        self.priorities.iter().map(|p| p.priority.clone()).collect()
    }
}

/// A cluster-agreed priority including its score.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScoredPriority {
    /// Priority identifier.
    pub priority: String,
    /// Aggregate score across proposing peers.
    pub score: i64,
}

/// Validates a received priority message's signature against a known peer set.
///
/// Returns the unknown-peer or invalid-signature error rather than a boolean,
/// so callers reject messages from unrecognised peers or with bad signatures.
pub type MsgVerifier = Box<dyn Fn(&PriorityMsg) -> Result<()> + Send + Sync + 'static>;

/// Returns a copy of the message signed by `privkey`.
///
/// The signature field is cleared before hashing so the signature covers the
/// message content only.
pub fn sign_msg(msg: &PriorityMsg, privkey: &SecretKey) -> Result<PriorityMsg> {
    let mut clone = msg.clone();
    clone.signature = Default::default();

    let hash = hash_proto(&clone).map_err(Error::HashProto)?;
    let sig = pluto_k1util::sign(privkey, &hash).map_err(Error::Sign)?;

    clone.signature = sig.to_vec().into();

    Ok(clone)
}

/// Returns whether `msg` was signed by `pubkey`.
///
/// Errors on an empty signature or on a recovery failure; a recovered key that
/// does not match `pubkey` returns `Ok(false)`.
pub(crate) fn verify_msg_sig(msg: &PriorityMsg, pubkey: &PublicKey) -> Result<bool> {
    if msg.signature.is_empty() {
        return Err(Error::EmptySignature);
    }

    let mut clone = msg.clone();
    clone.signature = Default::default();

    let hash = hash_proto(&clone).map_err(Error::HashProto)?;
    let recovered = pluto_k1util::recover(&hash, &msg.signature).map_err(Error::Recover)?;

    Ok(&recovered == pubkey)
}

/// Returns a verifier that checks message signatures against the public keys of
/// the provided peers.
///
/// The verifier rejects messages with missing duty fields, from unknown peers,
/// or with invalid signatures.
pub(crate) fn new_msg_verifier(peers: &[PeerId]) -> Result<MsgVerifier> {
    let mut keys: HashMap<String, PublicKey> = HashMap::with_capacity(peers.len());
    for peer in peers {
        let pk = peer_id_to_public_key(peer).map_err(Error::PeerKey)?;
        keys.insert(peer.to_string(), pk);
    }

    Ok(Box::new(move |msg: &PriorityMsg| {
        if msg.duty.is_none() {
            return Err(Error::InvalidMsgProtoFields);
        }

        let Some(key) = keys.get(&msg.peer_id) else {
            return Err(Error::UnknownPeerId);
        };

        if verify_msg_sig(msg, key)? {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }))
}

/// Packs a string as an `Any`-wrapped structpb string value.
fn string_to_any(s: &str) -> Any {
    let value = Value {
        kind: Some(Kind::StringValue(s.to_owned())),
    };

    Any {
        type_url: VALUE_TYPE_URL.to_owned(),
        value: value.encode_to_vec(),
    }
}

/// Returns the proto form of a topic proposal.
pub(crate) fn topic_proposal_to_proto(p: &TopicProposal) -> PriorityTopicProposal {
    PriorityTopicProposal {
        topic: Some(string_to_any(&p.topic)),
        priorities: p.priorities.iter().map(|s| string_to_any(s)).collect(),
    }
}

impl TryFrom<&PriorityTopicResult> for TopicResult {
    type Error = Error;

    /// Errors if an `Any` envelope is missing or carries the wrong message
    /// type, or if any topic or priority value is not a structpb string.
    fn try_from(p: &PriorityTopicResult) -> Result<Self> {
        let topic_val =
            unmarshal_value(p.topic.as_ref()).map_err(|e| Error::AnypbTopic(Box::new(e)))?;
        let topic = value_string(topic_val)?;

        let mut priorities = Vec::with_capacity(p.priorities.len());
        for scored in &p.priorities {
            let prio_val = unmarshal_value(scored.priority.as_ref())
                .map_err(|e| Error::AnypbPriority(Box::new(e)))?;
            let prio = value_string(prio_val)?;
            priorities.push(ScoredPriority {
                priority: prio,
                score: scored.score,
            });
        }

        Ok(Self { topic, priorities })
    }
}

/// Unpacks an optional `Any` envelope into a structpb [`Value`].
///
/// Rejects an absent envelope, or one whose `type_url` does not name
/// `google.protobuf.Value`, as a mismatched message type
/// ([`Error::MismatchedMessageType`]) before decoding. Only the path segment
/// after the last `/` of the `type_url` is significant, matching the identity
/// check applied when unpacking an `Any`.
fn unmarshal_value(any: Option<&Any>) -> Result<Value> {
    let any = any.ok_or(Error::MismatchedMessageType)?;

    let type_name = any.type_url.rsplit('/').next().unwrap_or(&any.type_url);
    if type_name != "google.protobuf.Value" {
        return Err(Error::MismatchedMessageType);
    }

    Value::decode(any.value.as_slice()).map_err(Error::DecodeAny)
}

/// Extracts the string from a structpb [`Value`].
///
/// Returns [`Error::TopicValueNotString`] when the value is not a structpb
/// string.
fn value_string(value: Value) -> Result<String> {
    match value.kind {
        Some(Kind::StringValue(s)) => Ok(s),
        _ => Err(Error::TopicValueNotString),
    }
}

/// Friendly-API output subscriber invoked with each decided duty result.
///
/// The boxed error is propagated back through the consensus subscription chain.
pub type ComponentSubscriber = Box<
    dyn Fn(Duty, Vec<TopicResult>) -> std::result::Result<(), crate::consensus::ConsensusError>
        + Send
        + Sync
        + 'static,
>;

/// Wraps a [`Prioritiser`] with the friendly string-based API and message
/// signing, hiding the underlying protobuf types.
pub struct Component {
    peer_id: PeerId,
    privkey: SecretKey,
    prioritiser: Prioritiser,
    calculator: Arc<dyn DeadlineCalculator>,
    /// Drives the deadliner's expired-duty channel; consumed once by [`start`].
    ///
    /// [`start`]: Component::start
    expired: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Duty>>>,
}

/// Constructs a priority [`Component`] and the libp2p [`Behaviour`] to register
/// with the swarm.
///
/// Builds the message verifier from `peers`, spawns a deadliner driven by
/// `calculator`, and wires the prioritiser. The caller must register the
/// returned behaviour with its swarm and call [`Component::start`] exactly
/// once.
#[allow(clippy::too_many_arguments)]
pub fn new_component(
    ctx: CancellationToken,
    local_id: PeerId,
    peers: Vec<PeerId>,
    min_required: i64,
    consensus: Arc<dyn Consensus>,
    exchange_timeout: Duration,
    privkey: SecretKey,
    calculator: impl DeadlineCalculator,
) -> Result<(Component, Behaviour)> {
    let verifier = new_msg_verifier(&peers)?;
    let calculator: Arc<dyn DeadlineCalculator> = Arc::new(calculator);

    let (deadliner, expired) = DeadlinerTask::start(ctx, "priority", calculator.clone());

    let (prioritiser, behaviour) = Prioritiser::new_internal(
        local_id,
        peers,
        min_required,
        consensus,
        verifier,
        exchange_timeout,
        deadliner,
    );

    let component = Component {
        peer_id: local_id,
        privkey,
        prioritiser,
        calculator,
        expired: std::sync::Mutex::new(Some(expired)),
    };

    Ok((component, behaviour))
}

impl Component {
    /// Starts the prioritiser's state-cleanup loop. Must be called exactly
    /// once.
    ///
    /// Consumes the deadliner's expired-duty receiver, which can only be taken
    /// once.
    ///
    /// # Panics
    /// Panics if called more than once.
    pub fn start(&self, ctx: CancellationToken) {
        let expired = self
            .expired
            .lock()
            .expect("expired receiver mutex poisoned")
            .take()
            .expect("Component::start called more than once");
        self.prioritiser.start(ctx, expired);
    }

    /// Registers a friendly output subscriber.
    ///
    /// The subscriber receives the decided result as domain [`TopicResult`]s;
    /// proto conversion errors short-circuit and propagate to consensus.
    pub fn subscribe(&self, sub: ComponentSubscriber) {
        let inner: PrioritySubscriber = Box::new(move |duty, result| {
            let mut results = Vec::with_capacity(result.topics.len());
            for topic in &result.topics {
                let r = TopicResult::try_from(topic)
                    .map_err(|e| -> crate::consensus::ConsensusError { Box::new(e) })?;
                results.push(r);
            }
            sub(duty, results)
        });
        self.prioritiser.subscribe(inner);
    }

    /// Starts a prioritisation instance for `duty` with the given proposals.
    ///
    /// Returns [`Error::DutyAlreadyExpired`] if the duty has no future
    /// deadline. Returns `Ok(())` when `ctx` is cancelled, otherwise
    /// propagates a prioritiser error.
    pub async fn prioritise(
        &self,
        ctx: CancellationToken,
        duty: Duty,
        proposals: &[TopicProposal],
    ) -> Result<()> {
        let topics = proposals.iter().map(topic_proposal_to_proto).collect();

        // Derive a per-instance deadline context. A future deadline is
        // required; absent or past means the duty already expired.
        let deadline = self
            .calculator
            .deadline(&duty)
            .ok()
            .flatten()
            .ok_or(Error::DutyAlreadyExpired)?;

        let msg = PriorityMsg {
            duty: Some(duty_to_proto(&duty)),
            peer_id: self.peer_id.to_string(),
            topics,
            signature: Default::default(),
        };
        let msg = sign_msg(&msg, &self.privkey)?;

        // Bound the instance by the duty deadline. The token is cancelled (not
        // merely dropped) on elapse so the prioritiser's detached consensus task,
        // which holds a clone of it, also tears down.
        let instance_ctx = ctx.child_token();
        let remaining = deadline
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(Duration::ZERO);

        let res = tokio::select! {
            res = self.prioritiser.prioritise(instance_ctx.clone(), msg) => res,
            () = tokio::time::sleep(remaining) => {
                instance_ctx.cancel();
                return Ok(());
            }
        };

        // A cancelled instance — parent context or deadline — is a graceful stop.
        if instance_ctx.is_cancelled() {
            return Ok(());
        }
        // A non-cancelled failure carries the duty as context.
        res.map_err(|e| Error::Prioritise {
            duty,
            source: Box::new(e),
        })
    }
}

#[cfg(test)]
mod tests {
    use pluto_core::corepb::v1::{core::Duty, priority::PriorityScoredResult};

    use super::*;

    /// Builds an unsigned message for the given peer id with one empty topic.
    fn unsigned_msg(peer_id: &str) -> PriorityMsg {
        PriorityMsg {
            duty: Some(Duty { slot: 1, r#type: 0 }),
            topics: vec![topic_proposal_to_proto(&TopicProposal {
                topic: "versions".to_owned(),
                priorities: vec!["v1".to_owned(), "v2".to_owned()],
            })],
            peer_id: peer_id.to_owned(),
            signature: Default::default(),
        }
    }

    fn random_key() -> SecretKey {
        SecretKey::random(&mut k256::elliptic_curve::rand_core::OsRng)
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = random_key();
        let peer_id = peer_id_from_secret(&key);

        let signed = sign_msg(&unsigned_msg(&peer_id.to_string()), &key).expect("sign");
        assert!(!signed.signature.is_empty(), "signature populated");

        assert!(verify_msg_sig(&signed, &key.public_key()).expect("verify"));
    }

    #[test]
    fn verify_tampered_signature() {
        let key = random_key();
        let peer_id = peer_id_from_secret(&key);

        let mut signed = sign_msg(&unsigned_msg(&peer_id.to_string()), &key).expect("sign");
        // Tamper with the content; the signature no longer covers it.
        signed.peer_id = "tampered".to_owned();

        // Recovered key differs from the signer's key.
        assert!(!verify_msg_sig(&signed, &key.public_key()).expect("verify"));
    }

    #[test]
    fn verify_empty_signature() {
        let key = random_key();
        assert!(matches!(
            verify_msg_sig(&unsigned_msg("0"), &key.public_key()),
            Err(Error::EmptySignature)
        ));
    }

    #[test]
    fn msg_verifier_round_trip() {
        let key = random_key();
        let peer_id = peer_id_from_secret(&key);
        let verifier = new_msg_verifier(&[peer_id]).expect("verifier");

        let signed = sign_msg(&unsigned_msg(&peer_id.to_string()), &key).expect("sign");
        verifier(&signed).expect("known peer + valid signature");
    }

    #[test]
    fn msg_verifier_unknown_peer() {
        let known = random_key();
        let other = random_key();
        let known_id = peer_id_from_secret(&known);
        let verifier = new_msg_verifier(&[known_id]).expect("verifier");

        let other_id = peer_id_from_secret(&other);
        let signed = sign_msg(&unsigned_msg(&other_id.to_string()), &other).expect("sign");

        assert!(matches!(verifier(&signed), Err(Error::UnknownPeerId)));
    }

    #[test]
    fn msg_verifier_invalid_signature() {
        let key = random_key();
        let peer_id = peer_id_from_secret(&key);
        let verifier = new_msg_verifier(&[peer_id]).expect("verifier");

        // Signed by a different key but claiming the known peer id.
        let attacker = random_key();
        let signed = sign_msg(&unsigned_msg(&peer_id.to_string()), &attacker).expect("sign");

        assert!(matches!(verifier(&signed), Err(Error::InvalidSignature)));
    }

    #[test]
    fn msg_verifier_missing_duty() {
        let key = random_key();
        let peer_id = peer_id_from_secret(&key);
        let verifier = new_msg_verifier(&[peer_id]).expect("verifier");

        let mut msg = sign_msg(&unsigned_msg(&peer_id.to_string()), &key).expect("sign");
        msg.duty = None;

        assert!(matches!(verifier(&msg), Err(Error::InvalidMsgProtoFields)));
    }

    #[test]
    fn structpb_round_trip() {
        let proposal = TopicProposal {
            topic: "versions".to_owned(),
            priorities: vec!["v1".to_owned(), "v2".to_owned()],
        };
        let proto = topic_proposal_to_proto(&proposal);

        // Build a topic result from the proposal to exercise unpacking.
        let result_proto = PriorityTopicResult {
            topic: proto.topic.clone(),
            priorities: proto
                .priorities
                .iter()
                .enumerate()
                .map(|(i, any)| PriorityScoredResult {
                    priority: Some(any.clone()),
                    score: i64::try_from(i).expect("test index fits i64"),
                })
                .collect(),
        };

        let result = TopicResult::try_from(&result_proto).expect("from proto");
        assert_eq!(result.topic, "versions");
        assert_eq!(result.priorities_only(), vec!["v1", "v2"]);
        assert_eq!(result.priorities[0].score, 0);
        assert_eq!(result.priorities[1].score, 1);
    }

    #[test]
    fn topic_result_from_proto_non_string() {
        // Pack a non-string structpb value (number) into the topic Any.
        let number = Value {
            kind: Some(Kind::NumberValue(1.0)),
        };
        let result_proto = PriorityTopicResult {
            topic: Some(Any {
                type_url: VALUE_TYPE_URL.to_owned(),
                value: number.encode_to_vec(),
            }),
            priorities: Vec::new(),
        };

        assert!(matches!(
            TopicResult::try_from(&result_proto),
            Err(Error::TopicValueNotString)
        ));
    }

    #[test]
    fn topic_result_from_proto_wrong_type_url() {
        // Valid StringValue bytes but an envelope naming the wrong message type.
        let value = Value {
            kind: Some(Kind::StringValue("v1".to_owned())),
        };
        let result_proto = PriorityTopicResult {
            topic: Some(Any {
                type_url: "type.googleapis.com/google.protobuf.Duration".to_owned(),
                value: value.encode_to_vec(),
            }),
            priorities: Vec::new(),
        };

        assert!(matches!(
            TopicResult::try_from(&result_proto),
            Err(Error::AnypbTopic(_))
        ));
    }

    #[test]
    fn topic_result_from_proto_missing_topic() {
        // Absent topic Any is rejected like a nil envelope.
        let result_proto = PriorityTopicResult {
            topic: None,
            priorities: Vec::new(),
        };

        assert!(matches!(
            TopicResult::try_from(&result_proto),
            Err(Error::AnypbTopic(_))
        ));
    }

    #[test]
    fn topic_result_from_proto_missing_priority() {
        // A present topic but an absent priority Any is rejected as priority.
        let topic = string_to_any("versions");
        let result_proto = PriorityTopicResult {
            topic: Some(topic),
            priorities: vec![PriorityScoredResult {
                priority: None,
                score: 1,
            }],
        };

        assert!(matches!(
            TopicResult::try_from(&result_proto),
            Err(Error::AnypbPriority(_))
        ));
    }

    /// Derives a libp2p `PeerId` from a secp256k1 secret key.
    fn peer_id_from_secret(key: &SecretKey) -> PeerId {
        pluto_p2p::peer::peer_id_from_key(key.public_key()).expect("peer id from key")
    }
}
