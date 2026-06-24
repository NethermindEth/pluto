//! Deterministic cluster-wide priority result calculation and message
//! validation for the priority protocol.

use std::collections::{HashMap, HashSet};

use pluto_consensus::qbft::msg::hash_proto_bytes;
use pluto_core::corepb::v1::priority::{
    PriorityMsg, PriorityResult, PriorityScoredResult, PriorityTopicProposal, PriorityTopicResult,
};
use pluto_ssz::HashRoot;
use prost::Message;
use prost_types::Any;

use crate::error::{Error, Result};

/// Maximum number of priorities allowed per topic.
const MAX_PRIORITIES: usize = 1000;
/// Weight applied to peer count so it dominates relative priority ordering.
///
/// Equals [`MAX_PRIORITIES`] so that one extra supporting peer always outweighs
/// any relative-priority difference (which is bounded by `MAX_PRIORITIES`).
/// `MAX_PRIORITIES` is a small compile-time constant that fits an `i64`.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
const COUNT_WEIGHT: i64 = MAX_PRIORITIES as i64;

/// Returns the SSZ hash root of an `Any` envelope's deterministic protobuf
/// encoding.
///
/// The priority protocol treats topics and priorities as opaque `Any` values
/// and binds equality to the encoded envelope (`type_url` + `value`), so the
/// envelope bytes are hashed directly rather than the inner concrete message.
fn hash_any(any: &Any) -> Result<HashRoot> {
    let encoded = any.encode_to_vec();
    hash_proto_bytes(&encoded).map_err(Error::HashProto)
}

/// Returns the cluster-wide priorities given the priorities of each peer.
///
/// Priorities are included in the result if at least `min_required` peers
/// provided them and are ordered by number of peers, then by overall priority.
/// The output is deterministic regardless of input message order.
pub(crate) fn calculate_result(msgs: &[PriorityMsg], min_required: i64) -> Result<PriorityResult> {
    validate_msgs(msgs)?;

    // Group all priority sets by topic. Grouping order is irrelevant: each
    // topic is scored independently and `order_topic_results` sorts the final
    // results by topic hash, so determinism rests on that final sort.
    let mut proposals_by_topic: HashMap<HashRoot, Vec<&PriorityTopicProposal>> = HashMap::new();

    for msg in sort_input(msgs) {
        for topic in &msg.topics {
            let topic_hash = hash_any(topic_any(topic))?;
            proposals_by_topic
                .entry(topic_hash)
                .or_default()
                .push(topic);
        }
    }

    // Minimum required score: priorities supported by fewer peers are dropped.
    let min_score = min_required.saturating_sub(1).saturating_mul(COUNT_WEIGHT);

    let mut topic_results: Vec<PriorityTopicResult> = Vec::new();

    for proposals in proposals_by_topic.values() {
        // Accumulate overall score per priority, ordering by count then by
        // relative priority. First-seen order is preserved for tie breaking.
        let mut all_priorities: Vec<HashRoot> = Vec::new();
        let mut scores: HashMap<HashRoot, i64> = HashMap::new();
        let mut priorities: HashMap<HashRoot, Any> = HashMap::new();

        for proposal in proposals {
            for (order, prio) in proposal.priorities.iter().enumerate() {
                let prio_hash = hash_any(prio)?;

                if !scores.contains_key(&prio_hash) {
                    all_priorities.push(prio_hash);
                }

                // `order` is bounded below MAX_PRIORITIES by validate_msgs, so
                // it fits in i64 and never exceeds COUNT_WEIGHT.
                let weight = COUNT_WEIGHT.saturating_sub(i64::try_from(order).unwrap_or(i64::MAX));
                let score = scores.entry(prio_hash).or_insert(0);
                *score = score.saturating_add(weight);
                priorities.insert(prio_hash, prio.clone());
            }
        }

        // Order by score decreasing. A stable sort preserves first-seen order
        // for equal scores (input is pre-sorted by peer id), so the output is
        // deterministic and internally consistent.
        all_priorities.sort_by(|a, b| scores[b].cmp(&scores[a]));

        let mut result = PriorityTopicResult {
            topic: proposals[0].topic.clone(),
            priorities: Vec::new(),
        };

        for prio_hash in &all_priorities {
            let score = scores[prio_hash];
            if score <= min_score {
                continue;
            }

            result.priorities.push(PriorityScoredResult {
                priority: Some(priorities[prio_hash].clone()),
                score,
            });
        }

        topic_results.push(result);
    }

    let ordered = order_topic_results(topic_results)?;

    Ok(PriorityResult {
        msgs: msgs.to_vec(),
        topics: ordered,
    })
}

/// Returns topic results ordered by topic hash for deterministic output.
fn order_topic_results(values: Vec<PriorityTopicResult>) -> Result<Vec<PriorityTopicResult>> {
    let mut tuples: Vec<(HashRoot, PriorityTopicResult)> = Vec::with_capacity(values.len());
    for value in values {
        let hash = hash_any(topic_result_any(&value))?;
        tuples.push((hash, value));
    }

    tuples.sort_by_key(|t| t.0);

    Ok(tuples.into_iter().map(|(_, value)| value).collect())
}

/// Returns a copy of the messages ordered by peer id.
fn sort_input(msgs: &[PriorityMsg]) -> Vec<&PriorityMsg> {
    let mut resp: Vec<&PriorityMsg> = msgs.iter().collect();
    resp.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
    resp
}

/// Validates the priority messages, rejecting:
///   - empty message sets,
///   - duplicate peers,
///   - mismatching duties,
///   - duplicate topics within a peer,
///   - more than 1000 priorities within a topic,
///   - duplicate priorities within a topic.
fn validate_msgs(msgs: &[PriorityMsg]) -> Result<()> {
    if msgs.is_empty() {
        return Err(Error::MessagesEmpty);
    }

    // All messages must carry the same duty; compare each against the first
    // (`msgs` is non-empty, checked above).
    let duty = &msgs[0].duty;
    let mut dedup_peers: HashSet<String> = HashSet::new();

    for msg in msgs {
        if msg.duty != *duty {
            return Err(Error::MismatchingDuties);
        }

        if !dedup_peers.insert(msg.peer_id.clone()) {
            return Err(Error::DuplicatePeer);
        }

        let mut dedup_topics: HashSet<HashRoot> = HashSet::new();

        for topic in &msg.topics {
            let topic_hash = hash_any(topic_any(topic))?;

            if !dedup_topics.insert(topic_hash) {
                return Err(Error::DuplicateTopic);
            } else if topic.priorities.len() >= MAX_PRIORITIES {
                return Err(Error::MaxPriorityReached);
            }

            let mut dedup_priority: HashSet<HashRoot> = HashSet::new();

            for priority in &topic.priorities {
                let prio_hash = hash_any(priority)?;
                if !dedup_priority.insert(prio_hash) {
                    return Err(Error::DuplicatePriority);
                }
            }
        }
    }

    Ok(())
}

/// Returns the topic's `Any`, treating an absent topic as the empty `Any`.
///
/// An unset topic and a default `Any` both encode to empty bytes, so they hash
/// identically; using the shared empty `Any` keeps that equivalence explicit.
fn topic_any(topic: &PriorityTopicProposal) -> &Any {
    topic.topic.as_ref().unwrap_or(&EMPTY_ANY)
}

/// See [`topic_any`]: yields the empty `Any` for an absent topic result topic.
fn topic_result_any(result: &PriorityTopicResult) -> &Any {
    result.topic.as_ref().unwrap_or(&EMPTY_ANY)
}

/// Shared empty `Any` used as the hash input for an unset topic.
static EMPTY_ANY: Any = Any {
    type_url: String::new(),
    value: Vec::new(),
};

#[cfg(test)]
mod tests {
    use pluto_core::corepb::v1::core::{Duty, ParSignedData};
    use rand::seq::SliceRandom;
    use test_case::test_case;

    use super::*;

    /// Quorum used by `TestCalculateResults` (not accurate, illustrative).
    const Q: i64 = 3;

    /// Wraps a string as an `Any` of `ParSignedData{data: s}`.
    fn to_any(s: &str) -> Any {
        Any::from_msg(&ParSignedData {
            data: s.as_bytes().to_vec().into(),
            ..Default::default()
        })
        .expect("pack ParSignedData")
    }

    /// Wraps each string as an `Any` of `ParSignedData{data}`.
    fn to_anys(ss: &[&str]) -> Vec<Any> {
        ss.iter().map(|s| to_any(s)).collect()
    }

    /// Extracts the string from an `Any` of `ParSignedData`.
    fn from_any(a: &Any) -> String {
        let psd: ParSignedData = a.to_msg().expect("unpack ParSignedData");
        String::from_utf8(psd.data.to_vec()).expect("utf8 data")
    }

    /// Builds the priority messages for a calculate test case from a list of
    /// per-peer priority sets and a slot.
    fn build_msgs(priority_sets: &[&[&str]], slot: u64) -> Vec<PriorityMsg> {
        let topic = to_any("versions");
        let ignored = to_any("ignored");

        priority_sets
            .iter()
            .enumerate()
            .map(|(j, set)| PriorityMsg {
                duty: Some(Duty { slot, r#type: 0 }),
                topics: vec![
                    PriorityTopicProposal {
                        topic: Some(topic.clone()),
                        priorities: to_anys(set),
                    },
                    PriorityTopicProposal {
                        topic: Some(ignored.clone()),
                        priorities: Vec::new(),
                    },
                ],
                peer_id: j.to_string(),
                signature: Vec::new().into(),
            })
            .collect()
    }

    // Calculate-result cases. Each case is the priority sets per peer, the
    // expected ordered result strings, and the expected scores (empty when the
    // result is empty).
    #[test_case(&[&["v1"]], &[], &[], 0; "1*v1")]
    #[test_case(&[&["v1"], &["v1"]], &[], &[], 1; "Q-1*v1")]
    #[test_case(&[&["v1"], &["v1"], &["v1"]], &["v1"], &[3000], 2; "Q*v1")]
    #[test_case(&[&["v1"], &["v1"], &["v1"], &["v1"], &["v1"]], &["v1"], &[5000], 3; "N*v1")]
    #[test_case(&[&["v1"], &["v1"], &["v1"], &["v1"], &["v2", "v1"]], &["v1"], &[4999], 4; "N-1*v1,1*v2")]
    #[test_case(&[&["v1"], &["v1"], &["v2", "v1"], &["v2", "v1"], &["v2", "v1"]], &["v1", "v2"], &[4997, 3000], 5; "N-Q*v1,Q*v2")]
    #[test_case(&[&["v2", "v1"], &["v2", "v1"], &["v2", "v1"], &["v2", "v1"], &["v2", "v1"]], &["v2", "v1"], &[5000, 4995], 6; "N*v2")]
    #[test_case(&[&["v2", "v1"], &["v2", "v1"], &["v2", "v1"], &["v2", "v1"]], &["v2", "v1"], &[4000, 3996], 7; "N-1*v2,1*down")]
    #[test_case(&[&["v2", "v1"], &["v2", "v1"]], &[], &[], 8; "Q-1*v2,3*down")]
    #[test_case(&[&["v1"], &["v2", "v1"], &["v2", "v1"], &["v2", "v1"], &["v2", "v1"]], &["v1", "v2"], &[4996, 4000], 9; "1*v1,N-1*v2")]
    #[test_case(&[&["v1"], &["v2", "v1"], &["v2", "v1"], &["v2", "v1"]], &["v1", "v2"], &[3997, 3000], 10; "1*v1,N-2*v2,1*down")]
    #[test_case(&[&["v1"], &["v2", "v1"], &["v2", "v1"]], &["v1"], &[2998], 11; "1*v1,Q-1*v2,2*down")]
    #[test_case(&[&["v1"], &["v2", "v1"], &["v2", "v1"], &["v2", "v1"], &["v3", "v2"]], &["v2", "v1"], &[3999, 3997], 12; "1*v1,N-2*v2,1*v3")]
    #[test_case(&[&["v1"], &["v1"], &["v2", "v1"], &["v2", "v1"], &["v3", "v2"]], &["v1", "v2"], &[3998, 2999], 13; "2*v1,N-3*v2,1*v3")]
    #[test_case(&[&["v1"], &["v2", "v1"], &["v3", "v2"], &["v3", "v2"], &["v3", "v2"]], &["v2", "v3"], &[3997, 3000], 14; "1*v1,1*v2,Q*v3")]
    #[test_case(&[&["v1"], &["v1"], &["v3", "v2"], &["v3", "v2"], &["v3", "v2"]], &["v3", "v2"], &[3000, 2997], 15; "2*v1,Q*v3")]
    #[test_case(&[&["x", "y"], &["x", "y"], &["y", "x"], &["y", "x"]], &["x", "y"], &[3998, 3998], 1; "deterministic ordering instance 1")]
    #[test_case(&[&["x", "y"], &["x", "y"], &["y", "x"], &["y", "x"]], &["x", "y"], &[3998, 3998], 9; "deterministic ordering instance 9")]
    fn calculate_results(
        priority_sets: &[&[&str]],
        expected_result: &[&str],
        expected_scores: &[i64],
        slot: u64,
    ) {
        let topic = to_any("versions");
        let mut msgs = build_msgs(priority_sets, slot);

        // Shuffle since the function must be deterministic.
        msgs.shuffle(&mut rand::thread_rng());

        let result = calculate_result(&msgs, Q).expect("calculate");
        assert_eq!(result.topics.len(), 2, "two topics (versions + ignored)");

        let topic_result = result
            .topics
            .iter()
            .find(|t| t.topic.as_ref() == Some(&topic))
            .expect("versions topic present");

        if expected_result.is_empty() {
            assert!(
                topic_result.priorities.is_empty(),
                "expected empty priorities, got {:?}",
                topic_result.priorities
            );
            return;
        }

        let actual_result: Vec<String> = topic_result
            .priorities
            .iter()
            .map(|p| from_any(p.priority.as_ref().expect("priority any")))
            .collect();
        let actual_scores: Vec<i64> = topic_result.priorities.iter().map(|p| p.score).collect();

        let expected_result: Vec<String> = expected_result.iter().map(|s| s.to_string()).collect();
        assert_eq!(actual_result, expected_result, "result ordering");

        if !expected_scores.is_empty() {
            assert_eq!(actual_scores, expected_scores, "scores");
        }
    }

    /// Helper to build a single valid message with one topic and given peer id.
    fn msg(peer_id: &str, slot: u64, priorities: &[&str]) -> PriorityMsg {
        PriorityMsg {
            duty: Some(Duty { slot, r#type: 0 }),
            topics: vec![PriorityTopicProposal {
                topic: Some(to_any("versions")),
                priorities: to_anys(priorities),
            }],
            peer_id: peer_id.to_string(),
            signature: Vec::new().into(),
        }
    }

    #[test]
    fn validate_empty() {
        assert!(matches!(
            calculate_result(&[], Q),
            Err(Error::MessagesEmpty)
        ));
    }

    #[test]
    fn validate_mismatching_duties() {
        let msgs = vec![msg("0", 1, &["v1"]), msg("1", 2, &["v1"])];
        assert!(matches!(
            calculate_result(&msgs, Q),
            Err(Error::MismatchingDuties)
        ));
    }

    #[test]
    fn validate_duplicate_peer() {
        let msgs = vec![msg("0", 1, &["v1"]), msg("0", 1, &["v2"])];
        assert!(matches!(
            calculate_result(&msgs, Q),
            Err(Error::DuplicatePeer)
        ));
    }

    #[test]
    fn validate_duplicate_topic() {
        let mut m = msg("0", 1, &["v1"]);
        m.topics.push(PriorityTopicProposal {
            topic: Some(to_any("versions")),
            priorities: to_anys(&["v2"]),
        });
        assert!(matches!(
            calculate_result(&[m], Q),
            Err(Error::DuplicateTopic)
        ));
    }

    #[test]
    fn validate_max_priority_reached() {
        let priorities: Vec<Any> = (0..MAX_PRIORITIES)
            .map(|i| to_any(&i.to_string()))
            .collect();
        let m = PriorityMsg {
            duty: Some(Duty { slot: 1, r#type: 0 }),
            topics: vec![PriorityTopicProposal {
                topic: Some(to_any("versions")),
                priorities,
            }],
            peer_id: "0".to_string(),
            signature: Vec::new().into(),
        };
        assert!(matches!(
            calculate_result(&[m], Q),
            Err(Error::MaxPriorityReached)
        ));
    }

    #[test]
    fn validate_duplicate_priority() {
        let m = msg("0", 1, &["v1", "v1"]);
        assert!(matches!(
            calculate_result(&[m], Q),
            Err(Error::DuplicatePriority)
        ));
    }
}
