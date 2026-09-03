//! # Infosync
//!
//! A simple use-case of the [priority protocol](pluto_priority) that
//! prioritises cluster-wide supported versions, protocols, and proposal types.
//!
//! Each epoch the node triggers a prioritisation across the cluster (via
//! [`Component::trigger`]); the resulting cluster-agreed values are stored per
//! slot and queried with [`Component::protocols`] and [`Component::proposals`].

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use pluto_core::{
    types::{Duty, ProposalType, SlotNumber},
    version::SemVer,
};
use pluto_featureset::{Feature, FeatureSet};
use pluto_priority::{Component as Prioritiser, TopicProposal, TopicResult};
use tokio_util::sync::CancellationToken;

/// Priority topic carrying the cluster's supported [`SemVer`] versions.
const TOPIC_VERSION: &str = "version";
/// Priority topic carrying the cluster's supported protocol ids.
///
/// Exported so callers (e.g. consensus-protocol selection) can match results by
/// topic.
pub const TOPIC_PROTOCOL: &str = "protocol";
/// Priority topic carrying the cluster's supported [`ProposalType`]s.
const TOPIC_PROPOSAL: &str = "proposal";

/// Eviction threshold for stored results. The oldest entry is dropped once the
/// stored count reaches this value (a `>=` check), so the retained history is
/// effectively capped at `MAX_RESULTS - 1` (99).
const MAX_RESULTS: usize = 100;

/// Mock alpha protocol appended when the `MockAlpha` feature is enabled, used
/// to exercise infosync in production.
const MOCK_ALPHA_PROTOCOL: &str = "/charon/mock_alpha/1.0.0";

/// A cluster-wide agreed-upon infosync result for a single slot.
#[derive(Clone, Debug, PartialEq, Eq)]
struct InfoResult {
    slot: SlotNumber,
    versions: Vec<String>,
    protocols: Vec<String>,
    proposals: Vec<ProposalType>,
}

/// Shared store of agreed-upon results, accessed by both the public getters and
/// the priority subscribe callback. Holds the local protocol list so
/// [`ResultStore::protocols`] can fall back to it when no result applies.
struct ResultStore {
    local_protocols: Vec<String>,
    results: Mutex<VecDeque<InfoResult>>,
}

impl ResultStore {
    fn new(local_protocols: Vec<String>) -> Self {
        Self {
            local_protocols,
            results: Mutex::new(VecDeque::new()),
        }
    }

    /// Folds a decided priority result into a stored [`InfoResult`].
    ///
    /// Versions and protocols are stored as their raw agreed wire strings;
    /// proposals are parsed into [`ProposalType`], with unrecognised values
    /// preserved as [`ProposalType::Unknown`] rather than dropped. The result
    /// is only stored when at least one version was agreed upon.
    fn handle_results(&self, duty: &Duty, results: &[TopicResult]) {
        let mut res = InfoResult {
            slot: duty.slot,
            versions: Vec::new(),
            protocols: Vec::new(),
            proposals: Vec::new(),
        };

        for result in results {
            for prio in result.priorities_only() {
                match result.topic.as_str() {
                    TOPIC_VERSION => res.versions.push(prio),
                    TOPIC_PROTOCOL => res.protocols.push(prio),
                    TOPIC_PROPOSAL => res.proposals.push(ProposalType::from(prio)),
                    _ => {}
                }
            }
        }

        tracing::debug!(slot = %duty.slot, ?results, "Infosync completed");

        if !res.versions.is_empty() {
            self.add_result(res);
        }
    }

    /// Adds a result unless it is identical to the most recent one. Once the
    /// stored count reaches [`MAX_RESULTS`] the oldest entry is dropped (see
    /// that constant for the resulting cap).
    fn add_result(&self, result: InfoResult) {
        let mut results = self
            .results
            .lock()
            .expect("infosync results mutex poisoned");

        if results.back() == Some(&result) {
            // Identical to previous, so don't add.
            return;
        }

        results.push_back(result);

        if results.len() >= MAX_RESULTS {
            results.pop_front();
        }
    }

    /// Latest cluster-wide supported protocols at or before `slot`, falling
    /// back to the local protocols when no earlier result exists.
    fn protocols(&self, slot: SlotNumber) -> Vec<String> {
        let results = self
            .results
            .lock()
            .expect("infosync results mutex poisoned");

        let idx = results.partition_point(|r| r.slot <= slot);
        idx.checked_sub(1)
            .and_then(|i| results.get(i))
            .map(|r| r.protocols.clone())
            .unwrap_or_else(|| self.local_protocols.clone())
    }

    /// Latest cluster-wide supported proposal types at or before `slot`,
    /// falling back to the default `[ProposalType::Full]` when no earlier
    /// result exists.
    fn proposals(&self, slot: SlotNumber) -> Vec<ProposalType> {
        let results = self
            .results
            .lock()
            .expect("infosync results mutex poisoned");

        let idx = results.partition_point(|r| r.slot <= slot);
        idx.checked_sub(1)
            .and_then(|i| results.get(i))
            .map(|r| r.proposals.clone())
            .unwrap_or_else(|| vec![ProposalType::Full])
    }
}

/// Infosync component: prioritises and tracks cluster-wide supported versions,
/// protocols, and proposal types.
pub struct Component {
    versions: Vec<SemVer>,
    proposals: Vec<ProposalType>,
    store: Arc<ResultStore>,
    prioritiser: Arc<Prioritiser>,
}

impl Component {
    /// Returns a new infosync component.
    ///
    /// Registers a subscriber on `prioritiser` that records decided results.
    /// The local `protocols` are augmented with a mock alpha protocol when the
    /// `MockAlpha` feature is enabled, to exercise infosync in production.
    pub fn new(
        prioritiser: Arc<Prioritiser>,
        versions: Vec<SemVer>,
        protocols: Vec<String>,
        proposals: Vec<ProposalType>,
        feature_set: &FeatureSet,
    ) -> Self {
        let store = Arc::new(ResultStore::new(augment_protocols(
            protocols,
            feature_set.enabled(Feature::MockAlpha),
        )));

        let cb_store = Arc::clone(&store);
        prioritiser.subscribe(Box::new(move |duty, results| {
            cb_store.handle_results(&duty, &results);
            Ok(())
        }));

        Self {
            versions,
            proposals,
            store,
            prioritiser,
        }
    }

    /// Returns the latest cluster-wide supported protocols at or before `slot`.
    ///
    /// Returns the local protocols if no earlier results are available.
    pub fn protocols(&self, slot: SlotNumber) -> Vec<String> {
        self.store.protocols(slot)
    }

    /// Returns the latest cluster-wide supported proposal types at or before
    /// `slot`.
    ///
    /// Returns the default `[ProposalType::Full]` if no earlier results are
    /// available. Values this binary does not recognise are preserved as
    /// [`ProposalType::Unknown`] rather than dropped.
    pub fn proposals(&self, slot: SlotNumber) -> Vec<ProposalType> {
        self.store.proposals(slot)
    }

    /// Triggers a cluster-wide prioritisation of the local versions, protocols,
    /// and proposal types for `slot`.
    pub async fn trigger(
        &self,
        ctx: CancellationToken,
        slot: SlotNumber,
    ) -> pluto_priority::Result<()> {
        let (duty, proposals) = build_request(
            &self.versions,
            &self.store.local_protocols,
            &self.proposals,
            slot,
        );

        self.prioritiser.prioritise(duty, &proposals, ctx).await
    }
}

/// Returns the versions as their string representations.
fn versions_to_strings(versions: &[SemVer]) -> Vec<String> {
    versions.iter().map(|v| v.to_string()).collect()
}

/// Returns the proposal types as their wire-format strings.
fn proposals_to_strings(proposals: &[ProposalType]) -> Vec<String> {
    proposals.iter().map(|p| p.as_str().to_owned()).collect()
}

/// Builds the info-sync duty and topic proposals sent by
/// [`Component::trigger`].
///
/// Split out as a free function so the wire payload — topics, priority
/// ordering, and the info-sync duty — is testable without a live prioritiser.
fn build_request(
    versions: &[SemVer],
    protocols: &[String],
    proposals: &[ProposalType],
    slot: SlotNumber,
) -> (Duty, Vec<TopicProposal>) {
    let topics = vec![
        TopicProposal {
            topic: TOPIC_VERSION.to_owned(),
            priorities: versions_to_strings(versions),
        },
        TopicProposal {
            topic: TOPIC_PROTOCOL.to_owned(),
            priorities: protocols.to_vec(),
        },
        TopicProposal {
            topic: TOPIC_PROPOSAL.to_owned(),
            priorities: proposals_to_strings(proposals),
        },
    ];

    (Duty::new_info_sync_duty(slot), topics)
}

/// Appends the mock alpha protocol when `mock_alpha` is enabled, used to
/// exercise infosync in production.
fn augment_protocols(mut protocols: Vec<String>, mock_alpha: bool) -> Vec<String> {
    if mock_alpha {
        protocols.push(MOCK_ALPHA_PROTOCOL.to_owned());
    }

    protocols
}

#[cfg(test)]
mod tests {
    use pluto_core::types::DutyType;
    use pluto_priority::ScoredPriority;

    use super::*;

    fn scored(values: &[&str]) -> Vec<ScoredPriority> {
        values
            .iter()
            .enumerate()
            .map(|(i, v)| ScoredPriority {
                priority: (*v).to_owned(),
                score: i64::try_from(i).expect("test index fits i64"),
            })
            .collect()
    }

    fn topic_result(topic: &str, values: &[&str]) -> TopicResult {
        TopicResult {
            topic: topic.to_owned(),
            priorities: scored(values),
        }
    }

    fn slot(n: u64) -> SlotNumber {
        SlotNumber::new(n)
    }

    fn info_result(
        s: u64,
        versions: &[&str],
        protocols: &[&str],
        proposals: &[&str],
    ) -> InfoResult {
        InfoResult {
            slot: slot(s),
            versions: versions.iter().map(|v| (*v).to_owned()).collect(),
            protocols: protocols.iter().map(|p| (*p).to_owned()).collect(),
            proposals: proposals.iter().map(|p| ProposalType::from(*p)).collect(),
        }
    }

    #[test]
    fn versions_to_strings_maps_display() {
        let versions = vec![
            SemVer::parse("v1.7").expect("valid"),
            SemVer::parse("v1.6").expect("valid"),
        ];
        assert_eq!(versions_to_strings(&versions), vec!["v1.7", "v1.6"]);
    }

    #[test]
    fn proposals_to_strings_maps_wire_format() {
        let proposals = vec![ProposalType::Builder, ProposalType::Full];
        assert_eq!(proposals_to_strings(&proposals), vec!["builder", "full"]);
    }

    #[test]
    fn augment_protocols_appends_mock_alpha_when_enabled() {
        let base = vec!["proto-a".to_owned()];
        assert_eq!(augment_protocols(base.clone(), false), vec!["proto-a"]);
        assert_eq!(
            augment_protocols(base, true),
            vec!["proto-a", MOCK_ALPHA_PROTOCOL]
        );
    }

    #[test]
    fn build_request_builds_infosync_duty_and_topic_proposals() {
        let versions = vec![SemVer::parse("v1.7").expect("valid")];
        let protocols = vec!["proto-a".to_owned(), "proto-b".to_owned()];
        let proposals = vec![ProposalType::Builder, ProposalType::Full];

        let (duty, topics) = build_request(&versions, &protocols, &proposals, slot(42));

        // The duty is the info-sync duty for the requested slot.
        assert_eq!(duty, Duty::new_info_sync_duty(slot(42)));
        assert_eq!(duty.duty_type, DutyType::InfoSync);

        // One topic proposal per dimension, in order, carrying wire strings.
        assert_eq!(topics.len(), 3);
        assert_eq!(topics[0].topic, TOPIC_VERSION);
        assert_eq!(topics[0].priorities, vec!["v1.7"]);
        assert_eq!(topics[1].topic, TOPIC_PROTOCOL);
        assert_eq!(topics[1].priorities, vec!["proto-a", "proto-b"]);
        assert_eq!(topics[2].topic, TOPIC_PROPOSAL);
        assert_eq!(topics[2].priorities, vec!["builder", "full"]);
    }

    #[test]
    fn protocols_defaults_to_local() {
        let store = ResultStore::new(vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(store.protocols(slot(10)), vec!["a", "b"]);
    }

    #[test]
    fn proposals_defaults_to_full() {
        let store = ResultStore::new(Vec::new());
        assert_eq!(store.proposals(slot(10)), vec![ProposalType::Full]);
    }

    #[test]
    fn getters_select_latest_result_at_or_before_slot() {
        let store = ResultStore::new(vec!["local".to_owned()]);
        store.add_result(info_result(5, &["v1.7"], &["p5"], &["builder"]));
        store.add_result(info_result(10, &["v1.7"], &["p10"], &["synthetic"]));

        // Before any result: local default / full default.
        assert_eq!(store.protocols(slot(4)), vec!["local"]);
        assert_eq!(store.proposals(slot(4)), vec![ProposalType::Full]);

        // At/after slot 5 but before 10: the slot-5 result.
        assert_eq!(store.protocols(slot(5)), vec!["p5"]);
        assert_eq!(store.proposals(slot(9)), vec![ProposalType::Builder]);

        // At/after slot 10: the slot-10 result.
        assert_eq!(store.protocols(slot(10)), vec!["p10"]);
        assert_eq!(store.proposals(slot(100)), vec![ProposalType::Synthetic]);
    }

    #[test]
    fn add_result_dedups_consecutive_identical() {
        let store = ResultStore::new(Vec::new());
        let r = info_result(1, &["v1.7"], &["p"], &["full"]);

        store.add_result(r.clone());
        store.add_result(r.clone());
        assert_eq!(store.results.lock().expect("lock").len(), 1);

        // A different result is appended.
        store.add_result(info_result(2, &["v1.7"], &["p"], &["full"]));
        assert_eq!(store.results.lock().expect("lock").len(), 2);

        // The same content as the last is again deduped.
        store.add_result(info_result(2, &["v1.7"], &["p"], &["full"]));
        assert_eq!(store.results.lock().expect("lock").len(), 2);
    }

    #[test]
    fn add_result_caps_history() {
        // Push well past MAX_RESULTS (100) with distinct slots.
        const PUSH_COUNT: u64 = 150;
        let store = ResultStore::new(Vec::new());
        for i in 0..PUSH_COUNT {
            store.add_result(info_result(i, &["v1.7"], &["p"], &["full"]));
        }

        let results = store.results.lock().expect("lock");
        assert!(
            results.len() < MAX_RESULTS,
            "history capped below MAX_RESULTS"
        );
        // Oldest entries were dropped; the newest slot (149) is retained.
        assert_eq!(results.back().expect("non-empty").slot, slot(149));
    }

    #[test]
    fn handle_results_routes_topics_and_stores() {
        let store = ResultStore::new(vec!["local".to_owned()]);
        let duty = Duty::new_info_sync_duty(slot(7));
        let results = vec![
            topic_result(TOPIC_VERSION, &["v1.7", "v1.6"]),
            topic_result(TOPIC_PROTOCOL, &["proto-a", "proto-b"]),
            topic_result(TOPIC_PROPOSAL, &["builder", "full"]),
        ];

        store.handle_results(&duty, &results);

        assert_eq!(store.protocols(slot(7)), vec!["proto-a", "proto-b"]);
        assert_eq!(
            store.proposals(slot(7)),
            vec![ProposalType::Builder, ProposalType::Full]
        );
    }

    #[test]
    fn handle_results_preserves_unknown_proposal_and_skips_unknown_topic() {
        let store = ResultStore::new(Vec::new());
        let duty = Duty::new_info_sync_duty(slot(1));
        let results = vec![
            topic_result(TOPIC_VERSION, &["v1.7"]),
            topic_result(TOPIC_PROPOSAL, &["builder", "future_type", "full"]),
            topic_result("unknown-topic", &["ignored"]),
        ];

        store.handle_results(&duty, &results);

        // Unknown proposal types are preserved as `Unknown` (not dropped); only
        // the unrecognised topic is ignored.
        assert_eq!(
            store.proposals(slot(1)),
            vec![
                ProposalType::Builder,
                ProposalType::Unknown("future_type".to_owned()),
                ProposalType::Full,
            ]
        );
    }

    #[test]
    fn handle_results_without_versions_is_not_stored() {
        let store = ResultStore::new(vec!["local".to_owned()]);
        let duty = Duty::new_info_sync_duty(slot(3));
        // No version topic → no agreed version → result discarded.
        let results = vec![topic_result(TOPIC_PROTOCOL, &["proto-a"])];

        store.handle_results(&duty, &results);

        assert!(store.results.lock().expect("lock").is_empty());
        // Falls back to local protocols since nothing was stored.
        assert_eq!(store.protocols(slot(3)), vec!["local"]);
    }
}
