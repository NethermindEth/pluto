//! On-chain inclusion checking for broadcast duties.
//!
//! [`InclusionCore`] caches duties as they are submitted to the beacon node
//! and, when fed observed blocks and attestations, determines whether each duty
//! landed on-chain. For every resolved duty it invokes the tracker callback
//! with either success or a [`InclusionError::NotIncludedOnChain`] error, and
//! reports inclusion delay / missed-duty metrics.
//!
//! The core is deliberately free of any beacon-node I/O so it can be driven
//! directly from tests. The networked driver that polls the beacon node and
//! builds the [`Block`] inputs is layered on top separately.

// TODO: The networked `InclusionChecker` that wires the default reporters and drives
// this core is added in a follow-up; until then some core items (default
// reporters, committee plumbing) have no in-crate caller.
#![allow(dead_code)]

use std::{any::Any, collections::HashMap, sync::Arc, time::Duration};

use pluto_eth2api::versioned;
use pluto_featureset::FeatureSet;
use pluto_ssz::{BitList, HashRoot};
use tree_hash::TreeHash;

use crate::{
    signeddata::{
        Attestation, SignedAggregateAndProof, SignedDataError, VersionedAttestation,
        VersionedSignedAggregateAndProof, VersionedSignedProposal,
    },
    tracker::{StepError, analysis::incl_supported, metrics::TRACKER_METRICS},
    types::{Duty, DutyType, PubKey, SignedData},
};

/// Number of slots after which an unincluded duty is assumed missed and its
/// cached submission (and associated committee state) is dropped.
const INCL_MISSED_LAG: u64 = 32;

/// SSZ capacity bound used only to decode aggregation bitlists for bit-level
/// comparisons. The bit operations (`contains`/`bit_at`) work on the decoded
/// length, so the concrete bound is irrelevant as long as it is an upper bound.
type AggBits = BitList<131_072>;

/// Tracker callback invoked when a duty's inclusion is resolved.
type TrackerInclFn = Box<dyn Fn(&Duty, PubKey, Option<StepError>) + Send>;
/// Callback invoked for duties broadcast but never included on-chain.
type MissedFn = Box<dyn Fn(&Submission) + Send>;
/// Callback invoked for attestations/aggregates observed on-chain.
type AttIncludedFn = Box<dyn Fn(&Submission, &Block) + Send>;

/// Errors produced while recording or checking duty inclusion.
#[derive(Debug, thiserror::Error)]
pub enum InclusionError {
    /// Submitted attester duty data was not an attestation.
    #[error("invalid attestation")]
    InvalidAttestation,
    /// Submitted aggregator duty data was not an aggregate-and-proof.
    #[error("invalid aggregate and proof")]
    InvalidAggregateAndProof,
    /// Submitted proposer duty data was not a versioned signed proposal.
    #[error("invalid block")]
    InvalidBlock,
    /// `DutyBuilderProposer` is deprecated and not tracked for inclusion.
    #[error("DutyBuilderProposer is deprecated and no longer supported")]
    DeprecatedDutyBuilderProposer,
    /// A broadcast duty was never observed on-chain.
    #[error("duty not included on-chain")]
    NotIncludedOnChain,
    /// The cached submission was not a versioned attestation.
    #[error("not an attestation block data")]
    NotAnAttestation,
    /// The cached submission was not a versioned aggregate-and-proof.
    #[error("parse VersionedSignedAggregateAndProof")]
    ParseVersionedAggregate,
    /// An Electra attestation lacked a validator index.
    #[error("no validator index in electra attestation")]
    NoValidatorIndex,
    /// No matching attester duty was found for an Electra attestation.
    #[error("no attester duty data found in electra attestation")]
    NoAttesterDuty,
    /// An Electra attestation did not reference exactly one committee.
    #[error("electra attestation must reference exactly one committee")]
    InvalidCommitteeBits,
    /// A versioned attestation carried no payload.
    #[error("missing attestation payload")]
    MissingAttestation,
    /// An aggregation-bits field could not be SSZ-decoded.
    #[error("decode aggregation bits")]
    DecodeAggregationBits,
    /// A bitfield comparison failed.
    #[error(transparent)]
    Bitfield(#[from] pluto_ssz::BitfieldError),
    /// A signed-data accessor failed.
    #[error(transparent)]
    SignedData(#[from] SignedDataError),
}

/// Uniquely identifies a cached submission.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SubKey {
    duty: Duty,
    pubkey: PubKey,
}

/// A duty submitted to the beacon node, awaiting on-chain confirmation.
pub struct Submission {
    /// The duty that produced this submission.
    pub duty: Duty,
    /// The validator the duty belongs to.
    pub pubkey: PubKey,
    /// The signed data broadcast to the beacon node.
    pub data: Box<dyn SignedData>,
    /// Hash-tree-root of the attestation data (zero for proposals).
    pub att_data_root: HashRoot,
    /// Delay between slot start and broadcast.
    pub delay: Duration,
}

/// A minimal attester duty, carrying only the fields used by inclusion checks.
#[derive(Clone)]
pub struct AttesterDuty {
    /// Validator index the duty belongs to.
    pub validator_index: u64,
    /// Index of the validator within its committee's aggregation bits.
    pub validator_committee_index: u64,
}

/// A beacon committee for a slot, carrying only the fields used by inclusion.
#[derive(Clone)]
pub struct BeaconCommittee {
    /// Committee index within the slot.
    pub index: u64,
    /// Validators assigned to this committee.
    pub validators: Vec<u64>,
}

/// A simplified observed block with its attestations and committee context.
pub struct Block {
    /// Slot of the block.
    pub slot: u64,
    /// Attester duties relevant to this slot (used for Electra inclusion).
    pub att_duties: Vec<AttesterDuty>,
    /// Block attestations keyed by their attestation-data root.
    pub attestations_by_data_root: HashMap<HashRoot, versioned::VersionedAttestation>,
    /// Beacon committees for the slot, ordered by committee index.
    pub beacon_committees: Vec<BeaconCommittee>,
}

/// Tracks the on-chain inclusion of submitted duties.
///
/// Holds a simplified, I/O-free API so it can be exercised directly in tests:
/// callers feed it blocks via [`InclusionCore::check_block`] /
/// [`InclusionCore::check_block_and_atts`] and trim stale state via
/// [`InclusionCore::trim`].
pub struct InclusionCore {
    submissions: HashMap<SubKey, Submission>,
    beacon_committees: HashMap<u64, Vec<BeaconCommittee>>,
    tracker_incl_fn: TrackerInclFn,
    missed_fn: MissedFn,
    att_included_fn: AttIncludedFn,
    feature_set: Arc<FeatureSet>,
}

impl InclusionCore {
    /// Creates a core with the production reporters ([`report_missed`] and
    /// [`report_att_inclusion`]) and the given tracker callback.
    pub fn new(tracker_incl_fn: TrackerInclFn, feature_set: Arc<FeatureSet>) -> Self {
        Self::with_handlers(
            tracker_incl_fn,
            Box::new(report_missed),
            Box::new(report_att_inclusion),
            feature_set,
        )
    }

    /// Creates a core with explicit reporter callbacks (used by tests).
    pub fn with_handlers(
        tracker_incl_fn: TrackerInclFn,
        missed_fn: MissedFn,
        att_included_fn: AttIncludedFn,
        feature_set: Arc<FeatureSet>,
    ) -> Self {
        Self {
            submissions: HashMap::new(),
            beacon_committees: HashMap::new(),
            tracker_incl_fn,
            missed_fn,
            att_included_fn,
            feature_set,
        }
    }

    /// Records a duty submitted to the beacon node.
    ///
    /// Unsupported duty types are ignored. Synthetic proposals are reported as
    /// included immediately since they are already on-chain.
    pub fn submitted(
        &mut self,
        duty: Duty,
        pubkey: PubKey,
        data: Box<dyn SignedData>,
        delay: Duration,
    ) -> Result<(), InclusionError> {
        if !incl_supported(&self.feature_set).contains(&duty.duty_type) {
            return Ok(());
        }

        let mut att_data_root = [0u8; 32];

        if duty.duty_type == DutyType::Attester {
            let any = &*data as &dyn Any;
            if let Some(att) = any.downcast_ref::<VersionedAttestation>() {
                let payload = att
                    .0
                    .attestation
                    .as_ref()
                    .ok_or(InclusionError::MissingAttestation)?;
                att_data_root = payload.data().tree_hash_root().0;
            } else if let Some(att) = any.downcast_ref::<Attestation>() {
                att_data_root = att.0.data.tree_hash_root().0;
            } else {
                return Err(InclusionError::InvalidAttestation);
            }
        }

        if duty.duty_type == DutyType::Aggregator {
            let any = &*data as &dyn Any;
            if let Some(agg) = any.downcast_ref::<VersionedSignedAggregateAndProof>() {
                let data = agg.data().ok_or(InclusionError::InvalidAggregateAndProof)?;
                att_data_root = data.tree_hash_root().0;
            } else if let Some(agg) = any.downcast_ref::<SignedAggregateAndProof>() {
                att_data_root = agg.0.message.aggregate.data.tree_hash_root().0;
            } else {
                return Err(InclusionError::InvalidAggregateAndProof);
            }
        }

        if duty.duty_type == DutyType::Proposer {
            let any = &*data as &dyn Any;
            let proposal = any
                .downcast_ref::<VersionedSignedProposal>()
                .ok_or(InclusionError::InvalidBlock)?;
            if proposal.0.is_synthetic() {
                // Synthetic blocks are already on-chain; report inclusion now.
                (self.tracker_incl_fn)(&duty, pubkey, None);
                return Ok(());
            }
        }

        // Defensive: builder proposals are deprecated and excluded by
        // `incl_supported`, so this is unreachable in practice.
        if duty.duty_type == DutyType::BuilderProposer {
            return Err(InclusionError::DeprecatedDutyBuilderProposer);
        }

        let key = SubKey {
            duty: duty.clone(),
            pubkey,
        };
        self.submissions.insert(
            key,
            Submission {
                duty,
                pubkey,
                data,
                att_data_root,
                delay,
            },
        );

        Ok(())
    }

    /// Removes submissions and committee state at or below `slot`, reporting
    /// each removed submission as missed and never included on-chain.
    pub fn trim(&mut self, slot: u64) {
        let stale: Vec<SubKey> = self
            .submissions
            .iter()
            .filter(|(_, sub)| sub.duty.slot.inner() <= slot)
            .map(|(key, _)| key.clone())
            .collect();

        for key in stale {
            let sub = self
                .submissions
                .remove(&key)
                .expect("key collected from submissions");
            (self.missed_fn)(&sub);
            let err: StepError = Arc::new(InclusionError::NotIncludedOnChain);
            (self.tracker_incl_fn)(&sub.duty, sub.pubkey, Some(err));
        }

        self.beacon_committees.retain(|&s, _| s > slot);
    }

    /// Checks whether a proposer duty for `slot` was included, given whether a
    /// block was found at that slot. Only proposer submissions are expected.
    pub fn check_block(&mut self, slot: u64, found: bool) {
        let matched: Vec<SubKey> = self
            .submissions
            .iter()
            .filter_map(|(key, sub)| match sub.duty.duty_type {
                DutyType::Proposer => (sub.duty.slot.inner() == slot).then(|| key.clone()),
                // Parity: charon core/tracker/inclusion.go:289-291 @ v1.7.1
                // panics with "bug: unexpected type" here — CheckBlock (the
                // non-attestation path) is only ever fed proposer submissions.
                // `unreachable!` reproduces that panic with the same message.
                // Accepted divergence in panic *site* only: Go panics while
                // iterating the offending submission; Rust panics inside the
                // `filter_map` closure on the same element — observably
                // identical.
                _ => unreachable!("bug: unexpected type"),
            })
            .collect();

        for key in matched {
            let blinded = match self.submissions.get(&key) {
                Some(sub) => {
                    match (&*sub.data as &dyn Any).downcast_ref::<VersionedSignedProposal>() {
                        Some(proposal) => proposal.0.blinded,
                        None => {
                            tracing::error!(
                                duty = %sub.duty,
                                "Submission data has wrong type",
                            );
                            continue;
                        }
                    }
                }
                None => continue,
            };

            let sub = self.submissions.remove(&key).expect("present");
            if found {
                log_block_included(&sub, slot, blinded);
            } else {
                (self.missed_fn)(&sub);
            }
            (self.tracker_incl_fn)(&sub.duty, sub.pubkey, None);
        }
    }

    /// Checks whether any submitted attester/aggregator/proposer duties were
    /// included in the given block (and its attestations).
    pub fn check_block_and_atts(&mut self, block: &Block) {
        enum Act {
            Include,
            ProposerInclude { blinded: bool },
        }

        let mut acts: Vec<(SubKey, Act)> = Vec::new();

        for (key, sub) in &self.submissions {
            match sub.duty.duty_type {
                DutyType::Attester => match check_attestation_inclusion(sub, block) {
                    // Matching Go: on error, log and still report inclusion.
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to check attestation inclusion");
                        acts.push((key.clone(), Act::Include));
                    }
                    Ok(true) => acts.push((key.clone(), Act::Include)),
                    Ok(false) => {}
                },
                DutyType::Aggregator => match check_aggregation_inclusion(sub, block) {
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to check aggregate inclusion");
                        acts.push((key.clone(), Act::Include));
                    }
                    Ok(true) => acts.push((key.clone(), Act::Include)),
                    Ok(false) => {}
                },
                DutyType::Proposer => {
                    if sub.duty.slot.inner() != block.slot {
                        continue;
                    }
                    match (&*sub.data as &dyn Any).downcast_ref::<VersionedSignedProposal>() {
                        Some(proposal) => acts.push((
                            key.clone(),
                            Act::ProposerInclude {
                                blinded: proposal.0.blinded,
                            },
                        )),
                        None => {
                            tracing::error!(duty = %sub.duty, "Submission data has wrong type");
                        }
                    }
                }
                _ => unreachable!("bug: unexpected type"),
            }
        }

        for (key, act) in acts {
            let sub = self.submissions.remove(&key).expect("present");
            match act {
                Act::Include => {
                    (self.att_included_fn)(&sub, block);
                    (self.tracker_incl_fn)(&sub.duty, sub.pubkey, None);
                }
                Act::ProposerInclude { blinded } => {
                    log_block_included(&sub, block.slot, blinded);
                    (self.tracker_incl_fn)(&sub.duty, sub.pubkey, None);
                }
            }
        }

        if let Some(old) = block.slot.checked_sub(INCL_MISSED_LAG) {
            self.beacon_committees.remove(&old);
        }
    }
}

/// Returns the aggregation bits of a block attestation, or an error if the
/// payload is missing.
fn block_att_agg_bits(att: &versioned::VersionedAttestation) -> Result<Vec<u8>, InclusionError> {
    att.attestation
        .as_ref()
        .map(versioned::AttestationPayload::aggregation_bits)
        .ok_or(InclusionError::MissingAttestation)
}

/// Returns the single committee index referenced by an Electra/Fulu attestation
/// payload, or an error if it does not reference exactly one committee.
fn electra_committee_index(payload: &versioned::AttestationPayload) -> Result<u64, InclusionError> {
    match payload {
        versioned::AttestationPayload::Electra(att) | versioned::AttestationPayload::Fulu(att) => {
            match att.committee_bits.bit_indices()[..] {
                [idx] => Ok(idx as u64),
                _ => Err(InclusionError::InvalidCommitteeBits),
            }
        }
        _ => Err(InclusionError::InvalidCommitteeBits),
    }
}

/// Checks whether the submitted attestation is included in the block.
fn check_attestation_inclusion(sub: &Submission, block: &Block) -> Result<bool, InclusionError> {
    let any = &*sub.data as &dyn Any;
    let sub_att = any
        .downcast_ref::<VersionedAttestation>()
        .ok_or(InclusionError::NotAnAttestation)?;

    let Some(att) = block.attestations_by_data_root.get(&sub.att_data_root) else {
        return Ok(false);
    };

    let payload = sub_att
        .0
        .attestation
        .as_ref()
        .ok_or(InclusionError::MissingAttestation)?;

    match sub_att.0.version {
        versioned::DataVersion::Phase0
        | versioned::DataVersion::Altair
        | versioned::DataVersion::Bellatrix
        | versioned::DataVersion::Capella
        | versioned::DataVersion::Deneb => {
            let sub_bits = AggBits::from_ssz_bytes(payload.aggregation_bits())
                .map_err(|_| InclusionError::DecodeAggregationBits)?;
            let att_bits = AggBits::from_ssz_bytes(block_att_agg_bits(att)?)
                .map_err(|_| InclusionError::DecodeAggregationBits)?;
            Ok(att_bits.contains(&sub_bits)?)
        }
        versioned::DataVersion::Electra | versioned::DataVersion::Fulu => {
            let validator_index = sub_att
                .0
                .validator_index
                .ok_or(InclusionError::NoValidatorIndex)?;
            let duty = block
                .att_duties
                .iter()
                .find(|d| d.validator_index == validator_index)
                .ok_or(InclusionError::NoAttesterDuty)?;

            let att_bits = AggBits::from_ssz_bytes(block_att_agg_bits(att)?)
                .map_err(|_| InclusionError::DecodeAggregationBits)?;
            let committee_index = electra_committee_index(payload)?;

            // Sum the validator counts of all committees preceding the
            // attestation's committee to offset into the full aggregation bits.
            let preceding = usize::try_from(committee_index).unwrap_or(usize::MAX);
            let previous_validators: usize = block
                .beacon_committees
                .iter()
                .take(preceding)
                .map(|c| c.validators.len())
                .sum();

            let offset = usize::try_from(duty.validator_committee_index).unwrap_or(usize::MAX);
            Ok(att_bits.bit_at(previous_validators.saturating_add(offset)))
        }
        versioned::DataVersion::Unknown => Err(InclusionError::NotAnAttestation),
    }
}

/// Checks whether the submitted aggregate is included in the block.
fn check_aggregation_inclusion(sub: &Submission, block: &Block) -> Result<bool, InclusionError> {
    let Some(att) = block.attestations_by_data_root.get(&sub.att_data_root) else {
        return Ok(false);
    };
    let att_bits = AggBits::from_ssz_bytes(block_att_agg_bits(att)?)
        .map_err(|_| InclusionError::DecodeAggregationBits)?;

    let any = &*sub.data as &dyn Any;
    let agg = any
        .downcast_ref::<VersionedSignedAggregateAndProof>()
        .ok_or(InclusionError::ParseVersionedAggregate)?;
    let sub_bits = AggBits::from_ssz_bytes(
        agg.aggregation_bits()
            .ok_or(InclusionError::ParseVersionedAggregate)?,
    )
    .map_err(|_| InclusionError::DecodeAggregationBits)?;

    Ok(att_bits.contains(&sub_bits)?)
}

/// Reports a duty that was broadcast but never included on-chain.
fn report_missed(sub: &Submission) {
    TRACKER_METRICS.inclusion_missed_total[&sub.duty.duty_type.to_string()].inc();

    match sub.duty.duty_type {
        DutyType::Attester | DutyType::Aggregator => {
            let msg = if sub.duty.duty_type == DutyType::Aggregator {
                "Broadcasted attestation aggregate never included on-chain"
            } else {
                "Broadcasted attestation never included on-chain"
            };
            tracing::warn!(
                pubkey = %sub.pubkey,
                attestation_slot = sub.duty.slot.inner(),
                broadcast_delay = ?sub.delay,
                "{msg}",
            );
        }
        DutyType::Proposer => {
            match (&*sub.data as &dyn Any).downcast_ref::<VersionedSignedProposal>() {
                Some(proposal) => {
                    let msg = if proposal.0.blinded {
                        "Broadcasted blinded block never included on-chain"
                    } else {
                        "Broadcasted block never included on-chain"
                    };
                    tracing::warn!(
                        pubkey = %sub.pubkey,
                        block_slot = sub.duty.slot.inner(),
                        broadcast_delay = ?sub.delay,
                        "{msg}",
                    );
                }
                None => tracing::error!(duty = %sub.duty, "Submission data has wrong type"),
            }
        }
        _ => unreachable!("bug: unexpected type"),
    }
}

/// Reports an attestation/aggregate observed on-chain, recording inclusion
/// delay.
fn report_att_inclusion(sub: &Submission, block: &Block) {
    let Some(att) = block.attestations_by_data_root.get(&sub.att_data_root) else {
        return;
    };
    let Some(payload) = att.attestation.as_ref() else {
        return;
    };

    let att_slot = payload.data().slot;
    let block_slot = block.slot;
    let inclusion_delay = block_slot.saturating_sub(att_slot);
    // Inclusion delay is a small slot count; widen losslessly via u32.
    let inclusion_delay_f64 = f64::from(u32::try_from(inclusion_delay).unwrap_or(u32::MAX));

    let msg = if sub.duty.duty_type == DutyType::Aggregator {
        "Broadcasted attestation aggregate included on-chain"
    } else {
        "Broadcasted attestation included on-chain"
    };
    tracing::info!(
        block_slot,
        attestation_slot = att_slot,
        pubkey = %sub.pubkey,
        inclusion_delay,
        broadcast_delay = ?sub.delay,
        "{msg}",
    );

    TRACKER_METRICS.inclusion_delay.set(inclusion_delay_f64);
}

/// Logs that a proposer's block was included on-chain.
fn log_block_included(sub: &Submission, block_slot: u64, blinded: bool) {
    let msg = if blinded {
        "Broadcasted blinded block included on-chain"
    } else {
        "Broadcasted block included on-chain"
    };
    tracing::info!(
        block_slot,
        pubkey = %sub.pubkey,
        broadcast_delay = ?sub.delay,
        "{msg}",
    );
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use pluto_eth2api::spec::phase0;
    use pluto_ssz::BitList;
    use pluto_testutil::random::random_deneb_versioned_attestation;
    use tree_hash::TreeHash;

    use pluto_featureset::{Config, Feature};

    use super::*;
    use crate::types::SlotNumber;

    /// Shared recorder of duties passed to a callback.
    type Rec = Arc<Mutex<Vec<Duty>>>;

    fn featureset(attestation_inclusion: bool) -> Arc<FeatureSet> {
        let enabled = if attestation_inclusion {
            vec![Feature::AttestationInclusion]
        } else {
            vec![]
        };
        Arc::new(
            FeatureSet::from_config(Config {
                enabled,
                ..Config::default()
            })
            .expect("test featureset is valid"),
        )
    }

    fn pubkey() -> PubKey {
        PubKey::from([0u8; 48])
    }

    fn checkpoint() -> phase0::Checkpoint {
        phase0::Checkpoint {
            epoch: 0,
            root: [0u8; 32],
        }
    }

    fn att_data(slot: u64) -> phase0::AttestationData {
        phase0::AttestationData {
            slot,
            index: 0,
            beacon_block_root: [1u8; 32],
            source: checkpoint(),
            target: checkpoint(),
        }
    }

    fn phase0_attestation(slot: u64) -> phase0::Attestation {
        phase0::Attestation {
            aggregation_bits: BitList::default(),
            data: att_data(slot),
            signature: [0u8; 96],
        }
    }

    fn phase0_aggregate(slot: u64) -> phase0::SignedAggregateAndProof {
        phase0::SignedAggregateAndProof {
            message: phase0::AggregateAndProof {
                aggregator_index: 0,
                aggregate: phase0_attestation(slot),
                selection_proof: [0u8; 96],
            },
            signature: [0u8; 96],
        }
    }

    /// Deserialises a real (Fulu, non-blinded) signed proposal from the shared
    /// JSON golden. The fork version is irrelevant to the checks under test.
    fn proposal() -> VersionedSignedProposal {
        serde_json::from_str(include_str!(
            "../../testdata/signeddata/TestJSONSerialisation_VersionedSignedProposal.json.golden"
        ))
        .expect("golden proposal deserialises")
    }

    fn submission(duty: Duty, data: Box<dyn SignedData>, att_data_root: HashRoot) -> Submission {
        Submission {
            duty,
            pubkey: pubkey(),
            data,
            att_data_root,
            delay: Duration::ZERO,
        }
    }

    fn sorted_slots(rec: &Rec) -> Vec<u64> {
        let mut slots: Vec<u64> = rec.lock().unwrap().iter().map(|d| d.slot.inner()).collect();
        slots.sort_unstable();
        slots
    }

    /// Mirrors Go's `TestInclusion`: non-versioned attester/aggregator data
    /// fails the versioned downcast inside the inclusion checks, which (per the
    /// Go semantics) logs and still reports the duty as included. Proposer
    /// duties are reported via the tracker callback but not the att-included
    /// callback.
    #[test]
    fn inclusion() {
        let included: Rec = Rec::default();
        let missed: Rec = Rec::default();
        let resolved: Rec = Rec::default();

        let (inc, mis, res) = (included.clone(), missed.clone(), resolved.clone());
        let mut core = InclusionCore::with_handlers(
            Box::new(move |duty: &Duty, _pk, _err| res.lock().unwrap().push(duty.clone())),
            Box::new(move |sub: &Submission| mis.lock().unwrap().push(sub.duty.clone())),
            Box::new(move |sub: &Submission, _b: &Block| {
                inc.lock().unwrap().push(sub.duty.clone())
            }),
            featureset(true),
        );

        let att1 = Attestation::new(phase0_attestation(1));
        let agg2 = SignedAggregateAndProof::new(phase0_aggregate(2));
        let att3 = Attestation::new(phase0_attestation(3));
        let block4 = proposal();

        // Seeded into the block below; the rest are recomputed inside `submitted`.
        let agg2_root = agg2.0.message.aggregate.data.tree_hash_root().0;

        core.submitted(
            Duty::new_attester_duty(SlotNumber::new(1)),
            pubkey(),
            Box::new(att1),
            Duration::ZERO,
        )
        .expect("submit attester 1");
        core.submitted(
            Duty::new_aggregator_duty(SlotNumber::new(2)),
            pubkey(),
            Box::new(agg2),
            Duration::ZERO,
        )
        .expect("submit aggregator 2");
        core.submitted(
            Duty::new_attester_duty(SlotNumber::new(3)),
            pubkey(),
            Box::new(att3),
            Duration::ZERO,
        )
        .expect("submit attester 3");
        core.submitted(
            Duty::new_proposer_duty(SlotNumber::new(100)),
            pubkey(),
            Box::new(block4),
            Duration::ZERO,
        )
        .expect("submit proposer 100");

        // The aggregator lookup must find a block attestation at its data root
        // before failing the versioned downcast, so seed one.
        let block = Block {
            slot: 100,
            att_duties: vec![],
            attestations_by_data_root: HashMap::from([(
                agg2_root,
                random_deneb_versioned_attestation(),
            )]),
            beacon_committees: vec![],
        };

        core.check_block_and_atts(&block);

        // Attester (1, 3) and aggregator (2) report via att-included.
        assert_eq!(sorted_slots(&included), vec![1, 2, 3]);
        assert!(missed.lock().unwrap().is_empty());
        // All four duties resolve via the tracker callback (incl. proposer 100).
        assert_eq!(sorted_slots(&resolved), vec![1, 2, 3, 100]);
    }

    /// Mirrors Go's `TestBlockInclusion`: a proposer duty is reported missed
    /// only when its slot's block is checked and not found.
    #[test]
    fn block_inclusion() {
        let scenario = |check_offset: u64, found: bool| -> usize {
            let missed: Rec = Rec::default();
            let mis = missed.clone();
            let mut core = InclusionCore::with_handlers(
                Box::new(|_d: &Duty, _pk, _err| {}),
                Box::new(move |sub: &Submission| mis.lock().unwrap().push(sub.duty.clone())),
                Box::new(|_s: &Submission, _b: &Block| {}),
                featureset(false),
            );

            // The duty slot is independent of the proposal's internal slot;
            // `check_block` matches against the duty slot.
            let slot = 42u64;
            core.submitted(
                Duty::new_proposer_duty(SlotNumber::new(slot)),
                pubkey(),
                Box::new(proposal()),
                Duration::ZERO,
            )
            .expect("submit proposal");

            core.check_block(slot.wrapping_add(check_offset), found);
            missed.lock().unwrap().len()
        };

        assert_eq!(scenario(0, true), 0, "block found at slot -> not missed");
        assert_eq!(scenario(0, false), 1, "block not found at slot -> missed");
        assert_eq!(scenario(1, true), 0, "slot mismatch -> skipped");
        assert_eq!(scenario(1, false), 0, "slot mismatch, not found -> skipped");
    }

    /// Pins the faithful parity with Go's `panic("bug: unexpected type")` in
    /// `CheckBlock` (charon core/tracker/inclusion.go:289-291 @ v1.7.1): the
    /// non-attestation path only ever expects proposer submissions.
    #[test]
    #[should_panic(expected = "bug: unexpected type")]
    fn check_block_panics_on_non_proposer_submission() {
        let mut core = InclusionCore::with_handlers(
            Box::new(|_d: &Duty, _pk, _err| {}),
            Box::new(|_s: &Submission| {}),
            Box::new(|_s: &Submission, _b: &Block| {}),
            featureset(true),
        );

        core.submitted(
            Duty::new_attester_duty(SlotNumber::new(7)),
            pubkey(),
            Box::new(Attestation::new(phase0_attestation(7))),
            Duration::ZERO,
        )
        .expect("submit attester");

        core.check_block(7, true);
    }

    /// `trim` reports each removed submission as missed and never included,
    /// only for slots at or below the trim slot.
    #[test]
    fn trim() {
        let missed: Rec = Rec::default();
        let resolved: Arc<Mutex<Vec<Option<StepError>>>> = Arc::default();

        let (mis, res) = (missed.clone(), resolved.clone());
        let mut core = InclusionCore::with_handlers(
            Box::new(move |_d: &Duty, _pk, err: Option<StepError>| res.lock().unwrap().push(err)),
            Box::new(move |sub: &Submission| mis.lock().unwrap().push(sub.duty.clone())),
            Box::new(|_s: &Submission, _b: &Block| {}),
            featureset(false),
        );

        core.submitted(
            Duty::new_proposer_duty(SlotNumber::new(5)),
            pubkey(),
            Box::new(proposal()),
            Duration::ZERO,
        )
        .expect("submit proposal");

        // Below the duty slot: nothing trimmed.
        core.trim(4);
        assert!(missed.lock().unwrap().is_empty());

        // At the duty slot: trimmed, reported missed and not-included.
        core.trim(5);
        assert_eq!(sorted_slots(&missed), vec![5]);
        let res = resolved.lock().unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(
            res[0].as_ref().map(|e| e.to_string()),
            Some("duty not included on-chain".to_string()),
        );
    }

    fn versioned_att_phase0(
        slot: u64,
        agg_bits: pluto_ssz::BitList<2048>,
    ) -> versioned::VersionedAttestation {
        versioned::VersionedAttestation {
            version: versioned::DataVersion::Deneb,
            validator_index: None,
            attestation: Some(versioned::AttestationPayload::Deneb(phase0::Attestation {
                aggregation_bits: agg_bits,
                data: att_data(slot),
                signature: [0u8; 96],
            })),
        }
    }

    fn run_phase0_inclusion_check(
        block_set_bits: &[usize],
        sub_set_bits: &[usize],
    ) -> Result<bool, InclusionError> {
        let slot = 5u64;
        let data_root = att_data(slot).tree_hash_root().0;
        let block_att = versioned_att_phase0(
            slot,
            pluto_ssz::BitList::<2048>::with_bits(4, block_set_bits),
        );
        let sub_att = versioned::VersionedAttestation {
            version: versioned::DataVersion::Deneb,
            validator_index: None,
            attestation: Some(versioned::AttestationPayload::Deneb(phase0::Attestation {
                aggregation_bits: pluto_ssz::BitList::<2048>::with_bits(4, sub_set_bits),
                data: att_data(slot),
                signature: [0u8; 96],
            })),
        };
        let sub = submission(
            Duty::new_attester_duty(SlotNumber::new(slot)),
            Box::new(VersionedAttestation::new(sub_att).unwrap()),
            data_root,
        );
        let block = Block {
            slot,
            att_duties: vec![],
            attestations_by_data_root: HashMap::from([(data_root, block_att)]),
            beacon_committees: vec![],
        };
        check_attestation_inclusion(&sub, &block)
    }

    /// Block has bits 0 and 1 set; submission has only bit 0 → included.
    #[test]
    fn check_attestation_inclusion_phase0_contains() {
        assert!(run_phase0_inclusion_check(&[0, 1], &[0]).unwrap());
    }

    /// Block has bit 1; submission has bit 0 → not included.
    #[test]
    fn check_attestation_inclusion_phase0_not_contained() {
        assert!(!run_phase0_inclusion_check(&[1], &[0]).unwrap());
    }

    // committee 0 has 3 validators, committee 1 has 4; validator sits at
    // committee_index=1, validator_committee_index=2 → global bit 5.
    fn run_electra_inclusion_check(block_set_bits: &[usize]) -> Result<bool, InclusionError> {
        use pluto_eth2api::spec::electra;
        use pluto_ssz::BitVector;

        let slot = 10u64;
        let validator_index: u64 = 99;
        let committee_index: usize = 1;
        let committee0_size: usize = 3;
        let validator_committee_index: u64 = 2;
        let total_validators = committee0_size + 4;

        let data_root = att_data(slot).tree_hash_root().0;
        let block_att = versioned::VersionedAttestation {
            version: versioned::DataVersion::Electra,
            validator_index: None,
            attestation: Some(versioned::AttestationPayload::Electra(
                electra::Attestation {
                    aggregation_bits: BitList::with_bits(total_validators, block_set_bits),
                    data: att_data(slot),
                    signature: [0u8; 96],
                    committee_bits: BitVector::with_bits(&[committee_index]),
                },
            )),
        };
        let sub_att = versioned::VersionedAttestation {
            version: versioned::DataVersion::Electra,
            validator_index: Some(validator_index),
            attestation: Some(versioned::AttestationPayload::Electra(
                electra::Attestation {
                    aggregation_bits: BitList::default(),
                    data: att_data(slot),
                    signature: [0u8; 96],
                    committee_bits: BitVector::with_bits(&[committee_index]),
                },
            )),
        };
        let sub = submission(
            Duty::new_attester_duty(SlotNumber::new(slot)),
            Box::new(VersionedAttestation::new(sub_att).unwrap()),
            data_root,
        );
        let block = Block {
            slot,
            att_duties: vec![AttesterDuty {
                validator_index,
                validator_committee_index,
            }],
            attestations_by_data_root: HashMap::from([(data_root, block_att)]),
            beacon_committees: vec![
                BeaconCommittee {
                    index: 0,
                    validators: vec![0u64; committee0_size],
                },
                BeaconCommittee {
                    index: 1,
                    validators: vec![0u64; 4],
                },
            ],
        };
        check_attestation_inclusion(&sub, &block)
    }

    /// Validator in committee 1 (preceded by 3 validators in committee 0),
    /// validator_committee_index 2 → global bit 5 is set → included.
    #[test]
    fn check_attestation_inclusion_electra_offset() {
        assert!(run_electra_inclusion_check(&[5]).unwrap());
    }

    /// Global bit 5 is not set in the block (bit 4 is) → not included.
    #[test]
    fn check_attestation_inclusion_electra_offset_not_included() {
        assert!(!run_electra_inclusion_check(&[4]).unwrap());
    }
}
