//! In-memory DutyDB implementation.
//!
//! Equivalent to charon/core/dutydb/memory.go.

use std::collections::HashMap;

use pluto_eth2api::{
    spec::{altair, phase0},
    versioned,
};
use tokio::sync::{Notify, RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tree_hash::TreeHash;

use crate::{
    deadline::{AddOutcome, DeadlinerHandle},
    signeddata::{
        AttestationData, SyncContribution, VersionedAggregatedAttestation, VersionedProposal,
    },
    types::{Duty, DutyType, PubKey},
    unsigneddata::{UnsignedDataSet, UnsignedDutyData},
};

/// Error type for DutyDB operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Duty has already expired; unsigned data will not be stored.
    #[error("duty expired: unsigned data will not be stored")]
    ExpiredDuty,

    /// The deadliner could not compute a deadline for the duty (calculator
    /// error or a shutdown race); unsigned data will not be stored.
    #[error("deadline computation failed: unsigned data will not be stored")]
    DeadlineComputation,

    /// Proposer data set must contain at most one entry.
    #[error("proposer data set must contain at most one entry")]
    UnexpectedProposerSetLength,

    /// `DutyBuilderProposer` is deprecated and no longer supported.
    #[error("DutyBuilderProposer is deprecated and no longer supported")]
    DeprecatedDutyBuilderProposer,

    /// Duty type is not stored by `DutyDB`.
    #[error("unsupported duty type: not stored by DutyDB")]
    UnsupportedDutyType,

    /// DB was shut down before the query could be answered.
    #[error("dutydb shutdown: query could not be answered")]
    Shutdown,

    /// The awaited duty was evicted before its unsigned data became
    /// available. Distinct from `Shutdown` so callers can map this to a
    /// timeout-style error rather than a service-down error.
    #[error("dutydb: awaited duty expired before data was stored")]
    AwaitDutyExpired,

    /// Two validators share the same `(slot, committee_index, valIdx)` with
    /// different public keys.
    #[error(
        "clashing public key: slot={slot} committee_index={committee_index} validator_index={validator_index}"
    )]
    ClashingPublicKey {
        /// Slot of the attestation duty.
        slot: u64,
        /// Committee index.
        committee_index: u64,
        /// Validator index.
        validator_index: u64,
    },

    /// Two different attestation data objects for the same `(slot,
    /// committee_index)`.
    #[error("clashing attestation data: slot={slot} committee_index={committee_index}")]
    ClashingAttestationData {
        /// Slot of the attestation duty.
        slot: u64,
        /// Committee index.
        committee_index: u64,
    },

    /// Two different sync contributions for the same `(slot,
    /// subcommittee_index, root)`.
    #[error("clashing sync contributions: slot={slot} subcommittee_index={subcommittee_index}")]
    ClashingSyncContributions {
        /// Slot of the sync contribution duty.
        slot: u64,
        /// Subcommittee index.
        subcommittee_index: u64,
    },

    /// Two different blocks for the same slot.
    #[error("clashing blocks: slot={slot}")]
    ClashingBlocks {
        /// Slot of the proposer duty.
        slot: u64,
    },

    /// No public key found for the given `(slot, committee_index,
    /// validator_index)`.
    #[error(
        "pubkey not found for the given (slot={slot}, committee_index={committee_index}, validator_index={validator_index})"
    )]
    PubKeyNotFound {
        /// Slot of the attestation duty.
        slot: u64,
        /// Committee index of the attestation duty.
        committee_index: u64,
        /// Validator index of the attestation duty.
        validator_index: u64,
    },

    /// Duty type is not handled by the delete path.
    #[error("unknown duty type: not handled by delete")]
    UnknownDutyType,

    /// Unsigned data does not match the expected type for `DutyProposer`.
    #[error("invalid versioned proposal: unsigned data does not match DutyProposer")]
    InvalidVersionedProposal,

    /// Unsigned data does not match the expected type for `DutyAttester`.
    #[error("invalid unsigned attestation data: does not match DutyAttester")]
    InvalidAttestationData,

    /// Unsigned data does not match the expected type for `DutyAggregator`.
    #[error("invalid unsigned aggregated attestation: does not match DutyAggregator")]
    InvalidAggregatedAttestation,

    /// Unsigned data does not match the expected type for
    /// `DutySyncContribution`.
    #[error("invalid unsigned sync committee contribution: does not match DutySyncContribution")]
    InvalidSyncContribution,
}

/// Result type for DutyDB operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Lookup key for attestation data: (slot, committee index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AttKey {
    slot: u64,
    committee_index: u64,
}

/// Lookup key for public-key-by-attestation: (slot, committee index, validator
/// index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PkKey {
    slot: u64,
    committee_index: u64,
    validator_index: u64,
}

/// Lookup key for aggregated attestations: attestation data root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AggKey {
    root: phase0::Root,
}

/// Lookup key for sync contributions: (slot, subcommittee index, beacon block
/// root).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ContribKey {
    slot: u64,
    subcommittee_index: u64,
    root: phase0::Root,
}

/// Per-poll outcome handed back by an `await_data` lookup closure.
enum Lookup<V> {
    /// The awaited value is now present — return it to the caller.
    Found(V),
    /// The awaited duty has been evicted; the lookup will never succeed.
    /// `await_data` returns [`Error::AwaitDutyExpired`].
    Evicted,
    /// Neither stored nor evicted yet — park on the notify and retry.
    Pending,
}

struct State {
    attestation_duties: HashMap<AttKey, phase0::AttestationData>,
    attestation_pub_keys: HashMap<PkKey, PubKey>,
    attestation_keys_by_slot: HashMap<u64, Vec<PkKey>>,

    proposer_duties: HashMap<u64, VersionedProposal>,

    aggregation_duties: HashMap<AggKey, VersionedAggregatedAttestation>,
    aggregation_keys_by_slot: HashMap<u64, Vec<AggKey>>,

    contrib_duties: HashMap<ContribKey, altair::SyncCommitteeContribution>,
    contrib_keys_by_slot: HashMap<u64, Vec<ContribKey>>,

    /// Highest slot whose attester duty has been evicted by the deadliner.
    /// Because the deadliner expires duties in non-decreasing slot order and
    /// `store()` refuses already-expired duties (`AddOutcome::AlreadyExpired`),
    /// any awaited slot `<=` this mark that is not currently stored will never
    /// be stored. Tracking only the high-water mark — rather than the set of
    /// every evicted slot, which would grow without bound for the lifetime of
    /// the node — lets `await_attestation` return `AwaitDutyExpired`
    /// immediately for a gone duty while keeping the bookkeeping O(1) in
    /// memory.
    max_evicted_attestation_slot: Option<u64>,
    /// Highest slot whose proposer duty has been evicted. See
    /// [`max_evicted_attestation_slot`](Self::max_evicted_attestation_slot).
    max_evicted_proposer_slot: Option<u64>,
    /// Highest slot whose sync-contribution duty has been evicted. See
    /// [`max_evicted_attestation_slot`](Self::max_evicted_attestation_slot).
    max_evicted_contrib_slot: Option<u64>,
    // NB: there is no eviction mark for aggregated attestations. They are
    // awaited by root only (`await_agg_attestation` has no slot), so there is
    // no slot to compare against a high-water mark; an evicted root relies on
    // the caller's request timeout instead, matching Charon's Go dutydb which
    // keeps no eviction record at all.
    deadliner_rx: tokio::sync::mpsc::Receiver<Duty>,
}

/// In-memory DutyDB.
///
/// Equivalent to charon's `MemDB`. Stores unsigned duty data and answers
/// blocking `await_*` queries when the relevant data becomes available.
pub struct MemDB {
    state: RwLock<State>,
    attestation_notify: Notify,
    proposer_notify: Notify,
    aggregation_notify: Notify,
    contrib_notify: Notify,
    cancel: CancellationToken,
    deadliner: DeadlinerHandle,
}

impl MemDB {
    /// Creates a new in-memory DutyDB. `deadliner_rx` is the receiver paired
    /// with `deadliner` (typically from `DeadlinerTask::start`).
    pub fn new(
        deadliner: DeadlinerHandle,
        deadliner_rx: mpsc::Receiver<Duty>,
        cancel: &CancellationToken,
    ) -> Self {
        Self {
            state: RwLock::new(State {
                attestation_duties: HashMap::new(),
                attestation_pub_keys: HashMap::new(),
                attestation_keys_by_slot: HashMap::new(),
                proposer_duties: HashMap::new(),
                aggregation_duties: HashMap::new(),
                aggregation_keys_by_slot: HashMap::new(),
                contrib_duties: HashMap::new(),
                contrib_keys_by_slot: HashMap::new(),
                max_evicted_attestation_slot: None,
                max_evicted_proposer_slot: None,
                max_evicted_contrib_slot: None,
                deadliner_rx,
            }),
            attestation_notify: Notify::new(),
            proposer_notify: Notify::new(),
            aggregation_notify: Notify::new(),
            contrib_notify: Notify::new(),
            cancel: cancel.child_token(),
            deadliner,
        }
    }

    /// Shuts down the DB, signalling all current and future `await_*` calls to
    /// return `Error::Shutdown` on their next poll.
    pub fn shutdown(&self) {
        info!("dutydb: shutting down");
        self.cancel.cancel();
    }

    /// Stores unsigned duty data for the given duty, waking any pending
    /// waiters.
    pub async fn store(&self, duty: Duty, unsigned_set: UnsignedDataSet) -> Result<()> {
        if duty.duty_type == DutyType::BuilderProposer {
            return Err(Error::DeprecatedDutyBuilderProposer);
        }

        let mut state = self.state.write().await;

        match self.deadliner.add(duty.clone()).await {
            AddOutcome::Scheduled => {}
            AddOutcome::AlreadyExpired => return Err(Error::ExpiredDuty),
            // Only `Exit`/`BuilderRegistration` have no deadline, and DutyDB
            // doesn't store either. Reject explicitly so this doesn't depend on
            // the `duty_type` match below also rejecting them.
            AddOutcome::NoDeadline => return Err(Error::UnsupportedDutyType),
            AddOutcome::FailedToCompute => return Err(Error::DeadlineComputation),
        }

        match duty.duty_type {
            DutyType::Proposer => {
                if unsigned_set.len() > 1 {
                    return Err(Error::UnexpectedProposerSetLength);
                }
                match unsigned_set.values().next() {
                    None => {}
                    Some(UnsignedDutyData::Proposal(p)) => state.store_proposal(p)?,
                    Some(_) => return Err(Error::InvalidVersionedProposal),
                }
            }
            DutyType::Attester => {
                for (pubkey, data) in &unsigned_set {
                    let att = match data {
                        UnsignedDutyData::Attestation(a) => a,
                        _ => return Err(Error::InvalidAttestationData),
                    };
                    state.store_attestation(*pubkey, att)?;
                }
            }
            DutyType::Aggregator => {
                for data in unsigned_set.values() {
                    let agg = match data {
                        UnsignedDutyData::AggAttestation(a) => a,
                        _ => return Err(Error::InvalidAggregatedAttestation),
                    };
                    state.store_agg_attestation(agg)?;
                }
            }
            DutyType::SyncContribution => {
                for data in unsigned_set.values() {
                    let contrib = match data {
                        UnsignedDutyData::SyncContribution(c) => c,
                        _ => return Err(Error::InvalidSyncContribution),
                    };
                    state.store_sync_contribution(contrib)?;
                }
            }
            _ => return Err(Error::UnsupportedDutyType),
        }
        // Wake the matching notify for the duty we just stored, plus
        // anything we drain below. `notify_waiters` is cheap if no one is
        // parked and just bumps a counter, so calling it under the write
        // lock is harmless — woken tasks block on `state.read()` until we
        // drop.
        self.wake(duty.duty_type);

        // Drain all expired duties that the deadliner has sent. Waiters
        // whose duty just expired need to see `Lookup::Evicted` and exit,
        // not re-park — so we wake the matching notify after each eviction.
        while let Ok(expired) = state.deadliner_rx.try_recv() {
            let duty_type = expired.duty_type.clone();
            state.delete_duty(expired)?;
            self.wake(duty_type);
        }

        Ok(())
    }

    /// Wakes the [`Notify`] paired with `duty_type`. No-op for duty types
    /// the DB doesn't track (e.g. `Exit`, `BuilderRegistration`).
    fn wake(&self, duty_type: DutyType) {
        let notify = match duty_type {
            DutyType::Proposer => &self.proposer_notify,
            DutyType::Attester => &self.attestation_notify,
            DutyType::Aggregator => &self.aggregation_notify,
            DutyType::SyncContribution => &self.contrib_notify,
            _ => return,
        };
        notify.notify_waiters();
    }

    /// Blocks until a proposal for the given slot is available, then returns
    /// it.
    pub async fn await_proposal(&self, slot: u64) -> Result<VersionedProposal> {
        self.await_data(&self.proposer_notify, |s| {
            if let Some(v) = s.proposer_duties.get(&slot) {
                Lookup::Found(v.clone())
            } else if s.max_evicted_proposer_slot.is_some_and(|hw| slot <= hw) {
                Lookup::Evicted
            } else {
                Lookup::Pending
            }
        })
        .await
    }

    /// Blocks until attestation data for the given slot and committee index is
    /// available.
    pub async fn await_attestation(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<phase0::AttestationData> {
        let key = AttKey {
            slot,
            committee_index,
        };
        self.await_data(&self.attestation_notify, |s| {
            if let Some(v) = s.attestation_duties.get(&key) {
                Lookup::Found(v.clone())
            } else if s
                .max_evicted_attestation_slot
                .is_some_and(|hw| key.slot <= hw)
            {
                Lookup::Evicted
            } else {
                Lookup::Pending
            }
        })
        .await
    }

    /// Blocks until an aggregated attestation for the given slot and
    /// attestation root is available.
    pub async fn await_agg_attestation(
        &self,
        attestation_root: phase0::Root,
    ) -> Result<versioned::VersionedAttestation> {
        let key = AggKey {
            root: attestation_root,
        };
        self.await_data(&self.aggregation_notify, |s| {
            // Awaited by root only, so there is no slot to test against an
            // eviction high-water mark: an evicted root relies on the caller's
            // request timeout to terminate (matching Charon's Go dutydb).
            if let Some(v) = s.aggregation_duties.get(&key) {
                Lookup::Found(v.0.clone())
            } else {
                Lookup::Pending
            }
        })
        .await
    }

    /// Blocks until a sync contribution for the given slot, subcommittee index,
    /// and beacon block root is available.
    pub async fn await_sync_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: phase0::Root,
    ) -> Result<altair::SyncCommitteeContribution> {
        let key = ContribKey {
            slot,
            subcommittee_index,
            root: beacon_block_root,
        };
        self.await_data(&self.contrib_notify, |s| {
            if let Some(v) = s.contrib_duties.get(&key) {
                Lookup::Found(v.clone())
            } else if s.max_evicted_contrib_slot.is_some_and(|hw| slot <= hw) {
                Lookup::Evicted
            } else {
                Lookup::Pending
            }
        })
        .await
    }

    // A single Notify per duty type wakes all waiters on every store, not only
    // those whose key matches. The number of concurrent waiters per duty type
    // is small (one per validator), so the extra wakeups are cheap. A keyed
    // notify (HashMap<Key, Sender>) would avoid them but adds complexity that
    // isn't worth it here.
    //
    // `delete_duty` also wakes the notify so waiters whose duty just expired
    // exit immediately via the `Lookup::Evicted` branch, instead of parking
    // for another `notify_waiters` call or for the per-request timeout in
    // the caller.
    async fn await_data<V>(
        &self,
        notify: &Notify,
        lookup: impl Fn(&State) -> Lookup<V>,
    ) -> Result<V> {
        loop {
            let notified = notify.notified();
            tokio::pin!(notified);

            {
                let state = self.state.read().await;
                match lookup(&state) {
                    Lookup::Found(v) => return Ok(v),
                    Lookup::Evicted => return Err(Error::AwaitDutyExpired),
                    Lookup::Pending => {}
                }
            }

            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => return Err(Error::Shutdown),
                _ = &mut notified => {}
            }
        }
    }

    /// Returns the public key of the validator that attested for the given
    /// slot, committee index, and validator index.
    pub async fn pub_key_by_attestation(
        &self,
        slot: u64,
        committee_index: u64,
        validator_index: u64,
    ) -> Result<PubKey> {
        let state = self.state.read().await;
        state
            .attestation_pub_keys
            .get(&PkKey {
                slot,
                committee_index,
                validator_index,
            })
            .copied()
            .ok_or(Error::PubKeyNotFound {
                slot,
                committee_index,
                validator_index,
            })
    }
}

impl Drop for MemDB {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl State {
    fn store_proposal(&mut self, proposal: &VersionedProposal) -> Result<()> {
        let slot = proposal.slot();
        if let Some(existing) = self.proposer_duties.get(&slot) {
            if existing.root() != proposal.root() {
                warn!(slot, "dutydb: clashing blocks");
                return Err(Error::ClashingBlocks { slot });
            }
        } else {
            self.proposer_duties.insert(slot, proposal.clone());
        }
        Ok(())
    }

    fn store_attestation(&mut self, pubkey: PubKey, att: &AttestationData) -> Result<()> {
        let slot = att.data.slot;
        let duty_slot = att.duty.slot;
        let committee_index = att.duty.committee_index;
        let validator_index = att.duty.validator_index;

        self.store_att_pubkey(slot, duty_slot, committee_index, validator_index, pubkey)?;
        self.store_att_data(slot, committee_index, &att.data)?;
        Ok(())
    }

    fn store_att_pubkey(
        &mut self,
        slot: u64,
        duty_slot: u64,
        committee_index: u64,
        validator_index: u64,
        pubkey: PubKey,
    ) -> Result<()> {
        let pk_key = PkKey {
            slot,
            committee_index,
            validator_index,
        };
        if let Some(&existing) = self.attestation_pub_keys.get(&pk_key) {
            if existing != pubkey {
                warn!(
                    slot,
                    committee_index, validator_index, "dutydb: clashing public key"
                );
                return Err(Error::ClashingPublicKey {
                    slot,
                    committee_index,
                    validator_index,
                });
            }
        } else {
            self.attestation_pub_keys.insert(pk_key, pubkey);
            self.attestation_keys_by_slot
                .entry(duty_slot)
                .or_default()
                .push(pk_key);
        }
        Ok(())
    }

    fn store_att_data(
        &mut self,
        slot: u64,
        committee_index: u64,
        data: &phase0::AttestationData,
    ) -> Result<()> {
        let att_key = AttKey {
            slot,
            committee_index,
        };
        if let Some(existing) = self.attestation_duties.get(&att_key) {
            if existing.source != data.source
                || existing.target != data.target
                || existing.beacon_block_root != data.beacon_block_root
            {
                warn!(slot, committee_index, "dutydb: clashing attestation data");
                return Err(Error::ClashingAttestationData {
                    slot,
                    committee_index,
                });
            }
        } else {
            self.attestation_duties.insert(att_key, data.clone());
        }
        Ok(())
    }

    fn store_agg_attestation(&mut self, agg: &VersionedAggregatedAttestation) -> Result<()> {
        let att_data = agg.data().ok_or(Error::InvalidAggregatedAttestation)?;
        let root = att_data.tree_hash_root().0;
        let slot = att_data.slot;

        // Unlike Go implementation, we key by root only, slot field is redundant.
        let key = AggKey { root };
        if !self.aggregation_duties.contains_key(&key) {
            self.aggregation_keys_by_slot
                .entry(slot)
                .or_default()
                .push(key);
        }
        // we don't check existingDataRoot != providedDataRoot because these values
        // come from the same source and the error was unreachable
        self.aggregation_duties.insert(key, agg.clone()); // unconditional overwrite

        Ok(())
    }

    fn store_sync_contribution(&mut self, contrib: &SyncContribution) -> Result<()> {
        let inner = &contrib.0;

        let key = ContribKey {
            slot: inner.slot,
            subcommittee_index: inner.subcommittee_index,
            root: inner.beacon_block_root,
        };

        if let Some(existing) = self.contrib_duties.get(&key) {
            if existing.tree_hash_root().0 != inner.tree_hash_root().0 {
                warn!(
                    slot = inner.slot,
                    subcommittee_index = inner.subcommittee_index,
                    "dutydb: clashing sync contributions"
                );
                return Err(Error::ClashingSyncContributions {
                    slot: inner.slot,
                    subcommittee_index: inner.subcommittee_index,
                });
            }
        } else {
            self.contrib_duties.insert(key, inner.clone());
            self.contrib_keys_by_slot
                .entry(inner.slot)
                .or_default()
                .push(key);
        }

        Ok(())
    }

    /// Raises an eviction high-water mark to `slot` if `slot` is newer (or the
    /// mark is unset). The deadliner expires duties in non-decreasing slot
    /// order, so in practice this only ever moves the mark forward.
    fn bump_high_water(mark: &mut Option<u64>, slot: u64) {
        *mark = Some(mark.map_or(slot, |current| current.max(slot)));
    }

    fn delete_duty(&mut self, duty: Duty) -> Result<()> {
        let slot = duty.slot.inner();
        info!(slot, duty_type = %duty.duty_type, "dutydb: deleting expired duty");
        match duty.duty_type {
            DutyType::Proposer => {
                self.proposer_duties.remove(&slot);
                Self::bump_high_water(&mut self.max_evicted_proposer_slot, slot);
            }
            DutyType::BuilderProposer => return Err(Error::DeprecatedDutyBuilderProposer),
            DutyType::Attester => {
                if let Some(keys) = self.attestation_keys_by_slot.remove(&slot) {
                    for key in keys {
                        self.attestation_pub_keys.remove(&key);
                        self.attestation_duties.remove(&AttKey {
                            slot: key.slot,
                            committee_index: key.committee_index,
                        });
                    }
                }
                Self::bump_high_water(&mut self.max_evicted_attestation_slot, slot);
            }
            DutyType::Aggregator => {
                // No eviction mark: aggregated attestations are awaited by root
                // only, so there is nothing for a slot high-water mark to gate.
                if let Some(keys) = self.aggregation_keys_by_slot.remove(&slot) {
                    for key in keys {
                        self.aggregation_duties.remove(&key);
                    }
                }
            }
            DutyType::SyncContribution => {
                if let Some(keys) = self.contrib_keys_by_slot.remove(&slot) {
                    for key in keys {
                        self.contrib_duties.remove(&key);
                    }
                }
                Self::bump_high_water(&mut self.max_evicted_contrib_slot, slot);
            }
            _ => return Err(Error::UnknownDutyType),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{DateTime, Utc};
    use tokio::sync::mpsc::{Receiver, channel};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::{
        deadline::{self, DeadlineCalculator, DeadlinerTask, NeverExpiringCalculator},
        signeddata::{AttesterDuty, ProposalBlock},
        testutils::random_core_pub_key,
        types::{DutyType, SlotNumber},
    };

    /// Test calculator whose every duty is `Scheduled` (deadline is `MAX_UTC`).
    /// The deadliner never actually fires for this calculator, so the paired
    /// output receiver stays silent — eviction in tests is driven manually
    /// through a separate channel (see `duty_expiry`).
    struct FarFutureCalculator;

    impl DeadlineCalculator for FarFutureCalculator {
        fn deadline(&self, _: &Duty) -> deadline::Result<Option<DateTime<Utc>>> {
            Ok(Some(DateTime::<Utc>::MAX_UTC))
        }
    }

    /// Builds a never-firing receiver for tests that don't exercise eviction.
    pub(crate) fn noop_deadliner_rx() -> Receiver<Duty> {
        let (_, rx) = channel(1);
        rx
    }

    /// Creates a real deadliner handle backed by [`FarFutureCalculator`] —
    /// `add()` always reports `Scheduled` but nothing naturally expires.
    fn far_future_handle() -> DeadlinerHandle {
        let (handle, _drop_rx) = DeadlinerTask::start(
            CancellationToken::new(),
            "dutydb-tests",
            FarFutureCalculator,
        );
        handle
    }

    fn make_db() -> MemDB {
        MemDB::new(
            far_future_handle(),
            noop_deadliner_rx(),
            &CancellationToken::new(),
        )
    }

    fn make_db_with_deadliner(deadliner: DeadlinerHandle, deadliner_rx: Receiver<Duty>) -> MemDB {
        MemDB::new(deadliner, deadliner_rx, &CancellationToken::new())
    }

    fn att_data(slot: u64, committee_index: u64, validator_index: u64) -> AttestationData {
        AttestationData {
            data: phase0::AttestationData {
                slot,
                index: committee_index,
                beacon_block_root: [0u8; 32],
                source: phase0::Checkpoint::default(),
                target: phase0::Checkpoint::default(),
            },
            duty: AttesterDuty {
                slot,
                validator_index,
                committee_index,
                committee_length: 8,
                committees_at_slot: 1,
                validator_committee_index: validator_index,
            },
        }
    }

    fn phase0_proposal(slot: u64, proposer_index: u64) -> VersionedProposal {
        use pluto_eth2api::spec::phase0 as p0;

        let block = p0::BeaconBlock {
            slot,
            proposer_index,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body: p0::BeaconBlockBody {
                randao_reveal: [0u8; 96],
                eth1_data: p0::ETH1Data {
                    deposit_root: [0u8; 32],
                    deposit_count: 0,
                    block_hash: [0u8; 32],
                },
                graffiti: [0u8; 32],
                proposer_slashings: vec![].into(),
                attester_slashings: vec![].into(),
                attestations: vec![].into(),
                deposits: vec![].into(),
                voluntary_exits: vec![].into(),
            },
        };
        VersionedProposal {
            block: ProposalBlock::Phase0(block),
            consensus_block_value: alloy::primitives::U256::ZERO,
            execution_payload_value: alloy::primitives::U256::ZERO,
        }
    }

    fn sync_contribution_fixture(
        slot: u64,
        subcommittee_index: u64,
        root: phase0::Root,
    ) -> SyncContribution {
        SyncContribution(altair::SyncCommitteeContribution {
            slot,
            beacon_block_root: root,
            subcommittee_index,
            aggregation_bits: pluto_ssz::BitVector::default(),
            signature: [0u8; 96],
        })
    }

    fn random_root(seed: u8) -> phase0::Root {
        [seed; 32]
    }

    #[tokio::test]
    async fn shutdown() {
        let db = make_db();
        db.shutdown();

        let err = db.await_proposal(999).await.unwrap_err();
        assert!(
            err.to_string().contains("shutdown"),
            "expected shutdown error, got: {err}"
        );
    }

    #[tokio::test]
    async fn mem_db() {
        let db = make_db();

        // Nothing in the DB yet.
        assert!(db.pub_key_by_attestation(0, 0, 0).await.is_err());

        const SLOT: u64 = 123;
        const COMM_IDX: u64 = 456;
        const V_IDX_A: u64 = 1;
        const V_IDX_B: u64 = 2;

        let pk_a = random_core_pub_key();
        let pk_b = random_core_pub_key();

        let duty = Duty::new(SlotNumber::new(SLOT), DutyType::Attester);

        let unsigned_a = att_data(SLOT, COMM_IDX, V_IDX_A);
        let unsigned_b = att_data(SLOT, COMM_IDX, V_IDX_B);

        let mut set = UnsignedDataSet::new();
        set.insert(pk_a, UnsignedDutyData::Attestation(unsigned_a.clone()));
        set.insert(pk_b, UnsignedDutyData::Attestation(unsigned_b.clone()));

        db.store(duty.clone(), set).await.unwrap();

        // Idempotent re-store.
        let mut set2 = UnsignedDataSet::new();
        set2.insert(pk_a, UnsignedDutyData::Attestation(unsigned_a.clone()));
        db.store(duty, set2).await.unwrap();

        let data = db.await_attestation(SLOT, COMM_IDX).await.unwrap();
        assert_eq!(data.slot, SLOT);
        assert_eq!(data.index, COMM_IDX);

        let resolved_a = db
            .pub_key_by_attestation(SLOT, COMM_IDX, V_IDX_A)
            .await
            .unwrap();
        assert_eq!(resolved_a, pk_a);

        let resolved_b = db
            .pub_key_by_attestation(SLOT, COMM_IDX, V_IDX_B)
            .await
            .unwrap();
        assert_eq!(resolved_b, pk_b);
    }

    #[tokio::test]
    async fn mem_db_store_unsupported() {
        let db = make_db();

        let unsupported = [
            DutyType::Unknown,
            DutyType::Signature,
            DutyType::Exit,
            DutyType::BuilderRegistration,
            DutyType::Randao,
            DutyType::PrepareAggregator,
            DutyType::SyncMessage,
            DutyType::PrepareSyncContribution,
            DutyType::InfoSync,
        ];

        for duty_type in unsupported {
            let duty_type_str = duty_type.to_string();
            let duty = Duty::new(SlotNumber::new(0), duty_type);
            let err = db.store(duty, UnsignedDataSet::new()).await.unwrap_err();
            assert!(
                err.to_string().contains("unsupported duty type"),
                "expected unsupported duty type for {duty_type_str}, got: {err}"
            );
        }

        let duty = Duty::new(SlotNumber::new(0), DutyType::BuilderProposer);
        let err = db.store(duty, UnsignedDataSet::new()).await.unwrap_err();
        assert!(
            matches!(err, Error::DeprecatedDutyBuilderProposer),
            "expected DeprecatedDutyBuilderProposer, got: {err}"
        );
    }

    /// `FarFutureCalculator` schedules every duty, so it can't exercise the
    /// `AddOutcome::NoDeadline` arm in `store()`. Back the DB with
    /// `NeverExpiringCalculator` (always `Ok(None)`) so that types without a
    /// deadline are rejected as `UnsupportedDutyType` — not misclassified as
    /// `ExpiredDuty`.
    #[tokio::test]
    async fn mem_db_store_no_deadline_rejected() {
        let (deadliner, drop_rx) = DeadlinerTask::start(
            CancellationToken::new(),
            "dutydb-tests",
            NeverExpiringCalculator,
        );
        let db = make_db_with_deadliner(deadliner, drop_rx);

        for duty_type in [DutyType::Exit, DutyType::BuilderRegistration] {
            let duty_type_str = duty_type.to_string();
            let duty = Duty::new(SlotNumber::new(0), duty_type);
            let err = db.store(duty, UnsignedDataSet::new()).await.unwrap_err();
            assert!(
                matches!(err, Error::UnsupportedDutyType),
                "expected UnsupportedDutyType for {duty_type_str}, got: {err}"
            );
        }
    }

    #[tokio::test]
    async fn mem_db_proposer() {
        let db = Arc::new(make_db());
        let slots = [123u64, 456, 789];

        let mut handles = Vec::new();
        for &slot in &slots {
            let db = Arc::clone(&db);
            handles.push(tokio::spawn(async move { db.await_proposal(slot).await }));
        }

        for (i, &slot) in slots.iter().enumerate() {
            let proposal = phase0_proposal(slot, u64::try_from(i).unwrap());
            let mut set = UnsignedDataSet::new();
            set.insert(
                random_core_pub_key(),
                UnsignedDutyData::Proposal(Box::new(proposal.clone())),
            );
            db.store(Duty::new(SlotNumber::new(slot), DutyType::Proposer), set)
                .await
                .unwrap();
        }

        for (handle, &slot) in handles.into_iter().zip(slots.iter()) {
            let proposal = handle.await.unwrap().unwrap();
            assert_eq!(proposal.slot(), slot);
        }
    }

    #[tokio::test]
    async fn mem_db_sync_contribution() {
        let db = Arc::new(make_db());

        for i in 0..3u8 {
            let slot = u64::from(i).saturating_add(100);
            let subcommittee_index = u64::from(i);
            let root = random_root(i);

            let contrib = sync_contribution_fixture(slot, subcommittee_index, root);

            let mut set = UnsignedDataSet::new();
            set.insert(
                random_core_pub_key(),
                UnsignedDutyData::SyncContribution(contrib.clone()),
            );

            db.store(
                Duty::new(SlotNumber::new(slot), DutyType::SyncContribution),
                set,
            )
            .await
            .unwrap();

            let resp = db
                .await_sync_contribution(slot, subcommittee_index, root)
                .await
                .unwrap();
            assert_eq!(resp.slot, slot);
            assert_eq!(resp.subcommittee_index, subcommittee_index);
            assert_eq!(resp.beacon_block_root, root);
        }
    }

    #[tokio::test]
    async fn dutydb_shutdown() {
        let db = make_db();
        db.shutdown();

        let err = db
            .await_sync_contribution(0, 0, [0u8; 32])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("shutdown"));
    }

    fn agg_attestation_fixture(
        slot: u64,
        committee_index: u64,
        validator_index: u64,
    ) -> VersionedAggregatedAttestation {
        let data = phase0::AttestationData {
            slot,
            index: committee_index,
            beacon_block_root: [0u8; 32],
            source: phase0::Checkpoint::default(),
            target: phase0::Checkpoint::default(),
        };
        let att = phase0::Attestation {
            aggregation_bits: phase0::BitList::<2048>::default(),
            data,
            signature: [0u8; 96],
        };
        VersionedAggregatedAttestation(versioned::VersionedAttestation {
            version: versioned::DataVersion::Phase0,
            validator_index: Some(validator_index),
            attestation: Some(versioned::AttestationPayload::Phase0(att)),
        })
    }

    #[tokio::test]
    async fn mem_db_aggregator() {
        let db = Arc::new(make_db());

        const SLOT: u64 = 200;
        const COMM_IDX: u64 = 3;
        const V_IDX: u64 = 7;

        let agg = agg_attestation_fixture(SLOT, COMM_IDX, V_IDX);
        let root = agg.data().unwrap().tree_hash_root().0;

        let db_clone = Arc::clone(&db);
        let waiter = tokio::spawn(async move { db_clone.await_agg_attestation(root).await });

        let mut set = UnsignedDataSet::new();
        set.insert(random_core_pub_key(), UnsignedDutyData::AggAttestation(agg));
        db.store(Duty::new(SlotNumber::new(SLOT), DutyType::Aggregator), set)
            .await
            .unwrap();

        let versioned_att = waiter.await.unwrap().unwrap();
        let resolved_data = versioned_att.attestation.unwrap();
        assert_eq!(resolved_data.data().slot, SLOT);
        assert_eq!(resolved_data.data().index, COMM_IDX);

        // Idempotent re-store.
        let agg2 = agg_attestation_fixture(SLOT, COMM_IDX, V_IDX);
        let mut set2 = UnsignedDataSet::new();
        set2.insert(
            random_core_pub_key(),
            UnsignedDutyData::AggAttestation(agg2),
        );
        db.store(Duty::new(SlotNumber::new(SLOT), DutyType::Aggregator), set2)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn clashing_public_key() {
        const SLOT: u64 = 50;
        const COMM_IDX: u64 = 1;
        const V_IDX: u64 = 5;

        let db = make_db();
        let pk_a = random_core_pub_key();
        let pk_b = random_core_pub_key();
        let duty = Duty::new(SlotNumber::new(SLOT), DutyType::Attester);

        let mut set1 = UnsignedDataSet::new();
        set1.insert(
            pk_a,
            UnsignedDutyData::Attestation(att_data(SLOT, COMM_IDX, V_IDX)),
        );
        db.store(duty.clone(), set1).await.unwrap();

        let mut set2 = UnsignedDataSet::new();
        set2.insert(
            pk_b,
            UnsignedDutyData::Attestation(att_data(SLOT, COMM_IDX, V_IDX)),
        );
        let err = db.store(duty, set2).await.unwrap_err();
        assert!(
            matches!(err, Error::ClashingPublicKey { .. }),
            "expected ClashingPublicKey, got: {err}"
        );
    }

    #[tokio::test]
    async fn clashing_attestation_data() {
        const SLOT: u64 = 51;
        const COMM_IDX: u64 = 2;

        let db = make_db();
        let duty = Duty::new(SlotNumber::new(SLOT), DutyType::Attester);

        let mut att_a = att_data(SLOT, COMM_IDX, 1);
        att_a.data.beacon_block_root = [0xaa; 32];

        let mut att_b = att_data(SLOT, COMM_IDX, 2);
        att_b.data.beacon_block_root = [0xbb; 32];

        let mut set1 = UnsignedDataSet::new();
        set1.insert(random_core_pub_key(), UnsignedDutyData::Attestation(att_a));
        db.store(duty.clone(), set1).await.unwrap();

        let mut set2 = UnsignedDataSet::new();
        set2.insert(random_core_pub_key(), UnsignedDutyData::Attestation(att_b));
        let err = db.store(duty, set2).await.unwrap_err();
        assert!(
            matches!(err, Error::ClashingAttestationData { .. }),
            "expected ClashingAttestationData, got: {err}"
        );
    }

    #[tokio::test]
    async fn shutdown_wakes_waiting_await() {
        let db = Arc::new(make_db());

        let db_clone = Arc::clone(&db);
        let waiter = tokio::spawn(async move { db_clone.await_proposal(9999).await });

        // Yield to give the waiter task a chance to park in select!.
        tokio::task::yield_now().await;

        db.shutdown();

        let err = waiter.await.unwrap().unwrap_err();
        println!("{err}");
        assert!(
            err.to_string().contains("shutdown"),
            "expected shutdown error, got: {err}"
        );
    }

    #[tokio::test]
    async fn clashing_sync_contributions() {
        const SLOT: u64 = 123;
        const SUBCOMM_IDX: u64 = 1;
        let root = random_root(42);

        let db = make_db();
        let pubkey = random_core_pub_key();
        let duty = Duty::new(SlotNumber::new(SLOT), DutyType::SyncContribution);

        let contrib1 = sync_contribution_fixture(SLOT, SUBCOMM_IDX, root);
        // Differ by aggregation_bits, which affects the SSZ tree-hash root.
        let mut contrib2 = sync_contribution_fixture(SLOT, SUBCOMM_IDX, root);
        contrib2.0.aggregation_bits = pluto_ssz::BitVector::with_bits(&[0]);

        let mut set1 = UnsignedDataSet::new();
        set1.insert(pubkey, UnsignedDutyData::SyncContribution(contrib1));
        db.store(duty.clone(), set1).await.unwrap();

        let mut set2 = UnsignedDataSet::new();
        set2.insert(pubkey, UnsignedDutyData::SyncContribution(contrib2));
        let err = db.store(duty, set2).await.unwrap_err();
        assert!(
            err.to_string().contains("clashing sync contributions"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn mem_db_clash_proposer() {
        const SLOT: u64 = 123;
        let db = make_db();
        let pubkey = random_core_pub_key();
        let duty = Duty::new(SlotNumber::new(SLOT), DutyType::Proposer);

        let block = phase0_proposal(SLOT, 0);

        let mut set = UnsignedDataSet::new();
        set.insert(pubkey, UnsignedDutyData::Proposal(Box::new(block.clone())));
        db.store(duty.clone(), set.clone()).await.unwrap();

        // Idempotent re-store.
        db.store(duty.clone(), set).await.unwrap();

        // Clashing block (different proposer index = different hash).
        let block_b = phase0_proposal(SLOT, 99);
        let mut set_b = UnsignedDataSet::new();
        set_b.insert(pubkey, UnsignedDutyData::Proposal(Box::new(block_b)));
        let err = db.store(duty, set_b).await.unwrap_err();
        assert!(err.to_string().contains("clashing blocks"), "got: {err}");
    }

    #[tokio::test]
    async fn duty_expiry() {
        // Real handle so `store()`'s `add(...)` returns `AddOutcome::Scheduled`.
        // Eviction is driven manually via `trim_tx` so the test stays
        // deterministic instead of racing the deadliner's timer.
        let deadliner = far_future_handle();
        let (trim_tx, trim_rx) = channel::<Duty>(64);
        let db = make_db_with_deadliner(deadliner, trim_rx);

        const SLOT: u64 = 123;

        let att = att_data(SLOT, 0, 0);
        let mut set = UnsignedDataSet::new();
        set.insert(
            random_core_pub_key(),
            UnsignedDutyData::Attestation(att.clone()),
        );
        db.store(Duty::new(SlotNumber::new(SLOT), DutyType::Attester), set)
            .await
            .unwrap();

        // Should be findable now.
        db.pub_key_by_attestation(SLOT, 0, 0).await.unwrap();

        // Expire the duty: simulate the deadliner emitting it.
        let expired_duty = Duty::new(SlotNumber::new(SLOT), DutyType::Attester);
        trim_tx
            .send(expired_duty)
            .await
            .expect("trim_tx should be open");

        // Trigger expiry processing by storing another duty.
        let proposal = phase0_proposal(SLOT.saturating_add(1), 0);
        let mut set2 = UnsignedDataSet::new();
        set2.insert(
            random_core_pub_key(),
            UnsignedDutyData::Proposal(Box::new(proposal)),
        );
        db.store(
            Duty::new(SlotNumber::new(SLOT.saturating_add(1)), DutyType::Proposer),
            set2,
        )
        .await
        .unwrap();

        // Should no longer be findable.
        assert!(db.pub_key_by_attestation(SLOT, 0, 0).await.is_err());
    }

    /// After a slot is evicted, `await_attestation` must return
    /// `AwaitDutyExpired` immediately (not park until the request timeout) for
    /// that slot AND for any older slot — the eviction state is a single
    /// high-water mark, so it stays O(1) in memory rather than accumulating one
    /// entry per evicted slot for the lifetime of the node.
    #[tokio::test]
    async fn await_attestation_expired_after_eviction_high_water() {
        let deadliner = far_future_handle();
        let (trim_tx, trim_rx) = channel::<Duty>(64);
        let db = make_db_with_deadliner(deadliner, trim_rx);

        const SLOT: u64 = 123;

        let mut set = UnsignedDataSet::new();
        set.insert(
            random_core_pub_key(),
            UnsignedDutyData::Attestation(att_data(SLOT, 0, 0)),
        );
        db.store(Duty::new(SlotNumber::new(SLOT), DutyType::Attester), set)
            .await
            .unwrap();

        // Evict SLOT, then trigger expiry processing with an unrelated store.
        trim_tx
            .send(Duty::new(SlotNumber::new(SLOT), DutyType::Attester))
            .await
            .expect("trim_tx should be open");
        let mut set2 = UnsignedDataSet::new();
        set2.insert(
            random_core_pub_key(),
            UnsignedDutyData::Proposal(Box::new(phase0_proposal(SLOT.saturating_add(1), 0))),
        );
        db.store(
            Duty::new(SlotNumber::new(SLOT.saturating_add(1)), DutyType::Proposer),
            set2,
        )
        .await
        .unwrap();

        // The evicted slot resolves to AwaitDutyExpired without parking.
        let timeout = std::time::Duration::from_secs(5);
        let evicted = tokio::time::timeout(timeout, db.await_attestation(SLOT, 0))
            .await
            .expect("await must not park for an evicted slot");
        assert!(
            matches!(evicted, Err(Error::AwaitDutyExpired)),
            "evicted slot: expected AwaitDutyExpired, got {evicted:?}"
        );

        // An older, never-stored slot is also below the high-water mark: its
        // deadline has necessarily passed too, so it must fail fast rather than
        // park — and we keep no per-slot record to answer this.
        let older = tokio::time::timeout(timeout, db.await_attestation(SLOT.saturating_sub(1), 0))
            .await
            .expect("await must not park for a slot below the eviction high-water");
        assert!(
            matches!(older, Err(Error::AwaitDutyExpired)),
            "older slot: expected AwaitDutyExpired, got {older:?}"
        );
    }

    #[tokio::test]
    async fn agg_attestation_two_roots_same_slot() {
        const SLOT: u64 = 300;
        let db = make_db();

        // Two aggregations at the same slot but different committee indices
        // produce different tree-hash roots and must coexist.
        let agg_a = agg_attestation_fixture(SLOT, 1, 0);
        let agg_b = agg_attestation_fixture(SLOT, 2, 0);
        let root_a = agg_a.data().unwrap().tree_hash_root().0;
        let root_b = agg_b.data().unwrap().tree_hash_root().0;
        assert_ne!(root_a, root_b);

        let duty = Duty::new(SlotNumber::new(SLOT), DutyType::Aggregator);
        let mut set = UnsignedDataSet::new();
        set.insert(
            random_core_pub_key(),
            UnsignedDutyData::AggAttestation(agg_a),
        );
        set.insert(
            random_core_pub_key(),
            UnsignedDutyData::AggAttestation(agg_b),
        );
        db.store(duty, set).await.unwrap();

        let att_a = db.await_agg_attestation(root_a).await.unwrap();
        assert_eq!(att_a.attestation.unwrap().data().slot, SLOT);

        let att_b = db.await_agg_attestation(root_b).await.unwrap();
        assert_eq!(att_b.attestation.unwrap().data().slot, SLOT);
    }

    #[tokio::test]
    async fn concurrent_attestation_waiters() {
        const SLOT: u64 = 400;
        const COMM_IDX: u64 = 5;
        const N: usize = 100;

        let db = Arc::new(make_db());
        let handles: Vec<_> = (0..N)
            .map(|_| {
                let db = Arc::clone(&db);
                tokio::spawn(async move { db.await_attestation(SLOT, COMM_IDX).await })
            })
            .collect();

        tokio::task::yield_now().await;

        let att = att_data(SLOT, COMM_IDX, 0);
        let mut set = UnsignedDataSet::new();
        set.insert(random_core_pub_key(), UnsignedDutyData::Attestation(att));
        db.store(Duty::new(SlotNumber::new(SLOT), DutyType::Attester), set)
            .await
            .unwrap();

        for handle in handles {
            let data = handle.await.unwrap().unwrap();
            assert_eq!(data.slot, SLOT);
            assert_eq!(data.index, COMM_IDX);
        }
    }

    #[tokio::test]
    async fn await_attestation_before_store() {
        const SLOT: u64 = 500;
        const COMM_IDX: u64 = 2;

        let db = Arc::new(make_db());
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let db = Arc::clone(&db);
                tokio::spawn(async move { db.await_attestation(SLOT, COMM_IDX).await })
            })
            .collect();

        tokio::task::yield_now().await;

        let att = att_data(SLOT, COMM_IDX, 0);
        let mut set = UnsignedDataSet::new();
        set.insert(random_core_pub_key(), UnsignedDutyData::Attestation(att));
        db.store(Duty::new(SlotNumber::new(SLOT), DutyType::Attester), set)
            .await
            .unwrap();

        for handle in handles {
            handle.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn await_before_shutdown() {
        let db = Arc::new(make_db());

        let db_clone = Arc::clone(&db);
        let waiter = tokio::spawn(async move { db_clone.await_attestation(9999, 0).await });

        tokio::task::yield_now().await;
        db.shutdown();

        let err = waiter.await.unwrap().unwrap_err();
        assert!(
            err.to_string().contains("shutdown"),
            "expected shutdown error, got: {err}"
        );
    }

    #[tokio::test]
    async fn shutdown_wakes_await_attestation() {
        let db = make_db();
        db.shutdown();

        let err = db.await_attestation(0, 0).await.unwrap_err();
        assert!(err.to_string().contains("shutdown"), "got: {err}");
    }

    #[tokio::test]
    async fn shutdown_wakes_await_agg_attestation() {
        let db = make_db();
        db.shutdown();

        let err = db.await_agg_attestation([0u8; 32]).await.unwrap_err();
        assert!(err.to_string().contains("shutdown"), "got: {err}");
    }

    #[tokio::test]
    async fn invalid_unsigned_type_proposer() {
        let db = make_db();
        let duty = Duty::new(SlotNumber::new(1), DutyType::Proposer);
        let mut set = UnsignedDataSet::new();
        set.insert(
            random_core_pub_key(),
            UnsignedDutyData::Attestation(att_data(1, 0, 0)),
        );
        let err = db.store(duty, set).await.unwrap_err();
        assert!(matches!(err, Error::InvalidVersionedProposal), "got: {err}");
    }

    #[tokio::test]
    async fn invalid_unsigned_type_attester() {
        let db = make_db();
        let duty = Duty::new(SlotNumber::new(1), DutyType::Attester);
        let mut set = UnsignedDataSet::new();
        set.insert(
            random_core_pub_key(),
            UnsignedDutyData::Proposal(Box::new(phase0_proposal(1, 0))),
        );
        let err = db.store(duty, set).await.unwrap_err();
        assert!(matches!(err, Error::InvalidAttestationData), "got: {err}");
    }

    #[tokio::test]
    async fn invalid_unsigned_type_aggregator() {
        let db = make_db();
        let duty = Duty::new(SlotNumber::new(1), DutyType::Aggregator);
        let mut set = UnsignedDataSet::new();
        set.insert(
            random_core_pub_key(),
            UnsignedDutyData::Attestation(att_data(1, 0, 0)),
        );
        let err = db.store(duty, set).await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidAggregatedAttestation),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn invalid_unsigned_type_sync_contribution() {
        let db = make_db();
        let duty = Duty::new(SlotNumber::new(1), DutyType::SyncContribution);
        let mut set = UnsignedDataSet::new();
        set.insert(
            random_core_pub_key(),
            UnsignedDutyData::Attestation(att_data(1, 0, 0)),
        );
        let err = db.store(duty, set).await.unwrap_err();
        assert!(matches!(err, Error::InvalidSyncContribution), "got: {err}");
    }
}
