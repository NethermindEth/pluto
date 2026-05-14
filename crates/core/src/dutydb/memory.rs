//! In-memory DutyDB implementation.
//!
//! Equivalent to charon/core/dutydb/memory.go.

use std::{collections::HashMap, sync::Arc};

use pluto_eth2api::{
    spec::{altair, phase0},
    versioned,
};
use tokio::sync::{Notify, RwLock};
use tokio_util::sync::CancellationToken;
use tree_hash::TreeHash;

use crate::{
    deadline::Deadliner,
    signeddata::{
        AttestationData, SyncContribution, VersionedAggregatedAttestation, VersionedProposal,
    },
    types::{Duty, DutyType, PubKey},
};

/// Error type for DutyDB operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Duty has already expired; data not stored.
    #[error("not storing unsigned data for expired duty")]
    ExpiredDuty,

    /// Proposer data set must contain at most one entry.
    #[error("unexpected proposer data set length")]
    UnexpectedProposerSetLength,

    /// DutyBuilderProposer is no longer supported.
    #[error("deprecated duty DutyBuilderProposer")]
    DeprecatedDutyBuilderProposer,

    /// Duty type is not stored by DutyDB.
    #[error("unsupported duty type")]
    UnsupportedDutyType,

    /// DB was shut down before the query could be answered.
    #[error("dutydb shutdown")]
    Shutdown,

    /// Two validators mapped to the same (slot, commIdx, valIdx) with different
    /// public keys.
    #[error("clashing public key")]
    ClashingPublicKey,

    /// Two different attestation data objects for the same (slot, commIdx).
    #[error("clashing attestation data")]
    ClashingAttestationData,

    /// Mismatched source checkpoint when storing commIdx=0 compatibility entry.
    #[error("clashing attestation data with hardcoded commidx=0 source")]
    ClashingAttestationDataCommIdx0Source,

    /// Mismatched target checkpoint when storing commIdx=0 compatibility entry.
    #[error("clashing attestation data with hardcoded commidx=0 target")]
    ClashingAttestationDataCommIdx0Target,

    /// Two different aggregated attestations for the same slot+root key.
    #[error("clashing data root")]
    ClashingDataRoot,

    /// Two different sync contributions for the same (slot, subcommIdx, root).
    #[error("clashing sync contributions")]
    ClashingSyncContributions,

    /// Two different blocks for the same slot.
    #[error("clashing blocks")]
    ClashingBlocks,

    /// No public key found for the given (slot, commIdx, valIdx).
    #[error("pubkey not found")]
    PubKeyNotFound,

    /// Duty type is not handled by deleteDutyUnsafe.
    #[error("unknown duty type")]
    UnknownDutyType,

    /// The unsigned data provided does not match the expected type for
    /// DutyProposer.
    #[error("invalid versioned proposal")]
    InvalidVersionedProposal,

    /// The unsigned data provided does not match the expected type for
    /// DutyAttester.
    #[error("invalid unsigned attestation data")]
    InvalidAttestationData,

    /// The unsigned data provided does not match the expected type for
    /// DutyAggregator.
    #[error("invalid unsigned aggregated attestation")]
    InvalidAggregatedAttestation,

    /// The unsigned data provided does not match the expected type for
    /// DutySyncContribution.
    #[error("invalid unsigned sync committee contribution")]
    InvalidSyncContribution,
}

/// Result type for DutyDB operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Unsigned duty data variant — matches Go's `core.UnsignedData` interface.
#[derive(Debug, Clone)]
pub enum UnsignedDutyData {
    /// Unsigned proposal (DutyProposer).
    Proposal(Box<VersionedProposal>),
    /// Unsigned attestation data (DutyAttester).
    Attestation(AttestationData),
    /// Unsigned aggregated attestation (DutyAggregator).
    AggAttestation(VersionedAggregatedAttestation),
    /// Unsigned sync contribution (DutySyncContribution).
    SyncContribution(SyncContribution),
}

/// Map from public key to unsigned duty data, equivalent to Go's
/// `core.UnsignedDataSet`.
pub type UnsignedDataSet = HashMap<PubKey, UnsignedDutyData>;

/// Lookup key for attestation data: (slot, committee index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AttKey {
    slot: u64,
    committee_idx: u64,
}

/// Lookup key for public-key-by-attestation: (slot, committee index, validator
/// index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PkKey {
    slot: u64,
    committee_idx: u64,
    validator_idx: u64,
}

/// Lookup key for aggregated attestations: (slot, attestation data root).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AggKey {
    slot: u64,
    root: phase0::Root,
}

/// Lookup key for sync contributions: (slot, subcommittee index, beacon block
/// root).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ContribKey {
    slot: u64,
    subcomm_idx: u64,
    root: phase0::Root,
}

struct State {
    att_duties: HashMap<AttKey, phase0::AttestationData>,
    att_pub_keys: HashMap<PkKey, PubKey>,
    att_keys_by_slot: HashMap<u64, Vec<PkKey>>,

    pro_duties: HashMap<u64, VersionedProposal>,

    agg_duties: HashMap<AggKey, VersionedAggregatedAttestation>,
    agg_keys_by_slot: HashMap<u64, Vec<AggKey>>,

    contrib_duties: HashMap<ContribKey, altair::SyncCommitteeContribution>,
    contrib_keys_by_slot: HashMap<u64, Vec<ContribKey>>,

    deadliner_rx: Option<tokio::sync::mpsc::Receiver<Duty>>,
}

/// In-memory DutyDB.
///
/// Equivalent to charon's `MemDB`. Stores unsigned duty data and answers
/// blocking `await_*` queries when the relevant data becomes available.
pub struct MemDB {
    state: RwLock<State>,
    att_notify: Notify,
    pro_notify: Notify,
    agg_notify: Notify,
    contrib_notify: Notify,
    cancel: CancellationToken,
    deadliner: Arc<dyn Deadliner>,
}

impl MemDB {
    /// Creates a new in-memory DutyDB.
    pub fn new(deadliner: Arc<dyn Deadliner>, cancel: CancellationToken) -> Self {
        let deadliner_rx = deadliner.c();
        Self {
            state: RwLock::new(State {
                att_duties: HashMap::new(),
                att_pub_keys: HashMap::new(),
                att_keys_by_slot: HashMap::new(),
                pro_duties: HashMap::new(),
                agg_duties: HashMap::new(),
                agg_keys_by_slot: HashMap::new(),
                contrib_duties: HashMap::new(),
                contrib_keys_by_slot: HashMap::new(),
                deadliner_rx,
            }),
            att_notify: Notify::new(),
            pro_notify: Notify::new(),
            agg_notify: Notify::new(),
            contrib_notify: Notify::new(),
            cancel,
            deadliner,
        }
    }

    /// Shuts down the DB, causing all pending `await_*` calls to return an
    /// error.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }

    /// Stores unsigned duty data for the given duty, waking any pending
    /// waiters.
    pub async fn store(&self, duty: Duty, unsigned_set: UnsignedDataSet) -> Result<()> {
        let mut state = self.state.write().await;

        if !self.deadliner.add(duty.clone()).await {
            return Err(Error::ExpiredDuty);
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
                self.pro_notify.notify_waiters();
            }
            DutyType::BuilderProposer => return Err(Error::DeprecatedDutyBuilderProposer),
            DutyType::Attester => {
                for (pubkey, data) in &unsigned_set {
                    let att = match data {
                        UnsignedDutyData::Attestation(a) => a,
                        _ => return Err(Error::InvalidAttestationData),
                    };
                    state.store_attestation(*pubkey, att)?;
                }
                self.att_notify.notify_waiters();
            }
            DutyType::Aggregator => {
                for data in unsigned_set.values() {
                    let agg = match data {
                        UnsignedDutyData::AggAttestation(a) => a,
                        _ => return Err(Error::InvalidAggregatedAttestation),
                    };
                    state.store_agg_attestation(agg)?;
                }
                self.agg_notify.notify_waiters();
            }
            DutyType::SyncContribution => {
                for data in unsigned_set.values() {
                    let contrib = match data {
                        UnsignedDutyData::SyncContribution(c) => c,
                        _ => return Err(Error::InvalidSyncContribution),
                    };
                    state.store_sync_contribution(contrib)?;
                }
                self.contrib_notify.notify_waiters();
            }
            _ => return Err(Error::UnsupportedDutyType),
        }

        // Drain all expired duties that the deadliner has sent.
        loop {
            let expired = match state.deadliner_rx {
                Some(ref mut rx) => match rx.try_recv() {
                    Ok(d) => d,
                    Err(_) => break,
                },
                None => break,
            };
            state.delete_duty(expired)?;
        }

        Ok(())
    }

    /// Blocks until a proposal for the given slot is available, then returns
    /// it.
    pub async fn await_proposal(&self, slot: u64) -> Result<VersionedProposal> {
        self.await_data(&self.pro_notify, |s| s.pro_duties.get(&slot))
            .await
    }

    /// Blocks until attestation data for the given slot and committee index is
    /// available.
    pub async fn await_attestation(
        &self,
        slot: u64,
        comm_idx: u64,
    ) -> Result<phase0::AttestationData> {
        let key = AttKey {
            slot,
            committee_idx: comm_idx,
        };
        self.await_data(&self.att_notify, |s| s.att_duties.get(&key))
            .await
    }

    /// Blocks until an aggregated attestation for the given slot and
    /// attestation root is available.
    pub async fn await_agg_attestation(
        &self,
        slot: u64,
        attestation_root: phase0::Root,
    ) -> Result<versioned::VersionedAttestation> {
        let key = AggKey {
            slot,
            root: attestation_root,
        };
        self.await_data(&self.agg_notify, |s| s.agg_duties.get(&key).map(|a| &a.0))
            .await
    }

    /// Blocks until a sync contribution for the given slot, subcommittee index,
    /// and beacon block root is available.
    pub async fn await_sync_contribution(
        &self,
        slot: u64,
        subcomm_idx: u64,
        beacon_block_root: phase0::Root,
    ) -> Result<altair::SyncCommitteeContribution> {
        let key = ContribKey {
            slot,
            subcomm_idx,
            root: beacon_block_root,
        };
        self.await_data(&self.contrib_notify, |s| s.contrib_duties.get(&key))
            .await
    }

    async fn await_data<V>(
        &self,
        notify: &Notify,
        lookup: impl for<'s> Fn(&'s State) -> Option<&'s V>,
    ) -> Result<V>
    where
        V: Clone,
    {
        loop {
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            {
                let state = self.state.read().await;
                if let Some(v) = lookup(&state) {
                    return Ok(v.clone());
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
        comm_idx: u64,
        val_idx: u64,
    ) -> Result<PubKey> {
        let state = self.state.read().await;
        state
            .att_pub_keys
            .get(&PkKey {
                slot,
                committee_idx: comm_idx,
                validator_idx: val_idx,
            })
            .copied()
            .ok_or(Error::PubKeyNotFound)
    }
}

impl State {
    fn store_proposal(&mut self, proposal: &VersionedProposal) -> Result<()> {
        let slot = proposal.slot();
        if let Some(existing) = self.pro_duties.get(&slot) {
            if existing.root() != proposal.root() {
                return Err(Error::ClashingBlocks);
            }
        } else {
            self.pro_duties.insert(slot, proposal.clone());
        }
        Ok(())
    }

    fn store_attestation(&mut self, pubkey: PubKey, att: &AttestationData) -> Result<()> {
        let slot = att.data.slot;
        let duty_slot = att.duty.slot;
        let comm_idx = att.duty.committee_index;
        let val_idx = att.duty.validator_index;

        self.store_att_pubkey(slot, duty_slot, comm_idx, val_idx, pubkey)?;
        self.store_att_data(slot, comm_idx, &att.data)?;
        self.store_att_compat_commidx0(slot, duty_slot, val_idx, pubkey, &att.data)?;

        Ok(())
    }

    fn store_att_pubkey(
        &mut self,
        slot: u64,
        duty_slot: u64,
        comm_idx: u64,
        val_idx: u64,
        pubkey: PubKey,
    ) -> Result<()> {
        let pk_key = PkKey {
            slot,
            committee_idx: comm_idx,
            validator_idx: val_idx,
        };
        if let Some(&existing) = self.att_pub_keys.get(&pk_key) {
            if existing != pubkey {
                return Err(Error::ClashingPublicKey);
            }
        } else {
            self.att_pub_keys.insert(pk_key, pubkey);
            self.att_keys_by_slot
                .entry(duty_slot)
                .or_default()
                .push(pk_key);
        }
        Ok(())
    }

    fn store_att_data(
        &mut self,
        slot: u64,
        comm_idx: u64,
        data: &phase0::AttestationData,
    ) -> Result<()> {
        let att_key = AttKey {
            slot,
            committee_idx: comm_idx,
        };
        if let Some(existing) = self.att_duties.get(&att_key) {
            if existing.source != data.source
                || existing.target != data.target
                || existing.beacon_block_root != data.beacon_block_root
            {
                return Err(Error::ClashingAttestationData);
            }
        } else {
            self.att_duties.insert(att_key, data.clone());
        }
        Ok(())
    }

    // Store pubkey and attestation data with commIdx=0 for post-Electra VC
    // compatibility. See: https://ethereum.github.io/beacon-APIs/#/Validator/produceAttestationData
    fn store_att_compat_commidx0(
        &mut self,
        slot: u64,
        duty_slot: u64,
        val_idx: u64,
        pubkey: PubKey,
        data: &phase0::AttestationData,
    ) -> Result<()> {
        let pk_key0 = PkKey {
            slot,
            committee_idx: 0,
            validator_idx: val_idx,
        };
        if let Some(&existing) = self.att_pub_keys.get(&pk_key0) {
            if existing != pubkey {
                return Err(Error::ClashingPublicKey);
            }
        } else {
            self.att_pub_keys.insert(pk_key0, pubkey);
            self.att_keys_by_slot
                .entry(duty_slot)
                .or_default()
                .push(pk_key0);
        }

        let att_key0 = AttKey {
            slot,
            committee_idx: 0,
        };
        if let Some(existing) = self.att_duties.get(&att_key0) {
            if existing.source != data.source {
                return Err(Error::ClashingAttestationDataCommIdx0Source);
            }
            if existing.target != data.target {
                return Err(Error::ClashingAttestationDataCommIdx0Target);
            }
        } else {
            self.att_duties.insert(att_key0, data.clone());
        }
        Ok(())
    }

    fn store_agg_attestation(&mut self, agg: &VersionedAggregatedAttestation) -> Result<()> {
        let att_data = agg.data().ok_or(Error::InvalidAggregatedAttestation)?;
        let root = att_data.tree_hash_root().0;
        let slot = att_data.slot;

        let key = AggKey { slot, root };
        if let Some(existing) = self.agg_duties.get(&key) {
            let existing_data = existing.data().ok_or(Error::InvalidAggregatedAttestation)?;
            if existing_data.tree_hash_root().0 != root {
                return Err(Error::ClashingDataRoot);
            }
        } else {
            self.agg_keys_by_slot.entry(slot).or_default().push(key);
        }
        self.agg_duties.insert(key, agg.clone());

        Ok(())
    }

    fn store_sync_contribution(&mut self, contrib: &SyncContribution) -> Result<()> {
        let inner = &contrib.0;
        let contrib_root = inner.tree_hash_root().0;

        let key = ContribKey {
            slot: inner.slot,
            subcomm_idx: inner.subcommittee_index,
            root: inner.beacon_block_root,
        };

        if let Some(existing) = self.contrib_duties.get(&key) {
            if existing.tree_hash_root().0 != contrib_root {
                return Err(Error::ClashingSyncContributions);
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

    fn delete_duty(&mut self, duty: Duty) -> Result<()> {
        let slot = duty.slot.inner();
        match duty.duty_type {
            DutyType::Proposer => {
                self.pro_duties.remove(&slot);
            }
            DutyType::BuilderProposer => return Err(Error::DeprecatedDutyBuilderProposer),
            DutyType::Attester => {
                if let Some(keys) = self.att_keys_by_slot.remove(&slot) {
                    for key in keys {
                        self.att_pub_keys.remove(&key);
                        self.att_duties.remove(&AttKey {
                            slot: key.slot,
                            committee_idx: key.committee_idx,
                        });
                    }
                }
            }
            DutyType::Aggregator => {
                if let Some(keys) = self.agg_keys_by_slot.remove(&slot) {
                    for key in keys {
                        self.agg_duties.remove(&key);
                    }
                }
            }
            DutyType::SyncContribution => {
                if let Some(keys) = self.contrib_keys_by_slot.remove(&slot) {
                    for key in keys {
                        self.contrib_duties.remove(&key);
                    }
                }
            }
            _ => return Err(Error::UnknownDutyType),
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::{
        signeddata::{AttesterDuty, ProposalBlock},
        testutils::random_core_pub_key,
        types::{DutyType, SlotNumber},
    };

    /// Deadliner that always accepts duties and never expires them.
    pub(crate) struct NoopDeadliner;

    #[async_trait]
    impl Deadliner for NoopDeadliner {
        async fn add(&self, _duty: Duty) -> bool {
            true
        }

        fn c(&self) -> Option<tokio::sync::mpsc::Receiver<Duty>> {
            None
        }
    }

    /// Deadliner that collects duties and can flush them to a channel on
    /// demand.
    pub(crate) struct TestDeadliner {
        added: std::sync::Mutex<Vec<Duty>>,
        tx: tokio::sync::mpsc::Sender<Duty>,
        rx: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Duty>>>,
    }

    impl TestDeadliner {
        pub(crate) fn new() -> Arc<Self> {
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            Arc::new(Self {
                added: std::sync::Mutex::new(Vec::new()),
                tx,
                rx: std::sync::Mutex::new(Some(rx)),
            })
        }

        /// Send all collected duties to the expiry channel.
        pub(crate) async fn expire(&self) {
            let duties: Vec<Duty> = {
                let mut added = self.added.lock().unwrap();
                std::mem::take(&mut *added)
            };
            for duty in duties {
                let _ = self.tx.send(duty).await;
            }
        }
    }

    #[async_trait]
    impl Deadliner for TestDeadliner {
        async fn add(&self, duty: Duty) -> bool {
            self.added.lock().unwrap().push(duty);
            true
        }

        fn c(&self) -> Option<tokio::sync::mpsc::Receiver<Duty>> {
            self.rx.lock().unwrap().take()
        }
    }

    fn make_db() -> MemDB {
        MemDB::new(Arc::new(NoopDeadliner), CancellationToken::new())
    }

    fn make_db_with_deadliner(deadliner: Arc<dyn Deadliner>) -> MemDB {
        MemDB::new(deadliner, CancellationToken::new())
    }

    fn att_data(slot: u64, comm_idx: u64, val_idx: u64) -> AttestationData {
        AttestationData {
            data: phase0::AttestationData {
                slot,
                index: comm_idx,
                beacon_block_root: [0u8; 32],
                source: phase0::Checkpoint {
                    epoch: 0,
                    root: [0u8; 32],
                },
                target: phase0::Checkpoint {
                    epoch: 0,
                    root: [0u8; 32],
                },
            },
            duty: AttesterDuty {
                slot,
                validator_index: val_idx,
                committee_index: comm_idx,
                committee_length: 8,
                committees_at_slot: 1,
                validator_committee_index: val_idx,
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
            version: versioned::DataVersion::Phase0,
            blinded: false,
            block: ProposalBlock::Phase0(block),
        }
    }

    fn sync_contribution_fixture(
        slot: u64,
        subcomm_idx: u64,
        root: phase0::Root,
    ) -> SyncContribution {
        SyncContribution(altair::SyncCommitteeContribution {
            slot,
            beacon_block_root: root,
            subcommittee_index: subcomm_idx,
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
            let subcomm_idx = u64::from(i);
            let root = random_root(i);

            let contrib = sync_contribution_fixture(slot, subcomm_idx, root);

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
                .await_sync_contribution(slot, subcomm_idx, root)
                .await
                .unwrap();
            assert_eq!(resp.slot, slot);
            assert_eq!(resp.subcommittee_index, subcomm_idx);
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

    #[tokio::test]
    async fn clashing_sync_contributions() {
        const SLOT: u64 = 123;
        const SUBCOMM_IDX: u64 = 1;
        let root = random_root(42);

        let db = make_db();
        let pubkey = random_core_pub_key();
        let duty = Duty::new(SlotNumber::new(SLOT), DutyType::SyncContribution);

        let contrib1 = sync_contribution_fixture(SLOT, SUBCOMM_IDX, root);
        let mut contrib2 = sync_contribution_fixture(SLOT, SUBCOMM_IDX, root);
        // Make them differ by changing the signature.
        contrib2.0.signature = [1u8; 96];

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
    async fn mem_db_clashing_blocks() {
        const SLOT: u64 = 123;
        let db = make_db();
        let pubkey = random_core_pub_key();
        let duty = Duty::new(SlotNumber::new(SLOT), DutyType::Proposer);

        let block1 = phase0_proposal(SLOT, 1);
        let block2 = phase0_proposal(SLOT, 2);

        let mut set1 = UnsignedDataSet::new();
        set1.insert(pubkey, UnsignedDutyData::Proposal(Box::new(block1)));
        db.store(duty.clone(), set1).await.unwrap();

        let mut set2 = UnsignedDataSet::new();
        set2.insert(pubkey, UnsignedDutyData::Proposal(Box::new(block2)));
        let err = db.store(duty, set2).await.unwrap_err();
        assert!(err.to_string().contains("clashing blocks"), "got: {err}");
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
        let deadliner = TestDeadliner::new();
        let db = make_db_with_deadliner(Arc::clone(&deadliner) as Arc<dyn Deadliner>);

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

        // Expire the duty.
        deadliner.expire().await;

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
}
