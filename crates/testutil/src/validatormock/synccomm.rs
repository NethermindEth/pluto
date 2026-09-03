//! Sync-committee duty driver.
//!
//! Port of `charon/testutil/validatormock/synccomm.go`. [`SyncCommMember`] is a
//! stateful per-validator driver that ports the Go workflow:
//!
//! 1. [`SyncCommMember::prepare_epoch`] resolves sync committee duties and
//!    submits subscriptions.
//! 2. [`SyncCommMember::prepare_slot`] computes per-slot selection proofs.
//! 3. [`SyncCommMember::message`] submits sync committee messages at 1/3rd into
//!    the slot and records the beacon block root.
//! 4. [`SyncCommMember::aggregate`] submits aggregated contribution-and-proofs
//!    at 2/3rd into the slot.
//!
//! The Go `chan struct{}` close-once readiness flags become
//! `Arc<CloseOnce>` (a small `AtomicBool` + `tokio::sync::Notify` pair shared
//! with [`super::attest`]); the per-slot maps lazily insert entries on both
//! setter and getter paths so callers may await readiness before any producer
//! has touched the slot, exactly like the Go version.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use pluto_eth2api::{
    EthBeaconNodeApiClient, EthBeaconNodeApiClientError,
    spec::{
        altair::{
            ContributionAndProof, SignedContributionAndProof, SyncAggregatorSelectionData,
            SyncCommitteeMessage,
        },
        phase0::{BLSPubKey, Epoch, Root, Slot, ValidatorIndex},
    },
    v1::{SyncCommitteeSelection, SyncCommitteeSubscription},
};
use pluto_eth2util::{
    eth2exp::is_sync_comm_aggregator,
    helpers::epoch_from_slot,
    signing::{DomainName, get_data_root},
};
use tracing::info;
use tree_hash::TreeHash;

pub use pluto_eth2api::v1::SyncCommitteeDuty;

use super::{
    close_once::CloseOnce,
    error::{Error, Result},
    sign::SignFunc,
    validators::{ActiveValidators, active_validators},
};

/// Mutable state guarded by a single [`Mutex`]. The Go `mutable` embedded
/// struct.
#[derive(Default)]
struct Mutable {
    vals: ActiveValidators,
    duties: Vec<SyncCommitteeDuty>,
    selections: HashMap<Slot, Vec<SyncCommitteeSelection>>,
    selections_ok: HashMap<Slot, Arc<CloseOnce>>,
    block_root: HashMap<Slot, Root>,
    block_root_ok: HashMap<Slot, Arc<CloseOnce>>,
}

/// Stateful driver providing the sync-committee message and contribution
/// APIs for a single epoch. Created with [`SyncCommMember::new`] and driven
/// by a scheduler via [`SyncCommMember::prepare_epoch`],
/// [`SyncCommMember::prepare_slot`], [`SyncCommMember::message`] and
/// [`SyncCommMember::aggregate`].
pub struct SyncCommMember {
    // Immutable state.
    eth2_cl: EthBeaconNodeApiClient,
    epoch: Epoch,
    #[expect(dead_code, reason = "reserved for duty matching against pubkeys")]
    pubkeys: Vec<BLSPubKey>,
    sign_func: SignFunc,

    // Mutable state.
    mutable: Mutex<Mutable>,
    duties_ok: Arc<CloseOnce>,
}

impl SyncCommMember {
    /// Builds a new sync committee member driver for `epoch`. Mirrors Go's
    /// `NewSyncCommMember`.
    #[must_use]
    pub fn new(
        eth2_cl: EthBeaconNodeApiClient,
        epoch: Epoch,
        sign_func: SignFunc,
        pubkeys: Vec<BLSPubKey>,
    ) -> Self {
        Self {
            eth2_cl,
            epoch,
            pubkeys,
            sign_func,
            mutable: Mutex::new(Mutable::default()),
            duties_ok: Arc::new(CloseOnce::default()),
        }
    }

    /// Returns the epoch this driver was constructed for.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    // -- mutable-state helpers (mirror the Go set*/get* methods). --

    fn set_selections(&self, slot: Slot, selections: Vec<SyncCommitteeSelection>) {
        let cell = {
            let mut guard = lock(&self.mutable);
            guard.selections.insert(slot, selections);
            Arc::clone(
                guard
                    .selections_ok
                    .entry(slot)
                    .or_insert_with(|| Arc::new(CloseOnce::default())),
            )
        };

        cell.close();
    }

    fn get_selections(&self, slot: Slot) -> Vec<SyncCommitteeSelection> {
        lock(&self.mutable)
            .selections
            .get(&slot)
            .cloned()
            .unwrap_or_default()
    }

    fn get_selections_ok(&self, slot: Slot) -> Arc<CloseOnce> {
        let mut guard = lock(&self.mutable);
        Arc::clone(
            guard
                .selections_ok
                .entry(slot)
                .or_insert_with(|| Arc::new(CloseOnce::default())),
        )
    }

    fn set_block_root(&self, slot: Slot, block_root: Root) {
        let cell = {
            let mut guard = lock(&self.mutable);
            guard.block_root.insert(slot, block_root);
            Arc::clone(
                guard
                    .block_root_ok
                    .entry(slot)
                    .or_insert_with(|| Arc::new(CloseOnce::default())),
            )
        };

        cell.close();
    }

    fn get_block_root(&self, slot: Slot) -> Root {
        lock(&self.mutable)
            .block_root
            .get(&slot)
            .copied()
            .unwrap_or_default()
    }

    fn get_block_root_ok(&self, slot: Slot) -> Arc<CloseOnce> {
        let mut guard = lock(&self.mutable);
        Arc::clone(
            guard
                .block_root_ok
                .entry(slot)
                .or_insert_with(|| Arc::new(CloseOnce::default())),
        )
    }

    fn set_duties(&self, vals: ActiveValidators, duties: Vec<SyncCommitteeDuty>) {
        {
            let mut guard = lock(&self.mutable);
            guard.vals = vals;
            guard.duties = duties;
        }
        self.duties_ok.close();
    }

    fn get_duties(&self) -> Vec<SyncCommitteeDuty> {
        lock(&self.mutable).duties.clone()
    }

    fn get_vals(&self) -> ActiveValidators {
        lock(&self.mutable).vals.clone()
    }

    // -- public workflow methods. --

    /// Resolves sync committee duties for this epoch and submits subscriptions
    /// covering the next epoch.
    pub async fn prepare_epoch(&self) -> Result<()> {
        let vals = active_validators(&self.eth2_cl).await?;
        let duties = prepare_sync_comm_duties(&self.eth2_cl, &vals, self.epoch).await?;
        self.set_duties(vals, duties.clone());
        subscribe_sync_comm_subnets(&self.eth2_cl, self.epoch, &duties).await?;
        Ok(())
    }

    /// Computes aggregate selection proofs for `slot` and marks them ready for
    /// [`SyncCommMember::aggregate`] consumers.
    pub async fn prepare_slot(&self, slot: Slot) -> Result<()> {
        self.duties_ok.wait().await;

        let selections =
            prepare_sync_selections(&self.eth2_cl, &self.sign_func, &self.get_duties(), slot)
                .await?;

        self.set_selections(slot, selections);
        Ok(())
    }

    /// Submits sync-committee messages at 1/3rd into the slot and records the
    /// beacon block root that drove them. Mirrors Go's `Message`.
    pub async fn message(&self, slot: Slot) -> Result<()> {
        self.duties_ok.wait().await;

        let duties = self.get_duties();
        if duties.is_empty() {
            self.set_block_root(slot, Root::default());
            return Ok(());
        }

        let block_root = fetch_head_block_root(&self.eth2_cl).await?;

        submit_sync_messages(&self.eth2_cl, slot, block_root, &self.sign_func, &duties).await?;

        self.set_block_root(slot, block_root);
        Ok(())
    }

    /// Submits aggregated contribution-and-proofs at 2/3rd into the slot.
    /// Blocks until duties, selections and the slot's beacon block root are
    /// ready. Returns `true` if contributions were submitted, `false` if there
    /// were no aggregator selections for this slot.
    pub async fn aggregate(&self, slot: Slot) -> Result<bool> {
        self.duties_ok.wait().await;
        self.get_selections_ok(slot).wait().await;
        self.get_block_root_ok(slot).wait().await;

        agg_contributions(
            &self.eth2_cl,
            &self.sign_func,
            slot,
            &self.get_vals(),
            &self.get_selections(slot),
            self.get_block_root(slot),
        )
        .await
    }
}

// -- helper functions (mirror the lowercase Go helpers). --

async fn prepare_sync_comm_duties(
    client: &EthBeaconNodeApiClient,
    vals: &ActiveValidators,
    epoch: Epoch,
) -> Result<Vec<SyncCommitteeDuty>> {
    if vals.is_empty() {
        return Ok(Vec::new());
    }

    let indices: Vec<ValidatorIndex> = vals.indices().collect();
    let response = client
        .get_sync_committee_duties(epoch, &indices)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    Ok(response.data)
}

async fn subscribe_sync_comm_subnets(
    client: &EthBeaconNodeApiClient,
    epoch: Epoch,
    duties: &[SyncCommitteeDuty],
) -> Result<()> {
    if duties.is_empty() {
        return Ok(());
    }

    let until_epoch = epoch.saturating_add(1);
    let subscriptions: Vec<SyncCommitteeSubscription> = duties
        .iter()
        .map(|duty| SyncCommitteeSubscription {
            validator_index: duty.validator_index,
            sync_committee_indices: duty.validator_sync_committee_indices.clone(),
            until_epoch,
        })
        .collect();

    client
        .prepare_sync_committee_subnets(&subscriptions)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    info!(epoch = epoch, "Mock sync committee subscription submitted");

    Ok(())
}

async fn prepare_sync_selections(
    client: &EthBeaconNodeApiClient,
    sign_func: &SignFunc,
    duties: &[SyncCommitteeDuty],
    slot: Slot,
) -> Result<Vec<SyncCommitteeSelection>> {
    if duties.is_empty() {
        return Ok(Vec::new());
    }

    let epoch = epoch_from_slot(client, slot).await?;

    let mut partials: Vec<SyncCommitteeSelection> = Vec::new();
    for duty in duties {
        let subcomm_idxs = get_subcommittees(client, duty).await?;
        for subcomm_idx in subcomm_idxs {
            let data = SyncAggregatorSelectionData {
                slot,
                subcommittee_index: subcomm_idx,
            };
            let sig_root = data.tree_hash_root().0;
            let sig_data = get_data_root(
                client,
                DomainName::SyncCommitteeSelectionProof,
                epoch,
                sig_root,
            )
            .await?;
            let sig = sign_func.sign(&duty.pubkey, &sig_data)?;
            partials.push(SyncCommitteeSelection {
                validator_index: duty.validator_index,
                slot,
                subcommittee_index: subcomm_idx,
                selection_proof: sig,
            });
        }
    }

    let aggregated = client
        .submit_sync_committee_selections(&partials)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    let mut selections = Vec::new();
    for selection in aggregated {
        let is_aggregator = is_sync_comm_aggregator(client, selection.selection_proof)
            .await
            .map_err(|e| Error::Malformed(format!("is_sync_comm_aggregator: {e}")))?;
        if !is_aggregator {
            continue;
        }
        selections.push(selection);
    }

    info!(
        aggregators = selections.len(),
        "Resolved sync committee aggregators"
    );

    Ok(selections)
}

/// Returns the subcommittee indices for `duty`. Mirrors Go's
/// `getSubcommittees`: `idx / (SYNC_COMMITTEE_SIZE /
/// SYNC_COMMITTEE_SUBNET_COUNT)`.
pub(crate) async fn get_subcommittees(
    client: &EthBeaconNodeApiClient,
    duty: &SyncCommitteeDuty,
) -> Result<Vec<u64>> {
    let spec = client.fetch_spec().await.map_err(Error::BeaconNode)?;

    let divisor = spec
        .sync_committee_size
        .checked_div(spec.sync_committee_subnet_count)
        .ok_or_else(|| Error::Malformed("zero SYNC_COMMITTEE_SUBNET_COUNT".to_string()))?;
    if divisor == 0 {
        return Err(Error::Malformed(
            "SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT is zero".to_string(),
        ));
    }

    let mut subcommittees = Vec::with_capacity(duty.validator_sync_committee_indices.len());
    for idx in &duty.validator_sync_committee_indices {
        let subcomm_idx = idx
            .checked_div(divisor)
            .ok_or_else(|| Error::Malformed("divide by zero in subcommittee index".to_string()))?;
        subcommittees.push(subcomm_idx);
    }

    Ok(subcommittees)
}

async fn fetch_head_block_root(client: &EthBeaconNodeApiClient) -> Result<Root> {
    let response = client
        .get_block_root("head")
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    Ok(response.data)
}

async fn submit_sync_messages(
    client: &EthBeaconNodeApiClient,
    slot: Slot,
    block_root: Root,
    sign_func: &SignFunc,
    duties: &[SyncCommitteeDuty],
) -> Result<()> {
    if duties.is_empty() {
        return Ok(());
    }

    let epoch = epoch_from_slot(client, slot).await?;
    let sig_data = get_data_root(client, DomainName::SyncCommittee, epoch, block_root).await?;

    let mut msgs: Vec<SyncCommitteeMessage> = Vec::new();
    for duty in duties {
        let sig = sign_func.sign(&duty.pubkey, &sig_data)?;
        msgs.push(SyncCommitteeMessage {
            slot,
            beacon_block_root: block_root,
            validator_index: duty.validator_index,
            signature: sig,
        });
    }

    client
        .submit_pool_sync_committee_signatures(&msgs)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    info!(slot = slot, "Mock sync committee msg submitted");

    Ok(())
}

async fn agg_contributions(
    client: &EthBeaconNodeApiClient,
    sign_func: &SignFunc,
    slot: Slot,
    vals: &ActiveValidators,
    selections: &[SyncCommitteeSelection],
    block_root: Root,
) -> Result<bool> {
    if selections.is_empty() {
        return Ok(false);
    }

    let epoch = epoch_from_slot(client, slot).await?;

    let mut signed: Vec<SignedContributionAndProof> = Vec::new();

    for selection in selections {
        // Query BN to get sync committee contribution.
        let contribution = client
            .produce_sync_committee_contribution(
                selection.slot,
                selection.subcommittee_index,
                block_root,
            )
            .await
            .map_err(EthBeaconNodeApiClientError::RequestError)?;

        let v_idx = selection.validator_index;
        let contrib_and_proof = ContributionAndProof {
            aggregator_index: v_idx,
            contribution,
            selection_proof: selection.selection_proof,
        };

        let pubkey = vals
            .get(v_idx)
            .copied()
            .ok_or(Error::MissingValidatorIndex(v_idx))?;

        let proof_root = contrib_and_proof.tree_hash_root().0;
        let sig_data =
            get_data_root(client, DomainName::ContributionAndProof, epoch, proof_root).await?;
        let sig = sign_func.sign(&pubkey, &sig_data)?;

        signed.push(SignedContributionAndProof {
            message: contrib_and_proof,
            signature: sig,
        });
    }

    client
        .publish_contribution_and_proofs(&signed)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    Ok(true)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beaconmock::BeaconMock;

    fn fake_pubkey() -> BLSPubKey {
        let mut k = [0u8; 48];
        for (i, slot) in k.iter_mut().enumerate() {
            // Deterministic non-zero pattern; this test does not verify the
            // value, only that `get_subcommittees` divides indices correctly.
            *slot = u8::try_from(i & 0xff).expect("u8");
        }
        k
    }

    /// Ports `TestGetSubcommittees` from `synccomm_internal_test.go`:
    /// SYNC_COMMITTEE_SIZE=512, SYNC_COMMITTEE_SUBNET_COUNT=4, so each
    /// subnet contains 128 indices, and indices [75, 133, 289, 491] map to
    /// subcommittees [0, 1, 2, 3].
    #[tokio::test]
    #[expect(
        clippy::redundant_test_prefix,
        reason = "test name mirrors the Go test identifier"
    )]
    async fn test_get_subcommittees() {
        let mock = BeaconMock::builder()
            .sync_committee_size(512)
            .sync_committee_subnet_count(4)
            .build()
            .await
            .expect("build mock");

        let duty = SyncCommitteeDuty {
            pubkey: fake_pubkey(),
            validator_index: 0,
            validator_sync_committee_indices: vec![75, 133, 289, 491],
        };

        let subcommittees = get_subcommittees(mock.client(), &duty)
            .await
            .expect("get_subcommittees");

        assert_eq!(subcommittees, vec![0, 1, 2, 3]);
    }
}
