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
    EthBeaconNodeApiClient, EthBeaconNodeApiClientError, GetBlockRootRequest, GetBlockRootResponse,
    GetSyncCommitteeDutiesRequest, GetSyncCommitteeDutiesResponse,
    GetSyncCommitteeDutiesResponseResponseDatum, PrepareSyncCommitteeSubnetsRequest,
    ProduceSyncCommitteeContributionRequest, ProduceSyncCommitteeContributionResponse,
    PublishContributionAndProofsRequest, SubmitPoolSyncCommitteeSignaturesRequest,
    SubmitSyncCommitteeSelectionsRequest, SubmitSyncCommitteeSelectionsResponse,
    spec::{
        altair::{
            ContributionAndProof, SignedContributionAndProof, SyncAggregatorSelectionData,
            SyncCommitteeContribution, SyncCommitteeMessage,
        },
        phase0::{BLSPubKey, BLSSignature, Epoch, Root, Slot, ValidatorIndex},
    },
};
use pluto_eth2util::{
    eth2exp::is_sync_comm_aggregator,
    helpers::epoch_from_slot,
    signing::{DomainName, get_data_root},
};
use tracing::info;
use tree_hash::TreeHash;

use super::{
    close_once::CloseOnce,
    error::{Error, Result},
    sign::SignFunc,
    validators::{ActiveValidators, active_validators},
};

/// Single sync-committee duty resolved for one of the local validators.
#[derive(Debug, Clone)]
pub struct SyncCommitteeDuty {
    /// Validator BLS public key.
    pub pubkey: BLSPubKey,
    /// Validator registry index.
    pub validator_index: ValidatorIndex,
    /// The validator's positions in the sync committee.
    pub validator_sync_committee_indices: Vec<u64>,
}

/// Aggregate sync-committee selection returned by the beacon node, post-DVT
/// aggregation. Mirrors `eth2v1.SyncCommitteeSelection`.
#[derive(Debug, Clone)]
struct SyncCommitteeSelection {
    validator_index: ValidatorIndex,
    slot: Slot,
    subcommittee_index: u64,
    selection_proof: BLSSignature,
}

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
    #[allow(dead_code)]
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

    let body: Vec<String> = vals.indices().map(|idx| idx.to_string()).collect();
    let request = GetSyncCommitteeDutiesRequest::builder()
        .epoch(epoch.to_string())
        .body(body)
        .build()
        .map_err(|e| Error::Malformed(format!("build sync committee duties request: {e}")))?;

    let response = client
        .get_sync_committee_duties(request)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    let GetSyncCommitteeDutiesResponse::Ok(payload) = response else {
        return Err(Error::BeaconNode(
            EthBeaconNodeApiClientError::UnexpectedResponse,
        ));
    };

    payload
        .data
        .into_iter()
        .map(parse_sync_committee_duty)
        .collect()
}

fn parse_sync_committee_duty(
    raw: GetSyncCommitteeDutiesResponseResponseDatum,
) -> Result<SyncCommitteeDuty> {
    let pubkey = parse_pubkey(&raw.pubkey)?;
    let validator_index = raw
        .validator_index
        .parse::<ValidatorIndex>()
        .map_err(|_| Error::Malformed(format!("parse validator_index: {}", raw.validator_index)))?;
    let validator_sync_committee_indices = raw
        .validator_sync_committee_indices
        .into_iter()
        .map(|s| {
            s.parse::<u64>()
                .map_err(|_| Error::Malformed(format!("parse sync committee index: {s}")))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(SyncCommitteeDuty {
        pubkey,
        validator_index,
        validator_sync_committee_indices,
    })
}

fn parse_pubkey(s: &str) -> Result<BLSPubKey> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|e| Error::Malformed(e.to_string()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed(format!("pubkey length {} != 48", bytes.len())))
}

async fn subscribe_sync_comm_subnets(
    client: &EthBeaconNodeApiClient,
    epoch: Epoch,
    duties: &[SyncCommitteeDuty],
) -> Result<()> {
    if duties.is_empty() {
        return Ok(());
    }

    let until_epoch = epoch.saturating_add(1).to_string();
    let body: Vec<pluto_eth2api::SyncCommitteeSubscriptionRequestBodyItem> = duties
        .iter()
        .map(
            |duty| pluto_eth2api::SyncCommitteeSubscriptionRequestBodyItem {
                sync_committee_indices: duty
                    .validator_sync_committee_indices
                    .iter()
                    .map(u64::to_string)
                    .collect(),
                until_epoch: until_epoch.clone(),
                validator_index: duty.validator_index.to_string(),
            },
        )
        .collect();

    let request = PrepareSyncCommitteeSubnetsRequest::builder()
        .body(body)
        .build()
        .map_err(|e| Error::Malformed(format!("build sync committee subscriptions: {e}")))?;

    client
        .prepare_sync_committee_subnets(request)
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

    let mut partials: Vec<pluto_eth2api::SyncCommitteeSelectionRequestRequestBodyItem> = Vec::new();
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
            partials.push(
                pluto_eth2api::SyncCommitteeSelectionRequestRequestBodyItem {
                    validator_index: duty.validator_index.to_string(),
                    slot: slot.to_string(),
                    subcommittee_index: subcomm_idx.to_string(),
                    selection_proof: hex_0x(sig),
                },
            );
        }
    }

    let request = SubmitSyncCommitteeSelectionsRequest::builder()
        .body(partials)
        .build()
        .map_err(|e| Error::Malformed(format!("build sync committee selections: {e}")))?;

    let response = client
        .submit_sync_committee_selections(request)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    let SubmitSyncCommitteeSelectionsResponse::Ok(payload) = response else {
        return Err(Error::BeaconNode(
            EthBeaconNodeApiClientError::UnexpectedResponse,
        ));
    };

    let mut selections = Vec::new();
    for raw in payload.data {
        let selection = parse_selection_wire(&raw)?;
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

fn parse_selection_wire(
    raw: &pluto_eth2api::SyncCommitteeSelectionRequestRequestBodyItem,
) -> Result<SyncCommitteeSelection> {
    let validator_index = raw
        .validator_index
        .parse::<ValidatorIndex>()
        .map_err(|_| Error::Malformed(format!("parse validator_index: {}", raw.validator_index)))?;
    let slot = raw
        .slot
        .parse::<Slot>()
        .map_err(|_| Error::Malformed(format!("parse slot: {}", raw.slot)))?;
    let subcommittee_index = raw.subcommittee_index.parse::<u64>().map_err(|_| {
        Error::Malformed(format!(
            "parse subcommittee_index: {}",
            raw.subcommittee_index
        ))
    })?;
    let selection_proof = decode_bls_signature(&raw.selection_proof)?;

    Ok(SyncCommitteeSelection {
        validator_index,
        slot,
        subcommittee_index,
        selection_proof,
    })
}

fn decode_bls_signature(s: &str) -> Result<BLSSignature> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|e| Error::Malformed(e.to_string()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed(format!("signature length {} != 96", bytes.len())))
}

fn decode_root(s: &str) -> Result<Root> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|e| Error::Malformed(e.to_string()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed(format!("root length {} != 32", bytes.len())))
}

fn hex_0x(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes.as_ref()))
}

/// Returns the subcommittee indices for `duty`. Mirrors Go's
/// `getSubcommittees`: `idx / (SYNC_COMMITTEE_SIZE /
/// SYNC_COMMITTEE_SUBNET_COUNT)`.
pub(crate) async fn get_subcommittees(
    client: &EthBeaconNodeApiClient,
    duty: &SyncCommitteeDuty,
) -> Result<Vec<u64>> {
    let spec = client.fetch_spec().await.map_err(Error::BeaconNode)?;

    let comm_size = spec_u64(&spec, "SYNC_COMMITTEE_SIZE")?;
    let subnet_count = spec_u64(&spec, "SYNC_COMMITTEE_SUBNET_COUNT")?;

    let divisor = comm_size
        .checked_div(subnet_count)
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

fn spec_u64(spec: &serde_json::Value, field: &str) -> Result<u64> {
    spec.as_object()
        .and_then(|o| o.get(field))
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Malformed(format!("missing spec field {field}")))?
        .parse::<u64>()
        .map_err(|_| Error::Malformed(format!("parse spec field {field}")))
}

async fn fetch_head_block_root(client: &EthBeaconNodeApiClient) -> Result<Root> {
    let request = GetBlockRootRequest::builder()
        .block_id("head".to_string())
        .build()
        .map_err(|e| Error::Malformed(format!("build block root request: {e}")))?;

    let response = client
        .get_block_root(request)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    let GetBlockRootResponse::Ok(payload) = response else {
        return Err(Error::BeaconNode(
            EthBeaconNodeApiClientError::UnexpectedResponse,
        ));
    };

    decode_root(&payload.data.root)
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

    let mut msgs: Vec<pluto_eth2api::SyncCommitteeRequestBodyItem> = Vec::new();
    for duty in duties {
        let sig = sign_func.sign(&duty.pubkey, &sig_data)?;
        // Build the altair value for SSZ/hash parity with Go, but the wire
        // shape POSTed to the beacon node uses stringified fields.
        let altair_msg = SyncCommitteeMessage {
            slot,
            beacon_block_root: block_root,
            validator_index: duty.validator_index,
            signature: sig,
        };
        msgs.push(pluto_eth2api::SyncCommitteeRequestBodyItem {
            slot: altair_msg.slot.to_string(),
            beacon_block_root: hex_0x(altair_msg.beacon_block_root),
            validator_index: altair_msg.validator_index.to_string(),
            signature: hex_0x(altair_msg.signature),
        });
    }

    let request = SubmitPoolSyncCommitteeSignaturesRequest::builder()
        .body(msgs)
        .build()
        .map_err(|e| Error::Malformed(format!("build sync committee messages: {e}")))?;

    client
        .submit_pool_sync_committee_signatures(request)
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

    let mut signed: Vec<pluto_eth2api::ContributionAndProofRequestBodyItem> = Vec::new();

    for selection in selections {
        // Query BN to get sync committee contribution.
        let request = ProduceSyncCommitteeContributionRequest::builder()
            .slot(selection.slot.to_string())
            .subcommittee_index(selection.subcommittee_index.to_string())
            .beacon_block_root(hex_0x(block_root))
            .build()
            .map_err(|e| Error::Malformed(format!("build produce contribution: {e}")))?;

        let response = client
            .produce_sync_committee_contribution(request)
            .await
            .map_err(EthBeaconNodeApiClientError::RequestError)?;

        let ProduceSyncCommitteeContributionResponse::Ok(payload) = response else {
            return Err(Error::BeaconNode(
                EthBeaconNodeApiClientError::UnexpectedResponse,
            ));
        };

        let contrib_value = serde_json::to_value(&payload.data)
            .map_err(|e| Error::Malformed(format!("serialise contribution: {e}")))?;
        let contribution: SyncCommitteeContribution = serde_json::from_value(contrib_value)
            .map_err(|e| Error::Malformed(format!("parse contribution: {e}")))?;

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

        let signed_payload = SignedContributionAndProof {
            message: contrib_and_proof,
            signature: sig,
        };

        signed.push(pluto_eth2api::ContributionAndProofRequestBodyItem {
            message: pluto_eth2api::AltairSignedContributionAndProofMessage {
                aggregator_index: signed_payload.message.aggregator_index.to_string(),
                contribution: pluto_eth2api::Contribution {
                    aggregation_bits: hex_0x(
                        &signed_payload.message.contribution.aggregation_bits.bytes,
                    ),
                    beacon_block_root: hex_0x(
                        signed_payload.message.contribution.beacon_block_root,
                    ),
                    signature: hex_0x(signed_payload.message.contribution.signature),
                    slot: signed_payload.message.contribution.slot.to_string(),
                    subcommittee_index: signed_payload
                        .message
                        .contribution
                        .subcommittee_index
                        .to_string(),
                },
                selection_proof: hex_0x(signed_payload.message.selection_proof),
            },
            signature: hex_0x(signed_payload.signature),
        });
    }

    let request = PublishContributionAndProofsRequest::builder()
        .body(signed)
        .build()
        .map_err(|e| Error::Malformed(format!("build contribution and proofs request: {e}")))?;

    client
        .publish_contribution_and_proofs(request)
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
    #[allow(clippy::redundant_test_prefix)]
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
