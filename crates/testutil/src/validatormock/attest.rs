//! Slot-level attestation and aggregation driver.
//!
//! Rust port of `charon/testutil/validatormock/attest.go`. [`SlotAttester`]
//! advances a single slot through `Prepare → Attest → Aggregate`, mirroring the
//! three-stage state machine from Go.
//!
//! Go uses `chan struct{}` channels closed once for each stage; Rust mirrors
//! that with `Arc<tokio::sync::OnceCell<()>>`: `OnceCell::set(())` closes the
//! channel, and `.wait().await` is the channel receive. Mutable state lives
//! behind `Arc<tokio::sync::Mutex<_>>` so the scheduler can hold a `&self`
//! handle.
//!
//! The mock originates Fulu-fork payloads (like Charon's vmock, which hardcodes
//! `DataVersionFulu`): attestations are submitted as versioned Fulu
//! attestations, which the client converts to the `SingleAttestation` wire
//! shape, and aggregates as Fulu `SignedAggregateAndProof`s. The goldens
//! capture the exact bytes.

use std::{collections::HashMap, sync::Arc};

use pluto_eth2api::{
    EthBeaconNodeApiClient, EthBeaconNodeApiClientError,
    spec::{
        electra,
        phase0::{AttestationData, BLSPubKey, Root, Slot, ValidatorIndex},
    },
    versioned::{
        AttestationPayload, DataVersion, SignedAggregateAndProofPayload, VersionedAttestation,
        VersionedSignedAggregateAndProof,
    },
};
use pluto_eth2util::{
    eth2exp::is_att_aggregator,
    helpers::epoch_from_slot,
    signing::{DomainName, get_data_root},
};
use pluto_ssz::{BitList, BitVector};
use tokio::sync::Mutex;
use tree_hash::TreeHash;

pub use pluto_eth2api::v1::{AttesterDuty, BeaconCommitteeSelection};

use super::{
    close_once::CloseOnce,
    error::{Error, Result},
    sign::SignFunc,
    validators::ActiveValidators,
};

/// Committee index type alias, mirroring Go's `eth2p0.CommitteeIndex` (uint64).
type CommitteeIndex = u64;

/// Fork the mock's payloads are tagged with.
const PAYLOAD_VERSION: DataVersion = DataVersion::Fulu;

/// Drives a single slot through `Prepare → Attest → Aggregate`.
///
/// All public entry points take `&self`; mutable state is owned by an internal
/// `Mutex`, and inter-stage ordering is enforced with three close-once
/// `OnceCell`s (one per stage) acting as Go's `chan struct{}` ready signals.
#[derive(Debug, Clone)]
pub struct SlotAttester {
    eth2_cl: Arc<EthBeaconNodeApiClient>,
    slot: Slot,
    #[expect(
        dead_code,
        reason = "matched against duties via the active-validator map"
    )]
    pubkeys: Vec<BLSPubKey>,
    sign_func: SignFunc,

    state: Arc<Mutex<MutableState>>,

    duties_ok: Arc<CloseOnce>,
    selections_ok: Arc<CloseOnce>,
    datas_ok: Arc<CloseOnce>,
}

#[derive(Debug, Default)]
struct MutableState {
    vals: ActiveValidators,
    duties: Vec<AttesterDuty>,
    selections: Vec<BeaconCommitteeSelection>,
    datas: Vec<AttestationData>,
}

impl SlotAttester {
    /// Builds a new attester for `slot`. The returned handle is cheap to clone
    /// and safe to share between the scheduler tasks.
    #[must_use]
    pub fn new(
        eth2_cl: Arc<EthBeaconNodeApiClient>,
        slot: Slot,
        sign_func: SignFunc,
        pubkeys: Vec<BLSPubKey>,
    ) -> Self {
        Self {
            eth2_cl,
            slot,
            pubkeys,
            sign_func,
            state: Arc::new(Mutex::new(MutableState::default())),
            duties_ok: Arc::new(CloseOnce::default()),
            selections_ok: Arc::new(CloseOnce::default()),
            datas_ok: Arc::new(CloseOnce::default()),
        }
    }

    /// Slot this attester drives.
    #[must_use]
    pub fn slot(&self) -> Slot {
        self.slot
    }

    /// Run the start-of-slot prep: fetch active validators, attester duties for
    /// the slot, and the beacon-committee selection for aggregators.
    ///
    /// Mirrors Go's `Prepare`. Calling twice on the same instance panics-like
    /// (the `set` calls on the close-once cells will return `Err`), which we
    /// silently swallow, matching the Go semantics of `close(ch)` on an
    /// already-closed channel only triggering an explicit panic; here we
    /// prefer idempotence.
    pub async fn prepare(&self) -> Result<()> {
        let vals = super::validators::active_validators(&self.eth2_cl).await?;

        let duties = prepare_attesters(&self.eth2_cl, &vals, self.slot).await?;
        self.set_prepare_duties(vals, duties.clone()).await;

        let selections =
            prepare_aggregators(&self.eth2_cl, &self.sign_func, &duties, self.slot).await?;
        self.set_prepare_selections(selections).await;

        Ok(())
    }

    /// Build attestation data and submit per-validator attestations.
    ///
    /// Awaits [`Self::prepare`]'s ready signal first, mirroring Go's
    /// `wait(ctx, a.dutiesOK)`.
    pub async fn attest(&self) -> Result<()> {
        self.duties_ok.wait().await;

        let duties = self.state.lock().await.duties.clone();
        let datas = attest(&self.eth2_cl, &self.sign_func, self.slot, &duties).await?;

        self.set_attest_datas(datas).await;
        Ok(())
    }

    /// Build aggregate-and-proof envelopes for selected aggregators and submit
    /// them. Returns `true` when at least one aggregate was submitted, matching
    /// Go's bool return.
    pub async fn aggregate(&self) -> Result<bool> {
        self.duties_ok.wait().await;
        self.selections_ok.wait().await;
        self.datas_ok.wait().await;

        let state = self.state.lock().await;
        aggregate(
            &self.eth2_cl,
            &self.sign_func,
            self.slot,
            &state.vals,
            &state.duties,
            &state.selections,
            &state.datas,
        )
        .await
    }

    async fn set_prepare_duties(&self, vals: ActiveValidators, duties: Vec<AttesterDuty>) {
        {
            let mut state = self.state.lock().await;
            state.vals = vals;
            state.duties = duties;
        }
        self.duties_ok.close();
    }

    async fn set_prepare_selections(&self, selections: Vec<BeaconCommitteeSelection>) {
        {
            let mut state = self.state.lock().await;
            state.selections = selections;
        }
        self.selections_ok.close();
    }

    async fn set_attest_datas(&self, datas: Vec<AttestationData>) {
        {
            let mut state = self.state.lock().await;
            state.datas = datas;
        }
        self.datas_ok.close();
    }
}

// ---------------------------------------------------------------------------
// Stage 1: attester duties
// ---------------------------------------------------------------------------

async fn prepare_attesters(
    eth2_cl: &EthBeaconNodeApiClient,
    vals: &ActiveValidators,
    slot: Slot,
) -> Result<Vec<AttesterDuty>> {
    if vals.is_empty() {
        return Ok(Vec::new());
    }

    let epoch = epoch_from_slot(eth2_cl, slot).await?;
    let indices: Vec<ValidatorIndex> = vals.indices().collect();

    let response = eth2_cl
        .get_attester_duties(epoch, &indices)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    Ok(response
        .data
        .into_iter()
        .filter(|duty| duty.slot == slot)
        .collect())
}

// ---------------------------------------------------------------------------
// Stage 2: aggregator selection
// ---------------------------------------------------------------------------

async fn prepare_aggregators(
    eth2_cl: &EthBeaconNodeApiClient,
    sign_func: &SignFunc,
    duties: &[AttesterDuty],
    slot: Slot,
) -> Result<Vec<BeaconCommitteeSelection>> {
    if duties.is_empty() {
        return Ok(Vec::new());
    }

    let epoch = epoch_from_slot(eth2_cl, slot).await?;
    let slot_root = slot.tree_hash_root().0;
    let sig_data = get_data_root(eth2_cl, DomainName::SelectionProof, epoch, slot_root).await?;

    let mut partials = Vec::with_capacity(duties.len());
    let mut comm_lengths: HashMap<ValidatorIndex, u64> = HashMap::with_capacity(duties.len());

    for duty in duties {
        let slot_sig = sign_func.sign(&duty.pubkey, &sig_data)?;
        comm_lengths.insert(duty.validator_index, duty.committee_length);

        partials.push(BeaconCommitteeSelection {
            selection_proof: slot_sig,
            slot: duty.slot,
            validator_index: duty.validator_index,
        });
    }

    let aggregate_selections = eth2_cl
        .submit_beacon_committee_selections(&partials)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    let mut selections = Vec::new();
    for selection in aggregate_selections {
        let comm_len = *comm_lengths
            .get(&selection.validator_index)
            .ok_or(Error::MissingValidatorIndex(selection.validator_index))?;

        if !is_att_aggregator(eth2_cl, comm_len, selection.selection_proof).await? {
            continue;
        }

        selections.push(selection);
    }

    Ok(selections)
}

// ---------------------------------------------------------------------------
// Stage 3: attest
// ---------------------------------------------------------------------------

async fn attest(
    eth2_cl: &EthBeaconNodeApiClient,
    sign_func: &SignFunc,
    slot: Slot,
    duties: &[AttesterDuty],
) -> Result<Vec<AttestationData>> {
    if duties.is_empty() {
        return Ok(Vec::new());
    }

    // Group duties by committee, preserving each duty list's insertion order.
    let mut comm_order: Vec<CommitteeIndex> = Vec::new();
    let mut duty_by_comm: HashMap<CommitteeIndex, Vec<&AttesterDuty>> = HashMap::new();
    for duty in duties {
        duty_by_comm
            .entry(duty.committee_index)
            .or_insert_with(|| {
                comm_order.push(duty.committee_index);
                Vec::new()
            })
            .push(duty);
    }

    let mut atts: Vec<VersionedAttestation> = Vec::new();
    let mut datas: Vec<AttestationData> = Vec::new();

    for comm_idx in &comm_order {
        let duty_list = duty_by_comm
            .get(comm_idx)
            .ok_or_else(|| malformed("duty group missing"))?;

        let data = eth2_cl
            .produce_attestation_data(slot, *comm_idx)
            .await
            .map_err(EthBeaconNodeApiClientError::RequestError)?;
        datas.push(data.clone());

        let root = data.tree_hash_root().0;
        let sig_data =
            get_data_root(eth2_cl, DomainName::BeaconAttester, data.target.epoch, root).await?;

        for duty in duty_list {
            let sig = sign_func.sign(&duty.pubkey, &sig_data)?;

            // The client converts each versioned attestation to the Electra+
            // `SingleAttestation` wire shape (go-eth2-client's
            // `ToSingleAttestation`): committee index from the committee bits,
            // attester index from the validator index.
            let committee_length = usize::try_from(duty.committee_length)
                .map_err(|_| malformed("committee length overflows usize"))?;
            let position = usize::try_from(duty.validator_committee_index)
                .map_err(|_| malformed("validator committee index overflows usize"))?;
            let committee = usize::try_from(duty.committee_index)
                .map_err(|_| malformed("committee index overflows usize"))?;
            atts.push(VersionedAttestation {
                version: PAYLOAD_VERSION,
                validator_index: Some(duty.validator_index),
                attestation: Some(AttestationPayload::Fulu(electra::Attestation {
                    aggregation_bits: BitList::with_bits(committee_length, &[position]),
                    data: data.clone(),
                    signature: sig,
                    committee_bits: BitVector::with_bits(&[committee]),
                })),
            });
        }
    }

    eth2_cl
        .submit_pool_attestations_v2(&atts)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    Ok(datas)
}

// ---------------------------------------------------------------------------
// Stage 4: aggregate
// ---------------------------------------------------------------------------

async fn aggregate(
    eth2_cl: &EthBeaconNodeApiClient,
    sign_func: &SignFunc,
    slot: Slot,
    vals: &ActiveValidators,
    duties: &[AttesterDuty],
    selections: &[BeaconCommitteeSelection],
    datas: &[AttestationData],
) -> Result<bool> {
    if selections.is_empty() {
        return Ok(false);
    }

    let epoch = epoch_from_slot(eth2_cl, slot).await?;

    let committees: HashMap<ValidatorIndex, CommitteeIndex> = duties
        .iter()
        .map(|duty| (duty.validator_index, duty.committee_index))
        .collect();

    let mut aggs: Vec<VersionedSignedAggregateAndProof> = Vec::new();
    let mut atts_by_comm: HashMap<CommitteeIndex, electra::Attestation> = HashMap::new();

    for selection in selections {
        let comm_idx = *committees
            .get(&selection.validator_index)
            .ok_or(Error::MissingValidatorIndex(selection.validator_index))?;

        let att = match atts_by_comm.get(&comm_idx) {
            Some(att) => att.clone(),
            None => {
                let att = get_aggregate_attestation(eth2_cl, datas, comm_idx).await?;
                atts_by_comm.insert(comm_idx, att.clone());
                att
            }
        };

        let proof_message = electra::AggregateAndProof {
            aggregator_index: selection.validator_index,
            aggregate: att,
            selection_proof: selection.selection_proof,
        };
        let proof_root = proof_message.tree_hash_root().0;
        let sig_data =
            get_data_root(eth2_cl, DomainName::AggregateAndProof, epoch, proof_root).await?;

        let pubkey = vals
            .get(selection.validator_index)
            .ok_or(Error::MissingValidatorIndex(selection.validator_index))?;

        let proof_sig = sign_func.sign(pubkey, &sig_data)?;

        aggs.push(VersionedSignedAggregateAndProof {
            version: PAYLOAD_VERSION,
            aggregate_and_proof: SignedAggregateAndProofPayload::Fulu(
                electra::SignedAggregateAndProof {
                    message: proof_message,
                    signature: proof_sig,
                },
            ),
        });
    }

    eth2_cl
        .publish_aggregate_and_proofs_v2(&aggs)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    Ok(true)
}

async fn get_aggregate_attestation(
    eth2_cl: &EthBeaconNodeApiClient,
    datas: &[AttestationData],
    comm_idx: CommitteeIndex,
) -> Result<electra::Attestation> {
    for data in datas {
        if data.index != comm_idx {
            continue;
        }

        let root: Root = data.tree_hash_root().0;
        let aggregate = eth2_cl
            .get_aggregated_attestation_v2(data.slot, comm_idx, root)
            .await
            .map_err(EthBeaconNodeApiClientError::RequestError)?;

        return match aggregate.attestation {
            Some(AttestationPayload::Electra(att) | AttestationPayload::Fulu(att)) => Ok(att),
            other => Err(malformed(format!(
                "expected an electra aggregate attestation, got {other:?}"
            ))),
        };
    }

    Err(Error::Malformed(
        "missing attestation data for committee index".into(),
    ))
}

fn malformed(s: impl Into<String>) -> Error {
    Error::Malformed(s.into())
}

// ---------------------------------------------------------------------------
// Tests: mirror Go's TestAttest for DutyFactor 0 and 1.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use assert_json_diff::assert_json_eq;
    use pluto_eth2api::spec::phase0::{BLSPubKey, BLSSignature};
    use serde_json::Value;

    use super::*;
    use crate::{
        BeaconMock, ValidatorSet,
        validatormock::{EndpointMatch, SubmissionCapture, error::SignError, sign::Sign},
    };

    /// Stub signer mirroring the Go test: copies the pubkey bytes into the
    /// signature, zero-padding the remaining 48 bytes.
    #[derive(Debug)]
    struct PubkeyEchoSigner;

    impl Sign for PubkeyEchoSigner {
        fn sign(
            &self,
            pubkey: &BLSPubKey,
            _data: &[u8],
        ) -> std::result::Result<BLSSignature, SignError> {
            let mut sig = [0u8; 96];
            sig[..48].copy_from_slice(pubkey);
            Ok(sig)
        }
    }

    async fn run_attest_case(
        duty_factor: u64,
        expect_attestations: usize,
        expect_aggregations: usize,
    ) {
        let valset = ValidatorSet::validator_set_a();
        let pubkeys = valset.public_keys();

        let mock = BeaconMock::builder()
            .validator_set(valset.clone())
            .deterministic_attester_duties(duty_factor)
            .build()
            .await
            .expect("build mock");

        // Phase 1's `active_validators` uses POST on `states/head/validators`;
        // the beaconmock only serves GET by default, so mount a POST
        // passthrough that returns the same payload as the GET handler.
        mount_post_state_validators(mock.server(), &valset).await;

        // `BeaconCommitteeSelections` is a DV-only endpoint not mounted by the
        // default beaconmock: Go's `beaconmock.New` runs the validator mock
        // against a DV middleware that echoes selections. We replicate the
        // echo: the response body is `{"data": <request body>}`.
        mount_echo_selections(mock.server()).await;

        // Capture submission bodies before invoking the SUT.
        let atts_capture = SubmissionCapture::mount(
            mock.server(),
            "POST",
            EndpointMatch::path("/eth/v2/beacon/pool/attestations"),
            serde_json::json!({}),
        )
        .await;
        let aggs_capture = SubmissionCapture::mount(
            mock.server(),
            "POST",
            EndpointMatch::path("/eth/v2/validator/aggregate_and_proofs"),
            serde_json::json!({}),
        )
        .await;

        // First slot in epoch 1.
        let (_seconds_per_slot, slots_per_epoch) = mock
            .client()
            .fetch_slots_config()
            .await
            .expect("fetch slots config");

        let sign_func: SignFunc = Arc::new(PubkeyEchoSigner);
        let attester = SlotAttester::new(
            Arc::new(mock.client().clone()),
            slots_per_epoch,
            sign_func,
            pubkeys,
        );

        attester.prepare().await.expect("prepare");
        attester.attest().await.expect("attest");
        let ok = attester.aggregate().await.expect("aggregate");
        assert_eq!(expect_aggregations > 0, ok);

        // The SUT issues exactly one POST to each endpoint. Both bodies are
        // bare JSON arrays: `SingleAttestation`s for attestations, and
        // `SignedAggregateAndProof`s for aggregate_and_proofs.
        let atts_bodies = atts_capture.take();
        assert_eq!(atts_bodies.len(), 1, "expected one POST to attestations");
        let mut atts_array = atts_bodies[0]
            .as_array()
            .cloned()
            .expect("attestations body is JSON array");

        let aggs_bodies = aggs_capture.take();
        assert_eq!(
            aggs_bodies.len(),
            1,
            "expected one POST to aggregate_and_proofs"
        );
        let mut aggs_array = aggs_bodies[0]
            .as_array()
            .cloned()
            .expect("aggregate_and_proofs body is JSON array");

        assert_eq!(atts_array.len(), expect_attestations);
        assert_eq!(aggs_array.len(), expect_aggregations);

        // Match Go's TestAttest deterministic ordering: sort by index.
        atts_array.sort_by_key(index_of_attestation);
        aggs_array.sort_by_key(index_of_aggregate);

        let atts_value = Value::Array(atts_array);
        let golden_atts: Value = serde_json::from_str(golden(duty_factor, "attestations"))
            .expect("parse attestations golden");
        assert_json_eq!(atts_value, golden_atts);

        let aggs_value = Value::Array(aggs_array);
        let golden_aggs: Value = serde_json::from_str(golden(duty_factor, "aggregations"))
            .expect("parse aggregations golden");
        assert_json_eq!(aggs_value, golden_aggs);
    }

    fn golden(duty_factor: u64, kind: &str) -> &'static str {
        match (duty_factor, kind) {
            (0, "attestations") => include_str!("testdata/TestAttest_0_attestations.golden"),
            (0, "aggregations") => include_str!("testdata/TestAttest_0_aggregations.golden"),
            (1, "attestations") => include_str!("testdata/TestAttest_1_attestations.golden"),
            (1, "aggregations") => include_str!("testdata/TestAttest_1_aggregations.golden"),
            _ => panic!("unknown golden combination"),
        }
    }

    fn index_of_attestation(value: &Value) -> u64 {
        // `SingleAttestation` is the wire shape; sort by attester index for a
        // deterministic order.
        value
            .get("attester_index")
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok())
            .unwrap_or(u64::MAX)
    }

    fn index_of_aggregate(value: &Value) -> u64 {
        value
            .get("message")
            .and_then(|m| m.get("aggregate"))
            .and_then(|a| a.get("data"))
            .and_then(|d| d.get("index"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok())
            .unwrap_or(u64::MAX)
    }

    async fn mount_echo_selections(server: &wiremock::MockServer) {
        use wiremock::{
            Mock, Request, ResponseTemplate,
            matchers::{method, path},
        };

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/beacon_committee_selections"))
            .respond_with(|request: &Request| {
                let body: Value =
                    serde_json::from_slice(&request.body).unwrap_or(Value::Array(Vec::new()));
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": body }))
            })
            .with_priority(2)
            .mount(server)
            .await;
    }

    async fn mount_post_state_validators(server: &wiremock::MockServer, valset: &ValidatorSet) {
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };

        let body = serde_json::json!({
            "data": valset.validators(),
            "execution_optimistic": false,
            "finalized": false,
        });

        // Priority 2: above defaults (255) but below capture (1).
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .with_priority(2)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn attest_duty_factor_0() {
        run_attest_case(0, 3, 3).await;
    }

    #[tokio::test]
    async fn attest_duty_factor_1() {
        run_attest_case(1, 1, 1).await;
    }
}
