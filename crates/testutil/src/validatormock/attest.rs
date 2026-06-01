//! Slot-level attestation and aggregation driver.
//!
//! Rust port of `charon/testutil/validatormock/attest.go`. [`SlotAttester`]
//! advances a single slot through `Prepare → Attest → Aggregate`, mirroring the
//! three-stage state machine from Go.
//!
//! Go uses `chan struct{}` channels closed once for each stage; Rust mirrors
//! that with `Arc<tokio::sync::OnceCell<()>>` — `OnceCell::set(())` closes the
//! channel, and `.wait().await` is the channel receive. Mutable state lives
//! behind `Arc<tokio::sync::Mutex<_>>` so the scheduler can hold a `&self`
//! handle.
//!
//! ## Wire-format note
//!
//! Charon's Go validator mock sends `*eth2spec.VersionedAttestation` and
//! `*eth2spec.VersionedSignedAggregateAndProof` JSON to the beacon node.
//! The Rust [`pluto_eth2api`] generated client encodes attestations using the
//! `SingleAttestation` shape (Electra+) which is incompatible with the Go
//! payload shape captured in the goldens. We therefore bypass the typed client
//! for the two submit endpoints (`POST /eth/v2/beacon/pool/attestations` and
//! `POST /eth/v2/validator/aggregate_and_proofs`) and submit raw JSON whose
//! structure matches the Go `eth2spec.VersionedAttestation` /
//! `*SubmitAggregateAttestationsOpts` serializations. All other beacon-node
//! interactions use the generated client.
//!
//! The byte-for-byte parity with the Go goldens is what current consumers
//! (Charon-as-beacon-node fakes in the DV test harness) expect. The shape has
//! NOT been validated end-to-end against a real beacon node — if a future
//! integration needs that, either the typed client must learn the
//! `VersionedAttestation` wire shape or we switch to the spec-conformant
//! `SingleAttestation` payload and regenerate the goldens. On non-success
//! responses [`submit_json`] surfaces the HTTP status and response body so a
//! mismatch against a real beacon node would show up directly in the error
//! message rather than as a silent reqwest failure.

use std::{collections::HashMap, sync::Arc};

use pluto_eth2api::{
    EthBeaconNodeApiClient, EthBeaconNodeApiClientError, GetAggregatedAttestationV2Request,
    GetAggregatedAttestationV2Response, GetAttesterDutiesRequest, GetAttesterDutiesResponse,
    ProduceAttestationDataRequest, ProduceAttestationDataResponse,
    SubmitBeaconCommitteeSelectionsRequest, SubmitBeaconCommitteeSelectionsResponse,
    spec::{
        electra,
        phase0::{AttestationData, BLSPubKey, BLSSignature, Root, Slot, ValidatorIndex},
    },
};
use pluto_eth2util::{
    eth2exp::is_att_aggregator,
    helpers::epoch_from_slot,
    signing::{DomainName, get_data_root},
};
use pluto_ssz::{BitList, BitVector};
use serde::Serialize;
use serde_with::serde_as;
use tokio::sync::Mutex;
use tree_hash::TreeHash;

use super::{
    close_once::CloseOnce,
    error::{Error, Result},
    sign::SignFunc,
    validators::ActiveValidators,
};

/// Committee index type alias, mirroring Go's `eth2p0.CommitteeIndex` (uint64).
type CommitteeIndex = u64;

/// Single-slot attester duty as returned by
/// `/eth/v1/validator/duties/attester`.
///
/// Mirrors `*eth2v1.AttesterDuty` after parsing the string-encoded JSON fields
/// into typed integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttesterDuty {
    /// Validator public key.
    pub pubkey: BLSPubKey,
    /// Validator's beacon-chain index.
    pub validator_index: ValidatorIndex,
    /// Committee index for this slot.
    pub committee_index: CommitteeIndex,
    /// Number of validators in the committee.
    pub committee_length: u64,
    /// Number of committees active at this slot.
    pub committees_at_slot: u64,
    /// Position of this validator inside the committee.
    pub validator_committee_index: u64,
    /// Slot at which the validator must attest.
    pub slot: Slot,
}

/// Selected aggregator entry returned by
/// `/eth/v1/validator/beacon_committee_selections`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconCommitteeSelection {
    /// Validator index.
    pub validator_index: ValidatorIndex,
    /// Slot the validator is attesting at.
    pub slot: Slot,
    /// Aggregated selection proof signature.
    pub selection_proof: BLSSignature,
}

/// Drives a single slot through `Prepare → Attest → Aggregate`.
///
/// All public entry points take `&self`; mutable state is owned by an internal
/// `Mutex`, and inter-stage ordering is enforced with three close-once
/// `OnceCell`s (one per stage) acting as Go's `chan struct{}` ready signals.
#[derive(Debug, Clone)]
pub struct SlotAttester {
    eth2_cl: Arc<EthBeaconNodeApiClient>,
    slot: Slot,
    #[allow(dead_code)] // matched against duties via the active-validator map
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
    /// silently swallow — matching the Go semantics of `close(ch)` on an
    /// already-closed channel only triggering an explicit panic; here we
    /// prefer idempotence.
    pub async fn prepare(&self) -> Result<()> {
        let vals = super::validators::active_validators(&self.eth2_cl).await?;

        let duties = prepare_attesters(&self.eth2_cl, &vals, self.slot).await?;
        self.set_prepare_duties(vals, duties.clone()).await;

        let selections = prepare_aggregators(
            &self.eth2_cl,
            &self.sign_func,
            &self.state,
            &duties,
            self.slot,
        )
        .await?;
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

    let indices: Vec<String> = vals.indices().map(|i| i.to_string()).collect();

    let request = GetAttesterDutiesRequest::builder()
        .epoch(epoch.to_string())
        .body(indices)
        .build()
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    let response = eth2_cl
        .get_attester_duties(request)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    let data = match response {
        GetAttesterDutiesResponse::Ok(ok) => ok.data,
        _ => return Err(EthBeaconNodeApiClientError::UnexpectedResponse.into()),
    };

    let mut duties = Vec::new();
    for datum in &data {
        let duty = parse_duty(datum)?;
        if duty.slot != slot {
            continue;
        }
        duties.push(duty);
    }

    Ok(duties)
}

fn parse_duty(
    datum: &pluto_eth2api::GetAttesterDutiesResponseResponseDatum,
) -> Result<AttesterDuty> {
    let pubkey = parse_pubkey(&datum.pubkey)?;
    let validator_index =
        parse_u64(&datum.validator_index).ok_or_else(|| malformed("validator_index"))?;
    let committee_index =
        parse_u64(&datum.committee_index).ok_or_else(|| malformed("committee_index"))?;
    let committee_length =
        parse_u64(&datum.committee_length).ok_or_else(|| malformed("committee_length"))?;
    let committees_at_slot =
        parse_u64(&datum.committees_at_slot).ok_or_else(|| malformed("committees_at_slot"))?;
    let validator_committee_index = parse_u64(&datum.validator_committee_index)
        .ok_or_else(|| malformed("validator_committee_index"))?;
    let slot = parse_u64(&datum.slot).ok_or_else(|| malformed("slot"))?;

    Ok(AttesterDuty {
        pubkey,
        validator_index,
        committee_index,
        committee_length,
        committees_at_slot,
        validator_committee_index,
        slot,
    })
}

// ---------------------------------------------------------------------------
// Stage 2: aggregator selection
// ---------------------------------------------------------------------------

async fn prepare_aggregators(
    eth2_cl: &EthBeaconNodeApiClient,
    sign_func: &SignFunc,
    _state: &Arc<Mutex<MutableState>>,
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

        partials.push(
            pluto_eth2api::BeaconCommitteeSelectionRequestRequestBodyItem {
                selection_proof: format!("0x{}", hex::encode(slot_sig)),
                slot: duty.slot.to_string(),
                validator_index: duty.validator_index.to_string(),
            },
        );
    }

    let request = SubmitBeaconCommitteeSelectionsRequest::builder()
        .body(partials)
        .build()
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    let response = eth2_cl
        .submit_beacon_committee_selections(request)
        .await
        .map_err(EthBeaconNodeApiClientError::RequestError)?;

    let aggregate_selections = match response {
        SubmitBeaconCommitteeSelectionsResponse::Ok(ok) => ok.data,
        _ => return Err(EthBeaconNodeApiClientError::UnexpectedResponse.into()),
    };

    let mut selections = Vec::new();
    for item in aggregate_selections {
        let validator_index =
            parse_u64(&item.validator_index).ok_or_else(|| malformed("validator_index"))?;
        let slot = parse_u64(&item.slot).ok_or_else(|| malformed("slot"))?;
        let selection_proof = parse_signature(&item.selection_proof)?;

        let comm_len = *comm_lengths
            .get(&validator_index)
            .ok_or(Error::MissingValidatorIndex(validator_index))?;

        if !is_att_aggregator(eth2_cl, comm_len, selection_proof).await? {
            continue;
        }

        selections.push(BeaconCommitteeSelection {
            validator_index,
            slot,
            selection_proof,
        });
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

    let mut atts: Vec<VersionedAttestationJson> = Vec::new();
    let mut datas: Vec<AttestationData> = Vec::new();

    for comm_idx in &comm_order {
        let duty_list = duty_by_comm
            .get(comm_idx)
            .ok_or_else(|| malformed("duty group missing"))?;

        let request = ProduceAttestationDataRequest::builder()
            .slot(slot.to_string())
            .committee_index(comm_idx.to_string())
            .build()
            .map_err(EthBeaconNodeApiClientError::RequestError)?;

        let response = eth2_cl
            .produce_attestation_data(request)
            .await
            .map_err(EthBeaconNodeApiClientError::RequestError)?;

        let data: AttestationData = match response {
            ProduceAttestationDataResponse::Ok(ok) => {
                // `Data` uses loose string fields; round-trip through JSON to
                // get the strongly typed `AttestationData` (with numeric slot,
                // index, hex roots, etc.).
                let value = serde_json::to_value(&ok.data).map_err(|e| malformed(e.to_string()))?;
                serde_json::from_value(value).map_err(|e| malformed(e.to_string()))?
            }
            _ => return Err(EthBeaconNodeApiClientError::UnexpectedResponse.into()),
        };
        datas.push(data.clone());

        let root = data.tree_hash_root().0;
        let sig_data =
            get_data_root(eth2_cl, DomainName::BeaconAttester, data.target.epoch, root).await?;

        for duty in duty_list {
            let sig = sign_func.sign(&duty.pubkey, &sig_data)?;

            let agg_bits = BitList::<131_072>::with_bits(
                usize_from_u64(duty.committee_length)?,
                &[usize_from_u64(duty.validator_committee_index)?],
            );
            let comm_bits = BitVector::<64>::with_bits(&[usize_from_u64(duty.committee_index)?]);

            atts.push(VersionedAttestationJson {
                version: "fulu",
                validator_index: duty.validator_index,
                phase0: None,
                altair: None,
                bellatrix: None,
                capella: None,
                deneb: None,
                electra: None,
                fulu: Some(electra::Attestation {
                    aggregation_bits: agg_bits,
                    data: data.clone(),
                    signature: sig,
                    committee_bits: comm_bits,
                }),
            });
        }
    }

    submit_attestations(eth2_cl, &atts).await?;

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

    let mut aggs: Vec<VersionedSignedAggregateAndProofJson> = Vec::new();
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

        aggs.push(VersionedSignedAggregateAndProofJson {
            version: "fulu",
            phase0: None,
            altair: None,
            bellatrix: None,
            capella: None,
            deneb: None,
            electra: None,
            fulu: Some(electra::SignedAggregateAndProof {
                message: proof_message,
                signature: proof_sig,
            }),
        });
    }

    submit_aggregate_attestations(eth2_cl, &aggs).await?;

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
        let request = GetAggregatedAttestationV2Request::builder()
            .attestation_data_root(format!("0x{}", hex::encode(root)))
            .slot(data.slot.to_string())
            .committee_index(comm_idx.to_string())
            .build()
            .map_err(EthBeaconNodeApiClientError::RequestError)?;

        let response = eth2_cl
            .get_aggregated_attestation_v2(request)
            .await
            .map_err(EthBeaconNodeApiClientError::RequestError)?;

        let data = match response {
            GetAggregatedAttestationV2Response::Ok(ok) => ok.data,
            _ => return Err(EthBeaconNodeApiClientError::UnexpectedResponse.into()),
        };
        // Beaconmock serves the Fulu-shaped Object variant; decode via JSON
        // round-trip into the typed `electra::Attestation` since the generated
        // Object variant has loosely typed string fields.
        let value = serde_json::to_value(&data).map_err(|e| malformed(e.to_string()))?;
        let att: electra::Attestation =
            serde_json::from_value(value).map_err(|e| malformed(e.to_string()))?;
        return Ok(att);
    }

    Err(Error::Malformed(
        "missing attestation data for committee index".into(),
    ))
}

// ---------------------------------------------------------------------------
// Raw POST helpers
// ---------------------------------------------------------------------------
//
// These submit the Go `*eth2spec.VersionedAttestation` /
// `*SubmitAggregateAttestationsOpts` JSON shape, NOT the typed-client
// `SingleAttestation` shape that the generated `submit_pool_attestations_v2`
// would produce. See the module-level docstring for the rationale and the
// follow-up tracked there. Errors surface the HTTP status AND response body
// (via [`Error::SubmitStatus`]) so beacon-node validation failures are visible
// — matching the diagnostic richness of Go's typed `SubmitAttestations` error.

/// Maximum number of bytes of an HTTP error response body to keep in the
/// surfaced error. Keeps log lines readable without dropping the useful prefix
/// of beacon-node validation messages (typically a few hundred bytes).
const ERROR_BODY_TRUNCATE: usize = 1024;

async fn submit_attestations(
    eth2_cl: &EthBeaconNodeApiClient,
    atts: &[VersionedAttestationJson],
) -> Result<()> {
    const ENDPOINT: &str = "/eth/v2/beacon/pool/attestations";
    submit_json(eth2_cl, ENDPOINT, atts).await
}

async fn submit_aggregate_attestations(
    eth2_cl: &EthBeaconNodeApiClient,
    aggs: &[VersionedSignedAggregateAndProofJson],
) -> Result<()> {
    const ENDPOINT: &str = "/eth/v2/validator/aggregate_and_proofs";
    let body = SubmitAggregateAttestationsOptsJson {
        common: CommonOpts::default(),
        signed_aggregate_and_proofs: aggs,
    };
    submit_json(eth2_cl, ENDPOINT, &body).await
}

async fn submit_json<T: Serialize + ?Sized>(
    eth2_cl: &EthBeaconNodeApiClient,
    endpoint: &'static str,
    body: &T,
) -> Result<()> {
    let mut url = eth2_cl.base_url.clone();
    {
        let mut segments = url.path_segments_mut().map_err(|()| {
            Error::Malformed(format!("base url has no path segments for {endpoint}"))
        })?;
        // `endpoint` always starts with '/'; skip the empty leading element.
        for segment in endpoint.split('/').filter(|s| !s.is_empty()) {
            segments.push(segment);
        }
    }

    let response = eth2_cl
        .client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|source| Error::Submit { endpoint, source })?;

    let status = response.status();
    if status.is_success() {
        return Ok(());
    }

    // Read the body before discarding the response so the beacon-node's error
    // payload (typically `{"code":400,"message":"..."}`) reaches the caller.
    let body = response.text().await.unwrap_or_default();
    let truncated = if body.len() > ERROR_BODY_TRUNCATE {
        // `floor_char_boundary` is unstable; walk back to a UTF-8 boundary
        // manually so non-ASCII payloads don't panic the slice.
        let mut cut = ERROR_BODY_TRUNCATE;
        while cut > 0 && !body.is_char_boundary(cut) {
            cut = cut.saturating_sub(1);
        }
        format!("{}…", &body[..cut])
    } else {
        body
    };
    Err(Error::SubmitStatus {
        endpoint,
        status,
        body: truncated,
    })
}

// ---------------------------------------------------------------------------
// Go-shaped JSON payloads
// ---------------------------------------------------------------------------

/// JSON shape matching Go's `*eth2spec.VersionedAttestation`.
///
/// Field names use Go's `PascalCase` for the version envelope, with
/// per-fork inner payloads keyed by the fork name. The inner
/// `electra::Attestation` serializes with snake_case fields
/// (`aggregation_bits`, `committee_bits`, `data`, `signature`) which matches
/// the Go output.
#[serde_as]
#[derive(Debug, Serialize)]
struct VersionedAttestationJson {
    #[serde(rename = "Version")]
    version: &'static str,
    #[serde(rename = "ValidatorIndex")]
    #[serde_as(as = "serde_with::DisplayFromStr")]
    validator_index: ValidatorIndex,
    #[serde(rename = "Phase0")]
    phase0: Option<()>,
    #[serde(rename = "Altair")]
    altair: Option<()>,
    #[serde(rename = "Bellatrix")]
    bellatrix: Option<()>,
    #[serde(rename = "Capella")]
    capella: Option<()>,
    #[serde(rename = "Deneb")]
    deneb: Option<()>,
    #[serde(rename = "Electra")]
    electra: Option<electra::Attestation>,
    #[serde(rename = "Fulu")]
    fulu: Option<electra::Attestation>,
}

/// JSON shape matching Go's `*eth2spec.VersionedSignedAggregateAndProof`.
#[derive(Debug, Serialize)]
struct VersionedSignedAggregateAndProofJson {
    #[serde(rename = "Version")]
    version: &'static str,
    #[serde(rename = "Phase0")]
    phase0: Option<()>,
    #[serde(rename = "Altair")]
    altair: Option<()>,
    #[serde(rename = "Bellatrix")]
    bellatrix: Option<()>,
    #[serde(rename = "Capella")]
    capella: Option<()>,
    #[serde(rename = "Deneb")]
    deneb: Option<()>,
    #[serde(rename = "Electra")]
    electra: Option<electra::SignedAggregateAndProof>,
    #[serde(rename = "Fulu")]
    fulu: Option<electra::SignedAggregateAndProof>,
}

/// JSON shape matching Go's `*eth2api.SubmitAggregateAttestationsOpts`.
#[derive(Debug, Serialize)]
struct SubmitAggregateAttestationsOptsJson<'a> {
    #[serde(rename = "Common")]
    common: CommonOpts,
    #[serde(rename = "SignedAggregateAndProofs")]
    signed_aggregate_and_proofs: &'a [VersionedSignedAggregateAndProofJson],
}

/// JSON shape matching Go's `eth2api.CommonOpts` (timeout in nanoseconds).
#[derive(Debug, Serialize, Default)]
struct CommonOpts {
    #[serde(rename = "Timeout")]
    timeout: u64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_pubkey(s: &str) -> Result<BLSPubKey> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|e| malformed(e.to_string()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| malformed(format!("pubkey length {} != 48", bytes.len())))
}

fn parse_signature(s: &str) -> Result<BLSSignature> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|e| malformed(e.to_string()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| malformed(format!("signature length {} != 96", bytes.len())))
}

fn parse_u64(s: &str) -> Option<u64> {
    s.parse::<u64>().ok()
}

fn usize_from_u64(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| malformed(format!("usize from u64 overflow: {value}")))
}

fn malformed(s: impl Into<String>) -> Error {
    Error::Malformed(s.into())
}

// ---------------------------------------------------------------------------
// Tests — mirror Go's TestAttest for DutyFactor 0 and 1.
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
        // the beaconmock only serves GET by default, so mount a POST passthrough
        // that returns the same payload as the GET handler.
        mount_post_state_validators(mock.server(), &valset).await;

        // `BeaconCommitteeSelections` is a DV-only endpoint not mounted by the
        // default beaconmock — Go's `beaconmock.New` runs the validator mock
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

        // The SUT issues exactly one POST to each endpoint. The body for
        // attestations is a JSON array of `VersionedAttestation`s; the body for
        // aggregate_and_proofs is a single `SubmitAggregateAttestationsOpts`
        // object whose `SignedAggregateAndProofs` array holds the
        // `VersionedSignedAggregateAndProof`s.
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
        let mut aggs_body = aggs_bodies[0].clone();
        let aggs_array = aggs_body
            .get_mut("SignedAggregateAndProofs")
            .and_then(Value::as_array_mut)
            .expect("SignedAggregateAndProofs must be an array");

        assert_eq!(atts_array.len(), expect_attestations);
        assert_eq!(aggs_array.len(), expect_aggregations);

        // Match Go's TestAttest deterministic ordering: sort by data.index
        // (ascending, numeric).
        atts_array.sort_by_key(index_of_attestation);
        aggs_array.sort_by_key(index_of_aggregate);

        let atts_value = Value::Array(atts_array);
        let golden_atts: Value = serde_json::from_str(golden(duty_factor, "attestations"))
            .expect("parse attestations golden");
        assert_json_eq!(atts_value, golden_atts);

        let golden_aggs: Value = serde_json::from_str(golden(duty_factor, "aggregations"))
            .expect("parse aggregations golden");
        assert_json_eq!(aggs_body, golden_aggs);
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
        value
            .get("Fulu")
            .and_then(|f| f.get("data"))
            .and_then(|d| d.get("index"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok())
            .unwrap_or(u64::MAX)
    }

    fn index_of_aggregate(value: &Value) -> u64 {
        value
            .get("Fulu")
            .and_then(|f| f.get("message"))
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

        let data: Vec<Value> = valset
            .validators()
            .into_iter()
            .map(|v| {
                serde_json::json!({
                    "index": v.index.to_string(),
                    "balance": v.balance.to_string(),
                    "status": v.status,
                    "validator": v.validator,
                })
            })
            .collect();
        let body = serde_json::json!({
            "data": data,
            "execution_optimistic": false,
            "finalized": false,
        });

        // Priority 2 — above defaults (255) but below capture (1).
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
