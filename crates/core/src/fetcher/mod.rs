//! Fetcher — fetches unsigned duty data from the beacon node.
//!
//! Ported from `charon/core/fetcher/fetcher.go`.

mod graffiti;

use graffiti::GraffitiBuilder;

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use pluto_eth2api::{
    EthBeaconNodeApiClient, EthBeaconNodeApiClientError, GetAggregatedAttestationV2Request,
    GetAggregatedAttestationV2Response, GetAggregatedAttestationV2ResponseResponseData,
    ProduceAttestationDataRequest, ProduceAttestationDataResponse, ProduceBlockV3Request,
    ProduceBlockV3Response, ProduceSyncCommitteeContributionRequest,
    ProduceSyncCommitteeContributionResponse,
    spec::{ConversionError, altair, bellatrix::ExecutionAddress, phase0},
    versioned,
};
use pluto_eth2util::eth2exp::{self, Eth2ExpError};
use tree_hash::TreeHash;

use crate::{
    signeddata::{
        AttestationData, BeaconCommitteeSelection, ProposalBlock, SignedDataError,
        SignedSyncMessage, SyncCommitteeSelection, SyncContribution,
        VersionedAggregatedAttestation, VersionedProposal,
    },
    types::{Duty, DutyDefinition, DutyDefinitionSet, DutyType, PubKey, SignedData},
    unsigneddata::{UnsignedDataSet, UnsignedDutyData},
};

/// Boxed error returned by injected callbacks (subscribers, AggSigDB, DutyDB).
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Future returned by an injected callback.
type CallbackFuture<T> = Pin<Box<dyn Future<Output = std::result::Result<T, BoxError>> + Send>>;

/// Subscriber callback invoked for each fetched duty data set.
pub type Subscriber = Arc<dyn Fn(Duty, UnsignedDataSet) -> CallbackFuture<()> + Send + Sync>;

/// AggSigDB callback: resolves aggregated signed data for a duty/pubkey.
pub type AggSigDbFunc =
    Arc<dyn Fn(Duty, PubKey) -> CallbackFuture<Box<dyn SignedData>> + Send + Sync>;

/// DutyDB callback: resolves attestation data for a `(slot, committee index)`.
pub type AwaitAttDataFunc =
    Arc<dyn Fn(u64, u64) -> CallbackFuture<phase0::AttestationData> + Send + Sync>;

/// Fee recipient resolver: returns the configured fee recipient for a pubkey.
pub type FeeRecipientFunc = Arc<dyn Fn(&PubKey) -> ExecutionAddress + Send + Sync>;

/// Errors returned while fetching duty data.
#[derive(Debug, thiserror::Error)]
pub enum FetcherError {
    /// Wraps an inner error with the duty-type context, matching Go's
    /// `errors.Wrap(err, "fetch <type> data")`.
    #[error("{context}: {source}")]
    Fetch {
        /// Context prefix (e.g. `fetch attester data`).
        context: &'static str,
        /// Wrapped inner error.
        source: Box<FetcherError>,
    },

    /// `DutyBuilderProposer` is deprecated and no longer supported.
    #[error("DutyBuilderProposer is deprecated and no longer supported")]
    DeprecatedDutyBuilderProposer,

    /// The duty type is not supported by the fetcher.
    #[error("unsupported duty type: {0}")]
    UnsupportedDutyType(String),

    /// A duty definition was not an attester definition.
    #[error("invalid attester definition")]
    InvalidAttesterDefinition,

    /// AggSigDB returned a value that was not a beacon committee selection.
    #[error("invalid beacon committee selection")]
    InvalidBeaconCommitteeSelection,

    /// AggSigDB returned a value that was not a sync committee selection.
    #[error("invalid sync committee selection")]
    InvalidSyncCommitteeSelection,

    /// AggSigDB returned a value that was not a sync committee message.
    #[error("invalid sync committee message")]
    InvalidSyncCommitteeMessage,

    /// The beacon node returned a nil attestation data response.
    #[error("attestation data cannot be nil")]
    NilAttestationData,

    /// The beacon node could not find an aggregate attestation for the root.
    #[error("aggregate attestation not found by root (retryable)")]
    AggregateAttestationNotFound,

    /// The beacon node could not find a sync committee contribution.
    #[error("sync committee contribution not found by root (retryable)")]
    SyncContributionNotFound,

    /// The beacon node returned an unexpected (non-success) response.
    #[error("unexpected beacon node response")]
    UnexpectedResponse,

    /// AggSigDB / DutyDB callback (or a subscriber) returned an error.
    #[error("{0}")]
    Callback(BoxError),

    /// Error from the beacon node API client.
    #[error(transparent)]
    BeaconNode(#[from] EthBeaconNodeApiClientError),

    /// Error from aggregator selection.
    #[error(transparent)]
    Eth2Exp(#[from] Eth2ExpError),

    /// JSON (de)serialization error while decoding a beacon node response.
    #[error("decode beacon node response: {0}")]
    Json(#[from] serde_json::Error),

    /// Failed to convert a loosely-typed beacon node value into a spec type.
    #[error("convert beacon node response: {0}")]
    Conversion(#[from] ConversionError),

    /// Failed to decode a beacon node response into a signed-data type.
    #[error("decode proposal: {0}")]
    SignedData(#[from] SignedDataError),

    /// A signed data value could not produce a signature.
    #[error("signature: {0}")]
    Signature(#[source] SignedDataError),
}

/// Result alias for fetcher operations.
type Result<T> = std::result::Result<T, FetcherError>;

/// Fetches proposed duty data from the beacon node.
#[derive(bon::Builder)]
pub struct Fetcher {
    /// Subscribers invoked for each fetched duty data set. Appended via the
    /// builder's `subscribe` method (zero or more times).
    #[builder(field)]
    subs: Vec<Subscriber>,
    eth2_cl: EthBeaconNodeApiClient,
    fee_recipient: FeeRecipientFunc,
    agg_sig_db: AggSigDbFunc,
    await_att_data: AwaitAttDataFunc,
    builder_enabled: bool,
    graffiti_builder: GraffitiBuilder,
    electra_slot: phase0::Slot,
    fetch_only_comm_idx0: bool,
}

impl<S: fetcher_builder::State> FetcherBuilder<S> {
    /// Registers a callback for fetched duties. May be called multiple times to
    /// register several subscribers.
    pub fn subscribe(mut self, sub: Subscriber) -> Self {
        self.subs.push(sub);
        self
    }
}

impl Fetcher {
    /// Triggers fetching of a proposed duty data set.
    pub async fn fetch(&self, duty: Duty, def_set: DutyDefinitionSet) -> Result<()> {
        let slot = duty.slot.inner();

        let unsigned_set = match duty.duty_type {
            DutyType::Proposer => self
                .fetch_proposer_data(slot, &def_set)
                .await
                .map_err(wrap("fetch proposer data"))?,
            DutyType::Attester => self
                .fetch_attester_data(slot, &def_set)
                .await
                .map_err(wrap("fetch attester data"))?,
            DutyType::BuilderProposer => return Err(FetcherError::DeprecatedDutyBuilderProposer),
            DutyType::Aggregator => {
                let set = self
                    .fetch_aggregator_data(slot, &def_set)
                    .await
                    .map_err(wrap("fetch aggregator data"))?;
                if set.is_empty() {
                    // No aggregators found in this slot.
                    return Ok(());
                }
                set
            }
            DutyType::SyncContribution => {
                let set = self
                    .fetch_contribution_data(slot, &def_set)
                    .await
                    .map_err(wrap("fetch contribution data"))?;
                if set.is_empty() {
                    // No sync committee contributors found in this slot.
                    return Ok(());
                }
                set
            }
            other => return Err(FetcherError::UnsupportedDutyType(other.to_string())),
        };

        for sub in &self.subs {
            // Clone before calling each subscriber.
            let clone = unsigned_set.clone();
            sub(duty.clone(), clone)
                .await
                .map_err(FetcherError::Callback)?;
        }

        Ok(())
    }

    /// Returns the fetched attestation data set for committees and validators
    /// in the arg set.
    async fn fetch_attester_data(
        &self,
        slot: u64,
        def_set: &DutyDefinitionSet,
    ) -> Result<UnsignedDataSet> {
        // We may have multiple validators in the same committee, use the same
        // attestation data in that case.
        let mut data_by_comm_idx: HashMap<u64, phase0::AttestationData> = HashMap::new();

        let mut resp = UnsignedDataSet::new();
        for (pubkey, def) in def_set {
            let DutyDefinition::Attester(att_def) = def else {
                return Err(FetcherError::InvalidAttesterDefinition);
            };

            let mut comm_idx = att_def.duty.committee_index;

            // Attestation data for Electra is not bound by committee index;
            // committee index is still persisted in the request but should be
            // set to 0 once all VCs request committee index 0.
            if slot >= self.electra_slot && self.fetch_only_comm_idx0 {
                comm_idx = 0;
            }

            let eth2_att_data = match data_by_comm_idx.get(&comm_idx) {
                Some(data) => data.clone(),
                None => {
                    let data = self.attestation_data(slot, comm_idx).await?;
                    data_by_comm_idx.insert(comm_idx, data.clone());
                    data
                }
            };

            resp.insert(
                *pubkey,
                UnsignedDutyData::Attestation(AttestationData {
                    data: eth2_att_data,
                    duty: att_def.duty.clone(),
                }),
            );
        }

        Ok(resp)
    }

    /// Fetches the attestation aggregation data.
    async fn fetch_aggregator_data(
        &self,
        slot: u64,
        def_set: &DutyDefinitionSet,
    ) -> Result<UnsignedDataSet> {
        let mut tracker = PubkeysTracker::new("attester aggregation");

        // We may have multiple aggregators in the same committee, use the same
        // aggregated attestation in that case.
        let mut agg_att_by_comm_idx: HashMap<u64, versioned::VersionedAttestation> = HashMap::new();

        let mut resp = UnsignedDataSet::new();
        for (pubkey, def) in def_set {
            let DutyDefinition::Attester(att_def) = def else {
                return Err(FetcherError::InvalidAttesterDefinition);
            };

            // Query AggSigDB for DutyPrepareAggregator to get beacon committee
            // selections.
            let prep_agg_data = self
                .query_agg_sig_db(Duty::new_prepare_aggregator_duty(slot.into()), *pubkey)
                .await?;
            let selection = downcast::<BeaconCommitteeSelection>(prep_agg_data.as_ref())
                .ok_or(FetcherError::InvalidBeaconCommitteeSelection)?;

            let is_aggregator = eth2exp::is_att_aggregator(
                &self.eth2_cl,
                att_def.duty.committee_length,
                selection.0.selection_proof,
            )
            .await?;
            if !is_aggregator {
                tracker.add_not_selected(pubkey.to_string());
                continue;
            }

            tracker.add_resolved(pubkey.to_string());

            let comm_idx = att_def.duty.committee_index;

            if let Some(agg_att) = agg_att_by_comm_idx.get(&comm_idx) {
                resp.insert(
                    *pubkey,
                    UnsignedDutyData::AggAttestation(VersionedAggregatedAttestation(
                        agg_att.clone(),
                    )),
                );
                // Skip querying aggregate attestation for aggregators of the
                // same committee.
                continue;
            }

            // Query DutyDB for attestation data to get the attestation data root.
            let att_data = self.query_att_data(slot, comm_idx).await?;
            let data_root = att_data.tree_hash_root().0;

            // Query BN for aggregate attestation.
            let agg_att = self
                .aggregate_attestation(slot, comm_idx, data_root)
                .await?;

            agg_att_by_comm_idx.insert(comm_idx, agg_att.clone());
            resp.insert(
                *pubkey,
                UnsignedDutyData::AggAttestation(VersionedAggregatedAttestation(agg_att)),
            );
        }

        Ok(resp)
    }

    /// Fetches the block proposal data set.
    async fn fetch_proposer_data(
        &self,
        slot: u64,
        def_set: &DutyDefinitionSet,
    ) -> Result<UnsignedDataSet> {
        let mut resp = UnsignedDataSet::new();
        for pubkey in def_set.keys() {
            // Fetch previously aggregated randao reveal from AggSigDB.
            let randao_data = self
                .query_agg_sig_db(Duty::new_randao_duty(slot.into()), *pubkey)
                .await?;
            let randao = randao_data.signature().map_err(FetcherError::Signature)?;

            // Maximum priority to builder blocks when the builder is enabled.
            let builder_boost_factor: u64 = if self.builder_enabled { u64::MAX } else { 0 };

            let graffiti = self.graffiti_builder.get_graffiti(pubkey);

            let request = ProduceBlockV3Request::builder()
                .slot(slot.to_string())
                .randao_reveal(format!("0x{}", hex::encode(randao)))
                .graffiti(format!("0x{}", hex::encode(graffiti)))
                .builder_boost_factor(builder_boost_factor.to_string())
                .build()
                .map_err(EthBeaconNodeApiClientError::RequestError)?;

            let response = match self
                .eth2_cl
                .produce_block_v3(request)
                .await
                .map_err(EthBeaconNodeApiClientError::RequestError)?
            {
                ProduceBlockV3Response::Ok(resp) => resp,
                _ => return Err(FetcherError::UnexpectedResponse),
            };

            let proposal = VersionedProposal::try_from(&response)?;

            // Builders set the fee recipient to themselves, so it always differs
            // from the validator's; only verify when the builder is disabled.
            if !self.builder_enabled {
                let fee_recipient = (self.fee_recipient)(pubkey);
                verify_fee_recipient(&proposal, &fee_recipient);
            }

            resp.insert(*pubkey, UnsignedDutyData::Proposal(Box::new(proposal)));
        }

        Ok(resp)
    }

    /// Fetches the sync committee contribution data.
    async fn fetch_contribution_data(
        &self,
        slot: u64,
        def_set: &DutyDefinitionSet,
    ) -> Result<UnsignedDataSet> {
        let mut tracker = PubkeysTracker::new("sync committee contribution");

        let mut resp = UnsignedDataSet::new();
        for pubkey in def_set.keys() {
            // Query AggSigDB for DutyPrepareSyncContribution to get the sync
            // committee selection.
            let selection_data = self
                .query_agg_sig_db(
                    Duty::new_prepare_sync_contribution_duty(slot.into()),
                    *pubkey,
                )
                .await?;
            let selection = downcast::<SyncCommitteeSelection>(selection_data.as_ref())
                .ok_or(FetcherError::InvalidSyncCommitteeSelection)?;

            let subcomm_idx = selection.0.subcommittee_index;

            // Check if the validator is an aggregator for the sync committee.
            let is_aggregator =
                eth2exp::is_sync_comm_aggregator(&self.eth2_cl, selection.0.selection_proof)
                    .await?;
            if !is_aggregator {
                tracker.add_not_selected(pubkey.to_string());
                continue;
            }

            // Query AggSigDB for DutySyncMessage to get the beacon block root.
            let sync_msg_data = self
                .query_agg_sig_db(Duty::new_sync_message_duty(slot.into()), *pubkey)
                .await?;
            let msg = downcast::<SignedSyncMessage>(sync_msg_data.as_ref())
                .ok_or(FetcherError::InvalidSyncCommitteeMessage)?;

            let block_root = msg.0.beacon_block_root;

            // Query BN for sync committee contribution.
            let contribution = self
                .sync_committee_contribution(slot, subcomm_idx, block_root)
                .await?;

            tracker.add_resolved(pubkey.to_string());

            resp.insert(
                *pubkey,
                UnsignedDutyData::SyncContribution(SyncContribution(contribution)),
            );
        }

        Ok(resp)
    }

    // Beacon node helpers

    /// Queries the beacon node for attestation data.
    async fn attestation_data(&self, slot: u64, comm_idx: u64) -> Result<phase0::AttestationData> {
        let request = ProduceAttestationDataRequest::builder()
            .slot(slot.to_string())
            .committee_index(comm_idx.to_string())
            .build()
            .map_err(EthBeaconNodeApiClientError::RequestError)?;

        match self
            .eth2_cl
            .produce_attestation_data(request)
            .await
            .map_err(EthBeaconNodeApiClientError::RequestError)?
        {
            ProduceAttestationDataResponse::Ok(ok) => {
                Ok(phase0::AttestationData::try_from(&ok.data)?)
            }
            _ => Err(FetcherError::NilAttestationData),
        }
    }

    /// Queries the beacon node for an aggregate attestation by data root.
    async fn aggregate_attestation(
        &self,
        slot: u64,
        comm_idx: u64,
        data_root: phase0::Root,
    ) -> Result<versioned::VersionedAttestation> {
        let request = GetAggregatedAttestationV2Request::builder()
            .attestation_data_root(format!("0x{}", hex::encode(data_root)))
            .slot(slot.to_string())
            .committee_index(comm_idx.to_string())
            .build()
            .map_err(EthBeaconNodeApiClientError::RequestError)?;

        let ok = match self
            .eth2_cl
            .get_aggregated_attestation_v2(request)
            .await
            .map_err(EthBeaconNodeApiClientError::RequestError)?
        {
            GetAggregatedAttestationV2Response::Ok(ok) => ok,
            // Some beacon nodes return nil if the root is not found; surface a
            // retryable error.
            _ => return Err(FetcherError::AggregateAttestationNotFound),
        };

        let version = versioned::DataVersion::from(&ok.version);
        Ok(versioned::VersionedAttestation {
            version,
            validator_index: None,
            attestation: Some(attestation_payload(version, &ok.data)?),
        })
    }

    /// Queries the beacon node for a sync committee contribution.
    async fn sync_committee_contribution(
        &self,
        slot: u64,
        subcomm_idx: u64,
        block_root: phase0::Root,
    ) -> Result<altair::SyncCommitteeContribution> {
        let request = ProduceSyncCommitteeContributionRequest::builder()
            .slot(slot.to_string())
            .subcommittee_index(subcomm_idx.to_string())
            .beacon_block_root(format!("0x{}", hex::encode(block_root)))
            .build()
            .map_err(EthBeaconNodeApiClientError::RequestError)?;

        match self
            .eth2_cl
            .produce_sync_committee_contribution(request)
            .await
            .map_err(EthBeaconNodeApiClientError::RequestError)?
        {
            ProduceSyncCommitteeContributionResponse::Ok(payload) => {
                Ok(altair::SyncCommitteeContribution::try_from(&payload.data)?)
            }
            _ => Err(FetcherError::SyncContributionNotFound),
        }
    }

    /// Invokes the AggSigDB resolver.
    async fn query_agg_sig_db(&self, duty: Duty, pubkey: PubKey) -> Result<Box<dyn SignedData>> {
        (self.agg_sig_db)(duty, pubkey)
            .await
            .map_err(FetcherError::Callback)
    }

    /// Invokes the DutyDB attestation-data resolver.
    async fn query_att_data(&self, slot: u64, comm_idx: u64) -> Result<phase0::AttestationData> {
        (self.await_att_data)(slot, comm_idx)
            .await
            .map_err(FetcherError::Callback)
    }
}

/// Builds a closure that wraps a [`FetcherError`] with the duty-type context,
/// matching Go's `errors.Wrap(err, context)`.
fn wrap(context: &'static str) -> impl Fn(FetcherError) -> FetcherError {
    move |source| FetcherError::Fetch {
        context,
        source: Box::new(source),
    }
}

/// Downcasts a `&dyn SignedData` to a concrete signed-data type.
fn downcast<T: 'static>(data: &dyn SignedData) -> Option<&T> {
    (data as &dyn std::any::Any).downcast_ref::<T>()
}

/// Builds a versioned attestation payload from the beacon node's aggregate
/// attestation response.
///
/// The response carries the attestation as an untagged union: `Object2` is the
/// phase0-style attestation returned up to Deneb, `Object` is the
/// committee-aware Electra shape returned from Electra onwards.
fn attestation_payload(
    version: versioned::DataVersion,
    data: &GetAggregatedAttestationV2ResponseResponseData,
) -> Result<versioned::AttestationPayload> {
    use GetAggregatedAttestationV2ResponseResponseData as GenData;
    use versioned::{AttestationPayload as AP, DataVersion as DV};

    Ok(match (version, data) {
        (DV::Phase0, GenData::Object2(att)) => AP::Phase0(att.try_into()?),
        (DV::Altair, GenData::Object2(att)) => AP::Altair(att.try_into()?),
        (DV::Bellatrix, GenData::Object2(att)) => AP::Bellatrix(att.try_into()?),
        (DV::Capella, GenData::Object2(att)) => AP::Capella(att.try_into()?),
        (DV::Deneb, GenData::Object2(att)) => AP::Deneb(att.try_into()?),
        (DV::Electra, GenData::Object(att)) => AP::Electra(att.try_into()?),
        (DV::Fulu, GenData::Object(att)) => AP::Fulu(att.try_into()?),
        // A spec-compliant beacon node never pairs a fork version with the
        // other fork's attestation shape (e.g. an Electra version reporting a
        // phase0-style body), and `version` is derived from a
        // `ConsensusVersion`, so it is never `Unknown`.
        _ => return Err(FetcherError::UnexpectedResponse),
    })
}

/// Logs a warning when the fee recipient is not correctly populated in the
/// proposal. Fee recipient is unavailable in forks earlier than Bellatrix.
fn verify_fee_recipient(proposal: &VersionedProposal, fee_recipient_address: &ExecutionAddress) {
    if let Some((expected, actual)) = fee_recipient_mismatch(proposal, fee_recipient_address) {
        tracing::warn!(
            expected = format!("0x{}", hex::encode(expected)),
            actual = format!("0x{}", hex::encode(actual)),
            "Proposal with unexpected fee recipient address"
        );
    }
}

/// Returns `Some((expected, actual))` when the proposal's fee recipient differs
/// from `fee_recipient_address`. Returns `None` for forks
/// without a fee recipient (pre-Bellatrix) or when the addresses match.
fn fee_recipient_mismatch(
    proposal: &VersionedProposal,
    fee_recipient_address: &ExecutionAddress,
) -> Option<(ExecutionAddress, ExecutionAddress)> {
    let actual_addr = proposal_block_fee_recipient(&proposal.block)?;

    if actual_addr == *fee_recipient_address {
        None
    } else {
        Some((*fee_recipient_address, actual_addr))
    }
}

/// Extracts the fee recipient from a proposal block, if available. Returns
/// `None` for pre-Bellatrix blocks or if the fee recipient cannot be extracted.
fn proposal_block_fee_recipient(block: &ProposalBlock) -> Option<[u8; 20]> {
    match block {
        ProposalBlock::Bellatrix(b) => Some(b.body.execution_payload.fee_recipient),
        ProposalBlock::BellatrixBlinded(b) => Some(b.body.execution_payload_header.fee_recipient),
        ProposalBlock::Capella(b) => Some(b.body.execution_payload.fee_recipient),
        ProposalBlock::CapellaBlinded(b) => Some(b.body.execution_payload_header.fee_recipient),
        ProposalBlock::Deneb { block, .. } => Some(block.body.execution_payload.fee_recipient),
        ProposalBlock::DenebBlinded(b) => Some(b.body.execution_payload_header.fee_recipient),
        ProposalBlock::Electra { block, .. } => Some(block.body.execution_payload.fee_recipient),
        ProposalBlock::ElectraBlinded(b) => Some(b.body.execution_payload_header.fee_recipient),
        ProposalBlock::Fulu { block, .. } => Some(block.body.execution_payload.fee_recipient),
        ProposalBlock::FuluBlinded(b) => Some(b.body.execution_payload_header.fee_recipient),
        _ => None,
    }
}

/// Tracks which pubkeys were selected/resolved for aggregation duties so the
/// outcome can be logged once per fetch.
struct PubkeysTracker {
    title: &'static str,
    not_selected_pubkeys: Vec<String>,
    resolved_pubkeys: Vec<String>,
}

impl PubkeysTracker {
    fn new(title: &'static str) -> Self {
        Self {
            title,
            not_selected_pubkeys: Vec::new(),
            resolved_pubkeys: Vec::new(),
        }
    }

    fn add_not_selected(&mut self, pubkey: String) {
        self.not_selected_pubkeys.push(pubkey);
    }

    fn add_resolved(&mut self, pubkey: String) {
        self.resolved_pubkeys.push(pubkey);
    }

    fn log(&self) {
        if !self.not_selected_pubkeys.is_empty() {
            tracing::debug!(
                title = self.title,
                pubkeys = self.not_selected_pubkeys.join(","),
                "not selected pubkeys"
            );
        }

        if !self.resolved_pubkeys.is_empty() {
            tracing::info!(
                title = self.title,
                pubkeys = self.resolved_pubkeys.join(","),
                "resolved pubkeys"
            );
        }
    }
}

impl Drop for PubkeysTracker {
    fn drop(&mut self) {
        // Log at the end of scope
        self.log();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use pluto_testutil::BeaconMock;

    use super::*;
    use crate::{
        signeddata::AttesterDuty,
        types::{
            AttesterDutyDefinition, ProposerDutyDefinition, SlotNumber, SyncCommitteeDutyDefinition,
        },
    };

    /// 48-byte BLS public key length used to build distinct test pubkeys.
    const PK_LEN: usize = 48;

    /// Captures the `(duty, set)` passed to the last subscriber invocation.
    type Captured = Arc<Mutex<Option<(Duty, UnsignedDataSet)>>>;

    /// Builds a subscriber that records its argument into `captured`.
    fn capturing_subscriber(captured: Captured) -> Subscriber {
        Arc::new(move |duty, set| {
            let captured = captured.clone();
            Box::pin(async move {
                *captured.lock().unwrap() = Some((duty, set));
                Ok(())
            })
        })
    }

    /// Fee-recipient stub for tests that don't exercise fee-recipient
    /// verification.
    fn stub_fee_recipient() -> FeeRecipientFunc {
        Arc::new(|_| ExecutionAddress::default())
    }

    /// AggSigDB stub for tests whose duty path never queries it.
    fn stub_agg_sig_db() -> AggSigDbFunc {
        Arc::new(|_, _| Box::pin(async { unreachable!("AggSigDB not expected in this test") }))
    }

    /// DutyDB attestation-data stub for tests whose duty path never queries it;
    fn stub_await_att_data() -> AwaitAttDataFunc {
        Arc::new(|_, _| Box::pin(async { unreachable!("AwaitAttData not expected in this test") }))
    }

    /// Spec fields required by `is_sync_comm_aggregator` /
    /// `is_att_aggregator`, matching the values the prysm selection-proof test
    /// vectors were generated against.
    fn aggregator_spec() -> serde_json::Value {
        serde_json::json!({
            "TARGET_AGGREGATORS_PER_COMMITTEE": "16",
            "SYNC_COMMITTEE_SIZE": "512",
            "SYNC_COMMITTEE_SUBNET_COUNT": "4",
            "TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE": "16",
        })
    }

    /// Decodes a 96-byte BLS signature from hex.
    fn bls_sig(hex_str: &str) -> phase0::BLSSignature {
        hex::decode(hex_str)
            .expect("valid hex")
            .try_into()
            .expect("96-byte signature")
    }

    /// Electra block contents (`{block, kzg_proofs, blobs}`) reused as the
    /// `produce_block_v3` response payload.
    const BLOCK_CONTENTS_GOLDEN: &str = include_str!(
        "../../testdata/signeddata/TestJSONSerialisation_VersionedProposal.json.golden"
    );

    /// Blinded proposal (`{slot, .., body}`) whose body carries an
    /// `execution_payload_header` with the Deneb-era blob fields. Reused to
    /// build blinded proposals across forks in [`verify_fee_recipient`].
    const BLINDED_BLOCK_GOLDEN: &str = include_str!(
        "../../testdata/signeddata/TestJSONSerialisation_VersionedBlindedProposal.json.golden"
    );

    /// Mounts a `produce_block_v3` responder that returns the golden Electra
    /// block contents with the request's slot, randao reveal and graffiti
    /// echoed back and a zero fee recipient.
    async fn mount_produce_block(server: &wiremock::MockServer) {
        let golden: serde_json::Value =
            serde_json::from_str(BLOCK_CONTENTS_GOLDEN).expect("parse golden");
        let base = golden["block"].clone();

        struct Responder {
            base: serde_json::Value,
        }
        impl wiremock::Respond for Responder {
            fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
                let query: HashMap<String, String> = req.url.query_pairs().into_owned().collect();
                let randao = query.get("randao_reveal").cloned().unwrap_or_default();
                let graffiti = query.get("graffiti").cloned().unwrap_or_default();
                // Slot is the final path segment.
                let slot = req
                    .url
                    .path_segments()
                    .and_then(|mut s| s.next_back())
                    .unwrap_or("0")
                    .to_string();

                let mut data = self.base.clone();
                data["block"]["slot"] = serde_json::json!(slot);
                data["block"]["body"]["randao_reveal"] = serde_json::json!(randao);
                data["block"]["body"]["graffiti"] = serde_json::json!(graffiti);
                data["block"]["body"]["execution_payload"]["fee_recipient"] =
                    serde_json::json!(format!("0x{}", "00".repeat(20)));

                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "version": "electra",
                    "execution_payload_blinded": false,
                    "execution_payload_value": "0",
                    "consensus_block_value": "0",
                    "data": data,
                }))
            }
        }

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path_regex(
                r"^/eth/v3/validator/blocks/[0-9]+$",
            ))
            .respond_with(Responder { base })
            .mount(server)
            .await;
    }

    /// Empties the variable-shape list fields of a block body JSON so it
    /// deserializes into any fork's block type, regardless of per-fork element
    /// shapes (e.g. Electra's committee-aware attestations vs. phase0's).
    fn empty_block_body_lists(body: &mut serde_json::Value) {
        for field in [
            "proposer_slashings",
            "attester_slashings",
            "attestations",
            "deposits",
            "voluntary_exits",
        ] {
            body[field] = serde_json::json!([]);
        }
    }

    /// Mirrors Go's `TestVerifyFeeRecipient`: every fork/blinded combination
    /// from Bellatrix onwards must extract a fee recipient. A matching address
    /// (case-insensitively) yields no mismatch; a different one is flagged.
    #[test]
    fn verify_fee_recipient() {
        // The unblinded golden is the richest fork shape (Electra), whose body
        // is a field-superset of every earlier fork. Since the spec types
        // ignore unknown fields it deserializes into each fork's `BeaconBlock`.
        let unblinded_block = {
            let golden: serde_json::Value =
                serde_json::from_str(BLOCK_CONTENTS_GOLDEN).expect("parse unblinded golden");
            let mut block = golden["block"]["block"].clone();
            empty_block_body_lists(&mut block["body"]);
            block
        };

        // The blinded golden's `execution_payload_header` already carries the
        // Deneb-era blob fields, so it deserializes into Bellatrix..Deneb
        // blinded blocks directly.
        let blinded_block = {
            let golden: serde_json::Value =
                serde_json::from_str(BLINDED_BLOCK_GOLDEN).expect("parse blinded golden");
            let mut block = golden["block"].clone();
            empty_block_body_lists(&mut block["body"]);
            block
        };

        // Electra+ blinded blocks additionally require `execution_requests`.
        let blinded_block_electra = {
            let mut block = blinded_block.clone();
            block["body"]["execution_requests"] = serde_json::json!({
                "deposits": [],
                "withdrawals": [],
                "consolidations": [],
            });
            block
        };

        let kzg_proofs = Vec::new();
        let blobs = Vec::new();
        let cases: Vec<(&str, ProposalBlock)> = vec![
            (
                "bellatrix",
                ProposalBlock::Bellatrix(
                    serde_json::from_value(unblinded_block.clone()).expect("bellatrix"),
                ),
            ),
            (
                "bellatrix blinded",
                ProposalBlock::BellatrixBlinded(
                    serde_json::from_value(blinded_block.clone()).expect("bellatrix b"),
                ),
            ),
            (
                "capella",
                ProposalBlock::Capella(
                    serde_json::from_value(unblinded_block.clone()).expect("capella"),
                ),
            ),
            (
                "capella blinded",
                ProposalBlock::CapellaBlinded(
                    serde_json::from_value(blinded_block.clone()).expect("capella b"),
                ),
            ),
            (
                "deneb",
                ProposalBlock::Deneb {
                    block: Box::new(
                        serde_json::from_value(unblinded_block.clone()).expect("deneb"),
                    ),
                    kzg_proofs: kzg_proofs.clone(),
                    blobs: blobs.clone(),
                },
            ),
            (
                "deneb blinded",
                ProposalBlock::DenebBlinded(
                    serde_json::from_value(blinded_block.clone()).expect("deneb b"),
                ),
            ),
            (
                "electra",
                ProposalBlock::Electra {
                    block: Box::new(
                        serde_json::from_value(unblinded_block.clone()).expect("electra"),
                    ),
                    kzg_proofs: kzg_proofs.clone(),
                    blobs: blobs.clone(),
                },
            ),
            (
                "electra blinded",
                ProposalBlock::ElectraBlinded(
                    serde_json::from_value(blinded_block_electra.clone()).expect("electra b"),
                ),
            ),
            (
                "fulu",
                ProposalBlock::Fulu {
                    block: Box::new(serde_json::from_value(unblinded_block.clone()).expect("fulu")),
                    kzg_proofs: kzg_proofs.clone(),
                    blobs: blobs.clone(),
                },
            ),
            (
                "fulu blinded",
                ProposalBlock::FuluBlinded(
                    serde_json::from_value(blinded_block_electra.clone()).expect("fulu b"),
                ),
            ),
        ];

        for (name, block) in cases {
            let proposal = VersionedProposal {
                block,
                consensus_block_value: alloy::primitives::U256::ZERO,
                execution_payload_value: alloy::primitives::U256::ZERO,
            };

            // A different address is reported as a mismatch.
            // the proposal's own fee recipient matches itself.
            let some_fee_recipient = [0xFF; 20];
            let (_, actual) = fee_recipient_mismatch(&proposal, &some_fee_recipient)
                .unwrap_or_else(|| panic!("{name}: expected a mismatch"));
            assert!(
                fee_recipient_mismatch(&proposal, &actual).is_none(),
                "{name}: should match its own fee recipient",
            );
        }
    }

    #[tokio::test]
    async fn fetch_blocks() {
        const SLOT: u64 = 1;
        let pk_a = PubKey::new([2u8; PK_LEN]);
        let pk_b = PubKey::new([3u8; PK_LEN]);

        let randao_a: phase0::BLSSignature = [7u8; 96];
        let randao_b: phase0::BLSSignature = [8u8; 96];
        let randao_by_pubkey: HashMap<PubKey, phase0::BLSSignature> =
            HashMap::from([(pk_a, randao_a), (pk_b, randao_b)]);

        // disable_client_append = true, so graffiti is the raw string padded to
        // 32 bytes.
        let mut graffiti_a = [0u8; 32];
        graffiti_a[..5].copy_from_slice(b"testA");
        let mut graffiti_b = [0u8; 32];
        graffiti_b[..5].copy_from_slice(b"testB");

        let def_set = DutyDefinitionSet::from([
            (
                pk_a,
                DutyDefinition::Proposer(ProposerDutyDefinition {
                    pubkey: pk_a,
                    v_idx: 2,
                    slot: SlotNumber::new(SLOT),
                }),
            ),
            (
                pk_b,
                DutyDefinition::Proposer(ProposerDutyDefinition {
                    pubkey: pk_b,
                    v_idx: 3,
                    slot: SlotNumber::new(SLOT),
                }),
            ),
        ]);

        let mock = BeaconMock::builder().build().await.expect("build mock");
        mount_produce_block(mock.server()).await;

        let graffiti_builder = GraffitiBuilder::new(
            &[pk_a, pk_b],
            Some(&["testA".to_string(), "testB".to_string()]),
            true,
            mock.client(),
        )
        .await
        .expect("build graffiti");

        let randaos = randao_by_pubkey.clone();
        let agg_sig_db: AggSigDbFunc = Arc::new(move |_duty: Duty, pubkey: PubKey| {
            let sig = randaos[&pubkey];
            Box::pin(async move {
                let data: Box<dyn SignedData> = Box::new(sig);
                Ok(data)
            })
        });

        let captured: Captured = Arc::new(Mutex::new(None));
        let fetcher = Fetcher::builder()
            .eth2_cl(mock.client().clone())
            .fee_recipient(stub_fee_recipient())
            .agg_sig_db(agg_sig_db)
            .await_att_data(stub_await_att_data())
            .builder_enabled(true)
            .graffiti_builder(graffiti_builder)
            .electra_slot(5)
            .fetch_only_comm_idx0(false)
            .subscribe(capturing_subscriber(captured.clone()))
            .build();

        let duty = Duty::new_proposer_duty(SlotNumber::new(SLOT));
        fetcher.fetch(duty, def_set).await.expect("fetch");

        let (_, res_set) = captured.lock().unwrap().take().expect("subscriber called");
        assert_eq!(res_set.len(), 2);

        for (pubkey, expected_randao, expected_graffiti) in
            [(pk_a, randao_a, graffiti_a), (pk_b, randao_b, graffiti_b)]
        {
            let UnsignedDutyData::Proposal(proposal) = res_set.get(&pubkey).expect("entry") else {
                panic!("expected proposal");
            };
            assert_eq!(proposal.slot(), SLOT);

            let ProposalBlock::Electra { block, .. } = &proposal.block else {
                panic!("expected electra block");
            };
            assert_eq!(block.slot, SLOT);
            assert_eq!(block.body.randao_reveal, expected_randao);
            assert_eq!(block.body.graffiti, expected_graffiti);
            assert_eq!(block.body.execution_payload.fee_recipient, [0u8; 20]);
        }
    }

    #[tokio::test]
    async fn fetch_attester() {
        const SLOT: u64 = 1;
        const V_IDX_A: u64 = 2;
        const V_IDX_B: u64 = 3;
        const NOT_ZERO: u64 = 99; // Validation requires non-zero values.

        let pk_a = PubKey::new([2u8; PK_LEN]);
        let pk_b = PubKey::new([3u8; PK_LEN]);

        let duty_a = AttesterDuty {
            slot: SLOT,
            validator_index: V_IDX_A,
            committee_index: V_IDX_A,
            committee_length: NOT_ZERO,
            committees_at_slot: NOT_ZERO,
            validator_committee_index: 0,
        };
        let duty_b = AttesterDuty {
            slot: SLOT,
            validator_index: V_IDX_B,
            committee_index: V_IDX_B,
            committee_length: NOT_ZERO,
            committees_at_slot: NOT_ZERO,
            validator_committee_index: 0,
        };

        let def_set = DutyDefinitionSet::from([
            (
                pk_a,
                DutyDefinition::Attester(attester_duty_def(pk_a, &duty_a)),
            ),
            (
                pk_b,
                DutyDefinition::Attester(attester_duty_def(pk_b, &duty_b)),
            ),
        ]);

        let duty = Duty::new_attester_duty(SlotNumber::new(SLOT));
        let mock = BeaconMock::builder().build().await.expect("build mock");

        let captured: Captured = Arc::new(Mutex::new(None));
        let fetcher = Fetcher::builder()
            .eth2_cl(mock.client().clone())
            .fee_recipient(stub_fee_recipient())
            .agg_sig_db(stub_agg_sig_db())
            .await_att_data(stub_await_att_data())
            .builder_enabled(true)
            .graffiti_builder(GraffitiBuilder::default())
            .electra_slot(5)
            .fetch_only_comm_idx0(false)
            .subscribe(capturing_subscriber(captured.clone()))
            .build();

        fetcher.fetch(duty.clone(), def_set).await.expect("fetch");

        let (res_duty, res_set) = captured.lock().unwrap().take().expect("subscriber called");
        assert_eq!(res_duty, duty);
        assert_eq!(res_set.len(), 2);

        for (pubkey, expected_duty, v_idx) in [(pk_a, &duty_a, V_IDX_A), (pk_b, &duty_b, V_IDX_B)] {
            let UnsignedDutyData::Attestation(att) = res_set.get(&pubkey).expect("entry") else {
                panic!("expected attestation data");
            };
            assert_eq!(att.data.slot, SLOT);
            assert_eq!(att.data.index, v_idx);
            assert_eq!(&att.duty, expected_duty);
        }
    }

    // Aggregator selection proofs from prysm's
    // validate_sync_contribution_proof_test.go.
    const SYNC_AGG_SIG_A: &str = "a9dbd88a49a7269e91b8ef1296f1e07f87fed919d51a446b67122bfdfd61d23f3f929fc1cd5209bd6862fd60f739b27213fb0a8d339f7f081fc84281f554b190bb49cc97a6b3364e622af9e7ca96a97fe2b766f9e746dead0b33b58473d91562";
    const SYNC_AGG_SIG_B: &str = "99e60f20dde4d4872b048d703f1943071c20213d504012e7e520c229da87661803b9f139b9a0c5be31de3cef6821c080125aed38ebaf51ba9a2e9d21d7fbf2903577983109d097a8599610a92c0305408d97c1fd4b0b2d1743fb4eedf5443f99";
    const SYNC_NON_AGG_SIG: &str = "b9251a82040d4620b8c5665f328ee6c2eaa02d31d71d153f4abba31a7922a981e541e85283f0ced387d26e86aef9386d18c6982b9b5f8759882fe7f25a328180d86e146994ef19d28bc1432baf29751dec12b5f3d65dbbe224d72cf900c6831a";

    /// Mounts a request-aware sync-committee-contribution responder that echoes
    /// the request slot / subcommittee index / beacon block root.
    async fn mount_sync_contribution(server: &wiremock::MockServer) {
        struct Responder;
        impl wiremock::Respond for Responder {
            fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
                let query: std::collections::HashMap<String, String> =
                    req.url.query_pairs().into_owned().collect();
                let slot = query.get("slot").cloned().unwrap_or_default();
                let subcommittee_index =
                    query.get("subcommittee_index").cloned().unwrap_or_default();
                let beacon_block_root = query.get("beacon_block_root").cloned().unwrap_or_default();

                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": {
                        "slot": slot,
                        "beacon_block_root": beacon_block_root,
                        "subcommittee_index": subcommittee_index,
                        "aggregation_bits": format!("0x{}", "00".repeat(16)),
                        "signature": format!("0x{}", "00".repeat(96)),
                    }
                }))
            }
        }

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/eth/v1/validator/sync_committee_contribution",
            ))
            .respond_with(Responder)
            .mount(server)
            .await;
    }

    /// Builds a phase0 attestation with the given committee index.
    fn build_attestation(index: u64) -> phase0::Attestation {
        phase0::Attestation {
            aggregation_bits: phase0::BitList::default(),
            data: phase0::AttestationData {
                slot: 1,
                index,
                beacon_block_root: [u8::try_from(index).unwrap_or(0); 32],
                source: phase0::Checkpoint {
                    epoch: 0,
                    root: [0u8; 32],
                },
                target: phase0::Checkpoint {
                    epoch: 0,
                    root: [0u8; 32],
                },
            },
            signature: [0u8; 96],
        }
    }

    /// Mounts an aggregate-attestation responder that returns the Deneb
    /// attestation whose data root matches the request, or 404 when unknown.
    async fn mount_aggregate(
        server: &wiremock::MockServer,
        by_root: HashMap<String, phase0::Attestation>,
    ) {
        struct Responder {
            by_root: HashMap<String, phase0::Attestation>,
        }
        impl wiremock::Respond for Responder {
            fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
                let query: HashMap<String, String> = req.url.query_pairs().into_owned().collect();
                let root = query
                    .get("attestation_data_root")
                    .cloned()
                    .unwrap_or_default();
                match self.by_root.get(&root) {
                    Some(att) => wiremock::ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({ "version": "deneb", "data": att })),
                    None => wiremock::ResponseTemplate::new(404)
                        .set_body_json(serde_json::json!({ "code": 404, "message": "not found" })),
                }
            }
        }

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/eth/v2/validator/aggregate_attestation",
            ))
            .respond_with(Responder { by_root })
            .mount(server)
            .await;
    }

    /// Builds an attester duty definition from an eth2 [`AttesterDuty`], keyed
    /// by the given public key.
    fn attester_duty_def(pubkey: PubKey, duty: &AttesterDuty) -> AttesterDutyDefinition {
        AttesterDutyDefinition {
            pubkey,
            duty: duty.clone(),
        }
    }

    /// Builds an attester definition with the given committee index/length.
    fn attester_def(comm_idx: u64, comm_len: u64) -> DutyDefinition {
        DutyDefinition::Attester(attester_duty_def(
            PubKey::new([0u8; PK_LEN]),
            &AttesterDuty {
                slot: 1,
                validator_index: 0,
                committee_index: comm_idx,
                committee_length: comm_len,
                committees_at_slot: 1,
                validator_committee_index: 0,
            },
        ))
    }

    /// Builds the AggSigDB (returns a beacon committee selection) and DutyDB
    /// (returns the attestation data for each committee index) callbacks used
    /// by the aggregator tests.
    fn aggregator_funcs(
        atts: impl AsRef<[phase0::Attestation]>,
    ) -> (AggSigDbFunc, AwaitAttDataFunc) {
        use pluto_eth2api::v1;

        let agg_sig_db: AggSigDbFunc = Arc::new(move |_duty: Duty, _pubkey: PubKey| {
            Box::pin(async move {
                let selection = BeaconCommitteeSelection::new(v1::BeaconCommitteeSelection {
                    slot: 1,
                    validator_index: 0,
                    selection_proof: [0u8; 96],
                });
                let data: Box<dyn SignedData> = Box::new(selection);
                Ok(data)
            })
        });

        let by_idx: HashMap<u64, phase0::AttestationData> = atts
            .as_ref()
            .iter()
            .map(|a| (a.data.index, a.data.clone()))
            .collect();
        let await_att_data: AwaitAttDataFunc = Arc::new(move |_slot: u64, comm_idx: u64| {
            let data = by_idx.get(&comm_idx).cloned();
            Box::pin(async move { data.ok_or_else(|| "missing attestation data".into()) })
        });

        (agg_sig_db, await_att_data)
    }

    #[tokio::test]
    async fn fetch_aggregator_different_committee() {
        const SLOT: u64 = 1;
        let pk_a = PubKey::new([2u8; PK_LEN]);
        let pk_b = PubKey::new([3u8; PK_LEN]);

        let att_a = build_attestation(2);
        let att_b = build_attestation(3);

        let def_set = DutyDefinitionSet::from([
            (pk_a, attester_def(att_a.data.index, 0)),
            (pk_b, attester_def(att_b.data.index, 0)),
        ]);

        let by_root = HashMap::from([
            (
                format!("0x{}", hex::encode(att_a.data.tree_hash_root().0)),
                att_a.clone(),
            ),
            (
                format!("0x{}", hex::encode(att_b.data.tree_hash_root().0)),
                att_b.clone(),
            ),
        ]);

        let mock = BeaconMock::builder()
            .spec(aggregator_spec())
            .build()
            .await
            .expect("build mock");
        mount_aggregate(mock.server(), by_root).await;

        let (agg_sig_db, await_att_data) = aggregator_funcs(&[att_a.clone(), att_b.clone()]);

        let captured: Captured = Arc::new(Mutex::new(None));
        let fetch = Fetcher::builder()
            .eth2_cl(mock.client().clone())
            .fee_recipient(stub_fee_recipient())
            .agg_sig_db(agg_sig_db)
            .await_att_data(await_att_data)
            .builder_enabled(true)
            .graffiti_builder(GraffitiBuilder::default())
            .electra_slot(5)
            .fetch_only_comm_idx0(false)
            .subscribe(capturing_subscriber(captured.clone()))
            .build();

        let duty = Duty::new_aggregator_duty(SlotNumber::new(SLOT));
        fetch.fetch(duty, def_set).await.expect("fetch");

        let (_, res_set) = captured.lock().unwrap().take().expect("subscriber called");
        assert_eq!(res_set.len(), 2);

        for (pubkey, expected_idx) in [(pk_a, 2u64), (pk_b, 3u64)] {
            let UnsignedDutyData::AggAttestation(agg) = res_set.get(&pubkey).expect("entry") else {
                panic!("expected aggregated attestation");
            };
            assert_eq!(agg.data().expect("data").index, expected_idx);
        }
    }

    #[tokio::test]
    async fn fetch_aggregator_same_committee() {
        const SLOT: u64 = 1;
        let pk_a = PubKey::new([2u8; PK_LEN]);
        let pk_b = PubKey::new([3u8; PK_LEN]);

        // Both validators belong to the same committee; the aggregate is fetched
        // once and reused for the second validator.
        let att = build_attestation(2);
        let def_set = DutyDefinitionSet::from([
            (pk_a, attester_def(att.data.index, 0)),
            (pk_b, attester_def(att.data.index, 0)),
        ]);

        let by_root = HashMap::from([(
            format!("0x{}", hex::encode(att.data.tree_hash_root().0)),
            att.clone(),
        )]);

        let mock = BeaconMock::builder()
            .spec(aggregator_spec())
            .build()
            .await
            .expect("build mock");
        mount_aggregate(mock.server(), by_root).await;

        let (agg_sig_db, await_att_data) = aggregator_funcs(std::slice::from_ref(&att));

        let captured: Captured = Arc::new(Mutex::new(None));
        let fetch = Fetcher::builder()
            .eth2_cl(mock.client().clone())
            .fee_recipient(stub_fee_recipient())
            .agg_sig_db(agg_sig_db)
            .await_att_data(await_att_data)
            .builder_enabled(true)
            .graffiti_builder(GraffitiBuilder::default())
            .electra_slot(5)
            .fetch_only_comm_idx0(false)
            .subscribe(capturing_subscriber(captured.clone()))
            .build();

        let duty = Duty::new_aggregator_duty(SlotNumber::new(SLOT));
        fetch.fetch(duty, def_set).await.expect("fetch");

        let (_, res_set) = captured.lock().unwrap().take().expect("subscriber called");
        assert_eq!(res_set.len(), 2);
        for pubkey in [pk_a, pk_b] {
            let UnsignedDutyData::AggAttestation(agg) = res_set.get(&pubkey).expect("entry") else {
                panic!("expected aggregated attestation");
            };
            assert_eq!(agg.data().expect("data").index, 2);
        }
    }

    #[tokio::test]
    async fn fetch_aggregator_no_aggregator() {
        const SLOT: u64 = 1;
        let pk_a = PubKey::new([2u8; PK_LEN]);

        let att_a = build_attestation(2);
        let mut def_set = DutyDefinitionSet::new();
        // u64::MAX committee length makes the selection modulo enormous, so the
        // validator is never selected as an aggregator.
        def_set.insert(pk_a, attester_def(att_a.data.index, u64::MAX));

        let mock = BeaconMock::builder()
            .spec(aggregator_spec())
            .build()
            .await
            .expect("build mock");
        mount_aggregate(mock.server(), HashMap::new()).await;

        let (agg_sig_db, await_att_data) = aggregator_funcs([att_a]);

        let captured: Captured = Arc::new(Mutex::new(None));
        let fetcher = Fetcher::builder()
            .eth2_cl(mock.client().clone())
            .fee_recipient(stub_fee_recipient())
            .agg_sig_db(agg_sig_db)
            .await_att_data(await_att_data)
            .builder_enabled(true)
            .graffiti_builder(GraffitiBuilder::default())
            .electra_slot(5)
            .fetch_only_comm_idx0(false)
            .subscribe(capturing_subscriber(captured.clone()))
            .build();

        let duty = Duty::new_aggregator_duty(SlotNumber::new(SLOT));
        // No aggregators found -> empty set -> Ok and subscriber not invoked.
        fetcher.fetch(duty, def_set).await.expect("fetch");
        assert!(captured.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn fetch_aggregator_nil_aggregate() {
        const SLOT: u64 = 1;
        let pk_a = PubKey::new([2u8; PK_LEN]);

        let att_a = build_attestation(2);
        let mut def_set = DutyDefinitionSet::new();
        def_set.insert(pk_a, attester_def(att_a.data.index, 0));

        let mock = BeaconMock::builder()
            .spec(aggregator_spec())
            .build()
            .await
            .expect("build mock");
        // Empty map -> responder returns 404 for every root.
        mount_aggregate(mock.server(), HashMap::new()).await;

        let (agg_sig_db, await_att_data) = aggregator_funcs(std::slice::from_ref(&att_a));

        let fetcher = Fetcher::builder()
            .eth2_cl(mock.client().clone())
            .fee_recipient(stub_fee_recipient())
            .agg_sig_db(agg_sig_db)
            .await_att_data(await_att_data)
            .builder_enabled(true)
            .graffiti_builder(GraffitiBuilder::default())
            .electra_slot(5)
            .fetch_only_comm_idx0(false)
            .build();

        let duty = Duty::new_aggregator_duty(SlotNumber::new(SLOT));
        let err = fetcher
            .fetch(duty, def_set)
            .await
            .expect_err("expected error");
        assert!(
            err.to_string()
                .contains("aggregate attestation not found by root (retryable)"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_sync_contribution_aggregator() {
        use pluto_eth2api::{spec::altair, v1};

        const SLOT: u64 = 1;
        const V_IDX_A: u64 = 2;
        const V_IDX_B: u64 = 3;
        const SUBCOMM_A: u64 = 4;
        const SUBCOMM_B: u64 = 5;

        let pk_a = PubKey::new([2u8; PK_LEN]);
        let pk_b = PubKey::new([3u8; PK_LEN]);

        let root_a = [10u8; 32];
        let root_b = [11u8; 32];

        let selection = |v_idx, subcomm, sig| {
            SyncCommitteeSelection::new(v1::SyncCommitteeSelection {
                slot: SLOT,
                validator_index: v_idx,
                subcommittee_index: subcomm,
                selection_proof: bls_sig(sig),
            })
        };
        let message = |v_idx, root| {
            SignedSyncMessage::new(altair::SyncCommitteeMessage {
                slot: SLOT,
                beacon_block_root: root,
                validator_index: v_idx,
                signature: [0u8; 96],
            })
        };

        let sel_a = selection(V_IDX_A, SUBCOMM_A, SYNC_AGG_SIG_A);
        let sel_b = selection(V_IDX_B, SUBCOMM_B, SYNC_AGG_SIG_B);
        let msg_a = message(V_IDX_A, root_a);
        let msg_b = message(V_IDX_B, root_b);

        let selections: HashMap<PubKey, SyncCommitteeSelection> =
            HashMap::from([(pk_a, sel_a), (pk_b, sel_b)]);
        let messages: HashMap<PubKey, SignedSyncMessage> =
            HashMap::from([(pk_a, msg_a), (pk_b, msg_b)]);

        let mut def_set = DutyDefinitionSet::new();
        for pk in [pk_a, pk_b] {
            def_set.insert(
                pk,
                DutyDefinition::SyncCommittee(SyncCommitteeDutyDefinition {
                    pubkey: pk,
                    validator_index: 0,
                    validator_sync_committee_indices: vec![],
                }),
            );
        }

        let mock = BeaconMock::builder()
            .spec(aggregator_spec())
            .build()
            .await
            .expect("build mock");
        mount_sync_contribution(mock.server()).await;

        let sels = selections.clone();
        let msgs = messages.clone();
        let agg_sig_db: AggSigDbFunc = Arc::new(move |duty: Duty, pubkey: PubKey| {
            let sels = sels.clone();
            let msgs = msgs.clone();
            Box::pin(async move {
                let data: Box<dyn SignedData> = match duty.duty_type {
                    DutyType::PrepareSyncContribution => Box::new(sels[&pubkey].clone()),
                    DutyType::SyncMessage => Box::new(msgs[&pubkey].clone()),
                    _ => return Err("unsupported duty".into()),
                };
                Ok(data)
            })
        });

        let captured: Captured = Arc::new(Mutex::new(None));
        let fetcher = Fetcher::builder()
            .eth2_cl(mock.client().clone())
            .fee_recipient(stub_fee_recipient())
            .agg_sig_db(agg_sig_db)
            .await_att_data(stub_await_att_data())
            .builder_enabled(true)
            .graffiti_builder(GraffitiBuilder::default())
            .electra_slot(5)
            .fetch_only_comm_idx0(false)
            .subscribe(capturing_subscriber(captured.clone()))
            .build();

        let duty = Duty::new_sync_contribution_duty(SlotNumber::new(SLOT));
        fetcher.fetch(duty, def_set).await.expect("fetch");

        let (_, res_set) = captured.lock().unwrap().take().expect("subscriber called");
        assert_eq!(res_set.len(), 2);

        for (pubkey, expected_subcomm, expected_root) in
            [(pk_a, SUBCOMM_A, root_a), (pk_b, SUBCOMM_B, root_b)]
        {
            let UnsignedDutyData::SyncContribution(contrib) = res_set.get(&pubkey).expect("entry")
            else {
                panic!("expected sync contribution");
            };
            assert_eq!(contrib.0.slot, SLOT);
            assert_eq!(contrib.0.subcommittee_index, expected_subcomm);
            assert_eq!(contrib.0.beacon_block_root, expected_root);
        }
    }

    #[tokio::test]
    async fn fetch_sync_contribution_not_aggregator() {
        use pluto_eth2api::v1;

        const SLOT: u64 = 1;
        let pk_a = PubKey::new([2u8; PK_LEN]);
        let pk_b = PubKey::new([3u8; PK_LEN]);

        let mut def_set = DutyDefinitionSet::new();
        for pk in [pk_a, pk_b] {
            def_set.insert(
                pk,
                DutyDefinition::SyncCommittee(SyncCommitteeDutyDefinition {
                    pubkey: pk,
                    validator_index: 0,
                    validator_sync_committee_indices: vec![],
                }),
            );
        }

        let mock = BeaconMock::builder()
            .spec(aggregator_spec())
            .build()
            .await
            .expect("build mock");

        let agg_sig_db: AggSigDbFunc = Arc::new(move |duty: Duty, _pubkey: PubKey| {
            Box::pin(async move {
                if duty.duty_type == DutyType::PrepareSyncContribution {
                    let selection = SyncCommitteeSelection::new(v1::SyncCommitteeSelection {
                        slot: 0,
                        validator_index: 0,
                        subcommittee_index: 0,
                        selection_proof: bls_sig(SYNC_NON_AGG_SIG),
                    });
                    let data: Box<dyn SignedData> = Box::new(selection);
                    return Ok(data);
                }
                Err("unsupported duty".into())
            })
        });

        let fetcher = Fetcher::builder()
            .eth2_cl(mock.client().clone())
            .fee_recipient(stub_fee_recipient())
            .agg_sig_db(agg_sig_db)
            .await_att_data(stub_await_att_data())
            .builder_enabled(true)
            .graffiti_builder(GraffitiBuilder::default())
            .electra_slot(5)
            .fetch_only_comm_idx0(false)
            .build();

        let duty = Duty::new_sync_contribution_duty(SlotNumber::new(SLOT));
        // Non-aggregators are skipped, producing an empty set and no error.
        fetcher.fetch(duty, def_set).await.expect("fetch");
    }

    #[tokio::test]
    async fn fetch_sync_contribution_data_error() {
        const SLOT: u64 = 1;
        let pk_a = PubKey::new([2u8; PK_LEN]);

        let mut def_set = DutyDefinitionSet::new();
        def_set.insert(
            pk_a,
            DutyDefinition::SyncCommittee(SyncCommitteeDutyDefinition {
                pubkey: pk_a,
                validator_index: 0,
                validator_sync_committee_indices: vec![],
            }),
        );

        let mock = BeaconMock::builder().build().await.expect("build mock");
        let agg_sig_db: AggSigDbFunc = Arc::new(move |_duty: Duty, _pubkey: PubKey| {
            Box::pin(async move { Err("error".into()) })
        });

        let fetcher = Fetcher::builder()
            .eth2_cl(mock.client().clone())
            .fee_recipient(stub_fee_recipient())
            .agg_sig_db(agg_sig_db)
            .await_att_data(stub_await_att_data())
            .builder_enabled(true)
            .graffiti_builder(GraffitiBuilder::default())
            .electra_slot(5)
            .fetch_only_comm_idx0(false)
            .build();

        let duty = Duty::new_sync_contribution_duty(SlotNumber::new(SLOT));
        let err = fetcher
            .fetch(duty, def_set)
            .await
            .expect_err("expected error");
        let msg = err.to_string();
        assert!(msg.contains("fetch contribution data"), "got: {msg}");
        assert!(msg.contains("error"), "got: {msg}");
    }
}
