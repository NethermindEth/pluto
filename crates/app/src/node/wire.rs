//! Core duty-workflow construction and wiring.
//!
//! This constructs the ten core duty-workflow components and connects them into
//! the data-flow graph that drives a single distributed-validator node.
//!
//! The construction order builds back-edge targets before their consumers (see
//! [`wire_core_workflow`]); Pluto interleaves construction and wiring because
//! of its builder/service split:
//!
//! * scheduler subscribers are registered on the *builder* before `.build()`;
//! * the fetcher's back-edges and subscribers are bon-builder fields;
//! * consensus / parsigdb / sigagg subscribers are registered on the *service*.
//!
//! Following the load-vs-wire split, this function takes already-resolved
//! inputs ([`WireInputs`]) and a [`ParSigExSeam`] for the partial-signature
//! exchange, so tests can inject a `BeaconMock` and an in-memory (loopback)
//! parsigex without a real libp2p swarm.

use std::{collections::HashMap, sync::Arc};

use futures::future::BoxFuture;
use pluto_consensus::wrapper::ConsensusWrapper;
use pluto_core::{
    aggsigdb::{memory::MemoryDBHandle, types::AggSigDB},
    bcast::Broadcaster,
    corepb::v1::core as pbcore,
    deadline::{DeadlineCalculator, DeadlinerTask},
    dutydb,
    fetcher::{
        AggSigDbFunc, AwaitAttDataFunc, FeeRecipientFunc, Fetcher, GraffitiBuilder, Subscriber,
    },
    parsigdb,
    scheduler::SchedulerBuilder,
    sigagg::{Aggregator, VerifyFn},
    signeddata::{SyncContribution, VersionedAggregatedAttestation},
    tracker::{
        AnalyserRx, DeleterRx, PeerInfo, StepError, Tracker, TrackerService,
        inclusion::{INCL_CHECK_LAG, INCL_MISSED_LAG, InclusionChecker},
    },
    types::{Duty, ParSignedData, ParSignedDataSet, PubKey, SignedData, SignedDataSet, Slot},
    unsigneddata::{self, UnsignedDataSet},
    validatorapi::{self, Component, Handler, SeenPubkeysFn},
};
use pluto_eth2api::{
    BeaconNodeClient, EthBeaconNodeApiClient,
    spec::{bellatrix::ExecutionAddress, phase0::BLSPubKey},
    valcache::{ValidatorCache, ValidatorCacheError},
};
use pluto_featureset::{Feature, FeatureSet, Status};
use tokio_util::sync::CancellationToken;

use crate::{
    builderregistration::{
        BuilderRegistrationService, RegistrationSubmitter, submit_proposal_preparations,
    },
    node::AppError,
};

/// A `Send + Sync` boxed future. The parsigdb subscriber seams require their
/// futures to be `Sync` (see `internal_subscriber`/`threshold_subscriber`), so
/// the broadcast seam future must be `Sync` too.
type SyncBoxFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + Sync + 'a>>;

/// Outbound partial-signature broadcast seam.
pub type ParSigExBroadcast = Arc<
    dyn Fn(Duty, ParSignedDataSet) -> SyncBoxFuture<'static, Result<(), AppError>> + Send + Sync,
>;

/// Inbound received-partial-signature subscriber, wired into
/// `parsigdb.store_external`.
pub type ParSigExReceived =
    Arc<dyn Fn(Duty, ParSignedDataSet) -> BoxFuture<'static, ()> + Send + Sync>;

/// Registers the inbound subscriber on the parsigex transport.
pub type ParSigExSubscribe =
    Box<dyn FnOnce(ParSigExReceived) -> BoxFuture<'static, ()> + Send + Sync>;

/// Partial-signature exchange seam.
///
/// The production path supplies a real `parsigex::Handle` (outbound broadcast)
/// plus an inbound subscription; tests supply a loopback so partial signatures
/// cross the threshold locally.
pub struct ParSigExSeam {
    /// Outbound broadcast, wired into `parsigdb.subscribe_internal`.
    pub broadcast: ParSigExBroadcast,
    /// Registers the inbound subscriber (received sets -> `store_external`).
    /// A loopback test may wire `broadcast` straight back into the subscriber.
    pub subscribe: ParSigExSubscribe,
}

/// Per-slot subscriber seam, registered on the scheduler's slot ticks.
///
/// A boxed callback so core wiring stays decoupled from what drives it:
/// production leaves it `None` (a real validator client drives the validator
/// API); simnet forwards each tick to the in-process validator mock.
pub type SlotTickFn = Arc<dyn Fn(&Slot) -> BoxFuture<'static, Result<(), AppError>> + Send + Sync>;

/// Per-validator data extracted from the cluster lock for this node.
pub struct ValidatorInfo {
    /// The distributed validator's group (root) public key.
    pub pubkey: PubKey,
    /// The DV root pubkey as an eth2 `BLSPubKey`.
    pub eth2_pubkey: BLSPubKey,
    /// This node's public share for the validator (eth2 `BLSPubKey`).
    pub pubshare: BLSPubKey,
    /// Fee recipient execution address for the validator.
    pub fee_recipient: ExecutionAddress,
}

/// Shares one step error between the tracker and the caller that must still
/// propagate it.
///
/// The tracker needs an owned [`StepError`] (`Arc<dyn Error>`), but the stitch
/// points also have to return their original error, and those error types are
/// not `Clone`. Moving the error into an `Arc` and handing the caller this
/// wrapper keeps a single allocation while preserving the chain: `source()`
/// returns the original error, so the tracker's reason inference — which walks
/// `source()` looking for an `EthBeaconNodeApiClientError` — still classifies
/// beacon-node failures correctly.
#[derive(Debug, Clone)]
struct SharedStepError(StepError);

impl std::fmt::Display for SharedStepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for SharedStepError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

/// Splits a step result into the error to report to the tracker and the error
/// to return to the caller, sharing one allocation between them.
fn share_step_err<E>(err: E) -> (StepError, SharedStepError)
where
    E: std::error::Error + Send + Sync + 'static,
{
    let shared: StepError = Arc::new(err);
    (Arc::clone(&shared), SharedStepError(shared))
}

/// Reports a step error to the tracker without needing to propagate it, for
/// stitch points whose errors are logged and swallowed locally.
fn owned_step_err<E>(err: E) -> StepError
where
    E: std::error::Error + Send + Sync + 'static,
{
    Arc::new(err)
}

/// Wraps a [`DeadlineCalculator`], shifting every deadline later by a fixed
/// offset. Used to derive the tracker's analyser/deleter deadlines from the
/// shared duty deadline. Parity: the closures charon builds in `newTracker`.
struct OffsetCalculator {
    inner: Arc<dyn DeadlineCalculator>,
    offset: std::time::Duration,
}

impl OffsetCalculator {
    fn new(inner: Arc<dyn DeadlineCalculator>, offset: std::time::Duration) -> Self {
        Self { inner, offset }
    }
}

impl DeadlineCalculator for OffsetCalculator {
    fn deadline(
        &self,
        duty: &Duty,
    ) -> pluto_core::deadline::Result<Option<chrono::DateTime<chrono::Utc>>> {
        let Some(deadline) = self.inner.deadline(duty)? else {
            return Ok(None);
        };
        // A deadline that cannot be shifted (overflow) is treated as
        // never-expiring rather than silently wrapping to an earlier instant.
        let shifted = chrono::Duration::from_std(self.offset)
            .ok()
            .and_then(|offset| deadline.checked_add_signed(offset));
        Ok(shifted)
    }
}

/// Feature set the tracker subsystem runs under.
///
/// The networked inclusion checker only resolves proposer inclusion; the
/// attestation-inclusion path (attester/aggregator) is a follow-up, and its
/// core panics if fed those submissions. So mask the (alpha, off-by-default)
/// `AttestationInclusion` feature off until that path lands, keeping the
/// analyser and the checker consistent.
fn tracker_feature_set(feature_set: &Arc<FeatureSet>) -> Arc<FeatureSet> {
    if !feature_set.enabled(Feature::AttestationInclusion) {
        return Arc::clone(feature_set);
    }

    tracing::warn!(
        "Feature attestation_inclusion is enabled but not yet supported by the \
         inclusion checker; disabling it for duty tracking"
    );
    let mut fs = (**feature_set).clone();
    fs.state
        .insert(Feature::AttestationInclusion, Status::Disable);
    Arc::new(fs)
}

/// Returns the slot to start tracking from, which suppresses noisy failed
/// duties at startup caused by a validator client that is still coming up.
///
/// Delays at most 10 seconds but never fewer than 2 slots. Parity: charon
/// `app.go` `calculateTrackerDelay`.
async fn calculate_tracker_delay(
    eth2_cl: &EthBeaconNodeApiClient,
    slot_duration: std::time::Duration,
) -> Result<u64, AppError> {
    const MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(10);
    const MIN_DELAY_SLOTS: u64 = 2;

    let genesis = eth2_cl
        .fetch_genesis_time()
        .await
        .map_err(AppError::BeaconApi)?;

    let elapsed = chrono::Utc::now()
        .signed_duration_since(genesis)
        .to_std()
        .unwrap_or(std::time::Duration::ZERO);
    let slot_nanos = slot_duration.as_nanos();
    let current_slot = elapsed
        .as_nanos()
        .checked_div(slot_nanos)
        .and_then(|slots| u64::try_from(slots).ok())
        .unwrap_or(u64::MAX);

    let max_delay_slots = MAX_DELAY
        .as_nanos()
        .checked_div(slot_nanos)
        .and_then(|slots| u64::try_from(slots).ok())
        .unwrap_or(u64::MAX);
    let max_delay_time_slot = current_slot
        .saturating_add(max_delay_slots)
        .saturating_add(1);
    let min_delay_slot = current_slot.saturating_add(MIN_DELAY_SLOTS);

    Ok(max_delay_time_slot.max(min_delay_slot))
}

/// Already-resolved inputs to [`wire_core_workflow`].
///
/// These are derived from the cluster manifest + config, but passed in so that
/// file-loading and P2P setup (in `run`) stay separate from
/// construction-and-wiring (here) — enabling the Tier 1 test to inject a
/// `BeaconMock` and in-memory parsigex.
pub struct WireInputs {
    /// Threshold of partial signatures required for aggregation.
    pub threshold: u64,
    /// This node's 1-indexed share index.
    pub share_idx: u64,
    /// Beacon node client used for scheduling.
    pub beacon_client: BeaconNodeClient,
    /// Beacon node API client used for fetching / dutydb / validatorapi.
    pub eth2_cl: EthBeaconNodeApiClient,
    /// Submission beacon node client used for broadcasting.
    pub submission_client: BeaconNodeClient,
    /// Per-validator data for this node.
    pub validators: Vec<ValidatorInfo>,
    /// Current consensus implementation, from the controller. Forwards to the
    /// default QBFT impl the caller also wires into the QBFT p2p behaviour.
    pub consensus: Arc<ConsensusWrapper>,
    /// Whether the builder API is enabled.
    pub builder_enabled: bool,
    /// Upstream beacon URL the validator API reverse-proxies unhandled requests
    /// to.
    pub upstream_url: reqwest::Url,
    /// Partial-signature exchange seam (production handle or test loopback).
    pub parsigex: ParSigExSeam,
    /// Aggregated-signature verifier for SigAgg. Production injects the eth2
    /// verifier (`sigagg::new_verifier`); tests may inject a permissive one to
    /// exercise the wiring without real BLS test vectors.
    pub sigagg_verifier: VerifyFn,
    /// Per-component deadline calculator. Production injects a beacon-derived
    /// [`DutyDeadlineCalculator`](pluto_core::deadline::DutyDeadlineCalculator);
    /// tests inject `NeverExpiringCalculator` so driven duties are never
    /// trimmed.
    pub deadline_calc: Arc<dyn DeadlineCalculator>,
    /// Per-validator graffiti builder for proposed blocks. Production injects a
    /// beacon-derived builder; tests inject the default.
    pub graffiti_builder: GraffitiBuilder,
    /// Slot at which the Electra fork activates (`electra_epoch *
    /// slots_per_epoch`); gates the `fetch_only_comm_idx0` committee-index
    /// behavior.
    pub electra_slot: u64,
    /// Whether to fetch only committee index 0 at/after `electra_slot`
    /// (`Feature::FetchOnlyCommIdx0`).
    pub fetch_only_comm_idx0: bool,
    /// Observer invoked with each DV root pubkey the validator client
    /// references on the validator API, feeding the monitoring readiness
    /// checker. `None` disables the signal (e.g. tests).
    pub seen_pubkeys: Option<SeenPubkeysFn>,
    /// Optional per-slot subscriber; simnet wires the in-process validator
    /// mock here. `None` in production and tests.
    pub slot_tick: Option<SlotTickFn>,
    /// Cluster peers, used by the tracker to attribute per-peer participation.
    /// Empty disables participation reporting but still tracks duty outcomes.
    pub peers: Vec<PeerInfo>,
    /// Resolved feature set. The tracker consults it to decide which duty types
    /// have an on-chain inclusion step (`Feature::AttestationInclusion`).
    pub feature_set: Arc<FeatureSet>,
    /// Infosync component, triggered on each epoch's last slot to run the
    /// cluster-wide priority exchange. `None` in tests.
    pub infosync: Option<Arc<pluto_infosync::Component>>,
    /// Builder-registration source. Drives the per-epoch registration
    /// submission and the `prepare_beacon_proposer` push, and supplies the
    /// effective fee recipient (which an overrides file or the Obol API can
    /// change at runtime). `None` in tests, which fall back to the static
    /// lock-derived fee recipients.
    pub builder_registrations: Option<BuilderRegistrationService>,
}

/// The wired components and long-lived handles produced by
/// [`wire_core_workflow`], returned so the caller (`run`) can drive their
/// background tasks and shut them down in order.
pub struct WiredComponents {
    /// Background task driving the self-spawning scheduler actor, returned so
    /// the caller can supervise its lifecycle. The scheduler's query handle is
    /// held directly by the validator API.
    pub scheduler_task: tokio::task::JoinHandle<()>,
    /// In-memory duty database (shared; needs explicit shutdown).
    pub dutydb: Arc<dutydb::MemDB>,
    /// In-memory partial-signature database (its `trim` task must be spawned).
    pub parsigdb: Arc<parsigdb::memory::MemDB>,
    /// Receiver paired with the parsigdb deadliner, for the `trim` task.
    pub parsigdb_deadliner_rx: tokio::sync::mpsc::Receiver<Duty>,
    /// Aggregated-signature database (self-spawning).
    pub aggsigdb: MemoryDBHandle,
    /// The fetcher (driven via scheduler subscriptions).
    pub fetcher: Arc<Fetcher>,
    /// Networked inclusion checker; its `run` loop is spawned and supervised by
    /// the caller.
    pub inclusion_checker: Arc<InclusionChecker>,
    /// The validator API axum router, ready to be served.
    pub validator_api_router: axum::Router,
}

/// Per-epoch trim + refresh for the shared [`ValidatorCache`], the Rust analog
/// of Charon's inline validator-cache refresh subscriber in `wireCoreWorkflow`.
///
/// Registered as a scheduler slot subscriber by [`wire_core_workflow`]. The
/// seeded cache is otherwise frozen at startup; this refresher re-fetches the
/// cluster validator set on each epoch's first slot so validators activating
/// after startup get duties scheduled and exited validators stop being
/// resolved.
struct ValidatorCacheRefresher {
    cache: ValidatorCache,
    bookkeeping: tokio::sync::Mutex<RefreshBookkeeping>,
}

/// Mirrors the `firstValCacheRefresh` / `refreshedBySlot` locals in Charon's
/// `wireCoreWorkflow`, which the refresh closure reads and writes under a lock.
struct RefreshBookkeeping {
    /// Whether the cache has never been refreshed. Forces the first tick to
    /// refresh regardless of the slot's position in the epoch.
    first_val_cache_refresh: bool,
    /// Whether the previous refresh fetched by slot (`true`) or fell back to
    /// the head state (`false`). A head fallback forces the next tick to
    /// refresh and to re-fetch the epoch's first slot.
    refresh_by_slot: bool,
}

impl ValidatorCacheRefresher {
    fn new(cache: ValidatorCache) -> Self {
        Self {
            cache,
            // Charon initializes both flags to `true`.
            bookkeeping: tokio::sync::Mutex::new(RefreshBookkeeping {
                first_val_cache_refresh: true,
                refresh_by_slot: true,
            }),
        }
    }

    /// Trims and refreshes the cache for `slot` when required, mirroring
    /// Charon's `shouldUpdateCache` gate and the `GetBySlot` head-fallback
    /// re-fetch.
    async fn refresh(&self, slot: &Slot) -> Result<(), ValidatorCacheError> {
        let mut bk = self.bookkeeping.lock().await;

        // shouldUpdateCache: skip mid-epoch slots once the cache has been
        // refreshed at least once by slot.
        if !slot.first_in_epoch() && !bk.first_val_cache_refresh && bk.refresh_by_slot {
            return Ok(());
        }

        tracing::info!(
            slot = %slot.slot,
            first_refresh = bk.first_val_cache_refresh,
            "Refreshing validator cache"
        );

        // If the previous refresh fell back to head, fetch the epoch's first
        // slot rather than the current slot. `epoch * slots_per_epoch <= slot`,
        // so the multiply never actually saturates.
        let slot_to_fetch = if bk.refresh_by_slot {
            slot.slot.inner()
        } else {
            slot.epoch().saturating_mul(slot.slots_per_epoch)
        };

        self.cache.trim().await;
        let (_, _, refresh_by_slot) = self.cache.get_by_slot(slot_to_fetch).await?;

        bk.refresh_by_slot = refresh_by_slot;
        bk.first_val_cache_refresh = false;

        Ok(())
    }
}

/// Constructs and wires the ten core duty-workflow components.
///
/// Reproduces the core duty-workflow data-flow graph. The 13 stitches and 3
/// deadlock-critical back-edges are annotated inline.
///
/// Construction order builds back-edge targets before their consumers:
/// deadliners → aggsigdb → dutydb → fetcher → consensus.subscribe → parsigdb →
/// sigagg → broadcaster → parsigex → validatorapi → scheduler (last).
pub async fn wire_core_workflow(
    inputs: WireInputs,
    ct: CancellationToken,
) -> Result<WiredComponents, AppError> {
    let WireInputs {
        threshold,
        share_idx,
        beacon_client,
        eth2_cl,
        submission_client,
        validators,
        consensus,
        builder_enabled,
        upstream_url,
        parsigex,
        sigagg_verifier,
        deadline_calc,
        graffiti_builder,
        electra_slot,
        fetch_only_comm_idx0,
        seen_pubkeys,
        slot_tick,
        peers,
        feature_set,
        infosync,
        builder_registrations,
    } = inputs;

    // ---- Derived validator maps ----
    let mut eth2_pubkeys = Vec::with_capacity(validators.len());
    // DV root pubkey -> this node's public share (validatorapi wants this flat
    // map already collapsed for our share index).
    let mut pub_share_by_pubkey: HashMap<BLSPubKey, BLSPubKey> = HashMap::new();
    let mut fee_recipient_by_pubkey: HashMap<PubKey, ExecutionAddress> = HashMap::new();
    for val in &validators {
        eth2_pubkeys.push(val.eth2_pubkey);
        pub_share_by_pubkey.insert(val.eth2_pubkey, val.pubshare);
        fee_recipient_by_pubkey.insert(val.pubkey, val.fee_recipient);
    }

    // One pubkey-scoped validator cache shared by the scheduler's beacon
    // client, the submission client, and the validator API, so every consumer
    // resolves the same cluster validator set. Without seeding, the scheduler
    // would resolve duties against an empty (or unfiltered) set. `ValidatorCache`
    // clones share state, so the per-epoch trim + refresh subscriber registered
    // below refreshes every consumer at once.
    let validator_cache = ValidatorCache::new(eth2_cl.clone(), eth2_pubkeys);
    tokio::join!(
        beacon_client.set_validator_cache(validator_cache.clone()),
        submission_client.set_validator_cache(validator_cache.clone()),
    );

    // The builder-registration service is the authority on fee recipients when
    // present: an overrides file or the Obol API can change them at runtime,
    // and the fetcher's proposal check must compare against the value actually
    // in force. Without it, fall back to the static lock-derived map.
    let fee_recipient_fn: FeeRecipientFunc = match builder_registrations.clone() {
        Some(service) => {
            Arc::new(move |pubkey: &PubKey| service.fee_recipient(pubkey).unwrap_or_default())
        }
        None => {
            let map = fee_recipient_by_pubkey.clone();
            Arc::new(move |pubkey: &PubKey| map.get(pubkey).copied().unwrap_or_default())
        }
    };

    // ---- Deadliners (one per component) ----
    //
    // Each component gets its own deadliner task sharing the injected calculator
    // (an `Arc<dyn DeadlineCalculator>`, so a single instance backs all three).
    let (dutydb_deadliner, dutydb_deadliner_rx) =
        DeadlinerTask::start(ct.clone(), "dutydb", Arc::clone(&deadline_calc));
    let (parsigdb_deadliner, parsigdb_deadliner_rx) =
        DeadlinerTask::start(ct.clone(), "parsigdb", Arc::clone(&deadline_calc));
    let (aggsigdb_deadliner, aggsigdb_deadliner_rx) =
        DeadlinerTask::start(ct.clone(), "aggsigdb", Arc::clone(&deadline_calc));

    // ---- Tracker ----
    //
    // Analysis has to wait until a duty's inclusion verdict can have arrived, so
    // both tracker deadliners sit `INCL_MISSED_LAG + INCL_CHECK_LAG` slots past
    // the duty deadline, and the deleter a further minute past the analyser so
    // duties of the same slot are analysed before their events are dropped.
    // Parity: charon `app.go` `newTracker`.
    let (slot_duration, _slots_per_epoch) = eth2_cl
        .fetch_slots_config()
        .await
        .map_err(AppError::BeaconApi)?;
    let tracker_lag = slot_duration
        .saturating_mul(u32::try_from(INCL_MISSED_LAG + INCL_CHECK_LAG).unwrap_or(u32::MAX));

    let (tracker_analyser, tracker_analyser_rx) = DeadlinerTask::start(
        ct.clone(),
        "tracker_analyser",
        Arc::new(OffsetCalculator::new(
            Arc::clone(&deadline_calc),
            tracker_lag,
        )),
    );
    let (tracker_deleter, tracker_deleter_rx) = DeadlinerTask::start(
        ct.clone(),
        "tracker_deleter",
        Arc::new(OffsetCalculator::new(
            Arc::clone(&deadline_calc),
            tracker_lag.saturating_add(std::time::Duration::from_secs(60)),
        )),
    );

    let tracker_feature_set = tracker_feature_set(&feature_set);

    let track_from = calculate_tracker_delay(&eth2_cl, slot_duration).await?;
    let tracker = TrackerService::start(
        ct.clone(),
        tracker_analyser,
        AnalyserRx(tracker_analyser_rx),
        tracker_deleter,
        DeleterRx(tracker_deleter_rx),
        peers,
        track_from,
        Arc::clone(&tracker_feature_set),
    );

    // Resolves the terminal `ChainInclusion` step; without it every duty with an
    // inclusion step would stall unresolved and be reported as failed. Spawned
    // and supervised by `run_lifecycle`.
    let inclusion_checker = {
        let tracker = Arc::clone(&tracker);
        Arc::new(
            InclusionChecker::new(
                eth2_cl.clone(),
                Box::new(move |duty: &Duty, pubkey: PubKey, err| {
                    let tracker = Arc::clone(&tracker);
                    let duty = duty.clone();
                    // The core's callback is sync but `inclusion_checked` is
                    // async, so hand the event to the runtime.
                    tokio::spawn(async move {
                        tracker.inclusion_checked(duty, pubkey, err).await;
                    });
                }),
                Arc::clone(&tracker_feature_set),
            )
            .await
            .map_err(AppError::BeaconApi)?,
        )
    };

    // ---- (4) AggSigDB (built before fetcher: agg_sig_db back-edge target) ----
    let aggsigdb = MemoryDBHandle::new(aggsigdb_deadliner, aggsigdb_deadliner_rx, ct.clone());

    // ---- (5) DutyDB (built before fetcher: await_att_data back-edge target) ----
    let dutydb = Arc::new(dutydb::MemDB::new(
        dutydb_deadliner,
        dutydb_deadliner_rx,
        &ct,
    ));

    // ---- (6) Fetcher ----
    //
    // Back-edge: fetcher.agg_sig_db = aggsigdb.wait_for (DEADLOCK-CRITICAL —
    // proposer RANDAO).
    let agg_sig_db_fn: AggSigDbFunc = {
        let aggsigdb = aggsigdb.clone();
        Arc::new(move |duty: Duty, pubkey: PubKey| {
            let aggsigdb = aggsigdb.clone();
            Box::pin(async move {
                let signed: Box<dyn SignedData> = aggsigdb.wait_for(duty, pubkey).await?;
                Ok(signed)
            })
        })
    };
    // Back-edge: fetcher.await_att_data = dutydb.await_attestation (DEADLOCK-
    // CRITICAL — aggregator duties).
    let await_att_data_fn: AwaitAttDataFunc = {
        let dutydb = Arc::clone(&dutydb);
        Arc::new(move |slot: u64, comm_idx: u64| {
            let dutydb = Arc::clone(&dutydb);
            Box::pin(async move {
                let data = dutydb.await_attestation(slot, comm_idx).await?;
                Ok(data)
            })
        })
    };
    // Stitch: fetcher.subscribe(consensus.propose), bounded by the duty deadline.
    let fetch_subscriber: Subscriber = {
        let consensus = Arc::clone(&consensus);
        let ct = ct.clone();
        let deadline_calc = Arc::clone(&deadline_calc);
        let tracker = Arc::clone(&tracker);
        Arc::new(move |duty: Duty, set: UnsignedDataSet| {
            let consensus = Arc::clone(&consensus);
            let ct = ct.clone();
            let deadline_calc = Arc::clone(&deadline_calc);
            let tracker = Arc::clone(&tracker);
            Box::pin(async move {
                let pubkeys: Vec<PubKey> = set.keys().copied().collect();
                let value = unsigneddata::unsigned_data_set_to_proto(&set)?;
                // Bound consensus by the duty deadline so a stuck instance is
                // cancelled (-> ConsensusTimeout) instead of running until shutdown.
                let result = run_bounded_by_duty_deadline(
                    &deadline_calc,
                    &ct,
                    duty.clone(),
                    move |duty, dct| async move { consensus.propose(dct, duty, value).await },
                )
                .await;

                match result {
                    Ok(()) => {
                        tracker.consensus_proposed(duty, &pubkeys, None).await;
                        Ok(())
                    }
                    Err(err) => {
                        let (reported, returned) = share_step_err(err);
                        tracker
                            .consensus_proposed(duty, &pubkeys, Some(reported))
                            .await;
                        Err(returned.into())
                    }
                }
            })
        })
    };

    let fetcher = Arc::new(
        Fetcher::builder()
            .eth2_cl(eth2_cl.clone())
            .fee_recipient(Arc::clone(&fee_recipient_fn))
            .agg_sig_db(agg_sig_db_fn)
            .await_att_data(await_att_data_fn)
            .builder_enabled(builder_enabled)
            .graffiti_builder(graffiti_builder)
            .electra_slot(electra_slot)
            .fetch_only_comm_idx0(fetch_only_comm_idx0)
            .subscribe(fetch_subscriber)
            .build(),
    );

    // ---- (7) consensus.subscribe(dutydb.store) ----
    //
    // The consensus subscriber callback is synchronous (`SubscriberResult`), so
    // we spawn the async `dutydb.store` inside it.
    {
        let dutydb = Arc::clone(&dutydb);
        let tracker = Arc::clone(&tracker);
        consensus.subscribe(Box::new(
            move |duty: Duty, value: pbcore::UnsignedDataSet| {
                let dutydb = Arc::clone(&dutydb);
                let tracker = Arc::clone(&tracker);
                tokio::spawn(async move {
                    let core_set =
                        match unsigneddata::unsigned_data_set_from_proto(&duty.duty_type, &value) {
                            Ok(set) => set,
                            Err(err) => {
                                tracing::warn!(?err, "dutydb: decode unsigned data set");
                                return;
                            }
                        };
                    let pubkeys: Vec<PubKey> = core_set.keys().copied().collect();
                    // Logged before the error moves into the tracker's `Arc`.
                    let step_err = match dutydb.store(duty.clone(), core_set).await {
                        Ok(()) => None,
                        Err(err) => {
                            tracing::warn!(?err, "dutydb: store");
                            Some(owned_step_err(err))
                        }
                    };
                    tracker.duty_db_stored(duty, &pubkeys, step_err).await;
                });
                Ok(())
            },
        ));
    }

    // ---- (8) ParSigDB ----
    let parsigdb = Arc::new(parsigdb::memory::MemDB::new(
        ct.clone(),
        threshold,
        parsigdb_deadliner,
    ));

    // Stitch: parsigdb.subscribe_internal(parsigex.broadcast).
    {
        let broadcast = Arc::clone(&parsigex.broadcast);
        let tracker = Arc::clone(&tracker);
        parsigdb
            .subscribe_internal(parsigdb::memory::internal_subscriber(
                move |duty: Duty, set: ParSignedDataSet| {
                    let broadcast = Arc::clone(&broadcast);
                    let tracker = Arc::clone(&tracker);
                    async move {
                        match broadcast(duty.clone(), set.clone()).await {
                            Ok(()) => {
                                tracker.par_sig_ex_broadcasted(duty, &set, None).await;
                                Ok(())
                            }
                            Err(err) => {
                                let (reported, returned) = share_step_err(err);
                                tracker
                                    .par_sig_ex_broadcasted(duty, &set, Some(reported))
                                    .await;
                                Err(
                                    parsigdb::memory::InternalSubscriberError::ParsigexBroadcast {
                                        source: Box::new(returned),
                                    }
                                    .into(),
                                )
                            }
                        }
                    }
                },
            ))
            .await;
    }

    // ---- (10) SigAgg (built before parsigdb.subscribe_threshold consumer) ----
    //
    // The production verifier (injected via `sigagg_verifier`) reconstructs the
    // group signature and verifies it against the beacon-node signing domain.
    let mut aggregator = Aggregator::new(threshold, sigagg_verifier).map_err(AppError::SigAgg)?;
    // Stitch: sigagg.subscribe(aggsigdb.store).
    //
    // SigAgg subscriber errors abort the whole aggregation, so downstream
    // store/broadcast failures are logged and swallowed (they are best-effort
    // sinks; in Charon they are wrapped in async-retry subscribers — part B).
    {
        let aggsigdb = aggsigdb.clone();
        let tracker = Arc::clone(&tracker);
        aggregator.subscribe(Arc::new(move |duty: &Duty, set: &SignedDataSet| {
            let aggsigdb = aggsigdb.clone();
            let tracker = Arc::clone(&tracker);
            let duty = duty.clone();
            let set = set.clone();
            Box::pin(async move {
                let pubkeys: Vec<PubKey> = set.keys().copied().collect();
                let step_err = match aggsigdb.store(duty.clone(), set).await {
                    Ok(()) => None,
                    Err(err) => {
                        tracing::warn!(?err, "aggsigdb: store");
                        Some(owned_step_err(err))
                    }
                };
                tracker.agg_sig_db_stored(duty, &pubkeys, step_err).await;
                Ok(())
            })
        }));
    }
    // ---- (11) Broadcaster ----
    // Cloned before the move: the builder-registration submitter below needs
    // the same submission client (see its use for the rationale).
    let submission_api = submission_client.api().clone();
    let broadcaster = Arc::new(
        Broadcaster::new(submission_client)
            .await
            .map_err(AppError::Broadcaster)?,
    );
    // Stitch: sigagg.subscribe(broadcaster.broadcast).
    {
        let broadcaster = Arc::clone(&broadcaster);
        let tracker = Arc::clone(&tracker);
        let inclusion = Arc::clone(&inclusion_checker);
        aggregator.subscribe(Arc::new(move |duty: &Duty, set: &SignedDataSet| {
            let broadcaster = Arc::clone(&broadcaster);
            let tracker = Arc::clone(&tracker);
            let inclusion = Arc::clone(&inclusion);
            let duty = duty.clone();
            let set = set.clone();
            Box::pin(async move {
                let pubkeys: Vec<PubKey> = set.keys().copied().collect();

                // Register for inclusion checking before broadcasting, and even
                // if the broadcast fails: peers may still succeed, so the duty
                // can land on-chain regardless. Parity: charon
                // `core/tracking.go` `BroadcasterBroadcast`.
                if let Err(err) = inclusion.submitted(&duty, &set) {
                    tracing::error!(
                        ?err,
                        duty = %duty,
                        "Internal error: failed to submit duty to inclusion checker. \
                         This indicates a tracking bug that should be reported",
                    );
                }

                let step_err = match broadcaster.broadcast(duty.clone(), set).await {
                    Ok(()) => None,
                    Err(err) => {
                        tracing::warn!(?err, "broadcaster: broadcast");
                        Some(owned_step_err(err))
                    }
                };
                tracker
                    .broadcaster_broadcast(duty, &pubkeys, step_err)
                    .await;
                Ok(())
            })
        }));
    }
    let aggregator = Arc::new(aggregator);

    // Stitch: parsigdb.subscribe_threshold(sigagg.aggregate).
    //
    // `Aggregator::aggregate`'s future is `Send` but not `Sync`, while the
    // parsigdb threshold subscriber requires a `Send + Sync` future. Bridge by
    // spawning the aggregation and awaiting its `JoinHandle` (which is `Sync`).
    {
        let aggregator = Arc::clone(&aggregator);
        let tracker_agg = Arc::clone(&tracker);
        parsigdb
            .subscribe_threshold(parsigdb::memory::threshold_subscriber(
                move |duty: Duty, set: HashMap<PubKey, Vec<ParSignedData>>| {
                    let aggregator = Arc::clone(&aggregator);
                    let tracker = Arc::clone(&tracker_agg);
                    async move {
                        let pubkeys: Vec<PubKey> = set.keys().copied().collect();
                        let tracked = duty.clone();
                        let result =
                            tokio::spawn(async move { aggregator.aggregate(&duty, &set).await })
                                .await;
                        match result {
                            Ok(Ok(())) => {
                                tracker.sig_agg_aggregated(tracked, &pubkeys, None).await;
                                Ok(())
                            }
                            Ok(Err(e)) => {
                                let (reported, returned) = share_step_err(e);
                                tracker
                                    .sig_agg_aggregated(tracked, &pubkeys, Some(reported))
                                    .await;
                                Err(
                                    parsigdb::memory::InternalSubscriberError::ParsigexBroadcast {
                                        source: Box::new(returned),
                                    }
                                    .into(),
                                )
                            }
                            Err(e) => {
                                let (reported, returned) = share_step_err(e);
                                tracker
                                    .sig_agg_aggregated(tracked, &pubkeys, Some(reported))
                                    .await;
                                Err(
                                    parsigdb::memory::InternalSubscriberError::ParsigexBroadcast {
                                        source: Box::new(returned),
                                    }
                                    .into(),
                                )
                            }
                        }
                    }
                },
            ))
            .await;
    }

    // ---- (9) parsigex inbound subscription -> parsigdb.store_external ----
    {
        let parsigdb = Arc::clone(&parsigdb);
        let tracker_ext = Arc::clone(&tracker);
        let received: ParSigExReceived = Arc::new(move |duty: Duty, set: ParSignedDataSet| {
            let parsigdb = Arc::clone(&parsigdb);
            let tracker = Arc::clone(&tracker_ext);
            Box::pin(async move {
                let step_err = match parsigdb.store_external(&duty, &set).await {
                    Ok(()) => None,
                    Err(err) => {
                        tracing::warn!(?err, "parsigdb: store external");
                        Some(owned_step_err(err))
                    }
                };
                tracker
                    .par_sig_db_stored_external(duty, &set, step_err)
                    .await;
            })
        });
        (parsigex.subscribe)(received).await;
    }

    // ---- (12) Scheduler ----
    //
    // Built before the validator API so its handle can back
    // `register_get_duty_definition`. Stitches:
    // scheduler.subscribe_duty(fetcher.fetch) and
    // scheduler.subscribe_duty(consensus.participate), registered on the builder
    // before `.build()` (which blocks until chain start + sync).
    let mut sched_builder = SchedulerBuilder::new();
    {
        let fetcher = Arc::clone(&fetcher);
        let ct = ct.clone();
        let tracker = Arc::clone(&tracker);
        sched_builder.subscribe_duty(
            move |duty: &Duty, set: &pluto_core::types::DutyDefinitionSet| {
                let fetcher = Arc::clone(&fetcher);
                let ct = ct.clone();
                let tracker = Arc::clone(&tracker);
                let duty = duty.clone();
                let set = set.clone();
                async move {
                    let pubkeys: Vec<PubKey> = set.keys().copied().collect();
                    match fetcher.fetch(duty.clone(), set).await {
                        // In-flight fetches racing shutdown fail against already
                        // terminated components (e.g. the aggsigdb back-edge);
                        // don't surface those as duty errors.
                        Err(err) if ct.is_cancelled() => {
                            tracing::debug!(?err, "fetch aborted by shutdown");
                            Ok(())
                        }
                        Ok(()) => {
                            tracker.fetcher_fetched(duty, &pubkeys, None).await;
                            Ok(())
                        }
                        Err(err) => {
                            let (reported, returned) = share_step_err(err);
                            tracker
                                .fetcher_fetched(duty, &pubkeys, Some(reported))
                                .await;
                            // `subscribe_duty` is generic over the error type, so
                            // the shared wrapper propagates as-is.
                            Err(returned)
                        }
                    }
                }
            },
            "fetcher",
        );
    }
    {
        let consensus = Arc::clone(&consensus);
        let ct = ct.clone();
        let deadline_calc = Arc::clone(&deadline_calc);
        sched_builder.subscribe_duty(
            move |duty: &Duty, _set: &pluto_core::types::DutyDefinitionSet| {
                let consensus = Arc::clone(&consensus);
                let ct = ct.clone();
                let deadline_calc = Arc::clone(&deadline_calc);
                let duty = duty.clone();
                async move {
                    // Bound consensus by the duty deadline (see fetch stitch).
                    run_bounded_by_duty_deadline(
                        &deadline_calc,
                        &ct,
                        duty,
                        move |duty, dct| async move { consensus.participate(dct, duty).await },
                    )
                    .await
                }
            },
            "consensus",
        );
    }
    // Optional per-slot subscriber (simnet validator mock).
    if let Some(slot_tick) = slot_tick {
        sched_builder.subscribe_slot(move |slot: &Slot| slot_tick(slot), "simnet.vmock");
    }
    // Per-epoch infosync trigger, fired on each epoch's last slot. A failure is
    // logged by `subscribe_slot` and does not fail the node.
    if let Some(infosync) = infosync {
        let ct = ct.clone();
        sched_builder.subscribe_slot(
            move |slot: &Slot| {
                let infosync = Arc::clone(&infosync);
                let ct = ct.clone();
                let slot = slot.clone();
                async move {
                    if slot.last_in_epoch() {
                        infosync.trigger(ct.child_token(), slot.slot).await?;
                    }
                    Ok::<(), AppError>(())
                }
            },
            "infosync",
        );
    }
    // Slot subscriber: per-epoch validator cache trim + refresh (Charon's
    // `wireCoreWorkflow`).
    {
        let refresher = Arc::new(ValidatorCacheRefresher::new(validator_cache.clone()));
        sched_builder.subscribe_slot(
            move |slot: &Slot| {
                let refresher = Arc::clone(&refresher);
                let slot = slot.clone();
                async move { refresher.refresh(&slot).await }
            },
            "validator_cache",
        );
    }
    // Slot subscribers: builder registrations and their fee recipients, both
    // submitted straight to the beacon node once per epoch (Charon's
    // `submitValidatorRegistrationsDelayed` and `setFeeRecipient`).
    //
    // Registrations do NOT go through the duty workflow: the lock already
    // carries a group-signed registration per validator, so there is nothing
    // to reach consensus on. Routing them through it would also deadlock a
    // mixed cluster, where Charon peers never contribute a partial signature.
    // Submitted once at startup (below, after the scheduler has waited for
    // chain start and beacon-node sync) so a restart does not go a full epoch
    // unregistered.
    let mut startup_submitter = None;
    if let Some(service) = builder_registrations.clone() {
        if builder_enabled {
            // Use the *submission* client, not the scheduling one. Beacon
            // nodes proxy `register_validator` to the builder relay and
            // routinely take seconds to answer, so it belongs under
            // `--beacon-node-submit-timeout` like every other submission;
            // the shorter general timeout would abort before the beacon node
            // replies and hide the real error.
            let submitter = RegistrationSubmitter::new(service.clone(), submission_api.clone());
            startup_submitter = Some(submitter.clone());
            sched_builder.subscribe_slot(
                move |slot: &Slot| {
                    let submitter = submitter.clone();
                    let slot = slot.clone();
                    async move {
                        if !slot.first_in_epoch() {
                            return Ok::<(), AppError>(());
                        }
                        // Charon delays to 75% into the slot so the burst does
                        // not collide with the epoch boundary's duty fetches.
                        let delay = slot.slot_duration.num_milliseconds().saturating_mul(3) / 4;
                        tokio::time::sleep(std::time::Duration::from_millis(
                            u64::try_from(delay).unwrap_or(0),
                        ))
                        .await;
                        let _ = submitter.submit(slot.epoch()).await;
                        Ok(())
                    }
                },
                "builder_registration",
            );
        }

        let indices_cache = validator_cache.clone();
        let eth2_cl_preps = submission_api.clone();
        // Mirror Charon's `setFeeRecipient` onStartup flag (app/app.go): the
        // first tick submits proposal preparations regardless of epoch
        // position, then only on epoch boundaries. Preparations expire after
        // three epochs and are seeded nowhere else, so a node that starts
        // mid-epoch would otherwise leave the beacon node with no fee-recipient
        // preparation until the next boundary — up to a full epoch during which
        // a locally-produced block pays the beacon node's default address.
        let preps_on_startup = Arc::new(std::sync::atomic::AtomicBool::new(true));
        sched_builder.subscribe_slot(
            move |slot: &Slot| {
                let service = service.clone();
                let cache = indices_cache.clone();
                let eth2_cl = eth2_cl_preps.clone();
                let slot = slot.clone();
                let on_startup = preps_on_startup.clone();
                async move {
                    // Either the first slot in the epoch or the first tick
                    // after startup; the startup flag is consumed even when the
                    // submission below fails, matching Charon (the next epoch
                    // boundary retries).
                    let startup = on_startup.swap(false, std::sync::atomic::Ordering::Relaxed);
                    if !startup && !slot.first_in_epoch() {
                        return Ok::<(), ValidatorCacheError>(());
                    }
                    let (active, ..) = cache.get_by_slot(slot.slot.inner()).await?;
                    let indices: HashMap<PubKey, u64> = active
                        .iter()
                        .map(|(index, pubkey)| (PubKey::new(*pubkey), *index))
                        .collect();

                    if let Err(err) =
                        submit_proposal_preparations(&service, &eth2_cl, &indices).await
                    {
                        // Preparations expire after three epochs, so a single
                        // failed push is recoverable at the next boundary.
                        tracing::warn!(%err, "Failed to submit proposal preparations");
                    }
                    Ok(())
                }
            },
            "proposal_preparations",
        );
    }

    let (scheduler, scheduler_task) = sched_builder
        .build(beacon_client, ct.clone())
        .await
        .map_err(AppError::Scheduler)?;

    // `build` has waited for chain start and beacon-node sync, so the beacon
    // node is reachable — Charon submits its startup registrations at the same
    // point. Epoch 0 is the sentinel Charon uses: the next `first_in_epoch`
    // tick submits again for the real epoch.
    if let Some(submitter) = startup_submitter {
        tokio::spawn(async move {
            if let Err(err) = submitter.submit(0).await {
                // Not fatal: the next epoch boundary retries, because the
                // epoch is only recorded on success.
                tracing::warn!(%err, "Initial validator registration submission failed");
            }
        });
    }

    // ---- (13) ValidatorAPI ----
    //
    // The `Component` holds `dutydb` directly; `await_proposal` falls back to it
    // when unregistered. The awaits with no fallback are registered here: the
    // agg-sig-db await (back-edge into `aggsigdb.wait_for`), the dutydb-backed
    // agg-attestation / sync-contribution / pubkey-by-attestation lookups, and
    // the scheduler-backed duty-definition lookup.
    let mut vapi = Component::new(
        Arc::new(eth2_cl.clone()),
        Arc::clone(&dutydb),
        share_idx,
        pub_share_by_pubkey,
        Arc::new(validator_cache),
    );
    // Back-edge: vapi.register_await_agg_sig_db(aggsigdb.wait_for).
    {
        let aggsigdb = aggsigdb.clone();
        vapi.register_await_agg_sig_db(move |duty: Duty, pubkey: PubKey| {
            let aggsigdb = aggsigdb.clone();
            async move { aggsigdb.wait_for(duty, pubkey).await.map_err(Into::into) }
        });
    }
    // dutydb-backed aggregate-attestation lookup (awaited by attestation root;
    // the VC-supplied slot is unused by the dutydb).
    {
        let dutydb = Arc::clone(&dutydb);
        vapi.register_await_agg_attestation(move |_slot: u64, root| {
            let dutydb = Arc::clone(&dutydb);
            async move {
                dutydb
                    .await_agg_attestation(root)
                    .await
                    .map(VersionedAggregatedAttestation)
                    .map_err(Into::into)
            }
        });
    }
    // dutydb-backed sync-contribution lookup.
    {
        let dutydb = Arc::clone(&dutydb);
        vapi.register_await_sync_contribution(move |slot: u64, subcomm: u64, root| {
            let dutydb = Arc::clone(&dutydb);
            async move {
                dutydb
                    .await_sync_contribution(slot, subcomm, root)
                    .await
                    .map(SyncContribution)
                    .map_err(Into::into)
            }
        });
    }
    // dutydb-backed pubkey-by-attestation lookup.
    {
        let dutydb = Arc::clone(&dutydb);
        vapi.register_pub_key_by_attestation(move |slot: u64, comm: u64, val: u64| {
            let dutydb = Arc::clone(&dutydb);
            async move {
                dutydb
                    .pub_key_by_attestation(slot, comm, val)
                    .await
                    .map_err(Into::into)
            }
        });
    }
    // scheduler-backed duty-definition lookup. The result is type-erased for the
    // validatorapi callback boundary and downcast to `DutyDefinitionSet` by the
    // component.
    {
        let scheduler = scheduler.clone();
        vapi.register_get_duty_definition(move |duty: Duty| {
            let scheduler = scheduler.clone();
            async move {
                scheduler
                    .get_duty_definition(duty)
                    .await
                    .map(|set| Box::new(set) as Box<dyn std::any::Any + Send + Sync>)
                    .map_err(Into::into)
            }
        });
    }
    // Stitch: vapi.subscribe(parsigdb.store_internal).
    {
        let parsigdb = Arc::clone(&parsigdb);
        let tracker = Arc::clone(&tracker);
        vapi.subscribe(move |duty: Duty, set: ParSignedDataSet| {
            let parsigdb = Arc::clone(&parsigdb);
            let tracker = Arc::clone(&tracker);
            async move {
                match parsigdb.store_internal(&duty, &set).await {
                    Ok(()) => {
                        tracker.par_sig_db_stored_internal(duty, &set, None).await;
                        Ok(())
                    }
                    Err(err) => {
                        let (reported, returned) = share_step_err(err);
                        tracker
                            .par_sig_db_stored_internal(duty, &set, Some(reported))
                            .await;
                        Err(returned.into())
                    }
                }
            }
        });
    }

    // Feed the monitoring readiness checker the pubkeys the VC references.
    if let Some(observer) = seen_pubkeys {
        vapi.register_seen_pubkeys(observer);
    }

    let validator_api_router = validatorapi::new_router(
        Arc::new(vapi) as Arc<dyn Handler>,
        builder_enabled,
        upstream_url,
    );

    Ok(WiredComponents {
        scheduler_task,
        dutydb,
        parsigdb,
        parsigdb_deadliner_rx,
        aggsigdb,
        fetcher,
        inclusion_checker,
        validator_api_router,
    })
}

/// Runs `f` under a child of `parent_ct` that is *also* cancelled at
/// `deadline`.
///
/// Consensus `Propose`/`Participate` are bounded by the duty deadline, so an
/// instance that cannot decide has its context cancelled at the deadline (→
/// `Error::ConsensusTimeout`) instead of running until component shutdown. A
/// `None` deadline leaves the call bounded only by `parent_ct` (component
/// lifetime).
async fn bounded_by_deadline<Fut>(
    parent_ct: &CancellationToken,
    deadline: Option<chrono::DateTime<chrono::Utc>>,
    f: impl FnOnce(CancellationToken) -> Fut,
) -> Fut::Output
where
    Fut: std::future::Future,
{
    let child = parent_ct.child_token();
    // Cancel the child when we return, so the timer task exits promptly on the
    // decided (happy) path — not only when the deadline elapses.
    let _guard = child.clone().drop_guard();

    if let Some(deadline) = deadline {
        let until = deadline
            .signed_duration_since(chrono::Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        let timer_ct = child.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(until) => timer_ct.cancel(),
                () = timer_ct.cancelled() => {}
            }
        });
    }

    f(child).await
}

/// Failure driving a duty's consensus instance: either the deadline could not
/// be computed or the consensus round itself failed.
#[derive(Debug, thiserror::Error)]
enum DutyConsensusError {
    #[error(transparent)]
    Deadline(#[from] pluto_core::deadline::DeadlineError),
    #[error(transparent)]
    Consensus(#[from] pluto_consensus::wrapper::Error),
}

/// Runs `run_consensus` for `duty`, bounded by the duty's deadline.
///
/// A deadline-calculator error is surfaced rather than silently downgraded to
/// "no deadline"; otherwise a failing calculator would leave the QBFT instance
/// bounded only by component lifetime instead of the intended deadline.
async fn run_bounded_by_duty_deadline<F, Fut>(
    deadline_calc: &Arc<dyn DeadlineCalculator>,
    ct: &CancellationToken,
    duty: Duty,
    run_consensus: F,
) -> Result<(), DutyConsensusError>
where
    F: FnOnce(Duty, CancellationToken) -> Fut,
    Fut: std::future::Future<Output = pluto_consensus::wrapper::Result<()>>,
{
    let deadline = deadline_calc.deadline(&duty)?;
    bounded_by_deadline(ct, deadline, move |dct| run_consensus(duty, dct)).await?;
    Ok(())
}

#[cfg(test)]
mod deadline_bound_tests {
    use super::*;

    // A deadline at/before now cancels the child context promptly, so a bounded
    // consensus call returns instead of running until shutdown.
    #[tokio::test]
    async fn bounded_by_deadline_past_deadline_cancels() {
        let parent = CancellationToken::new();
        let now = chrono::Utc::now();
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            bounded_by_deadline(&parent, Some(now), |child| async move {
                child.cancelled().await;
                "cancelled"
            }),
        )
        .await
        .expect("child should cancel at the (elapsed) deadline");
        assert_eq!(out, "cancelled");
    }

    // With no deadline the child is bound only by the parent token.
    #[tokio::test]
    async fn bounded_by_deadline_none_follows_parent() {
        let parent = CancellationToken::new();
        parent.cancel();
        bounded_by_deadline(&parent, None, |child| async move {
            // Child of an already-cancelled parent is cancelled immediately.
            child.cancelled().await;
        })
        .await;
    }

    // A deadline-calculator error must surface and must skip consensus entirely
    // (previously the error was swallowed as "no deadline", leaving the QBFT
    // instance bounded only by component lifetime).
    #[tokio::test]
    async fn duty_deadline_error_surfaces_and_skips_consensus() {
        use std::sync::atomic::{AtomicBool, Ordering};

        use pluto_core::{
            deadline::{DeadlineError, Result as DeadlineResult},
            types::{DutyType, SlotNumber},
        };

        struct FailingCalc;
        impl DeadlineCalculator for FailingCalc {
            fn deadline(
                &self,
                _duty: &Duty,
            ) -> DeadlineResult<Option<chrono::DateTime<chrono::Utc>>> {
                Err(DeadlineError::ArithmeticOverflow)
            }
        }

        let calc: Arc<dyn DeadlineCalculator> = Arc::new(FailingCalc);
        let ct = CancellationToken::new();
        let duty = Duty {
            slot: SlotNumber::new(1),
            duty_type: DutyType::Attester,
        };
        let ran = Arc::new(AtomicBool::new(false));
        let ran_probe = Arc::clone(&ran);

        let result = run_bounded_by_duty_deadline(&calc, &ct, duty, move |_duty, _dct| {
            let ran_probe = Arc::clone(&ran_probe);
            async move {
                ran_probe.store(true, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;

        assert!(result.is_err(), "calculator error must surface");
        assert!(
            !ran.load(Ordering::SeqCst),
            "consensus must not run when the deadline calculation fails"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_core::types::SlotNumber;
    use pluto_eth2api::{
        BlindedBlock400Response, GetStateValidatorsResponseResponse,
        GetStateValidatorsResponseResponseDatum, ValidatorResponseValidator, ValidatorStatus,
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const FAR_FUTURE_EPOCH: &str = "18446744073709551615";

    fn test_pubkey(seed: u8) -> BLSPubKey {
        let mut bytes = [0u8; 48];
        bytes[0] = seed;
        bytes
    }

    fn format_pubkey(pubkey: &BLSPubKey) -> String {
        format!("0x{}", hex::encode(pubkey))
    }

    fn test_datum(
        index: u64,
        pubkey: &BLSPubKey,
        status: ValidatorStatus,
    ) -> GetStateValidatorsResponseResponseDatum {
        GetStateValidatorsResponseResponseDatum {
            index: index.to_string(),
            balance: "32000000000".to_string(),
            status,
            validator: ValidatorResponseValidator {
                pubkey: format_pubkey(pubkey),
                withdrawal_credentials:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                effective_balance: "32000000000".to_string(),
                slashed: false,
                activation_eligibility_epoch: "0".to_string(),
                activation_epoch: "0".to_string(),
                exit_epoch: FAR_FUTURE_EPOCH.to_string(),
                withdrawable_epoch: FAR_FUTURE_EPOCH.to_string(),
            },
        }
    }

    /// An unmounted `POST /states/{state_id}/validators` mock returning `data`.
    fn post_validators_ok(
        state_id: impl AsRef<str>,
        data: Vec<GetStateValidatorsResponseResponseDatum>,
    ) -> Mock {
        Mock::given(method("POST"))
            .and(path(format!(
                "/eth/v1/beacon/states/{}/validators",
                state_id.as_ref()
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                GetStateValidatorsResponseResponse {
                    execution_optimistic: false,
                    finalized: true,
                    data,
                },
            ))
    }

    /// An unmounted `POST /states/{state_id}/validators` mock returning 404, so
    /// `get_by_slot` falls back to the head state.
    fn post_validators_not_found(state_id: impl AsRef<str>) -> Mock {
        Mock::given(method("POST"))
            .and(path(format!(
                "/eth/v1/beacon/states/{}/validators",
                state_id.as_ref()
            )))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(BlindedBlock400Response {
                    code: 404.0,
                    message: "State not found".to_string(),
                    stacktraces: None,
                }),
            )
    }

    fn test_cache(server: &MockServer, pubkeys: Vec<BLSPubKey>) -> ValidatorCache {
        let client =
            EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid mock server URL");
        ValidatorCache::new(client, pubkeys)
    }

    /// A [`Slot`]. Only `slot`/`slots_per_epoch` matter to the refresher;
    /// `time` and `slot_duration` are placeholders.
    fn test_slot(slot: u64, slots_per_epoch: u64) -> Slot {
        Slot {
            slot: SlotNumber::new(slot),
            time: chrono::Utc::now(),
            slot_duration: chrono::Duration::seconds(12),
            slots_per_epoch,
        }
    }

    const SPE: u64 = 32;

    /// A validator that is inactive at startup and activates later is picked up
    /// on the next epoch's first slot.
    #[tokio::test]
    async fn refresh_observes_validator_activated_after_startup() {
        let pk = test_pubkey(5);
        let mock = MockServer::start().await;
        // Startup epoch: still pending (not active).
        post_validators_ok(
            "0",
            vec![test_datum(5, &pk, ValidatorStatus::PendingQueued)],
        )
        .mount(&mock)
        .await;
        // Next epoch: activated.
        post_validators_ok(
            "32",
            vec![test_datum(5, &pk, ValidatorStatus::ActiveOngoing)],
        )
        .mount(&mock)
        .await;

        let cache = test_cache(&mock, vec![pk]);
        let refresher = ValidatorCacheRefresher::new(cache.clone());

        // First tick (epoch 0, first slot): fetches slot 0 — validator inactive.
        refresher
            .refresh(&test_slot(0, SPE))
            .await
            .expect("refresh slot 0");
        let (active, _) = cache.get_by_head().await.expect("read cache");
        assert!(
            active.is_empty(),
            "validator should be inactive at startup, got {active:?}"
        );

        // Next epoch's first slot: fetches slot 32 — validator now active.
        refresher
            .refresh(&test_slot(SPE, SPE))
            .await
            .expect("refresh slot 32");
        let (active, _) = cache.get_by_head().await.expect("read cache");
        assert_eq!(
            active.len(),
            1,
            "activated validator should now be resolved"
        );
        assert!(active.contains_key(&5));
    }

    /// A validator that exits stops being resolved after the next epoch tick.
    #[tokio::test]
    async fn refresh_stops_resolving_exited_validator() {
        let pk = test_pubkey(5);
        let mock = MockServer::start().await;
        post_validators_ok(
            "0",
            vec![test_datum(5, &pk, ValidatorStatus::ActiveOngoing)],
        )
        .mount(&mock)
        .await;
        post_validators_ok(
            "32",
            vec![test_datum(5, &pk, ValidatorStatus::ExitedUnslashed)],
        )
        .mount(&mock)
        .await;

        let cache = test_cache(&mock, vec![pk]);
        let refresher = ValidatorCacheRefresher::new(cache.clone());

        refresher
            .refresh(&test_slot(0, SPE))
            .await
            .expect("refresh slot 0");
        let (active, _) = cache.get_by_head().await.expect("read cache");
        assert_eq!(active.len(), 1, "validator active at startup");

        refresher
            .refresh(&test_slot(SPE, SPE))
            .await
            .expect("refresh slot 32");
        let (active, _) = cache.get_by_head().await.expect("read cache");
        assert!(
            active.is_empty(),
            "exited validator should no longer be resolved, got {active:?}"
        );
    }

    /// Once refreshed by slot, mid-epoch ticks are skipped
    /// (`shouldUpdateCache`): slot 0 is fetched exactly once and no
    /// mid-epoch re-fetch is issued.
    #[tokio::test]
    async fn refresh_skips_mid_epoch_slot_once_refreshed_by_slot() {
        let pk = test_pubkey(5);
        let mock = MockServer::start().await;
        // Only slot 0 is served, and it must be hit exactly once. Slot 1 is left
        // unmounted: any mid-epoch fetch would 404 → head fallback → error.
        post_validators_ok(
            "0",
            vec![test_datum(5, &pk, ValidatorStatus::ActiveOngoing)],
        )
        .expect(1)
        .mount(&mock)
        .await;

        let cache = test_cache(&mock, vec![pk]);
        let refresher = ValidatorCacheRefresher::new(cache.clone());

        refresher
            .refresh(&test_slot(0, SPE))
            .await
            .expect("refresh slot 0");

        // Mid-epoch tick: skipped, so it returns Ok without any fetch and the
        // cache is untouched.
        refresher
            .refresh(&test_slot(1, SPE))
            .await
            .expect("mid-epoch refresh is a skipped no-op");

        let (active, _) = cache.get_by_head().await.expect("read cache");
        assert_eq!(active.len(), 1, "cache retained the slot-0 set");
    }

    /// After a head fallback (`refresh_by_slot == false`), the next tick is
    /// forced to refresh even mid-epoch, and it re-fetches the epoch's first
    /// slot rather than the current slot.
    #[tokio::test]
    async fn refresh_refetches_epoch_first_slot_after_head_fallback() {
        let pk = test_pubkey(1);
        let mock = MockServer::start().await;
        // First tick is at mid-epoch slot 5, fetched by slot; it 404s and falls
        // back to head, which reports the validator as still pending.
        post_validators_not_found("5").mount(&mock).await;
        post_validators_ok(
            "head",
            vec![test_datum(1, &pk, ValidatorStatus::PendingQueued)],
        )
        .mount(&mock)
        .await;
        // The epoch's first slot (0) reports the validator active. Slot 6 (the
        // current slot on the second tick) is deliberately left unmounted: were
        // it fetched, it would 404 → head → empty active set, failing the assert.
        post_validators_ok(
            "0",
            vec![test_datum(1, &pk, ValidatorStatus::ActiveOngoing)],
        )
        .mount(&mock)
        .await;

        let cache = test_cache(&mock, vec![pk]);
        let refresher = ValidatorCacheRefresher::new(cache.clone());

        // First tick at slot 5: get_by_slot(5) 404s → head fallback (pending).
        refresher
            .refresh(&test_slot(5, SPE))
            .await
            .expect("refresh slot 5 via head fallback");
        let (active, _) = cache.get_by_head().await.expect("read cache");
        assert!(
            active.is_empty(),
            "head fallback reported pending validator"
        );

        // Second tick at mid-epoch slot 6: forced to refresh because the prior
        // refresh fell back to head, and it fetches epoch-first slot 0 (active),
        // not slot 6.
        refresher
            .refresh(&test_slot(6, SPE))
            .await
            .expect("refresh slot 6 refetches epoch-first slot");
        let (active, _) = cache.get_by_head().await.expect("read cache");
        assert_eq!(
            active.len(),
            1,
            "refetched the epoch's first slot (0), where the validator is active"
        );
        assert!(active.contains_key(&1));
    }

    fn feature_set(enabled: Vec<Feature>) -> Arc<FeatureSet> {
        Arc::new(
            FeatureSet::from_config(pluto_featureset::Config {
                enabled,
                ..Default::default()
            })
            .expect("valid featureset"),
        )
    }

    /// `AttestationInclusion` is masked off for the tracker so the
    /// proposer-only inclusion checker is never fed attester/aggregator
    /// submissions.
    #[test]
    fn tracker_feature_set_masks_attestation_inclusion() {
        let fs = feature_set(vec![Feature::AttestationInclusion]);
        assert!(fs.enabled(Feature::AttestationInclusion));

        let tracker_fs = tracker_feature_set(&fs);
        assert!(!tracker_fs.enabled(Feature::AttestationInclusion));
    }

    /// Without the feature the set is passed through untouched (same `Arc`).
    #[test]
    fn tracker_feature_set_is_passthrough_when_disabled() {
        let fs = feature_set(vec![]);
        let tracker_fs = tracker_feature_set(&fs);
        assert!(Arc::ptr_eq(&fs, &tracker_fs));
    }
}
