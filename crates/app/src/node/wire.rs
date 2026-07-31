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
use pluto_consensus::qbft;
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
    types::{Duty, ParSignedData, ParSignedDataSet, PubKey, SignedData, SignedDataSet, Slot},
    unsigneddata::{self, UnsignedDataSet},
    validatorapi::{self, Component, Handler, SeenPubkeysFn},
};
use pluto_eth2api::{
    BeaconNodeClient, EthBeaconNodeApiClient,
    spec::{bellatrix::ExecutionAddress, phase0::BLSPubKey},
    valcache::{ValidatorCache, ValidatorCacheError},
};
use tokio_util::sync::CancellationToken;

use crate::node::AppError;

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
    /// Already-constructed consensus component, also wired into the QBFT p2p
    /// behaviour by the caller.
    pub consensus: Arc<qbft::Consensus>,
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
    /// Optional infosync component. When `Some`, it is triggered on the last
    /// slot of each epoch to run the cluster-wide priority exchange (supported
    /// versions/protocols/proposal types) for the next epoch. `None` in tests.
    pub infosync: Option<Arc<pluto_infosync::Component>>,
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
        infosync,
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

    let fee_recipient_fn: FeeRecipientFunc = {
        let map = fee_recipient_by_pubkey.clone();
        Arc::new(move |pubkey: &PubKey| map.get(pubkey).copied().unwrap_or_default())
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
        Arc::new(move |duty: Duty, set: UnsignedDataSet| {
            let consensus = Arc::clone(&consensus);
            let ct = ct.clone();
            let deadline_calc = Arc::clone(&deadline_calc);
            Box::pin(async move {
                let value = unsigneddata::unsigned_data_set_to_proto(&set)?;
                // Bound consensus by the duty deadline so a stuck instance is
                // cancelled (-> ConsensusTimeout) instead of running until shutdown.
                run_bounded_by_duty_deadline(
                    &deadline_calc,
                    &ct,
                    duty,
                    move |duty, dct| async move { consensus.propose(duty, value, &dct).await },
                )
                .await?;
                Ok(())
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
        consensus.subscribe(move |duty: Duty, value: pbcore::UnsignedDataSet| {
            let dutydb = Arc::clone(&dutydb);
            tokio::spawn(async move {
                let core_set =
                    match unsigneddata::unsigned_data_set_from_proto(&duty.duty_type, &value) {
                        Ok(set) => set,
                        Err(err) => {
                            tracing::warn!(?err, "dutydb: decode unsigned data set");
                            return;
                        }
                    };
                if let Err(err) = dutydb.store(duty, core_set).await {
                    tracing::warn!(?err, "dutydb: store");
                }
            });
            Ok(())
        });
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
        parsigdb
            .subscribe_internal(parsigdb::memory::internal_subscriber(
                move |duty: Duty, set: ParSignedDataSet| {
                    let broadcast = Arc::clone(&broadcast);
                    async move {
                        broadcast(duty, set).await.map_err(|e| {
                            parsigdb::memory::InternalSubscriberError::ParsigexBroadcast {
                                source: Box::new(e),
                            }
                            .into()
                        })
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
        aggregator.subscribe(Arc::new(move |duty: &Duty, set: &SignedDataSet| {
            let aggsigdb = aggsigdb.clone();
            let duty = duty.clone();
            let set = set.clone();
            Box::pin(async move {
                if let Err(err) = aggsigdb.store(duty, set).await {
                    tracing::warn!(?err, "aggsigdb: store");
                }
                Ok(())
            })
        }));
    }
    // ---- (11) Broadcaster ----
    let broadcaster = Arc::new(
        Broadcaster::new(submission_client)
            .await
            .map_err(AppError::Broadcaster)?,
    );
    // Stitch: sigagg.subscribe(broadcaster.broadcast).
    {
        let broadcaster = Arc::clone(&broadcaster);
        aggregator.subscribe(Arc::new(move |duty: &Duty, set: &SignedDataSet| {
            let broadcaster = Arc::clone(&broadcaster);
            let duty = duty.clone();
            let set = set.clone();
            Box::pin(async move {
                if let Err(err) = broadcaster.broadcast(duty, set).await {
                    tracing::warn!(?err, "broadcaster: broadcast");
                }
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
        parsigdb
            .subscribe_threshold(parsigdb::memory::threshold_subscriber(
                move |duty: Duty, set: HashMap<PubKey, Vec<ParSignedData>>| {
                    let aggregator = Arc::clone(&aggregator);
                    async move {
                        let result =
                            tokio::spawn(async move { aggregator.aggregate(&duty, &set).await })
                                .await;
                        match result {
                            Ok(Ok(())) => Ok(()),
                            Ok(Err(e)) => Err(
                                parsigdb::memory::InternalSubscriberError::ParsigexBroadcast {
                                    source: Box::new(e),
                                }
                                .into(),
                            ),
                            Err(e) => Err(
                                parsigdb::memory::InternalSubscriberError::ParsigexBroadcast {
                                    source: Box::new(e),
                                }
                                .into(),
                            ),
                        }
                    }
                },
            ))
            .await;
    }

    // ---- (9) parsigex inbound subscription -> parsigdb.store_external ----
    {
        let parsigdb = Arc::clone(&parsigdb);
        let received: ParSigExReceived = Arc::new(move |duty: Duty, set: ParSignedDataSet| {
            let parsigdb = Arc::clone(&parsigdb);
            Box::pin(async move {
                if let Err(err) = parsigdb.store_external(&duty, &set).await {
                    tracing::warn!(?err, "parsigdb: store external");
                }
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
        sched_builder.subscribe_duty(
            move |duty: &Duty, set: &pluto_core::types::DutyDefinitionSet| {
                let fetcher = Arc::clone(&fetcher);
                let ct = ct.clone();
                let duty = duty.clone();
                let set = set.clone();
                async move {
                    match fetcher.fetch(duty, set).await {
                        // In-flight fetches racing shutdown fail against already
                        // terminated components (e.g. the aggsigdb back-edge);
                        // don't surface those as duty errors.
                        Err(err) if ct.is_cancelled() => {
                            tracing::debug!(?err, "fetch aborted by shutdown");
                            Ok(())
                        }
                        res => res,
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
                        move |duty, dct| async move { consensus.participate(duty, &dct).await },
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
    // Per-epoch infosync trigger: on the last slot of each epoch, run the
    // cluster-wide priority exchange for the next epoch. A trigger failure is
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

    let (scheduler, scheduler_task) = sched_builder
        .build(beacon_client, ct.clone())
        .await
        .map_err(AppError::Scheduler)?;

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
        builder_enabled,
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
        vapi.subscribe(move |duty: Duty, set: ParSignedDataSet| {
            let parsigdb = Arc::clone(&parsigdb);
            async move {
                parsigdb
                    .store_internal(&duty, &set)
                    .await
                    .map_err(Into::into)
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
    Consensus(#[from] qbft::RunnerError),
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
    Fut: std::future::Future<Output = qbft::RunnerResult<()>>,
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
                Ok::<(), qbft::RunnerError>(())
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
}
