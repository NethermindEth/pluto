//! Core duty-workflow construction and wiring.
//!
//! This is the Rust analog of Charon's `wireCoreWorkflow` (`app/app.go:399`)
//! and `core.Wire` (`core/interfaces.go:283`). It constructs the ten core duty
//! workflow components and connects them into the data-flow graph that drives a
//! single distributed-validator node.
//!
//! The construction order builds back-edge targets before their consumers (see
//! [`wire_core_workflow`]), and — unlike Charon's split between a `wireFuncs`
//! struct and the `Wire` call — Pluto interleaves construction and wiring
//! because of its builder/service split:
//!
//! * scheduler subscribers are registered on the *builder* before `.build()`;
//! * the fetcher's back-edges and subscribers are bon-builder fields;
//! * consensus / parsigdb / sigagg subscribers are registered on the *service*.
//!
//! To mirror Charon's `Run` (loads) vs `wireCoreWorkflow` (wires) split — and
//! Charon's `TestConfig.ParSigExFunc` injection — this function takes
//! already-resolved inputs ([`WireInputs`]) and a [`ParSigExSeam`] for the
//! partial-signature exchange, so tests can inject a `BeaconMock` and an
//! in-memory (loopback) parsigex without a real libp2p swarm.

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
    scheduler::{SchedulerBuilder, SchedulerHandle},
    sigagg::{Aggregator, VerifyFn},
    signeddata::{SyncContribution, VersionedAggregatedAttestation},
    types::{Duty, ParSignedData, ParSignedDataSet, PubKey, SignedData, SignedDataSet},
    unsigneddata::{self, UnsignedDataSet},
    validatorapi::{self, Component, Handler},
};
use pluto_eth2api::{
    BeaconNodeClient, EthBeaconNodeApiClient,
    spec::{bellatrix::ExecutionAddress, phase0::BLSPubKey},
    valcache::ValidatorCache,
};
use tokio_util::sync::CancellationToken;

use crate::node::AppError;

/// Boxed std error used by the various callback seams.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

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
/// Mirrors Charon's `TestConfig.ParSigExFunc`: the production path supplies a
/// real `parsigex::Handle` (outbound broadcast) plus an inbound subscription;
/// tests supply a loopback so partial signatures cross the threshold locally.
pub struct ParSigExSeam {
    /// Outbound broadcast, wired into `parsigdb.subscribe_internal`.
    pub broadcast: ParSigExBroadcast,
    /// Registers the inbound subscriber (received sets -> `store_external`).
    /// A loopback test may wire `broadcast` straight back into the subscriber.
    pub subscribe: ParSigExSubscribe,
}

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
/// These mirror what Charon's `wireCoreWorkflow` derives from the cluster
/// manifest + config, but are passed in so that file-loading and P2P setup
/// (in `run`) stay separate from construction-and-wiring (here) — enabling the
/// Tier 1 test to inject a `BeaconMock` and in-memory parsigex.
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
    /// exercise the wiring without real BLS test vectors (mirrors Charon's
    /// `TestConfig`).
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
}

/// The wired components and long-lived handles produced by
/// [`wire_core_workflow`], returned so the caller (`run`) can drive their
/// background tasks and shut them down in order.
pub struct WiredComponents {
    /// Scheduler handle (self-driving; also queried by the validator API).
    pub scheduler: SchedulerHandle,
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

/// Boxes any error into [`BoxError`].
fn box_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> BoxError {
    Box::new(e)
}

/// Constructs and wires the ten core duty-workflow components.
///
/// Reproduces the data-flow graph from `core/interfaces.go:337-357`. The 13
/// stitches and 3 deadlock-critical back-edges are annotated inline.
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
    } = inputs;

    // ---- Derived validator maps (mirrors app.go:407-452) ----
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
    // resolves the same cluster validator set. Charon seeds a single cache
    // into both clients (app.go:481-482 and app.go:598); without seeding, the
    // scheduler would resolve duties against an empty (or unfiltered) set.
    // `ValidatorCache` clones share state; the per-epoch trim + refresh
    // subscriber is a planned follow-up.
    let validator_cache = ValidatorCache::new(eth2_cl.clone(), eth2_pubkeys);
    beacon_client
        .set_validator_cache(validator_cache.clone())
        .await;
    submission_client
        .set_validator_cache(validator_cache.clone())
        .await;

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
                let signed: Box<dyn SignedData> =
                    aggsigdb.wait_for(duty, pubkey).await.map_err(box_err)?;
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
                let data = dutydb
                    .await_attestation(slot, comm_idx)
                    .await
                    .map_err(box_err)?;
                Ok(data)
            })
        })
    };
    // Stitch: fetcher.subscribe(consensus.propose).
    let fetch_subscriber: Subscriber = {
        let consensus = Arc::clone(&consensus);
        let ct = ct.clone();
        Arc::new(move |duty: Duty, set: UnsignedDataSet| {
            let consensus = Arc::clone(&consensus);
            let ct = ct.clone();
            Box::pin(async move {
                let value = unsigneddata::unsigned_data_set_to_proto(&set).map_err(box_err)?;
                consensus.propose(duty, value, &ct).await.map_err(box_err)?;
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
    // group signature and verifies it against the beacon-node signing domain
    // (Charon `sigagg.NewVerifier`).
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
        sched_builder.subscribe_duty(
            move |duty: &Duty, set: &pluto_core::types::DutyDefinitionSet| {
                let fetcher = Arc::clone(&fetcher);
                let duty = duty.clone();
                let set = set.clone();
                async move { fetcher.fetch(duty, set).await }
            },
            "fetcher",
        );
    }
    {
        let consensus = Arc::clone(&consensus);
        let ct = ct.clone();
        sched_builder.subscribe_duty(
            move |duty: &Duty, _set: &pluto_core::types::DutyDefinitionSet| {
                let consensus = Arc::clone(&consensus);
                let ct = ct.clone();
                let duty = duty.clone();
                async move { consensus.participate(duty, &ct).await }
            },
            "consensus",
        );
    }
    let scheduler = sched_builder
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
            async move { aggsigdb.wait_for(duty, pubkey).await.map_err(box_err) }
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
                    .map_err(box_err)
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
                    .map_err(box_err)
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
                    .map_err(box_err)
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
                    .map_err(box_err)
            }
        });
    }
    // Stitch: vapi.subscribe(parsigdb.store_internal).
    {
        let parsigdb = Arc::clone(&parsigdb);
        vapi.subscribe(move |duty: Duty, set: ParSignedDataSet| {
            let parsigdb = Arc::clone(&parsigdb);
            async move { parsigdb.store_internal(&duty, &set).await.map_err(box_err) }
        });
    }

    let validator_api_router = validatorapi::new_router(
        Arc::new(vapi) as Arc<dyn Handler>,
        builder_enabled,
        upstream_url,
    );

    Ok(WiredComponents {
        scheduler,
        dutydb,
        parsigdb,
        parsigdb_deadliner_rx,
        aggsigdb,
        fetcher,
        validator_api_router,
    })
}
