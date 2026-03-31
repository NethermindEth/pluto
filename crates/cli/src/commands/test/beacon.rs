//! Beacon node API tests.
//!
//! Connectivity, load, and simulation
//! tests against one or more beacon node endpoints.

use super::{
    TestConfigArgs,
    constants::{
        COMMITTEE_SIZE_PER_SLOT, EPOCH_TIME, SLOT_TIME, SLOT_TIME_SECS, SLOTS_IN_EPOCH,
        SUB_COMMITTEE_SIZE,
    },
    helpers::{
        AllCategoriesResult, CategoryScore, TestCaseName, TestCategory, TestCategoryResult,
        TestResult, TestResultError, TestVerdict, calculate_score, evaluate_highest_rtt,
        evaluate_rtt, filter_tests, must_output_to_file_on_quiet, publish_result_to_obol_api,
        request_rtt, sort_tests, write_result_to_file, write_result_to_writer,
    },
};
use crate::{duration::Duration, error::Result as CliResult};
use clap::Args;
use rand::Rng;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Write, path::PathBuf, time::Duration as StdDuration};
use tokio::{
    sync::mpsc,
    task::JoinSet,
    time::{Instant, interval, interval_at, sleep, sleep_until},
};
use tokio_util::sync::CancellationToken;

const THRESHOLD_BEACON_MEASURE_AVG: StdDuration = StdDuration::from_millis(40);
const THRESHOLD_BEACON_MEASURE_POOR: StdDuration = StdDuration::from_millis(100);
const THRESHOLD_BEACON_LOAD_AVG: StdDuration = StdDuration::from_millis(40);
const THRESHOLD_BEACON_LOAD_POOR: StdDuration = StdDuration::from_millis(100);
const THRESHOLD_BEACON_PEERS_AVG: u64 = 50;
const THRESHOLD_BEACON_PEERS_POOR: u64 = 20;
const THRESHOLD_BEACON_SIMULATION_AVG: StdDuration = StdDuration::from_millis(200);
const THRESHOLD_BEACON_SIMULATION_POOR: StdDuration = StdDuration::from_millis(400);

/// Arguments for the beacon test command.
#[derive(Args, Clone, Debug)]
pub struct TestBeaconArgs {
    #[command(flatten)]
    pub test_config: TestConfigArgs,

    /// Beacon node endpoint URLs.
    #[arg(
        long = "endpoints",
        value_delimiter = ',',
        required = true,
        help = "Comma separated list of one or more beacon node endpoint URLs."
    )]
    pub endpoints: Vec<String>,

    /// Enable load test, not advisable when testing towards external beacon
    /// nodes.
    #[arg(long = "load-test", help = "Enable load test.")]
    pub load_test: bool,

    /// Time to keep running the load tests.
    #[arg(
        long = "load-test-duration",
        default_value = "5s",
        value_parser = humantime::parse_duration,
        help = "Time to keep running the load tests. For each second a new continuous ping instance is spawned."
    )]
    pub load_test_duration: StdDuration,

    /// Simulation duration in slots.
    #[arg(
        long = "simulation-duration-in-slots",
        default_value_t = SLOTS_IN_EPOCH.get(),
        help = "Time to keep running the simulation in slots."
    )]
    pub simulation_duration: u64,

    /// Directory to write simulation result files.
    #[arg(
        long = "simulation-file-dir",
        default_value = "./",
        help = "Directory to write simulation result JSON files."
    )]
    pub simulation_file_dir: PathBuf,

    /// Show results for each request and each validator.
    #[arg(
        long = "simulation-verbose",
        help = "Show results for each request and each validator."
    )]
    pub simulation_verbose: bool,

    /// Run custom simulation with the specified amount of validators.
    #[arg(
        long = "simulation-custom",
        default_value_t = 0,
        help = "Run custom simulation with the specified amount of validators."
    )]
    pub simulation_custom: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimulationValues {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub endpoint: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub all: Vec<Duration>,
    pub min: Duration,
    pub max: Duration,
    pub median: Duration,
    pub avg: Duration,
}

#[derive(Debug, Clone, Copy)]
struct RequestsIntensity {
    attestation_duty: StdDuration,
    aggregator_duty: StdDuration,
    proposal_duty: StdDuration,
    sync_committee_submit: StdDuration,
    sync_committee_contribution: StdDuration,
    sync_committee_subscribe: StdDuration,
}

#[derive(Debug, Clone, Copy)]
struct DutiesPerformed {
    attestation: bool,
    aggregation: bool,
    proposal: bool,
    sync_committee: bool,
}

#[derive(Debug, Clone, Copy)]
struct SimParams {
    total_validators_count: u64,
    attestation_validators_count: u64, // attestation + aggregation
    proposal_validators_count: u64,    // attestation + aggregation + proposals
    sync_committee_validators_count: u64, // attestation + aggregation + proposals + sync committee
    request_intensity: RequestsIntensity,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Simulation {
    pub general_cluster_requests: SimulationCluster,
    pub validators_requests: SimulationValidators,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimulationValidators {
    pub averaged: SimulationSingleValidator,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub all_validators: Vec<SimulationSingleValidator>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimulationSingleValidator {
    #[serde(flatten)]
    pub values: SimulationValues,
    pub attestation_duty: SimulationAttestation,
    pub aggregation_duty: SimulationAggregation,
    pub proposal_duty: SimulationProposal,
    pub sync_committee_duties: SimulationSyncCommittee,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimulationAttestation {
    #[serde(flatten)]
    pub values: SimulationValues,
    pub get_attestation_data_request: SimulationValues,
    pub post_attestations_request: SimulationValues,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimulationAggregation {
    #[serde(flatten)]
    pub values: SimulationValues,
    pub get_aggregate_attestation_request: SimulationValues,
    pub post_aggregate_and_proofs_request: SimulationValues,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimulationProposal {
    #[serde(flatten)]
    pub values: SimulationValues,
    pub produce_block_request: SimulationValues,
    pub publish_blinded_block_request: SimulationValues,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimulationSyncCommittee {
    #[serde(flatten)]
    pub values: SimulationValues,
    pub message_duty: SyncCommitteeMessageDuty,
    pub contribution_duty: SyncCommitteeContributionDuty,
    pub subscribe_sync_committee_request: SimulationValues,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncCommitteeContributionDuty {
    #[serde(flatten)]
    pub values: SimulationValues,
    pub produce_sync_committee_contribution_request: SimulationValues,
    pub submit_sync_committee_contribution_request: SimulationValues,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncCommitteeMessageDuty {
    pub submit_sync_committee_message_request: SimulationValues,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimulationCluster {
    pub attestations_for_block_request: SimulationValues,
    pub proposal_duties_for_epoch_request: SimulationValues,
    pub syncing_request: SimulationValues,
    pub peer_count_request: SimulationValues,
    pub beacon_committee_subscription_request: SimulationValues,
    pub duties_attester_for_epoch_request: SimulationValues,
    pub duties_sync_committee_for_epoch_request: SimulationValues,
    pub beacon_head_validators_request: SimulationValues,
    pub beacon_genesis_request: SimulationValues,
    pub prep_beacon_proposer_request: SimulationValues,
    pub config_spec_request: SimulationValues,
    pub node_version_request: SimulationValues,
}

const SUPPORTED_BEACON_TEST_CASES: [TestCaseName; 12] = [
    TestCaseName::new("Ping", 1),
    TestCaseName::new("PingMeasure", 2),
    TestCaseName::new("Version", 3),
    TestCaseName::new("Synced", 4),
    TestCaseName::new("PeerCount", 5),
    TestCaseName::new("PingLoad", 6),
    TestCaseName::new("Simulate1", 7),
    TestCaseName::new("Simulate10", 8),
    TestCaseName::new("Simulate100", 9),
    TestCaseName::new("Simulate500", 10),
    TestCaseName::new("Simulate1000", 11),
    TestCaseName::new("SimulateCustom", 12),
];

pub fn test_case_names() -> Vec<String> {
    SUPPORTED_BEACON_TEST_CASES
        .iter()
        .map(|n| n.name.to_string())
        .collect()
}

async fn run_test_case(
    cancel: CancellationToken,
    cfg: TestBeaconArgs,
    target: impl AsRef<str>,
    name: impl AsRef<str>,
) -> TestResult {
    let target = target.as_ref();
    let name = name.as_ref();
    match name {
        "Ping" => beacon_ping_test(cancel, cfg, target).await,
        "PingMeasure" => beacon_ping_measure_test(cancel, cfg, target).await,
        "Version" => beacon_version_test(cancel, cfg, target).await,
        "Synced" => beacon_is_synced_test(cancel, cfg, target).await,
        "PeerCount" => beacon_peer_count_test(cancel, cfg, target).await,
        "PingLoad" => beacon_ping_load_test(cancel, cfg, target).await,
        "Simulate1" => beacon_simulation_1_test(cancel, cfg, target).await,
        "Simulate10" => beacon_simulation_10_test(cancel, cfg, target).await,
        "Simulate100" => beacon_simulation_100_test(cancel, cfg, target).await,
        "Simulate500" => beacon_simulation_500_test(cancel, cfg, target).await,
        "Simulate1000" => beacon_simulation_1000_test(cancel, cfg, target).await,
        "SimulateCustom" => beacon_simulation_custom_test(cancel, cfg, target).await,
        _ => TestResult::new(name).fail(TestResultError::from_string(format!(
            "unknown test case: {name}"
        ))),
    }
}

/// Runs the beacon node tests.
pub async fn run(
    args: TestBeaconArgs,
    writer: &mut dyn Write,
    shutdown: CancellationToken,
) -> CliResult<TestCategoryResult> {
    must_output_to_file_on_quiet(args.test_config.quiet, &args.test_config.output_json)?;

    tracing::info!("Starting beacon node test");

    let all_cases = SUPPORTED_BEACON_TEST_CASES;
    let mut queued = filter_tests(&all_cases, args.test_config.test_cases.as_deref());

    if queued.is_empty() {
        return Err(crate::error::CliError::Other(
            "test case not supported".into(),
        ));
    }
    sort_tests(&mut queued);

    cancel_after(&shutdown, args.test_config.timeout);

    let start = Instant::now();

    let mut set = JoinSet::new();

    for endpoint in &args.endpoints {
        let queued = queued.clone();
        let args = args.clone();
        let endpoint = endpoint.clone();
        let shutdown = shutdown.clone();

        set.spawn(async move {
            let results = test_single_beacon(&args, &queued, &endpoint, shutdown).await;
            (endpoint, results)
        });
    }

    let mut test_results: HashMap<String, Vec<TestResult>> = HashMap::new();
    while let Some(res) = set.join_next().await {
        let (target, results) = res.map_err(|e| crate::error::CliError::Other(e.to_string()))?;
        test_results.insert(target, results);
    }

    let exec_time = Duration::new(start.elapsed());

    let score = test_results
        .values()
        .map(|t| calculate_score(t))
        .min()
        .unwrap_or(CategoryScore::A);

    let res = TestCategoryResult {
        category_name: Some(TestCategory::Beacon),
        targets: test_results,
        execution_time: Some(exec_time),
        score: Some(score),
    };

    if !args.test_config.quiet {
        write_result_to_writer(&res, writer)?;
    }

    if !args.test_config.output_json.is_empty() {
        write_result_to_file(
            &res,
            &std::path::PathBuf::from(&args.test_config.output_json),
        )
        .await?;
    }

    if args.test_config.publish {
        let all = AllCategoriesResult {
            beacon: Some(res.clone()),
            ..Default::default()
        };
        publish_result_to_obol_api(
            all,
            &args.test_config.publish_addr,
            &args.test_config.publish_private_key_file,
        )
        .await?;
    }

    Ok(res)
}

async fn test_single_beacon(
    cfg: &TestBeaconArgs,
    queued: impl AsRef<[TestCaseName]>,
    target: impl AsRef<str>,
    cancel: CancellationToken,
) -> Vec<TestResult> {
    let mut results = Vec::new();

    for tc in queued.as_ref() {
        if cancel.is_cancelled() {
            results.push(
                TestResult::new(tc.name.to_string())
                    .fail(TestResultError::from_string("timeout/interrupted")),
            );
            break;
        }

        let result = run_test_case(cancel.clone(), cfg.clone(), target.as_ref(), tc.name).await;
        results.push(result);
    }

    results
}

async fn beacon_ping_test(
    _cancel: CancellationToken,
    _cfg: TestBeaconArgs,
    target: &str,
) -> TestResult {
    let mut res = TestResult::new("Ping");
    let url = format!("{target}/eth/v1/node/health");

    match request_rtt(&url, Method::GET, None, reqwest::StatusCode::OK).await {
        Ok(_) => {
            res.verdict = TestVerdict::Ok;
            res
        }
        Err(e) => res.fail(e),
    }
}

async fn beacon_ping_measure_test(
    _cancel: CancellationToken,
    _cfg: TestBeaconArgs,
    target: &str,
) -> TestResult {
    let res = TestResult::new("PingMeasure");

    match beacon_ping_once(target).await {
        Ok(rtt) => evaluate_rtt(
            rtt,
            res,
            THRESHOLD_BEACON_MEASURE_AVG,
            THRESHOLD_BEACON_MEASURE_POOR,
        ),
        Err(e) => res.fail(e),
    }
}

async fn beacon_version_test(
    _cancel: CancellationToken,
    _cfg: TestBeaconArgs,
    target: &str,
) -> TestResult {
    let mut res = TestResult::new("Version");
    let url = format!("{target}/eth/v1/node/version");

    let client = reqwest::Client::new();
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return res.fail(e),
    };

    // More strict than the Charon check, which requires the status code to be >
    // 399.
    if !resp.status().is_success() {
        return res.fail(TestResultError::from_string(format!(
            "http status {}",
            resp.status().as_u16()
        )));
    }

    #[derive(Deserialize)]
    struct VersionData {
        version: String,
    }
    #[derive(Deserialize)]
    struct VersionResponse {
        data: VersionData,
    }

    let body = match resp.json::<VersionResponse>().await {
        Ok(b) => b,
        Err(e) => return res.fail(e),
    };

    // Keep only provider, version and platform
    let parts: Vec<&str> = body.data.version.split('/').collect();
    let version = if parts.len() > 3 {
        parts[..3].join("/")
    } else {
        body.data.version
    };

    res.measurement = version;
    res.verdict = TestVerdict::Ok;
    res
}

async fn beacon_is_synced_test(
    _cancel: CancellationToken,
    _cfg: TestBeaconArgs,
    target: &str,
) -> TestResult {
    let mut res = TestResult::new("Synced");
    let url = format!("{target}/eth/v1/node/syncing");

    let client = reqwest::Client::new();
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return res.fail(e),
    };

    // More strict than the Charon check, which requires the status code to be >
    // 399.
    if !resp.status().is_success() {
        return res.fail(TestResultError::from_string(format!(
            "http status {}",
            resp.status().as_u16()
        )));
    }

    #[derive(Deserialize)]
    struct SyncData {
        is_syncing: bool,
    }
    #[derive(Deserialize)]
    struct SyncResponse {
        data: SyncData,
    }

    let body = match resp.json::<SyncResponse>().await {
        Ok(b) => b,
        Err(e) => return res.fail(e),
    };

    res.verdict = if body.data.is_syncing {
        TestVerdict::Fail
    } else {
        TestVerdict::Ok
    };
    res
}

async fn beacon_peer_count_test(
    _cancel: CancellationToken,
    _cfg: TestBeaconArgs,
    target: &str,
) -> TestResult {
    let mut res = TestResult::new("PeerCount");
    let url = format!("{target}/eth/v1/node/peers?state=connected");

    let client = reqwest::Client::new();
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return res.fail(e),
    };

    // More strict than the Charon check, which requires the status code to be >
    // 399.
    if !resp.status().is_success() {
        return res.fail(TestResultError::from_string(format!(
            "http status {}",
            resp.status().as_u16()
        )));
    }

    #[derive(Deserialize)]
    struct Meta {
        count: u64,
    }
    #[derive(Deserialize)]
    struct PeerCountResponse {
        meta: Meta,
    }

    let body = match resp.json::<PeerCountResponse>().await {
        Ok(b) => b,
        Err(e) => return res.fail(e),
    };

    res.measurement = body.meta.count.to_string();

    if body.meta.count < THRESHOLD_BEACON_PEERS_POOR {
        res.verdict = TestVerdict::Poor;
    } else if body.meta.count < THRESHOLD_BEACON_PEERS_AVG {
        res.verdict = TestVerdict::Avg;
    } else {
        res.verdict = TestVerdict::Good;
    }
    res
}

async fn beacon_ping_once(target: &str) -> CliResult<StdDuration> {
    let url = format!("{target}/eth/v1/node/health");
    request_rtt(&url, Method::GET, None, reqwest::StatusCode::OK).await
}

async fn ping_beacon_continuously(cancel: CancellationToken, target: String) -> Vec<StdDuration> {
    let mut rtts = Vec::new();
    loop {
        let Some(Ok(rtt)) = cancel.run_until_cancelled(beacon_ping_once(&target)).await else {
            return rtts;
        };

        rtts.push(rtt);

        let jitter = rand::thread_rng().gen_range(0..100u64);
        tokio::select! {
            _ = cancel.cancelled() => return rtts,
            _ = sleep(StdDuration::from_millis(jitter)) => {}
        }
    }
}

async fn beacon_ping_load_test(
    cancel: CancellationToken,
    cfg: TestBeaconArgs,
    target: &str,
) -> TestResult {
    if !cfg.load_test {
        return skip_result("PingLoad");
    }
    let res = TestResult::new("PingLoad");

    tracing::info!(
        duration = ?cfg.load_test_duration,
        target = %target,
        "Running ping load tests..."
    );

    let load_cancel = cancel.child_token();
    cancel_after(&load_cancel, cfg.load_test_duration);

    let mut set = JoinSet::new();
    let mut interval = interval(StdDuration::from_secs(1));

    loop {
        tokio::select! {
            _ = load_cancel.cancelled() => break,
            _ = interval.tick() => {
                let cancel = load_cancel.clone();
                let target = target.to_string();
                set.spawn(async move {
                    ping_beacon_continuously(cancel, target).await
                });
            }
        }
    }

    let rtts: Vec<StdDuration> = set.join_all().await.into_iter().flatten().collect();

    tracing::info!(target = %target, "Ping load tests finished");

    evaluate_highest_rtt(
        rtts,
        res,
        THRESHOLD_BEACON_LOAD_AVG,
        THRESHOLD_BEACON_LOAD_POOR,
    )
}

fn default_intensity() -> RequestsIntensity {
    RequestsIntensity {
        attestation_duty: SLOT_TIME,
        aggregator_duty: SLOT_TIME.saturating_mul(2),
        proposal_duty: SLOT_TIME.saturating_mul(4),
        sync_committee_submit: SLOT_TIME,
        sync_committee_contribution: SLOT_TIME.saturating_mul(4),
        sync_committee_subscribe: EPOCH_TIME,
    }
}

async fn beacon_simulation_1_test(
    cancel: CancellationToken,
    cfg: TestBeaconArgs,
    target: &str,
) -> TestResult {
    if !cfg.load_test {
        return skip_result("Simulate1");
    }
    let res = TestResult::new("Simulate1");
    let params = SimParams {
        total_validators_count: 1,
        attestation_validators_count: 0,
        proposal_validators_count: 0,
        sync_committee_validators_count: 1,
        request_intensity: default_intensity(),
    };
    beacon_simulation_test(cancel, &cfg, target, res, params).await
}

async fn beacon_simulation_10_test(
    cancel: CancellationToken,
    cfg: TestBeaconArgs,
    target: &str,
) -> TestResult {
    if !cfg.load_test {
        return skip_result("Simulate10");
    }
    let res = TestResult::new("Simulate10");
    let params = SimParams {
        total_validators_count: 10,
        attestation_validators_count: 6,
        proposal_validators_count: 3,
        sync_committee_validators_count: 1,
        request_intensity: default_intensity(),
    };
    beacon_simulation_test(cancel, &cfg, target, res, params).await
}

async fn beacon_simulation_100_test(
    cancel: CancellationToken,
    cfg: TestBeaconArgs,
    target: &str,
) -> TestResult {
    if !cfg.load_test {
        return skip_result("Simulate100");
    }
    let res = TestResult::new("Simulate100");
    let params = SimParams {
        total_validators_count: 100,
        attestation_validators_count: 80,
        proposal_validators_count: 18,
        sync_committee_validators_count: 2,
        request_intensity: default_intensity(),
    };
    beacon_simulation_test(cancel, &cfg, target, res, params).await
}

async fn beacon_simulation_500_test(
    cancel: CancellationToken,
    cfg: TestBeaconArgs,
    target: &str,
) -> TestResult {
    if !cfg.load_test {
        return skip_result("Simulate500");
    }
    let res = TestResult::new("Simulate500");
    let params = SimParams {
        total_validators_count: 500,
        attestation_validators_count: 450,
        proposal_validators_count: 45,
        sync_committee_validators_count: 5,
        request_intensity: default_intensity(),
    };
    beacon_simulation_test(cancel, &cfg, target, res, params).await
}

async fn beacon_simulation_1000_test(
    cancel: CancellationToken,
    cfg: TestBeaconArgs,
    target: &str,
) -> TestResult {
    if !cfg.load_test {
        return skip_result("Simulate1000");
    }
    let res = TestResult::new("Simulate1000");
    let params = SimParams {
        total_validators_count: 1000,
        attestation_validators_count: 930,
        proposal_validators_count: 65,
        sync_committee_validators_count: 5,
        request_intensity: default_intensity(),
    };
    beacon_simulation_test(cancel, &cfg, target, res, params).await
}

async fn beacon_simulation_custom_test(
    cancel: CancellationToken,
    cfg: TestBeaconArgs,
    target: &str,
) -> TestResult {
    if cfg.simulation_custom < 1 {
        return TestResult {
            verdict: TestVerdict::Skip,
            ..TestResult::new("SimulateCustom")
        };
    }

    let total = cfg.simulation_custom;
    let mut sync_committees = total / 100;
    if sync_committees == 0 {
        sync_committees = 1;
    }
    let mut proposals = total / 15;
    if proposals == 0 && (total.saturating_sub(sync_committees) != 0) {
        proposals = 1;
    }
    let attestations = total
        .saturating_sub(sync_committees)
        .saturating_sub(proposals);

    let res = TestResult::new(format!("Simulate{total}"));
    let params = SimParams {
        total_validators_count: total,
        attestation_validators_count: attestations,
        proposal_validators_count: proposals,
        sync_committee_validators_count: sync_committees,
        request_intensity: default_intensity(),
    };
    beacon_simulation_test(cancel, &cfg, target, res, params).await
}

async fn beacon_simulation_test(
    cancel: CancellationToken,
    cfg: &TestBeaconArgs,
    target: &str,
    mut test_res: TestResult,
    params: SimParams,
) -> TestResult {
    let sim_duration = StdDuration::from_secs(
        cfg.simulation_duration
            .saturating_mul(SLOT_TIME_SECS.get())
            .saturating_add(1),
    );

    tracing::info!(
        validators_count = params.total_validators_count,
        target = %target,
        duration_in_slots = cfg.simulation_duration,
        slot_duration = ?SLOT_TIME,
        "Running beacon node simulation..."
    );

    let sim_cancel = cancel.child_token();
    cancel_after(&sim_cancel, sim_duration);

    // General cluster requests
    tracing::info!("Starting general cluster requests...");
    let cluster_cancel = sim_cancel.clone();
    let cluster_target = target.to_string();
    let cluster_handle = tokio::spawn(async move {
        single_cluster_simulation(cluster_cancel, sim_duration, &cluster_target).await
    });

    // Validator simulations
    let mut validator_handles = Vec::new();

    let sync_duties = DutiesPerformed {
        attestation: true,
        aggregation: true,
        proposal: true,
        sync_committee: true,
    };
    tracing::info!(
        validators = params.sync_committee_validators_count,
        "Starting validators performing duties attestation, aggregation, proposal, sync committee..."
    );
    for _ in 0..params.sync_committee_validators_count {
        let cancel = sim_cancel.clone();
        let target = target.to_string();
        let intensity = params.request_intensity;
        validator_handles.push(tokio::spawn(async move {
            single_validator_simulation(cancel, sim_duration, &target, intensity, sync_duties).await
        }));
    }

    let proposal_duties = DutiesPerformed {
        attestation: true,
        aggregation: true,
        proposal: true,
        sync_committee: false,
    };
    tracing::info!(
        validators = params.proposal_validators_count,
        "Starting validators performing duties attestation, aggregation, proposal..."
    );
    for _ in 0..params.proposal_validators_count {
        let cancel = sim_cancel.clone();
        let target = target.to_string();
        let intensity = params.request_intensity;
        validator_handles.push(tokio::spawn(async move {
            single_validator_simulation(cancel, sim_duration, &target, intensity, proposal_duties)
                .await
        }));
    }

    let attester_duties = DutiesPerformed {
        attestation: true,
        aggregation: true,
        proposal: false,
        sync_committee: false,
    };
    tracing::info!(
        validators = params.attestation_validators_count,
        "Starting validators performing duties attestation, aggregation..."
    );
    for _ in 0..params.attestation_validators_count {
        let cancel = sim_cancel.clone();
        let target = target.to_string();
        let intensity = params.request_intensity;
        validator_handles.push(tokio::spawn(async move {
            single_validator_simulation(cancel, sim_duration, &target, intensity, attester_duties)
                .await
        }));
    }

    tracing::info!("Waiting for simulation to complete...");

    let cluster_result = cluster_handle.await.unwrap_or_default();
    let mut all_validators = Vec::new();
    for h in validator_handles {
        if let Ok(v) = h.await {
            all_validators.push(v);
        }
    }

    tracing::info!("Simulation finished, evaluating results...");

    let averaged = average_validators_result(&all_validators);

    let mut final_simulation = Simulation {
        general_cluster_requests: cluster_result,
        validators_requests: SimulationValidators {
            averaged,
            all_validators: all_validators.clone(),
        },
    };

    if !cfg.simulation_verbose {
        strip_verbose(&mut final_simulation);
    }

    if let Ok(json) = serde_json::to_vec(&final_simulation) {
        let path = cfg
            .simulation_file_dir
            .join(format!("{}-validators.json", params.total_validators_count));
        if let Err(e) = tokio::fs::write(&path, json).await {
            tracing::error!(?e, "Failed to write simulation file");
        }
    }

    let highest_rtt = all_validators
        .iter()
        .map(|v| v.values.max)
        .max_by_key(|d| d.as_nanos())
        .unwrap_or_default();

    test_res = evaluate_rtt(
        highest_rtt.into(),
        test_res,
        THRESHOLD_BEACON_SIMULATION_AVG,
        THRESHOLD_BEACON_SIMULATION_POOR,
    );

    tracing::info!(
        validators_count = params.total_validators_count,
        target = %target,
        "Validators simulation finished"
    );

    test_res
}

async fn single_cluster_simulation(
    cancel: CancellationToken,
    sim_duration: StdDuration,
    target: &str,
) -> SimulationCluster {
    let mut attestations_for_block = Vec::new();
    let mut proposal_duties_for_epoch = Vec::new();
    let mut syncing = Vec::new();
    let mut peer_count = Vec::new();
    let mut beacon_committee_sub = Vec::new();
    let mut duties_attester = Vec::new();
    let mut duties_sync_committee = Vec::new();
    let mut beacon_head_validators = Vec::new();
    let mut beacon_genesis_all = Vec::new();
    let mut prep_beacon_proposer = Vec::new();
    let mut config_spec_all = Vec::new();
    let mut node_version_all = Vec::new();

    let mut slot = get_current_slot(target).await.unwrap_or(1);

    let deadline = sim_deadline(sim_duration);

    let now = Instant::now();
    #[allow(clippy::arithmetic_side_effects)]
    let mut slot_interval = interval_at(now + SLOT_TIME, SLOT_TIME);
    #[allow(clippy::arithmetic_side_effects)]
    let mut interval_12_slots = interval_at(
        now + SLOT_TIME.saturating_mul(12),
        SLOT_TIME.saturating_mul(12),
    );
    #[allow(clippy::arithmetic_side_effects)]
    let mut interval_10_sec =
        interval_at(now + StdDuration::from_secs(10), StdDuration::from_secs(10));
    #[allow(clippy::arithmetic_side_effects)]
    let mut interval_minute =
        interval_at(now + StdDuration::from_secs(60), StdDuration::from_secs(60));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = sleep_until(deadline) => break,
            _ = slot_interval.tick() => {
                slot = slot.saturating_add(1);
                let epoch = slot / SLOTS_IN_EPOCH;

                if let Ok(rtt) = req_get_attestations_for_block(target, slot.saturating_sub(6)).await {
                    attestations_for_block.push(rtt);
                }
                if let Ok(rtt) = req_get_proposal_duties_for_epoch(target, epoch).await {
                    proposal_duties_for_epoch.push(rtt);
                }

                // First slot of epoch
                if slot % SLOTS_IN_EPOCH == 0 {
                    if let Ok(rtt) = req_get_attester_duties_for_epoch(target, epoch).await { duties_attester.push(rtt); }
                    if let Ok(rtt) = req_get_sync_committee_duties_for_epoch(target, epoch).await { duties_sync_committee.push(rtt); }
                    if let Ok(rtt) = req_beacon_head_validators(target).await { beacon_head_validators.push(rtt); }
                    if let Ok(rtt) = req_beacon_genesis(target).await { beacon_genesis_all.push(rtt); }
                    if let Ok(rtt) = req_prep_beacon_proposer(target).await { prep_beacon_proposer.push(rtt); }
                    if let Ok(rtt) = req_config_spec(target).await { config_spec_all.push(rtt); }
                    if let Ok(rtt) = req_node_version(target).await { node_version_all.push(rtt); }
                }

                // Last-but-one slot of epoch
                if slot % SLOTS_IN_EPOCH == SLOTS_IN_EPOCH.get().saturating_sub(2)
                    && let Ok(rtt) = req_get_attester_duties_for_epoch(target, epoch).await
                {
                    duties_attester.push(rtt);
                }

                // Last slot of epoch
                if slot % SLOTS_IN_EPOCH == SLOTS_IN_EPOCH.get().saturating_sub(1) {
                    if let Ok(rtt) = req_get_attester_duties_for_epoch(target, epoch).await { duties_attester.push(rtt); }
                    if let Ok(rtt) = req_get_sync_committee_duties_for_epoch(target, epoch).await { duties_sync_committee.push(rtt); }
                    if let Ok(rtt) = req_get_sync_committee_duties_for_epoch(target, epoch.saturating_add(256)).await { duties_sync_committee.push(rtt); }
                }
            }
            _ = interval_12_slots.tick() => {
                if let Ok(rtt) = req_beacon_committee_sub(target).await { beacon_committee_sub.push(rtt); }
            }
            _ = interval_10_sec.tick() => {
                if let Ok(rtt) = req_get_syncing(target).await { syncing.push(rtt); }
            }
            _ = interval_minute.tick() => {
                if let Ok(rtt) = req_get_peer_count(target).await { peer_count.push(rtt); }
            }
        }
    }

    SimulationCluster {
        attestations_for_block_request: generate_simulation_values(
            &attestations_for_block,
            "GET /eth/v1/beacon/blocks/{BLOCK}/attestations",
        ),
        proposal_duties_for_epoch_request: generate_simulation_values(
            &proposal_duties_for_epoch,
            "GET /eth/v1/validator/duties/proposer/{EPOCH}",
        ),
        syncing_request: generate_simulation_values(&syncing, "GET /eth/v1/node/syncing"),
        peer_count_request: generate_simulation_values(&peer_count, "GET /eth/v1/node/peer_count"),
        beacon_committee_subscription_request: generate_simulation_values(
            &beacon_committee_sub,
            "POST /eth/v1/validator/beacon_committee_subscriptions",
        ),
        duties_attester_for_epoch_request: generate_simulation_values(
            &duties_attester,
            "POST /eth/v1/validator/duties/attester/{EPOCH}",
        ),
        duties_sync_committee_for_epoch_request: generate_simulation_values(
            &duties_sync_committee,
            "POST /eth/v1/validator/duties/sync/{EPOCH}",
        ),
        beacon_head_validators_request: generate_simulation_values(
            &beacon_head_validators,
            "POST /eth/v1/beacon/states/head/validators",
        ),
        beacon_genesis_request: generate_simulation_values(
            &beacon_genesis_all,
            "GET /eth/v1/beacon/genesis",
        ),
        prep_beacon_proposer_request: generate_simulation_values(
            &prep_beacon_proposer,
            "POST /eth/v1/validator/prepare_beacon_proposer",
        ),
        config_spec_request: generate_simulation_values(
            &config_spec_all,
            "GET /eth/v1/config/spec",
        ),
        node_version_request: generate_simulation_values(
            &node_version_all,
            "GET /eth/v1/node/version",
        ),
    }
}

async fn single_validator_simulation(
    cancel: CancellationToken,
    sim_duration: StdDuration,
    target: &str,
    intensity: RequestsIntensity,
    duties: DutiesPerformed,
) -> SimulationSingleValidator {
    let mut sync_committee_subscription_all = Vec::new();
    let mut submit_sync_committee_message_all = Vec::new();
    let mut produce_sync_committee_contribution_all = Vec::new();
    let mut submit_sync_committee_contribution_all = Vec::new();

    // Attestation duty
    let att_handle = if duties.attestation {
        let cancel = cancel.clone();
        let target = target.to_string();
        Some(tokio::spawn(async move {
            attestation_duty(cancel, &target, sim_duration, intensity.attestation_duty).await
        }))
    } else {
        None
    };

    // Aggregation duty
    let agg_handle = if duties.aggregation {
        let cancel = cancel.clone();
        let target = target.to_string();
        Some(tokio::spawn(async move {
            aggregation_duty(cancel, &target, sim_duration, intensity.aggregator_duty).await
        }))
    } else {
        None
    };

    // Proposal duty
    let prop_handle = if duties.proposal {
        let cancel = cancel.clone();
        let target = target.to_string();
        Some(tokio::spawn(async move {
            proposal_duty(cancel, &target, sim_duration, intensity.proposal_duty).await
        }))
    } else {
        None
    };

    // Sync committee duties
    let (sc_sub_tx, mut sc_sub_rx) = mpsc::channel(256);
    let (sc_msg_tx, mut sc_msg_rx) = mpsc::channel(256);
    let (sc_produce_tx, mut sc_produce_rx) = mpsc::channel(256);
    let (sc_contrib_tx, mut sc_contrib_rx) = mpsc::channel(256);
    if duties.sync_committee {
        let cancel = cancel.clone();
        let target = target.to_string();
        tokio::spawn(async move {
            sync_committee_duties(
                cancel,
                &target,
                sim_duration,
                intensity.sync_committee_submit,
                intensity.sync_committee_subscribe,
                intensity.sync_committee_contribution,
                sc_msg_tx,
                sc_produce_tx,
                sc_sub_tx,
                sc_contrib_tx,
            )
            .await;
        });
    } else {
        drop(sc_sub_tx);
        drop(sc_msg_tx);
        drop(sc_produce_tx);
        drop(sc_contrib_tx);
    }

    // Collect results from sync committee channels
    let sc_deadline = sim_deadline(sim_duration);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = sleep_until(sc_deadline) => break,
            Some(v) = sc_sub_rx.recv() => sync_committee_subscription_all.push(v),
            Some(v) = sc_msg_rx.recv() => submit_sync_committee_message_all.push(v),
            Some(v) = sc_produce_rx.recv() => produce_sync_committee_contribution_all.push(v),
            Some(v) = sc_contrib_rx.recv() => submit_sync_committee_contribution_all.push(v),
            else => break,
        }
    }

    let (get_attestation_data_all, submit_attestation_object_all) = match att_handle {
        Some(h) => h.await.unwrap_or_default(),
        None => (Vec::new(), Vec::new()),
    };
    let (get_aggregate_attestations_all, submit_aggregate_and_proofs_all) = match agg_handle {
        Some(h) => h.await.unwrap_or_default(),
        None => (Vec::new(), Vec::new()),
    };
    let (produce_block_all, publish_blinded_block_all) = match prop_handle {
        Some(h) => h.await.unwrap_or_default(),
        None => (Vec::new(), Vec::new()),
    };

    let mut all_requests = Vec::new();

    // Attestation results
    let (values, get_vals, post_vals) = compute_two_phase_results(
        &get_attestation_data_all,
        "GET /eth/v1/validator/attestation_data",
        &submit_attestation_object_all,
        "POST /eth/v1/beacon/pool/attestations",
        &mut all_requests,
    );
    let attestation_result = SimulationAttestation {
        values,
        get_attestation_data_request: get_vals,
        post_attestations_request: post_vals,
    };

    // Aggregation results
    let (values, get_vals, post_vals) = compute_two_phase_results(
        &get_aggregate_attestations_all,
        "GET /eth/v1/validator/aggregate_attestation",
        &submit_aggregate_and_proofs_all,
        "POST /eth/v1/validator/aggregate_and_proofs",
        &mut all_requests,
    );
    let aggregation_result = SimulationAggregation {
        values,
        get_aggregate_attestation_request: get_vals,
        post_aggregate_and_proofs_request: post_vals,
    };

    // Proposal results
    let (values, produce_vals, publish_vals) = compute_two_phase_results(
        &produce_block_all,
        "GET /eth/v3/validator/blocks/{SLOT}",
        &publish_blinded_block_all,
        "POST /eth/v2/beacon/blinded",
        &mut all_requests,
    );
    let proposal_result = SimulationProposal {
        values,
        produce_block_request: produce_vals,
        publish_blinded_block_request: publish_vals,
    };

    // Sync committee results
    let sync_committee_result = if duties.sync_committee {
        let sub_vals = generate_simulation_values(
            &sync_committee_subscription_all,
            "POST /eth/v1/validator/sync_committee_subscriptions",
        );
        let msg_vals = generate_simulation_values(
            &submit_sync_committee_message_all,
            "POST /eth/v1/beacon/pool/sync_committees",
        );
        let produce_vals = generate_simulation_values(
            &produce_sync_committee_contribution_all,
            "GET /eth/v1/validator/sync_committee_contribution",
        );
        let contrib_vals = generate_simulation_values(
            &submit_sync_committee_contribution_all,
            "POST /eth/v1/validator/contribution_and_proofs",
        );

        let contribution_cumulative: Vec<_> = produce_sync_committee_contribution_all
            .iter()
            .zip(&submit_sync_committee_contribution_all)
            .map(|(a, b)| a.saturating_add(*b))
            .collect();

        let mut sc_all = Vec::new();
        sc_all.extend_from_slice(&sync_committee_subscription_all);
        sc_all.extend_from_slice(&submit_sync_committee_message_all);
        sc_all.extend_from_slice(&contribution_cumulative);
        all_requests.extend_from_slice(&sc_all);

        SimulationSyncCommittee {
            values: generate_simulation_values(&sc_all, ""),
            message_duty: SyncCommitteeMessageDuty {
                submit_sync_committee_message_request: msg_vals,
            },
            contribution_duty: SyncCommitteeContributionDuty {
                values: generate_simulation_values(&contribution_cumulative, ""),
                produce_sync_committee_contribution_request: produce_vals,
                submit_sync_committee_contribution_request: contrib_vals,
            },
            subscribe_sync_committee_request: sub_vals,
        }
    } else {
        SimulationSyncCommittee::default()
    };

    SimulationSingleValidator {
        values: generate_simulation_values(&all_requests, ""),
        attestation_duty: attestation_result,
        aggregation_duty: aggregation_result,
        proposal_duty: proposal_result,
        sync_committee_duties: sync_committee_result,
    }
}

async fn attestation_duty(
    cancel: CancellationToken,
    target: &str,
    sim_duration: StdDuration,
    tick_time: StdDuration,
) -> (Vec<StdDuration>, Vec<StdDuration>) {
    let mut get_all = Vec::new();
    let mut submit_all = Vec::new();
    let deadline = sim_deadline(sim_duration);
    if cancel
        .run_until_cancelled(sleep(randomize_start(tick_time)))
        .await
        .is_none()
    {
        return Default::default();
    }
    #[allow(clippy::arithmetic_side_effects)]
    let mut interval = interval_at(Instant::now() + tick_time, tick_time);
    let mut slot = cancel
        .run_until_cancelled(get_current_slot(target))
        .await
        .and_then(|r| r.ok())
        .unwrap_or(1);

    loop {
        if cancel.is_cancelled() || Instant::now() >= deadline {
            break;
        }

        let committee_index = rand::thread_rng().gen_range(0..COMMITTEE_SIZE_PER_SLOT);
        if let Some(Ok(rtt)) = cancel
            .run_until_cancelled(req_get_attestation_data(target, slot, committee_index))
            .await
        {
            get_all.push(rtt);
        }
        if let Some(Ok(rtt)) = cancel
            .run_until_cancelled(req_submit_attestation_object(target))
            .await
        {
            submit_all.push(rtt);
        }

        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = sleep_until(deadline) => break,
            _ = interval.tick() => {
                slot = slot.saturating_add(tick_time.as_secs() / SLOT_TIME_SECS);
            }
        }
    }

    (get_all, submit_all)
}

async fn aggregation_duty(
    cancel: CancellationToken,
    target: &str,
    sim_duration: StdDuration,
    tick_time: StdDuration,
) -> (Vec<StdDuration>, Vec<StdDuration>) {
    let mut get_all = Vec::new();
    let mut submit_all = Vec::new();
    let deadline = sim_deadline(sim_duration);
    let mut slot = cancel
        .run_until_cancelled(get_current_slot(target))
        .await
        .and_then(|r| r.ok())
        .unwrap_or(1);
    if cancel
        .run_until_cancelled(sleep(randomize_start(tick_time)))
        .await
        .is_none()
    {
        return Default::default();
    }
    #[allow(clippy::arithmetic_side_effects)]
    let mut interval = interval_at(Instant::now() + tick_time, tick_time);

    loop {
        if cancel.is_cancelled() || Instant::now() >= deadline {
            break;
        }

        if let Some(Ok(rtt)) = cancel
            .run_until_cancelled(req_get_aggregate_attestations(
                target,
                slot,
                "0x87db5c50a4586fa37662cf332382d56a0eeea688a7d7311a42735683dfdcbfa4",
            ))
            .await
        {
            get_all.push(rtt);
        }
        if let Some(Ok(rtt)) = cancel
            .run_until_cancelled(req_post_aggregate_and_proofs(target))
            .await
        {
            submit_all.push(rtt);
        }

        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = sleep_until(deadline) => break,
            _ = interval.tick() => {
                slot = slot.saturating_add(tick_time.as_secs() / SLOT_TIME_SECS);
            }
        }
    }

    (get_all, submit_all)
}

async fn proposal_duty(
    cancel: CancellationToken,
    target: &str,
    sim_duration: StdDuration,
    tick_time: StdDuration,
) -> (Vec<StdDuration>, Vec<StdDuration>) {
    let mut produce_all = Vec::new();
    let mut publish_all = Vec::new();
    let deadline = sim_deadline(sim_duration);
    if cancel
        .run_until_cancelled(sleep(randomize_start(tick_time)))
        .await
        .is_none()
    {
        return Default::default();
    }
    #[allow(clippy::arithmetic_side_effects)]
    let mut interval = interval_at(Instant::now() + tick_time, tick_time);
    let mut slot = cancel
        .run_until_cancelled(get_current_slot(target))
        .await
        .and_then(|r| r.ok())
        .unwrap_or(1);
    let randao = "0x1fe79e4193450abda94aec753895cfb2aac2c2a930b6bab00fbb27ef6f4a69f4400ad67b5255b91837982b4c511ae1d94eae1cf169e20c11bd417c1fffdb1f99f4e13e2de68f3b5e73f1de677d73cd43e44bf9b133a79caf8e5fad06738e1b0c";

    loop {
        if cancel.is_cancelled() || Instant::now() >= deadline {
            break;
        }

        if let Some(Ok(rtt)) = cancel
            .run_until_cancelled(req_produce_block(target, slot, randao))
            .await
        {
            produce_all.push(rtt);
        }
        if let Some(Ok(rtt)) = cancel
            .run_until_cancelled(req_publish_blinded_block(target))
            .await
        {
            publish_all.push(rtt);
        }

        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = sleep_until(deadline) => break,
            _ = interval.tick() => {
                slot = slot.saturating_add(tick_time.as_secs() / SLOT_TIME_SECS).saturating_add(1); // produce block for the next slot, as the current one might have already been proposed
            }
        }
    }

    (produce_all, publish_all)
}

#[allow(clippy::too_many_arguments)]
async fn sync_committee_duties(
    cancel: CancellationToken,
    target: &str,
    sim_duration: StdDuration,
    tick_time_submit: StdDuration,
    tick_time_subscribe: StdDuration,
    tick_time_contribution: StdDuration,
    msg_tx: mpsc::Sender<StdDuration>,
    produce_tx: mpsc::Sender<StdDuration>,
    sub_tx: mpsc::Sender<StdDuration>,
    contrib_tx: mpsc::Sender<StdDuration>,
) {
    let c1 = cancel.clone();
    let t1 = target.to_string();
    tokio::spawn(async move {
        sync_committee_contribution_duty(
            c1,
            &t1,
            sim_duration,
            tick_time_contribution,
            produce_tx,
            contrib_tx,
        )
        .await;
    });

    let c2 = cancel.clone();
    let t2 = target.to_string();
    tokio::spawn(async move {
        sync_committee_message_duty(c2, &t2, sim_duration, tick_time_submit, msg_tx).await;
    });

    // Subscribe loop
    let deadline = sim_deadline(sim_duration);
    if cancel
        .run_until_cancelled(sleep(randomize_start(tick_time_subscribe)))
        .await
        .is_none()
    {
        return;
    }
    #[allow(clippy::arithmetic_side_effects)]
    let mut interval = interval_at(Instant::now() + tick_time_subscribe, tick_time_subscribe);

    loop {
        if cancel.is_cancelled() || Instant::now() >= deadline {
            break;
        }

        if let Some(Ok(rtt)) = cancel
            .run_until_cancelled(req_sync_committee_subscription(target))
            .await
        {
            let _ = sub_tx.send(rtt).await;
        }

        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = sleep_until(deadline) => break,
            _ = interval.tick() => {}
        }
    }
}

async fn sync_committee_contribution_duty(
    cancel: CancellationToken,
    target: &str,
    sim_duration: StdDuration,
    tick_time: StdDuration,
    produce_tx: mpsc::Sender<StdDuration>,
    contrib_tx: mpsc::Sender<StdDuration>,
) {
    let deadline = sim_deadline(sim_duration);
    if cancel
        .run_until_cancelled(sleep(randomize_start(tick_time)))
        .await
        .is_none()
    {
        return;
    }
    #[allow(clippy::arithmetic_side_effects)]
    let mut interval = interval_at(Instant::now() + tick_time, tick_time);
    let mut slot = cancel
        .run_until_cancelled(get_current_slot(target))
        .await
        .and_then(|r| r.ok())
        .unwrap_or(1);

    loop {
        if cancel.is_cancelled() || Instant::now() >= deadline {
            break;
        }

        let sub_idx = rand::thread_rng().gen_range(0..SUB_COMMITTEE_SIZE);
        let beacon_block_root =
            "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2";
        if let Some(Ok(rtt)) = cancel
            .run_until_cancelled(req_produce_sync_committee_contribution(
                target,
                slot,
                sub_idx,
                beacon_block_root,
            ))
            .await
        {
            let _ = produce_tx.send(rtt).await;
        }
        if let Some(Ok(rtt)) = cancel
            .run_until_cancelled(req_submit_sync_committee_contribution(target))
            .await
        {
            let _ = contrib_tx.send(rtt).await;
        }

        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = sleep_until(deadline) => break,
            _ = interval.tick() => {
                slot = slot.saturating_add(tick_time.as_secs() / SLOT_TIME_SECS);
            }
        }
    }
}

async fn sync_committee_message_duty(
    cancel: CancellationToken,
    target: &str,
    sim_duration: StdDuration,
    tick_time: StdDuration,
    msg_tx: mpsc::Sender<StdDuration>,
) {
    let deadline = sim_deadline(sim_duration);
    if cancel
        .run_until_cancelled(sleep(randomize_start(tick_time)))
        .await
        .is_none()
    {
        return;
    }
    #[allow(clippy::arithmetic_side_effects)]
    let mut interval = interval_at(Instant::now() + tick_time, tick_time);

    loop {
        if cancel.is_cancelled() || Instant::now() >= deadline {
            break;
        }

        if let Some(Ok(rtt)) = cancel
            .run_until_cancelled(req_submit_sync_committee(target))
            .await
        {
            let _ = msg_tx.send(rtt).await;
        }

        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = sleep_until(deadline) => break,
            _ = interval.tick() => {}
        }
    }
}

async fn get_current_slot(target: &str) -> CliResult<u64> {
    let url = format!("{target}/eth/v1/node/syncing");
    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await?;

    // More strict than the Charon check, which requires the status code to be >
    // 399.
    if !resp.status().is_success() {
        return Err(crate::error::CliError::Other(format!(
            "syncing request failed: {}",
            resp.status()
        )));
    }

    #[derive(Deserialize)]
    struct Data {
        head_slot: String,
    }
    #[derive(Deserialize)]
    struct Response {
        data: Data,
    }

    let body: Response = resp.json().await?;
    body.data
        .head_slot
        .parse()
        .map_err(|e| crate::error::CliError::Other(format!("parse head_slot: {e}")))
}

fn compute_two_phase_results(
    first: &[StdDuration],
    first_endpoint: &str,
    second: &[StdDuration],
    second_endpoint: &str,
    all_requests: &mut Vec<StdDuration>,
) -> (SimulationValues, SimulationValues, SimulationValues) {
    let first_vals = generate_simulation_values(first, first_endpoint);
    let second_vals = generate_simulation_values(second, second_endpoint);
    let cumulative: Vec<_> = first
        .iter()
        .zip(second)
        .map(|(a, b)| a.saturating_add(*b))
        .collect();
    all_requests.extend_from_slice(&cumulative);
    let cumulative_vals = generate_simulation_values(&cumulative, "");
    (cumulative_vals, first_vals, second_vals)
}

fn generate_simulation_values(durations: &[StdDuration], endpoint: &str) -> SimulationValues {
    if durations.is_empty() {
        return SimulationValues {
            endpoint: endpoint.to_string(),
            ..Default::default()
        };
    }

    let mut sorted: Vec<StdDuration> = durations.to_vec();
    sorted.sort();

    let min = sorted[0];
    let max = sorted[sorted.len().saturating_sub(1)];
    let median = sorted[sorted.len() / 2];
    let sum: StdDuration = durations.iter().sum();
    let count = u32::try_from(durations.len()).unwrap_or_else(|_| {
        tracing::warn!("Failed to convert duration length to u32");
        u32::MAX
    });
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "count is non-zero (early return above)"
    )]
    let avg = sum / count;

    let all: Vec<Duration> = durations.iter().map(|d| Duration::new(*d)).collect();

    SimulationValues {
        endpoint: endpoint.to_string(),
        all,
        min: Duration::new(min),
        max: Duration::new(max),
        median: Duration::new(median),
        avg: Duration::new(avg),
    }
}

fn average_validators_result(
    validators: &[SimulationSingleValidator],
) -> SimulationSingleValidator {
    if validators.is_empty() {
        return SimulationSingleValidator::default();
    }

    let collect_durations =
        |f: &dyn Fn(&SimulationSingleValidator) -> &SimulationValues| -> Vec<StdDuration> {
            validators
                .iter()
                .flat_map(|v| f(v).all.iter().map(|d| (*d).into()))
                .collect()
        };

    let att_get = collect_durations(&|v| &v.attestation_duty.get_attestation_data_request);
    let att_post = collect_durations(&|v| &v.attestation_duty.post_attestations_request);
    let att_all = collect_durations(&|v| &v.attestation_duty.values);

    let agg_get = collect_durations(&|v| &v.aggregation_duty.get_aggregate_attestation_request);
    let agg_post = collect_durations(&|v| &v.aggregation_duty.post_aggregate_and_proofs_request);
    let agg_all = collect_durations(&|v| &v.aggregation_duty.values);

    let prop_produce = collect_durations(&|v| &v.proposal_duty.produce_block_request);
    let prop_publish = collect_durations(&|v| &v.proposal_duty.publish_blinded_block_request);
    let prop_all = collect_durations(&|v| &v.proposal_duty.values);

    let sc_msg = collect_durations(&|v| {
        &v.sync_committee_duties
            .message_duty
            .submit_sync_committee_message_request
    });
    let sc_produce = collect_durations(&|v| {
        &v.sync_committee_duties
            .contribution_duty
            .produce_sync_committee_contribution_request
    });
    let sc_contrib = collect_durations(&|v| {
        &v.sync_committee_duties
            .contribution_duty
            .submit_sync_committee_contribution_request
    });
    let sc_contrib_all = collect_durations(&|v| &v.sync_committee_duties.contribution_duty.values);
    let sc_sub = collect_durations(&|v| &v.sync_committee_duties.subscribe_sync_committee_request);
    let sc_all = collect_durations(&|v| &v.sync_committee_duties.values);

    let all = collect_durations(&|v| &v.values);

    SimulationSingleValidator {
        values: generate_simulation_values(&all, ""),
        attestation_duty: SimulationAttestation {
            values: generate_simulation_values(&att_all, ""),
            get_attestation_data_request: generate_simulation_values(
                &att_get,
                "GET /eth/v1/validator/attestation_data",
            ),
            post_attestations_request: generate_simulation_values(
                &att_post,
                "POST /eth/v1/beacon/pool/attestations",
            ),
        },
        aggregation_duty: SimulationAggregation {
            values: generate_simulation_values(&agg_all, ""),
            get_aggregate_attestation_request: generate_simulation_values(
                &agg_get,
                "GET /eth/v1/validator/aggregate_attestation",
            ),
            post_aggregate_and_proofs_request: generate_simulation_values(
                &agg_post,
                "POST /eth/v1/validator/aggregate_and_proofs",
            ),
        },
        proposal_duty: SimulationProposal {
            values: generate_simulation_values(&prop_all, ""),
            produce_block_request: generate_simulation_values(
                &prop_produce,
                "GET /eth/v3/validator/blocks/{SLOT}",
            ),
            publish_blinded_block_request: generate_simulation_values(
                &prop_publish,
                "POST /eth/v2/beacon/blinded",
            ),
        },
        sync_committee_duties: SimulationSyncCommittee {
            values: generate_simulation_values(&sc_all, ""),
            message_duty: SyncCommitteeMessageDuty {
                submit_sync_committee_message_request: generate_simulation_values(
                    &sc_msg,
                    "POST /eth/v1/beacon/pool/sync_committees",
                ),
            },
            contribution_duty: SyncCommitteeContributionDuty {
                values: generate_simulation_values(&sc_contrib_all, ""),
                produce_sync_committee_contribution_request: generate_simulation_values(
                    &sc_produce,
                    "GET /eth/v1/validator/sync_committee_contribution",
                ),
                submit_sync_committee_contribution_request: generate_simulation_values(
                    &sc_contrib,
                    "POST /eth/v1/validator/contribution_and_proofs",
                ),
            },
            subscribe_sync_committee_request: generate_simulation_values(
                &sc_sub,
                "POST /eth/v1/validator/sync_committee_subscriptions",
            ),
        },
    }
}

fn skip_result(name: &str) -> TestResult {
    TestResult {
        verdict: TestVerdict::Skip,
        ..TestResult::new(name)
    }
}

fn cancel_after(token: &CancellationToken, duration: StdDuration) {
    let token = token.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = sleep(duration) => token.cancel(),
            _ = token.cancelled() => {}
        }
    });
}

#[allow(clippy::arithmetic_side_effects)]
fn sim_deadline(sim_duration: StdDuration) -> Instant {
    Instant::now() + sim_duration
}

fn randomize_start(tick_time: StdDuration) -> StdDuration {
    let slots = (tick_time.as_secs() / SLOT_TIME_SECS).max(1);
    let random_slots = rand::thread_rng().gen_range(0..slots);
    SLOT_TIME.saturating_mul(u32::try_from(random_slots).unwrap_or_else(|_| {
        tracing::warn!("Failed to convert random slots to u32");
        u32::MAX
    }))
}

fn strip_verbose(sim: &mut Simulation) {
    sim.validators_requests.all_validators.clear();

    strip_vals(&mut sim.validators_requests.averaged.values);
    strip_vals(&mut sim.validators_requests.averaged.attestation_duty.values);
    strip_vals(
        &mut sim
            .validators_requests
            .averaged
            .attestation_duty
            .get_attestation_data_request,
    );
    strip_vals(
        &mut sim
            .validators_requests
            .averaged
            .attestation_duty
            .post_attestations_request,
    );
    strip_vals(&mut sim.validators_requests.averaged.aggregation_duty.values);
    strip_vals(
        &mut sim
            .validators_requests
            .averaged
            .aggregation_duty
            .get_aggregate_attestation_request,
    );
    strip_vals(
        &mut sim
            .validators_requests
            .averaged
            .aggregation_duty
            .post_aggregate_and_proofs_request,
    );
    strip_vals(&mut sim.validators_requests.averaged.proposal_duty.values);
    strip_vals(
        &mut sim
            .validators_requests
            .averaged
            .proposal_duty
            .produce_block_request,
    );
    strip_vals(
        &mut sim
            .validators_requests
            .averaged
            .proposal_duty
            .publish_blinded_block_request,
    );
    strip_vals(
        &mut sim
            .validators_requests
            .averaged
            .sync_committee_duties
            .values,
    );
    strip_vals(
        &mut sim
            .validators_requests
            .averaged
            .sync_committee_duties
            .contribution_duty
            .values,
    );
    strip_vals(
        &mut sim
            .validators_requests
            .averaged
            .sync_committee_duties
            .contribution_duty
            .produce_sync_committee_contribution_request,
    );
    strip_vals(
        &mut sim
            .validators_requests
            .averaged
            .sync_committee_duties
            .contribution_duty
            .submit_sync_committee_contribution_request,
    );
    strip_vals(
        &mut sim
            .validators_requests
            .averaged
            .sync_committee_duties
            .message_duty
            .submit_sync_committee_message_request,
    );
    strip_vals(
        &mut sim
            .validators_requests
            .averaged
            .sync_committee_duties
            .subscribe_sync_committee_request,
    );

    strip_vals(&mut sim.general_cluster_requests.attestations_for_block_request);
    strip_vals(
        &mut sim
            .general_cluster_requests
            .proposal_duties_for_epoch_request,
    );
    strip_vals(&mut sim.general_cluster_requests.syncing_request);
    strip_vals(&mut sim.general_cluster_requests.peer_count_request);
    strip_vals(
        &mut sim
            .general_cluster_requests
            .beacon_committee_subscription_request,
    );
    strip_vals(
        &mut sim
            .general_cluster_requests
            .duties_attester_for_epoch_request,
    );
    strip_vals(
        &mut sim
            .general_cluster_requests
            .duties_sync_committee_for_epoch_request,
    );
    strip_vals(&mut sim.general_cluster_requests.beacon_head_validators_request);
    strip_vals(&mut sim.general_cluster_requests.beacon_genesis_request);
    strip_vals(&mut sim.general_cluster_requests.prep_beacon_proposer_request);
    strip_vals(&mut sim.general_cluster_requests.config_spec_request);
    strip_vals(&mut sim.general_cluster_requests.node_version_request);
}

fn strip_vals(v: &mut SimulationValues) {
    v.all.clear();
}

async fn req_get_attestations_for_block(target: &str, block: u64) -> CliResult<StdDuration> {
    request_rtt(
        &format!("{target}/eth/v1/beacon/blocks/{block}/attestations"),
        Method::GET,
        None,
        reqwest::StatusCode::OK,
    )
    .await
}

async fn req_get_proposal_duties_for_epoch(target: &str, epoch: u64) -> CliResult<StdDuration> {
    request_rtt(
        &format!("{target}/eth/v1/validator/duties/proposer/{epoch}"),
        Method::GET,
        None,
        reqwest::StatusCode::OK,
    )
    .await
}

async fn req_get_syncing(target: &str) -> CliResult<StdDuration> {
    request_rtt(
        &format!("{target}/eth/v1/node/syncing"),
        Method::GET,
        None,
        reqwest::StatusCode::OK,
    )
    .await
}

async fn req_get_peer_count(target: &str) -> CliResult<StdDuration> {
    request_rtt(
        &format!("{target}/eth/v1/node/peer_count"),
        Method::GET,
        None,
        reqwest::StatusCode::OK,
    )
    .await
}

async fn req_beacon_committee_sub(target: &str) -> CliResult<StdDuration> {
    let body = r#"[{"validator_index":"1","committee_index":"1","committees_at_slot":"1","slot":"1","is_aggregator":true}]"#;
    request_rtt(
        &format!("{target}/eth/v1/validator/beacon_committee_subscriptions"),
        Method::POST,
        Some(body.into()),
        reqwest::StatusCode::OK,
    )
    .await
}

async fn req_get_attester_duties_for_epoch(target: &str, epoch: u64) -> CliResult<StdDuration> {
    let body = r#"["1"]"#;
    request_rtt(
        &format!("{target}/eth/v1/validator/duties/attester/{epoch}"),
        Method::POST,
        Some(body.into()),
        reqwest::StatusCode::OK,
    )
    .await
}

async fn req_get_sync_committee_duties_for_epoch(
    target: &str,
    epoch: u64,
) -> CliResult<StdDuration> {
    let body = r#"["1"]"#;
    request_rtt(
        &format!("{target}/eth/v1/validator/duties/sync/{epoch}"),
        Method::POST,
        Some(body.into()),
        reqwest::StatusCode::OK,
    )
    .await
}

async fn req_beacon_head_validators(target: &str) -> CliResult<StdDuration> {
    let body = r#"{"ids":["0xb6066945aa87a1e0e4b55e347d3a8a0ef7f0d9f7ef2c46abebadb25d7de176b83c88547e5f8644b659598063c845719a"]}"#;
    request_rtt(
        &format!("{target}/eth/v1/beacon/states/head/validators"),
        Method::POST,
        Some(body.into()),
        reqwest::StatusCode::OK,
    )
    .await
}

async fn req_beacon_genesis(target: &str) -> CliResult<StdDuration> {
    request_rtt(
        &format!("{target}/eth/v1/beacon/genesis"),
        Method::GET,
        None,
        reqwest::StatusCode::OK,
    )
    .await
}

async fn req_prep_beacon_proposer(target: &str) -> CliResult<StdDuration> {
    let body = r#"[{"validator_index":"1725802","fee_recipient":"0x74b1C2f5788510c9ecA5f56D367B0a3D8a15a430"}]"#;
    request_rtt(
        &format!("{target}/eth/v1/validator/prepare_beacon_proposer"),
        Method::POST,
        Some(body.into()),
        reqwest::StatusCode::OK,
    )
    .await
}

async fn req_config_spec(target: &str) -> CliResult<StdDuration> {
    request_rtt(
        &format!("{target}/eth/v1/config/spec"),
        Method::GET,
        None,
        reqwest::StatusCode::OK,
    )
    .await
}

async fn req_node_version(target: &str) -> CliResult<StdDuration> {
    request_rtt(
        &format!("{target}/eth/v1/node/version"),
        Method::GET,
        None,
        reqwest::StatusCode::OK,
    )
    .await
}

async fn req_get_attestation_data(
    target: &str,
    slot: u64,
    committee_index: u64,
) -> CliResult<StdDuration> {
    request_rtt(&format!("{target}/eth/v1/validator/attestation_data?slot={slot}&committee_index={committee_index}"), Method::GET, None, reqwest::StatusCode::OK).await
}

async fn req_submit_attestation_object(target: &str) -> CliResult<StdDuration> {
    let body = r#"{{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}}"#;
    request_rtt(
        &format!("{target}/eth/v1/beacon/pool/attestations"),
        Method::POST,
        Some(body.into()),
        reqwest::StatusCode::BAD_REQUEST,
    )
    .await
}

async fn req_get_aggregate_attestations(
    target: &str,
    slot: u64,
    attestation_data_root: &str,
) -> CliResult<StdDuration> {
    request_rtt(&format!("{target}/eth/v1/validator/aggregate_attestation?slot={slot}&attestation_data_root={attestation_data_root}"), Method::GET, None, reqwest::StatusCode::NOT_FOUND).await
}

async fn req_post_aggregate_and_proofs(target: &str) -> CliResult<StdDuration> {
    let body = r#"[{"message":{"aggregator_index":"1","aggregate":{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"selection_proof":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}]"#;
    request_rtt(
        &format!("{target}/eth/v1/validator/aggregate_and_proofs"),
        Method::POST,
        Some(body.into()),
        reqwest::StatusCode::BAD_REQUEST,
    )
    .await
}

async fn req_produce_block(target: &str, slot: u64, randao_reveal: &str) -> CliResult<StdDuration> {
    request_rtt(
        &format!("{target}/eth/v3/validator/blocks/{slot}?randao_reveal={randao_reveal}"),
        Method::GET,
        None,
        reqwest::StatusCode::OK,
    )
    .await
}

async fn req_publish_blinded_block(target: &str) -> CliResult<StdDuration> {
    let body = r#"{"message":{"slot":"2872079","proposer_index":"1725813","parent_root":"0x05bea9b8e9cc28c4efa5586b4efac20b7a42c3112dbe144fb552b37ded249abd","state_root":"0x0138e6e8e956218aa534597a450a93c2c98f07da207077b4be05742279688da2","body":{"randao_reveal":"0x9880dad5a0e900906a1355da0697821af687b4c2cd861cd219f2d779c50a47d3c0335c08d840c86c167986ae0aaf50070b708fe93a83f66c99a4f931f9a520aebb0f5b11ca202c3d76343e30e49f43c0479e850af0e410333f7c59c4d37fa95a","eth1_data":{"deposit_root":"0x7dbea1a0af14d774da92d94a88d3bb1ae7abad16374da4db2c71dd086c84029e","deposit_count":"452100","block_hash":"0xc4bf450c9e362dcb2b50e76b45938c78d455acd1e1aec4e1ce4338ec023cd32a"},"graffiti":"0x636861726f6e2f76312e312e302d613139336638340000000000000000000000","proposer_slashings":[],"attester_slashings":[],"attestations":[{"aggregation_bits":"0xdbedbfa74eccaf3d7ef570bfdbbf84b4dffc5beede1c1f8b59feb8b3f2fbabdbdef3ceeb7b3dfdeeef8efcbdcd7bebbeff7adfff5ae3bf66bc5613feffef3deb987f7e7fff87ed6f8bbd1fffa57f1677efff646f0d3bd79fffdc5dfd78df6cf79fb7febff5dfdefb8e03","data":{"slot":"2872060","index":"12","beacon_block_root":"0x310506169f7f92dcd2bf00e8b4c2daac999566929395120fbbf4edd222e003eb","source":{"epoch":"89750","root":"0xcdb449d69e3e2d22378bfc2299ee1e9aeb1b2d15066022e854759dda73d1e219"},"target":{"epoch":"89751","root":"0x4ad0882f7adbb735c56b0b3f09d8e45dbd79db9528110f7117ec067f3a19eb0e"}},"signature":"0xa9d91d6cbc669ffcc8ba2435c633e0ec0eebecaa3acdcaa1454282ece1f816e8b853f00ba67ec1244703221efae4c834012819ca7b199354669f24ba8ab1c769f072c9f46b803082eac32e3611cd323eeb5b17fcd6201b41f3063834ff26ef53"}],"deposits":[],"voluntary_exits":[],"sync_aggregate":{"sync_committee_bits":"0xf9ff3ff7ffffb7dbfefddff5fffffefdbffffffffffedfefffffff7fbe9fdffffdb5feffffffbfdbefff3ffdf7f3fc6ff7fffbffff9df6fbbaf3beffefffffff","sync_committee_signature":"0xa9cf7d9f23a62e84f11851e2e4b3b929b1d03719a780b59ecba5daf57e21a0ceccaf13db4e1392a42e3603abeb839a2d16373dcdd5e696f11c5a809972c1e368d794f1c61d4d10b220df52616032f09b33912febf8c7a64f3ce067ab771c7ddf"},"execution_payload_header":{"parent_hash":"0x71c564f4a0c1dea921e8063fc620ccfa39c1b073e4ac0845ce7e9e6f909752de","fee_recipient":"0x148914866080716b10D686F5570631Fbb2207002","state_root":"0x89e74be562cd4a10eb20cdf674f65b1b0e53b33a7c3f2df848eb4f7e226742e0","receipts_root":"0x55b494ee1bb919e7abffaab1d5be05a109612c59a77406d929d77c0ce714f21d","logs_bloom":"0x20500886140245d001002010680c10411a2540420182810440a108800fc008440801180020011008004045005a2007826802e102000005c0c04030590004044810d0d20745c0904a4d583008a01758018001082024e40046000410020042400100012260220299a8084415e20002891224c132220010003a00006010020ed0c108920a13c0e200a1a00251100888c01408008132414068c88b028920440248209a280581a0e10800c14ea63082c1781308208b130508d4000400802d1224521094260912473404012810001503417b4050141100c1103004000c8900644560080472688450710084088800c4c80000c02008931188204c008009011784488060","prev_randao":"0xf4e9a4a7b88a3d349d779e13118b6d099f7773ec5323921343ac212df19c620f","block_number":"2643688","gas_limit":"30000000","gas_used":"24445884","timestamp":"1730367348","extra_data":"0x546974616e2028746974616e6275696c6465722e78797a29","base_fee_per_gas":"122747440","block_hash":"0x7524d779d328159e4d9ee8a4b04c4b251261da9a6da1d1461243125faa447227","transactions_root":"0x7e8a3391a77eaea563bf4e0ca4cf3190425b591ed8572818924c38f7e423c257","withdrawals_root":"0x61a5653b614ec3db0745ae5568e6de683520d84bc3db2dedf6a5158049cee807","blob_gas_used":"0","excess_blob_gas":"0"},"bls_to_execution_changes":[],"blob_kzg_commitments":[]}},"signature":"0x94320e6aecd65da3ef3e55e45208978844b262fe21cacbb0a8448b2caf21e8619b205c830116d8aad0a2c55d879fb571123a3fcf31b515f9508eb346ecd3de2db07cea6700379c00831cfb439f4aeb3bfa164395367c8d8befb92aa6682eae51"}"#;
    request_rtt(
        &format!("{target}/eth/v2/beacon/blinded"),
        Method::POST,
        Some(body.into()),
        reqwest::StatusCode::NOT_FOUND,
    )
    .await
}

async fn req_submit_sync_committee(target: &str) -> CliResult<StdDuration> {
    let body = r#"{{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}}"#;
    request_rtt(
        &format!("{target}/eth/v1/beacon/pool/sync_committees"),
        Method::POST,
        Some(body.into()),
        reqwest::StatusCode::BAD_REQUEST,
    )
    .await
}

async fn req_produce_sync_committee_contribution(
    target: &str,
    slot: u64,
    subcommittee_index: u64,
    beacon_block_root: &str,
) -> CliResult<StdDuration> {
    request_rtt(&format!("{target}/eth/v1/validator/sync_committee_contribution?slot={slot}&subcommittee_index={subcommittee_index}&beacon_block_root={beacon_block_root}"), Method::GET, None, reqwest::StatusCode::NOT_FOUND).await
}

async fn req_sync_committee_subscription(target: &str) -> CliResult<StdDuration> {
    let body = r#"[{"message":{"aggregator_index":"1","aggregate":{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"selection_proof":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}]"#;
    request_rtt(
        &format!("{target}/eth/v1/validator/sync_committee_subscriptions"),
        Method::POST,
        Some(body.into()),
        reqwest::StatusCode::BAD_REQUEST,
    )
    .await
}

async fn req_submit_sync_committee_contribution(target: &str) -> CliResult<StdDuration> {
    let body = r#"[{"message":{"aggregator_index":"1","contribution":{"slot":"1","beacon_block_root":"0xace2cad95a1b113457ccc680372880694a3ef820584d04a165aa2bda0f261950","subcommittee_index":"3","aggregation_bits":"0xfffffbfff7ddffffbef3bfffebffff7f","signature":"0xaa4cf0db0677555025fe12223572e67b509b0b24a2b07dc162aed38522febb2a64ad293e6dbfa1b81481eec250a2cdb61619456291f8d0e3f86097a42a71985d6dabd256107af8b4dfc2982a7d67ac63e2d6b7d59d24a9e87546c71b9c68ca1f"},"selection_proof":"0xb177453ba19233da0625b354d6a43e8621b676243ec4aa5dbb269ac750079cc23fced007ea6cdc1bfb6cc0e2fc796fbb154abed04d9aac7c1171810085beff2b9e5cff961975dbdce4199f39d97b4c46339e26eb7946762394905dbdb9818afe"},"signature":"0x8f73f3185164454f6807549bcbf9d1b0b5516279f35ead1a97812da5db43088de344fdc46aaafd20650bd6685515fb4e18f9f053e9e3691065f8a87f6160456ef8aa550f969ef8260368aae3e450e8763c6317f40b09863ad9b265a0e618e472"}]"#;
    request_rtt(
        &format!("{target}/eth/v1/validator/contribution_and_proofs"),
        Method::POST,
        Some(body.into()),
        reqwest::StatusCode::OK,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn default_test_config() -> TestConfigArgs {
        TestConfigArgs {
            output_json: String::new(),
            quiet: false,
            test_cases: None,
            timeout: StdDuration::from_secs(60),
            publish: false,
            publish_addr: String::new(),
            publish_private_key_file: std::path::PathBuf::new(),
        }
    }

    fn default_beacon_args(endpoints: Vec<String>) -> TestBeaconArgs {
        TestBeaconArgs {
            test_config: default_test_config(),
            endpoints,
            load_test: false,
            load_test_duration: StdDuration::from_secs(5),
            simulation_duration: SLOTS_IN_EPOCH.get(),
            simulation_file_dir: std::path::PathBuf::from("./"),
            simulation_verbose: false,
            simulation_custom: 0,
        }
    }

    async fn start_healthy_mocked_beacon_node() -> MockServer {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    r#"{"data":{"head_slot":"0","sync_distance":"0","is_optimistic":false,"is_syncing":false}}"#,
                ),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"meta":{"count":500}}"#))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/version"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"version":"BeaconNodeProvider/v1.0.0/linux_x86_64"}}"#,
            ))
            .mount(&server)
            .await;

        server
    }

    fn expected_results_for_healthy_node() -> Vec<(&'static str, TestVerdict)> {
        vec![
            ("Ping", TestVerdict::Ok),
            ("PingMeasure", TestVerdict::Good),
            ("Version", TestVerdict::Ok),
            ("Synced", TestVerdict::Ok),
            ("PeerCount", TestVerdict::Good),
            ("PingLoad", TestVerdict::Skip),
            ("Simulate1", TestVerdict::Skip),
            ("Simulate10", TestVerdict::Skip),
            ("Simulate100", TestVerdict::Skip),
            ("Simulate500", TestVerdict::Skip),
            ("Simulate1000", TestVerdict::Skip),
            ("SimulateCustom", TestVerdict::Skip),
        ]
    }

    fn assert_results(
        results: &std::collections::HashMap<String, Vec<TestResult>>,
        target: &str,
        expected: &[(&str, TestVerdict)],
    ) {
        let target_results = results.get(target).expect("missing target in results");
        assert_eq!(
            target_results.len(),
            expected.len(),
            "result count mismatch for {target}"
        );
        for (result, (name, verdict)) in target_results.iter().zip(expected) {
            assert_eq!(result.name, *name, "name mismatch");
            assert_eq!(result.verdict, *verdict, "verdict mismatch for {name}");
        }
    }

    #[tokio::test]
    async fn test_beacon_default_scenario() {
        let server = start_healthy_mocked_beacon_node().await;
        let url = server.uri();
        let args = default_beacon_args(vec![url.clone()]);

        let mut buf = Vec::new();
        let res = run(args, &mut buf, CancellationToken::new()).await.unwrap();

        let expected = expected_results_for_healthy_node();
        assert_results(&res.targets, &url, &expected);
    }

    #[tokio::test]
    async fn test_beacon_connection_refused() {
        let port1 = 19876;
        let port2 = 19877;
        let endpoint1 = format!("http://localhost:{port1}");
        let endpoint2 = format!("http://localhost:{port2}");
        let args = default_beacon_args(vec![endpoint1.clone(), endpoint2.clone()]);

        let mut buf = Vec::new();
        let res = run(args, &mut buf, CancellationToken::new()).await.unwrap();

        for endpoint in [&endpoint1, &endpoint2] {
            let target_results = res.targets.get(endpoint).expect("missing target");
            for r in target_results {
                match r.name.as_str() {
                    "PingLoad" | "Simulate1" | "Simulate10" | "Simulate100" | "Simulate500"
                    | "Simulate1000" | "SimulateCustom" => {
                        assert_eq!(r.verdict, TestVerdict::Skip, "expected skip for {}", r.name);
                    }
                    _ => {
                        assert_eq!(r.verdict, TestVerdict::Fail, "expected fail for {}", r.name);
                        assert!(
                            r.error.message().is_some(),
                            "expected error message for {}",
                            r.name
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_beacon_timeout() {
        let endpoint1 = "http://localhost:19878".to_string();
        let endpoint2 = "http://localhost:19879".to_string();
        let mut args = default_beacon_args(vec![endpoint1.clone(), endpoint2.clone()]);
        args.test_config.timeout = StdDuration::from_nanos(100);

        let mut buf = Vec::new();
        let res = run(args, &mut buf, CancellationToken::new()).await.unwrap();

        for endpoint in [&endpoint1, &endpoint2] {
            let target_results = res.targets.get(endpoint).expect("missing target");
            let first = &target_results[0];
            assert_eq!(first.name, "Ping");
            assert_eq!(first.verdict, TestVerdict::Fail);
        }
    }

    #[tokio::test]
    async fn test_beacon_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("output.json");

        let endpoint1 = "http://localhost:19880".to_string();
        let endpoint2 = "http://localhost:19881".to_string();
        let mut args = default_beacon_args(vec![endpoint1, endpoint2]);
        args.test_config.quiet = true;
        args.test_config.output_json = json_path.to_str().unwrap().to_string();

        let mut buf = Vec::new();
        let res = run(args, &mut buf, CancellationToken::new()).await.unwrap();

        assert!(buf.is_empty(), "expected no output on quiet mode");
        assert!(!res.targets.is_empty());
    }

    #[tokio::test]
    async fn test_beacon_unsupported_test() {
        let args = TestBeaconArgs {
            test_config: TestConfigArgs {
                test_cases: Some(vec!["notSupportedTest".to_string()]),
                ..default_test_config()
            },
            ..default_beacon_args(vec!["http://localhost:19882".to_string()])
        };

        let mut buf = Vec::new();
        let err = run(args, &mut buf, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("test case not supported"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_beacon_custom_test_cases() {
        let endpoint1 = "http://localhost:19883".to_string();
        let endpoint2 = "http://localhost:19884".to_string();
        let mut args = default_beacon_args(vec![endpoint1.clone(), endpoint2.clone()]);
        args.test_config.test_cases = Some(vec!["Ping".to_string()]);

        let mut buf = Vec::new();
        let res = run(args, &mut buf, CancellationToken::new()).await.unwrap();

        for endpoint in [&endpoint1, &endpoint2] {
            let target_results = res.targets.get(endpoint).expect("missing target");
            assert_eq!(target_results.len(), 1);
            assert_eq!(target_results[0].name, "Ping");
            assert_eq!(target_results[0].verdict, TestVerdict::Fail);
        }
    }

    #[tokio::test]
    async fn test_beacon_write_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("beacon-test-output.json");

        let endpoint1 = "http://localhost:19885".to_string();
        let endpoint2 = "http://localhost:19886".to_string();
        let mut args = default_beacon_args(vec![endpoint1, endpoint2]);
        args.test_config.output_json = file_path.to_str().unwrap().to_string();

        let mut buf = Vec::new();
        let res = run(args, &mut buf, CancellationToken::new()).await.unwrap();

        assert!(file_path.exists(), "output file should exist");

        let content = std::fs::read_to_string(&file_path).unwrap();
        let written: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(
            written.get("beacon_node").is_some(),
            "expected beacon_node key in output JSON"
        );

        assert_eq!(res.category_name, Some(TestCategory::Beacon));
        assert!(res.score.is_some());
    }

    #[tokio::test]
    async fn test_beacon_basic_auth_with_credentials() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/health"))
            .and(wiremock::matchers::header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let addr = server.address();
        let url_with_auth = format!("http://testuser:testpass123@{addr}");

        let cancel = CancellationToken::new();
        let cfg = default_beacon_args(vec![]);
        let result = beacon_ping_test(cancel, cfg, &url_with_auth).await;

        assert_eq!(result.verdict, TestVerdict::Ok);
    }

    #[tokio::test]
    async fn test_beacon_basic_auth_without_credentials() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let url_without_auth = server.uri();

        let cancel = CancellationToken::new();
        let cfg = default_beacon_args(vec![]);
        let result = beacon_ping_test(cancel, cfg, &url_without_auth).await;

        // Without credentials the request still succeeds (no auth enforcement by
        // request_rtt), but no Authorization header is sent.
        assert_eq!(result.verdict, TestVerdict::Ok);

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].headers.get("Authorization").is_none(),
            "Authorization header should not be present without credentials"
        );
    }
}
