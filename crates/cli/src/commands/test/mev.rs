//! MEV relay tests.

use std::{collections::HashMap, io::Write, time::Duration};

use reqwest::{Method, StatusCode};
use tokio::{task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::{
    AllCategoriesResult, TestCategory, TestCategoryResult, TestConfigArgs, TestResult, TestVerdict,
    calculate_score,
    constants::{SLOT_TIME, SLOTS_IN_EPOCH},
    evaluate_rtt, must_output_to_file_on_quiet, publish_result_to_obol_api, request_rtt,
    write_result_to_file, write_result_to_writer,
};
use crate::{
    commands::test::TestCaseName,
    duration::Duration as CliDuration,
    error::{CliError, MevTestError, Result},
};
use clap::Args;

/// Thresholds for MEV ping measure test.
const THRESHOLD_MEV_MEASURE_AVG: Duration = Duration::from_millis(40);
/// Threshold for poor MEV ping measure.
const THRESHOLD_MEV_MEASURE_POOR: Duration = Duration::from_millis(100);
/// Threshold for average MEV block creation RTT.
const THRESHOLD_MEV_BLOCK_AVG: Duration = Duration::from_millis(500);
/// Threshold for poor MEV block creation RTT.
const THRESHOLD_MEV_BLOCK_POOR: Duration = Duration::from_millis(800);

/// Arguments for the MEV test command.
#[derive(Args, Clone, Debug)]
pub struct TestMevArgs {
    #[command(flatten)]
    pub test_config: TestConfigArgs,

    /// Comma separated list of one or more MEV relay endpoint URLs.
    #[arg(
        long = "endpoints",
        value_delimiter = ',',
        required = true,
        help = "Comma separated list of one or more MEV relay endpoint URLs."
    )]
    pub endpoints: Vec<String>,

    /// Beacon node endpoint URL used for block creation test.
    #[arg(
        long = "beacon-node-endpoint",
        help = "[REQUIRED] Beacon node endpoint URL used for block creation test."
    )]
    pub beacon_node_endpoint: Option<String>,

    /// Enable load test.
    #[arg(long = "load-test", help = "Enable load test.")]
    pub load_test: bool,

    /// Increases the accuracy of the load test by asking for multiple payloads.
    #[arg(
        long = "number-of-payloads",
        default_value = "1",
        help = "Increases the accuracy of the load test by asking for multiple payloads. Increases test duration."
    )]
    pub number_of_payloads: u32,
}

#[derive(Debug, Clone)]
enum TestCaseMev {
    Ping,
    PingMeasure,
    CreateBlock,
}

impl TestCaseMev {
    fn all() -> Vec<TestCaseMev> {
        vec![Self::Ping, Self::PingMeasure, Self::CreateBlock]
    }

    fn test_case_name(&self) -> TestCaseName {
        match self {
            TestCaseMev::Ping => TestCaseName::new("Ping", 1),
            TestCaseMev::PingMeasure => TestCaseName::new("PingMeasure", 2),
            TestCaseMev::CreateBlock => TestCaseName::new("CreateBlock", 3),
        }
    }

    async fn run(&self, target: &str, conf: &TestMevArgs) -> TestResult {
        match self {
            TestCaseMev::Ping => mev_ping_test(target, conf).await,
            TestCaseMev::PingMeasure => mev_ping_measure_test(target, conf).await,
            TestCaseMev::CreateBlock => mev_create_block_test(target, conf).await,
        }
    }
}

/// Runs the MEV relay tests.
pub async fn run(
    args: TestMevArgs,
    writer: &mut dyn Write,
    token: CancellationToken,
) -> Result<TestCategoryResult> {
    must_output_to_file_on_quiet(args.test_config.quiet, &args.test_config.output_json)?;

    // Validate flag combinations.
    if args.load_test && args.beacon_node_endpoint.is_none() {
        return Err(MevTestError::BeaconNodeEndpointRequired.into());
    }
    if !args.load_test && args.beacon_node_endpoint.is_some() {
        return Err(MevTestError::BeaconNodeEndpointNotAllowed.into());
    }

    info!("Starting MEV relays test");

    let queued_tests = {
        let mut filtered = TestCaseMev::all().to_vec();
        if let Some(filtered_cases) = args.test_config.test_cases.as_ref() {
            filtered.retain(|case| {
                filtered_cases
                    .iter()
                    .any(|s| s == case.test_case_name().name)
            });
        }
        filtered
    };
    if queued_tests.is_empty() {
        return Err(CliError::TestCaseNotSupported);
    }

    let token = token.child_token();
    tokio::spawn({
        let token = token.clone();
        async move {
            tokio::time::sleep(args.test_config.timeout).await;
            token.cancel();
        }
    });

    let start_time = Instant::now();
    let test_results = test_all_mevs(&queued_tests, &args, token).await;
    let exec_time = CliDuration::new(start_time.elapsed());

    let score = test_results
        .values()
        .map(|results| calculate_score(results))
        .min();

    let res = TestCategoryResult {
        category_name: Some(TestCategory::Mev),
        targets: test_results,
        execution_time: Some(exec_time),
        score,
    };

    if !args.test_config.quiet {
        write_result_to_writer(&res, writer)?;
    }

    if !args.test_config.output_json.is_empty() {
        write_result_to_file(&res, args.test_config.output_json.as_ref()).await?;
    }

    if args.test_config.publish {
        publish_result_to_obol_api(
            AllCategoriesResult {
                mev: Some(res.clone()),
                ..Default::default()
            },
            &args.test_config.publish_addr,
            &args.test_config.publish_private_key_file,
        )
        .await?;
    }

    Ok(res)
}

async fn test_all_mevs(
    queued_tests: &[TestCaseMev],
    conf: &TestMevArgs,
    token: CancellationToken,
) -> HashMap<String, Vec<TestResult>> {
    let mut join_set = JoinSet::new();

    for endpoint in &conf.endpoints {
        let queued_tests = queued_tests.to_vec();
        let conf = conf.clone();
        let endpoint = endpoint.clone();
        let token = token.clone();

        join_set.spawn(async move {
            let results = test_single_mev(&queued_tests, &conf, &endpoint, token).await;
            let relay_name = format_mev_relay_name(&endpoint);
            (relay_name, results)
        });
    }

    let all_results = join_set.join_all().await;
    all_results.into_iter().collect::<HashMap<_, _>>()
}

async fn test_single_mev(
    queued_tests: &[TestCaseMev],
    conf: &TestMevArgs,
    target: &str,
    token: CancellationToken,
) -> Vec<TestResult> {
    let mut join_set = JoinSet::new();

    let queued_tests = queued_tests.to_vec();
    for test_case in queued_tests {
        let token = token.clone();
        let conf = conf.clone();
        let target = target.to_string();

        join_set.spawn(async move {
            let tc_name = test_case.test_case_name();
            tokio::select! {
                _ = token.cancelled() => {
                    let tr = TestResult::new(tc_name.name);
                    tr.fail(CliError::TimeoutInterrupted)
                }
                r = test_case.run(&target, &conf) => {
                    r
                }
            }
        });
    }

    join_set.join_all().await
}

async fn mev_ping_test(target: &str, _conf: &TestMevArgs) -> TestResult {
    let test_res = TestResult::new("Ping");
    let url = format!("{target}/eth/v1/builder/status");
    let client = reqwest::Client::new();

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return test_res.fail(e),
    };

    if resp.status().as_u16() > 399 {
        return test_res.fail(MevTestError::HttpStatus(resp.status().as_u16()));
    }

    test_res.ok()
}

async fn mev_ping_measure_test(target: &str, _conf: &TestMevArgs) -> TestResult {
    let test_res = TestResult::new("PingMeasure");
    let url = format!("{target}/eth/v1/builder/status");

    let rtt = match request_rtt(&url, Method::GET, None, StatusCode::OK).await {
        Ok(r) => r,
        Err(e) => return test_res.fail(e),
    };

    evaluate_rtt(
        rtt,
        test_res,
        THRESHOLD_MEV_MEASURE_AVG,
        THRESHOLD_MEV_MEASURE_POOR,
    )
}

async fn mev_create_block_test(target: &str, conf: &TestMevArgs) -> TestResult {
    let test_res = TestResult::new("CreateBlock");

    if !conf.load_test {
        return TestResult {
            verdict: TestVerdict::Skip,
            ..test_res
        };
    }

    let beacon_endpoint = match &conf.beacon_node_endpoint {
        Some(ep) => ep.as_str(),
        None => {
            return test_res.fail(MevTestError::BeaconNodeEndpointRequired);
        }
    };

    let latest_block = match latest_beacon_block(beacon_endpoint).await {
        Ok(b) => b,
        Err(e) => return test_res.fail(e),
    };

    let latest_block_ts_unix: i64 = match latest_block.body.execution_payload.timestamp.parse() {
        Ok(v) => v,
        Err(e) => return test_res.fail(MevTestError::ParseTimestamp(e.to_string())),
    };

    let latest_block_ts = match std::time::UNIX_EPOCH
        .checked_add(Duration::from_secs(latest_block_ts_unix.unsigned_abs()))
    {
        Some(ts) => ts,
        None => return test_res.fail(MevTestError::TimestampOverflow),
    };
    let next_block_ts = match latest_block_ts.checked_add(SLOT_TIME) {
        Some(ts) => ts,
        None => return test_res.fail(MevTestError::NextBlockTimestampOverflow),
    };

    if let Ok(remaining) = next_block_ts.duration_since(std::time::SystemTime::now()) {
        tokio::time::sleep(remaining).await;
    }

    let latest_slot: i64 = match latest_block.slot.parse() {
        Ok(v) => v,
        Err(e) => return test_res.fail(MevTestError::ParseSlot(e.to_string())),
    };

    let mut next_slot = latest_slot.saturating_add(1);
    let slots_in_epoch_i64 = match i64::try_from(SLOTS_IN_EPOCH.get()) {
        Ok(v) => v,
        Err(e) => return test_res.fail(MevTestError::SlotsInEpochConversion(e.to_string())),
    };
    let epoch = match next_slot.checked_div(slots_in_epoch_i64) {
        Some(v) => v,
        None => return test_res.fail(MevTestError::EpochCalculationOverflow),
    };

    let mut proposer_duties = match fetch_proposers_for_epoch(beacon_endpoint, epoch).await {
        Ok(d) => d,
        Err(e) => return test_res.fail(e),
    };

    let mut all_blocks_rtt: Vec<Duration> = Vec::new();

    info!(
        mev_relay = target,
        blocks = conf.number_of_payloads,
        "Starting attempts for block creation"
    );

    let mut latest_block = latest_block;

    loop {
        let start_iteration = Instant::now();

        let rtt = match create_mev_block(
            conf,
            target,
            next_slot,
            &mut latest_block,
            &mut proposer_duties,
            beacon_endpoint,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => return test_res.fail(e),
        };

        all_blocks_rtt.push(rtt);
        if all_blocks_rtt.len() == conf.number_of_payloads as usize {
            break;
        }

        let elapsed = start_iteration.elapsed();
        let elapsed_nanos = match u64::try_from(elapsed.as_nanos()) {
            Ok(v) => v,
            Err(e) => {
                return test_res.fail(MevTestError::ElapsedNanosConversion(e.to_string()));
            }
        };
        let slot_nanos = SLOT_TIME.as_nanos() as u64;
        let remainder_nanos = elapsed_nanos.checked_rem(slot_nanos).unwrap_or(0);
        let slot_remainder = SLOT_TIME
            .checked_sub(Duration::from_nanos(remainder_nanos))
            .unwrap_or_default();
        if let Some(sleep_dur) = slot_remainder.checked_sub(Duration::from_secs(1)) {
            tokio::time::sleep(sleep_dur).await;
        }

        let start_beacon_fetch = Instant::now();
        latest_block = match latest_beacon_block(beacon_endpoint).await {
            Ok(b) => b,
            Err(e) => return test_res.fail(e),
        };

        let latest_slot_parsed: i64 = match latest_block.slot.parse() {
            Ok(v) => v,
            Err(e) => return test_res.fail(MevTestError::ParseSlot(e.to_string())),
        };

        next_slot = latest_slot_parsed.saturating_add(1);

        // Wait 1 second minus how long the fetch took.
        if let Some(sleep_dur) = Duration::from_secs(1).checked_sub(start_beacon_fetch.elapsed()) {
            tokio::time::sleep(sleep_dur).await;
        }
    }

    if all_blocks_rtt.is_empty() {
        return test_res.fail(CliError::TimeoutInterrupted);
    }

    let total_rtt: Duration = all_blocks_rtt.iter().sum();
    let count = match u32::try_from(all_blocks_rtt.len().max(1)) {
        Ok(v) => v,
        Err(e) => return test_res.fail(MevTestError::BlockCountConversion(e.to_string())),
    };
    let average_rtt = total_rtt.checked_div(count).unwrap_or_default();

    evaluate_rtt(
        average_rtt,
        test_res,
        THRESHOLD_MEV_BLOCK_AVG,
        THRESHOLD_MEV_BLOCK_POOR,
    )
}

// Helper types
#[derive(Debug, Clone, serde::Deserialize)]
struct BeaconBlock {
    data: BeaconBlockData,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BeaconBlockData {
    message: BeaconBlockMessage,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BeaconBlockMessage {
    slot: String,
    body: BeaconBlockBody,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BeaconBlockBody {
    execution_payload: BeaconBlockExecPayload,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BeaconBlockExecPayload {
    block_hash: String,
    timestamp: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ProposerDuties {
    data: Vec<ProposerDutiesData>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ProposerDutiesData {
    pubkey: String,
    slot: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BuilderBidResponse {
    version: String,
    data: serde_json::Value,
}

async fn latest_beacon_block(endpoint: &str) -> Result<BeaconBlockMessage> {
    let url = format!("{endpoint}/eth/v2/beacon/blocks/head");
    let resp = reqwest::Client::new().get(&url).send().await?;
    let body = resp.bytes().await?;
    let block: BeaconBlock = serde_json::from_slice(&body)?;

    Ok(block.data.message)
}

async fn fetch_proposers_for_epoch(
    beacon_endpoint: &str,
    epoch: i64,
) -> Result<Vec<ProposerDutiesData>> {
    let url = format!("{beacon_endpoint}/eth/v1/validator/duties/proposer/{epoch}");
    let resp = reqwest::Client::new().get(&url).send().await?;
    let body = resp.bytes().await?;
    let duties: ProposerDuties = serde_json::from_slice(&body)?;

    Ok(duties.data)
}

fn get_validator_pk_for_slot(proposers: &[ProposerDutiesData], slot: i64) -> Option<String> {
    let slot_str = slot.to_string();
    proposers
        .iter()
        .find(|p| p.slot == slot_str)
        .map(|p| p.pubkey.clone())
}

async fn get_block_header(
    target: &str,
    next_slot: i64,
    block_hash: &str,
    validator_pub_key: &str,
) -> Result<(BuilderBidResponse, Duration)> {
    let url =
        format!("{target}/eth/v1/builder/header/{next_slot}/{block_hash}/{validator_pub_key}");

    let start = Instant::now();

    let resp = reqwest::Client::new().get(&url).send().await?;

    let rtt = start.elapsed();

    if resp.status() != StatusCode::OK {
        return Err(MevTestError::StatusCodeNot200.into());
    }

    let body = resp.bytes().await?;

    let bid: BuilderBidResponse = serde_json::from_slice(&body)?;

    Ok((bid, rtt))
}

async fn create_mev_block(
    _conf: &TestMevArgs,
    target: &str,
    mut next_slot: i64,
    latest_block: &mut BeaconBlockMessage,
    proposer_duties: &mut Vec<ProposerDutiesData>,
    beacon_endpoint: &str,
) -> Result<Duration> {
    let rtt_get_header;
    let builder_bid;

    loop {
        let start_iteration = Instant::now();
        let slots_in_epoch_i64 = i64::try_from(SLOTS_IN_EPOCH.get())
            .map_err(|e| MevTestError::SlotsInEpochConversion(e.to_string()))?;
        let epoch = next_slot
            .checked_div(slots_in_epoch_i64)
            .ok_or(MevTestError::EpochCalculationOverflow)?;

        let pk = if let Some(pk) = get_validator_pk_for_slot(proposer_duties, next_slot) {
            pk
        } else {
            *proposer_duties = fetch_proposers_for_epoch(beacon_endpoint, epoch).await?;
            get_validator_pk_for_slot(proposer_duties, next_slot)
                .ok_or(MevTestError::SlotNotFound)?
        };

        match get_block_header(
            target,
            next_slot,
            &latest_block.body.execution_payload.block_hash,
            &pk,
        )
        .await
        {
            Ok((bid, rtt)) => {
                builder_bid = bid;
                rtt_get_header = rtt;

                info!(
                    slot = next_slot,
                    target = target,
                    "Created block headers for slot"
                );
                break;
            }

            Err(CliError::MevTest(MevTestError::StatusCodeNot200)) => {
                let elapsed = start_iteration.elapsed();
                if let Some(sleep_dur) = SLOT_TIME.checked_sub(elapsed)
                    && let Some(sleep_dur) = sleep_dur.checked_sub(Duration::from_secs(1))
                {
                    tokio::time::sleep(sleep_dur).await;
                }

                let start_beacon_fetch = Instant::now();
                *latest_block = latest_beacon_block(beacon_endpoint).await?;
                next_slot = next_slot.saturating_add(1);

                if let Some(sleep_dur) =
                    Duration::from_secs(1).checked_sub(start_beacon_fetch.elapsed())
                {
                    tokio::time::sleep(sleep_dur).await;
                }

                continue;
            }
            Err(e) => return Err(e),
        }
    }

    let payload = build_blinded_block_payload(&builder_bid)?;
    let payload_json =
        serde_json::to_vec(&payload).map_err(|e| MevTestError::PayloadMarshal(e.to_string()))?;

    let rtt_submit_block = request_rtt(
        format!("{target}/eth/v1/builder/blinded_blocks"),
        Method::POST,
        Some(payload_json),
        StatusCode::BAD_REQUEST,
    )
    .await?;

    Ok(rtt_get_header
        .checked_add(rtt_submit_block)
        .unwrap_or(rtt_get_header))
}

fn build_blinded_block_payload(bid: &BuilderBidResponse) -> Result<serde_json::Value> {
    let sig_hex = "0xb9251a82040d4620b8c5665f328ee6c2eaa02d31d71d153f4abba31a7922a981e541e85283f0ced387d26e86aef9386d18c6982b9b5f8759882fe7f25a328180d86e146994ef19d28bc1432baf29751dec12b5f3d65dbbe224d72cf900c6831a";

    let header = extract_execution_payload_header(&bid.data, &bid.version)?;

    let zero_hash = "0x0000000000000000000000000000000000000000000000000000000000000000";
    let zero_sig = "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    let mut body = serde_json::json!({
        "randao_reveal": zero_sig,
        "eth1_data": {
            "deposit_root": zero_hash,
            "deposit_count": "0",
            "block_hash": zero_hash
        },
        "graffiti": zero_hash,
        "proposer_slashings": [],
        "attester_slashings": [],
        "attestations": [],
        "deposits": [],
        "voluntary_exits": [],
        "sync_aggregate": {
            "sync_committee_bits": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "sync_committee_signature": zero_sig
        },
        "execution_payload_header": header
    });

    let version_lower = bid.version.to_lowercase();

    if matches!(
        version_lower.as_str(),
        "capella" | "deneb" | "electra" | "fulu"
    ) {
        body["bls_to_execution_changes"] = serde_json::json!([]);
    }

    if matches!(version_lower.as_str(), "deneb" | "electra" | "fulu") {
        body["blob_kzg_commitments"] = serde_json::json!([]);
    }

    if matches!(version_lower.as_str(), "electra" | "fulu") {
        body["execution_requests"] = serde_json::json!({
            "deposits": [],
            "withdrawals": [],
            "consolidations": []
        });
    }

    Ok(serde_json::json!({
        "message": {
            "slot": "0",
            "proposer_index": "0",
            "parent_root": zero_hash,
            "state_root": zero_hash,
            "body": body
        },
        "signature": sig_hex
    }))
}

fn extract_execution_payload_header(
    data: &serde_json::Value,
    version: &str,
) -> Result<serde_json::Value> {
    data.get("message")
        .and_then(|m| m.get("header"))
        .cloned()
        .ok_or_else(|| MevTestError::UnsupportedVersionOrMissingHeader(version.to_string()).into())
}

fn format_mev_relay_name(url_string: &str) -> String {
    let Some((scheme, rest)) = url_string.split_once("://") else {
        return url_string.to_string();
    };

    let Some((hash, host)) = rest.split_once('@') else {
        return url_string.to_string();
    };

    if !hash.starts_with("0x") || hash.len() < 18 {
        return url_string.to_string();
    }

    let hash_short = format!("{}...{}", &hash[..6], &hash[hash.len().saturating_sub(4)..]);
    format!("{scheme}://{hash_short}@{host}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;
    use tokio_util::sync::CancellationToken;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    fn refused_addr() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        format!("http://{addr}")
    }

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

    fn default_mev_args(endpoints: Vec<String>) -> TestMevArgs {
        TestMevArgs {
            test_config: default_test_config(),
            endpoints,
            beacon_node_endpoint: None,
            load_test: false,
            number_of_payloads: 1,
        }
    }

    async fn start_healthy_mocked_mev_node() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        server
    }

    fn assert_verdict(
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
        let by_name: std::collections::HashMap<&str, TestVerdict> = target_results
            .iter()
            .map(|r| (r.name.as_str(), r.verdict))
            .collect();
        for (name, verdict) in expected {
            let actual = by_name
                .get(name)
                .unwrap_or_else(|| panic!("missing result for {name}"));
            assert_eq!(*actual, *verdict, "verdict mismatch for {name}");
        }
    }

    #[tokio::test]
    async fn test_mev_default_scenario() {
        let server = start_healthy_mocked_mev_node().await;
        let url = server.uri();
        let args = default_mev_args(vec![url.clone()]);

        let mut buf = Vec::new();
        let res = run(args, &mut buf, CancellationToken::new()).await.unwrap();

        let target_results = res.targets.get(&url).expect("missing target");
        let by_name: std::collections::HashMap<&str, TestVerdict> = target_results
            .iter()
            .map(|r| (r.name.as_str(), r.verdict))
            .collect();

        assert_eq!(by_name["Ping"], TestVerdict::Ok, "Ping should be Ok");
        assert_eq!(
            by_name["CreateBlock"],
            TestVerdict::Skip,
            "CreateBlock should be Skip"
        );
        assert!(
            matches!(
                by_name["PingMeasure"],
                TestVerdict::Good | TestVerdict::Poor
            ),
            "PingMeasure should be Good or Poor, got {:?}",
            by_name.get("PingMeasure")
        );
    }

    #[tokio::test]
    async fn test_mev_connection_refused() {
        let endpoint1 = refused_addr();
        let endpoint2 = refused_addr();
        let args = default_mev_args(vec![endpoint1.clone(), endpoint2.clone()]);

        let mut buf = Vec::new();
        let res = run(args, &mut buf, CancellationToken::new()).await.unwrap();

        for endpoint in [&endpoint1, &endpoint2] {
            let target_results = res.targets.get(endpoint).expect("missing target");
            for r in target_results {
                if r.name == "CreateBlock" {
                    assert_eq!(
                        r.verdict,
                        TestVerdict::Skip,
                        "expected skip for CreateBlock"
                    );
                } else {
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

    #[tokio::test]
    async fn test_mev_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(StdDuration::from_millis(500)))
            .mount(&server)
            .await;

        let url = server.uri();
        let mut args = default_mev_args(vec![url.clone()]);
        args.test_config.timeout = StdDuration::from_millis(10);

        let mut buf = Vec::new();
        let res = run(args, &mut buf, CancellationToken::new()).await.unwrap();

        let target_results = res.targets.get(&url).expect("missing target");
        assert!(!target_results.is_empty());
        for r in target_results {
            let expected = if r.name == "CreateBlock" {
                TestVerdict::Skip
            } else {
                TestVerdict::Fail
            };
            assert_eq!(r.verdict, expected, "verdict mismatch for {}", r.name);
        }
    }

    #[tokio::test]
    async fn test_mev_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("output.json");

        let endpoint1 = refused_addr();
        let endpoint2 = refused_addr();
        let mut args = default_mev_args(vec![endpoint1, endpoint2]);
        args.test_config.quiet = true;
        args.test_config.output_json = json_path.to_str().unwrap().to_string();

        let mut buf = Vec::new();
        run(args, &mut buf, CancellationToken::new()).await.unwrap();

        assert!(buf.is_empty(), "expected no output on quiet mode");
    }

    #[tokio::test]
    async fn test_mev_unsupported_test() {
        let mut args = default_mev_args(vec![refused_addr()]);
        args.test_config.test_cases = Some(vec!["notSupportedTest".to_string()]);

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
    async fn test_mev_custom_test_cases() {
        let endpoint1 = refused_addr();
        let endpoint2 = refused_addr();
        let mut args = default_mev_args(vec![endpoint1.clone(), endpoint2.clone()]);
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
    async fn test_mev_write_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("mev-test-output.json");

        let endpoint1 = refused_addr();
        let endpoint2 = refused_addr();
        let mut args = default_mev_args(vec![endpoint1, endpoint2]);
        args.test_config.output_json = file_path.to_str().unwrap().to_string();

        let mut buf = Vec::new();
        let res = run(args, &mut buf, CancellationToken::new()).await.unwrap();

        assert!(file_path.exists(), "output file should exist");

        let content = std::fs::read_to_string(&file_path).unwrap();
        let written: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(
            written.get("mev").is_some(),
            "expected mev key in output JSON"
        );

        assert_eq!(res.category_name, Some(TestCategory::Mev));
        assert!(res.score.is_some());
    }

    #[test]
    fn format_mev_relay_name_works() {
        assert_eq!(
            format_mev_relay_name(
                "https://0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae@boost-relay.flashbots.net"
            ),
            "https://0xac6e...37ae@boost-relay.flashbots.net"
        );

        assert_eq!(
            format_mev_relay_name("boost-relay.flashbots.net"),
            "boost-relay.flashbots.net"
        );

        assert_eq!(
            format_mev_relay_name("https://boost-relay.flashbots.net"),
            "https://boost-relay.flashbots.net"
        );

        assert_eq!(
            format_mev_relay_name("https://0xshort@boost-relay.flashbots.net"),
            "https://0xshort@boost-relay.flashbots.net"
        );

        assert_eq!(
            format_mev_relay_name("https://noprefixhashvalue1234567890@boost-relay.flashbots.net"),
            "https://noprefixhashvalue1234567890@boost-relay.flashbots.net"
        );
    }

    #[test]
    fn get_validator_pk_for_slot_works() {
        let duties = vec![
            ProposerDutiesData {
                pubkey: "0xabc".to_string(),
                slot: "100".to_string(),
            },
            ProposerDutiesData {
                pubkey: "0xdef".to_string(),
                slot: "101".to_string(),
            },
        ];

        assert_eq!(
            get_validator_pk_for_slot(&duties, 100),
            Some("0xabc".to_string())
        );
        assert_eq!(
            get_validator_pk_for_slot(&duties, 101),
            Some("0xdef".to_string())
        );
        assert_eq!(get_validator_pk_for_slot(&duties, 102), None);
    }
}
