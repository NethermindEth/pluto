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
    error::{CliError, Result},
};
use clap::Args;

/// MEV-specific errors.
#[derive(Debug, thiserror::Error)]
enum MevError {
    /// Relay returned non-200 for the header request.
    #[error("status code not 200 OK")]
    StatusCodeNot200,
    #[error(transparent)]
    Cli(#[from] CliError),
}

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
        return Err(CliError::Other(
            "beacon-node-endpoint required when load-test enabled".to_string(),
        ));
    }
    if !args.load_test && args.beacon_node_endpoint.is_some() {
        return Err(CliError::Other(
            "beacon-node-endpoint only supported when load-test enabled".to_string(),
        ));
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
        return test_res.fail(CliError::Other(http_status_error(resp.status())));
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
            return test_res.fail(CliError::Other("beacon-node-endpoint required".to_string()));
        }
    };

    let latest_block = match latest_beacon_block(beacon_endpoint).await {
        Ok(b) => b,
        Err(e) => return test_res.fail(e),
    };

    let latest_block_ts_unix: i64 = match latest_block.body.execution_payload.timestamp.parse() {
        Ok(v) => v,
        Err(e) => return test_res.fail(CliError::Other(format!("parse timestamp: {e}"))),
    };

    let latest_block_ts = std::time::UNIX_EPOCH
        .checked_add(Duration::from_secs(latest_block_ts_unix.unsigned_abs()))
        .unwrap_or(std::time::UNIX_EPOCH);
    let next_block_ts = latest_block_ts
        .checked_add(SLOT_TIME)
        .unwrap_or(latest_block_ts);

    if let Ok(remaining) = next_block_ts.duration_since(std::time::SystemTime::now()) {
        tokio::time::sleep(remaining).await;
    }

    let latest_slot: i64 = match latest_block.slot.parse() {
        Ok(v) => v,
        Err(e) => return test_res.fail(CliError::Other(format!("parse slot: {e}"))),
    };

    let mut next_slot = latest_slot.saturating_add(1);
    let slots_in_epoch_i64 = i64::try_from(SLOTS_IN_EPOCH.get()).unwrap_or(i64::MAX);
    let epoch = next_slot.checked_div(slots_in_epoch_i64).unwrap_or(0);

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
        if all_blocks_rtt.len() == usize::try_from(conf.number_of_payloads).unwrap_or(usize::MAX) {
            break;
        }

        let elapsed = start_iteration.elapsed();
        let elapsed_nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let slot_nanos = u64::try_from(SLOT_TIME.as_nanos()).unwrap_or(1);
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
            Err(e) => return test_res.fail(CliError::Other(format!("parse slot: {e}"))),
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
    let count = u32::try_from(all_blocks_rtt.len().max(1)).unwrap_or(u32::MAX);
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
) -> std::result::Result<(BuilderBidResponse, Duration), MevError> {
    let url =
        format!("{target}/eth/v1/builder/header/{next_slot}/{block_hash}/{validator_pub_key}");

    let start = Instant::now();

    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| MevError::Cli(e.into()))?;

    let rtt = start.elapsed();

    if resp.status() != StatusCode::OK {
        return Err(MevError::StatusCodeNot200);
    }

    let body = resp.bytes().await.map_err(|e| MevError::Cli(e.into()))?;

    let bid: BuilderBidResponse =
        serde_json::from_slice(&body).map_err(|e| MevError::Cli(e.into()))?;

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
        let slots_in_epoch_i64 = i64::try_from(SLOTS_IN_EPOCH.get()).unwrap_or(i64::MAX);
        let epoch = next_slot.checked_div(slots_in_epoch_i64).unwrap_or(0);

        let pk = if let Some(pk) = get_validator_pk_for_slot(proposer_duties, next_slot) {
            pk
        } else {
            *proposer_duties = fetch_proposers_for_epoch(beacon_endpoint, epoch).await?;
            get_validator_pk_for_slot(proposer_duties, next_slot)
                .ok_or_else(|| CliError::Other("slot not found".to_string()))?
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

            Err(MevError::StatusCodeNot200) => {
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
            Err(MevError::Cli(e)) => return Err(e),
        }
    }

    let payload = build_blinded_block_payload(&builder_bid)?;
    let payload_json = serde_json::to_vec(&payload).map_err(|e| {
        CliError::Other(format!(
            "signed blinded beacon block json payload marshal: {e}"
        ))
    })?;

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
        .ok_or_else(|| {
            CliError::Other(format!(
                "not supported version or missing header: {version}"
            ))
        })
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

fn http_status_error(status: StatusCode) -> String {
    format!("status code {}", status.as_u16())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_mev_relay_name() {
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
    fn test_get_validator_pk_for_slot() {
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
