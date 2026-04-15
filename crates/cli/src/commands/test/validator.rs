//! Validator client connectivity tests.

use std::{fmt, io::Write, time::Duration};

use clap::Args;
use rand::Rng;
use tokio::{
    net::TcpStream,
    sync::mpsc,
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;

use super::{
    AllCategoriesResult, TestCategory, TestCategoryResult, TestConfigArgs, TestResult, TestVerdict,
};
use crate::{duration::Duration as CliDuration, error::{CliError, Result}};

// Thresholds (from Go implementation)
const THRESHOLD_MEASURE_AVG: Duration = Duration::from_millis(50);
const THRESHOLD_MEASURE_POOR: Duration = Duration::from_millis(240);
const THRESHOLD_LOAD_AVG: Duration = Duration::from_millis(50);
const THRESHOLD_LOAD_POOR: Duration = Duration::from_millis(240);

/// Validator test cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidatorTestCase {
    /// TCP connectivity check.
    Ping,
    /// TCP round-trip time measurement.
    PingMeasure,
    /// Sustained TCP load test.
    PingLoad,
}

impl ValidatorTestCase {
    /// Returns all validator test cases.
    pub fn all() -> &'static [ValidatorTestCase] {
        &[
            ValidatorTestCase::Ping,
            ValidatorTestCase::PingMeasure,
            ValidatorTestCase::PingLoad,
        ]
    }
}

impl fmt::Display for ValidatorTestCase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ValidatorTestCase::Ping => "Ping",
            ValidatorTestCase::PingMeasure => "PingMeasure",
            ValidatorTestCase::PingLoad => "PingLoad",
        })
    }
}

/// Arguments for the validator test command.
#[derive(Args, Clone, Debug)]
pub struct TestValidatorArgs {
    #[command(flatten)]
    pub test_config: TestConfigArgs,

    /// Listening address (ip and port) for validator-facing traffic.
    #[arg(
        long = "validator-api-address",
        default_value = "127.0.0.1:3600",
        help = "Listening address (ip and port) for validator-facing traffic proxying the beacon-node API."
    )]
    pub api_address: String,

    /// Time to keep running the load tests.
    #[arg(
        long = "load-test-duration",
        default_value = "5s",
        value_parser = humantime::parse_duration,
        help = "Time to keep running the load tests. For each second a new continuous ping instance is spawned."
    )]
    pub load_test_duration: Duration,
}

/// Runs the validator client tests.
pub async fn run(
    args: TestValidatorArgs,
    writer: &mut dyn Write,
    ct: CancellationToken,
) -> Result<TestCategoryResult> {
    pluto_tracing::init(
        &pluto_tracing::TracingConfig::builder()
            .with_default_console()
            .build(),
    )
    .expect("Failed to initialize tracing");

    tracing::info!("Starting validator client test");

    // Get and filter test cases
    let queued_tests: Vec<ValidatorTestCase> = if let Some(ref filter) = args.test_config.test_cases
    {
        ValidatorTestCase::all()
            .iter()
            .filter(|tc| filter.contains(&tc.to_string()))
            .copied()
            .collect()
    } else {
        ValidatorTestCase::all().to_vec()
    };

    if queued_tests.is_empty() {
        return Err(CliError::TestCaseNotSupported);
    }

    let start_time = Instant::now();
    let test_results = run_tests_with_timeout(&args, &queued_tests, ct).await;
    let elapsed = start_time.elapsed();

    let score = super::calculate_score(&test_results);

    let mut res = TestCategoryResult::new(TestCategory::Validator);
    res.targets.insert(args.api_address.clone(), test_results);
    res.execution_time = Some(CliDuration::new(elapsed));
    res.score = Some(score);

    if !args.test_config.quiet {
        super::write_result_to_writer(&res, writer)?;
    }

    if !args.test_config.output_json.is_empty() {
        super::write_result_to_file(&res, args.test_config.output_json.as_ref()).await?;
    }

    if args.test_config.publish {
        let all = AllCategoriesResult {
            validator: Some(res.clone()),
            ..Default::default()
        };
        super::publish_result_to_obol_api(
            all,
            &args.test_config.publish_addr,
            &args.test_config.publish_private_key_file,
        )
        .await?;
    }

    Ok(res)
}

/// Runs tests with timeout, keeping completed tests on timeout.
async fn run_tests_with_timeout(
    args: &TestValidatorArgs,
    tests: &[ValidatorTestCase],
    ct: CancellationToken,
) -> Vec<TestResult> {
    let mut results = Vec::new();
    let start = Instant::now();

    for &test_case in tests {
        let remaining = args.test_config.timeout.saturating_sub(start.elapsed());

        tokio::select! {
            result = run_single_test(args, test_case) => {
                results.push(result);
            }
            _ = tokio::time::sleep(remaining) => {
                results.push(
                    TestResult::new(test_case.to_string())
                        .fail(CliError::TimeoutInterrupted),
                );
                break;
            }
            _ = ct.cancelled() => {
                results.push(
                    TestResult::new(test_case.to_string())
                        .fail(CliError::TimeoutInterrupted),
                );
                break;
            }
        }
    }

    results
}

/// Runs a single test case.
async fn run_single_test(args: &TestValidatorArgs, test_case: ValidatorTestCase) -> TestResult {
    match test_case {
        ValidatorTestCase::Ping => ping_test(args).await,
        ValidatorTestCase::PingMeasure => ping_measure_test(args).await,
        ValidatorTestCase::PingLoad => ping_load_test(args).await,
    }
}

async fn ping_test(args: &TestValidatorArgs) -> TestResult {
    let mut result = TestResult::new(ValidatorTestCase::Ping.to_string());

    match timeout(
        Duration::from_secs(1),
        TcpStream::connect(&args.api_address),
    )
    .await
    {
        Ok(Ok(_conn)) => {
            result.verdict = TestVerdict::Ok;
        }
        Ok(Err(e)) => {
            return result.fail(e);
        }
        Err(_) => {
            return result.fail(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connection timeout",
            ));
        }
    }

    result
}

async fn ping_measure_test(args: &TestValidatorArgs) -> TestResult {
    let mut result = TestResult::new(ValidatorTestCase::PingMeasure.to_string());
    let before = Instant::now();

    match timeout(
        Duration::from_secs(1),
        TcpStream::connect(&args.api_address),
    )
    .await
    {
        Ok(Ok(_conn)) => {
            let rtt = before.elapsed();
            result =
                super::evaluate_rtt(rtt, result, THRESHOLD_MEASURE_AVG, THRESHOLD_MEASURE_POOR);
        }
        Ok(Err(e)) => {
            return result.fail(e);
        }
        Err(_) => {
            return result.fail(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connection timeout",
            ));
        }
    }

    result
}

async fn ping_load_test(args: &TestValidatorArgs) -> TestResult {
    tracing::info!(
        duration = ?args.load_test_duration,
        target = %args.api_address,
        "Running ping load tests..."
    );

    let mut result = TestResult::new(ValidatorTestCase::PingLoad.to_string());
    let (tx, mut rx) = mpsc::channel::<Duration>(i16::MAX as usize);
    let address = args.api_address.clone();
    let duration = args.load_test_duration;

    {
        let start = Instant::now();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut workers = tokio::task::JoinSet::new();

        interval.tick().await;
        while start.elapsed() < duration {
            interval.tick().await;

            let tx = tx.clone();
            let addr = address.clone();
            let remaining = duration.saturating_sub(start.elapsed());

            workers.spawn(ping_continuously(addr, tx, remaining));
        }

        // Drop the scheduler's clone so only workers hold senders
        drop(tx);

        // Wait for all spawned ping workers to finish
        workers.join_all().await;
    }

    tracing::info!(target = %args.api_address, "Ping load tests finished");

    // All senders dropped, collect all RTTs
    rx.close();
    let mut rtts = Vec::new();
    while let Some(rtt) = rx.recv().await {
        rtts.push(rtt);
    }

    result = super::evaluate_highest_rtt(rtts, result, THRESHOLD_LOAD_AVG, THRESHOLD_LOAD_POOR);

    result
}

async fn ping_continuously(
    address: impl AsRef<str>,
    tx: mpsc::Sender<Duration>,
    max_duration: Duration,
) {
    let address = address.as_ref();
    let start = Instant::now();

    while start.elapsed() < max_duration {
        let before = Instant::now();

        match timeout(Duration::from_secs(1), TcpStream::connect(address)).await {
            Ok(Ok(_conn)) => {
                let rtt = before.elapsed();
                if tx.send(rtt).await.is_err() {
                    return;
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(target = %address, error = ?e, "Ping connection attempt failed during load test");
            }
            Err(e) => {
                tracing::warn!(target = %address, error = ?e, "Ping connection attempt timed out during load test");
            }
        }
        let sleep_ms = rand::thread_rng().gen_range(0..100);
        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
    }
}
