//! Infrastructure and hardware tests.

use std::{
    io::{BufRead as _, BufReader, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use clap::Args;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use super::{
    AllCategoriesResult, TestCaseName, TestCategory, TestCategoryResult, TestConfigArgs,
    TestResult, TestVerdict, calculate_score, evaluate_rtt, filter_tests,
    must_output_to_file_on_quiet, publish_result_to_obol_api, sort_tests, write_result_to_file,
    write_result_to_writer,
};
use crate::{
    duration::Duration as CliDuration,
    error::{CliError, Result},
};

const FIO_NOT_FOUND: &str = "fio command not found, install fio from https://fio.readthedocs.io/en/latest/fio_doc.html#binary-packages or using the package manager of your choice (apt, yum, brew, etc.)";

const DISK_OPS_NUM_OF_JOBS: u32 = 8;
const DISK_OPS_MBS_TOTAL: u32 = 4096;
const DISK_WRITE_SPEED_MBS_AVG: f64 = 1000.0;
const DISK_WRITE_SPEED_MBS_POOR: f64 = 500.0;
const DISK_WRITE_IOPS_AVG: f64 = 2000.0;
const DISK_WRITE_IOPS_POOR: f64 = 1000.0;
const DISK_READ_SPEED_MBS_AVG: f64 = 1000.0;
const DISK_READ_SPEED_MBS_POOR: f64 = 500.0;
const DISK_READ_IOPS_AVG: f64 = 2000.0;
const DISK_READ_IOPS_POOR: f64 = 1000.0;
const AVAILABLE_MEMORY_MBS_AVG: i64 = 4000;
const AVAILABLE_MEMORY_MBS_POOR: i64 = 2000;
const TOTAL_MEMORY_MBS_AVG: i64 = 8000;
const TOTAL_MEMORY_MBS_POOR: i64 = 4000;
const INTERNET_LATENCY_AVG: Duration = Duration::from_millis(20);
const INTERNET_LATENCY_POOR: Duration = Duration::from_millis(50);
const INTERNET_DOWNLOAD_SPEED_MBPS_AVG: f64 = 50.0;
const INTERNET_DOWNLOAD_SPEED_MBPS_POOR: f64 = 15.0;
const INTERNET_UPLOAD_SPEED_MBPS_AVG: f64 = 50.0;
const INTERNET_UPLOAD_SPEED_MBPS_POOR: f64 = 15.0;

#[derive(Deserialize)]
struct FioResult {
    jobs: Vec<FioResultJob>,
}

#[derive(Deserialize)]
struct FioResultJob {
    read: FioResultSingle,
    write: FioResultSingle,
}

#[derive(Deserialize)]
struct FioResultSingle {
    iops: f64,
    bw: f64,
}

#[allow(async_fn_in_trait)]
trait DiskTestTool {
    async fn check_availability(&self) -> Result<()>;
    async fn write_speed(&self, path: &Path, block_size_kb: i32) -> Result<f64>;
    async fn write_iops(&self, path: &Path, block_size_kb: i32) -> Result<f64>;
    async fn read_speed(&self, path: &Path, block_size_kb: i32) -> Result<f64>;
    async fn read_iops(&self, path: &Path, block_size_kb: i32) -> Result<f64>;
}

struct FioTestTool;

impl DiskTestTool for FioTestTool {
    async fn check_availability(&self) -> Result<()> {
        let result = tokio::process::Command::new("fio")
            .arg("--version")
            .output()
            .await;
        match result {
            Ok(o) if o.status.success() => Ok(()),
            _ => Err(CliError::Other(FIO_NOT_FOUND.to_string())),
        }
    }

    async fn write_speed(&self, path: &Path, block_size_kb: i32) -> Result<f64> {
        let out = fio_command(path, block_size_kb, "write").await?;
        let res: FioResult = serde_json::from_slice(&out)
            .map_err(|e| CliError::Other(format!("unmarshal fio result: {e}")))?;
        let job = res
            .jobs
            .into_iter()
            .next()
            .ok_or_else(|| CliError::Other("fio returned no jobs".to_string()))?;
        Ok(job.write.bw / 1024.0)
    }

    async fn write_iops(&self, path: &Path, block_size_kb: i32) -> Result<f64> {
        let out = fio_command(path, block_size_kb, "write").await?;
        let res: FioResult = serde_json::from_slice(&out)
            .map_err(|e| CliError::Other(format!("unmarshal fio result: {e}")))?;
        let job = res
            .jobs
            .into_iter()
            .next()
            .ok_or_else(|| CliError::Other("fio returned no jobs".to_string()))?;
        Ok(job.write.iops)
    }

    async fn read_speed(&self, path: &Path, block_size_kb: i32) -> Result<f64> {
        let out = fio_command(path, block_size_kb, "read").await?;
        let res: FioResult = serde_json::from_slice(&out)
            .map_err(|e| CliError::Other(format!("unmarshal fio result: {e}")))?;
        let job = res
            .jobs
            .into_iter()
            .next()
            .ok_or_else(|| CliError::Other("fio returned no jobs".to_string()))?;
        Ok(job.read.bw / 1024.0)
    }

    async fn read_iops(&self, path: &Path, block_size_kb: i32) -> Result<f64> {
        let out = fio_command(path, block_size_kb, "read").await?;
        let res: FioResult = serde_json::from_slice(&out)
            .map_err(|e| CliError::Other(format!("unmarshal fio result: {e}")))?;
        let job = res
            .jobs
            .into_iter()
            .next()
            .ok_or_else(|| CliError::Other("fio returned no jobs".to_string()))?;
        Ok(job.read.iops)
    }
}

fn can_write_to_dir(dir: &Path) -> bool {
    let test_file = dir.join(".perm_test_tmp");
    match std::fs::File::create(&test_file) {
        Ok(_) => {
            let _ = std::fs::remove_file(&test_file);
            true
        }
        Err(_) => false,
    }
}

async fn fio_command(path: &Path, block_size_kb: i32, operation: &str) -> Result<Vec<u8>> {
    let filename = path.join("fiotest");
    let filename_str = filename.to_string_lossy().into_owned();
    let size_per_job = DISK_OPS_MBS_TOTAL / DISK_OPS_NUM_OF_JOBS;

    let output = tokio::process::Command::new("fio")
        .arg("--name=fioTest")
        .arg(format!("--filename={filename_str}"))
        .arg(format!("--size={size_per_job}Mb"))
        .arg(format!("--blocksize={block_size_kb}k"))
        .arg(format!("--numjobs={DISK_OPS_NUM_OF_JOBS}"))
        .arg(format!("--rw={operation}"))
        .arg("--direct=1")
        .arg("--runtime=60s")
        .arg("--group_reporting")
        .arg("--output-format=json")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| CliError::Other(format!("exec fio command: {e}")))?
        .wait_with_output()
        .await
        .map_err(|e| CliError::Other(format!("exec fio command: {e}")))?;

    let _ = tokio::fs::remove_file(&filename).await;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CliError::Other(format!("exec fio command: {stderr}")));
    }

    Ok(output.stdout)
}

fn available_memory_linux() -> Result<i64> {
    let file = std::fs::File::open("/proc/meminfo")
        .map_err(|e| CliError::Other(format!("open /proc/meminfo: {e}")))?;
    let reader = BufReader::new(file);

    for line_result in reader.lines() {
        let line = line_result.map_err(|e| CliError::Other(format!("open /proc/meminfo: {e}")))?;
        if !line.contains("MemAvailable") {
            continue;
        }
        let (_, value_part) = line
            .split_once(": ")
            .ok_or_else(|| CliError::Other("parse MemAvailable int".to_string()))?;
        let kbs_str = value_part
            .split("kB")
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        let kbs: i64 = kbs_str
            .parse()
            .map_err(|_| CliError::Other("parse MemAvailable int".to_string()))?;

        #[allow(
            clippy::arithmetic_side_effects,
            reason = "The memory won't overflow i64 because the value would be larger than 9223372TB"
        )]
        return Ok(kbs * 1024);
    }

    Err(CliError::Other(
        "memAvailable not found in /proc/meminfo".to_string(),
    ))
}

async fn available_memory_macos() -> Result<i64> {
    let page_size_out = tokio::process::Command::new("pagesize")
        .output()
        .await
        .map_err(|e| CliError::Other(format!("run pagesize: {e}")))?;
    let page_size_str = String::from_utf8_lossy(&page_size_out.stdout);
    let page_size: i64 = page_size_str
        .trim()
        .parse()
        .map_err(|_| CliError::Other("parse memorySizePerPage int".to_string()))?;

    let vm_stat_out = tokio::process::Command::new("vm_stat")
        .output()
        .await
        .map_err(|e| CliError::Other(format!("run vm_stat: {e}")))?;
    let vm_stat = String::from_utf8_lossy(&vm_stat_out.stdout).into_owned();

    let mut pages_free: i64 = 0;
    let mut pages_inactive: i64 = 0;
    let mut pages_speculative: i64 = 0;

    for line in vm_stat.lines() {
        let Some((key, value)) = line.split_once(": ") else {
            continue;
        };
        let num_str = value.split('.').next().unwrap_or_default().trim();

        if key.contains("Pages free") {
            pages_free = num_str
                .parse()
                .map_err(|_| CliError::Other("parse Pages free int".to_string()))?;
        } else if key.contains("Pages inactive") {
            pages_inactive = num_str
                .parse()
                .map_err(|_| CliError::Other("parse Pages inactive int".to_string()))?;
        } else if key.contains("Pages speculative") {
            pages_speculative = num_str
                .parse()
                .map_err(|_| CliError::Other("parse Pages speculative int".to_string()))?;
        }
    }

    let total = pages_free
        .saturating_add(pages_inactive)
        .saturating_add(pages_speculative);
    Ok(total.saturating_mul(page_size))
}

fn total_memory_linux() -> Result<i64> {
    let file = std::fs::File::open("/proc/meminfo")
        .map_err(|e| CliError::Other(format!("open /proc/meminfo: {e}")))?;
    let reader = BufReader::new(file);

    for line_result in reader.lines() {
        let line = line_result.map_err(|e| CliError::Other(format!("open /proc/meminfo: {e}")))?;
        if !line.contains("MemTotal") {
            continue;
        }
        let (_, value_part) = line
            .split_once(": ")
            .ok_or_else(|| CliError::Other("parse MemTotal int".to_string()))?;
        let kbs_str = value_part
            .split("kB")
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        let kbs: i64 = kbs_str
            .parse()
            .map_err(|_| CliError::Other("parse MemTotal int".to_string()))?;

        #[allow(
            clippy::arithmetic_side_effects,
            reason = "The memory won't overflow i64 because the value would be larger than 9223372TB"
        )]
        return Ok(kbs * 1024);
    }

    Err(CliError::Other(
        "memTotal not found in /proc/meminfo".to_string(),
    ))
}

async fn total_memory_macos() -> Result<i64> {
    let out = tokio::process::Command::new("sysctl")
        .arg("hw.memsize")
        .output()
        .await
        .map_err(|e| CliError::Other(format!("run sysctl hw.memsize: {e}")))?;
    let output_str = String::from_utf8_lossy(&out.stdout);
    let mem_str = output_str
        .split_once(": ")
        .map(|(_, v)| v.trim())
        .ok_or_else(|| CliError::Other("parse memSize int".to_string()))?;
    mem_str
        .parse()
        .map_err(|_| CliError::Other("parse memSize int".to_string()))
}

async fn disk_write_speed_test(
    args: &TestInfraArgs,
    disk_dir: &Path,
    tool: &impl DiskTestTool,
) -> TestResult {
    let mut result = TestResult::new("DiskWriteSpeed");

    tracing::info!(
        test_file_size_mb = DISK_OPS_MBS_TOTAL,
        jobs = DISK_OPS_NUM_OF_JOBS,
        test_file_path = %disk_dir.display(),
        "Testing disk write speed..."
    );

    if let Err(e) = tool.check_availability().await {
        return result.fail(e);
    }

    match tool.write_speed(disk_dir, args.disk_io_block_size_kb).await {
        Err(e) => result.fail(e),
        Ok(speed) => {
            result.verdict = if speed < DISK_WRITE_SPEED_MBS_POOR {
                TestVerdict::Poor
            } else if speed < DISK_WRITE_SPEED_MBS_AVG {
                TestVerdict::Avg
            } else {
                TestVerdict::Good
            };
            result.measurement = format!("{speed:.2}MB/s");
            result
        }
    }
}

async fn disk_write_iops_test(
    args: &TestInfraArgs,
    disk_dir: &Path,
    tool: &impl DiskTestTool,
) -> TestResult {
    let mut result = TestResult::new("DiskWriteIOPS");

    tracing::info!(
        test_file_size_mb = DISK_OPS_MBS_TOTAL,
        jobs = DISK_OPS_NUM_OF_JOBS,
        test_file_path = %disk_dir.display(),
        "Testing disk write IOPS..."
    );

    if let Err(e) = tool.check_availability().await {
        return result.fail(e);
    }

    match tool.write_iops(disk_dir, args.disk_io_block_size_kb).await {
        Err(e) => result.fail(e),
        Ok(iops) => {
            result.verdict = if iops < DISK_WRITE_IOPS_POOR {
                TestVerdict::Poor
            } else if iops < DISK_WRITE_IOPS_AVG {
                TestVerdict::Avg
            } else {
                TestVerdict::Good
            };
            result.measurement = format!("{iops:.0}");
            result
        }
    }
}

async fn disk_read_speed_test(
    args: &TestInfraArgs,
    disk_dir: &Path,
    tool: &impl DiskTestTool,
) -> TestResult {
    let mut result = TestResult::new("DiskReadSpeed");

    tracing::info!(
        test_file_size_mb = DISK_OPS_MBS_TOTAL,
        jobs = DISK_OPS_NUM_OF_JOBS,
        test_file_path = %disk_dir.display(),
        "Testing disk read speed..."
    );

    if let Err(e) = tool.check_availability().await {
        return result.fail(e);
    }

    match tool.read_speed(disk_dir, args.disk_io_block_size_kb).await {
        Err(e) => result.fail(e),
        Ok(speed) => {
            result.verdict = if speed < DISK_READ_SPEED_MBS_POOR {
                TestVerdict::Poor
            } else if speed < DISK_READ_SPEED_MBS_AVG {
                TestVerdict::Avg
            } else {
                TestVerdict::Good
            };
            result.measurement = format!("{speed:.2}MB/s");
            result
        }
    }
}

/// Go bug parity: the original Go implementation (testinfra.go:377) calls
/// ReadSpeed instead of ReadIOPS for this test, then compares the bandwidth
/// result against IOPS thresholds. Fixed here to call read_iops() correctly;
/// the Go behaviour was clearly unintentional.
async fn disk_read_iops_test(
    args: &TestInfraArgs,
    disk_dir: &Path,
    tool: &impl DiskTestTool,
) -> TestResult {
    let mut result = TestResult::new("DiskReadIOPS");

    tracing::info!(
        test_file_size_mb = DISK_OPS_MBS_TOTAL,
        jobs = DISK_OPS_NUM_OF_JOBS,
        test_file_path = %disk_dir.display(),
        "Testing disk read IOPS..."
    );

    if let Err(e) = tool.check_availability().await {
        return result.fail(e);
    }

    match tool.read_iops(disk_dir, args.disk_io_block_size_kb).await {
        Err(e) => result.fail(e),
        Ok(iops) => {
            result.verdict = if iops < DISK_READ_IOPS_POOR {
                TestVerdict::Poor
            } else if iops < DISK_READ_IOPS_AVG {
                TestVerdict::Avg
            } else {
                TestVerdict::Good
            };
            result.measurement = format!("{iops:.0}");
            result
        }
    }
}

async fn available_memory_test() -> TestResult {
    let mut result = TestResult::new("AvailableMemory");

    let bytes = match std::env::consts::OS {
        "linux" => available_memory_linux(),
        "macos" => available_memory_macos().await,
        os => return result.fail(CliError::Other(format!("unknown OS {os}"))),
    };

    match bytes {
        Err(e) => result.fail(e),
        Ok(b) => {
            let mb = b / 1024 / 1024;
            result.verdict = if mb < AVAILABLE_MEMORY_MBS_POOR {
                TestVerdict::Poor
            } else if mb < AVAILABLE_MEMORY_MBS_AVG {
                TestVerdict::Avg
            } else {
                TestVerdict::Good
            };
            result.measurement = format!("{mb}MB");
            result
        }
    }
}

async fn total_memory_test() -> TestResult {
    let mut result = TestResult::new("TotalMemory");

    let bytes = match std::env::consts::OS {
        "linux" => total_memory_linux(),
        "macos" => total_memory_macos().await,
        os => return result.fail(CliError::Other(format!("unknown OS {os}"))),
    };

    match bytes {
        Err(e) => result.fail(e),
        Ok(b) => {
            let mb = b / 1024 / 1024;
            result.verdict = if mb < TOTAL_MEMORY_MBS_POOR {
                TestVerdict::Poor
            } else if mb < TOTAL_MEMORY_MBS_AVG {
                TestVerdict::Avg
            } else {
                TestVerdict::Good
            };
            result.measurement = format!("{mb}MB");
            result
        }
    }
}

async fn internet_latency_test(args: &TestInfraArgs, client: &reqwest::Client) -> TestResult {
    let result = TestResult::new("InternetLatency");

    let mut server = match super::speedtest::fetch_best_server(
        &args.internet_test_servers_only,
        &args.internet_test_servers_exclude,
        client,
    )
    .await
    {
        Err(e) => return result.fail(e),
        Ok(s) => s,
    };

    tracing::info!(
        server_name = %server.name,
        server_country = %server.country,
        server_distance_km = server.distance,
        server_id = %server.id,
        "Testing internet latency..."
    );

    if let Err(e) = server.ping_test(client).await {
        return result.fail(e);
    }

    evaluate_rtt(
        server.latency,
        result,
        INTERNET_LATENCY_AVG,
        INTERNET_LATENCY_POOR,
    )
}

async fn internet_download_speed_test(
    args: &TestInfraArgs,
    client: &reqwest::Client,
) -> TestResult {
    let mut result = TestResult::new("InternetDownloadSpeed");

    let mut server = match super::speedtest::fetch_best_server(
        &args.internet_test_servers_only,
        &args.internet_test_servers_exclude,
        client,
    )
    .await
    {
        Err(e) => return result.fail(e),
        Ok(s) => s,
    };

    tracing::info!(
        server_name = %server.name,
        server_country = %server.country,
        server_distance_km = server.distance,
        server_id = %server.id,
        "Testing internet download speed..."
    );

    if let Err(e) = server.download_test(client).await {
        return result.fail(e);
    }

    let speed = server.dl_speed_mbps;
    result.verdict = if speed < INTERNET_DOWNLOAD_SPEED_MBPS_POOR {
        TestVerdict::Poor
    } else if speed < INTERNET_DOWNLOAD_SPEED_MBPS_AVG {
        TestVerdict::Avg
    } else {
        TestVerdict::Good
    };
    result.measurement = format!("{speed:.2}Mb/s");
    result
}

async fn internet_upload_speed_test(args: &TestInfraArgs, client: &reqwest::Client) -> TestResult {
    let mut result = TestResult::new("InternetUploadSpeed");

    let mut server = match super::speedtest::fetch_best_server(
        &args.internet_test_servers_only,
        &args.internet_test_servers_exclude,
        client,
    )
    .await
    {
        Err(e) => return result.fail(e),
        Ok(s) => s,
    };

    tracing::info!(
        server_name = %server.name,
        server_country = %server.country,
        server_distance_km = server.distance,
        server_id = %server.id,
        "Testing internet upload speed..."
    );

    if let Err(e) = server.upload_test(client).await {
        return result.fail(e);
    }

    let speed = server.ul_speed_mbps;
    result.verdict = if speed < INTERNET_UPLOAD_SPEED_MBPS_POOR {
        TestVerdict::Poor
    } else if speed < INTERNET_UPLOAD_SPEED_MBPS_AVG {
        TestVerdict::Avg
    } else {
        TestVerdict::Good
    };
    result.measurement = format!("{speed:.2}Mb/s");
    result
}

/// Returns the ordered list of supported infra test case names.
pub(crate) fn supported_infra_test_cases() -> Vec<TestCaseName> {
    vec![
        TestCaseName::new("DiskWriteSpeed", 1),
        TestCaseName::new("DiskWriteIOPS", 2),
        TestCaseName::new("DiskReadSpeed", 3),
        TestCaseName::new("DiskReadIOPS", 4),
        TestCaseName::new("AvailableMemory", 5),
        TestCaseName::new("TotalMemory", 6),
        TestCaseName::new("InternetLatency", 7),
        TestCaseName::new("InternetDownloadSpeed", 8),
        TestCaseName::new("InternetUploadSpeed", 9),
    ]
}

async fn run_single_test(
    name: &str,
    args: &TestInfraArgs,
    disk_dir: &Path,
    tool: &impl DiskTestTool,
    client: &reqwest::Client,
) -> TestResult {
    match name {
        "DiskWriteSpeed" => disk_write_speed_test(args, disk_dir, tool).await,
        "DiskWriteIOPS" => disk_write_iops_test(args, disk_dir, tool).await,
        "DiskReadSpeed" => disk_read_speed_test(args, disk_dir, tool).await,
        "DiskReadIOPS" => disk_read_iops_test(args, disk_dir, tool).await,
        "AvailableMemory" => available_memory_test().await,
        "TotalMemory" => total_memory_test().await,
        "InternetLatency" => internet_latency_test(args, client).await,
        "InternetDownloadSpeed" => internet_download_speed_test(args, client).await,
        "InternetUploadSpeed" => internet_upload_speed_test(args, client).await,
        _ => TestResult::new(name).fail(CliError::Other(format!("unknown test: {name}"))),
    }
}

async fn run_tests_with_timeout(
    args: &TestInfraArgs,
    tests: &[TestCaseName],
    disk_dir: &Path,
    client: &reqwest::Client,
    ct: CancellationToken,
) -> Vec<TestResult> {
    let tool = FioTestTool;
    let mut results = Vec::new();
    let start = Instant::now();

    for test_case in tests {
        let remaining = args.test_config.timeout.saturating_sub(start.elapsed());
        tokio::select! {
            result = run_single_test(test_case.name, args, disk_dir, &tool, client) => {
                results.push(result);
            }
            () = tokio::time::sleep(remaining) => {
                results.push(TestResult::new(test_case.name).fail(CliError::TimeoutInterrupted));
                break;
            }
            () = ct.cancelled() => {
                results.push(TestResult::new(test_case.name).fail(CliError::TimeoutInterrupted));
                break;
            }
        }
    }

    results
}

/// Runs the infrastructure tests.
pub async fn run(
    args: TestInfraArgs,
    writer: &mut dyn Write,
    ct: CancellationToken,
) -> Result<TestCategoryResult> {
    pluto_tracing::init(
        &pluto_tracing::TracingConfig::builder()
            .with_default_console()
            .build(),
    )
    .expect("Failed to initialize tracing");

    must_output_to_file_on_quiet(args.test_config.quiet, &args.test_config.output_json)?;

    tracing::info!("Starting hardware performance and network connectivity test");

    let disk_dir = match &args.disk_io_test_file_dir {
        Some(dir) => PathBuf::from(dir),
        None => std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(PathBuf::from)
            .map_err(|_| CliError::Other("get user home directory".to_string()))?,
    };

    if !can_write_to_dir(&disk_dir) {
        return Err(CliError::Other(format!(
            "no write permissions to disk IO test file directory: {}",
            disk_dir.display()
        )));
    }

    let client = super::speedtest::build_client()?;

    let all_cases = supported_infra_test_cases();
    let mut queued = filter_tests(&all_cases, args.test_config.test_cases.as_deref());
    if queued.is_empty() {
        return Err(CliError::TestCaseNotSupported);
    }
    sort_tests(&mut queued);

    let start = Instant::now();
    let test_results = run_tests_with_timeout(&args, &queued, &disk_dir, &client, ct).await;
    let elapsed = start.elapsed();

    let score = calculate_score(&test_results);

    let mut res = TestCategoryResult::new(TestCategory::Infra);
    res.targets.insert("local".to_string(), test_results);
    res.execution_time = Some(CliDuration::new(elapsed));
    res.score = Some(score);

    if !args.test_config.quiet {
        write_result_to_writer(&res, writer)?;
    }

    if !args.test_config.output_json.is_empty() {
        write_result_to_file(&res, args.test_config.output_json.as_ref()).await?;
    }

    if args.test_config.publish {
        let all = AllCategoriesResult {
            infra: Some(res.clone()),
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

/// Arguments for the infra test command.
#[derive(Args, Clone, Debug)]
pub struct TestInfraArgs {
    #[command(flatten)]
    pub test_config: TestConfigArgs,

    /// Directory at which disk performance will be measured.
    #[arg(
        long = "disk-io-test-file-dir",
        help = "Directory at which disk performance will be measured. If none specified, current user's home directory will be used."
    )]
    pub disk_io_test_file_dir: Option<String>,

    /// The block size in kilobytes used for I/O units.
    #[arg(
        long = "disk-io-block-size-kb",
        default_value = "4096",
        help = "The block size in kilobytes used for I/O units. Same value applies for both reads and writes."
    )]
    pub disk_io_block_size_kb: i32,

    /// List of specific server names to be included for the internet tests.
    #[arg(
        long = "internet-test-servers-only",
        value_delimiter = ',',
        help = "List of specific server names to be included for the internet tests, the best performing one is chosen. If not provided, closest and best performing servers are chosen automatically."
    )]
    pub internet_test_servers_only: Vec<String>,

    /// List of server names to be excluded from the tests.
    #[arg(
        long = "internet-test-servers-exclude",
        value_delimiter = ',',
        help = "List of server names to be excluded from the tests. To be specified only if you experience issues with a server that is wrongly considered best performing."
    )]
    pub internet_test_servers_exclude: Vec<String>,
}
