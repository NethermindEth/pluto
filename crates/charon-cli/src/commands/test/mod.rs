//! Test command module for cluster evaluation.
//!
//! This module provides a comprehensive test suite to evaluate the current
//! cluster setup, including tests for peers, beacon nodes, validator clients,
//! MEV relays, and infrastructure.

// TODO: Foundation for the test command, the detail will be implemented later
#![allow(dead_code)]

pub mod all;
pub mod beacon;
pub mod infra;
pub mod mev;
pub mod peers;
pub mod validator;

use clap::Args;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::Duration as StdDuration,
};

use crate::{
    ascii::{append_score, get_category_ascii, get_score_ascii},
    duration::Duration,
    error::{CliError, Result as CliResult},
};

use charon::obolapi::{Client, ClientOptions};
use charon_cluster::ssz_hasher::{HashWalker, Hasher};
use charon_eth2::enr::Record;
use charon_k1util::{load, sign};
use k256::SecretKey;
use serde_with::{base64::Base64, serde_as};

/// Test category identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestCategory {
    Peers,
    Beacon,
    Validator,
    Mev,
    Infra,
    All,
}

impl TestCategory {
    /// Returns the string representation of the test category.
    pub fn as_str(&self) -> &'static str {
        match self {
            TestCategory::Peers => "peers",
            TestCategory::Beacon => "beacon",
            TestCategory::Validator => "validator",
            TestCategory::Mev => "mev",
            TestCategory::Infra => "infra",
            TestCategory::All => "all",
        }
    }
}

impl fmt::Display for TestCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Ethereum beacon chain constants.
pub(crate) const COMMITTEE_SIZE_PER_SLOT: u64 = 64;
pub(crate) const SUB_COMMITTEE_SIZE: u64 = 4;
pub(crate) const SLOT_TIME: StdDuration = StdDuration::from_secs(12);
pub(crate) const SLOTS_IN_EPOCH: u64 = 32;
pub(crate) const EPOCH_TIME: StdDuration = StdDuration::from_secs(SLOTS_IN_EPOCH * 12);

/// Base test configuration shared by all test commands.
#[derive(Args, Clone, Debug)]
pub struct TestConfigArgs {
    #[arg(
        long = "output-json",
        default_value = "",
        help = "File path to which output can be written in JSON format"
    )]
    pub output_json: String,

    #[arg(long, help = "Do not print test results to stdout")]
    pub quiet: bool,

    /// (Help text will be overridden in main.rs to include available tests)
    #[arg(
        long = "test-cases",
        value_delimiter = ',',
        help = "Comma-separated list of test names to execute."
    )]
    pub test_cases: Option<Vec<String>>,

    #[arg(
        long,
        default_value = "1h",
        value_parser = humantime::parse_duration,
        help = "Execution timeout for all tests"
    )]
    pub timeout: StdDuration,

    #[arg(long, help = "Publish test result file to obol-api")]
    pub publish: bool,

    #[arg(
        long = "publish-address",
        default_value = "https://api.obol.tech/v1",
        help = "The URL to publish the test result file to"
    )]
    pub publish_addr: String,

    #[arg(
        long = "publish-private-key-file",
        default_value = ".charon/charon-enr-private-key",
        help = "The path to the charon enr private key file, used for signing the publish request"
    )]
    pub publish_private_key_file: PathBuf,
}

/// Lists available test case names for a given test category.
pub fn list_test_cases(category: TestCategory) -> Vec<String> {
    // Returns available test case names for each category.
    match category {
        TestCategory::Validator => {
            // From validator::supported_validator_test_cases()
            vec![
                "Ping".to_string(),
                "PingMeasure".to_string(),
                "PingLoad".to_string(),
            ]
        }
        TestCategory::Beacon => {
            // TODO: Extract from beacon::supported_beacon_test_cases()
            vec![]
        }
        TestCategory::Mev => {
            vec![
                "Ping".to_string(),
                "PingMeasure".to_string(),
                "CreateBlock".to_string(),
            ]
        }
        TestCategory::Peers => {
            // TODO: Extract from peers::supported_peer_test_cases() +
            // supported_self_test_cases()
            vec![]
        }
        TestCategory::Infra => {
            // TODO: Extract from infra::supported_infra_test_cases()
            vec![]
        }
        TestCategory::All => {
            // TODO: Combine all test cases from all categories
            vec![]
        }
    }
}

pub fn must_output_to_file_on_quiet(quiet: bool, output_json: &str) -> CliResult<()> {
    if quiet && output_json.is_empty() {
        Err(CliError::Other(
            "on --quiet, an --output-json is required".to_string(),
        ))
    } else {
        Ok(())
    }
}

/// Test verdict indicating the outcome of a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestVerdict {
    #[serde(rename = "OK")]
    Ok,
    Good,
    Avg,
    Poor,
    Fail,
    Skip,
}

impl fmt::Display for TestVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestVerdict::Ok => write!(f, "OK"),
            TestVerdict::Good => write!(f, "Good"),
            TestVerdict::Avg => write!(f, "Avg"),
            TestVerdict::Poor => write!(f, "Poor"),
            TestVerdict::Fail => write!(f, "Fail"),
            TestVerdict::Skip => write!(f, "Skip"),
        }
    }
}

/// Category-level score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CategoryScore {
    A,
    B,
    C,
}

impl fmt::Display for CategoryScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CategoryScore::A => write!(f, "A"),
            CategoryScore::B => write!(f, "B"),
            CategoryScore::C => write!(f, "C"),
        }
    }
}

/// Wrapper for test error with custom serialization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TestResultError(String);

impl TestResultError {
    pub fn empty() -> Self {
        Self(String::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn message(&self) -> Option<&str> {
        if self.0.is_empty() {
            None
        } else {
            Some(&self.0)
        }
    }
}

impl fmt::Display for TestResultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<E: std::error::Error> From<E> for TestResultError {
    fn from(err: E) -> Self {
        Self(err.to_string())
    }
}

/// Result of a single test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "verdict")]
    pub verdict: TestVerdict,

    #[serde(
        rename = "measurement",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub measurement: String,

    #[serde(
        rename = "suggestion",
        skip_serializing_if = "String::is_empty",
        default
    )]
    pub suggestion: String,

    #[serde(
        rename = "error",
        skip_serializing_if = "TestResultError::is_empty",
        default
    )]
    pub error: TestResultError,

    #[serde(skip)]
    pub is_acceptable: bool,
}

impl TestResult {
    /// Creates a new test result with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            verdict: TestVerdict::Fail,
            measurement: String::new(),
            suggestion: String::new(),
            error: TestResultError::empty(),
            is_acceptable: false,
        }
    }

    /// Marks the test as failed with the given error.
    pub fn fail(mut self, error: impl Into<TestResultError>) -> Self {
        self.verdict = TestVerdict::Fail;
        self.error = error.into();
        self
    }

    /// Marks the test as passed (OK verdict).
    pub fn ok(mut self) -> Self {
        self.verdict = TestVerdict::Ok;
        self
    }
}

/// Test case name with execution order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TestCaseName {
    pub name: String,
    pub order: u32,
}

impl TestCaseName {
    /// Creates a new test case name.
    pub fn new(name: &str, order: u32) -> Self {
        Self {
            name: name.into(),
            order,
        }
    }
}

/// Result of a test category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCategoryResult {
    #[serde(
        rename = "category_name",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub category_name: Option<TestCategory>,

    #[serde(rename = "targets", skip_serializing_if = "HashMap::is_empty", default)]
    pub targets: HashMap<String, Vec<TestResult>>,

    #[serde(rename = "execution_time", skip_serializing_if = "Option::is_none")]
    pub execution_time: Option<Duration>,

    #[serde(rename = "score", skip_serializing_if = "Option::is_none")]
    pub score: Option<CategoryScore>,
}

impl TestCategoryResult {
    /// Creates a new test category result with the given name.
    pub fn new(category_name: TestCategory) -> Self {
        Self {
            category_name: Some(category_name),
            targets: HashMap::new(),
            execution_time: None,
            score: None,
        }
    }
}

/// All test categories result for JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AllCategoriesResult {
    #[serde(rename = "charon_peers", skip_serializing_if = "Option::is_none")]
    pub peers: Option<TestCategoryResult>,

    #[serde(rename = "beacon_node", skip_serializing_if = "Option::is_none")]
    pub beacon: Option<TestCategoryResult>,

    #[serde(rename = "validator_client", skip_serializing_if = "Option::is_none")]
    pub validator: Option<TestCategoryResult>,

    #[serde(rename = "mev", skip_serializing_if = "Option::is_none")]
    pub mev: Option<TestCategoryResult>,

    #[serde(rename = "infra", skip_serializing_if = "Option::is_none")]
    pub infra: Option<TestCategoryResult>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObolApiResult {
    #[serde(rename = "enr")]
    enr: String,

    /// Base64-encoded signature (65 bytes)
    /// TODO: double check with obol - API docs show "0x..." but Go []byte
    /// marshals to base64
    #[serde_as(as = "Base64")]
    #[serde(rename = "sig")]
    sig: Vec<u8>,

    #[serde(rename = "data")]
    data: AllCategoriesResult,
}

/// Publishes test results to the Obol API.
pub async fn publish_result_to_obol_api(
    data: AllCategoriesResult,
    api_url: &str,
    private_key_file: &Path,
) -> CliResult<()> {
    let private_key = load_or_generate_key(private_key_file)?;
    let enr = create_enr(&private_key)?;
    let sign_data_bytes = serde_json::to_vec(&data)?;
    let hash = hash_ssz(&sign_data_bytes)?;
    let sig = sign(&private_key, &hash)?;

    let result = ObolApiResult {
        enr: enr.to_string(),
        sig: sig.to_vec(),
        data,
    };

    let obol_api_json = serde_json::to_vec(&result)?;
    let client = Client::new(api_url, ClientOptions::default())?;
    client.post_test_result(obol_api_json).await?;

    Ok(())
}

/// Writes test results to a JSON file.
pub fn write_result_to_file(result: &TestCategoryResult, path: &Path) -> CliResult<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut existing_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o644)
        .open(path)?;

    let stat = existing_file.metadata()?;

    let mut all_results: AllCategoriesResult = if stat.len() == 0 {
        AllCategoriesResult::default()
    } else {
        serde_json::from_reader(&mut existing_file)?
    };

    let category = result
        .category_name
        .ok_or_else(|| CliError::Other("unknown category: (missing)".to_string()))?;

    match category {
        TestCategory::Peers => all_results.peers = Some(result.clone()),
        TestCategory::Beacon => all_results.beacon = Some(result.clone()),
        TestCategory::Validator => all_results.validator = Some(result.clone()),
        TestCategory::Mev => all_results.mev = Some(result.clone()),
        TestCategory::Infra => all_results.infra = Some(result.clone()),
        TestCategory::All => {
            return Err(CliError::Other("unknown category: all".to_string()));
        }
    }

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let base = path
        .file_name()
        .ok_or_else(|| CliError::Other(format!("no filename in path: {}", path.display())))?
        .to_string_lossy()
        .to_string();

    // Match Go's `os.CreateTemp(dir, fmt.Sprintf("%v-tmp-*.json", base))`.
    let mut tmp = tempfile::Builder::new()
        .prefix(&format!("{base}-tmp-"))
        .suffix(".json")
        .tempfile_in(dir)
        .map_err(|e| CliError::Io {
            source: e,
            context: "create temp file".to_string(),
        })?;

    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o644))?;

    let file_content_json = serde_json::to_vec(&all_results).map_err(|e| CliError::Json {
        source: e,
        context: "marshal fileResult to JSON".to_string(),
    })?;

    tmp.as_file_mut().write_all(&file_content_json)?;

    tmp.persist(path).map_err(|e| CliError::Io {
        source: e.error,
        context: "rename temp file".to_string(),
    })?;

    Ok(())
}

/// Writes test results to a writer (stdout or file).
pub fn write_result_to_writer<W: Write + ?Sized>(
    result: &TestCategoryResult,
    writer: &mut W,
) -> CliResult<()> {
    let mut lines = Vec::new();

    // Add category ASCII art
    let category_ascii = get_category_ascii(
        result
            .category_name
            .as_ref()
            .map(|c| c.as_str())
            .unwrap_or(""),
    );
    lines.extend(category_ascii.iter().map(|line| line.to_string()));

    if let Some(score) = result.score {
        let score_ascii = get_score_ascii(score);
        lines = append_score(lines, score_ascii);
    }

    // Add test results
    lines.push(String::new());
    lines.push(format!("{:<64}{}", "TEST NAME", "RESULT"));

    let mut suggestions = Vec::new();

    // Sort targets by name for consistent output
    let mut targets: Vec<_> = result.targets.iter().collect();
    targets.sort_by_key(|(name, _)| *name);

    for (target, test_results) in targets {
        if !target.is_empty() && !test_results.is_empty() {
            lines.push(String::new());
            lines.push(target.clone());
        }

        for test_result in test_results {
            let mut test_output = format!("{:<64}", test_result.name);

            if !test_result.measurement.is_empty() {
                let trim_count = test_result.measurement.chars().count().saturating_add(1);
                let spaces_to_trim = " ".repeat(trim_count);

                if test_output.ends_with(&spaces_to_trim) {
                    let new_len = test_output.len().saturating_sub(trim_count);
                    test_output.truncate(new_len);
                }

                test_output.push_str(&test_result.measurement);
                test_output.push(' ');
            }

            // Add verdict
            test_output.push_str(&test_result.verdict.to_string());

            // Add suggestion if present
            if !test_result.suggestion.is_empty() {
                suggestions.push(test_result.suggestion.clone());
            }

            // Add error if present
            if let Some(err_msg) = test_result.error.message() {
                test_output.push_str(&format!(" - {}", err_msg));
            }

            lines.push(test_output);
        }
    }

    // Add suggestions section
    if !suggestions.is_empty() {
        lines.push(String::new());
        lines.push("SUGGESTED IMPROVEMENTS".to_string());
        lines.extend(suggestions);
    }

    // Add execution time
    lines.push(String::new());
    lines.push(result.execution_time.unwrap_or_default().to_string());

    // Write all lines
    lines.push(String::new());
    for line in lines {
        writeln!(writer, "{}", line)?;
    }

    Ok(())
}

/// Evaluates highest RTT from a channel and assigns a verdict.
pub fn evaluate_highest_rtt(
    rtts: Vec<StdDuration>,
    result: TestResult,
    avg_threshold: StdDuration,
    poor_threshold: StdDuration,
) -> TestResult {
    let highest_rtt = rtts.into_iter().max().unwrap_or_default();
    evaluate_rtt(highest_rtt, result, avg_threshold, poor_threshold)
}

/// Evaluates RTT (Round Trip Time) and assigns a verdict based on thresholds.
pub fn evaluate_rtt(
    rtt: StdDuration,
    mut result: TestResult,
    avg_threshold: StdDuration,
    poor_threshold: StdDuration,
) -> TestResult {
    if rtt.is_zero() || rtt > poor_threshold {
        result.verdict = TestVerdict::Poor;
    } else if rtt > avg_threshold {
        result.verdict = TestVerdict::Avg;
    } else {
        result.verdict = TestVerdict::Good;
    }

    result.measurement = Duration::new(rtt).round().to_string();
    result
}

/// Calculates the overall score for a list of test results.
pub fn calculate_score(results: &[TestResult]) -> CategoryScore {
    // TODO: calculate score more elaborately (potentially use weights)
    let mut avg: i32 = 0;

    for test in results {
        match test.verdict {
            TestVerdict::Poor => return CategoryScore::C,
            TestVerdict::Good => avg = avg.saturating_add(1),
            TestVerdict::Avg => avg = avg.saturating_sub(1),
            TestVerdict::Fail => {
                if !test.is_acceptable {
                    return CategoryScore::C;
                }
                continue;
            }
            TestVerdict::Ok | TestVerdict::Skip => continue,
        }
    }

    if avg < 0 {
        CategoryScore::B
    } else {
        CategoryScore::A
    }
}

/// Filters tests based on configuration.
pub fn filter_tests<V>(
    supported_test_cases: &HashMap<TestCaseName, V>,
    test_cases: Option<&[String]>,
) -> Vec<TestCaseName> {
    let Some(cases) = test_cases else {
        return supported_test_cases.keys().cloned().collect();
    };
    cases
        .iter()
        .flat_map(|case| {
            supported_test_cases
                .keys()
                .filter(move |supported_case| supported_case.name.as_str() == case.as_str())
                .cloned()
        })
        .collect()
}

/// Sorts tests by their order field.
pub fn sort_tests(tests: &mut [TestCaseName]) {
    tests.sort_by_key(|t| t.order);
}

fn load_or_generate_key(path: &Path) -> CliResult<SecretKey> {
    if path.exists() {
        Ok(load(path)?)
    } else {
        tracing::warn!(
            private_key_file = %path.display(),
            "Private key file does not exist, will generate a temporary key"
        );
        use k256::elliptic_curve::rand_core::OsRng;
        Ok(SecretKey::random(&mut OsRng))
    }
}

fn create_enr(secret_key: &SecretKey) -> CliResult<Record> {
    Ok(Record::new(secret_key.clone(), vec![])?)
}

/// Hashes data using SSZ merkleization.
/// - Empty data: Returns zero bytes (all 0x00)
/// - Data 1-32 bytes: Returns data padded to 32 bytes
/// - Data > 32 bytes: Chunks into 32-byte pieces, builds merkle tree with
///   SHA256
fn hash_ssz(data: &[u8]) -> CliResult<[u8; 32]> {
    if data.is_empty() {
        return Ok([0u8; 32]);
    }

    let mut hasher: Hasher = Hasher::default();
    let index = hasher.index();

    hasher
        .put_bytes(data)
        .map_err(|e: charon_cluster::ssz_hasher::HasherError| {
            CliError::Other(format!("put bytes: {}", e))
        })?;

    hasher
        .merkleize(index)
        .map_err(|e: charon_cluster::ssz_hasher::HasherError| {
            CliError::Other(format!("merkleize: {}", e))
        })?;

    hasher
        .hash_root()
        .map_err(|e| CliError::Other(format!("hash root: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_score() {
        let mut results = vec![
            TestResult {
                name: "test1".to_string(),
                verdict: TestVerdict::Good,
                measurement: String::new(),
                suggestion: String::new(),
                error: TestResultError::empty(),
                is_acceptable: false,
            },
            TestResult {
                name: "test2".to_string(),
                verdict: TestVerdict::Good,
                measurement: String::new(),
                suggestion: String::new(),
                error: TestResultError::empty(),
                is_acceptable: false,
            },
        ];

        assert_eq!(calculate_score(&results), CategoryScore::A);

        results.push(TestResult {
            name: "test3".to_string(),
            verdict: TestVerdict::Poor,
            measurement: String::new(),
            suggestion: String::new(),
            error: TestResultError::empty(),
            is_acceptable: false,
        });

        assert_eq!(calculate_score(&results), CategoryScore::C);
    }

    #[test]
    fn test_write_result_to_writer_smoke() {
        let mut result = TestCategoryResult::new(TestCategory::Peers);
        result.score = Some(CategoryScore::A);
        result.execution_time = Some(Duration::new(StdDuration::from_secs(10)));

        let mut tests = vec![TestResult::new("Ping")];
        tests[0].verdict = TestVerdict::Ok;
        result.targets.insert("peer1".to_string(), tests);

        let mut buf = Vec::new();
        write_result_to_writer(&result, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("TEST NAME"));
        assert!(output.contains("RESULT"));
        assert!(output.contains("Ping"));
        assert!(output.contains("OK"));
    }

    #[test]
    fn test_must_output_to_file_on_quiet() {
        assert!(must_output_to_file_on_quiet(false, "").is_ok());
        assert!(must_output_to_file_on_quiet(true, "out.json").is_ok());
        assert!(must_output_to_file_on_quiet(true, "").is_err());
    }

    // Ground truth from Go fastssz (with Duration as string format matching Rust)
    const GO_HASH_EMPTY: &str = "7b7d000000000000000000000000000000000000000000000000000000000000";
    const GO_HASH_SINGLE_CATEGORY: &str =
        "bf90f36739059294e479cc3c35f5ca8762af9313fe72603b3f40ef38e3418801";

    fn assert_hash(data: &AllCategoriesResult, expected_go_hash: &str) {
        let json_bytes = serde_json::to_vec(data).expect("Failed to serialize to JSON");
        let rust_hash = hash_ssz(&json_bytes).expect("hash_ssz failed");
        assert_eq!(hex::encode(rust_hash), expected_go_hash);
    }

    #[test]
    fn test_hash_ssz_empty_all_categories_result() {
        assert_hash(&AllCategoriesResult::default(), GO_HASH_EMPTY);
    }

    #[test]
    fn test_hash_ssz_single_category_one_test() {
        let mut targets = HashMap::new();
        targets.insert(
            "peer1".to_string(),
            vec![TestResult {
                name: "Ping".to_string(),
                verdict: TestVerdict::Ok,
                measurement: "10ms".to_string(),
                suggestion: String::new(),
                error: TestResultError::empty(),
                is_acceptable: false,
            }],
        );

        let peers = TestCategoryResult {
            category_name: Some(TestCategory::Peers),
            targets,
            execution_time: Some(Duration::new(StdDuration::from_nanos(1_500_000_000))),
            score: Some(CategoryScore::A),
        };

        let data = AllCategoriesResult {
            peers: Some(peers),
            beacon: None,
            validator: None,
            mev: None,
            infra: None,
        };

        assert_hash(&data, GO_HASH_SINGLE_CATEGORY);
    }
}
