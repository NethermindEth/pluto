//! Shared types and helper functions for all test categories.

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, io::Write, path::Path, time::Duration as StdDuration};

use crate::{
    ascii::{append_score, get_category_ascii, get_score_ascii},
    duration::Duration,
    error::{CliError, Result as CliResult},
};

use k256::SecretKey;
use pluto_app::obolapi::{Client, ClientOptions};
use pluto_eth2util::enr::Record;
use pluto_k1util::{load, sign};
use pluto_ssz::{HashWalker, Hasher};
use reqwest::{Method, StatusCode, header::CONTENT_TYPE};
use serde_with::{base64::Base64, serde_as};
use std::os::unix::fs::PermissionsExt as _;
use tokio::io::AsyncReadExt;

/// Test category identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TestCategory {
    Peers,
    Beacon,
    Validator,
    Mev,
    Infra,
    All,
}

impl fmt::Display for TestCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TestCategory::Peers => "peers",
            TestCategory::Beacon => "beacon",
            TestCategory::Validator => "validator",
            TestCategory::Mev => "mev",
            TestCategory::Infra => "infra",
            TestCategory::All => "all",
        })
    }
}

/// Test verdict indicating the outcome of a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum TestVerdict {
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
pub(crate) enum CategoryScore {
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
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct TestResultError(String);

impl TestResultError {
    pub(crate) fn empty() -> Self {
        Self(String::new())
    }

    pub(crate) fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn message(&self) -> Option<&str> {
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct TestResult {
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
pub(crate) struct TestCaseName {
    pub name: &'static str,
    pub order: u32,
}

impl TestCaseName {
    pub const fn new(name: &'static str, order: u32) -> Self {
        Self { name, order }
    }
}

/// Result of a test category.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct TestCategoryResult {
    #[serde(
        rename = "category_name",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub category_name: Option<TestCategory>,

    #[serde(rename = "targets", skip_serializing_if = "HashMap::is_empty", default)]
    pub targets: HashMap<String, Vec<TestResult>>,

    // NOTE: Duration wraps Go's time.Duration and mimics the same formatting for compatibility.
    // This works correctly but isn't ideal design - duration formatting typically varies between
    // languages.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub(crate) struct AllCategoriesResult {
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
pub(crate) async fn publish_result_to_obol_api(
    data: AllCategoriesResult,
    api_url: impl AsRef<str>,
    private_key_file: impl AsRef<Path>,
) -> CliResult<()> {
    let private_key = load_or_generate_key(private_key_file.as_ref()).await?;
    let enr = Record::new(&private_key, vec![])?;
    let sign_data_bytes = serde_json::to_vec(&data)?;
    let hash = hash_ssz(&sign_data_bytes)?;
    let sig = sign(&private_key, &hash)?;

    let result = ObolApiResult {
        enr: enr.to_string(),
        sig: sig.to_vec(),
        data,
    };

    let obol_api_json = serde_json::to_vec(&result)?;
    let client = Client::new(api_url.as_ref(), ClientOptions::default())?;
    client.post_test_result(obol_api_json).await?;

    Ok(())
}

/// Writes test results to a JSON file.
pub(crate) async fn write_result_to_file(
    result: &TestCategoryResult,
    path: &Path,
) -> CliResult<()> {
    let mut existing_file: tokio::fs::File = tokio::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o644)
        .open(path)
        .await?;

    let stat = existing_file.metadata().await?;

    let mut all_results: AllCategoriesResult = if stat.len() == 0 {
        AllCategoriesResult::default()
    } else {
        let mut buf = Vec::new();
        existing_file.read_to_end(&mut buf).await?;
        serde_json::from_slice(&buf)?
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

    let dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let base = path
        .file_name()
        .ok_or_else(|| CliError::Other(format!("no filename in path: {}", path.display())))?
        .to_string_lossy()
        .to_string();
    let path_buf = path.to_path_buf();

    let file_content_json = serde_json::to_vec(&all_results)?;

    // tempfile is a synchronous crate, but keep existing_file open during operation
    tokio::task::spawn_blocking(move || -> CliResult<()> {
        use std::io::Write as _;

        let mut tmp_file = tempfile::Builder::new()
            .prefix(&format!("{base}-tmp-"))
            .suffix(".json")
            .tempfile_in(&dir)?;

        tmp_file
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;

        tmp_file.as_file_mut().write_all(&file_content_json)?;

        tmp_file
            .persist(&path_buf)
            .map_err(|e| CliError::Io(e.error))?;

        Ok(())
    })
    .await
    .map_err(|e| CliError::Other(format!("spawn_blocking: {}", e)))?
}

/// Writes test results to a writer (stdout or file).
pub(crate) fn write_result_to_writer<W: Write + ?Sized>(
    result: &TestCategoryResult,
    writer: &mut W,
) -> CliResult<()> {
    let mut lines = Vec::new();

    // Add category ASCII art
    lines.extend(get_category_ascii(&result.category_name));

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
pub(crate) fn evaluate_highest_rtt(
    rtts: Vec<StdDuration>,
    result: TestResult,
    avg_threshold: StdDuration,
    poor_threshold: StdDuration,
) -> TestResult {
    let highest_rtt = rtts.into_iter().max().unwrap_or_default();
    evaluate_rtt(highest_rtt, result, avg_threshold, poor_threshold)
}

/// Evaluates RTT (Round Trip Time) and assigns a verdict based on thresholds.
pub(crate) fn evaluate_rtt(
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
pub(crate) fn calculate_score(results: &[TestResult]) -> CategoryScore {
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
pub(crate) fn filter_tests(
    supported_test_cases: &[TestCaseName],
    test_cases: Option<&[String]>,
) -> Vec<TestCaseName> {
    let mut filtered: Vec<TestCaseName> = supported_test_cases.to_vec();
    if let Some(cases) = test_cases {
        filtered.retain(|supported_case| cases.iter().any(|c| c == supported_case.name));
    }
    filtered
}

/// Sorts tests by their order field.
pub(crate) fn sort_tests(tests: &mut [TestCaseName]) {
    tests.sort_by_key(|t| t.order);
}

pub(crate) fn must_output_to_file_on_quiet(
    quiet: bool,
    output_json: impl AsRef<str>,
) -> CliResult<()> {
    if quiet && output_json.as_ref().is_empty() {
        Err(CliError::Other(
            "on --quiet, an --output-json is required".to_string(),
        ))
    } else {
        Ok(())
    }
}

async fn load_or_generate_key(path: &Path) -> CliResult<SecretKey> {
    if tokio::fs::try_exists(path).await? {
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

pub(crate) fn hash_ssz(data: &[u8]) -> CliResult<[u8; 32]> {
    if data.is_empty() {
        return Ok([0u8; 32]);
    }

    let mut hasher: Hasher = Hasher::default();
    let index = hasher.index();

    hasher.put_bytes(data)?;
    hasher.merkleize(index)?;

    Ok(hasher.hash_root()?)
}

/// Measures the round-trip time (RTT) for an HTTP request and logs a warning if
/// the response status code doesn't match the expected status.
pub(crate) async fn request_rtt(
    url: impl AsRef<str>,
    method: Method,
    body: Option<Vec<u8>>,
    expected_status: StatusCode,
) -> CliResult<StdDuration> {
    let client = reqwest::Client::new();

    let mut request_builder = client.request(method, url.as_ref());

    if let Some(body_bytes) = body {
        request_builder = request_builder
            .header(CONTENT_TYPE, "application/json")
            .body(body_bytes);
    }

    let start = std::time::Instant::now();
    let response = request_builder.send().await?;
    let rtt = start.elapsed();

    let status = response.status();
    if status == expected_status {
        return Ok(rtt);
    }

    if status.as_u16() > 399 {
        return Err(CliError::Other(format!(
            "HTTP status code {}",
            status.as_u16()
        )));
    }

    match response.text().await {
        Ok(body) if !body.is_empty() => tracing::warn!(
            status_code = status.as_u16(),
            expected_status_code = expected_status.as_u16(),
            endpoint = url.as_ref(),
            body = body,
            "Unexpected status code"
        ),
        _ => tracing::warn!(
            status_code = status.as_u16(),
            expected_status_code = expected_status.as_u16(),
            endpoint = url.as_ref(),
            "Unexpected status code"
        ),
    }

    Ok(rtt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn calculate_score_output() {
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
    fn must_output_to_file_on_quiet_output() {
        assert!(must_output_to_file_on_quiet(false, "").is_ok());
        assert!(must_output_to_file_on_quiet(true, "out.json").is_ok());
        assert!(must_output_to_file_on_quiet(true, "").is_err());
    }

    // Ground truth from Go fastssz (with Duration as string format matching Rust)
    const GO_HASH_EMPTY: &str = "7b7d000000000000000000000000000000000000000000000000000000000000";
    const GO_HASH_ALL_CATEGORIES: &str =
        "64469d918903e272849172b3b36e812f602411b664a89b59c04393332b69f63b";

    fn assert_hash(data: &AllCategoriesResult, expected_go_hash: &str) {
        let json_bytes = serde_json::to_vec(data).expect("Failed to serialize to JSON");
        let rust_hash = hash_ssz(&json_bytes).expect("hash_ssz failed");
        assert_eq!(hex::encode(rust_hash), expected_go_hash);
    }

    #[test]
    fn hash_ssz_empty_all_categories_result() {
        assert_hash(&AllCategoriesResult::default(), GO_HASH_EMPTY);
    }

    #[test]
    fn hash_ssz_multi_category_result() {
        use crate::duration::Duration;

        let result = AllCategoriesResult {
            peers: Some(TestCategoryResult {
                category_name: Some(TestCategory::Peers),
                targets: HashMap::from([(
                    "peer1".to_string(),
                    vec![TestResult {
                        name: "Test1".to_string(),
                        verdict: TestVerdict::Ok,
                        measurement: String::new(),
                        suggestion: String::new(),
                        error: TestResultError::empty(),
                        is_acceptable: false,
                    }],
                )]),
                execution_time: Some(Duration::new(std::time::Duration::from_nanos(1500000000))),
                score: Some(CategoryScore::A),
            }),
            beacon: Some(TestCategoryResult {
                category_name: Some(TestCategory::Beacon),
                targets: HashMap::from([(
                    "beacon1".to_string(),
                    vec![TestResult {
                        name: "Test2".to_string(),
                        verdict: TestVerdict::Good,
                        measurement: String::new(),
                        suggestion: String::new(),
                        error: TestResultError::empty(),
                        is_acceptable: false,
                    }],
                )]),
                execution_time: Some(Duration::new(std::time::Duration::from_nanos(2500000000))),
                score: Some(CategoryScore::A),
            }),
            validator: Some(TestCategoryResult {
                category_name: Some(TestCategory::Validator),
                targets: HashMap::from([(
                    "validator1".to_string(),
                    vec![TestResult {
                        name: "Test3".to_string(),
                        verdict: TestVerdict::Avg,
                        measurement: String::new(),
                        suggestion: String::new(),
                        error: TestResultError::empty(),
                        is_acceptable: false,
                    }],
                )]),
                execution_time: Some(Duration::new(std::time::Duration::from_nanos(500000000))),
                score: Some(CategoryScore::B),
            }),
            mev: Some(TestCategoryResult {
                category_name: Some(TestCategory::Mev),
                targets: HashMap::from([(
                    "mev1".to_string(),
                    vec![TestResult {
                        name: "Test4".to_string(),
                        verdict: TestVerdict::Poor,
                        measurement: String::new(),
                        suggestion: String::new(),
                        error: TestResultError::empty(),
                        is_acceptable: false,
                    }],
                )]),
                execution_time: Some(Duration::new(std::time::Duration::from_nanos(3000000000))),
                score: Some(CategoryScore::C),
            }),
            infra: Some(TestCategoryResult {
                category_name: Some(TestCategory::Infra),
                targets: HashMap::from([(
                    "server1".to_string(),
                    vec![TestResult {
                        name: "Test5".to_string(),
                        verdict: TestVerdict::Skip,
                        measurement: String::new(),
                        suggestion: String::new(),
                        error: TestResultError::empty(),
                        is_acceptable: false,
                    }],
                )]),
                execution_time: Some(Duration::new(std::time::Duration::from_nanos(1000000000))),
                score: Some(CategoryScore::A),
            }),
        };

        assert_hash(&result, GO_HASH_ALL_CATEGORIES);
    }

    #[tokio::test]
    async fn test_write_result_to_file_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.json");

        let mut result = TestCategoryResult::new(TestCategory::Peers);
        result.score = Some(CategoryScore::A);
        let mut tests = vec![TestResult::new("Ping")];
        tests[0].verdict = TestVerdict::Ok;
        tests[0].measurement = "5ms".to_string();
        result.targets.insert("peer1".to_string(), tests);

        write_result_to_file(&result, &path).await.unwrap();

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let written: AllCategoriesResult = serde_json::from_str(&content).unwrap();

        let expected = AllCategoriesResult {
            peers: Some(result),
            ..Default::default()
        };
        assert_eq!(written, expected);
    }

    #[tokio::test]
    async fn test_write_result_to_file_merges_categories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.json");

        let mut peers = TestCategoryResult::new(TestCategory::Peers);
        peers.score = Some(CategoryScore::A);
        peers
            .targets
            .insert("peer1".to_string(), vec![TestResult::new("Ping")]);
        write_result_to_file(&peers, &path).await.unwrap();

        let mut beacon = TestCategoryResult::new(TestCategory::Beacon);
        beacon.score = Some(CategoryScore::B);
        beacon.targets.insert(
            "http://beacon:5052".to_string(),
            vec![TestResult::new("Version")],
        );
        write_result_to_file(&beacon, &path).await.unwrap();

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let written: AllCategoriesResult = serde_json::from_str(&content).unwrap();

        let expected = AllCategoriesResult {
            peers: Some(peers),
            beacon: Some(beacon),
            ..Default::default()
        };
        assert_eq!(written, expected);
    }

    #[tokio::test]
    async fn test_write_result_to_file_overwrites_same_category() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.json");

        let mut first = TestCategoryResult::new(TestCategory::Peers);
        first.score = Some(CategoryScore::A);
        first
            .targets
            .insert("peer1".to_string(), vec![TestResult::new("Ping")]);
        write_result_to_file(&first, &path).await.unwrap();

        let mut second = TestCategoryResult::new(TestCategory::Peers);
        second.score = Some(CategoryScore::C);
        second
            .targets
            .insert("peer2".to_string(), vec![TestResult::new("PingMeasure")]);
        write_result_to_file(&second, &path).await.unwrap();

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let written: AllCategoriesResult = serde_json::from_str(&content).unwrap();

        let expected = AllCategoriesResult {
            peers: Some(second),
            ..Default::default()
        };
        assert_eq!(written, expected);
    }

    fn sample_test_cases() -> Vec<TestCaseName> {
        vec![
            TestCaseName::new("Ping", 0),
            TestCaseName::new("Version", 1),
            TestCaseName::new("Health", 2),
        ]
    }

    #[test]
    fn filter_tests_unsupported_case_filtered_out() {
        let supported = sample_test_cases();
        let filtered = filter_tests(&supported, Some(&["notSupportedTest".into()]));
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_tests_specific_case() {
        let supported = sample_test_cases();
        let filtered = filter_tests(&supported, Some(&["Ping".into()]));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "Ping");
    }

    #[test]
    fn filter_tests_none_returns_all() {
        let supported = sample_test_cases();
        let filtered = filter_tests(&supported, None);
        assert_eq!(filtered.len(), supported.len());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_write_result_to_file_sets_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.json");

        let result = TestCategoryResult::new(TestCategory::Infra);
        write_result_to_file(&result, &path).await.unwrap();

        let metadata = tokio::fs::metadata(&path).await.unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o644);
    }

    #[tokio::test]
    async fn test_write_result_to_file_all_categories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.json");

        let mut expected = AllCategoriesResult::default();
        let categories = [
            TestCategory::Peers,
            TestCategory::Beacon,
            TestCategory::Validator,
            TestCategory::Mev,
            TestCategory::Infra,
        ];

        for category in &categories {
            let mut result = TestCategoryResult::new(*category);
            result.score = Some(CategoryScore::A);
            result.targets.insert(
                format!("target-{}", category),
                vec![TestResult::new("Ping")],
            );
            write_result_to_file(&result, &path).await.unwrap();

            match category {
                TestCategory::Peers => expected.peers = Some(result),
                TestCategory::Beacon => expected.beacon = Some(result),
                TestCategory::Validator => expected.validator = Some(result),
                TestCategory::Mev => expected.mev = Some(result),
                TestCategory::Infra => expected.infra = Some(result),
                TestCategory::All => unreachable!(),
            }
        }

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let written: AllCategoriesResult = serde_json::from_str(&content).unwrap();

        assert_eq!(written, expected);
    }
}
