//! Core types for test results and verdicts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::Duration as StdDuration;

/// Test verdict indicating the outcome of a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestVerdict {
    /// Boolean test passed.
    #[serde(rename = "OK")]
    Ok,
    /// Measurement test - good performance.
    Good,
    /// Measurement test - average performance.
    Avg,
    /// Measurement test - poor performance.
    Poor,
    /// Test failed.
    Fail,
    /// Test was skipped.
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
#[derive(Debug, Clone, Default)]
pub struct TestResultError {
    error: Option<String>,
}

impl TestResultError {
    /// Creates a new empty error.
    pub fn empty() -> Self {
        Self { error: None }
    }

    /// Creates a new error from a string.
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            error: Some(msg.into()),
        }
    }

    /// Returns the error message if present.
    pub fn message(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Returns true if there is no error.
    pub fn is_empty(&self) -> bool {
        self.error.is_none()
    }
}

impl fmt::Display for TestResultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.error {
            Some(err) => write!(f, "{}", err),
            None => Ok(()),
        }
    }
}

impl Serialize for TestResultError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.error {
            Some(err) => serializer.serialize_str(err),
            None => serializer.serialize_str(""),
        }
    }
}

impl<'de> Deserialize<'de> for TestResultError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(if s.is_empty() {
            Self::empty()
        } else {
            Self::new(s)
        })
    }
}

impl<E: std::error::Error> From<E> for TestResultError {
    fn from(err: E) -> Self {
        Self::new(err.to_string())
    }
}

/// Result of a single test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "verdict")]
    pub verdict: TestVerdict,

    #[serde(rename = "measurement", skip_serializing_if = "String::is_empty", default)]
    pub measurement: String,

    #[serde(rename = "suggestion", skip_serializing_if = "String::is_empty", default)]
    pub suggestion: String,

    #[serde(rename = "error", skip_serializing_if = "TestResultError::is_empty", default)]
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

/// Result of a test category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCategoryResult {
    #[serde(rename = "category_name", skip_serializing_if = "String::is_empty", default)]
    pub category_name: String,

    #[serde(rename = "targets", skip_serializing_if = "HashMap::is_empty", default)]
    pub targets: HashMap<String, Vec<TestResult>>,

    #[serde(rename = "execution_time", skip_serializing_if = "Option::is_none")]
    pub execution_time: Option<Duration>,

    #[serde(rename = "score", skip_serializing_if = "Option::is_none")]
    pub score: Option<CategoryScore>,
}

impl TestCategoryResult {
    /// Creates a new test category result with the given name.
    pub fn new(category_name: impl Into<String>) -> Self {
        Self {
            category_name: category_name.into(),
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

/// Custom Duration wrapper with JSON serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Duration {
    inner: StdDuration,
}

impl Duration {
    /// Creates a new Duration from a std::time::Duration.
    pub fn new(duration: StdDuration) -> Self {
        Self { inner: duration }
    }

    /// Returns the inner std::time::Duration.
    pub fn as_std(&self) -> StdDuration {
        self.inner
    }

    /// Rounds the duration based on its magnitude (matching Go's RoundDuration).
    pub fn round(self) -> Self {
        let rounded = if self.inner > StdDuration::from_secs(1) {
            // Round to 10ms
            let millis = self.inner.as_millis();
            let rounded_millis = (millis + 5) / 10 * 10;
            StdDuration::from_millis(rounded_millis as u64)
        } else if self.inner > StdDuration::from_millis(1) {
            // Round to 1ms
            let millis = self.inner.as_millis();
            StdDuration::from_millis(millis as u64)
        } else if self.inner > StdDuration::from_micros(1) {
            // Round to 1μs
            let micros = self.inner.as_micros();
            StdDuration::from_micros(micros as u64)
        } else {
            self.inner
        };

        Self::new(rounded)
    }
}

impl From<StdDuration> for Duration {
    fn from(duration: StdDuration) -> Self {
        Self::new(duration)
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format duration as Go does: "1.234s", "123ms", "1.234µs", etc.
        let duration = self.inner;
        if duration >= StdDuration::from_secs(1) {
            write!(f, "{:.3}s", duration.as_secs_f64())
        } else if duration >= StdDuration::from_millis(1) {
            write!(f, "{}ms", duration.as_millis())
        } else if duration >= StdDuration::from_micros(1) {
            write!(f, "{}µs", duration.as_micros())
        } else {
            write!(f, "{}ns", duration.as_nanos())
        }
    }
}

impl Serialize for Duration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // Try parsing as integer (nanoseconds)
        if let Ok(nanos) = s.parse::<u64>() {
            return Ok(Self::new(StdDuration::from_nanos(nanos)));
        }

        // Try parsing as duration string
        // This is a simplified parser - may need humantime crate for full compatibility
        if let Some(val) = s.strip_suffix("ns") {
            if let Ok(n) = val.parse::<u64>() {
                return Ok(Self::new(StdDuration::from_nanos(n)));
            }
        } else if let Some(val) = s.strip_suffix("µs") {
            if let Ok(n) = val.parse::<u64>() {
                return Ok(Self::new(StdDuration::from_micros(n)));
            }
        } else if let Some(val) = s.strip_suffix("ms") {
            if let Ok(n) = val.parse::<u64>() {
                return Ok(Self::new(StdDuration::from_millis(n)));
            }
        } else if let Some(val) = s.strip_suffix('s') {
            if let Ok(n) = val.parse::<f64>() {
                return Ok(Self::new(StdDuration::from_secs_f64(n)));
            }
        }

        Err(serde::de::Error::custom("invalid duration"))
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
    pub fn new(name: impl Into<String>, order: u32) -> Self {
        Self {
            name: name.into(),
            order,
        }
    }
}
