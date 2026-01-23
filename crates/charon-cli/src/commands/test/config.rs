//! Shared test configuration types.

use clap::Args;
use std::path::PathBuf;
use std::time::Duration;

/// Base test configuration shared by all test commands.
#[derive(Args, Clone, Debug)]
pub struct TestConfigArgs {
    /// File path to which output can be written in JSON format.
    #[arg(long = "output-json", default_value = "")]
    pub output_json: String,

    /// Do not print test results to stdout.
    #[arg(long)]
    pub quiet: bool,

    /// List of comma separated names of tests to be executed.
    #[arg(long = "test-cases", value_delimiter = ',')]
    pub test_cases: Option<Vec<String>>,

    /// Execution timeout for all tests.
    #[arg(long, default_value = "1h", value_parser = parse_duration)]
    pub timeout: Duration,

    /// Publish test result file to obol-api.
    #[arg(long)]
    pub publish: bool,

    /// The URL to publish the test result file to.
    #[arg(long = "publish-address", default_value = "https://api.obol.tech/v1")]
    pub publish_addr: String,

    /// The path to the charon enr private key file, used for signing the publish request.
    #[arg(
        long = "publish-private-key-file",
        default_value = ".charon/charon-enr-private-key"
    )]
    pub publish_private_key_file: PathBuf,
}

/// Parses duration strings like "1h", "30m", "10s".
fn parse_duration(s: &str) -> Result<Duration, String> {
    // Simple duration parser - matches Go's time.ParseDuration behavior
    let s = s.trim();

    if let Some(val) = s.strip_suffix("ns") {
        val.parse::<u64>()
            .map(Duration::from_nanos)
            .map_err(|e| e.to_string())
    } else if let Some(val) = s.strip_suffix("us") {
        val.parse::<u64>()
            .map(Duration::from_micros)
            .map_err(|e| e.to_string())
    } else if let Some(val) = s.strip_suffix("µs") {
        val.parse::<u64>()
            .map(Duration::from_micros)
            .map_err(|e| e.to_string())
    } else if let Some(val) = s.strip_suffix("ms") {
        val.parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|e| e.to_string())
    } else if let Some(val) = s.strip_suffix('s') {
        val.parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|e| e.to_string())
    } else if let Some(val) = s.strip_suffix('m') {
        val.parse::<u64>()
            .map(|m| Duration::from_secs(m * 60))
            .map_err(|e| e.to_string())
    } else if let Some(val) = s.strip_suffix('h') {
        val.parse::<u64>()
            .map(|h| Duration::from_secs(h * 3600))
            .map_err(|e| e.to_string())
    } else {
        Err(format!("invalid duration: {}", s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("100us").unwrap(), Duration::from_micros(100));
        assert!(parse_duration("invalid").is_err());
    }
}
