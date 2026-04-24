//! Test command module for cluster evaluation.
//!
//! This module provides a comprehensive test suite to evaluate the current
//! cluster setup, including tests for peers, beacon nodes, validator clients,
//! MEV relays, and infrastructure.

// TODO: Foundation for the test command, the detail will be implemented later
#![allow(dead_code)]

pub mod all;
pub mod beacon;
pub mod constants;
pub mod helpers;
pub mod infra;
pub mod mev;
pub mod peers;
pub mod validator;

pub(crate) use helpers::*;

use clap::Args;
use std::{path::PathBuf, time::Duration as StdDuration};

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
fn list_test_cases(category: TestCategory) -> Vec<String> {
    // Returns available test case names for each category.
    match category {
        TestCategory::Validator => validator::ValidatorTestCase::all()
            .iter()
            .map(|tc| tc.to_string())
            .collect(),
        TestCategory::Beacon => beacon::test_case_names(),
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

/// Updates the `--test-cases` argument help text to include available tests
/// dynamically.
pub fn update_test_cases_help(mut cmd: clap::Command) -> clap::Command {
    if let Some(alpha_cmd) = cmd.find_subcommand_mut("alpha")
        && let Some(test_cmd) = alpha_cmd.find_subcommand_mut("test")
    {
        for category in &[
            TestCategory::Validator,
            TestCategory::Beacon,
            TestCategory::Mev,
            TestCategory::Peers,
            TestCategory::Infra,
            TestCategory::All,
        ] {
            if let Some(category_cmd) = test_cmd.find_subcommand_mut(category.to_string()) {
                let available_tests = list_test_cases(*category);
                let help_text = format!(
                    "Comma-separated list of test names to execute. Available tests are: {}",
                    available_tests.join(", ")
                );

                *category_cmd = category_cmd.clone().mut_arg("test_cases", |arg| {
                    arg.help(help_text.clone()).long_help(help_text)
                });
            }
        }
    }
    cmd
}
