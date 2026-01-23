//! Validator client connectivity tests.

use super::{config::TestConfigArgs, types::TestCategoryResult};
use crate::error::Result;
use clap::Args;
use std::io::Write;

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

    /// Time to keep running the load tests in seconds.
    #[arg(
        long = "load-test-duration",
        default_value = "5s",
        help = "Time to keep running the load tests in seconds. For each second a new continuous ping instance is spawned."
    )]
    pub load_test_duration: String,
}

/// Runs the validator client tests.
pub async fn run(_args: TestValidatorArgs, _writer: &mut dyn Write) -> Result<TestCategoryResult> {
    // TODO: Implement validator tests
    // - Ping
    // - PingMeasure
    // - PingLoad
    unimplemented!("validator test not yet implemented")
}
