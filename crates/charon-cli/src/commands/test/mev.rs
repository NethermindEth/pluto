//! MEV relay tests.

use super::config::TestConfigArgs;
use super::types::TestCategoryResult;
use crate::error::Result;
use clap::Args;
use std::io::Write;

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

/// Runs the MEV relay tests.
pub async fn run(_args: TestMevArgs, _writer: &mut dyn Write) -> Result<TestCategoryResult> {
    // TODO: Implement MEV tests
    // - Ping
    // - PingMeasure
    // - CreateBlock
    unimplemented!("mev test not yet implemented")
}
