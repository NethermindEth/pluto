//! Beacon node API tests.

use super::{TestCategoryResult, TestConfigArgs};
use crate::error::Result;
use clap::Args;
use std::io::Write;

/// Arguments for the beacon test command.
#[derive(Args, Clone, Debug)]
pub struct TestBeaconArgs {
    #[command(flatten)]
    pub test_config: TestConfigArgs,

    /// Beacon node endpoint URLs.
    #[arg(
        long = "endpoints",
        value_delimiter = ',',
        help = "Comma separated list of one or more beacon node endpoint URLs."
    )]
    pub endpoints: Vec<String>,
    // TODO: Add remaining flags from Go implementation
}

/// Runs the beacon node tests.
pub async fn run(_args: TestBeaconArgs, _writer: &mut dyn Write) -> Result<TestCategoryResult> {
    // TODO: Implement beacon tests
    // - Ping
    // - PingMeasure
    // - Synced
    // - Version
    // - Pubkeys
    // - etc.
    unimplemented!("beacon test not yet implemented")
}
