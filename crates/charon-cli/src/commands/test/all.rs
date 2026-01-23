//! Run all test categories.

use super::{
    beacon::TestBeaconArgs, config::TestConfigArgs, infra::TestInfraArgs, mev::TestMevArgs,
    peers::TestPeersArgs, validator::TestValidatorArgs,
};
use crate::error::Result;
use clap::Args;
use std::io::Write;

/// Arguments for the all tests command.
#[derive(Args, Clone, Debug)]
pub struct TestAllArgs {
    #[command(flatten)]
    pub test_config: TestConfigArgs,

    // Include all sub-test configs with prefixes
    #[command(flatten)]
    pub peers: TestPeersArgs,

    #[command(flatten)]
    pub beacon: TestBeaconArgs,

    #[command(flatten)]
    pub validator: TestValidatorArgs,

    #[command(flatten)]
    pub mev: TestMevArgs,

    #[command(flatten)]
    pub infra: TestInfraArgs,
}

/// Runs all test categories.
pub async fn run(_args: TestAllArgs, _writer: &mut dyn Write) -> Result<()> {
    // TODO: Implement orchestration of all tests
    // Run tests sequentially in order:
    // 1. Beacon
    // 2. Validator
    // 3. MEV
    // 4. Infra
    // 5. Peers
    //
    // Write results for each category
    unimplemented!("all test not yet implemented")
}
