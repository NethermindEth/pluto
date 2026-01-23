//! Peer connectivity tests.

use super::config::TestConfigArgs;
use super::types::TestCategoryResult;
use crate::error::Result;
use clap::Args;
use std::io::Write;

/// Arguments for the peers test command.
#[derive(Args, Clone, Debug)]
pub struct TestPeersArgs {
    #[command(flatten)]
    pub test_config: TestConfigArgs,

    /// Comma-separated list of each peer ENR address.
    #[arg(long = "enrs", value_delimiter = ',')]
    pub enrs: Option<Vec<String>>,

    // TODO: Add remaining flags from Go implementation
}

/// Runs the peer connectivity tests.
pub async fn run(_args: TestPeersArgs, _writer: &mut dyn Write) -> Result<TestCategoryResult> {
    // TODO: Implement peer tests
    // - Ping
    // - PingMeasure
    // - PingLoad
    // - DirectConn
    // - Libp2pTCPPortOpen
    // - Relay tests
    unimplemented!("peers test not yet implemented")
}
