//! Infrastructure and hardware tests.

use super::{config::TestConfigArgs, types::TestCategoryResult};
use crate::error::Result;
use clap::Args;
use std::io::Write;

/// Arguments for the infra test command.
#[derive(Args, Clone, Debug)]
pub struct TestInfraArgs {
    #[command(flatten)]
    pub test_config: TestConfigArgs,

    /// Directory at which disk performance will be measured.
    #[arg(
        long = "disk-io-test-file-dir",
        help = "Directory at which disk performance will be measured. If none specified, current user's home directory will be used."
    )]
    pub disk_io_test_file_dir: Option<String>,

    /// The block size in kilobytes used for I/O units.
    #[arg(
        long = "disk-io-block-size-kb",
        default_value = "4096",
        help = "The block size in kilobytes used for I/O units. Same value applies for both reads and writes."
    )]
    pub disk_io_block_size_kb: i32,

    /// List of specific server names to be included for the internet tests.
    #[arg(
        long = "internet-test-servers-only",
        value_delimiter = ',',
        help = "List of specific server names to be included for the internet tests, the best performing one is chosen. If not provided, closest and best performing servers are chosen automatically."
    )]
    pub internet_test_servers_only: Vec<String>,

    /// List of server names to be excluded from the tests.
    #[arg(
        long = "internet-test-servers-exclude",
        value_delimiter = ',',
        help = "List of server names to be excluded from the tests. To be specified only if you experience issues with a server that is wrongly considered best performing."
    )]
    pub internet_test_servers_exclude: Vec<String>,
}

/// Runs the infrastructure tests.
pub async fn run(_args: TestInfraArgs, _writer: &mut dyn Write) -> Result<TestCategoryResult> {
    // TODO: Implement infra tests
    // - DiskWriteSpeed
    // - DiskWriteIOPS
    // - DiskReadSpeed
    // - DiskReadIOPS
    // - AvailableMemory
    // - TotalMemory
    // - InternetLatency
    // - InternetDownloadSpeed
    // - InternetUploadSpeed
    unimplemented!("infra test not yet implemented")
}
