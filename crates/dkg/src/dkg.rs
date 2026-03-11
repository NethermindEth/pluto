/// DKG configuration
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Path to the definition file. Can be an URL or an absolute path on disk.
    pub def_file: String,
    /// Skip cluster definition verification.
    pub no_verify: bool,
    /// Test configuration, used for testing purposes.
    pub test_config: TestConfig,
}

/// Additional test-only config for DKG.
#[derive(Debug, Clone, Default)]
pub struct TestConfig {
    /// Provides the cluster definition explicitly, skips loading from disk.
    pub def: Option<pluto_cluster::definition::Definition>,
}
