use std::{path, time::Duration};

use bon::Builder;
use tokio_util::sync::CancellationToken;
use tracing::warn;

const DEFAULT_DATA_DIR: &str = ".charon";
const DEFAULT_DEFINITION_FILE: &str = ".charon/cluster-definition.json";
const DEFAULT_RELAYS: [&str; 3] = [
    "https://0.relay.obol.tech",
    "https://2.relay.obol.dev",
    "https://1.relay.obol.tech",
];
const DEFAULT_PUBLISH_ADDRESS: &str = "https://api.obol.tech/v1";
const DEFAULT_PUBLISH_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_SHUTDOWN_DELAY: Duration = Duration::from_secs(1);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Entry-point DKG error.
#[derive(Debug, thiserror::Error)]
pub enum DkgError {
    /// Shutdown was requested before the DKG entrypoint started.
    #[error("DKG shutdown requested before startup")]
    ShutdownRequestedBeforeStartup,

    /// Keymanager address was provided without the auth token.
    #[error(
        "--keymanager-address provided but --keymanager-auth-token absent. Please fix configuration flags"
    )]
    MissingKeymanagerAuthToken,

    /// Keymanager auth token was provided without the address.
    #[error(
        "--keymanager-auth-token provided but --keymanager-address absent. Please fix configuration flags"
    )]
    MissingKeymanagerAddress,

    /// Failed to parse the keymanager address.
    #[error("failed to parse keymanager addr: {addr}: {source}")]
    InvalidKeymanagerAddress {
        /// The address that failed to parse.
        addr: String,
        /// The parse error.
        source: url::ParseError,
    },

    /// Failed to build the ETH1 client.
    #[error("ETH1 client setup failed: {0}")]
    Eth1Client(#[from] pluto_eth1wrap::EthClientError),

    /// Disk or definition preflight failed.
    #[error("DKG preflight failed: {0}")]
    Disk(#[from] crate::disk::DiskError),
}

/// Keymanager configuration accepted by the entrypoint.
#[derive(Debug, Clone, Default, Builder)]
pub struct KeymanagerConfig {
    /// The keymanager URL.
    pub address: String,
    /// Bearer token used for authentication.
    pub auth_token: String,
}

/// Publish configuration accepted by the entrypoint.
#[derive(Debug, Clone, Builder)]
pub struct PublishConfig {
    /// Publish API base address.
    pub address: String,
    /// Publish timeout.
    pub timeout: Duration,
    /// Whether publishing is enabled.
    pub enabled: bool,
}

impl Default for PublishConfig {
    fn default() -> Self {
        Self {
            address: DEFAULT_PUBLISH_ADDRESS.to_string(),
            timeout: DEFAULT_PUBLISH_TIMEOUT,
            enabled: false,
        }
    }
}

/// DKG configuration
#[derive(Debug, Clone, Builder)]
pub struct Config {
    /// Path to the definition file. Can be an URL or an absolute path on disk.
    #[builder(default = DEFAULT_DEFINITION_FILE.to_string())]
    pub def_file: String,
    /// Skip cluster definition verification.
    #[builder(default)]
    pub no_verify: bool,

    /// Data directory to store generated keys and other DKG artifacts.
    #[builder(default = path::PathBuf::from(DEFAULT_DATA_DIR))]
    pub data_dir: path::PathBuf,

    /// P2P entrypoint configuration.
    #[builder(default = default_p2p_config())]
    pub p2p: pluto_p2p::config::P2PConfig,

    /// Shared tracing configuration for the DKG entrypoint.
    #[builder(default = default_tracing_config())]
    pub log: pluto_tracing::TracingConfig,

    /// Keymanager configuration.
    #[builder(default)]
    pub keymanager: KeymanagerConfig,

    /// Publish configuration.
    #[builder(default)]
    pub publish: PublishConfig,

    /// Graceful shutdown delay after completion.
    #[builder(default = DEFAULT_SHUTDOWN_DELAY)]
    pub shutdown_delay: Duration,

    /// Overall DKG timeout.
    #[builder(default = DEFAULT_TIMEOUT)]
    pub timeout: Duration,

    /// Execution engine JSON-RPC endpoint.
    #[builder(default)]
    pub execution_engine_addr: String,

    /// Whether to bundle the output directory as a tarball.
    #[builder(default)]
    pub zipped: bool,

    /// Test configuration, used for testing purposes.
    #[builder(default)]
    pub test_config: TestConfig,
}

impl Config {
    /// Returns `true` if any test-only configuration is active.
    pub fn has_test_config(&self) -> bool {
        // TODO: Extend this when more test-only hooks are added to TestConfig,
        // so preflight skips stay aligned with the full test configuration.
        self.test_config.def.is_some()
    }
}

/// Additional test-only config for DKG.
#[derive(Debug, Clone, Default, Builder)]
pub struct TestConfig {
    /// Provides the cluster definition explicitly, skips loading from disk.
    pub def: Option<pluto_cluster::definition::Definition>,
}

fn default_p2p_config() -> pluto_p2p::config::P2PConfig {
    let relays = DEFAULT_RELAYS
        .iter()
        .map(|relay| libp2p::multiaddr::from_url(relay).expect("default relay should parse"))
        .collect();

    pluto_p2p::config::P2PConfig {
        relays,
        ..Default::default()
    }
}

fn default_tracing_config() -> pluto_tracing::TracingConfig {
    pluto_tracing::TracingConfig::builder()
        .with_default_console()
        .override_env_filter("info")
        .build()
}

/// Runs the DKG entrypoint until the unported backend boundary.
pub async fn run(conf: Config, shutdown: CancellationToken) -> Result<(), DkgError> {
    if shutdown.is_cancelled() {
        return Err(DkgError::ShutdownRequestedBeforeStartup);
    }

    let eth1 = pluto_eth1wrap::EthClient::new(&conf.execution_engine_addr).await?;

    let _definition = crate::disk::load_definition(&conf, &eth1).await?;

    validate_keymanager_flags(&conf)?;

    if !conf.has_test_config() {
        crate::disk::check_clear_data_dir(&conf.data_dir).await?;
    }
    crate::disk::check_writes(&conf.data_dir).await?;

    unimplemented!("DKG ceremony backend is not implemented yet");
}

fn validate_keymanager_flags(conf: &Config) -> Result<(), DkgError> {
    let addr = conf.keymanager.address.trim();
    let auth_token = conf.keymanager.auth_token.trim();

    if !addr.is_empty() && auth_token.is_empty() {
        return Err(DkgError::MissingKeymanagerAuthToken);
    }

    if addr.is_empty() && !auth_token.is_empty() {
        return Err(DkgError::MissingKeymanagerAddress);
    }

    if addr.is_empty() {
        return Ok(());
    }

    let parsed = url::Url::parse(addr).map_err(|source| DkgError::InvalidKeymanagerAddress {
        addr: addr.to_string(),
        source,
    })?;

    if parsed.scheme() == "http" {
        warn!(addr = addr, "Keymanager URL does not use https protocol");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::multiaddr;

    #[test]
    fn config_builder_defaults_match_charon() {
        let config = Config::builder().build();

        assert_eq!(config.def_file, DEFAULT_DEFINITION_FILE);
        assert!(!config.no_verify);
        assert_eq!(config.data_dir, path::PathBuf::from(DEFAULT_DATA_DIR));
        assert_eq!(
            config.p2p.relays,
            DEFAULT_RELAYS
                .iter()
                .map(|relay| multiaddr::from_url(relay).expect("default relay should parse"))
                .collect::<Vec<_>>()
        );
        assert_eq!(config.log.override_env_filter.as_deref(), Some("info"));
        assert!(config.log.console.is_some());
        assert_eq!(config.publish.address, DEFAULT_PUBLISH_ADDRESS);
        assert_eq!(config.publish.timeout, DEFAULT_PUBLISH_TIMEOUT);
        assert!(!config.publish.enabled);
        assert_eq!(config.shutdown_delay, DEFAULT_SHUTDOWN_DELAY);
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
        assert_eq!(config.execution_engine_addr, "");
        assert!(!config.zipped);
        assert!(config.test_config.def.is_none());
    }

    #[tokio::test]
    async fn run_rejects_mismatched_keymanager_flags() {
        let (lock, ..) = pluto_cluster::test_cluster::new_for_test(1, 3, 4, 0);

        let err = run(
            Config::builder()
                .test_config(
                    TestConfig::builder()
                        .def(lock.definition.clone())
                        .build(),
                )
                .keymanager(
                    KeymanagerConfig::builder()
                        .address("https://keymanager.example".to_string())
                        .auth_token(String::new())
                        .build(),
                )
                .build(),
            CancellationToken::new(),
        )
        .await
        .expect_err("mismatched keymanager flags should fail");

        assert!(matches!(err, DkgError::MissingKeymanagerAuthToken));
    }

    #[tokio::test]
    async fn run_executes_preflight_before_reaching_backend_boundary() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let definition_path = tempdir.path().join("cluster-definition.json");
        let private_key_path = tempdir.path().join("charon-enr-private-key");

        tokio::fs::write(&private_key_path, b"dummy")
            .await
            .expect("private key");

        let (lock, ..) = pluto_cluster::test_cluster::new_for_test(1, 3, 4, 0);
        let definition = serde_json::to_string(&lock.definition).expect("definition json");
        tokio::fs::write(&definition_path, definition)
            .await
            .expect("definition file");

        let join_err = tokio::spawn(async move {
            run(
                Config::builder()
                    .data_dir(tempdir.path().to_path_buf())
                    .def_file(definition_path.to_string_lossy().into_owned())
                    .no_verify(true)
                    .build(),
                CancellationToken::new(),
            )
            .await
        })
        .await
        .expect_err("backend handoff should panic until implemented");

        assert!(join_err.is_panic());
    }

    #[tokio::test]
    async fn run_surfaces_data_dir_preflight_errors() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let definition_path = tempdir.path().join("cluster-definition.json");

        let (lock, ..) = pluto_cluster::test_cluster::new_for_test(1, 3, 4, 0);
        let definition = serde_json::to_string(&lock.definition).expect("definition json");
        tokio::fs::write(&definition_path, definition)
            .await
            .expect("definition file");

        let err = run(
            Config::builder()
                .data_dir(tempdir.path().to_path_buf())
                .def_file(definition_path.to_string_lossy().into_owned())
                .no_verify(true)
                .build(),
            CancellationToken::new(),
        )
        .await
        .expect_err("missing private key should fail preflight");

        assert!(matches!(
            err,
            DkgError::Disk(crate::disk::DiskError::MissingRequiredFiles { .. })
        ));
    }
}
