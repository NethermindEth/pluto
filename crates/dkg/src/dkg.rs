use std::{path, time::Duration};

use bon::Builder;
use pluto_cluster::version::{
    support_node_signatures, support_partial_deposits, support_pregen_registrations,
};
use pluto_eth2util::{
    deposit::{dedup_amounts, default_deposit_amounts},
    network::fork_version_to_network,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const DEFAULT_DATA_DIR: &str = ".charon";
const DEFAULT_DEFINITION_FILE: &str = ".charon/cluster-definition.json";
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

    /// Failed to verify keymanager connectivity.
    #[error("verify keymanager address: {0}")]
    Keymanager(#[from] pluto_eth2util::keymanager::KeymanagerError),

    /// DKG ceremony backend failed.
    #[error("DKG ceremony failed: {0}")]
    Backend(String),
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
    pluto_p2p::config::P2PConfig {
        relays: pluto_p2p::config::default_relay_multiaddrs(),
        ..Default::default()
    }
}

fn default_tracing_config() -> pluto_tracing::TracingConfig {
    pluto_tracing::TracingConfig::builder()
        .with_default_console()
        .override_env_filter("info")
        .build()
}

fn resolve_deposit_amounts(definition: &pluto_cluster::definition::Definition) -> Vec<u64> {
    if definition.deposit_amounts.is_empty() {
        if support_partial_deposits(&definition.version) {
            default_deposit_amounts(definition.compounding)
        } else {
            vec![pluto_eth2util::deposit::DEFAULT_DEPOSIT_AMOUNT]
        }
    } else {
        dedup_amounts(&definition.deposit_amounts)
    }
}

/// Errors that can arise in the DKG backend (beyond preflight).
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// P2P node setup failed.
    #[error("node setup failed: {0}")]
    NodeSetup(#[from] crate::node::NodeSetupError),
    /// Step-synchronization protocol error.
    #[error("sync error: {0}")]
    Sync(#[from] crate::sync::Error),
    /// FROST DKG ceremony failed.
    #[error("FROST ceremony failed: {0}")]
    Frost(#[from] crate::frost::FrostError),
    /// Post-DKG signing or aggregation failed.
    #[error("signing failed: {0}")]
    Signing(#[from] crate::signing::SigningError),
    /// K1 node signature exchange failed.
    #[error("node signatures: {0}")]
    NodeSigs(#[from] crate::nodesigs::Error),
    /// Final lock signature verification failed.
    #[error("lock signature verification: {0}")]
    LockVerify(#[from] pluto_cluster::lock::LockError),
    /// Disk I/O error.
    #[error("disk I/O: {0}")]
    Disk(#[from] crate::disk::DiskError),
    /// Deposit data file write failed.
    #[error("deposit file write: {0}")]
    DepositWrite(#[from] pluto_eth2util::deposit::DepositError),
    /// Network / fork-version error.
    #[error("network: {0}")]
    Network(#[from] pluto_eth2util::network::NetworkError),
    /// Definition parsing error.
    #[error("definition: {0}")]
    Definition(#[from] pluto_cluster::definition::DefinitionError),
    /// DKG was cancelled externally.
    #[error("DKG cancelled")]
    Cancelled,
}

impl From<BackendError> for DkgError {
    fn from(e: BackendError) -> Self {
        // Re-use the existing Disk error arm for IO, others become their own strings.
        // For now wrap as a generic disk error when possible, else use a new variant.
        DkgError::Backend(e.to_string())
    }
}

/// Runs the full DKG ceremony: preflight, networking, FROST, signing, output.
pub async fn run(conf: Config, shutdown: CancellationToken) -> Result<(), DkgError> {
    if shutdown.is_cancelled() {
        return Err(DkgError::ShutdownRequestedBeforeStartup);
    }

    let eth1 = pluto_eth1wrap::EthClient::new(&conf.execution_engine_addr).await?;

    let definition = crate::disk::load_definition(&conf, &eth1).await?;

    validate_keymanager_flags(&conf)?;
    verify_keymanager_connection(&conf).await?;

    if !conf.has_test_config() {
        crate::disk::check_clear_data_dir(&conf.data_dir).await?;
    }
    crate::disk::check_writes(&conf.data_dir).await?;

    run_ceremony(conf, definition, eth1, shutdown)
        .await
        .map_err(Into::into)
}

async fn run_ceremony(
    conf: Config,
    definition: pluto_cluster::definition::Definition,
    eth1: pluto_eth1wrap::EthClient,
    ct: CancellationToken,
) -> Result<(), BackendError> {
    let network = fork_version_to_network(&definition.fork_version)?;

    let num_validators = u32::try_from(definition.num_validators).map_err(|_| {
        BackendError::Definition(pluto_cluster::definition::DefinitionError::FailedToConvertLength)
    })?;
    let num_nodes = u32::try_from(definition.operators.len()).map_err(|_| {
        BackendError::Definition(pluto_cluster::definition::DefinitionError::FailedToConvertLength)
    })?;
    let threshold = u32::try_from(definition.threshold).map_err(|_| {
        BackendError::Definition(pluto_cluster::definition::DefinitionError::FailedToConvertLength)
    })?;
    let fork_version = definition.fork_version.clone();
    let withdrawal_addrs = definition.withdrawal_addresses();
    let fee_recipients = definition.fee_recipient_addresses();

    // ── P2P node setup ────────────────────────────────────────────────────────
    info!("Setting up DKG P2P node");
    let handles = crate::node::setup_node(&conf, &definition, ct.child_token()).await?;
    let node_idx = handles.node_idx;

    // ── Exchanger (partial-sig exchange for signing rounds) ───────────────────
    let exchanger = crate::exchanger::Exchanger::new(
        ct.child_token(),
        handles.parsigex_handle,
        definition.peer_ids()?,
        vec![
            crate::exchanger::SIG_LOCK,
            crate::exchanger::SIG_VALIDATOR_REG,
            crate::exchanger::SIG_DEPOSIT_DATA,
        ],
    )
    .await;

    // ── FROST P2P transport (registers bcast callbacks) ───────────────────────
    let peers = definition.peers()?;
    let share_idx = u32::try_from(node_idx.share_idx).map_err(|_| {
        BackendError::Definition(pluto_cluster::definition::DefinitionError::FailedToConvertLength)
    })?;
    let mut frost_tp = crate::frost::new_frost_p2p(
        handles.bcast_comp.clone(),
        handles.frost_p2p,
        &peers,
        share_idx,
    )
    .await?;

    // ── Node signature broadcaster ────────────────────────────────────────────
    let node_sig_bcast = crate::nodesigs::NodeSigBcast::new(
        peers.clone(),
        node_idx.peer_idx,
        handles.bcast_comp.clone(),
        ct.child_token(),
    )
    .await?;

    // ── Sync protocol: wait for all peers to connect ──────────────────────────
    info!("Waiting for all peers to connect...");
    let mut sync =
        SyncControl::start(handles.sync_server, handles.sync_clients, ct.child_token()).await?;
    info!("All peers connected, starting DKG ceremony");

    // ── FROST DKG ceremony ────────────────────────────────────────────────────
    let dkg_ctx = format!("0x{}", hex::encode(&definition.definition_hash));
    let shares = crate::frost::run_frost_parallel(
        &ct,
        &mut frost_tp,
        num_validators,
        num_nodes,
        threshold,
        share_idx,
        &dkg_ctx,
    )
    .await?;
    debug!("FROST ceremony complete, {} shares", shares.len());
    sync.next_step(ct.child_token()).await?; // step 1 → 2

    // ── Deposit data ──────────────────────────────────────────────────────────
    let deposit_amounts = resolve_deposit_amounts(&definition);

    let deposit_datas = crate::signing::sign_and_agg_deposit_data(
        &exchanger,
        &shares,
        &withdrawal_addrs,
        &network,
        &node_idx,
        &deposit_amounts,
        definition.compounding,
    )
    .await?;
    sync.next_step(ct.child_token()).await?; // step 2 → 3

    // ── Validator registrations ───────────────────────────────────────────────
    let mut val_regs = crate::signing::sign_and_agg_validator_registrations(
        &exchanger,
        &shares,
        &fee_recipients,
        definition.target_gas_limit,
        &node_idx,
        &fork_version,
    )
    .await?;
    sync.next_step(ct.child_token()).await?; // step 3 → 4

    // ── Lock hash ─────────────────────────────────────────────────────────────
    if !support_pregen_registrations(&definition.version) {
        val_regs.clear();
    }

    let mut lock = crate::signing::sign_and_agg_lock_hash(
        ct.child_token(),
        &shares,
        definition,
        &node_idx,
        &exchanger,
        deposit_datas.clone(),
        val_regs,
    )
    .await?;
    sync.next_step(ct.child_token()).await?; // step 4 → 5

    // ── Node signatures ───────────────────────────────────────────────────────
    let p2p_key = pluto_p2p::k1::load_priv_key(&conf.data_dir)
        .map_err(crate::node::NodeSetupError::LoadKey)
        .map_err(BackendError::NodeSetup)?;

    let node_sigs = node_sig_bcast
        .exchange(Some(&p2p_key), &lock.lock_hash, ct.child_token())
        .await?;

    if support_node_signatures(&lock.version) {
        lock.node_signatures = node_sigs;
    }
    sync.next_step(ct.child_token()).await?; // step 5 → 6

    // ── Verify + write outputs ────────────────────────────────────────────────
    if !conf.no_verify {
        lock.verify_signatures(&eth1).await?;
    }

    if conf.keymanager.address.is_empty() {
        crate::disk::write_keys_to_disk(&conf, &shares, false).await?;
        debug!("Wrote key shares to disk");
    } else {
        crate::disk::write_to_keymanager(
            &conf.keymanager.address,
            &conf.keymanager.auth_token,
            &shares,
        )
        .await?;
        debug!("Imported key shares to keymanager");
    }

    if conf.publish.enabled {
        publish_lock_to_api(&conf.publish, &lock).await;
    }

    crate::disk::write_lock(&conf.data_dir, &lock).await?;
    debug!("Wrote cluster lock to disk");

    for deposit_set in &deposit_datas {
        pluto_eth2util::deposit::write_deposit_data_file(deposit_set, &network, &conf.data_dir)
            .await?;
    }
    debug!("Wrote deposit data files");

    sync.next_step(ct.child_token()).await?; // step 6 → 7
    sync.stop(ct.child_token()).await?;

    debug!(
        delay_secs = conf.shutdown_delay.as_secs_f64(),
        "Graceful shutdown delay"
    );
    tokio::time::sleep(conf.shutdown_delay).await;

    info!("DKG ceremony complete 🎉");
    Ok(())
}

// ── Sync protocol helpers ────────────────────────────────────────────────────

/// Manages DKG step synchronization after initial connection.
struct SyncControl {
    step: i64,
    clients: Vec<crate::sync::Client>,
    server: crate::sync::Server,
}

impl SyncControl {
    /// Starts the sync protocol: spawns client run tasks, waits for all peers
    /// to connect, and advances to step 1.
    async fn start(
        server: crate::sync::Server,
        clients: Vec<crate::sync::Client>,
        ct: CancellationToken,
    ) -> Result<Self, BackendError> {
        server.start();

        for client in &clients {
            let ct = ct.child_token();
            let client = client.clone();
            tokio::spawn(async move {
                match client.run(ct).await {
                    Err(e) if !matches!(e, crate::sync::Error::Canceled) => {
                        warn!(err = %e, "Sync client error");
                    }
                    _ => {}
                }
            });
        }

        loop {
            if ct.is_cancelled() {
                return Err(BackendError::Cancelled);
            }
            let connected = clients.iter().filter(|c| c.is_connected()).count();
            if connected == clients.len() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        for client in &clients {
            client.disable_reconnect();
        }
        server.await_all_connected(ct.child_token()).await?;

        let mut ctrl = Self {
            step: 0,
            clients,
            server,
        };
        ctrl.next_step(ct).await?; // advance from step 0 → 1
        Ok(ctrl)
    }

    /// Increments the step counter and waits for all peers to reach it.
    async fn next_step(&mut self, ct: CancellationToken) -> Result<(), BackendError> {
        self.step = self.step.checked_add(1).ok_or(BackendError::Cancelled)?;
        for client in &self.clients {
            client.set_step(self.step);
        }
        self.server.await_all_at_step(self.step, ct).await?;
        Ok(())
    }

    /// Shuts down all sync clients and waits for the server to confirm.
    async fn stop(&self, ct: CancellationToken) -> Result<(), BackendError> {
        for client in &self.clients {
            client.shutdown(ct.child_token()).await?;
        }
        self.server.await_all_shutdown(ct).await?;
        Ok(())
    }
}

// ── Publish to Obol API ──────────────────────────────────────────────────────

async fn publish_lock_to_api(publish: &PublishConfig, lock: &pluto_cluster::lock::Lock) {
    // Best-effort: log warning on failure, do not abort DKG.
    let client = match reqwest::Client::builder().timeout(publish.timeout).build() {
        Ok(c) => c,
        Err(e) => {
            warn!(err = %e, "Failed to build HTTP client for lock publication");
            return;
        }
    };

    let url = format!("{}/lock", publish.address.trim_end_matches('/'));
    match client.post(&url).json(lock).send().await {
        Ok(resp) if resp.status().is_success() => {
            debug!("Published lock to Obol API");
        }
        Ok(resp) => {
            warn!(status = %resp.status(), "Lock publication returned non-2xx");
        }
        Err(e) => {
            warn!(err = %e, "Failed to publish lock to Obol API");
        }
    }
}

fn validate_keymanager_flags(conf: &Config) -> Result<(), DkgError> {
    let addr = conf.keymanager.address.as_str();
    let auth_token = conf.keymanager.auth_token.as_str();

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

async fn verify_keymanager_connection(conf: &Config) -> Result<(), DkgError> {
    let addr = conf.keymanager.address.as_str();

    if addr.is_empty() {
        return Ok(());
    }

    let client = pluto_eth2util::keymanager::Client::new(addr, &conf.keymanager.auth_token)?;
    client.verify_connection().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_cluster::{
        definition::{Creator, Definition},
        operator::Operator,
        version::{V1_10, V1_7},
    };

    fn test_definition(version: &str, deposit_amounts: Vec<u64>, compounding: bool) -> Definition {
        let mut definition = Definition::new(
            "test".into(),
            1,
            1,
            vec!["0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF".into()],
            vec!["0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF".into()],
            "0x01017000".to_string(),
            Creator::default(),
            vec![Operator::default()],
            deposit_amounts,
            String::new(),
            30_000_000,
            compounding,
            Vec::new(),
        )
        .unwrap();
        definition.version = version.to_string();

        definition
    }

    #[test]
    fn config_builder_defaults_match_charon() {
        let config = Config::builder().build();

        assert_eq!(config.def_file, DEFAULT_DEFINITION_FILE);
        assert!(!config.no_verify);
        assert_eq!(config.data_dir, path::PathBuf::from(DEFAULT_DATA_DIR));
        assert_eq!(
            config.p2p.relays,
            pluto_p2p::config::default_relay_multiaddrs()
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
                .test_config(TestConfig::builder().def(lock.definition.clone()).build())
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
    async fn verify_keymanager_connection_succeeds_for_reachable_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = format!("http://{}", listener.local_addr().expect("local addr"));

        let config = Config::builder()
            .keymanager(
                KeymanagerConfig::builder()
                    .address(addr)
                    .auth_token("token".to_string())
                    .build(),
            )
            .build();

        verify_keymanager_connection(&config)
            .await
            .expect("reachable keymanager should verify");
    }

    #[tokio::test]
    async fn verify_keymanager_connection_fails_for_unreachable_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = format!("http://{}", listener.local_addr().expect("local addr"));
        drop(listener);

        let config = Config::builder()
            .keymanager(
                KeymanagerConfig::builder()
                    .address(addr)
                    .auth_token("token".to_string())
                    .build(),
            )
            .build();

        let err = verify_keymanager_connection(&config)
            .await
            .expect_err("unreachable keymanager should fail");

        assert!(matches!(err, DkgError::Keymanager(_)));
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

        // Preflight passes (writes check etc.) then fails at backend (bad p2p key).
        let err = run(
            Config::builder()
                .data_dir(tempdir.path().to_path_buf())
                .def_file(definition_path.to_string_lossy().into_owned())
                .no_verify(true)
                .build(),
            CancellationToken::new(),
        )
        .await
        .expect_err("invalid p2p key should fail backend setup");

        // Error is a backend error (node setup / key load), not a preflight error.
        assert!(matches!(err, DkgError::Backend(_)));
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

    #[test]
    fn resolve_deposit_amounts_defaults_partial_deposits_for_v1_10() {
        let definition = test_definition(V1_10, Vec::new(), false);

        assert_eq!(
            resolve_deposit_amounts(&definition),
            vec![
                pluto_eth2util::deposit::MIN_DEPOSIT_AMOUNT,
                pluto_eth2util::deposit::DEFAULT_DEPOSIT_AMOUNT,
            ]
        );
    }

    #[test]
    fn resolve_deposit_amounts_defaults_single_deposit_before_partial_support() {
        let definition = test_definition(V1_7, Vec::new(), false);

        assert_eq!(
            resolve_deposit_amounts(&definition),
            vec![pluto_eth2util::deposit::DEFAULT_DEPOSIT_AMOUNT]
        );
    }
}
