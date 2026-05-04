use std::{num::TryFromIntError, path, time::Duration};

use bon::Builder;
use libp2p::PeerId;
use pluto_cluster::version::{
    V1_6, V1_7, V1_8, V1_9, V1_10, support_node_signatures, support_partial_deposits,
};
use pluto_eth2util::{
    deposit::{dedup_amounts, default_deposit_amounts, merge_deposit_data_sets},
    network::{MAINNET, fork_version_to_network},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub use crate::{
    aggregate::{AggregateError, agg_deposit_data, agg_lock_hash_sig, agg_validator_registrations},
    disk,
    publish::{PublishError, write_lock_to_api},
    share::Share,
    signing::{SigningError, sign_deposit_msgs, sign_lock_hash, sign_validator_registrations},
    validators::{
        ValidatorsError, builder_registration_from_eth2, create_dist_validators,
        set_registration_signature,
    },
};
use pluto_cluster::{
    definition::{Definition, ValidatorAddresses},
    distvalidator::DistValidatorError,
    lock::Lock,
    operator::Operator,
};
use pluto_crypto::types::PrivateKey;
use pluto_eth1wrap::{EthClient, EthClientError};
use pluto_eth2api::spec::phase0;
use pluto_eth2util::keymanager::{self, KeymanagerError};
use pluto_p2p::{config::P2PConfig, peer::Peer};
use pluto_tracing::TracingConfig;
use std::collections::{HashMap, HashSet};
use url::Url;

const DEFAULT_DATA_DIR: &str = ".charon";
const DEFAULT_DEFINITION_FILE: &str = ".charon/cluster-definition.json";
const DEFAULT_PUBLISH_ADDRESS: &str = "https://api.obol.tech/v1";
const DEFAULT_PUBLISH_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_SHUTDOWN_DELAY: Duration = Duration::from_secs(10);
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
    Eth1Client(#[from] EthClientError),

    /// Disk or definition preflight failed.
    #[error("DKG preflight failed: {0}")]
    Disk(#[from] crate::disk::DiskError),

    /// Failed to verify keymanager connectivity.
    #[error("verify keymanager address: {0}")]
    Keymanager(#[from] KeymanagerError),

    /// DKG ceremony backend failed.
    #[error("DKG ceremony failed: {0}")]
    Backend(String),

    /// Failed to decode distributed validator data from the existing lock.
    #[error("existing shares lock decode failed: {0}")]
    DistValidator(#[from] DistValidatorError),

    /// There are more secret shares than distributed validators in the lock.
    #[error(
        "existing shares input invalid: got {secret_shares} secret shares for {validators} distributed validators"
    )]
    ExistingSharesCountMismatch {
        /// Number of secret shares provided.
        secret_shares: usize,
        /// Number of distributed validators present in the lock.
        validators: usize,
    },

    /// Failed to convert share index to u64.
    #[error("failed to convert share index to u64: {0}")]
    ShareIndexConversion(#[from] TryFromIntError),

    /// Integer overflow.
    #[error("integer overflow")]
    IntegerOverflow,

    /// Cluster definition version not supported by this DKG implementation.
    #[error("only v1.6.0 and newer cluster definition versions supported (got {0})")]
    UnsupportedVersion(String),

    /// DKG algorithm not supported.
    #[error("unsupported dkg algorithm: {0}")]
    UnsupportedDkgAlgorithm(String),

    /// Test configuration was provided while running on mainnet.
    #[error("cannot use test flags on mainnet")]
    MainnetTestConfigForbidden,

    /// AppendConfig deposit data length does not match the configured deposit
    /// amounts.
    #[error(
        "deposit data length does not match deposit amounts length: deposit_data={deposit_data}, deposit_amounts={deposit_amounts}"
    )]
    DepositDataLengthMismatch {
        /// Number of deposit data sets supplied via AppendConfig.
        deposit_data: usize,
        /// Number of deposit amounts resolved from the definition.
        deposit_amounts: usize,
    },

    /// Failed to bundle the output directory as a tarball.
    #[error("bundle output: {0}")]
    BundleOutput(#[from] pluto_app::utils::UtilsError),

    /// Failed to resolve network metadata from the fork version.
    #[error("network: {0}")]
    Network(#[from] pluto_eth2util::network::NetworkError),

    /// Private-key lock service failed to start.
    #[error("private key lock setup failed: {0}")]
    PrivKeyLock(#[from] pluto_app::privkeylock::PrivKeyLockError),
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
    pub p2p: P2PConfig,

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

    /// Append-mode configuration. When set, the existing cluster lock and
    /// secret shares are merged with the newly-generated validators.
    pub append_config: Option<AppendConfig>,

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
    pub def: Option<Definition>,
}

/// Configuration used to merge the outcome of two DKG ceremonies.
#[derive(Debug, Clone)]
pub struct AppendConfig {
    /// Cluster lock of the existing cluster.
    pub cluster_lock: Lock,
    /// Private key shares of the existing cluster.
    pub secret_shares: Vec<PrivateKey>,
    /// Number of validators to add to the existing cluster.
    pub add_validators: usize,
    /// Set when the source validator keys are not available; signs nothing and
    /// preserves existing creator/operator signatures.
    pub unverified: bool,
    /// Validator addresses for the newly added validators. Length must match
    /// [`AppendConfig::add_validators`].
    pub validator_addresses: Vec<ValidatorAddresses>,
    /// Deposit data from the existing cluster, indexed by deposit-amount slot.
    pub deposit_data: Vec<Vec<phase0::DepositData>>,
}

fn default_p2p_config() -> P2PConfig {
    P2PConfig {
        relays: pluto_p2p::config::default_relay_multiaddrs(),
        ..Default::default()
    }
}

fn default_tracing_config() -> TracingConfig {
    TracingConfig::builder()
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
#[allow(private_interfaces)]
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
    /// Bcast setup (registering frost handlers) failed.
    #[error("bcast setup failed: {0}")]
    BcastSetup(#[from] crate::bcast::Error),
    /// Failed to rebuild existing shares from append config.
    #[error("get existing shares: {0}")]
    ExistingShares(String),
    /// AppendConfig deposit data length does not match the configured deposit
    /// amounts.
    #[error(
        "deposit data length does not match deposit amounts length: deposit_data={deposit_data}, deposit_amounts={deposit_amounts}"
    )]
    DepositDataLengthMismatch {
        /// Number of deposit data sets supplied via AppendConfig.
        deposit_data: usize,
        /// Number of deposit amounts resolved from the definition.
        deposit_amounts: usize,
    },
    /// Failed to bundle the output directory as a tarball.
    #[error("bundle output: {0}")]
    BundleOutput(#[source] pluto_app::utils::UtilsError),
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

    // Private-key lock: guards the p2p key file against concurrent charon
    // processes for the duration of the DKG. Mirrors Go's `privkeylock` setup.
    let lock_path = pluto_p2p::k1::key_path(&conf.data_dir).with_extension("lock");
    let priv_lock =
        std::sync::Arc::new(pluto_app::privkeylock::Service::new(&lock_path, "charon dkg").await?);
    {
        let svc = priv_lock.clone();
        tokio::spawn(async move {
            if let Err(e) = svc.run().await {
                warn!(err = %e, "Error locking private key file");
            }
        });
    }

    let result = run_inner(conf, shutdown).await;
    priv_lock.close().await;
    result
}

async fn run_inner(conf: Config, shutdown: CancellationToken) -> Result<(), DkgError> {
    let eth1 = EthClient::new(&conf.execution_engine_addr).await?;

    // Resolve definition and per-run validator inputs. In append mode the
    // existing cluster lock provides the definition and the new addresses come
    // from `AppendConfig.validator_addresses`; otherwise they come from the
    // definition itself.
    let (definition, new_validators, new_withdrawal_addrs, new_fee_recipient_addrs) =
        if let Some(append) = conf.append_config.as_ref() {
            let def = append.cluster_lock.definition.clone();
            let withdrawal = append
                .validator_addresses
                .iter()
                .map(|a| a.withdrawal_address.clone())
                .collect();
            let fee_recipient = append
                .validator_addresses
                .iter()
                .map(|a| a.fee_recipient_address.clone())
                .collect();
            (def, append.add_validators, withdrawal, fee_recipient)
        } else {
            let def = crate::disk::load_definition(&conf, &eth1).await?;
            let n = usize::try_from(def.num_validators)?;
            let withdrawal = def.withdrawal_addresses();
            let fee_recipient = def.fee_recipient_addresses();
            (def, n, withdrawal, fee_recipient)
        };

    if !matches!(
        definition.version.as_str(),
        V1_6 | V1_7 | V1_8 | V1_9 | V1_10
    ) {
        return Err(DkgError::UnsupportedVersion(definition.version.clone()));
    }

    if !matches!(definition.dkg_algorithm.as_str(), "default" | "frost") {
        return Err(DkgError::UnsupportedDkgAlgorithm(
            definition.dkg_algorithm.clone(),
        ));
    }

    validate_keymanager_flags(&conf)?;
    verify_keymanager_connection(&conf).await?;

    if !conf.has_test_config() {
        disk::check_clear_data_dir(&conf.data_dir).await?;
    }
    disk::check_writes(&conf.data_dir).await?;

    let network = fork_version_to_network(&definition.fork_version)?;

    if network == MAINNET.name && conf.has_test_config() {
        return Err(DkgError::MainnetTestConfigForbidden);
    }

    let inputs = CeremonyInputs {
        new_validators,
        new_withdrawal_addrs,
        new_fee_recipient_addrs,
        network,
    };

    run_ceremony(conf, definition, eth1, shutdown, inputs)
        .await
        .map_err(Into::into)
}

/// Per-run inputs computed in [`run_inner`] and forwarded to the ceremony.
struct CeremonyInputs {
    /// Number of validators generated in this DKG run
    /// (`AppendConfig.add_validators` in append mode, otherwise
    /// `definition.num_validators`).
    new_validators: usize,
    /// Withdrawal addresses for the validators generated in this run.
    new_withdrawal_addrs: Vec<String>,
    /// Fee recipient addresses for the validators generated in this run.
    new_fee_recipient_addrs: Vec<String>,
    /// Network name resolved from the cluster definition's fork version.
    network: String,
}

async fn run_ceremony(
    conf: Config,
    definition: pluto_cluster::definition::Definition,
    eth1: pluto_eth1wrap::EthClient,
    ct: CancellationToken,
    inputs: CeremonyInputs,
) -> Result<(), BackendError> {
    let CeremonyInputs {
        new_validators,
        new_withdrawal_addrs,
        new_fee_recipient_addrs,
        network,
    } = inputs;

    let num_validators = u32::try_from(new_validators).map_err(|_| {
        BackendError::Definition(pluto_cluster::definition::DefinitionError::FailedToConvertLength)
    })?;
    let num_nodes = u32::try_from(definition.operators.len()).map_err(|_| {
        BackendError::Definition(pluto_cluster::definition::DefinitionError::FailedToConvertLength)
    })?;
    let threshold = u32::try_from(definition.threshold).map_err(|_| {
        BackendError::Definition(pluto_cluster::definition::DefinitionError::FailedToConvertLength)
    })?;
    let fork_version = definition.fork_version.clone();

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
    let frost_tp = crate::frost::new_frost_p2p(
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
        ct.clone(),
        &frost_tp,
        num_validators,
        num_nodes,
        threshold,
        share_idx,
        &dkg_ctx,
    )
    .await?;
    debug!("FROST ceremony complete, {} shares", shares.len());
    sync.next_step(ct.child_token()).await?; // step 1 → 2

    // ── Existing shares (append mode) ─────────────────────────────────────────
    let existing_shares: Vec<Share> = match conf.append_config.as_ref() {
        Some(append) if !append.unverified => get_existing_shares(Some(append))
            .map_err(|e| BackendError::ExistingShares(e.to_string()))?,
        _ => Vec::new(),
    };

    // ── Deposit data ──────────────────────────────────────────────────────────
    let deposit_amounts = resolve_deposit_amounts(&definition);

    if let Some(append) = conf.append_config.as_ref()
        && !append.deposit_data.is_empty()
        && append.deposit_data.len() != deposit_amounts.len()
    {
        return Err(BackendError::DepositDataLengthMismatch {
            deposit_data: append.deposit_data.len(),
            deposit_amounts: deposit_amounts.len(),
        });
    }

    let mut deposit_datas = crate::signing::sign_and_agg_deposit_data(
        &exchanger,
        &shares,
        &new_withdrawal_addrs,
        &network,
        &node_idx,
        &deposit_amounts,
        definition.compounding,
    )
    .await?;
    sync.next_step(ct.child_token()).await?; // step 2 → 3

    // ── Validator registrations ───────────────────────────────────────────────
    let val_regs = crate::signing::sign_and_agg_validator_registrations(
        &exchanger,
        &shares,
        &new_fee_recipient_addrs,
        definition.target_gas_limit,
        &node_idx,
        &fork_version,
    )
    .await?;
    sync.next_step(ct.child_token()).await?; // step 3 → 4

    // ── Lock hash ─────────────────────────────────────────────────────────────
    let mut lock = crate::signing::sign_and_aggregate_lock_hash(
        &existing_shares,
        &shares,
        definition,
        &node_idx,
        &exchanger,
        deposit_datas.clone(),
        val_regs,
        conf.append_config.as_ref(),
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
    let unverified_append = conf.append_config.as_ref().is_some_and(|a| a.unverified);
    if !conf.no_verify && !unverified_append {
        lock.verify_signatures(&eth1).await?;
    }

    if conf.keymanager.address.is_empty() {
        // KeymanagerAddr unset: write all (existing + new) shares to disk so
        // operators see the combined key set after an append ceremony.
        let all_shares: Vec<Share> = existing_shares
            .iter()
            .chain(shares.iter())
            .cloned()
            .collect();
        crate::disk::write_keys_to_disk(&conf, &all_shares, false).await?;
        debug!(total = all_shares.len(), "Wrote key shares to disk");
    } else {
        // Keymanager: only the newly-generated shares are imported.
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

    if let Some(append) = conf.append_config.as_ref()
        && !append.deposit_data.is_empty()
    {
        deposit_datas = merge_deposit_data_sets(deposit_datas, append.deposit_data.clone());
    }

    for deposit_set in &deposit_datas {
        pluto_eth2util::deposit::write_deposit_data_file(deposit_set, &network, &conf.data_dir)
            .await?;
    }
    debug!("Wrote deposit data files");

    sync.next_step(ct.child_token()).await?; // step 6 → 7
    sync.stop(ct.child_token()).await?;

    if conf.zipped {
        pluto_app::utils::bundle_output(&conf.data_dir, "dkg.tar.gz")
            .map_err(BackendError::BundleOutput)?;
    }

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

        let total = clients.len();
        let mut logged: HashSet<PeerId> = HashSet::with_capacity(total);
        loop {
            if ct.is_cancelled() {
                return Err(BackendError::Cancelled);
            }
            for client in &clients {
                if client.is_connected() && logged.insert(client.peer_id()) {
                    info!(
                        peer = %client.peer_id(),
                        "Connected to peer {} of {}",
                        logged.len(),
                        total
                    );
                }
            }
            if logged.len() == total {
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
        debug!(step = self.step, "Waiting for peers to start next step");
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

    let parsed = Url::parse(addr).map_err(|source| DkgError::InvalidKeymanagerAddress {
        addr: addr.to_string(),
        source,
    })?;

    if parsed.scheme() == "http" {
        warn!(addr = addr, "Keymanager URL does not use https protocol");
    }

    Ok(())
}

/// Logs peer summary with peer names and operator addresses.
pub fn log_peer_summary(current_peer: PeerId, peers: &[Peer], operators: &[Operator]) {
    for (idx, peer) in peers.iter().enumerate() {
        let address = operators
            .get(idx)
            .filter(|operator| !operator.address.is_empty())
            .map(|operator| operator.address.as_str());
        let is_current_peer = peer.id == current_peer;
        let you = is_current_peer.then_some("⭐");

        info!(
            peer = peer.name,
            index = peer.index,
            address,
            you,
            "Peer summary"
        );
    }
}

/// Rebuilds existing shares from an [`AppendConfig`]. Returns an empty vector
/// when no append config is provided.
pub fn get_existing_shares(append_config: Option<&AppendConfig>) -> Result<Vec<Share>, DkgError> {
    let Some(append_config) = append_config else {
        return Ok(Vec::new());
    };

    let lock = &append_config.cluster_lock;
    let secret_shares = &append_config.secret_shares;

    if secret_shares.len() > lock.distributed_validators.len() {
        return Err(DkgError::ExistingSharesCountMismatch {
            secret_shares: secret_shares.len(),
            validators: lock.distributed_validators.len(),
        });
    }

    let mut shares = Vec::with_capacity(secret_shares.len());

    for (idx, secret_share) in secret_shares.iter().enumerate() {
        let validator = &lock.distributed_validators[idx];
        let pub_key = validator.public_key()?;

        let mut public_shares = HashMap::with_capacity(validator.pub_shares.len());
        for share_idx in 0..validator.pub_shares.len() {
            let share_id = u64::try_from(share_idx)?
                .checked_add(1)
                .ok_or(DkgError::IntegerOverflow)?;
            public_shares.insert(share_id, validator.public_share(share_idx)?);
        }

        shares.push(Share {
            pub_key,
            secret_share: *secret_share,
            public_shares,
        });
    }

    Ok(shares)
}

async fn verify_keymanager_connection(conf: &Config) -> Result<(), DkgError> {
    let addr = conf.keymanager.address.as_str();

    if addr.is_empty() {
        return Ok(());
    }

    let client = keymanager::Client::new(addr, &conf.keymanager.auth_token)?;
    client.verify_connection().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_cluster::{
        definition::{Creator, Definition},
        operator::Operator,
        version::{V1_7, V1_10},
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

    fn append_config_with_secret_shares(
        lock: pluto_cluster::lock::Lock,
        secret_shares: Vec<pluto_crypto::types::PrivateKey>,
    ) -> AppendConfig {
        AppendConfig {
            cluster_lock: lock,
            secret_shares,
            add_validators: 0,
            unverified: false,
            validator_addresses: Vec::new(),
            deposit_data: Vec::new(),
        }
    }

    #[test]
    fn get_existing_shares_returns_empty_for_no_append_config() {
        let shares = get_existing_shares(None).unwrap();
        assert!(shares.is_empty());
    }

    #[test]
    fn get_existing_shares_rebuilds_share_shape_from_lock() {
        let (lock, _, dv_shares) = pluto_cluster::test_cluster::new_for_test(2, 3, 4, 1);
        let secret_shares = dv_shares.iter().map(|shares| shares[0]).collect::<Vec<_>>();
        let append_config = append_config_with_secret_shares(lock.clone(), secret_shares.clone());

        let shares = get_existing_shares(Some(&append_config)).unwrap();

        assert_eq!(shares.len(), secret_shares.len());

        for (idx, share) in shares.iter().enumerate() {
            let validator = &lock.distributed_validators[idx];

            assert_eq!(share.secret_share, secret_shares[idx]);
            assert_eq!(share.pub_key, validator.public_key().unwrap());
            assert_eq!(share.public_shares.len(), validator.pub_shares.len());

            for share_idx in 0..validator.pub_shares.len() {
                assert_eq!(
                    share.public_shares.get(&((share_idx + 1) as u64)),
                    Some(&validator.public_share(share_idx).unwrap())
                );
            }
        }
    }

    #[test]
    fn get_existing_shares_rejects_more_secret_shares_than_validators() {
        let (lock, _, dv_shares) = pluto_cluster::test_cluster::new_for_test(2, 3, 4, 1);
        let mut secret_shares = dv_shares.iter().map(|shares| shares[0]).collect::<Vec<_>>();
        secret_shares.push([0x55; 32]);
        let append_config = append_config_with_secret_shares(lock, secret_shares);

        let err = get_existing_shares(Some(&append_config)).unwrap_err();

        assert!(matches!(
            err,
            DkgError::ExistingSharesCountMismatch {
                secret_shares: 3,
                validators: 2
            }
        ));
    }

    #[tokio::test]
    async fn run_rejects_mismatched_keymanager_flags() {
        let (lock, ..) = pluto_cluster::test_cluster::new_for_test(1, 3, 4, 0);
        let tempdir = tempfile::tempdir().expect("tempdir");

        let err = run(
            Config::builder()
                .data_dir(tempdir.path().to_path_buf())
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
