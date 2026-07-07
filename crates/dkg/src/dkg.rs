use std::{collections::HashMap, ffi::OsStr, fmt, num::TryFromIntError, path, time::Duration};

use bon::Builder;
use futures::StreamExt;
use libp2p::PeerId;
use pluto_app::{privkeylock, utils::UtilsError};
use pluto_core::version;
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

pub use crate::{
    aggregate::{AggregateError, agg_deposit_data, agg_lock_hash_sig, agg_validator_registrations},
    exchanger::{Exchanger, SIG_DEPOSIT_DATA, SIG_LOCK, SIG_VALIDATOR_REG},
    publish::{PublishError, write_lock_to_api},
    share::Share,
    signing::{SigningError, sign_deposit_msgs, sign_lock_hash, sign_validator_registrations},
    validators::{
        ValidatorsError, builder_registration_from_eth2, create_dist_validators,
        set_registration_signature,
    },
};
use crate::{disk, frost, frostp2p, nodesigs};
use pluto_cluster::{
    definition::{Definition, DefinitionError, ValidatorAddresses},
    distvalidator::DistValidatorError,
    lock::{Lock, LockError},
    operator::Operator,
    version::versions::*,
};
use pluto_crypto::types::PrivateKey;
use pluto_eth1wrap::{EthClient, EthClientError};
use pluto_eth2api::spec::phase0;
use pluto_eth2util as eth2util;
use pluto_eth2util::keymanager::{self, KeymanagerError};
use pluto_p2p::{
    bootnode::BootnodeError, config::P2PConfig, k1::key_path, p2p::P2PError, peer::Peer,
};
use pluto_tracing::TracingConfig;
use url::Url;

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
    Eth1Client(#[from] EthClientError),

    /// Disk or definition preflight failed.
    #[error("DKG preflight failed: {0}")]
    Disk(#[from] crate::disk::DiskError),

    /// Failed to verify keymanager connectivity.
    #[error("verify keymanager address: {0}")]
    Keymanager(#[from] KeymanagerError),

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

    /// `AppendConfig::validator_addresses` length does not match
    /// `AppendConfig::add_validators`.
    #[error(
        "append config invalid: got {validator_addresses} validator addresses for {add_validators} new validators"
    )]
    AppendConfigAddressCountMismatch {
        /// Number of validator addresses provided.
        validator_addresses: usize,
        /// Number of validators to add.
        add_validators: usize,
    },

    /// Failed to convert share index to u64.
    #[error("failed to convert share index to u64: {0}")]
    ShareIndexConversion(#[from] TryFromIntError),

    /// Integer overflow.
    #[error("integer overflow")]
    IntegerOverflow,

    /// Test-only configuration is not allowed on mainnet.
    #[error("cannot use test flags on mainnet")]
    TestConfigOnMainnet,

    /// Failed to create private key lock service.
    #[error("failed to create private key lock service: {0}")]
    PrivKeyLock(#[from] privkeylock::PrivKeyLockError),

    /// Unsupported definition version.
    #[error("only v1.6.0 and newer cluster definition versions supported, got: {version}")]
    UnsupportedDefinitionVersion {
        /// The unsupported version.
        version: String,
    },

    /// Failed to convert fork version to network.
    #[error("failed to convert fork version to network: {0}")]
    ForkVersionToNetwork(#[from] eth2util::network::NetworkError),

    /// Failed to load private key.
    #[error("failed to load private key: {0}")]
    KeyLoadError(#[from] pluto_p2p::k1::K1Error),

    /// Peer error.
    #[error("peer error: {0}")]
    PeerError(#[from] pluto_p2p::peer::PeerError),

    /// The local P2P key did not match the definition peer set.
    #[error("private key not matching definition file: peer not in definition: {peer_id}")]
    LocalPeerNotInDefinition {
        /// Local peer ID derived from the P2P private key.
        peer_id: PeerId,
    },

    /// Definition error.
    #[error("definition error: {0}")]
    Definition(#[from] DefinitionError),

    /// Bootnode or relay resolution error.
    #[error("bootnode error: {0}")]
    Bootnode(#[from] BootnodeError),

    /// Sync protocol error.
    #[error("sync error: {0}")]
    Sync(#[from] crate::sync::Error),

    /// P2P node setup error.
    #[error("p2p error: {0}")]
    P2P(#[from] P2PError),

    /// FROST DKG setup or execution failed.
    #[error("frost error: {0}")]
    Frost(#[from] frost::FrostError),

    /// DKG signing or aggregation failed.
    #[error("dkg signing error: {0}")]
    Signing(#[from] SigningError),

    /// K1 node-signature exchange failed.
    #[error("k1 lock hash signature exchange: {0}")]
    NodeSignatures(#[from] nodesigs::Error),

    /// Cluster lock verification failed.
    #[error("invalid lock file signatures: {0}")]
    LockVerification(#[source] LockError),

    /// Deposit-data file write failed.
    #[error("deposit data error: {0}")]
    Deposit(#[from] pluto_eth2util::deposit::DepositError),

    /// Output archive creation failed.
    #[error("bundle output: {0}")]
    BundleOutput(#[from] UtilsError),

    /// Background task failed.
    #[error("background task failed: {0}")]
    Join(#[from] tokio::task::JoinError),

    /// The configured deposit data does not match deposit amounts.
    #[error(
        "deposit data length does not match deposit amounts length: deposit_data={deposit_data}, deposit_amounts={deposit_amounts}"
    )]
    DepositDataLengthMismatch {
        /// Deposit-data set count.
        deposit_data: usize,
        /// Deposit amount count.
        deposit_amounts: usize,
    },

    /// The configured DKG algorithm is not supported.
    #[error("unsupported dkg algorithm: {algorithm}")]
    UnsupportedDkgAlgorithm {
        /// Algorithm name from the cluster definition.
        algorithm: String,
    },
}

/// Keymanager configuration accepted by the entrypoint.
#[derive(Clone, Default, Builder)]
pub struct KeymanagerConfig {
    /// The keymanager URL.
    pub address: String,
    /// Bearer token used for authentication.
    pub auth_token: String,
}

impl fmt::Debug for KeymanagerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeymanagerConfig")
            .field("address", &self.address)
            .field("auth_token", &"<redacted>")
            .finish()
    }
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

    /// Append configuration.
    pub append_config: Option<AppendConfig>,

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
        self.test_config.def.is_some() || self.test_config.p2p_key.is_some()
    }
}

/// Additional test-only config for DKG.
#[derive(Debug, Clone, Default, Builder)]
pub struct TestConfig {
    /// Provides the cluster definition explicitly, skips loading from disk.
    pub def: Option<Definition>,

    /// Provides the P2P private key explicitly, skips loading from disk.
    pub p2p_key: Option<k256::SecretKey>,
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
    /// Validator addresses for the newly added validators. The caller is
    /// responsible for ensuring the length matches
    /// [`AppendConfig::add_validators`]; use [`AppendConfig::validate`].
    pub validator_addresses: Vec<ValidatorAddresses>,
    /// Deposit data from the existing cluster, indexed by deposit-amount slot.
    pub deposit_data: Vec<Vec<phase0::DepositData>>,
}

impl AppendConfig {
    /// Checks invariants that the public fields cannot enforce on construction.
    pub fn validate(&self) -> Result<(), DkgError> {
        if self.validator_addresses.len() != self.add_validators {
            return Err(DkgError::AppendConfigAddressCountMismatch {
                validator_addresses: self.validator_addresses.len(),
                add_validators: self.add_validators,
            });
        }

        Ok(())
    }
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

/// Runs the DKG entrypoint.
pub async fn run(conf: Config, ct: CancellationToken) -> Result<(), DkgError> {
    if ct.is_cancelled() {
        return Err(DkgError::ShutdownRequestedBeforeStartup);
    }

    let (lock_ct, lock_task) = start_private_key_lock(&conf).await?;
    let result = run_inner(conf, ct).await;

    lock_ct.cancel();
    lock_task
        .await
        .unwrap_or_else(|err| error!(?err, "Error joining private key lock task"));

    result
}

async fn start_private_key_lock(
    conf: &Config,
) -> Result<(CancellationToken, tokio::task::JoinHandle<()>), DkgError> {
    let lock_svc = std::sync::Arc::new(
        privkeylock::Service::new(private_key_lock_path(&conf.data_dir), "charon dkg").await?,
    );
    let lock_ct = CancellationToken::new();
    let task_ct = lock_ct.clone();
    let task = tokio::spawn(async move {
        let run_svc = lock_svc.clone();
        let mut run_task = tokio::spawn(async move { run_svc.run().await });

        select! {
            _ = task_ct.cancelled() => {
                lock_svc.close().await;
                log_private_key_lock_result(run_task.await);
            }
            result = &mut run_task => log_private_key_lock_result(result),
        }
    });

    Ok((lock_ct, task))
}

fn log_private_key_lock_result(
    result: std::result::Result<
        std::result::Result<(), privkeylock::PrivKeyLockError>,
        tokio::task::JoinError,
    >,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => error!(?err, "Error locking private key file"),
        Err(err) => error!(?err, "Error locking private key file"),
    }
}

fn private_key_lock_path(data_dir: &path::Path) -> path::PathBuf {
    let mut lock_path = key_path(data_dir);
    let file_name = lock_path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("charon-enr-private-key");
    lock_path.set_file_name(format!("{file_name}.lock"));
    lock_path
}

async fn run_inner(conf: Config, ct: CancellationToken) -> Result<(), DkgError> {
    if let Some(append) = &conf.append_config {
        append.validate()?;
    }

    version::log_info("Charon DKG starting");

    let eth1 = EthClient::new(&conf.execution_engine_addr).await?;

    let (
        def,
        total_validators,
        new_validators,
        new_withdrawal_addresses,
        new_fee_recipient_addresses,
    ) = if let Some(append) = &conf.append_config {
        let def = append.cluster_lock.definition.clone();
        let new_validators = u64::try_from(append.add_validators)?;
        let total_validators = def
            .num_validators
            .checked_add(new_validators)
            .ok_or(DkgError::IntegerOverflow)?;
        let new_withdrawal_addresses = append
            .validator_addresses
            .iter()
            .map(|addr| addr.withdrawal_address.clone())
            .collect::<Vec<_>>();
        let new_fee_recipient_addresses = append
            .validator_addresses
            .iter()
            .map(|addr| addr.fee_recipient_address.clone())
            .collect::<Vec<_>>();

        (
            def,
            total_validators,
            new_validators,
            new_withdrawal_addresses,
            new_fee_recipient_addresses,
        )
    } else {
        let def = disk::load_definition(&conf, &eth1).await?;

        let total_validators = def.num_validators;
        let new_validators = def.num_validators;
        let new_withdrawal_addresses = def.withdrawal_addresses();
        let new_fee_recipient_addresses = def.fee_recipient_addresses();

        (
            def,
            total_validators,
            new_validators,
            new_withdrawal_addresses,
            new_fee_recipient_addresses,
        )
    };

    // This DKG only supports a few specific config versions.
    if !matches!(def.version.as_str(), V1_6 | V1_7 | V1_8 | V1_9 | V1_10) {
        return Err(DkgError::UnsupportedDefinitionVersion {
            version: def.version.clone(),
        });
    }

    validate_keymanager_flags(&conf)?;

    // Check if keymanager address is reachable.
    verify_keymanager_connection(&conf).await?;

    if !conf.has_test_config() {
        disk::check_clear_data_dir(&conf.data_dir).await?;
    }

    disk::check_writes(&conf.data_dir).await?;

    let network = eth2util::network::fork_version_to_network(&def.fork_version)?;
    if network == eth2util::network::MAINNET.name && conf.has_test_config() {
        return Err(DkgError::TestConfigOnMainnet);
    }

    let peers = def.peers()?;

    let def_hash = pluto_cluster::helpers::to_0x_hex(&def.definition_hash);

    let key = if let Some(key) = conf.test_config.p2p_key.clone() {
        key
    } else {
        pluto_p2p::k1::load_priv_key(&conf.data_dir)?
    };

    let peer_id = pluto_p2p::peer::peer_id_from_key(key.public_key())?;

    info!("Starting local P2P networking peer");

    log_peer_summary(peer_id, &peers, &def.operators);

    let sig_types = vec![SIG_LOCK, SIG_DEPOSIT_DATA, SIG_VALIDATOR_REG];
    let sig_type_set = std::sync::Arc::new(sig_types.iter().copied().collect());
    let num_validators = u32::try_from(new_validators)?;
    let (node, mut handlers) = crate::node::setup_p2p(
        key.clone(),
        &conf,
        &peers,
        def.definition_hash.clone(),
        sig_type_set,
        num_validators,
        ct.child_token(),
    )
    .await?;

    let node_idx = def
        .node_idx(node.local_peer_id())
        .map_err(|source| match source {
            DefinitionError::PeerNotFound { peer_id } => {
                DkgError::LocalPeerNotInDefinition { peer_id }
            }
            other => DkgError::Definition(other),
        })?;

    let peer_ids = def.peer_ids()?;
    let exchanger = Exchanger::new(
        ct.child_token(),
        handlers.parsigex.clone(),
        peer_ids,
        sig_types,
    )
    .await;

    let peer_share_indices = peers
        .iter()
        .map(|peer| Ok((peer.id, u32::try_from(peer.share_idx())?)))
        .collect::<Result<HashMap<_, _>, DkgError>>()?;
    let local_share_idx = u32::try_from(node_idx.share_idx)?;
    let threshold = usize::try_from(def.threshold)?;
    let mut frost_transport = frostp2p::new_frost_p2p(
        handlers.bcast.clone(),
        &mut handlers.frost_p2p,
        &peer_share_indices,
        local_share_idx,
        threshold,
        num_validators as usize,
    )
    .await?;
    let node_sig_caster = nodesigs::NodeSigBcast::new(
        peers.clone(),
        node_idx.peer_idx,
        handlers.bcast.clone(),
        ct.child_token(),
    )
    .await?;

    let sync_clients = handlers.sync.clone();
    let sync_server = handlers.sync_server.clone();
    let network_ct = ct.child_token();
    let network_task = tokio::spawn(drive_dkg_network(node, network_ct.clone()));

    let result = run_ceremony(
        &conf,
        &eth1,
        ct.child_token(),
        def,
        total_validators,
        new_validators,
        new_withdrawal_addresses,
        new_fee_recipient_addresses,
        network,
        def_hash,
        key,
        node_idx,
        peers,
        exchanger,
        &mut frost_transport,
        node_sig_caster,
        sync_server,
        sync_clients,
    )
    .await;

    network_ct.cancel();
    network_task.await?;

    result
}

#[allow(clippy::too_many_arguments, reason = "mirrors the Go DKG run flow")]
async fn run_ceremony<T: frost::FTransport>(
    conf: &Config,
    eth1: &EthClient,
    ct: CancellationToken,
    def: Definition,
    total_validators: u64,
    new_validators: u64,
    new_withdrawal_addresses: Vec<String>,
    new_fee_recipient_addresses: Vec<String>,
    network: String,
    def_hash: String,
    key: k256::SecretKey,
    node_idx: pluto_cluster::definition::NodeIdx,
    peers: Vec<Peer>,
    exchanger: Exchanger,
    frost_transport: &mut T,
    node_sig_caster: nodesigs::NodeSigBcast,
    sync_server: crate::sync::Server,
    sync_clients: Vec<crate::sync::Client>,
) -> Result<(), DkgError> {
    info!("Waiting to connect to all peers...");

    let mut sync_runtime = start_sync_protocol(sync_server, sync_clients, ct.child_token()).await?;

    info!("All peers connected, starting DKG ceremony");

    let num_validators = u32::try_from(new_validators)?;
    let threshold = u32::try_from(def.threshold)?;
    let share_idx = u32::try_from(node_idx.share_idx)?;

    let shares = match def.dkg_algorithm.as_str() {
        "default" | "frost" => {
            let num_nodes = u32::try_from(peers.len())?;
            frost::run_frost_parallel(
                ct.child_token(),
                frost_transport,
                num_validators,
                num_nodes,
                threshold,
                share_idx,
                &def_hash,
            )
            .await?
        }
        algorithm => {
            return Err(DkgError::UnsupportedDkgAlgorithm {
                algorithm: algorithm.to_string(),
            });
        }
    };

    // DKG was step 1, advance to step 2.
    sync_runtime.next_step().await?;

    let append_config = conf.append_config.as_ref();
    let existing_shares = if append_config.is_some_and(|append| !append.unverified) {
        get_existing_shares(append_config)?
    } else {
        Vec::new()
    };

    if append_config.is_some() {
        debug!(
            total = total_validators,
            added = new_validators,
            "Validator keys summary"
        );
    }

    let deposit_amounts = deposit_amounts_for_definition(&def);
    if let Some(append) = append_config
        && !append.deposit_data.is_empty()
        && append.deposit_data.len() != deposit_amounts.len()
    {
        return Err(DkgError::DepositDataLengthMismatch {
            deposit_data: append.deposit_data.len(),
            deposit_amounts: deposit_amounts.len(),
        });
    }

    let mut deposit_datas = crate::signing::sign_and_agg_deposit_data(
        &exchanger,
        &shares,
        &new_withdrawal_addresses,
        &network,
        &node_idx,
        &deposit_amounts,
        def.compounding,
    )
    .await?;

    // Deposit data was step 2, advance to step 3.
    sync_runtime.next_step().await?;

    let val_regs = crate::signing::sign_and_agg_validator_registrations(
        &exchanger,
        &shares,
        &new_fee_recipient_addresses,
        def.target_gas_limit,
        &node_idx,
        &def.fork_version,
    )
    .await?;

    // Pre-regs was step 3, advance to step 4.
    sync_runtime.next_step().await?;

    let mut lock = crate::signing::sign_and_aggregate_lock_hash(
        &existing_shares,
        &shares,
        def,
        &node_idx,
        &exchanger,
        deposit_datas.clone(),
        val_regs,
        append_config,
    )
    .await?;

    // Lock hash aggregate was step 4, advance to step 5.
    sync_runtime.next_step().await?;

    lock.node_signatures = node_sig_caster
        .exchange(Some(&key), &lock.lock_hash, ct.child_token())
        .await?;

    if !pluto_cluster::version::support_node_signatures(&lock.version) {
        lock.node_signatures.clear();
    }

    // Node signatures was step 5, advance to step 6.
    sync_runtime.next_step().await?;

    if !conf.no_verify && append_config.is_none_or(|append| !append.unverified) {
        lock.verify_signatures(eth1)
            .await
            .map_err(DkgError::LockVerification)?;
    }

    if conf.keymanager.address.is_empty() {
        let all_shares = existing_shares
            .iter()
            .chain(shares.iter())
            .cloned()
            .collect::<Vec<_>>();
        disk::write_keys_to_disk(conf, &all_shares, false).await?;
        debug!(total = all_shares.len(), "Saved keyshares to disk");
    } else {
        disk::write_to_keymanager(
            &conf.keymanager.address,
            &conf.keymanager.auth_token,
            &shares,
        )
        .await?;
        debug!(
            keymanager_address = conf.keymanager.address,
            total = shares.len(),
            "Imported keyshares to keymanager"
        );
    }

    let mut dashboard_url = None;
    if conf.publish.enabled {
        match write_lock_to_api(&conf.publish.address, &lock, conf.publish.timeout).await {
            Ok(url) => dashboard_url = Some(url),
            Err(error) => warn!(%error, "Couldn't publish lock file to Obol API"),
        }
    }

    disk::write_lock(&conf.data_dir, &lock).await?;
    debug!("Saved lock file to disk");

    if let Some(append) = append_config
        && !append.deposit_data.is_empty()
    {
        deposit_datas = pluto_eth2util::deposit::merge_deposit_data_sets(
            deposit_datas,
            append.deposit_data.clone(),
        );
        debug!(
            amounts = deposit_datas.len(),
            validators = deposit_datas.first().map_or(0, Vec::len),
            "Merged deposit data files"
        );
    }

    for deposit_data in &deposit_datas {
        pluto_eth2util::deposit::write_deposit_data_file(deposit_data, &network, &conf.data_dir)
            .await?;
        debug!("Saved deposit data file(s) to disk");
    }

    // Signature verification and disk key write was step 6, advance to step 7.
    sync_runtime.next_step().await?;

    sync_runtime.shutdown().await?;

    if conf.zipped {
        let data_dir = conf.data_dir.clone();
        tokio::task::spawn_blocking(move || {
            pluto_app::utils::bundle_output(data_dir, "dkg.tar.gz")
        })
        .await??;
    }

    debug!(
        seconds = conf.shutdown_delay.as_secs(),
        "Graceful shutdown delay"
    );
    tokio::time::sleep(conf.shutdown_delay).await;

    info!("Successfully completed DKG ceremony 🎉");
    if let Some(url) = dashboard_url {
        info!("You can find your newly-created cluster dashboard here: {url}");
    }

    Ok(())
}

fn deposit_amounts_for_definition(def: &Definition) -> Vec<phase0::Gwei> {
    if def.deposit_amounts.is_empty() {
        if pluto_cluster::definition::Definition::support_partial_deposits(&def.version) {
            pluto_eth2util::deposit::default_deposit_amounts(def.compounding)
        } else {
            vec![pluto_eth2util::deposit::DEFAULT_DEPOSIT_AMOUNT]
        }
    } else {
        pluto_eth2util::deposit::dedup_amounts(&def.deposit_amounts)
    }
}

struct SyncRuntime {
    server: crate::sync::Server,
    clients: Vec<crate::sync::Client>,
    step: i64,
    cancellation: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl SyncRuntime {
    async fn next_step(&mut self) -> Result<(), DkgError> {
        self.step = self.step.checked_add(1).ok_or(DkgError::IntegerOverflow)?;
        for client in &self.clients {
            client.set_step(self.step);
        }

        debug!(step = self.step, "Waiting for peers to start next step");
        self.server
            .await_all_at_step(self.step, self.cancellation.child_token())
            .await?;

        Ok(())
    }

    async fn shutdown(mut self) -> Result<(), DkgError> {
        for client in &self.clients {
            client.shutdown(self.cancellation.child_token()).await?;
        }

        self.server
            .await_all_shutdown(self.cancellation.child_token())
            .await?;
        self.cancellation.cancel();

        for task in self.tasks.drain(..) {
            task.await?;
        }

        Ok(())
    }
}

impl Drop for SyncRuntime {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

async fn start_sync_protocol(
    server: crate::sync::Server,
    clients: Vec<crate::sync::Client>,
    cancellation: CancellationToken,
) -> Result<SyncRuntime, DkgError> {
    server.start();

    let mut tasks = Vec::with_capacity(clients.len());
    for client in &clients {
        let client = client.clone();
        let client_ct = cancellation.child_token();
        let cancel_on_error = cancellation.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(error) = client.run(client_ct).await
                && !matches!(error, crate::sync::Error::Canceled)
            {
                error!(%error, "Sync failed to peer");
                cancel_on_error.cancel();
            }
        }));
    }

    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    loop {
        if let Some(error) = server.err().await {
            return Err(DkgError::Sync(error));
        }

        let connected_count = clients
            .iter()
            .filter(|client| client.is_connected())
            .count();
        if connected_count == clients.len() {
            break;
        }

        tokio::select! {
            _ = cancellation.cancelled() => return Err(crate::sync::Error::Canceled.into()),
            _ = ticker.tick() => {}
        }
    }

    for client in &clients {
        client.disable_reconnect();
    }

    server
        .await_all_connected(cancellation.child_token())
        .await?;

    let mut runtime = SyncRuntime {
        server,
        clients,
        step: 0,
        cancellation,
        tasks,
    };
    runtime.next_step().await?;

    Ok(runtime)
}

async fn drive_dkg_network(
    mut node: pluto_p2p::p2p::Node<crate::node::DkgBehaviour>,
    cancellation: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            _ = node.select_next_some() => {}
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
        let tempdir = tempfile::tempdir().expect("tempdir");
        let (lock, ..) = pluto_cluster::test_cluster::new_for_test(1, 3, 4, 0);

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
    async fn run_reaches_p2p_key_verification_after_preflight() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let (lock, ..) = pluto_cluster::test_cluster::new_for_test(1, 3, 4, 1);
        let mismatched_key = pluto_testutil::random::generate_insecure_k1_key(99);

        let err = run(
            Config::builder()
                .data_dir(tempdir.path().to_path_buf())
                .p2p(P2PConfig::default())
                .shutdown_delay(Duration::ZERO)
                .test_config(
                    TestConfig::builder()
                        .def(lock.definition.clone())
                        .p2p_key(mismatched_key)
                        .build(),
                )
                .build(),
            CancellationToken::new(),
        )
        .await
        .expect_err("mismatched P2P key should fail before networking");

        assert!(matches!(
            err,
            DkgError::PeerError(pluto_p2p::peer::PeerError::UnknownPublicKey)
        ));
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
    fn keymanager_config_debug_redacts_auth_token() {
        let cfg = KeymanagerConfig::builder()
            .address("https://keymanager.example".to_string())
            .auth_token("super-secret-token".to_string())
            .build();
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("super-secret-token"),
            "token leaked in Debug: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "expected <redacted> marker in Debug: {rendered}"
        );
        assert!(
            rendered.contains("https://keymanager.example"),
            "address should be visible"
        );
    }
}
