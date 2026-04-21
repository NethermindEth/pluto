//! Create cluster command implementation.
//!
//! This module implements the `pluto create cluster` command, which creates a
//! local distributed validator cluster configuration including validator keys,
//! threshold BLS key shares, p2p private keys, cluster-lock files, and deposit
//! data files.

use std::{
    collections::HashMap,
    io::Write,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use chrono::Utc;
use k256::SecretKey;
use pluto_cluster::{
    definition::Definition,
    deposit::DepositData,
    distvalidator::DistValidator,
    helpers,
    lock::Lock,
    operator::Operator,
    registration::{BuilderRegistration, Registration},
};
use pluto_core::consensus::protocols;
use pluto_crypto::{
    blst_impl::BlstImpl,
    tbls::Tbls,
    types::{PrivateKey, PublicKey},
};
use pluto_eth1wrap as eth1wrap;

use pluto_app::{obolapi, utils as app_utils};
use pluto_eth2util::{
    self as eth2util,
    deposit::{self, Gwei},
    enr::Record,
    keymanager,
    keystore::{self, CONFIRM_INSECURE_KEYS, Keystore},
    network, registration as eth2util_registration,
};
use pluto_p2p::k1 as p2p_k1;
use pluto_ssz::to_0x_hex;
use rand::rngs::OsRng;
use tracing::{debug, info, warn};

use crate::{
    commands::{
        address_validation::validate_addresses,
        constants::{MIN_NODES, MIN_THRESHOLD},
        create_dkg,
    },
    error::{
        CliError, CreateClusterError, InvalidNetworkConfigError, Result as CliResult,
        ThresholdError,
    },
};

/// HTTP scheme.
const HTTP_SCHEME: &str = "http";
/// HTTPS scheme.
const HTTPS_SCHEME: &str = "https";

type Result<T> = std::result::Result<T, CreateClusterError>;

/// Ethereum network options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum Network {
    /// Ethereum mainnet
    #[default]
    Mainnet,
    /// Prater testnet (alias for Goerli)
    Prater,
    /// Goerli testnet
    Goerli,
    /// Sepolia testnet
    Sepolia,
    /// Hoodi testnet
    Hoodi,
    /// Holesky testnet
    Holesky,
    /// Gnosis chain
    Gnosis,
    /// Chiado testnet
    Chiado,
}

impl Network {
    /// Returns the canonical network name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Goerli | Network::Prater => "goerli",
            Network::Sepolia => "sepolia",
            Network::Hoodi => "hoodi",
            Network::Holesky => "holesky",
            Network::Gnosis => "gnosis",
            Network::Chiado => "chiado",
        }
    }
}

impl TryFrom<&str> for Network {
    type Error = InvalidNetworkConfigError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "mainnet" => Ok(Network::Mainnet),
            "prater" => Ok(Network::Prater),
            "goerli" => Ok(Network::Goerli),
            "sepolia" => Ok(Network::Sepolia),
            "hoodi" => Ok(Network::Hoodi),
            "holesky" => Ok(Network::Holesky),
            "gnosis" => Ok(Network::Gnosis),
            "chiado" => Ok(Network::Chiado),
            _ => Err(InvalidNetworkConfigError::InvalidNetworkSpecified {
                network: value.to_string(),
            }),
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Custom testnet configuration.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct TestnetConfig {
    /// Chain ID of the custom test network
    #[arg(
        long = "testnet-chain-id",
        help = "Chain ID of the custom test network."
    )]
    pub chain_id: Option<u64>,

    /// Genesis fork version of the custom test network (in hex)
    #[arg(
        long = "testnet-fork-version",
        help = "Genesis fork version of the custom test network (in hex)."
    )]
    pub fork_version: Option<String>,

    /// Genesis timestamp of the custom test network
    #[arg(
        long = "testnet-genesis-timestamp",
        help = "Genesis timestamp of the custom test network."
    )]
    pub genesis_timestamp: Option<u64>,

    /// Name of the custom test network
    #[arg(long = "testnet-name", help = "Name of the custom test network.")]
    pub testnet_name: Option<String>,
}

impl TestnetConfig {
    pub fn is_empty(&self) -> bool {
        self.testnet_name.is_none()
            && self.fork_version.is_none()
            && self.chain_id.is_none()
            && self.genesis_timestamp.is_none()
    }
}

/// Arguments for the create cluster command
#[derive(clap::Args)]
pub struct CreateClusterArgs {
    /// The target folder to create the cluster in.
    #[arg(
        long = "cluster-dir",
        default_value = "./",
        help = "The target folder to create the cluster in."
    )]
    pub cluster_dir: PathBuf,

    /// Enable compounding rewards for validators
    #[arg(
        long = "compounding",
        help = "Enable compounding rewards for validators by using 0x02 withdrawal credentials."
    )]
    pub compounding: bool,

    /// Preferred consensus protocol name for the cluster
    #[arg(
        long = "consensus-protocol",
        help = "Preferred consensus protocol name for the cluster. Selected automatically when not specified."
    )]
    pub consensus_protocol: Option<String>,

    /// Path to a cluster definition file or HTTP URL
    #[arg(
        long = "definition-file",
        help = "Optional path to a cluster definition file or an HTTP URL. This overrides all other configuration flags."
    )]
    pub definition_file: Option<String>,

    /// List of partial deposit amounts (integers) in ETH
    #[arg(
        long = "deposit-amounts",
        value_delimiter = ',',
        help = "List of partial deposit amounts (integers) in ETH. Values must sum up to at least 32ETH."
    )]
    pub deposit_amounts: Vec<u64>,

    /// The address of the execution engine JSON-RPC API
    #[arg(
        long = "execution-client-rpc-endpoint",
        help = "The address of the execution engine JSON-RPC API."
    )]
    pub execution_engine_addr: Option<String>,

    /// Comma separated list of fee recipient addresses
    #[arg(
        long = "fee-recipient-addresses",
        value_delimiter = ',',
        help = "Comma separated list of Ethereum addresses of the fee recipient for each validator. Either provide a single fee recipient address or fee recipient addresses for each validator."
    )]
    pub fee_recipient_addrs: Vec<String>,

    /// Generates insecure keystore files (testing only)
    #[arg(
        long = "insecure-keys",
        help = "Generates insecure keystore files. This should never be used. It is not supported on mainnet."
    )]
    pub insecure_keys: bool,

    /// Comma separated list of keymanager URLs
    #[arg(
        long = "keymanager-addresses",
        value_delimiter = ',',
        help = "Comma separated list of keymanager URLs to import validator key shares to. Note that multiple addresses are required, one for each node in the cluster."
    )]
    pub keymanager_addrs: Vec<String>,

    /// Authentication bearer tokens for keymanager URLs
    #[arg(
        long = "keymanager-auth-tokens",
        value_delimiter = ',',
        help = "Authentication bearer tokens to interact with the keymanager URLs. Don't include the \"Bearer\" symbol, only include the api-token."
    )]
    pub keymanager_auth_tokens: Vec<String>,

    /// The cluster name
    #[arg(long = "name")]
    pub name: Option<String>,

    /// Ethereum network to create validators for
    #[arg(long = "network", help = "Ethereum network to create validators for.")]
    pub network: Option<Network>,

    /// The number of charon nodes in the cluster
    #[arg(
        long = "nodes",
        default_value = "0",
        help = "The number of charon nodes in the cluster. Minimum is 3."
    )]
    pub nodes: u64,

    /// The number of distributed validators needed in the cluster
    #[arg(
        long = "num-validators",
        default_value = "0",
        help = "The number of distributed validators needed in the cluster."
    )]
    pub num_validators: u64,

    /// Publish lock file to obol-api
    #[arg(long = "publish", help = "Publish lock file to obol-api.")]
    pub publish: bool,

    /// The URL to publish the lock file to
    #[arg(
        long = "publish-address",
        default_value = "https://api.obol.tech/v1",
        help = "The URL to publish the lock file to."
    )]
    pub publish_address: String,

    /// Split an existing validator's private key
    #[arg(
        long = "split-existing-keys",
        help = "Split an existing validator's private key into a set of distributed validator private key shares. Does not re-create deposit data for this key."
    )]
    pub split_keys: bool,

    /// Directory containing keys to split
    #[arg(
        long = "split-keys-dir",
        help = "Directory containing keys to split. Expects keys in keystore-*.json and passwords in keystore-*.txt. Requires --split-existing-keys."
    )]
    pub split_keys_dir: Option<PathBuf>,

    /// Preferred target gas limit for transactions
    #[arg(
        long = "target-gas-limit",
        default_value = "60000000",
        help = "Preferred target gas limit for transactions."
    )]
    pub target_gas_limit: u64,

    /// Custom testnet configuration
    #[command(flatten)]
    pub testnet_config: TestnetConfig,

    /// Optional override of threshold
    #[arg(
        long = "threshold",
        help = "Optional override of threshold required for signature reconstruction. Defaults to ceil(n*2/3) if zero. Warning, non-default values decrease security."
    )]
    pub threshold: Option<u64>,

    /// Comma separated list of withdrawal addresses
    #[arg(
        long = "withdrawal-addresses",
        value_delimiter = ',',
        help = "Comma separated list of Ethereum addresses to receive the returned stake and accrued rewards for each validator. Either provide a single withdrawal address or withdrawal addresses for each validator."
    )]
    pub withdrawal_addrs: Vec<String>,

    /// Create a tar archive compressed with gzip
    #[arg(
        long = "zipped",
        help = "Create a tar archive compressed with gzip of the cluster directory after creation."
    )]
    pub zipped: bool,
}

impl From<TestnetConfig> for network::Network {
    fn from(config: TestnetConfig) -> Self {
        network::Network {
            chain_id: config.chain_id.unwrap_or(0),
            name: Box::leak(
                config
                    .testnet_name
                    .as_ref()
                    .unwrap_or(&String::new())
                    .clone()
                    .into_boxed_str(),
            ),
            genesis_fork_version_hex: Box::leak(
                config
                    .fork_version
                    .as_ref()
                    .unwrap_or(&String::new())
                    .clone()
                    .into_boxed_str(),
            ),
            genesis_timestamp: config.genesis_timestamp.unwrap_or(0),
            capella_hard_fork: "",
        }
    }
}

fn init_tracing() -> CliResult<()> {
    match pluto_tracing::init(&pluto_tracing::TracingConfig::default()) {
        Ok(_) | Err(pluto_tracing::init::Error::InitError(_)) => Ok(()),
        Err(err) => Err(CliError::from(err)),
    }
}

fn validate_threshold(args: &CreateClusterArgs) -> Result<()> {
    let Some(threshold) = args.threshold else {
        return Ok(());
    };

    if threshold < MIN_THRESHOLD {
        return Err(ThresholdError::ThresholdTooLow { threshold }.into());
    }

    let number_of_nodes = args.nodes;
    if threshold > number_of_nodes {
        return Err(ThresholdError::ThresholdTooHigh {
            threshold,
            number_of_nodes,
        }
        .into());
    }

    Ok(())
}

/// Runs the create cluster command
pub async fn run(w: &mut dyn Write, mut args: CreateClusterArgs) -> CliResult<()> {
    init_tracing()?;

    let mut definition_input = None;

    if let Some(definition_file) = args.definition_file.as_ref() {
        let Some(addr) = args.execution_engine_addr.as_ref() else {
            return Err(CreateClusterError::MissingExecutionEngineAddress.into());
        };

        let eth1cl = eth1wrap::EthClient::new(addr.clone()).await?;
        let def = load_definition(definition_file, &eth1cl).await?;

        args.nodes = u64::try_from(def.operators.len()).expect("operators length is too large");
        args.threshold = Some(def.threshold);

        let network_name = eth2util::network::fork_version_to_network(&def.fork_version)?;
        args.network = Some(
            Network::try_from(network_name.as_str())
                .map_err(CreateClusterError::InvalidNetworkConfig)?,
        );

        definition_input = Some((def, eth1cl));
    }

    validate_threshold(&args)?;

    validate_create_config(&args)?;

    let mut secrets: Vec<PrivateKey> = Vec::new();

    // If we're splitting keys, read them from `split_keys_dir` and set
    // args.num_validators to the amount of secrets we read.
    // If `split_keys` wasn't set, we wouldn't have reached this part of code
    // because `validate_create_config()` would've already errored.
    if args.split_keys {
        let use_sequence_keys = args.withdrawal_addrs.len() > 1;

        let Some(split_keys_dir) = &args.split_keys_dir else {
            return Err(CreateClusterError::MissingSplitKeysDir.into());
        };

        secrets = get_keys(&split_keys_dir, use_sequence_keys).await?;

        debug!(
            "Read {} secrets from {}",
            secrets.len(),
            split_keys_dir.display()
        );

        // Needed if --split-existing-keys is called without a definition file.
        // It's safe to unwrap here because we know the length is less than u64::MAX.
        args.num_validators = u64::try_from(secrets.len()).expect("secrets length is too large");
    }

    // Get a cluster definition, either from a definition file or from the config.
    let (mut def, mut deposit_amounts) = if let Some((def, eth1cl)) = definition_input {
        validate_definition(&def, args.insecure_keys, &args.keymanager_addrs, &eth1cl).await?;

        let deposit_amounts = def.deposit_amounts.clone();

        (def, deposit_amounts)
    } else {
        // Create new definition from cluster config
        let def = new_def_from_config(&args)?;

        let deposit_amounts = deposit::eths_to_gweis(&args.deposit_amounts);

        (def, deposit_amounts)
    };

    if deposit_amounts.is_empty() {
        deposit_amounts = deposit::default_deposit_amounts(args.compounding);
    }

    if secrets.is_empty() {
        // This is the case in which split-keys is undefined and user passed validator
        // amount on CLI
        secrets = generate_keys(def.num_validators)?;
    }

    let num_validators_usize =
        usize::try_from(def.num_validators).map_err(|_| CreateClusterError::ValueExceedsUsize {
            value: def.num_validators,
        })?;

    if secrets.len() != num_validators_usize {
        return Err(CreateClusterError::KeyCountMismatch {
            disk_keys: secrets.len(),
            definition_keys: def.num_validators,
        }
        .into());
    }

    let num_nodes = u64::try_from(def.operators.len()).expect("operators length is too large");

    // Generate threshold bls key shares

    let (pub_keys, share_sets) = get_tss_shares(&secrets, def.threshold, num_nodes)?;

    // Create cluster directory at the given location
    tokio::fs::create_dir_all(&args.cluster_dir).await?;

    // Set directory permissions to 0o755
    let permissions = std::fs::Permissions::from_mode(0o755);
    tokio::fs::set_permissions(&args.cluster_dir, permissions).await?;

    // Create operators and their enr node keys
    let (ops, node_keys) = get_operators(num_nodes, &args.cluster_dir)?;

    def.operators = ops;
    def.set_definition_hashes()
        .map_err(CreateClusterError::DefinitionError)?;

    let keys_to_disk = args.keymanager_addrs.is_empty();

    if keys_to_disk {
        write_keys_to_disk(
            num_nodes,
            &args.cluster_dir,
            args.insecure_keys,
            &share_sets,
        )
        .await?;
    } else {
        write_keys_to_keymanager(&args, num_nodes, &share_sets).await?;
    }

    let network = eth2util::network::fork_version_to_network(&def.fork_version)?;

    let deposit_datas = create_deposit_datas(
        &def.withdrawal_addresses(),
        &network,
        &secrets,
        &deposit_amounts,
        def.compounding,
    )?;

    let eth2util_deposit_datas = deposit_datas
        .iter()
        .map(|dd| cluster_deposit_data_to_eth2util_deposit_data(dd))
        .collect::<Vec<_>>();

    // Write deposit-data files
    eth2util::deposit::write_cluster_deposit_data_files(
        &eth2util_deposit_datas,
        network,
        &args.cluster_dir,
        usize::try_from(num_nodes).expect("num_nodes should fit in usize"),
    )
    .await?;

    let val_regs = create_validator_registrations(
        &def.fee_recipient_addresses(),
        &secrets,
        &def.fork_version,
        args.split_keys,
        args.target_gas_limit,
    )?;

    let vals = get_validators(&pub_keys, &share_sets, &deposit_datas, val_regs)?;

    let mut lock = Lock {
        definition: def,
        distributed_validators: vals,
        ..Default::default()
    };

    lock.set_lock_hash().map_err(CreateClusterError::from)?;

    lock.signature_aggregate = agg_sign(&share_sets, &lock.lock_hash)?;

    for op_key in &node_keys {
        let node_sig =
            pluto_k1util::sign(op_key, &lock.lock_hash).map_err(CreateClusterError::K1UtilError)?;
        lock.node_signatures.push(node_sig.to_vec());
    }

    let mut dashboard_url = String::new();
    if args.publish {
        match write_lock_to_api(&args.publish_address, &lock).await {
            Ok(url) => dashboard_url = url,
            Err(err) => {
                warn!(error = %err, "Failed to publish lock file to Obol API");
            }
        }
    }

    write_lock(&lock, &args.cluster_dir, num_nodes).await?;

    if args.zipped {
        app_utils::bundle_output(&args.cluster_dir, "cluster.tar.gz")
            .map_err(CreateClusterError::BundleOutputError)?;
    }

    if args.split_keys {
        write_split_keys_warning(w)?;
    }

    write_output(
        w,
        args.split_keys,
        &args.cluster_dir,
        num_nodes,
        keys_to_disk,
        args.zipped,
    )?;

    if !dashboard_url.is_empty() {
        info!(
            "You can find your newly-created cluster dashboard here: {}",
            dashboard_url
        );
    }

    Ok(())
}

async fn write_lock_to_api(publish_addr: &str, lock: &Lock) -> Result<String> {
    let client = obolapi::Client::new(publish_addr, obolapi::ClientOptions::default())
        .map_err(CreateClusterError::ObolApiError)?;
    match client.publish_lock(lock.clone()).await {
        Ok(()) => {
            info!(addr = publish_addr, "Published lock file");
            match client.launchpad_url_for_lock(lock) {
                Ok(url) => Ok(url),
                Err(err) => Err(CreateClusterError::ObolApiError(err)),
            }
        }
        Err(err) => Err(CreateClusterError::ObolApiError(err)),
    }
}

fn create_validator_registrations(
    fee_recipient_addresses: &[String],
    secrets: &[PrivateKey],
    fork_version: &[u8],
    split_keys: bool,
    target_gas_limit: u64,
) -> Result<Vec<BuilderRegistration>> {
    if fee_recipient_addresses.len() != secrets.len() {
        return Err(CreateClusterError::InsufficientFeeAddresses {
            expected: secrets.len(),
            got: fee_recipient_addresses.len(),
        });
    }

    let effective_gas_limit = if target_gas_limit == 0 {
        warn!(
            default_gas_limit = eth2util_registration::DEFAULT_GAS_LIMIT,
            "Custom target gas limit not supported, setting to default"
        );
        eth2util_registration::DEFAULT_GAS_LIMIT
    } else {
        target_gas_limit
    };

    let fork_version: [u8; 4] = fork_version
        .try_into()
        .map_err(|_| CreateClusterError::InvalidForkVersionLength)?;

    let tbls = BlstImpl;
    let mut registrations = Vec::with_capacity(secrets.len());

    for (secret, fee_address) in secrets.iter().zip(fee_recipient_addresses.iter()) {
        let timestamp = if split_keys {
            Utc::now()
        } else {
            eth2util::network::fork_version_to_genesis_time(&fork_version)?
        };

        let pk = tbls.secret_to_public_key(secret)?;

        let unsigned_reg = eth2util_registration::new_message(
            pk,
            fee_address,
            effective_gas_limit,
            u64::try_from(timestamp.timestamp()).expect("timestamp should fit in u64"),
        )?;

        let sig_root = eth2util_registration::get_message_signing_root(&unsigned_reg, fork_version);

        let sig = tbls.sign(secret, &sig_root)?;

        registrations.push(BuilderRegistration {
            message: Registration {
                fee_recipient: unsigned_reg.fee_recipient,
                gas_limit: unsigned_reg.gas_limit,
                timestamp,
                pub_key: unsigned_reg.pubkey,
            },
            signature: sig,
        });
    }

    Ok(registrations)
}

fn cluster_deposit_data_to_eth2util_deposit_data(
    deposit_datas: &[DepositData],
) -> Vec<eth2util::deposit::DepositData> {
    deposit_datas
        .iter()
        .map(|dd| eth2util::deposit::DepositData {
            pubkey: dd.pub_key,
            withdrawal_credentials: dd.withdrawal_credentials,
            amount: dd.amount,
            signature: dd.signature,
        })
        .collect()
}

async fn write_keys_to_disk(
    num_nodes: u64,
    cluster_dir: impl AsRef<Path>,
    insecure_keys: bool,
    share_sets: &[Vec<PrivateKey>],
) -> Result<()> {
    for i in 0..num_nodes {
        let i_usize = usize::try_from(i).expect("node index should fit in usize on all platforms");

        let mut secrets: Vec<PrivateKey> = Vec::new();
        for shares in share_sets {
            secrets.push(shares[i_usize]);
        }

        let keys_dir =
            helpers::create_validator_keys_dir(node_dir(cluster_dir.as_ref(), i)).await?;

        if insecure_keys {
            keystore::store_keys_insecure(&secrets, &keys_dir, &CONFIRM_INSECURE_KEYS).await?;
        } else {
            keystore::store_keys(&secrets, &keys_dir).await?;
        }
    }

    Ok(())
}

fn random_hex64() -> Result<String> {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    Ok(hex::encode(bytes))
}

async fn write_keys_to_keymanager(
    args: &CreateClusterArgs,
    num_nodes: u64,
    share_sets: &[Vec<PrivateKey>],
) -> Result<()> {
    // Create and verify all keymanager clients first.
    let mut clients: Vec<keymanager::Client> = Vec::new();
    for i in 0..num_nodes {
        let i_usize = usize::try_from(i).expect("node index should fit in usize on all platforms");
        let cl = keymanager::Client::new(
            &args.keymanager_addrs[i_usize],
            &args.keymanager_auth_tokens[i_usize],
        )?;
        cl.verify_connection().await?;
        clients.push(cl);
    }

    // For each node, build keystores from this node's share of each validator,
    // then import them into that node's keymanager.
    for i in 0..num_nodes {
        let i_usize = usize::try_from(i).expect("node index should fit in usize on all platforms");

        let mut keystores: Vec<Keystore> = Vec::new();
        let mut passwords: Vec<String> = Vec::new();

        // share_sets[validator_idx][node_idx]
        for shares in share_sets {
            let password = random_hex64()?;
            let pbkdf2_c = if args.insecure_keys {
                // Match Charon's `keystorev4.WithCost(..., 4)` => 2^4 iterations.
                Some(16u32)
            } else {
                None
            };
            let store = keystore::encrypt(&shares[i_usize], &password, pbkdf2_c, &mut OsRng)?;
            passwords.push(password);
            keystores.push(store);
        }

        clients[i_usize]
            .import_keystores(&keystores, &passwords)
            .await
            .inspect_err(|_| {
                tracing::error!(
                    addr = %args.keymanager_addrs[i_usize],
                    "Failed to import keys",
                );
            })?;

        info!(
            node = format!("node{}", i),
            addr = %args.keymanager_addrs[i_usize],
            "Imported key shares to keymanager",
        );
    }

    info!("Imported all validator keys to respective keymanagers");

    Ok(())
}

fn create_deposit_datas(
    withdrawal_addresses: &[String],
    network: impl AsRef<str>,
    secrets: &[PrivateKey],
    deposit_amounts: &[Gwei],
    compounding: bool,
) -> Result<Vec<Vec<DepositData>>> {
    if secrets.len() != withdrawal_addresses.len() {
        return Err(CreateClusterError::InsufficientWithdrawalAddresses);
    }
    if deposit_amounts.is_empty() {
        return Err(CreateClusterError::EmptyDepositAmounts);
    }
    let deduped = deposit::dedup_amounts(deposit_amounts);
    sign_deposit_datas(
        secrets,
        withdrawal_addresses,
        network.as_ref(),
        &deduped,
        compounding,
    )
}

fn sign_deposit_datas(
    secrets: &[PrivateKey],
    withdrawal_addresses: &[String],
    network: &str,
    deposit_amounts: &[Gwei],
    compounding: bool,
) -> Result<Vec<Vec<DepositData>>> {
    if secrets.len() != withdrawal_addresses.len() {
        return Err(CreateClusterError::InsufficientWithdrawalAddresses);
    }
    if deposit_amounts.is_empty() {
        return Err(CreateClusterError::EmptyDepositAmounts);
    }
    let tbls = BlstImpl;
    let mut dd = Vec::new();
    for &deposit_amount in deposit_amounts {
        let mut datas = Vec::new();
        for (secret, withdrawal_addr) in secrets.iter().zip(withdrawal_addresses.iter()) {
            let withdrawal_addr = eth2util::helpers::checksum_address(withdrawal_addr)?;
            let pk = tbls.secret_to_public_key(secret)?;
            let msg = deposit::new_message(pk, &withdrawal_addr, deposit_amount, compounding)?;
            let sig_root = deposit::get_message_signing_root(&msg, network)?;
            let sig = tbls.sign(secret, &sig_root)?;
            datas.push(DepositData {
                pub_key: msg.pubkey,
                withdrawal_credentials: msg.withdrawal_credentials,
                amount: msg.amount,
                signature: sig,
            });
        }
        dd.push(datas);
    }
    Ok(dd)
}

fn generate_keys(num_validators: u64) -> Result<Vec<PrivateKey>> {
    let tbls = BlstImpl;
    let mut secrets = Vec::new();

    for _ in 0..num_validators {
        let secret = tbls.generate_secret_key(OsRng)?;
        secrets.push(secret);
    }

    Ok(secrets)
}

fn get_operators(
    num_nodes: u64,
    cluster_dir: impl AsRef<Path>,
) -> Result<(Vec<Operator>, Vec<SecretKey>)> {
    let mut ops = Vec::new();
    let mut node_keys = Vec::new();

    for i in 0..num_nodes {
        let (record, identity_key) = new_peer(&cluster_dir, i)?;

        ops.push(Operator {
            enr: record.to_string(),
            ..Default::default()
        });
        node_keys.push(identity_key);
    }

    Ok((ops, node_keys))
}

fn new_peer(cluster_dir: impl AsRef<Path>, peer_idx: u64) -> Result<(Record, SecretKey)> {
    let dir = node_dir(cluster_dir.as_ref(), peer_idx);

    let p2p_key = p2p_k1::new_saved_priv_key(&dir)?;

    let record = Record::new(&p2p_key, Vec::new())?;

    Ok((record, p2p_key))
}

async fn get_keys(
    split_keys_dir: impl AsRef<Path>,
    use_sequence_keys: bool,
) -> Result<Vec<PrivateKey>> {
    if use_sequence_keys {
        let files = keystore::load_files_unordered(split_keys_dir).await?;
        Ok(files.sequenced_keys()?)
    } else {
        let files = keystore::load_files_recursively(split_keys_dir).await?;
        Ok(files.keys())
    }
}

/// Creates a new cluster definition from the provided configuration.
fn new_def_from_config(args: &CreateClusterArgs) -> Result<Definition> {
    let num_validators = args.num_validators;
    if num_validators == 0 {
        return Err(CreateClusterError::MissingNumValidatorsOrDefinitionFile);
    }

    let (fee_recipient_addrs, withdrawal_addrs) = validate_addresses(
        num_validators,
        &args.fee_recipient_addrs,
        &args.withdrawal_addrs,
    )?;

    let fork_version = if let Some(network) = args.network {
        eth2util::network::network_to_fork_version(network.as_str())?
    } else if let Some(ref fork_version_hex) = args.testnet_config.fork_version {
        fork_version_hex.clone()
    } else {
        return Err(CreateClusterError::InvalidNetworkConfig(
            InvalidNetworkConfigError::MissingNetworkFlagAndNoTestnetConfigFlag,
        ));
    };

    let num_nodes = args.nodes;
    if num_nodes == 0 {
        return Err(CreateClusterError::MissingNodesOrDefinitionFile);
    }

    let operators = vec![
        pluto_cluster::operator::Operator::default();
        usize::try_from(num_nodes).expect("num_nodes should fit in usize")
    ];
    let threshold = safe_threshold(num_nodes, args.threshold);

    let name = args.name.clone().unwrap_or_default();

    let consensus_protocol = args.consensus_protocol.clone().unwrap_or_default();

    let def = pluto_cluster::definition::Definition::new(
        name,
        num_validators,
        threshold,
        fee_recipient_addrs,
        withdrawal_addrs,
        fork_version,
        pluto_cluster::definition::Creator::default(),
        operators,
        deposit::eths_to_gweis(&args.deposit_amounts),
        consensus_protocol,
        args.target_gas_limit,
        args.compounding,
        vec![],
    )?;
    Ok(def)
}

fn get_tss_shares(
    secrets: &[PrivateKey],
    threshold: u64,
    num_nodes: u64,
) -> Result<(Vec<PublicKey>, Vec<Vec<PrivateKey>>)> {
    let tbls = BlstImpl;
    let mut dvs = Vec::new();
    let mut splits = Vec::new();

    let num_nodes = u8::try_from(num_nodes)
        .map_err(|_| CreateClusterError::ValueExceedsU8 { value: num_nodes })?;
    let threshold = u8::try_from(threshold)
        .map_err(|_| CreateClusterError::ValueExceedsU8 { value: threshold })?;

    for secret in secrets {
        let shares = tbls.threshold_split(secret, num_nodes, threshold)?;

        // Preserve order when transforming from map of private shares to array of
        // private keys
        let mut entries: Vec<_> = shares.into_iter().collect();
        entries.sort_by_key(|(idx, _)| *idx);
        let secret_set = entries.into_iter().map(|(_, share)| share).collect();

        splits.push(secret_set);

        let pubkey = tbls.secret_to_public_key(secret)?;
        dvs.push(pubkey);
    }

    Ok((dvs, splits))
}

async fn validate_definition(
    def: &Definition,
    insecure_keys: bool,
    keymanager_addrs: &[String],
    eth1cl: &eth1wrap::EthClient,
) -> Result<()> {
    if def.num_validators == 0 {
        return Err(CreateClusterError::ZeroValidators);
    }

    let num_operators =
        u64::try_from(def.operators.len()).expect("operators length should fit in u64");
    if num_operators < MIN_NODES {
        return Err(CreateClusterError::TooFewNodes {
            num_nodes: num_operators,
        });
    }

    if !keymanager_addrs.is_empty() && (keymanager_addrs.len() != def.operators.len()) {
        return Err(CreateClusterError::InsufficientKeymanagerAddresses {
            expected: def.operators.len(),
            got: keymanager_addrs.len(),
        });
    }

    if !def.deposit_amounts.is_empty() {
        deposit::verify_deposit_amounts(&def.deposit_amounts, def.compounding)?;
    }

    let network_name = network::fork_version_to_network(&def.fork_version)?;

    if insecure_keys && is_main_or_gnosis(&network_name) {
        return Err(CreateClusterError::InsecureKeysOnMainnetOrGnosis);
    } else if insecure_keys {
        tracing::warn!("Insecure keystores configured. ONLY DO THIS DURING TESTING");
    }

    if def.name.is_empty() {
        return Err(CreateClusterError::DefinitionNameNotProvided);
    }

    def.verify_hashes()?;

    def.verify_signatures(eth1cl).await?;

    if !network::valid_network(&network_name) {
        return Err(CreateClusterError::UnsupportedNetwork {
            network: network_name.to_string(),
        });
    }

    if !def.consensus_protocol.is_empty()
        && !protocols::is_supported_protocol_name(&def.consensus_protocol)
    {
        return Err(CreateClusterError::UnsupportedConsensusProtocol {
            consensus_protocol: def.consensus_protocol.clone(),
        });
    }

    create_dkg::validate_withdrawal_addrs(&def.withdrawal_addresses(), &network_name)?;

    Ok(())
}

pub fn is_main_or_gnosis(network: &str) -> bool {
    network == network::MAINNET.name || network == network::GNOSIS.name
}

fn validate_create_config(args: &CreateClusterArgs) -> Result<()> {
    if args.nodes == 0 && args.definition_file.is_none() {
        return Err(CreateClusterError::MissingNodesOrDefinitionFile);
    }

    // Check for valid network configuration.
    validate_network_config(args)?;

    detect_node_dirs(&args.cluster_dir, args.nodes)?;

    // Ensure sufficient auth tokens are provided for the keymanager addresses
    if args.keymanager_addrs.len() != args.keymanager_auth_tokens.len() {
        return Err(CreateClusterError::InvalidKeymanagerConfig {
            keymanager_addrs: args.keymanager_addrs.len(),
            keymanager_auth_tokens: args.keymanager_auth_tokens.len(),
        });
    }

    if !args.deposit_amounts.is_empty() {
        let amount = eth2util::deposit::eths_to_gweis(&args.deposit_amounts);

        eth2util::deposit::verify_deposit_amounts(&amount, args.compounding)?;
    }

    for addr in &args.keymanager_addrs {
        let keymanager_url =
            url::Url::parse(addr).map_err(CreateClusterError::InvalidKeymanagerUrl)?;

        if keymanager_url.scheme() == HTTP_SCHEME {
            warn!(addr, "Keymanager URL does not use https protocol");
        }
    }

    if args.split_keys && args.num_validators != 0 {
        return Err(CreateClusterError::CannotSpecifyNumValidatorsWithSplitKeys);
    } else if !args.split_keys && args.num_validators == 0 && args.definition_file.is_none() {
        return Err(CreateClusterError::MissingNumValidatorsOrDefinitionFile);
    }

    // Don't allow cluster size to be less than `MIN_NODES`.
    let num_nodes = args.nodes;
    if num_nodes < MIN_NODES {
        return Err(CreateClusterError::TooFewNodes { num_nodes });
    }

    if let Some(consensus_protocol) = &args.consensus_protocol
        && !protocols::is_supported_protocol_name(consensus_protocol)
    {
        return Err(CreateClusterError::UnsupportedConsensusProtocol {
            consensus_protocol: consensus_protocol.clone(),
        });
    }

    Ok(())
}

fn detect_node_dirs(cluster_dir: impl AsRef<Path>, node_amount: u64) -> Result<()> {
    for i in 0..node_amount {
        let abs_path = std::path::absolute(node_dir(cluster_dir.as_ref(), i))?;

        if std::fs::exists(abs_path.join("cluster-lock.json"))? {
            return Err(CreateClusterError::NodeDirectoryAlreadyExists { node_dir: abs_path });
        }
    }

    Ok(())
}

fn node_dir(cluster_dir: impl AsRef<Path>, node_index: u64) -> PathBuf {
    cluster_dir.as_ref().join(format!("node{}", node_index))
}

/// Validates the network configuration.
fn validate_network_config(args: &CreateClusterArgs) -> Result<()> {
    if let Some(network) = args.network {
        if eth2util::network::valid_network(network.as_str()) {
            return Ok(());
        }

        return Err(InvalidNetworkConfigError::InvalidNetworkSpecified {
            network: network.to_string(),
        }
        .into());
    }

    // Check if custom testnet configuration is provided.
    if !args.testnet_config.is_empty() {
        // Add testnet config to supported networks.
        eth2util::network::add_test_network(args.testnet_config.clone().into())?;

        return Ok(());
    }

    Err(InvalidNetworkConfigError::MissingNetworkFlagAndNoTestnetConfigFlag.into())
}

/// Returns true if the input string is a valid HTTP/HTTPS URI.
fn is_valid_uri(s: impl AsRef<str>) -> bool {
    if let Ok(url) = url::Url::parse(s.as_ref()) {
        (url.scheme() == HTTP_SCHEME || url.scheme() == HTTPS_SCHEME)
            && !url.host_str().unwrap_or("").is_empty()
    } else {
        false
    }
}

/// Loads and validates the cluster definition from disk or an HTTP URL.
///
/// It fetches the definition, verifies signatures and hashes, and checks
/// that at least one validator is specified before returning.
async fn load_definition(
    definition_file: impl AsRef<str>,
    eth1cl: &eth1wrap::EthClient,
) -> Result<Definition> {
    let def_file = definition_file.as_ref();

    // Fetch definition from network if URI is provided
    let def = if is_valid_uri(def_file) {
        let def = helpers::fetch_definition(def_file).await?;

        info!(
            url = def_file,
            definition_hash = to_0x_hex(&def.definition_hash),
            "Cluster definition downloaded from URL"
        );

        def
    } else {
        // Fetch definition from disk
        let buf = tokio::fs::read(def_file).await?;
        let def: Definition = serde_json::from_slice(&buf)?;

        info!(
            path = def_file,
            definition_hash = to_0x_hex(&def.definition_hash),
            "Cluster definition loaded from disk",
        );

        def
    };

    def.verify_signatures(eth1cl).await?;
    def.verify_hashes()?;

    if def.num_validators == 0 {
        return Err(CreateClusterError::NoValidatorsInDefinition);
    }

    Ok(def)
}

/// Returns the safe threshold, logging a warning if a non-standard threshold is
/// provided.
fn safe_threshold(num_nodes: u64, threshold: Option<u64>) -> u64 {
    let safe = pluto_cluster::helpers::threshold(num_nodes);

    match threshold {
        Some(0) | None => safe,
        Some(t) => {
            if t != safe {
                warn!(
                    num_nodes = num_nodes,
                    threshold = t,
                    safe_threshold = safe,
                    "Non standard threshold provided, this will affect cluster safety"
                );
            }
            t
        }
    }
}

/// Builds the list of `DistValidator`s from the DV public keys, precomputed
/// public shares, deposit data and validator registrations.
fn get_validators(
    dv_pubkeys: &[PublicKey],
    dv_priv_shares: &[Vec<PrivateKey>],
    deposit_datas: &[Vec<DepositData>],
    val_regs: Vec<BuilderRegistration>,
) -> Result<Vec<DistValidator>> {
    let mut deposit_datas_map: HashMap<PublicKey, Vec<DepositData>> = HashMap::new();
    for amount_level in deposit_datas {
        for dd in amount_level {
            deposit_datas_map
                .entry(dd.pub_key)
                .or_default()
                .push(dd.clone());
        }
    }

    let mut vals = Vec::with_capacity(dv_pubkeys.len());
    let tbls = BlstImpl;

    for (idx, dv_pubkey) in dv_pubkeys.iter().enumerate() {
        let pub_shares: Vec<Vec<u8>> = dv_priv_shares
            .get(idx)
            .map(|shares| {
                shares
                    .iter()
                    .map(|share| tbls.secret_to_public_key(share))
                    .collect::<std::result::Result<Vec<_>, _>>()
            })
            .transpose()?
            .ok_or(CreateClusterError::DvPrivSharesNotFound { index: idx })?
            .into_iter()
            .map(|share| share.to_vec())
            .collect();

        // Builder registration — same index as the validator.
        let builder_registration = val_regs
            .get(idx)
            .cloned()
            .ok_or(CreateClusterError::ValidatorRegistrationNotFound { index: idx })?;

        // Partial deposit data for this DV pubkey.
        let partial_deposit_data = deposit_datas_map.remove(dv_pubkey).ok_or_else(|| {
            CreateClusterError::DepositDataNotFound {
                dv: hex::encode(dv_pubkey),
            }
        })?;

        vals.push(DistValidator {
            pub_key: dv_pubkey.to_vec(),
            pub_shares,
            partial_deposit_data,
            builder_registration,
        });
    }

    Ok(vals)
}

/// Returns a BLS aggregate signature of the message signed by all the shares.
fn agg_sign(secrets: &[Vec<PrivateKey>], message: &[u8]) -> Result<Vec<u8>> {
    use pluto_crypto::types::Signature;

    let tbls = BlstImpl;
    let mut sigs: Vec<Signature> = Vec::new();

    for shares in secrets {
        for share in shares {
            let sig = tbls.sign(share, message)?;
            sigs.push(sig);
        }
    }

    if sigs.is_empty() {
        return Ok(Vec::new());
    }

    let agg = tbls.aggregate(&sigs)?;
    Ok(agg.to_vec())
}

/// Writes `cluster-lock.json` to every node directory under `cluster_dir`.
/// The file is created with 0o400 (owner read-only) permissions.
async fn write_lock(lock: &Lock, cluster_dir: impl AsRef<Path>, num_nodes: u64) -> Result<()> {
    let json = serde_json::to_string_pretty(lock)?;
    let bytes = json.into_bytes();

    for i in 0..num_nodes {
        let lock_path = node_dir(cluster_dir.as_ref(), i).join("cluster-lock.json");

        tokio::fs::write(&lock_path, &bytes).await?;

        let perms = std::fs::Permissions::from_mode(0o400);
        tokio::fs::set_permissions(&lock_path, perms).await?;
    }

    Ok(())
}

fn write_output(
    w: &mut dyn Write,
    split_keys: bool,
    cluster_dir: impl AsRef<Path>,
    num_nodes: u64,
    keys_to_disk: bool,
    zipped: bool,
) -> std::io::Result<()> {
    let abs_cluster_dir = std::path::absolute(cluster_dir.as_ref())?;
    let abs_str = abs_cluster_dir.display().to_string();
    let abs_str = abs_str.trim_end_matches('/');

    writeln!(w, "Created charon cluster:")?;
    writeln!(w, " --split-existing-keys={}", split_keys)?;
    writeln!(w)?;
    writeln!(w, "{}/", abs_str)?;
    writeln!(
        w,
        "├─ node[0-{}]/\t\t\tDirectory for each node",
        num_nodes.saturating_sub(1)
    )?;
    writeln!(
        w,
        "│  ├─ charon-enr-private-key\tCharon networking private key for node authentication"
    )?;
    writeln!(
        w,
        "│  ├─ cluster-lock.json\t\tCluster lock defines the cluster lock file which is signed by all nodes"
    )?;
    writeln!(
        w,
        "│  ├─ deposit-data-*.json\tDeposit data files are used to activate a Distributed Validator on the DV Launchpad"
    )?;
    if keys_to_disk {
        writeln!(
            w,
            "│  ├─ validator_keys\t\tValidator keystores and password"
        )?;
        writeln!(
            w,
            "│  │  ├─ keystore-*.json\tValidator private share key for duty signing"
        )?;
        writeln!(
            w,
            "│  │  ├─ keystore-*.txt\t\tKeystore password files for keystore-*.json"
        )?;
    }
    if zipped {
        writeln!(w)?;
        writeln!(w, "Files compressed and archived to:")?;
        writeln!(w, "{}/cluster.tar.gz", abs_str)?;
    }

    Ok(())
}

fn write_split_keys_warning(w: &mut dyn Write) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(
        w,
        "***************** WARNING: Splitting keys **********************"
    )?;
    writeln!(
        w,
        " Please make sure any existing validator has been shut down for"
    )?;
    writeln!(
        w,
        " at least 2 finalised epochs before starting the charon cluster,"
    )?;
    writeln!(
        w,
        " otherwise slashing could occur.                               "
    )?;
    writeln!(
        w,
        "****************************************************************"
    )?;
    writeln!(w)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use pluto_cluster::{lock::Lock, version::versions::*};
    use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls as _};
    use pluto_eth1wrap::EthClient;
    use pluto_eth2util::{
        deposit,
        keystore::{self, CONFIRM_INSECURE_KEYS},
    };
    use rand::Rng as _;
    use tempfile::TempDir;

    use crate::commands::constants::ZERO_ADDRESS;

    use super::*;

    const DEF_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cluster/src/examples/cluster-definition-006.json"
    );
    const DEF_PATH_TWO_NODES: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cluster/src/examples/cluster-definition-001.json"
    );
    const DEFAULT_NETWORK: &str = "mainnet";

    const TESTDATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/commands/testdata");

    /// Returns the path for a golden file.
    fn golden_path(test_name: &str, subtest: &str) -> std::path::PathBuf {
        std::path::Path::new(TESTDATA_DIR).join(format!(
            "test_create_cluster_{}_{}.golden",
            test_name, subtest
        ))
    }

    /// Compares `actual` against a golden file.
    ///
    /// Set `UPDATE_GOLDEN=1` in the environment to regenerate golden files.
    fn require_golden_bytes(test_name: &str, subtest: &str, actual: &[u8]) {
        let path = golden_path(test_name, subtest);
        if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
            std::fs::create_dir_all(TESTDATA_DIR).unwrap();
            std::fs::write(&path, actual).unwrap();
            return;
        }
        let expected = std::fs::read(&path).unwrap_or_else(|_| {
            panic!(
                "golden file not found: {}. Run with UPDATE_GOLDEN=1 to create it.",
                path.display()
            )
        });
        assert_eq!(
            String::from_utf8_lossy(actual),
            String::from_utf8_lossy(&expected),
            "golden file mismatch: {}",
            path.display()
        );
    }

    /// Serializes `data` as a JSON array with 1-space indent (matching Go's
    /// `json.MarshalIndent(data, "", " ")`) and compares against a golden file.
    fn require_golden_json(test_name: &str, subtest: &str, data: &[String]) {
        let json = if data.is_empty() {
            "[]".to_string()
        } else {
            let items: Vec<String> = data
                .iter()
                .map(|s| format!(" {}", serde_json::to_string(s).unwrap()))
                .collect();
            format!("[\n{}\n]", items.join(",\n"))
        };
        require_golden_bytes(test_name, subtest, json.as_bytes());
    }

    #[derive(Debug, Clone)]
    struct TestCaseConfig {
        num_nodes: u64,
        threshold: Option<u64>,
        num_dvs: u64,
        network: Option<&'static str>,
        deposit_amounts: Vec<u64>,
        split_keys: bool,
        def_file_path: Option<&'static str>,
        name: Option<&'static str>,
        consensus_protocol: Option<&'static str>,
        target_gas_limit: u64,
        testnet_chain_id: Option<u64>,
        testnet_name: Option<&'static str>,
        testnet_fork_version: Option<&'static str>,
    }

    #[derive(Debug, Clone, Copy)]
    enum PrepKind {
        None,
        SplitKeys { num_keys: usize },
        RandomAddrs,
    }

    #[derive(Debug, Clone, Copy)]
    enum DefProvider {
        None,
        Def006,
        DefTwoNodes,
    }

    async fn test_eth1_client() -> EthClient {
        EthClient::new("http://127.0.0.1:8545").await.unwrap()
    }

    fn random_checksummed_eth_address() -> String {
        let mut bytes = [0u8; 20];
        rand::thread_rng().fill(&mut bytes[..]);
        let hex_addr = format!("0x{}", hex::encode(bytes));
        pluto_eth2util::helpers::checksum_address(&hex_addr).unwrap()
    }

    /// Port of Go's testCreateCluster helper.
    async fn run_test_create_cluster(
        config: TestCaseConfig,
        prep: PrepKind,
        def_provider: DefProvider,
        expected_err: Option<&str>,
    ) {
        let dir = TempDir::new().unwrap();

        // Load reference definition for post-creation checks (used when def_file_path
        // is set). Inject defaults for fields absent from older JSON examples
        // (e.g. `compounding`).
        let ref_def: pluto_cluster::definition::Definition = {
            let bytes = tokio::fs::read(DEF_PATH).await.unwrap();
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            if value.get("compounding").is_none() {
                value["compounding"] = serde_json::json!(false);
            }
            serde_json::from_value(value).unwrap()
        };

        // Start a mock HTTP server when the test case needs to serve a definition over
        // network.
        let mock_server = match def_provider {
            DefProvider::None => None,
            path @ DefProvider::Def006 | path @ DefProvider::DefTwoNodes => {
                let server = wiremock::MockServer::start().await;
                let json = if matches!(path, DefProvider::Def006) {
                    tokio::fs::read(DEF_PATH).await.unwrap()
                } else {
                    tokio::fs::read(DEF_PATH_TWO_NODES).await.unwrap()
                };
                wiremock::Mock::given(wiremock::matchers::any())
                    .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(json))
                    .mount(&server)
                    .await;
                Some(server)
            }
        };

        // Apply defaults matching the Go test loop.
        let def_url = mock_server.as_ref().map(|s| s.uri());
        let definition_file = if let Some(url) = &def_url {
            Some(url.clone())
        } else {
            config.def_file_path.map(String::from)
        };

        let mut fee_addrs = vec![ZERO_ADDRESS.to_string()];
        let mut withdrawal_addrs = vec![ZERO_ADDRESS.to_string()];

        let target_gas_limit = if config.target_gas_limit != 0 {
            config.target_gas_limit
        } else if def_url.is_none() {
            30_000_000
        } else {
            0
        };

        // Split keys temp dir kept alive for the full duration of the test.
        let split_keys_temp = TempDir::new().unwrap();
        let mut split_keys_dir: Option<std::path::PathBuf> = None;

        match prep {
            PrepKind::None => {}
            PrepKind::SplitKeys { num_keys } => {
                let tbls = BlstImpl;
                let mut keys = Vec::new();
                for _ in 0..num_keys {
                    keys.push(tbls.generate_secret_key(rand::thread_rng()).unwrap());
                }
                keystore::store_keys_insecure(
                    &keys,
                    split_keys_temp.path(),
                    &CONFIRM_INSECURE_KEYS,
                )
                .await
                .unwrap();
                split_keys_dir = Some(split_keys_temp.path().to_path_buf());
            }
            PrepKind::RandomAddrs => {
                fee_addrs = vec![random_checksummed_eth_address()];
                withdrawal_addrs = vec![random_checksummed_eth_address()];
            }
        }

        let testnet_config = TestnetConfig {
            chain_id: config.testnet_chain_id,
            fork_version: config.testnet_fork_version.map(String::from),
            genesis_timestamp: config.testnet_chain_id.map(|_| {
                u64::try_from(chrono::Utc::now().timestamp()).expect("timestamp fits u64")
            }),
            testnet_name: config.testnet_name.map(String::from),
        };

        let network = config.network.and_then(|n| Network::try_from(n).ok());
        let execution_engine_addr = definition_file
            .as_ref()
            .map(|_| "http://127.0.0.1:8545".to_string());

        let args = CreateClusterArgs {
            cluster_dir: dir.path().to_path_buf(),
            compounding: false,
            consensus_protocol: config.consensus_protocol.map(String::from),
            definition_file,
            deposit_amounts: config.deposit_amounts.clone(),
            execution_engine_addr,
            fee_recipient_addrs: fee_addrs,
            insecure_keys: true,
            keymanager_addrs: vec![],
            keymanager_auth_tokens: vec![],
            name: config.name.map(String::from),
            network,
            nodes: config.num_nodes,
            num_validators: config.num_dvs,
            publish: false,
            publish_address: "https://api.obol.tech/v1".to_string(),
            split_keys: config.split_keys,
            split_keys_dir,
            target_gas_limit,
            testnet_config,
            threshold: config.threshold,
            withdrawal_addrs,
            zipped: false,
        };

        let mut output = Vec::new();
        let result = run(&mut output, args).await;

        if let Some(expected) = expected_err {
            let err = result.unwrap_err();
            let err_str = format!("{err}");
            assert!(
                err_str.contains(expected),
                "expected error containing '{expected}', got: {err_str}"
            );
            return;
        }

        result.unwrap();

        // Validate lock (port of Go's t.Run("valid lock", ...)).
        let eth1 = test_eth1_client().await;
        let lock_bytes = tokio::fs::read(dir.path().join("node0/cluster-lock.json"))
            .await
            .unwrap();
        let lock: Lock = serde_json::from_slice(&lock_bytes).unwrap();

        lock.verify_hashes().unwrap();
        lock.verify_signatures(&eth1).await.unwrap();

        // Check validators have unique public keys.
        let pub_keys: HashSet<Vec<u8>> = lock
            .distributed_validators
            .iter()
            .map(|v| v.pub_key.clone())
            .collect();
        assert_eq!(
            pub_keys.len(),
            usize::try_from(lock.definition.num_validators).unwrap()
        );

        // Check partial deposit data amounts match expected.
        let mut amounts = deposit::dedup_amounts(&deposit::eths_to_gweis(&config.deposit_amounts));
        if amounts.is_empty() {
            amounts = deposit::default_deposit_amounts(false);
        }
        for val in &lock.distributed_validators {
            assert_eq!(val.partial_deposit_data.len(), amounts.len());
            for (pdd, &expected_amount) in val.partial_deposit_data.iter().zip(amounts.iter()) {
                assert_eq!(pdd.amount, expected_amount);
            }
        }

        // If a definition file was loaded from disk, config hash and creator must be
        // preserved, and operators must have their ENRs populated.
        if config.def_file_path.is_some() {
            assert_eq!(lock.definition.config_hash, ref_def.config_hash);
            assert_eq!(lock.definition.creator, ref_def.creator);
            for op in &lock.operators {
                assert!(!op.enr.is_empty());
            }
        }

        const PREV_VERSIONS: &[&str] = &[V1_0, V1_1, V1_2, V1_3, V1_4, V1_5];

        // Builder registrations must be populated (v1.7+, always true for v1.10).
        for val in &lock.distributed_validators {
            if PREV_VERSIONS.contains(&lock.definition.version.as_str()) {
                continue;
            }

            if matches!(lock.definition.version.as_str(), V1_6 | V1_7) {
                assert_eq!(val.partial_deposit_data.len(), 1);
            }

            if lock.definition.version.as_str() == V1_7 {
                assert!(!val.builder_registration.signature.is_empty());
            }

            if config.split_keys {
                // For SplitKeys mode the timestamp must be close to now, not a genesis time.
                let reg_ts = val.builder_registration.message.timestamp;
                let diff = chrono::Utc::now().signed_duration_since(reg_ts);
                assert!(
                    diff.num_minutes().abs() < 5,
                    "builder registration timestamp likely a genesis time"
                );
            }
        }

        // Node signatures must be populated (v1.7+).
        if lock.version.as_str() == V1_7 {
            assert!(!lock.node_signatures.is_empty());
            for sig in &lock.node_signatures {
                assert!(!sig.is_empty());
            }
        }

        // --- Golden tests ---

        // Extract the leaf test-case name from the thread name
        // (e.g. "...::tests::simnet" -> "simnet").
        let test_name = std::thread::current()
            .name()
            .unwrap_or("")
            .rsplit("::")
            .next()
            .unwrap_or("unknown")
            .to_string();

        // Output golden: replace the temp cluster-dir path with "pluto" to
        // produce a deterministic, portable snapshot.
        let abs_dir = std::path::absolute(dir.path()).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        let output_replaced = output_str.replace(abs_dir.to_string_lossy().as_ref(), "pluto");
        require_golden_bytes(&test_name, "output", output_replaced.as_bytes());

        // Files golden: list cluster-dir contents two levels deep (sorted),
        // L1 entries first then L2 entries — mirrors Go's
        // `filepath.Glob(dir+"/*")` + `filepath.Glob(dir+"/*/*")`.
        let mut l1: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        l1.sort_by_key(|e| e.file_name());

        let mut files: Vec<String> = l1
            .iter()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();

        for entry1 in &l1 {
            let mut l2: Vec<_> = std::fs::read_dir(entry1.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .collect();
            l2.sort_by_key(|e| e.file_name());
            for entry2 in &l2 {
                files.push(format!(
                    "{}/{}",
                    entry1.file_name().to_string_lossy(),
                    entry2.file_name().to_string_lossy()
                ));
            }
        }

        require_golden_json(&test_name, "files", &files);
    }

    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 4, threshold: Some(3), num_dvs: 1,
            network: Some("goerli"), deposit_amounts: vec![],
            split_keys: false, def_file_path: None, name: None,
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::None, DefProvider::None, None
        ; "simnet"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 4, threshold: Some(3), num_dvs: 1,
            network: Some("goerli"), deposit_amounts: vec![31, 1],
            split_keys: false, def_file_path: None, name: None,
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::None, DefProvider::None, None
        ; "two partial deposits"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 4, threshold: Some(3), num_dvs: 1,
            network: Some("goerli"), deposit_amounts: vec![8, 8, 8, 8],
            split_keys: false, def_file_path: None, name: None,
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::None, DefProvider::None, None
        ; "four partial deposits"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 4, threshold: Some(3), num_dvs: 0,
            network: Some("goerli"), deposit_amounts: vec![],
            split_keys: true, def_file_path: None, name: None,
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::SplitKeys { num_keys: 2 }, DefProvider::None, None
        ; "splitkeys"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 0, threshold: None, num_dvs: 0,
            network: Some(DEFAULT_NETWORK), deposit_amounts: vec![],
            split_keys: true, def_file_path: Some(DEF_PATH), name: None,
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::SplitKeys { num_keys: 2 }, DefProvider::None, None
        ; "splitkeys with cluster definition"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 0, threshold: None, num_dvs: 0,
            network: Some(DEFAULT_NETWORK), deposit_amounts: vec![],
            split_keys: true, def_file_path: Some(DEF_PATH), name: None,
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::SplitKeys { num_keys: 1 }, DefProvider::None,
        Some("Amount of keys read from disk")
        ; "splitkeys with cluster definition but amount of keys read from disk differ"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 0, threshold: None, num_dvs: 0,
            network: Some(DEFAULT_NETWORK), deposit_amounts: vec![],
            split_keys: false, def_file_path: None, name: None,
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::None, DefProvider::None, Some("Missing --nodes")
        ; "missing nodes amount flag"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 4, threshold: None, num_dvs: 0,
            network: None, deposit_amounts: vec![],
            split_keys: false, def_file_path: None, name: None,
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::None, DefProvider::None, Some("Missing --network flag")
        ; "missing network flag"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 4, threshold: Some(3), num_dvs: 0,
            network: Some(DEFAULT_NETWORK), deposit_amounts: vec![],
            split_keys: false, def_file_path: None, name: None,
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::None, DefProvider::None, Some("Missing --num-validators")
        ; "missing numdvs with no split keys set"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 4, threshold: Some(3), num_dvs: 1,
            network: Some(DEFAULT_NETWORK), deposit_amounts: vec![],
            split_keys: true, def_file_path: None, name: None,
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::None, DefProvider::None, Some("--split-existing-keys")
        ; "splitkeys with numdvs set"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: MIN_NODES, threshold: Some(3), num_dvs: 2,
            network: Some("goerli"), deposit_amounts: vec![],
            split_keys: false, def_file_path: None, name: None,
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::None, DefProvider::None, None
        ; "goerli"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 0, threshold: None, num_dvs: 0,
            network: Some("goerli"), deposit_amounts: vec![],
            split_keys: false, def_file_path: Some(DEF_PATH), name: None,
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::None, DefProvider::None, None
        ; "solo flow definition from disk"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 0, threshold: None, num_dvs: 0,
            network: Some("goerli"), deposit_amounts: vec![],
            split_keys: false, def_file_path: None, name: None,
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::None, DefProvider::Def006, None
        ; "solo flow definition from network"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 3, threshold: Some(3), num_dvs: 5,
            network: Some("goerli"), deposit_amounts: vec![],
            split_keys: false, def_file_path: None, name: Some("test_cluster"),
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::RandomAddrs, DefProvider::None, None
        ; "with fee recipient and withdrawal addresses"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 4, threshold: Some(3), num_dvs: 3,
            network: None, deposit_amounts: vec![],
            split_keys: false, def_file_path: None, name: Some("testnet"),
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: Some(243),
            testnet_name: Some("obolnetwork"),
            testnet_fork_version: Some("0x00000101"),
        },
        PrepKind::None, DefProvider::None, None
        ; "custom testnet flags"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 4, threshold: Some(3), num_dvs: 3,
            network: Some(DEFAULT_NETWORK), deposit_amounts: vec![],
            split_keys: false, def_file_path: None, name: Some("test_cluster"),
            consensus_protocol: Some("unreal"), target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::None, DefProvider::None, Some("Unsupported consensus protocol")
        ; "preferred consensus protocol"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 2, threshold: Some(2), num_dvs: 1,
            network: Some("goerli"), deposit_amounts: vec![],
            split_keys: false, def_file_path: None, name: Some("test_cluster"),
            consensus_protocol: None, target_gas_limit: 0,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::None, DefProvider::DefTwoNodes, Some("Too few nodes")
        ; "with number of nodes below minimum"
    )]
    #[test_case::test_case(
        TestCaseConfig {
            num_nodes: 4, threshold: Some(3), num_dvs: 3,
            network: Some("holesky"), deposit_amounts: vec![],
            split_keys: false, def_file_path: None, name: Some("test_cluster"),
            consensus_protocol: None, target_gas_limit: 36_000_000,
            testnet_chain_id: None, testnet_name: None, testnet_fork_version: None,
        },
        PrepKind::None, DefProvider::None, None
        ; "custom target gas limit"
    )]
    #[tokio::test]
    async fn create_cluster(
        config: TestCaseConfig,
        prep: PrepKind,
        def_provider: DefProvider,
        expected_err: Option<&'static str>,
    ) {
        run_test_create_cluster(config, prep, def_provider, expected_err).await;
    }

    const DEF_PATH_004: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cluster/src/examples/cluster-definition-004.json"
    );

    /// Port of Go's TestSplitKeys.
    ///
    /// Verifies that `run` correctly handles split-keys mode both when a
    /// cluster definition is loaded from disk and when it is built from
    /// inline config. For each case the test generates BLS private keys,
    /// stores them insecurely, runs cluster creation, then checks the
    /// produced lock for hash/signature validity and that the number of
    /// distributed validators equals the number of keys that were split.
    #[test_case::test_case(
        2, Some(DEF_PATH_004), 4, None, None
        ; "split keys from local definition"
    )]
    #[test_case::test_case(
        3, None, MIN_NODES, Some(3), Some("test split keys")
        ; "split keys from config with one num-validators"
    )]
    #[tokio::test]
    async fn split_keys(
        num_split_keys: usize,
        def_file_path: Option<&'static str>,
        num_nodes: u64,
        threshold: Option<u64>,
        cluster_name: Option<&'static str>,
    ) {
        let dir = TempDir::new().unwrap();
        let split_keys_temp = TempDir::new().unwrap();

        // Generate and store split keys insecurely.
        let tbls_impl = BlstImpl;
        let mut keys = Vec::new();
        for _ in 0..num_split_keys {
            keys.push(tbls_impl.generate_secret_key(rand::thread_rng()).unwrap());
        }
        keystore::store_keys_insecure(&keys, split_keys_temp.path(), &CONFIRM_INSECURE_KEYS)
            .await
            .unwrap();

        let execution_engine_addr = def_file_path.map(|_| "http://127.0.0.1:8545".to_string());

        let args = CreateClusterArgs {
            cluster_dir: dir.path().to_path_buf(),
            compounding: false,
            consensus_protocol: None,
            definition_file: def_file_path.map(String::from),
            deposit_amounts: vec![],
            execution_engine_addr,
            fee_recipient_addrs: vec![ZERO_ADDRESS.to_string()],
            insecure_keys: true,
            keymanager_addrs: vec![],
            keymanager_auth_tokens: vec![],
            name: cluster_name.map(String::from),
            network: Some(Network::Goerli),
            nodes: num_nodes,
            num_validators: 0,
            publish: false,
            publish_address: "https://api.obol.tech/v1".to_string(),
            split_keys: true,
            split_keys_dir: Some(split_keys_temp.path().to_path_buf()),
            target_gas_limit: 30_000_000,
            testnet_config: TestnetConfig::default(),
            threshold,
            withdrawal_addrs: vec![ZERO_ADDRESS.to_string()],
            zipped: false,
        };

        let mut output = Vec::new();
        run(&mut output, args).await.unwrap();

        // Since `cluster-lock.json` is copied into each node directory, use node0.
        let lock_bytes = tokio::fs::read(dir.path().join("node0/cluster-lock.json"))
            .await
            .unwrap();
        let lock: Lock = serde_json::from_slice(&lock_bytes).unwrap();

        lock.verify_hashes().unwrap();

        let eth1 = test_eth1_client().await;
        lock.verify_signatures(&eth1).await.unwrap();

        assert_eq!(
            usize::try_from(lock.definition.num_validators).unwrap(),
            num_split_keys,
        );
    }

    const DEF_PATH_002: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cluster/src/examples/cluster-definition-002.json"
    );

    #[tokio::test]
    async fn validate_definition() {
        let num_dvs = 4u64;
        let fee_recipient_addrs: Vec<String> = (0..num_dvs)
            .map(|_| random_checksummed_eth_address())
            .collect();
        let withdrawal_addrs: Vec<String> =
            vec![ZERO_ADDRESS.to_string(); usize::try_from(num_dvs).unwrap()];

        let args = CreateClusterArgs {
            cluster_dir: std::path::PathBuf::from("./"),
            compounding: false,
            consensus_protocol: None,
            definition_file: None,
            deposit_amounts: vec![],
            execution_engine_addr: None,
            fee_recipient_addrs,
            insecure_keys: false,
            keymanager_addrs: vec![],
            keymanager_auth_tokens: vec![],
            name: Some("test".to_string()),
            network: Some(Network::Goerli),
            nodes: 4,
            num_validators: num_dvs,
            publish: false,
            publish_address: "https://api.obol.tech/v1".to_string(),
            split_keys: false,
            split_keys_dir: None,
            target_gas_limit: 30_000_000,
            testnet_config: TestnetConfig::default(),
            threshold: Some(3),
            withdrawal_addrs,
            zipped: false,
        };

        let definition = super::new_def_from_config(&args).unwrap();

        let remote_def: pluto_cluster::definition::Definition = {
            let bytes = tokio::fs::read(DEF_PATH_002).await.unwrap();
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            if value.get("compounding").is_none() {
                value["compounding"] = serde_json::json!(false);
            }
            serde_json::from_value(value).unwrap()
        };

        let eth1 = test_eth1_client().await;
        let keymanager_addrs: Vec<String> = vec![];

        // "zero address": gnosis fork version with zero withdrawal addrs -> error
        {
            let mut def = definition.clone();
            def.fork_version = vec![0x00, 0x00, 0x00, 0x64]; // gnosis
            assert!(
                super::validate_definition(&def, false, &keymanager_addrs, &eth1)
                    .await
                    .is_err()
            );
        }

        // "fork versions": goerli -> ok; mainnet with zero withdrawal addrs -> error
        {
            let def = definition.clone();
            super::validate_definition(&def, false, &keymanager_addrs, &eth1)
                .await
                .unwrap();

            let mut def = definition.clone();
            def.fork_version = vec![0x00, 0x00, 0x00, 0x00]; // mainnet
            assert!(
                super::validate_definition(&def, false, &keymanager_addrs, &eth1)
                    .await
                    .is_err()
            );
        }

        // "insufficient keymanager addresses": 1 addr for 4-operator cluster -> error
        {
            let def = definition.clone();
            let km_addrs = vec!["127.0.0.1:1234".to_string()];
            assert!(
                super::validate_definition(&def, true, &km_addrs, &eth1)
                    .await
                    .is_err()
            );
        }

        // "insecure keys": insecure_keys=true, goerli -> ok
        {
            let def = definition.clone();
            super::validate_definition(&def, true, &keymanager_addrs, &eth1)
                .await
                .unwrap();
        }

        // "insufficient number of nodes": no operators -> "Too few nodes"
        {
            let mut def = definition.clone();
            def.operators = vec![];
            let err = super::validate_definition(&def, false, &keymanager_addrs, &eth1)
                .await
                .unwrap_err();
            let err_str = format!("{err}");
            assert!(
                err_str.contains("Too few nodes"),
                "expected 'Too few nodes', got: {err_str}"
            );
        }

        // "name not provided": empty name -> "Name not provided"
        {
            let mut def = definition.clone();
            def.name = String::new();
            let err = super::validate_definition(&def, false, &keymanager_addrs, &eth1)
                .await
                .unwrap_err();
            let err_str = format!("{err}");
            assert!(
                err_str.contains("Name not provided"),
                "expected 'Name not provided', got: {err_str}"
            );
        }

        // "zero validators provided": num_validators=0 -> "zero validators"
        {
            let mut def = definition.clone();
            def.num_validators = 0;
            let err = super::validate_definition(&def, false, &keymanager_addrs, &eth1)
                .await
                .unwrap_err();
            let err_str = format!("{err}");
            assert!(
                err_str.contains("zero validators"),
                "expected 'zero validators', got: {err_str}"
            );
        }

        // "invalid hash": remote def with modified num_validators -> "Invalid config
        // hash"
        {
            let mut def = remote_def.clone();
            def.num_validators = 3;
            let err = super::validate_definition(&def, false, &keymanager_addrs, &eth1)
                .await
                .unwrap_err();
            let err_str = format!("{err}");
            assert!(
                err_str.contains("Invalid config hash"),
                "expected 'Invalid config hash', got: {err_str}"
            );
        }

        // "invalid config signatures": remote def with modified num_validators + rehash
        // -> "invalid creator config signature"
        {
            let mut def = remote_def.clone();
            def.num_validators = 3;
            def.set_definition_hashes().unwrap();
            let err = super::validate_definition(&def, false, &keymanager_addrs, &eth1)
                .await
                .unwrap_err();
            let err_str = format!("{err}");
            assert!(
                err_str.contains("invalid creator config signature"),
                "expected 'invalid creator config signature', got: {err_str}"
            );
        }

        // "unsupported consensus protocol": unrecognised protocol -> error
        {
            let mut def = definition.clone();
            def.consensus_protocol = "unreal".to_string();
            assert!(
                super::validate_definition(&def, false, &keymanager_addrs, &eth1)
                    .await
                    .is_err()
            );
        }
    }

    /// Port of Go's TestMultipleAddresses.
    #[tokio::test]
    async fn multiple_addresses() {
        // "insufficient fee recipient addresses": 0 addrs for 4 validators → error
        {
            let err = super::validate_addresses(4, &[], &[]).unwrap_err();
            let err_str = format!("{err}");
            assert!(
                err_str.contains("mismatching --num-validators and --fee-recipient-addresses"),
                "expected fee-recipient error, got: {err_str}"
            );
        }

        // "insufficient withdrawal addresses": 0 withdrawal addrs for 1 validator →
        // error
        {
            let fee_addr = "0x0000000000000000000000000000000000000000".to_string();
            let err = super::validate_addresses(1, &[fee_addr], &[]).unwrap_err();
            let err_str = format!("{err}");
            assert!(
                err_str.contains("mismatching --num-validators and --withdrawal-addresses"),
                "expected withdrawal error, got: {err_str}"
            );
        }

        // "insufficient addresses from remote URL": deserializing a definition
        // with num_validators=2 but empty validators list must fail with the
        // Go-compatible error message.  Testing at the JSON-parse level mirrors
        // what Go's runCreateCluster triggers when it calls unmarshalDefinitionV1x10.
        {
            let def_json = tokio::fs::read(DEF_PATH).await.unwrap();
            let mut def_value: serde_json::Value = serde_json::from_slice(&def_json).unwrap();
            // Clear the validators list while keeping num_validators=2 to create a
            // mismatch that mirrors the Go test (d.ValidatorAddresses = []).
            def_value["validators"] = serde_json::json!([]);
            let modified_json = serde_json::to_vec(&def_value).unwrap();

            let err =
                serde_json::from_slice::<pluto_cluster::definition::Definition>(&modified_json)
                    .unwrap_err();
            let err_str = format!("{err}");
            assert!(
                err_str.contains("num_validators not matching validators length"),
                "expected validator length error, got: {err_str}"
            );
        }
    }

    const DEF_PATH_005: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cluster/src/examples/cluster-definition-005.json"
    );

    #[test_case::test_case(
        Some(DEF_PATH_005), 0, 0, None
        ; "target gas limit from unsupported version"
    )]
    #[test_case::test_case(
        Some(DEF_PATH), 0, 30_000_000, None
        ; "target gas limit from supported version"
    )]
    #[test_case::test_case(
        None, 36_000_000, 36_000_000, None
        ; "target gas limit with default version"
    )]
    #[test_case::test_case(
        None, 0, 0, Some("target gas limit should be set")
        ; "no target gas limit with default version"
    )]
    #[tokio::test]
    async fn test_target_gas_limit(
        def_file_path: Option<&'static str>,
        target_gas_limit: u64,
        expected_gas_limit: u64,
        expected_err: Option<&'static str>,
    ) {
        let dir = TempDir::new().unwrap();

        let execution_engine_addr = def_file_path.map(|_| "http://127.0.0.1:8545".to_string());

        let args = CreateClusterArgs {
            cluster_dir: dir.path().to_path_buf(),
            compounding: false,
            consensus_protocol: None,
            definition_file: def_file_path.map(String::from),
            deposit_amounts: vec![],
            execution_engine_addr,
            fee_recipient_addrs: vec![ZERO_ADDRESS.to_string()],
            insecure_keys: true,
            keymanager_addrs: vec![],
            keymanager_auth_tokens: vec![],
            name: Some("test target gas limit".to_string()),
            network: Some(Network::Mainnet),
            nodes: 4,
            num_validators: 1,
            publish: false,
            publish_address: "https://api.obol.tech/v1".to_string(),
            split_keys: false,
            split_keys_dir: None,
            target_gas_limit,
            testnet_config: TestnetConfig::default(),
            threshold: Some(3),
            withdrawal_addrs: vec![ZERO_ADDRESS.to_string()],
            zipped: false,
        };

        let mut output = Vec::new();
        let result = run(&mut output, args).await;

        if let Some(expected) = expected_err {
            let err = result.unwrap_err();
            let err_str = format!("{err}");
            assert!(
                err_str.contains(expected),
                "expected error containing '{expected}', got: {err_str}"
            );
            return;
        }

        result.unwrap();

        let lock_bytes = tokio::fs::read(dir.path().join("node0/cluster-lock.json"))
            .await
            .unwrap();
        let lock: Lock = serde_json::from_slice(&lock_bytes).unwrap();

        lock.verify_hashes().unwrap();

        let eth1 = test_eth1_client().await;
        lock.verify_signatures(&eth1).await.unwrap();

        assert_eq!(lock.target_gas_limit, expected_gas_limit);
    }

    #[tokio::test]
    async fn keymanager() {
        #[derive(serde::Deserialize)]
        struct MockKeymanagerReq {
            keystores: Vec<String>,
            passwords: Vec<String>,
        }

        const TEST_AUTH_TOKEN: &str = "api-token-test";

        let tbls_impl = BlstImpl;

        let original_secret = tbls_impl.generate_secret_key(rand::thread_rng()).unwrap();
        let key_dir = TempDir::new().unwrap();
        keystore::store_keys_insecure(
            std::slice::from_ref(&original_secret),
            key_dir.path(),
            &CONFIRM_INSECURE_KEYS,
        )
        .await
        .unwrap();

        let auth_tokens: Vec<String> =
            vec![TEST_AUTH_TOKEN.to_string(); usize::try_from(MIN_NODES).unwrap()];

        // --- all successful ---
        {
            let mut servers = Vec::new();
            let mut addrs = Vec::new();
            for _ in 0..MIN_NODES {
                let server = wiremock::MockServer::start().await;
                addrs.push(server.uri());
                servers.push(server);
            }
            for server in &servers {
                wiremock::Mock::given(wiremock::matchers::method("POST"))
                    .and(wiremock::matchers::path("/eth/v1/keystores"))
                    .respond_with(wiremock::ResponseTemplate::new(200))
                    .mount(server)
                    .await;
            }

            let cluster_dir = TempDir::new().unwrap();
            let mut output = Vec::new();
            run(
                &mut output,
                CreateClusterArgs {
                    cluster_dir: cluster_dir.path().to_path_buf(),
                    compounding: false,
                    consensus_protocol: None,
                    definition_file: None,
                    deposit_amounts: vec![],
                    execution_engine_addr: None,
                    fee_recipient_addrs: vec![ZERO_ADDRESS.to_string()],
                    insecure_keys: true,
                    keymanager_addrs: addrs,
                    keymanager_auth_tokens: auth_tokens.clone(),
                    name: Some("TestKeymanager".to_string()),
                    network: Some(Network::Goerli),
                    nodes: MIN_NODES,
                    num_validators: 0,
                    publish: false,
                    publish_address: "https://api.obol.tech/v1".to_string(),
                    split_keys: true,
                    split_keys_dir: Some(key_dir.path().to_path_buf()),
                    target_gas_limit: 30_000_000,
                    testnet_config: TestnetConfig::default(),
                    threshold: Some(MIN_THRESHOLD),
                    withdrawal_addrs: vec![ZERO_ADDRESS.to_string()],
                    zipped: false,
                },
            )
            .await
            .unwrap();

            let mut shares = std::collections::HashMap::new();
            for (i, server) in servers.iter().enumerate() {
                let requests = server.received_requests().await.unwrap();
                assert_eq!(
                    requests.len(),
                    1,
                    "server {i} should have received exactly 1 request"
                );

                let req: MockKeymanagerReq = serde_json::from_slice(&requests[0].body).unwrap();
                assert_eq!(req.keystores.len(), 1, "only 1 key was split");
                assert_eq!(req.passwords.len(), 1);

                let ks: keystore::Keystore = serde_json::from_str(&req.keystores[0]).unwrap();
                let secret = keystore::decrypt(&ks, &req.passwords[0]).unwrap();
                shares.insert(u8::try_from(i + 1).unwrap(), secret);
            }

            let recovered = tbls_impl.recover_secret(&shares).unwrap();
            assert_eq!(recovered, original_secret);
        }

        // --- some unsuccessful ---
        {
            let mut addrs = vec!["http://127.0.0.1:1".to_string()];
            let mut servers = Vec::new();
            for _ in 1..MIN_NODES {
                let server = wiremock::MockServer::start().await;
                addrs.push(server.uri());
                servers.push(server);
            }
            for server in &servers {
                wiremock::Mock::given(wiremock::matchers::method("POST"))
                    .and(wiremock::matchers::path("/eth/v1/keystores"))
                    .respond_with(wiremock::ResponseTemplate::new(200))
                    .mount(server)
                    .await;
            }

            let cluster_dir = TempDir::new().unwrap();
            let mut output = Vec::new();
            let err = run(
                &mut output,
                CreateClusterArgs {
                    cluster_dir: cluster_dir.path().to_path_buf(),
                    compounding: false,
                    consensus_protocol: None,
                    definition_file: None,
                    deposit_amounts: vec![],
                    execution_engine_addr: None,
                    fee_recipient_addrs: vec![ZERO_ADDRESS.to_string()],
                    insecure_keys: true,
                    keymanager_addrs: addrs,
                    keymanager_auth_tokens: auth_tokens.clone(),
                    name: Some("TestKeymanager".to_string()),
                    network: Some(Network::Goerli),
                    nodes: MIN_NODES,
                    num_validators: 0,
                    publish: false,
                    publish_address: "https://api.obol.tech/v1".to_string(),
                    split_keys: true,
                    split_keys_dir: Some(key_dir.path().to_path_buf()),
                    target_gas_limit: 30_000_000,
                    testnet_config: TestnetConfig::default(),
                    threshold: Some(MIN_THRESHOLD),
                    withdrawal_addrs: vec![ZERO_ADDRESS.to_string()],
                    zipped: false,
                },
            )
            .await
            .unwrap_err();

            let err_str = format!("{err}");
            assert!(
                err_str.contains("cannot ping address"),
                "expected 'cannot ping address' in error, got: {err_str}"
            );
        }

        // --- lengths don't match ---
        {
            let mut addrs = Vec::new();
            let mut servers = Vec::new();
            for _ in 0..MIN_NODES {
                let server = wiremock::MockServer::start().await;
                addrs.push(server.uri());
                servers.push(server);
            }

            let short_tokens = auth_tokens[1..].to_vec();

            let cluster_dir = TempDir::new().unwrap();
            let mut output = Vec::new();
            let err = run(
                &mut output,
                CreateClusterArgs {
                    cluster_dir: cluster_dir.path().to_path_buf(),
                    compounding: false,
                    consensus_protocol: None,
                    definition_file: None,
                    deposit_amounts: vec![],
                    execution_engine_addr: None,
                    fee_recipient_addrs: vec![ZERO_ADDRESS.to_string()],
                    insecure_keys: true,
                    keymanager_addrs: addrs,
                    keymanager_auth_tokens: short_tokens,
                    name: Some("TestKeymanager".to_string()),
                    network: Some(Network::Goerli),
                    nodes: MIN_NODES,
                    num_validators: 0,
                    publish: false,
                    publish_address: "https://api.obol.tech/v1".to_string(),
                    split_keys: true,
                    split_keys_dir: Some(key_dir.path().to_path_buf()),
                    target_gas_limit: 30_000_000,
                    testnet_config: TestnetConfig::default(),
                    threshold: Some(MIN_THRESHOLD),
                    withdrawal_addrs: vec![ZERO_ADDRESS.to_string()],
                    zipped: false,
                },
            )
            .await
            .unwrap_err();

            let err_str = format!("{err}");
            assert!(
                err_str.contains("--keymanager-addresses")
                    && err_str.contains("do not match --keymanager-auth-tokens"),
                "expected mismatch error, got: {err_str}"
            );
        }
    }

    #[tokio::test]
    async fn publish() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/lock"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let cluster_dir = TempDir::new().unwrap();
        let mut output = Vec::new();
        run(
            &mut output,
            CreateClusterArgs {
                cluster_dir: cluster_dir.path().to_path_buf(),
                compounding: false,
                consensus_protocol: None,
                definition_file: None,
                deposit_amounts: vec![],
                execution_engine_addr: None,
                fee_recipient_addrs: vec![ZERO_ADDRESS.to_string()],
                insecure_keys: true,
                keymanager_addrs: vec![],
                keymanager_auth_tokens: vec![],
                name: Some("TestPublish".to_string()),
                network: Some(Network::Goerli),
                nodes: MIN_NODES,
                num_validators: 1,
                publish: true,
                publish_address: server.uri(),
                split_keys: false,
                split_keys_dir: None,
                target_gas_limit: 30_000_000,
                testnet_config: TestnetConfig::default(),
                threshold: Some(MIN_THRESHOLD),
                withdrawal_addrs: vec![ZERO_ADDRESS.to_string()],
                zipped: false,
            },
        )
        .await
        .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "expected exactly 1 publish request");
    }

    const VALID_ETH_ADDR: &str = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";

    #[test_case::test_case(Some(1), 3, Some("Threshold must be greater than") ; "threshold below minimum")]
    #[test_case::test_case(Some(5), 4, Some("Threshold cannot be greater than number of operators") ; "threshold above maximum")]
    #[test_case::test_case(None, 3, None ; "no threshold provided")]
    #[tokio::test]
    async fn test_cluster_cli(
        threshold: Option<u64>,
        nodes: u64,
        expected_err: Option<&'static str>,
    ) {
        let cluster_dir = TempDir::new().unwrap();
        let mut output = Vec::new();
        let result = run(
            &mut output,
            CreateClusterArgs {
                cluster_dir: cluster_dir.path().to_path_buf(),
                compounding: false,
                consensus_protocol: None,
                definition_file: None,
                deposit_amounts: vec![],
                execution_engine_addr: None,
                fee_recipient_addrs: vec![VALID_ETH_ADDR.to_string()],
                insecure_keys: true,
                keymanager_addrs: vec![],
                keymanager_auth_tokens: vec![],
                name: None,
                network: Some(Network::Holesky),
                nodes,
                num_validators: 1,
                publish: false,
                publish_address: "https://api.obol.tech/v1".to_string(),
                split_keys: false,
                split_keys_dir: None,
                target_gas_limit: 30_000_000,
                testnet_config: TestnetConfig::default(),
                threshold,
                withdrawal_addrs: vec![VALID_ETH_ADDR.to_string()],
                zipped: false,
            },
        )
        .await;

        if let Some(expected) = expected_err {
            let err = result.unwrap_err();
            let err_str = format!("{err}");
            assert!(
                err_str.contains(expected),
                "expected error containing '{expected}', got: {err_str}"
            );
        } else {
            result.unwrap();
        }
    }

    fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            if ty.is_dir() {
                copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
            } else {
                std::fs::copy(entry.path(), dst.join(entry.file_name()))?;
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn zipped() {
        let cluster_dir = TempDir::new().unwrap();
        let backup_dir = TempDir::new().unwrap();

        let mut output = Vec::new();
        run(
            &mut output,
            CreateClusterArgs {
                cluster_dir: cluster_dir.path().to_path_buf(),
                compounding: false,
                consensus_protocol: None,
                definition_file: None,
                deposit_amounts: vec![],
                execution_engine_addr: None,
                fee_recipient_addrs: vec![ZERO_ADDRESS.to_string()],
                insecure_keys: true,
                keymanager_addrs: vec![],
                keymanager_auth_tokens: vec![],
                name: Some("test".to_string()),
                network: Some(Network::Goerli),
                nodes: 4,
                num_validators: 4,
                publish: false,
                publish_address: "https://api.obol.tech/v1".to_string(),
                split_keys: false,
                split_keys_dir: None,
                target_gas_limit: 30_000_000,
                testnet_config: TestnetConfig::default(),
                threshold: Some(3),
                withdrawal_addrs: vec![ZERO_ADDRESS.to_string()],
                zipped: false,
            },
        )
        .await
        .unwrap();

        copy_dir_all(cluster_dir.path(), backup_dir.path()).unwrap();

        app_utils::bundle_output(cluster_dir.path(), "cluster.tar.gz").unwrap();

        let unzipped_dir = TempDir::new().unwrap();
        app_utils::extract_archive(
            cluster_dir.path().join("cluster.tar.gz"),
            unzipped_dir.path(),
        )
        .unwrap();

        std::fs::remove_file(cluster_dir.path().join("cluster.tar.gz")).unwrap();

        app_utils::compare_directories(backup_dir.path(), unzipped_dir.path()).unwrap();
    }
}
