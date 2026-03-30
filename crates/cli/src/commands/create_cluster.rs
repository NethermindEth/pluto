//! Create cluster command implementation.
//!
//! This module implements the `pluto create cluster` command, which creates a
//! local distributed validator cluster configuration including validator keys,
//! threshold BLS key shares, p2p private keys, cluster-lock files, and deposit
//! data files.

use std::{
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use k256::SecretKey;
use pluto_cluster::{definition::Definition, helpers::fetch_definition, manifest::cluster, operator::Operator};
use pluto_core::consensus::protocols;
use pluto_crypto::{
    blst_impl::BlstImpl,
    tbls::Tbls,
    types::{PrivateKey, PublicKey},
};
use pluto_eth1wrap as eth1wrap;
use pluto_eth2util::{
    self as eth2util, deposit, enr::Record, keystore::{load_files_recursively, load_files_unordered}, network
};
use pluto_p2p::k1::new_saved_priv_key;
use pluto_ssz::to_0x_hex;
use rand::rngs::OsRng;
use tracing::{debug, info, warn};

use crate::{
    commands::create_dkg::validate_withdrawal_addrs,
    error::{CreateClusterError, InvalidNetworkConfigError, Result as CliResult, ThresholdError},
};

/// Minimum number of nodes required in a cluster.
pub const MIN_NODES: u64 = 3;
/// Minimum threshold value.
pub const MIN_THRESHOLD: u64 = 2;
/// Zero ethereum address (not allowed on mainnet/gnosis).
pub const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
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
        help = "The number of charon nodes in the cluster. Minimum is 3."
    )]
    pub nodes: Option<u64>,

    /// The number of distributed validators needed in the cluster
    #[arg(
        long = "num-validators",
        help = "The number of distributed validators needed in the cluster."
    )]
    pub num_validators: Option<u64>,

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

fn validate_threshold(args: &CreateClusterArgs) -> Result<()> {
    let Some(threshold) = args.threshold else {
        return Ok(());
    };

    if threshold < MIN_THRESHOLD {
        return Err(ThresholdError::ThresholdTooLow { threshold }.into());
    }

    let number_of_nodes = args.nodes.unwrap_or(0);
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
pub async fn run(mut args: CreateClusterArgs) -> CliResult<()> {
    validate_threshold(&args)?;

    validate_create_config(&args)?;

    let mut secrets: Vec<PrivateKey> = Vec::new();

    // If we're splitting keys, read them from `split_keys_dir` and set
    // args.num_validators to the amount of secrets we read.
    // If `split_keys` wasn't set, we wouldn't have reached this part of code
    // because `validate_create_config()` would've already errored.
    if args.split_keys == true {
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
        args.num_validators =
            Some(u64::try_from(secrets.len()).expect("secrets length is too large"));
    }

    // Get a cluster definition, either from a definition file or from the config.
    let definition_file = args.definition_file.clone();
    let (def, mut deposit_amounts) = if let Some(definition_file) = definition_file {
        let Some(addr) = args.execution_engine_addr.clone() else {
            return Err(CreateClusterError::MissingExecutionEngineAddress.into());
        };

        let eth1cl = eth1wrap::EthClient::new(addr).await?;

        let def = load_definition(&definition_file, &eth1cl).await?;

        // Should not happen, if it does - it won't affect the runtime, because the
        // validation will fail.
        args.nodes =
            Some(u64::try_from(def.operators.len()).expect("operators length is too large"));
        args.threshold = Some(def.threshold);

        validate_definition(&def, args.insecure_keys, &args.keymanager_addrs, &eth1cl).await?;

        let network = eth2util::network::fork_version_to_network(&def.fork_version)?;

        args.network = Some(
            Network::try_from(network.as_str())
                .map_err(CreateClusterError::InvalidNetworkConfig)?,
        );

        let deposit_amounts = def.deposit_amounts.clone();

        (def, deposit_amounts)
    } else {
        // Create new definition from cluster config
        let def = new_def_from_config(&args).await?;

        let deposit_amounts = deposit::eths_to_gweis(&args.deposit_amounts);

        (def, deposit_amounts)
    };

    if deposit_amounts.len() == 0 {
        deposit_amounts = deposit::default_deposit_amounts(args.compounding);
    }

    if secrets.len() == 0 {
        // This is the case in which split-keys is undefined and user passed validator
        // amount on CLI
        secrets = generate_keys(def.num_validators)?;
    }

    let num_validators_usize =
        usize::try_from(def.num_validators).map_err(|_| CreateClusterError::ValueExceedsU8 {
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
    let (ops, node_keys) = get_operators(num_nodes, args.cluster_dir)?;

    Ok(())
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

fn get_operators(num_nodes: u64, cluster_dir: impl AsRef<Path>) -> Result<(Vec<Operator>, Vec<SecretKey>)> {
    let mut ops = Vec::new();
    let mut node_keys = Vec::new();

    for i in 0..num_nodes {
        let (record, identity_key) = new_peer(&cluster_dir, i)?;

        ops.push(Operator { enr: record.to_string(), ..Default::default() });
        node_keys.push(identity_key);
    }

    Ok((ops, node_keys))
}

fn new_peer(cluster_dir: impl AsRef<Path>, peer_idx: u64) -> Result<(Record, SecretKey)> {
    let dir = node_dir(cluster_dir.as_ref(), peer_idx);

    let p2p_key = new_saved_priv_key(&dir)?;

    let record = Record::new(&p2p_key, Vec::new())?;

    Ok((record, p2p_key))
}

async fn get_keys(
    split_keys_dir: impl AsRef<Path>,
    use_sequence_keys: bool,
) -> Result<Vec<PrivateKey>> {
    if use_sequence_keys {
        let files = load_files_unordered(&split_keys_dir).await?;
        Ok(files.sequenced_keys()?)
    } else {
        let files = load_files_recursively(&split_keys_dir).await?;
        Ok(files.keys())
    }
}

/// Creates a new cluster definition from the provided configuration.
async fn new_def_from_config(args: &CreateClusterArgs) -> Result<Definition> {
    let num_validators = args
        .num_validators
        .ok_or(CreateClusterError::MissingNumValidatorsOrDefinitionFile)?;

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

    let num_nodes = args
        .nodes
        .ok_or(CreateClusterError::MissingNodesOrDefinitionFile)?;

    let operators = vec![
        pluto_cluster::operator::Operator::default();
        usize::try_from(num_nodes).expect("num_nodes should fit in usize")
    ];
    let threshold = safe_threshold(num_nodes, args.threshold);

    let name = args
        .name
        .clone()
        .unwrap_or(String::new());

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
        args.deposit_amounts.clone(),
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
        let mut secret_set = vec![PrivateKey::default(); shares.len()];
        for i in 1..=shares.len() {
            let i_u64 = u64::try_from(i).expect("shares length should fit in u64 on all platforms");
            let idx =
                u8::try_from(i).map_err(|_| CreateClusterError::ValueExceedsU8 { value: i_u64 })?;
            secret_set[i - 1] = shares[&idx].clone();
        }

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

    validate_withdrawal_addrs(&def.withdrawal_addresses(), &network_name)?;

    Ok(())
}

pub fn is_main_or_gnosis(network: &str) -> bool {
    network == network::MAINNET.name || network == network::GNOSIS.name
}

fn validate_create_config(args: &CreateClusterArgs) -> Result<()> {
    if args.nodes.is_none() && args.definition_file.is_none() {
        return Err(CreateClusterError::MissingNodesOrDefinitionFile);
    }

    // Check for valid network configuration.
    validate_network_config(args)?;

    detect_node_dirs(&args.cluster_dir, args.nodes.unwrap_or(0))?;

    // Ensure sufficient auth tokens are provided for the keymanager addresses
    if args.keymanager_addrs.len() != args.keymanager_auth_tokens.len() {
        return Err(CreateClusterError::InvalidKeymanagerConfig {
            keymanager_addrs: args.keymanager_addrs.len(),
            keymanager_auth_tokens: args.keymanager_auth_tokens.len(),
        });
    }

    if args.deposit_amounts.len() > 0 {
        let amount = eth2util::deposit::eths_to_gweis(&args.deposit_amounts);

        eth2util::deposit::verify_deposit_amounts(&amount, args.compounding)?;
    }

    for addr in &args.keymanager_addrs {
        let keymanager_url =
            url::Url::parse(addr).map_err(CreateClusterError::InvalidKeymanagerUrl)?;

        if keymanager_url.scheme() != HTTP_SCHEME {
            return Err(CreateClusterError::InvalidKeymanagerUrlScheme { addr: addr.clone() });
        }
    }

    if args.split_keys && !args.num_validators.is_none() {
        return Err(CreateClusterError::CannotSpecifyNumValidatorsWithSplitKeys);
    } else if !args.split_keys && args.num_validators.is_none() && args.definition_file.is_none() {
        return Err(CreateClusterError::MissingNumValidatorsOrDefinitionFile);
    }

    // Don't allow cluster size to be less than `MIN_NODES`.
    let num_nodes = args.nodes.unwrap_or(0);
    if num_nodes < MIN_NODES {
        return Err(CreateClusterError::TooFewNodes { num_nodes });
    }

    if let Some(consensus_protocol) = &args.consensus_protocol
        && !protocols::is_supported_protocol_name(&consensus_protocol)
    {
        return Err(CreateClusterError::UnsupportedConsensusProtocol {
            consensus_protocol: consensus_protocol.clone(),
        });
    }

    Ok(())
}

fn detect_node_dirs(cluster_dir: impl AsRef<Path>, node_amount: u64) -> Result<()> {
    for i in 0..node_amount {
        let abs_path = std::path::absolute(node_dir(cluster_dir.as_ref(), i))
            .map_err(CreateClusterError::AbsolutePathError)?;

        if std::fs::exists(abs_path.join("cluster-lock.json"))
            .map_err(CreateClusterError::IoError)?
        {
            return Err(
                CreateClusterError::NodeDirectoryAlreadyExists { node_dir: abs_path }.into(),
            );
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
        let def = fetch_definition(def_file).await?;

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
        return Err(CreateClusterError::NoValidatorsInDefinition.into());
    }

    Ok(def)
}

/// Validates that addresses match the number of validators.
/// If only one address is provided, it fills the slice to match num_validators.
///
/// Returns an error if the number of addresses doesn't match and isn't exactly
/// 1.
fn validate_addresses(
    num_validators: u64,
    fee_recipient_addrs: &[String],
    withdrawal_addrs: &[String],
) -> Result<(Vec<String>, Vec<String>)> {
    let num_validators_usize =
        usize::try_from(num_validators).map_err(|_| CreateClusterError::ValueExceedsU8 {
            value: num_validators,
        })?;

    if fee_recipient_addrs.len() != num_validators_usize && fee_recipient_addrs.len() != 1 {
        return Err(CreateClusterError::MismatchingFeeRecipientAddresses {
            num_validators,
            addresses: fee_recipient_addrs.len(),
        }
        .into());
    }

    if withdrawal_addrs.len() != num_validators_usize && withdrawal_addrs.len() != 1 {
        return Err(CreateClusterError::MismatchingWithdrawalAddresses {
            num_validators,
            addresses: withdrawal_addrs.len(),
        }
        .into());
    }

    let mut fee_addrs = fee_recipient_addrs.to_vec();
    let mut withdraw_addrs = withdrawal_addrs.to_vec();

    // Expand single address to match num_validators
    if fee_addrs.len() == 1 {
        let addr = fee_addrs[0].clone();
        fee_addrs = vec![addr; num_validators_usize];
    }

    if withdraw_addrs.len() == 1 {
        let addr = withdraw_addrs[0].clone();
        withdraw_addrs = vec![addr; num_validators_usize];
    }

    Ok((fee_addrs, withdraw_addrs))
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
