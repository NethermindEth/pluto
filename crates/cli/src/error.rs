//! Error types for the Pluto CLI.

use std::path::PathBuf;

use crate::commands::constants::{MIN_NODES, MIN_THRESHOLD};

/// Result type for CLI operations.
pub type Result<T> = std::result::Result<T, CliError>;

/// Errors that can occur in the Pluto CLI.
#[derive(thiserror::Error, Debug)]
pub enum CliError {
    /// Private key file not found.
    #[error(
        "Private key not found. If this is your first time running this client, create one with `pluto create enr`."
    )]
    PrivateKeyNotFound {
        /// Path where the ENR private key was expected.
        enr_path: PathBuf,
    },

    /// Private key already exists.
    #[error("charon-enr-private-key already exists")]
    PrivateKeyAlreadyExists {
        /// Path where the ENR private key exists.
        enr_path: PathBuf,
    },

    /// Failed to load private key.
    #[error("Failed to load private key: {0}")]
    KeyLoadError(#[from] pluto_p2p::k1::K1Error),

    /// ENR generation failed.
    #[error("ENR generation failed: {0}")]
    EnrError(#[from] pluto_eth2util::enr::RecordError),

    /// Invalid Multiaddr
    #[error("Invalid multiaddr: {0}")]
    InvalidMultiaddr(#[from] libp2p::multiaddr::Error),

    /// IO error occurred.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// K1 utility error.
    #[error("K1 utility error: {0}")]
    K1Util(#[from] pluto_k1util::K1UtilError),

    /// Obol API error.
    #[error("Obol API error: {0}")]
    ObolApi(#[from] pluto_app::obolapi::ObolApiError),

    /// SSZ hasher error.
    #[error("Hasher error: {0}")]
    HasherError(#[from] pluto_ssz::HasherError),

    /// HTTP request error.
    #[error("HTTP request error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// Test timeout or interrupted.
    #[error("timeout/interrupted")]
    TimeoutInterrupted,

    /// Test case not supported.
    #[error("test case not supported")]
    TestCaseNotSupported,

    /// Relay P2P error.
    #[error("Relay P2P error: {0}")]
    RelayP2PError(#[from] pluto_relay_server::error::RelayP2PError),

    /// Create cluster error.
    #[error("Create cluster error: {0}")]
    CreateClusterError(#[from] CreateClusterError),

    /// Eth1wrap error.
    #[error("Eth1wrap error: {0}")]
    Eth1wrapError(#[from] pluto_eth1wrap::EthClientError),

    /// Eth2util network error.
    #[error("Eth2util network error: {0}")]
    Eth2utilNetworkError(#[from] pluto_eth2util::network::NetworkError),

    /// Eth2util deposit error.
    #[error("Eth2util deposit error: {0}")]
    Eth2utilDepositError(#[from] pluto_eth2util::deposit::DepositError),

    /// Tracing initialization error.
    #[error("Tracing initialization error: {0}")]
    TracingInitError(#[from] pluto_tracing::init::Error),

    /// Command parsing error.
    #[error("Command parsing error: {0}")]
    CommandParsingError(#[from] clap::Error),

    /// Create DKG error.
    #[error("Create DKG error: {0}")]
    CreateDKGError(#[from] crate::commands::create_dkg::CreateDkgError),

    /// Generic error with message.
    #[error("{0}")]
    Other(String),
}

#[derive(thiserror::Error, Debug)]
pub enum CreateClusterError {
    /// Invalid threshold.
    #[error("Invalid threshold: {0}")]
    InvalidThreshold(#[from] ThresholdError),

    /// Missing nodes or definition file.
    #[error("Missing --nodes or --definition-file flag")]
    MissingNodesOrDefinitionFile,

    /// Invalid network configuration.
    #[error("Invalid network configuration: {0}")]
    InvalidNetworkConfig(InvalidNetworkConfigError),

    /// IO error.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Node directory already exists.
    #[error(
        "Existing node directory found, please delete it before running this command: node_dir={node_dir}"
    )]
    NodeDirectoryAlreadyExists {
        /// Node directory.
        node_dir: PathBuf,
    },

    /// Invalid keymanager configuration.
    #[error(
        "number of --keymanager-addresses={keymanager_addrs} do not match --keymanager-auth-tokens={keymanager_auth_tokens}. Please fix configuration flags"
    )]
    InvalidKeymanagerConfig {
        /// Number of keymanager addresses.
        keymanager_addrs: usize,
        /// Number of keymanager auth tokens.
        keymanager_auth_tokens: usize,
    },

    /// Invalid deposit amounts.
    #[error("Invalid deposit amounts: {0}")]
    InvalidDepositAmounts(#[from] pluto_eth2util::deposit::DepositError),

    /// Invalid keymanager URL.
    #[error("Invalid keymanager URL: {0}")]
    InvalidKeymanagerUrl(#[from] url::ParseError),

    /// Cannot specify --num-validators with --split-existing-keys.
    #[error("Cannot specify --num-validators with --split-existing-keys")]
    CannotSpecifyNumValidatorsWithSplitKeys,

    /// Missing --num-validators or --definition-file flag.
    #[error("Missing --num-validators or --definition-file flag")]
    MissingNumValidatorsOrDefinitionFile,

    /// Too few nodes.
    #[error("Too few nodes: {num_nodes}. Minimum is {MIN_NODES}")]
    TooFewNodes {
        /// Number of nodes.
        num_nodes: u64,
    },

    /// Unsupported consensus protocol.
    #[error("Unsupported consensus protocol: {consensus_protocol}")]
    UnsupportedConsensusProtocol {
        /// Consensus protocol.
        consensus_protocol: String,
    },

    /// Missing --split-keys-dir flag.
    #[error("--split-keys-dir is required when splitting keys")]
    MissingSplitKeysDir,

    /// Missing --execution-client-rpc-endpoint flag.
    #[error("--execution-client-rpc-endpoint is required when creating a new cluster")]
    MissingExecutionEngineAddress,

    /// Amount of keys read from disk differs from cluster definition.
    #[error(
        "Amount of keys read from disk differs from cluster definition: disk={disk_keys}, definition={definition_keys}"
    )]
    KeyCountMismatch {
        /// Number of keys read from disk.
        disk_keys: usize,
        /// Number of validators in the definition.
        definition_keys: u64,
    },

    /// Crypto error.
    #[error("Crypto error: {0}")]
    CryptoError(#[from] pluto_crypto::types::Error),

    /// Value exceeds u8::MAX.
    #[error("Value {value} exceeds u8::MAX (255)")]
    ValueExceedsU8 {
        /// The value that exceeds u8::MAX.
        value: u64,
    },

    /// Value exceeds usize::MAX.
    #[error("Value {value} exceeds usize::MAX")]
    ValueExceedsUsize {
        /// The value that exceeds usize::MAX.
        value: u64,
    },

    /// Keystore error.
    #[error("Keystore error: {0}")]
    KeystoreError(#[from] pluto_eth2util::keystore::KeystoreError),

    /// Cannot create cluster with zero validators.
    #[error("Cannot create cluster with zero validators, specify at least one")]
    ZeroValidators,

    /// Insufficient keymanager addresses.
    #[error("Insufficient number of keymanager addresses: expected={expected}, got={got}")]
    InsufficientKeymanagerAddresses {
        /// Expected number of keymanager addresses.
        expected: usize,
        /// Actual number of keymanager addresses.
        got: usize,
    },

    /// Insecure keys not supported on mainnet/gnosis.
    #[error("Insecure keys not supported on mainnet or gnosis")]
    InsecureKeysOnMainnetOrGnosis,

    /// Definition name not provided.
    #[error("Name not provided in cluster definition")]
    DefinitionNameNotProvided,

    /// Definition error.
    #[error("Definition error: {0}")]
    DefinitionError(#[from] pluto_cluster::definition::DefinitionError),

    /// Unsupported network.
    #[error("Unsupported network: {network}")]
    UnsupportedNetwork {
        /// Network name.
        network: String,
    },

    /// Withdrawal validation error.
    #[error("Withdrawal validation error: {0}")]
    WithdrawalValidationError(#[from] crate::commands::create_dkg::WithdrawalValidationError),

    /// Failed to parse definition JSON.
    #[error("Failed to parse definition JSON: {0}")]
    ParseDefinitionJson(#[from] serde_json::Error),

    /// Cluster fetch error.
    #[error("Failed to fetch cluster definition: {0}")]
    FetchDefinition(#[from] pluto_cluster::helpers::FetchError),

    /// No validators specified in definition.
    #[error("No validators specified in the given definition")]
    NoValidatorsInDefinition,

    /// Address validation error.
    #[error("Address validation error: {0}")]
    AddressValidationError(#[from] crate::commands::address_validation::AddressValidationError),

    /// K1 error.
    #[error("K1 error: {0}")]
    K1Error(#[from] pluto_p2p::k1::K1Error),

    /// Record error.
    #[error("Record error: {0}")]
    RecordError(#[from] pluto_eth2util::enr::RecordError),

    /// Eth2util helper error.
    #[error("Eth2util helper error: {0}")]
    Eth2utilHelperError(#[from] pluto_eth2util::helpers::HelperError),

    /// Insufficient withdrawal addresses.
    #[error("Insufficient withdrawal addresses")]
    InsufficientWithdrawalAddresses,

    /// Empty deposit amounts.
    #[error("Empty deposit amounts")]
    EmptyDepositAmounts,

    /// Keymanager error.
    #[error("Keymanager error: {0}")]
    KeymanagerError(#[from] pluto_eth2util::keymanager::KeymanagerError),

    /// Insufficient fee addresses.
    #[error("Insufficient fee addresses: expected {expected}, got {got}")]
    InsufficientFeeAddresses {
        /// Expected number of fee addresses.
        expected: usize,
        /// Actual number of fee addresses.
        got: usize,
    },

    /// Invalid fork version length.
    #[error("Invalid fork version length: expected 4 bytes")]
    InvalidForkVersionLength,

    /// Registration error.
    #[error("Registration error: {0}")]
    RegistrationError(#[from] pluto_eth2util::registration::RegistrationError),

    /// Validator registration not found at the given index.
    #[error("Validator registration not found at index {index}")]
    ValidatorRegistrationNotFound {
        /// Index that was out of bounds.
        index: usize,
    },

    /// Private key shares not found for distributed validator at the given
    /// index.
    #[error("Private key shares not found for distributed validator at index {index}")]
    DvPrivSharesNotFound {
        /// Index that was not found.
        index: usize,
    },

    /// Deposit data not found for the given distributed validator pubkey.
    #[error("Deposit data not found for distributed validator pubkey: {dv}")]
    DepositDataNotFound {
        /// Hex-encoded distributed validator pubkey.
        dv: String,
    },

    /// Lock error (e.g. set_lock_hash failed).
    #[error("Lock error: {0}")]
    LockError(#[from] pluto_cluster::lock::LockError),

    /// K1 utility signing error.
    #[error("K1 util signing error: {0}")]
    K1UtilError(#[from] pluto_k1util::K1UtilError),

    /// Obol API error (publish_lock / launchpad URL).
    #[error("Obol API error: {0}")]
    ObolApiError(#[from] pluto_app::obolapi::ObolApiError),

    /// Bundle output (tar.gz archival) error.
    #[error("Bundle output error: {0}")]
    BundleOutputError(#[from] pluto_app::utils::UtilsError),
}

#[derive(thiserror::Error, Debug)]
pub enum ThresholdError {
    /// Threshold must be greater than {MIN_THRESHOLD}.
    #[error("Threshold must be greater than {MIN_THRESHOLD}, got {threshold}")]
    ThresholdTooLow {
        /// Threshold value.
        threshold: u64,
    },

    /// Threshold must be less than the number of nodes.
    #[error(
        "Threshold cannot be greater than number of operators (nodes): Threshold={threshold}, Number of nodes={number_of_nodes}"
    )]
    ThresholdTooHigh {
        /// Threshold value.
        threshold: u64,
        /// Number of operators (nodes).
        number_of_nodes: u64,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum InvalidNetworkConfigError {
    /// Invalid network name.
    #[error("Invalid network name: {0}")]
    InvalidNetworkName(#[from] pluto_eth2util::network::NetworkError),

    /// Invalid network specified.
    #[error("Invalid network specified: network={network}")]
    InvalidNetworkSpecified {
        /// Network name.
        network: String,
    },

    /// Missing --network flag or testnet config flags.
    #[error("Missing --network flag and no testnet config flag")]
    MissingNetworkFlagAndNoTestnetConfigFlag,
}

impl From<InvalidNetworkConfigError> for CreateClusterError {
    fn from(error: InvalidNetworkConfigError) -> Self {
        CreateClusterError::InvalidNetworkConfig(error)
    }
}

impl From<pluto_eth2util::network::NetworkError> for CreateClusterError {
    fn from(error: pluto_eth2util::network::NetworkError) -> Self {
        CreateClusterError::InvalidNetworkConfig(InvalidNetworkConfigError::InvalidNetworkName(
            error,
        ))
    }
}
