//! The `run` command — the entry point for the long-running Pluto middleware
//! client that performs distributed validator duties for a cluster: connecting
//! to beacon nodes, exposing a validator-facing API, and coordinating duties
//! with the other cluster operators over libp2p.
//!
//! Typical invocation:
//!
//! ```text
//! pluto run --beacon-node-endpoints https://beacon.example
//! ```
//!
//! Use `--simnet-beacon-mock` to run against an internal mock instead of a real
//! beacon node. Every flag also reads from its `CHARON_*` environment variable.
//! The hidden `unsafe run` variant adds test-only flags (e.g. `--p2p-fuzz`) and
//! must not be used in production.
//!
//! Flags are parsed and validated into [`RunConfig`]. The long-running workflow
//! itself is not yet implemented: invoking the command currently panics at
//! [`run_workflow`], the seam where the engine will be wired in.
//!
//! Limitations:
//! - The run workflow is a stub; the command does not yet perform real duties.
//! - `--log-format` and `--log-output-path` are accepted but not yet applied
//!   (console and Loki output only).

use std::{collections::HashMap, path::Path, time::Duration as StdDuration};

use libp2p::multiaddr::Protocol;
use pluto_eth2util::helpers::validate_http_headers;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    commands::common::{ConsoleColor, LICENSE, build_console_tracing_config, parse_relay_addr},
    duration::Duration,
    error::{CliError, Result},
};

/// Maximum graffiti length in bytes when the `OB<CL_TYPE>` client suffix is
/// appended.
const MAX_GRAFFITI_BYTES: usize = 28;
/// Maximum graffiti length in bytes when the client suffix is disabled.
const MAX_GRAFFITI_BYTES_NO_APPEND: usize = 32;
/// Maximum peer nickname length in bytes.
const MAX_NICKNAME_BYTES: usize = 32;
/// Grace period for the Loki background task to flush buffered logs on exit.
const LOKI_FLUSH_TIMEOUT: StdDuration = StdDuration::from_secs(3);

/// Arguments for the `run` command.
///
/// Field order groups the flags (priv-key, run, debug/monitoring, no-verify,
/// p2p, log, loki, feature); `--help` lists them alphabetically regardless.
#[derive(clap::Args, Clone, Debug)]
pub struct RunArgs {
    #[command(flatten)]
    pub priv_key: RunPrivKeyArgs,

    #[command(flatten)]
    pub general: RunGeneralArgs,

    #[command(flatten)]
    pub debug_monitoring: RunDebugMonitoringArgs,

    #[arg(
        long = "no-verify",
        env = "CHARON_NO_VERIFY",
        default_value_t = false,
        help = "Disables cluster definition and lock file verification."
    )]
    pub no_verify: bool,

    #[command(flatten)]
    pub p2p: RunP2PArgs,

    #[command(flatten)]
    pub log: RunLogArgs,

    #[command(flatten)]
    pub loki: RunLokiArgs,

    #[command(flatten)]
    pub feature: RunFeatureArgs,
}

/// Arguments for the hidden `unsafe run` command, which adds the `--p2p-fuzz`
/// flag on top of the regular [`RunArgs`]. Registered only under the hidden
/// `unsafe` parent so `--p2p-fuzz` is rejected on the safe `run` command.
#[derive(clap::Args, Clone, Debug)]
pub struct RunUnsafeArgs {
    #[command(flatten)]
    pub run: RunArgs,

    #[arg(
        long = "p2p-fuzz",
        env = "CHARON_P2P_FUZZ",
        default_value_t = false,
        help = "Configures pluto to send fuzzed data via p2p network to its peers."
    )]
    pub p2p_fuzz: bool,
}

/// Private key flags.
#[derive(clap::Args, Clone, Debug)]
pub struct RunPrivKeyArgs {
    #[arg(
        long = "private-key-file",
        env = "CHARON_PRIVATE_KEY_FILE",
        default_value = ".charon/charon-enr-private-key",
        help = "The path to the pluto enr private key file."
    )]
    pub private_key_file: String,

    #[arg(
        long = "private-key-file-lock",
        env = "CHARON_PRIVATE_KEY_FILE_LOCK",
        default_value_t = false,
        help = "Enables private key locking to prevent multiple instances using the same key."
    )]
    pub private_key_file_lock: bool,
}

/// General run flags.
#[derive(clap::Args, Clone, Debug)]
pub struct RunGeneralArgs {
    #[arg(
        long = "lock-file",
        env = "CHARON_LOCK_FILE",
        default_value = ".charon/cluster-lock.json",
        help = "The path to the cluster lock file defining the distributed validator cluster. If both cluster manifest and cluster lock files are provided, the cluster manifest file takes precedence."
    )]
    pub lock_file: String,

    #[arg(
        long = "manifest-file",
        env = "CHARON_MANIFEST_FILE",
        default_value = ".charon/cluster-manifest.pb",
        help = "The path to the cluster manifest file. If both cluster manifest and cluster lock files are provided, the cluster manifest file takes precedence."
    )]
    pub manifest_file: String,

    #[arg(
        long = "beacon-node-endpoints",
        env = "CHARON_BEACON_NODE_ENDPOINTS",
        value_delimiter = ',',
        help = "Comma separated list of one or more beacon node endpoint URLs."
    )]
    pub beacon_node_endpoints: Vec<String>,

    #[arg(
        long = "beacon-node-timeout",
        env = "CHARON_BEACON_NODE_TIMEOUT",
        default_value = "2s",
        help = "Timeout for the HTTP requests Pluto makes to the configured beacon nodes."
    )]
    pub beacon_node_timeout: Duration,

    #[arg(
        long = "beacon-node-submit-timeout",
        env = "CHARON_BEACON_NODE_SUBMIT_TIMEOUT",
        default_value = "2s",
        help = "Timeout for the submission-related HTTP requests Pluto makes to the configured beacon nodes."
    )]
    pub beacon_node_submit_timeout: Duration,

    #[arg(
        long = "validator-api-address",
        env = "CHARON_VALIDATOR_API_ADDRESS",
        default_value = "127.0.0.1:3600",
        help = "Listening address (ip and port) for validator-facing traffic proxying the beacon-node API."
    )]
    pub validator_api_address: String,

    #[arg(
        long = "jaeger-address",
        env = "CHARON_JAEGER_ADDRESS",
        default_value = "",
        help = "[DISABLED] Listening address for jaeger tracing."
    )]
    pub jaeger_address: String,

    #[arg(
        long = "jaeger-service",
        env = "CHARON_JAEGER_SERVICE",
        default_value = "",
        help = "[DISABLED] Service name used for jaeger tracing."
    )]
    pub jaeger_service: String,

    #[arg(
        long = "otlp-address",
        env = "CHARON_OTLP_ADDRESS",
        default_value = "",
        help = "Listening address for OTLP gRPC tracing backend."
    )]
    pub otlp_address: String,

    #[arg(
        long = "otlp-headers",
        env = "CHARON_OTLP_HEADERS",
        value_delimiter = ',',
        help = "Comma separated list of headers formatted as header=value, to include in OTLP requests."
    )]
    pub otlp_headers: Vec<String>,

    #[arg(
        long = "otlp-insecure",
        env = "CHARON_OTLP_INSECURE",
        default_value_t = false,
        help = "Use insecure connection (no TLS) when connecting to OTLP endpoint."
    )]
    pub otlp_insecure: bool,

    #[arg(
        long = "otlp-service-name",
        env = "CHARON_OTLP_SERVICE_NAME",
        default_value = "pluto",
        help = "Service name used for OTLP gRPC tracing."
    )]
    pub otlp_service_name: String,

    #[arg(
        long = "simnet-beacon-mock",
        env = "CHARON_SIMNET_BEACON_MOCK",
        default_value_t = false,
        help = "Enables an internal mock beacon node for running a simnet."
    )]
    pub simnet_beacon_mock: bool,

    #[arg(
        long = "simnet-validator-mock",
        env = "CHARON_SIMNET_VALIDATOR_MOCK",
        default_value_t = false,
        help = "Enables an internal mock validator client when running a simnet. Requires simnet-beacon-mock."
    )]
    pub simnet_validator_mock: bool,

    #[arg(
        long = "simnet-validator-keys-dir",
        env = "CHARON_SIMNET_VALIDATOR_KEYS_DIR",
        default_value = ".charon/validator_keys",
        help = "The directory containing the simnet validator key shares."
    )]
    pub simnet_validator_keys_dir: String,

    #[arg(
        long = "builder-api",
        env = "CHARON_BUILDER_API",
        default_value_t = false,
        help = "Enables the builder api. Will only produce builder blocks. Builder API must also be enabled on the validator client. Beacon node must be connected to a builder-relay to access the builder network."
    )]
    pub builder_api: bool,

    #[arg(
        long = "synthetic-block-proposals",
        env = "CHARON_SYNTHETIC_BLOCK_PROPOSALS",
        default_value_t = false,
        help = "Enables additional synthetic block proposal duties. Used for testing of rare duties."
    )]
    pub synthetic_block_proposals: bool,

    #[arg(
        long = "simnet-slot-duration",
        env = "CHARON_SIMNET_SLOT_DURATION",
        default_value = "1s",
        help = "Configures slot duration in simnet beacon mock."
    )]
    pub simnet_slot_duration: Duration,

    #[arg(
        long = "simnet-beacon-mock-fuzz",
        env = "CHARON_SIMNET_BEACON_MOCK_FUZZ",
        default_value_t = false,
        help = "Configures simnet beaconmock to return fuzzed responses."
    )]
    pub simnet_beacon_mock_fuzz: bool,

    #[arg(
        long = "testnet-name",
        env = "CHARON_TESTNET_NAME",
        default_value = "",
        help = "Name of the custom test network."
    )]
    pub testnet_name: String,

    #[arg(
        long = "testnet-fork-version",
        env = "CHARON_TESTNET_FORK_VERSION",
        default_value = "",
        help = "Genesis fork version in hex of the custom test network."
    )]
    pub testnet_fork_version: String,

    #[arg(
        long = "testnet-chain-id",
        env = "CHARON_TESTNET_CHAIN_ID",
        default_value_t = 0,
        help = "Chain ID of the custom test network."
    )]
    pub testnet_chain_id: u64,

    #[arg(
        long = "testnet-genesis-timestamp",
        env = "CHARON_TESTNET_GENESIS_TIMESTAMP",
        default_value_t = 0,
        help = "Genesis timestamp of the custom test network."
    )]
    pub testnet_genesis_timestamp: i64,

    #[arg(
        long = "testnet-capella-hard-fork",
        env = "CHARON_TESTNET_CAPELLA_HARD_FORK",
        default_value = "",
        help = "Capella hard fork version of the custom test network."
    )]
    pub testnet_capella_hard_fork: String,

    #[arg(
        long = "proc-directory",
        env = "CHARON_PROC_DIRECTORY",
        default_value = "",
        help = "Directory to look into in order to detect other stack components running on the host."
    )]
    pub proc_directory: String,

    #[arg(
        long = "consensus-protocol",
        env = "CHARON_CONSENSUS_PROTOCOL",
        default_value = "",
        help = "Preferred consensus protocol name for the node. Selected automatically when not specified."
    )]
    pub consensus_protocol: String,

    #[arg(
        long = "nickname",
        env = "CHARON_NICKNAME",
        default_value = "",
        help = "Human friendly peer nickname. Maximum 32 characters."
    )]
    pub nickname: String,

    #[arg(
        long = "beacon-node-headers",
        env = "CHARON_BEACON_NODE_HEADERS",
        value_delimiter = ',',
        help = "Comma separated list of headers formatted as header=value"
    )]
    pub beacon_node_headers: Vec<String>,

    #[arg(
        long = "fallback-beacon-node-endpoints",
        env = "CHARON_FALLBACK_BEACON_NODE_ENDPOINTS",
        value_delimiter = ',',
        help = "A list of beacon nodes to use if the primary list are offline or unhealthy."
    )]
    pub fallback_beacon_node_endpoints: Vec<String>,

    #[arg(
        long = "execution-client-rpc-endpoint",
        env = "CHARON_EXECUTION_CLIENT_RPC_ENDPOINT",
        default_value = "",
        help = "The address of the execution engine JSON-RPC API."
    )]
    pub execution_client_rpc_endpoint: String,

    #[arg(
        long = "graffiti",
        env = "CHARON_GRAFFITI",
        value_delimiter = ',',
        help = "Comma-separated list or single graffiti string to include in block proposals. List maps to validator's public key in cluster lock. Appends \"OB<CL_TYPE>\" suffix to graffiti. Maximum 28 bytes per graffiti."
    )]
    pub graffiti: Vec<String>,

    #[arg(
        long = "graffiti-disable-client-append",
        env = "CHARON_GRAFFITI_DISABLE_CLIENT_APPEND",
        default_value_t = false,
        help = "Disables appending \"OB<CL_TYPE>\" suffix to graffiti. Increases maximum bytes per graffiti to 32."
    )]
    pub graffiti_disable_client_append: bool,

    #[arg(
        long = "vc-tls-cert-file",
        env = "CHARON_VC_TLS_CERT_FILE",
        default_value = "",
        help = "The path to the TLS certificate file used by pluto for the validator client API endpoint."
    )]
    pub vc_tls_cert_file: String,

    #[arg(
        long = "vc-tls-key-file",
        env = "CHARON_VC_TLS_KEY_FILE",
        default_value = "",
        help = "The path to the TLS private key file associated with the provided TLS certificate."
    )]
    pub vc_tls_key_file: String,
}

/// Debug and monitoring flags; `run` defaults the monitoring address to
/// `127.0.0.1:3620`.
#[derive(clap::Args, Clone, Debug)]
pub struct RunDebugMonitoringArgs {
    #[arg(
        long = "monitoring-address",
        env = "CHARON_MONITORING_ADDRESS",
        default_value = "127.0.0.1:3620",
        help = "Listening address (ip and port) for the monitoring API (prometheus)."
    )]
    pub monitor_addr: String,

    #[arg(
        long = "debug-address",
        env = "CHARON_DEBUG_ADDRESS",
        default_value = "",
        help = "Listening address (ip and port) for the pprof and QBFT debug API. It is not enabled by default."
    )]
    pub debug_addr: String,
}

/// P2P flags.
#[derive(clap::Args, Clone, Debug)]
pub struct RunP2PArgs {
    #[arg(
        long = "p2p-relays",
        env = "CHARON_P2P_RELAYS",
        value_delimiter = ',',
        default_values_t = pluto_p2p::config::DEFAULT_RELAYS.map(String::from),
        help = "Comma-separated list of libp2p relay URLs or multiaddrs."
    )]
    pub relays: Vec<String>,

    #[arg(
        long = "p2p-external-ip",
        env = "CHARON_P2P_EXTERNAL_IP",
        help = "The IP address advertised by libp2p. This may be used to advertise an external IP."
    )]
    pub external_ip: Option<String>,

    #[arg(
        long = "p2p-external-hostname",
        env = "CHARON_P2P_EXTERNAL_HOSTNAME",
        help = "The DNS hostname advertised by libp2p. This may be used to advertise an external DNS."
    )]
    pub external_host: Option<String>,

    #[arg(
        long = "p2p-tcp-address",
        env = "CHARON_P2P_TCP_ADDRESS",
        value_delimiter = ',',
        help = "Comma-separated list of listening TCP addresses (ip and port) for libP2P traffic. Empty default doesn't bind to local port therefore only supports outgoing connections."
    )]
    pub tcp_addrs: Vec<String>,

    #[arg(
        long = "p2p-udp-address",
        env = "CHARON_P2P_UDP_ADDRESS",
        value_delimiter = ',',
        help = "Comma-separated list of listening UDP addresses (ip and port) for libP2P traffic. Empty default doesn't bind to local port therefore only supports outgoing connections."
    )]
    pub udp_addrs: Vec<String>,

    #[arg(
        long = "p2p-disable-reuseport",
        env = "CHARON_P2P_DISABLE_REUSEPORT",
        default_value_t = false,
        help = "Disables TCP port reuse for outgoing libp2p connections."
    )]
    pub disable_reuseport: bool,
}

/// Logging flags.
#[derive(clap::Args, Clone, Debug)]
pub struct RunLogArgs {
    #[arg(
        long = "log-format",
        env = "CHARON_LOG_FORMAT",
        default_value = "console",
        help = "Log format; console, logfmt or json"
    )]
    pub format: String,

    #[arg(
        long = "log-level",
        env = "CHARON_LOG_LEVEL",
        default_value = "info",
        help = "Log level; debug, info, warn or error"
    )]
    pub level: String,

    #[arg(
        long = "log-color",
        env = "CHARON_LOG_COLOR",
        default_value = "auto",
        help = "Log color; auto, force, disable."
    )]
    pub color: ConsoleColor,

    #[arg(
        long = "log-output-path",
        env = "CHARON_LOG_OUTPUT_PATH",
        help = "Path in which to write on-disk logs."
    )]
    pub log_output_path: Option<std::path::PathBuf>,
}

/// Loki flags.
#[derive(clap::Args, Clone, Debug)]
pub struct RunLokiArgs {
    #[arg(
        long = "loki-addresses",
        env = "CHARON_LOKI_ADDRESSES",
        value_delimiter = ',',
        help = "Enables sending of logfmt structured logs to these Loki log aggregation server addresses. This is in addition to normal stderr logs."
    )]
    pub loki_addresses: Vec<String>,

    #[arg(
        long = "loki-service",
        env = "CHARON_LOKI_SERVICE",
        default_value = "pluto",
        help = "Service label sent with logs to Loki."
    )]
    pub loki_service: String,
}

/// Feature set flags.
#[derive(clap::Args, Clone, Debug)]
pub struct RunFeatureArgs {
    #[arg(
        long = "feature-set-enable",
        env = "CHARON_FEATURE_SET_ENABLE",
        value_delimiter = ',',
        help = "Comma-separated list of features to enable, overriding the default minimum feature set."
    )]
    pub feature_set_enable: Vec<String>,

    #[arg(
        long = "feature-set-disable",
        env = "CHARON_FEATURE_SET_DISABLE",
        value_delimiter = ',',
        help = "Comma-separated list of features to disable, overriding the default minimum feature set."
    )]
    pub feature_set_disable: Vec<String>,

    #[arg(
        long = "feature-set",
        env = "CHARON_FEATURE_SET",
        default_value = "stable",
        help = "Minimum feature set to enable by default: alpha, beta, or stable. Warning: modify at own risk."
    )]
    pub feature_set: String,
}

/// Custom test network configuration.
//
// Populated from flags and consumed by the future app entry; until the run
// workflow is wired (see module docs) these fields are written but not read.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct TestnetConfig {
    /// Name of the custom test network.
    pub name: String,
    /// Genesis fork version in hex.
    pub genesis_fork_version_hex: String,
    /// Chain ID.
    pub chain_id: u64,
    /// Genesis timestamp (unix seconds).
    pub genesis_timestamp: i64,
    /// Capella hard fork version.
    pub capella_hard_fork: String,
}

/// Feature set configuration.
//
// Populated from flags and consumed by the future app entry; until the run
// workflow is wired (see module docs) these fields are written but not read.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct FeatureConfig {
    /// Minimum feature status to enable by default (alpha/beta/stable).
    pub min_status: String,
    /// Features to enable on top of the minimum set.
    pub enabled: Vec<String>,
    /// Features to disable from the minimum set.
    pub disabled: Vec<String>,
}

/// Configuration for the `run` command — the settings produced from the parsed
/// flags. This is the object the future app entry consumes (see the seam in
/// [`run`]); `p2p_fuzz` is the single test-only field, set only via the hidden
/// `unsafe run` command.
//
// The parsed config surface; the run workflow that reads these fields is not
// yet implemented, so they are populated but not yet consumed.
#[allow(dead_code)]
#[derive(Debug)]
pub struct RunConfig {
    /// P2P configuration built from [`RunP2PArgs`].
    pub p2p: pluto_p2p::config::P2PConfig,
    /// Tracing configuration built from [`RunLogArgs`]/[`RunLokiArgs`].
    pub log: pluto_tracing::TracingConfig,
    /// Feature set configuration.
    pub feature: FeatureConfig,
    /// Path to the cluster lock file.
    pub lock_file: String,
    /// Path to the cluster manifest file.
    pub manifest_file: String,
    /// Disables cluster definition and lock file verification.
    pub no_verify: bool,
    /// Path to the ENR private key file.
    pub private_key_file: String,
    /// Enables private key locking.
    pub private_key_locking: bool,
    /// Monitoring API listen address.
    pub monitoring_addr: String,
    /// Debug API listen address.
    pub debug_addr: String,
    /// Validator API listen address.
    pub validator_api_addr: String,
    /// Beacon node endpoint URLs.
    pub beacon_node_addrs: Vec<String>,
    /// Beacon node request timeout.
    pub beacon_node_timeout: StdDuration,
    /// Beacon node submission request timeout.
    pub beacon_node_submit_timeout: StdDuration,
    /// [DISABLED] Jaeger tracing address.
    pub jaeger_addr: String,
    /// [DISABLED] Jaeger tracing service name.
    pub jaeger_service: String,
    /// OTLP gRPC tracing backend address.
    pub otlp_address: String,
    /// OTLP request headers (header=value).
    pub otlp_headers: Vec<String>,
    /// Use an insecure (no TLS) OTLP connection.
    pub otlp_insecure: bool,
    /// OTLP tracing service name.
    pub otlp_service_name: String,
    /// Enables the internal mock beacon node (simnet).
    pub simnet_beacon_mock: bool,
    /// Enables the internal mock validator client (simnet).
    pub simnet_validator_mock: bool,
    /// Directory containing simnet validator key shares.
    pub simnet_validator_keys_dir: String,
    /// Simnet beacon mock slot duration.
    pub simnet_slot_duration: StdDuration,
    /// Enables additional synthetic block proposal duties.
    pub synthetic_block_proposals: bool,
    /// Enables the builder API.
    pub builder_api: bool,
    /// Configures the simnet beacon mock to return fuzzed responses.
    pub simnet_beacon_mock_fuzz: bool,
    /// Custom test network configuration.
    pub testnet: TestnetConfig,
    /// Directory used to detect other stack components on the host.
    pub proc_directory: String,
    /// Preferred consensus protocol (auto-selected when empty).
    pub consensus_protocol: String,
    /// Human friendly peer nickname.
    pub nickname: String,
    /// Beacon node request headers (header=value).
    pub beacon_node_headers: Vec<String>,
    /// Fallback beacon node endpoint URLs.
    pub fallback_beacon_node_addrs: Vec<String>,
    /// Execution engine JSON-RPC API address.
    pub execution_engine_addr: String,
    /// Graffiti strings included in block proposals.
    pub graffiti: Vec<String>,
    /// Disables appending the client suffix to graffiti.
    pub graffiti_disable_client_append: bool,
    /// Path to the validator client API TLS certificate.
    pub vc_tls_cert_file: String,
    /// Path to the validator client API TLS private key.
    pub vc_tls_key_file: String,
    /// Send fuzzed p2p data to peers (test-only; hidden `unsafe run`).
    pub p2p_fuzz: bool,
}

impl TryFrom<RunArgs> for RunConfig {
    type Error = CliError;

    /// Validates the parsed flags and builds the run configuration. Validation
    /// is grouped: p2p checks first, then the run-level checks.
    fn try_from(args: RunArgs) -> Result<Self> {
        let RunArgs {
            priv_key,
            general,
            debug_monitoring,
            no_verify,
            p2p,
            log,
            loki,
            feature,
        } = args;

        // --- p2p validation ---
        validate_hostname(p2p.external_host.as_deref())?;

        let mut relays = Vec::with_capacity(p2p.relays.len());
        for relay in &p2p.relays {
            let multiaddr = parse_relay_addr(relay)?;

            if multiaddr.iter().any(|protocol| protocol == Protocol::Http) {
                warn!(address = %relay, "Insecure relay address provided, not HTTPS");
            }

            relays.push(multiaddr);
        }

        // --- run-level validation ---
        if general.beacon_node_endpoints.is_empty() && !general.simnet_beacon_mock {
            return Err(CliError::Other(
                "either flag 'beacon-node-endpoints' or flag 'simnet-beacon-mock=true' must be specified"
                    .to_string(),
            ));
        }

        if general.nickname.len() > MAX_NICKNAME_BYTES {
            return Err(CliError::Other(format!(
                "flag 'nickname' can not exceed {MAX_NICKNAME_BYTES} characters"
            )));
        }

        if !general.jaeger_address.is_empty() || !general.jaeger_service.is_empty() {
            warn!("Jaeger flags are disabled and will be removed in a future release");
        }

        validate_http_headers(&general.beacon_node_headers)
            .map_err(|err| CliError::Other(err.to_string()))?;

        let max_graffiti_bytes = if general.graffiti_disable_client_append {
            MAX_GRAFFITI_BYTES_NO_APPEND
        } else {
            MAX_GRAFFITI_BYTES
        };
        for graffiti in &general.graffiti {
            if graffiti.len() > max_graffiti_bytes {
                return Err(CliError::Other(
                    "graffiti string length is greater than maximum size".to_string(),
                ));
            }
        }

        validate_vc_tls(&general.vc_tls_cert_file, &general.vc_tls_key_file)?;

        // --- build sub-configs ---
        let p2p_config = pluto_p2p::config::P2PConfig {
            relays,
            external_ip: p2p.external_ip,
            external_host: p2p.external_host,
            tcp_addrs: p2p.tcp_addrs,
            udp_addrs: p2p.udp_addrs,
            disable_reuse_port: p2p.disable_reuseport,
        };

        let log_config =
            build_console_tracing_config(log.level, &log.color, build_loki_config(&loki));

        Ok(Self {
            p2p: p2p_config,
            log: log_config,
            feature: FeatureConfig {
                min_status: feature.feature_set,
                enabled: feature.feature_set_enable,
                disabled: feature.feature_set_disable,
            },
            lock_file: general.lock_file,
            manifest_file: general.manifest_file,
            no_verify,
            private_key_file: priv_key.private_key_file,
            private_key_locking: priv_key.private_key_file_lock,
            monitoring_addr: debug_monitoring.monitor_addr,
            debug_addr: debug_monitoring.debug_addr,
            validator_api_addr: general.validator_api_address,
            beacon_node_addrs: general.beacon_node_endpoints,
            beacon_node_timeout: general.beacon_node_timeout.into(),
            beacon_node_submit_timeout: general.beacon_node_submit_timeout.into(),
            jaeger_addr: general.jaeger_address,
            jaeger_service: general.jaeger_service,
            otlp_address: general.otlp_address,
            otlp_headers: general.otlp_headers,
            otlp_insecure: general.otlp_insecure,
            otlp_service_name: general.otlp_service_name,
            simnet_beacon_mock: general.simnet_beacon_mock,
            simnet_validator_mock: general.simnet_validator_mock,
            simnet_validator_keys_dir: general.simnet_validator_keys_dir,
            simnet_slot_duration: general.simnet_slot_duration.into(),
            synthetic_block_proposals: general.synthetic_block_proposals,
            builder_api: general.builder_api,
            simnet_beacon_mock_fuzz: general.simnet_beacon_mock_fuzz,
            testnet: TestnetConfig {
                name: general.testnet_name,
                genesis_fork_version_hex: general.testnet_fork_version,
                chain_id: general.testnet_chain_id,
                genesis_timestamp: general.testnet_genesis_timestamp,
                capella_hard_fork: general.testnet_capella_hard_fork,
            },
            proc_directory: general.proc_directory,
            consensus_protocol: general.consensus_protocol,
            nickname: general.nickname,
            beacon_node_headers: general.beacon_node_headers,
            fallback_beacon_node_addrs: general.fallback_beacon_node_endpoints,
            execution_engine_addr: general.execution_client_rpc_endpoint,
            graffiti: general.graffiti,
            graffiti_disable_client_append: general.graffiti_disable_client_append,
            vc_tls_cert_file: general.vc_tls_cert_file,
            vc_tls_key_file: general.vc_tls_key_file,
            p2p_fuzz: false,
        })
    }
}

impl TryFrom<RunUnsafeArgs> for RunConfig {
    type Error = CliError;

    fn try_from(args: RunUnsafeArgs) -> Result<Self> {
        let mut config = RunConfig::try_from(args.run)?;
        config.p2p_fuzz = args.p2p_fuzz;
        Ok(config)
    }
}

/// Validates the optional p2p external hostname via `url::Host::parse`. An
/// empty value means "no external host" (same as omitting the flag), so only a
/// non-empty value is validated.
fn validate_hostname(host: Option<&str>) -> Result<()> {
    if let Some(host) = host.filter(|h| !h.is_empty()) {
        url::Host::parse(host)
            .map_err(|err| CliError::Other(format!("invalid hostname: {host}: {err}")))?;
    }

    Ok(())
}

/// Validates the validator-client TLS cert/key pairing and existence: both must
/// be set or both empty, and any provided path must exist.
fn validate_vc_tls(cert: &str, key: &str) -> Result<()> {
    if cert.is_empty() != key.is_empty() {
        return Err(CliError::Other(
            "both vc-tls-cert-file and vc-tls-key-file must be set or both must be empty"
                .to_string(),
        ));
    }

    if !cert.is_empty() && !Path::new(cert).exists() {
        return Err(CliError::Other(
            "file vc-tls-cert-file does not exist".to_string(),
        ));
    }

    if !key.is_empty() && !Path::new(key).exists() {
        return Err(CliError::Other(
            "file vc-tls-key-file does not exist".to_string(),
        ));
    }

    Ok(())
}

/// Builds the optional Loki tracing configuration from the loki flags.
///
/// Only a single Loki endpoint is supported today, so any extra
/// `--loki-addresses` entries are ignored with a warning. The warning goes to
/// stderr because no tracing subscriber is installed yet.
fn build_loki_config(loki: &RunLokiArgs) -> Option<pluto_tracing::LokiConfig> {
    match loki.loki_addresses.as_slice() {
        [] => None,
        [loki_url, rest @ ..] => {
            if !rest.is_empty() {
                eprintln!(
                    "warning: {extra} additional --loki-addresses ignored; only the first is used",
                    extra = rest.len(),
                );
            }

            Some(pluto_tracing::LokiConfig {
                loki_url: loki_url.clone(),
                labels: HashMap::from([("service".to_string(), loki.loki_service.clone())]),
                extra_fields: HashMap::new(),
            })
        }
    }
}

/// Runs the `run` command from an already-built configuration.
///
/// Initializes tracing and owns the Loki lifecycle for the command's lifetime:
/// when `--loki-addresses` is set, the background task is spawned here and
/// drained on exit so buffered logs are delivered.
pub async fn run(config: RunConfig, ct: CancellationToken) -> Result<()> {
    let loki_shutdown = match pluto_tracing::init(&config.log) {
        Ok(Some(loki)) => Some((loki.controller, tokio::spawn(loki.task))),
        Ok(None) => None,
        // In tests the global subscriber is shared across runs in the same
        // process, so reinitializing fails; treat that as "no Loki worker"
        // rather than failing the command.
        #[cfg(test)]
        Err(pluto_tracing::init::Error::Init(_)) => None,
        Err(err) => return Err(err.into()),
    };

    info!("{LICENSE}");

    let result = run_workflow(config, ct).await;

    if let Err(err) = &result {
        // Surface the failure through the subscriber so it reaches Loki before
        // the worker is drained; `main` only `eprintln!`s the returned error
        // and that path bypasses the tracing subscriber.
        error!(error = %err, "run exited with error");
    }

    // Drain the Loki worker under a single budget so a hung endpoint cannot
    // wedge process exit; hard-abort after the budget elapses.
    if let Some((controller, handle)) = loki_shutdown {
        let abort_handle = handle.abort_handle();
        let _ = tokio::time::timeout(LOKI_FLUSH_TIMEOUT, async {
            controller.shutdown().await;
            let _ = handle.await;
        })
        .await;
        abort_handle.abort();
    }

    result
}

/// The long-running validator workflow. Not yet implemented: panics via
/// `unimplemented!` at the seam where the app entry will be wired in.
async fn run_workflow(_config: RunConfig, _ct: CancellationToken) -> Result<()> {
    unimplemented!("pluto run")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands, UnsafeCommands};
    use clap::{CommandFactory, Parser};
    use std::{collections::BTreeSet, time::Duration as StdDuration};

    /// Every flag the safe `run` command must expose.
    const EXPECTED_RUN_FLAGS: [&str; 54] = [
        // priv key
        "private-key-file",
        "private-key-file-lock",
        // general
        "lock-file",
        "manifest-file",
        "beacon-node-endpoints",
        "beacon-node-timeout",
        "beacon-node-submit-timeout",
        "validator-api-address",
        "jaeger-address",
        "jaeger-service",
        "otlp-address",
        "otlp-headers",
        "otlp-insecure",
        "otlp-service-name",
        "simnet-beacon-mock",
        "simnet-validator-mock",
        "simnet-validator-keys-dir",
        "builder-api",
        "synthetic-block-proposals",
        "simnet-slot-duration",
        "simnet-beacon-mock-fuzz",
        "testnet-name",
        "testnet-fork-version",
        "testnet-chain-id",
        "testnet-genesis-timestamp",
        "testnet-capella-hard-fork",
        "proc-directory",
        "consensus-protocol",
        "nickname",
        "beacon-node-headers",
        "fallback-beacon-node-endpoints",
        "execution-client-rpc-endpoint",
        "graffiti",
        "graffiti-disable-client-append",
        "vc-tls-cert-file",
        "vc-tls-key-file",
        // debug / monitoring
        "monitoring-address",
        "debug-address",
        // no-verify
        "no-verify",
        // p2p
        "p2p-relays",
        "p2p-external-ip",
        "p2p-external-hostname",
        "p2p-tcp-address",
        "p2p-udp-address",
        "p2p-disable-reuseport",
        // log
        "log-format",
        "log-level",
        "log-color",
        "log-output-path",
        // loki
        "loki-addresses",
        "loki-service",
        // feature
        "feature-set-enable",
        "feature-set-disable",
        "feature-set",
    ];

    /// Returns the named subcommand from the root `Cli` command.
    fn subcommand(name: &str) -> clap::Command {
        Cli::command()
            .get_subcommands()
            .find(|sub| sub.get_name() == name)
            .unwrap_or_else(|| panic!("missing subcommand: {name}"))
            .clone()
    }

    /// Long names of every (non-help) argument exposed by a command.
    fn flag_names(command: &clap::Command) -> BTreeSet<String> {
        command
            .get_arguments()
            .filter_map(|arg| arg.get_long())
            .filter(|long| *long != "help")
            .map(String::from)
            .collect()
    }

    /// Parses safe `run` args (with the beacon requirement already satisfied)
    /// and builds the config.
    fn parse_run(extra: &[&str]) -> Result<RunConfig> {
        let mut argv = vec![
            "pluto",
            "run",
            "--beacon-node-endpoints",
            "http://beacon.node",
        ];
        argv.extend_from_slice(extra);
        let cli = Cli::try_parse_from(argv).expect("run args should parse");
        let Commands::Run(args) = cli.command else {
            panic!("expected run command");
        };
        (*args).try_into()
    }

    /// Returns the `Display` string of the error from a failing `parse_run`.
    fn run_err(extra: &[&str]) -> String {
        parse_run(extra)
            .expect_err("expected validation error")
            .to_string()
    }

    /// Parses `argv` expecting a clap failure and returns the error. Uses a
    /// `match` (not `expect_err`) because `Cli` does not implement `Debug`.
    fn parse_err(argv: &[&str]) -> clap::Error {
        match Cli::try_parse_from(argv) {
            Ok(_) => panic!("expected parse failure"),
            Err(err) => err,
        }
    }

    #[test]
    fn run_is_registered_as_top_level_subcommand() {
        let cli = Cli::try_parse_from(["pluto", "run", "--beacon-node-endpoints", "http://b.node"])
            .expect("run command should parse");

        assert!(matches!(cli.command, Commands::Run(_)));
    }

    #[test]
    fn run_exposes_all_charon_flags() {
        let expected: BTreeSet<String> = EXPECTED_RUN_FLAGS
            .iter()
            .map(|flag| flag.to_string())
            .collect();

        assert_eq!(flag_names(&subcommand("run")), expected);
    }

    #[test]
    fn unsafe_run_exposes_all_charon_flags_plus_fuzz() {
        let unsafe_run = subcommand("unsafe")
            .get_subcommands()
            .find(|sub| sub.get_name() == "run")
            .expect("unsafe run subcommand should exist")
            .clone();

        let mut expected: BTreeSet<String> = EXPECTED_RUN_FLAGS
            .iter()
            .map(|flag| flag.to_string())
            .collect();
        expected.insert("p2p-fuzz".to_string());

        assert_eq!(flag_names(&unsafe_run), expected);
    }

    #[test]
    fn run_help_text_matches_charon_rebranded() {
        let run = subcommand("run");
        assert_eq!(
            run.get_about().map(ToString::to_string).as_deref(),
            Some("Run the pluto middleware client"),
        );
        assert_eq!(
            run.get_long_about().map(ToString::to_string).as_deref(),
            Some(
                "Starts the long-running Pluto middleware process to perform distributed validator duties."
            ),
        );
    }

    #[test]
    fn unsafe_parent_is_hidden_with_rebranded_help() {
        let unsafe_cmd = subcommand("unsafe");
        assert!(unsafe_cmd.is_hide_set());
        assert_eq!(
            unsafe_cmd.get_about().map(ToString::to_string).as_deref(),
            Some("Unsafe subcommands provides regular pluto commands for testing purposes"),
        );
    }

    #[test]
    fn run_flags_use_charon_env_prefix() {
        let run = subcommand("run");

        for arg in run.get_arguments() {
            let Some(long) = arg.get_long() else { continue };
            if long == "help" {
                continue;
            }

            let expected = format!("CHARON_{}", long.replace('-', "_").to_uppercase());
            let actual = arg.get_env().map(|env| env.to_string_lossy().into_owned());
            assert_eq!(actual.as_deref(), Some(expected.as_str()), "flag --{long}");
        }
    }

    #[test]
    fn run_defaults_match_go() {
        let cli = Cli::try_parse_from([
            "pluto",
            "run",
            "--beacon-node-endpoints",
            "http://beacon.node",
        ])
        .expect("run command should parse");
        let Commands::Run(args) = cli.command else {
            panic!("expected run command");
        };
        let args = *args;

        // Private key.
        assert_eq!(
            args.priv_key.private_key_file,
            ".charon/charon-enr-private-key"
        );
        assert!(!args.priv_key.private_key_file_lock);

        // General.
        let g = &args.general;
        assert_eq!(g.lock_file, ".charon/cluster-lock.json");
        assert_eq!(g.manifest_file, ".charon/cluster-manifest.pb");
        assert_eq!(
            g.beacon_node_endpoints,
            vec!["http://beacon.node".to_string()]
        );
        assert_eq!(
            g.beacon_node_timeout,
            Duration::new(StdDuration::from_secs(2))
        );
        assert_eq!(
            g.beacon_node_submit_timeout,
            Duration::new(StdDuration::from_secs(2))
        );
        assert_eq!(g.validator_api_address, "127.0.0.1:3600");
        assert_eq!(g.jaeger_address, "");
        assert_eq!(g.jaeger_service, "");
        assert_eq!(g.otlp_address, "");
        assert!(!g.otlp_insecure);
        assert_eq!(g.otlp_service_name, "pluto");
        assert!(!g.simnet_beacon_mock);
        assert_eq!(g.simnet_validator_keys_dir, ".charon/validator_keys");
        assert_eq!(
            g.simnet_slot_duration,
            Duration::new(StdDuration::from_secs(1))
        );
        assert_eq!(g.testnet_chain_id, 0);
        assert_eq!(g.testnet_genesis_timestamp, 0);
        assert!(g.graffiti.is_empty());

        // Debug / monitoring.
        assert_eq!(args.debug_monitoring.monitor_addr, "127.0.0.1:3620");
        assert_eq!(args.debug_monitoring.debug_addr, "");

        // No-verify.
        assert!(!args.no_verify);

        // P2P uses Pluto's 5-entry default relay list.
        assert_eq!(
            args.p2p.relays,
            pluto_p2p::config::DEFAULT_RELAYS.map(String::from).to_vec(),
        );
        assert!(args.p2p.tcp_addrs.is_empty());
        assert!(args.p2p.external_ip.is_none());

        // Log.
        assert_eq!(args.log.level, "info");
        assert_eq!(args.log.format, "console");

        // Loki.
        assert_eq!(args.loki.loki_service, "pluto");

        // Feature.
        assert_eq!(args.feature.feature_set, "stable");
        assert!(args.feature.feature_set_enable.is_empty());
        assert!(args.feature.feature_set_disable.is_empty());
    }

    #[test]
    fn run_requires_beacon_addrs() {
        let cli = Cli::try_parse_from(["pluto", "run"]).expect("run command should parse");
        let Commands::Run(args) = cli.command else {
            panic!("expected run command");
        };
        let err = TryInto::<RunConfig>::try_into(*args).expect_err("missing beacon should fail");

        assert_eq!(
            err.to_string(),
            "either flag 'beacon-node-endpoints' or flag 'simnet-beacon-mock=true' must be specified",
        );
    }

    #[test]
    fn run_simnet_beacon_mock_satisfies_beacon_requirement() {
        let cli = Cli::try_parse_from(["pluto", "run", "--simnet-beacon-mock"])
            .expect("run command should parse");
        let Commands::Run(args) = cli.command else {
            panic!("expected run command");
        };

        let config: RunConfig = (*args)
            .try_into()
            .expect("simnet bmock should satisfy beacon req");
        assert!(config.simnet_beacon_mock);
        assert!(config.beacon_node_addrs.is_empty());
    }

    #[test]
    fn run_rejects_invalid_inputs_with_charon_error_strings() {
        // Verbatim error string for each rejected input.
        assert_eq!(
            run_err(&["--nickname", "thisnicknameiswaytoolongandshouldfail"]),
            "flag 'nickname' can not exceed 32 characters",
        );
        assert_eq!(
            run_err(&["--graffiti", "thisgraffitostringiswaytoolongandshouldfail"]),
            "graffiti string length is greater than maximum size",
        );
        assert_eq!(
            run_err(&["--beacon-node-headers", "key1=value1,key2:value2"]),
            "http headers must be comma separated values formatted as header=value",
        );
        assert_eq!(
            run_err(&["--beacon-node-headers", "key1=value1,key2="]),
            "http headers must be comma separated values formatted as header=value",
        );
        assert_eq!(
            run_err(&["--vc-tls-cert-file", "cert.pem"]),
            "both vc-tls-cert-file and vc-tls-key-file must be set or both must be empty",
        );
        assert_eq!(
            run_err(&["--vc-tls-key-file", "cert.key"]),
            "both vc-tls-cert-file and vc-tls-key-file must be set or both must be empty",
        );
        assert_eq!(
            run_err(&[
                "--vc-tls-cert-file",
                "/no/such/cert.pem",
                "--vc-tls-key-file",
                "/no/such/cert.key",
            ]),
            "file vc-tls-cert-file does not exist",
        );
        assert!(
            run_err(&["--p2p-external-hostname", "not a hostname"]).contains("invalid hostname"),
        );
    }

    #[test]
    fn run_accepts_valid_inputs() {
        parse_run(&["--nickname", "validnickname"]).expect("valid nickname");
        parse_run(&["--graffiti", "validgraffiti"]).expect("valid graffiti");
        parse_run(&["--beacon-node-headers", "key1=value1,key2=value2"]).expect("valid headers");
        // An explicit empty external hostname is treated as unset.
        parse_run(&["--p2p-external-hostname", ""]).expect("empty external hostname");
    }

    #[test]
    fn run_loki_config_built_from_addresses() {
        // `--loki-addresses` must produce a Loki layer in the tracing config so
        // `run` spawns/drains the Loki worker (regression for the lifecycle bug
        // where the worker was initialized in `main` and then dropped).
        let config = parse_run(&[
            "--loki-addresses",
            "http://loki.test/push",
            "--loki-service",
            "svc",
        ])
        .expect("config should build");

        let loki = config
            .log
            .loki
            .as_ref()
            .expect("loki layer should be configured");
        assert_eq!(loki.loki_url, "http://loki.test/push");
        assert_eq!(loki.labels.get("service").map(String::as_str), Some("svc"));

        // No `--loki-addresses` → no Loki layer (nothing to spawn).
        assert!(
            parse_run(&[])
                .expect("config should build")
                .log
                .loki
                .is_none()
        );
    }

    #[test]
    fn run_accepts_valid_vc_tls_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("cert.key");
        std::fs::write(&cert, b"cert").expect("write cert");
        std::fs::write(&key, b"key").expect("write key");

        parse_run(&[
            "--vc-tls-cert-file",
            cert.to_str().expect("cert path"),
            "--vc-tls-key-file",
            key.to_str().expect("key path"),
        ])
        .expect("valid cert and key files");
    }

    #[test]
    fn invalid_duration_fails_during_parse() {
        let err = parse_err(&[
            "pluto",
            "run",
            "--beacon-node-endpoints",
            "http://beacon.node",
            "--beacon-node-timeout=not-a-duration",
        ]);

        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn unsafe_run_exposes_p2p_fuzz() {
        let cli = Cli::try_parse_from([
            "pluto",
            "unsafe",
            "run",
            "--p2p-fuzz",
            "--beacon-node-endpoints",
            "http://beacon.node",
        ])
        .expect("unsafe run should parse");

        let Commands::Unsafe(args) = cli.command else {
            panic!("expected unsafe command");
        };
        let UnsafeCommands::Run(args) = args.command;

        let config: RunConfig = (*args).try_into().expect("unsafe config should build");
        assert!(config.p2p_fuzz);
    }

    #[test]
    fn safe_run_rejects_p2p_fuzz() {
        let err = parse_err(&[
            "pluto",
            "run",
            "--p2p-fuzz",
            "--beacon-node-endpoints",
            "http://beacon.node",
        ]);

        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn config_mapping_preserves_fields() {
        let cli = Cli::try_parse_from([
            "pluto",
            "run",
            "--lock-file=/tmp/lock.json",
            "--manifest-file=/tmp/manifest.pb",
            "--beacon-node-endpoints=http://a.node,http://b.node",
            "--beacon-node-timeout=5s",
            "--beacon-node-submit-timeout=6s",
            "--validator-api-address=127.0.0.1:7600",
            "--otlp-service-name=svc",
            "--simnet-slot-duration=3s",
            "--testnet-name=devnet",
            "--testnet-chain-id=1234",
            "--testnet-genesis-timestamp=42",
            "--nickname=node-a",
            "--fallback-beacon-node-endpoints=http://c.node",
            "--execution-client-rpc-endpoint=http://127.0.0.1:8545",
            "--graffiti=hello",
            "--private-key-file=/tmp/key",
            "--private-key-file-lock",
            "--no-verify",
            "--monitoring-address=127.0.0.1:9620",
            "--debug-address=127.0.0.1:9630",
            "--p2p-relays=https://relay.one,/ip4/127.0.0.1/tcp/9000",
            "--p2p-tcp-address=0.0.0.0:9000",
            "--log-level=debug",
            "--log-color=force",
            "--feature-set=alpha",
            "--feature-set-enable=feat_a,feat_b",
        ])
        .expect("run command should parse");
        let Commands::Run(args) = cli.command else {
            panic!("expected run command");
        };

        let config: RunConfig = (*args).try_into().expect("config should build");

        assert_eq!(config.lock_file, "/tmp/lock.json");
        assert_eq!(config.manifest_file, "/tmp/manifest.pb");
        assert_eq!(
            config.beacon_node_addrs,
            vec!["http://a.node".to_string(), "http://b.node".to_string()]
        );
        assert_eq!(config.beacon_node_timeout, StdDuration::from_secs(5));
        assert_eq!(config.beacon_node_submit_timeout, StdDuration::from_secs(6));
        assert_eq!(config.validator_api_addr, "127.0.0.1:7600");
        assert_eq!(config.otlp_service_name, "svc");
        assert_eq!(config.simnet_slot_duration, StdDuration::from_secs(3));
        assert_eq!(config.testnet.name, "devnet");
        assert_eq!(config.testnet.chain_id, 1234);
        assert_eq!(config.testnet.genesis_timestamp, 42);
        assert_eq!(config.nickname, "node-a");
        assert_eq!(
            config.fallback_beacon_node_addrs,
            vec!["http://c.node".to_string()]
        );
        assert_eq!(config.execution_engine_addr, "http://127.0.0.1:8545");
        assert_eq!(config.graffiti, vec!["hello".to_string()]);
        assert_eq!(config.private_key_file, "/tmp/key");
        assert!(config.private_key_locking);
        assert!(config.no_verify);
        assert_eq!(config.monitoring_addr, "127.0.0.1:9620");
        assert_eq!(config.debug_addr, "127.0.0.1:9630");
        assert_eq!(config.p2p.relays.len(), 2);
        assert_eq!(config.p2p.tcp_addrs, vec!["0.0.0.0:9000".to_string()]);
        assert_eq!(config.feature.min_status, "alpha");
        assert_eq!(
            config.feature.enabled,
            vec!["feat_a".to_string(), "feat_b".to_string()]
        );
        // p2p_fuzz is never set on the safe `run` path.
        assert!(!config.p2p_fuzz);
        // `--log-color=force` forces ANSI on the console layer.
        let console = config.log.console.as_ref().expect("console config");
        assert!(console.with_ansi);
        assert_eq!(config.log.override_env_filter.as_deref(), Some("debug"));
    }

    #[tokio::test]
    #[should_panic(expected = "not implemented: pluto run")]
    async fn run_stub_panics_unimplemented() {
        let config = parse_run(&[]).expect("config should build");
        let _ = run(config, CancellationToken::new()).await;
    }
}
