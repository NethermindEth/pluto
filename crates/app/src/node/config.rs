//! Configuration for the distributed-validator node.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use pluto_p2p::config::P2PConfig;

/// Application configuration for running a distributed-validator node.
///
/// Reduced to the minimal set required to wire and run the core duty workflow
/// plus the monitoring API and simnet mocks. Debug/pprof API and OTLP/Jaeger
/// tracing fields are intentionally omitted for the minimal-runnable wiring.
// TODO(#402 part B): add debug/pprof addr, OTLP/Jaeger tracing config, and
// test-injection overrides.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// P2P networking configuration (listen/advertise addresses, relays, ...).
    pub p2p: P2PConfig,

    /// Path to the cluster lock file (`cluster-lock.json`).
    pub lock_file: PathBuf,

    /// Path to the node's secp256k1 P2P private key.
    pub priv_key_file: PathBuf,

    /// Enable private-key file locking. When set, a
    /// `<priv_key_file>.lock`sentinel is maintained for the node's lifetime to
    /// detect a second node started against the same key.
    pub priv_key_locking: bool,

    /// Beacon node API endpoints. The first reachable endpoint is used;
    /// multiple addresses enable fallback.
    pub beacon_node_addrs: Vec<String>,

    /// Timeout for general beacon node requests.
    pub beacon_node_timeout: Duration,

    /// Timeout for beacon node submission (broadcast) requests.
    pub beacon_node_submit_timeout: Duration,

    /// Address the validator API HTTP server binds to.
    pub validator_api_addr: SocketAddr,

    /// Address the monitoring API HTTP server binds to. Serves the Prometheus
    /// `/metrics` scrape endpoint plus the `/livez` and `/readyz` health
    /// probes.
    pub monitoring_addr: SocketAddr,

    /// Whether the builder API (MEV-boost) is enabled.
    pub builder_api: bool,

    /// Path to the builder-registration overrides file. When the file exists,
    /// its registrations replace the cluster lock's for any validator where
    /// they are strictly newer, letting an operator change a fee recipient
    /// without a new lock. Watched for changes at runtime.
    pub builder_reg_overrides_file: Option<PathBuf>,

    /// Obol API base URL, used for background fee-recipient fetching.
    pub publish_address: Option<String>,

    /// Timeout for Obol API requests.
    pub publish_timeout: Duration,

    /// Whether to fetch updated fee recipients from the Obol API. Off by
    /// default: it makes the node depend on an external service for
    /// configuration it can otherwise read from the lock.
    pub fetch_feerecipient_updates: bool,

    /// Human-readable node nickname, surfaced via the peerinfo protocol.
    pub nickname: String,

    /// Skip cluster lock hash + signature verification.
    pub no_verify: bool,

    /// Execution-layer (eth1) JSON-RPC endpoint, used to verify operator
    /// signatures (including EIP-1271 smart-contract signatures) in the cluster
    /// lock. When `None`, lock verification runs without eth1 and such operator
    /// signatures are not checked.
    pub eth1_endpoint: Option<String>,

    /// Graffiti included in proposed blocks. `None` gives every validator the
    /// default (client) graffiti; a single value applies to all validators; one
    /// value per validator otherwise.
    pub graffiti: Option<Vec<String>>,

    /// Disable appending the client version/codex to graffiti.
    pub graffiti_disable_client_append: bool,

    /// Feature-set configuration for optional/alpha capabilities (e.g.
    /// `FetchOnlyCommIdx0`, `ChainSplitHalt`) and chain-specific behavior
    /// (e.g. `GnosisBlockHotfix`), resolved into a `FeatureSet`.
    pub feature_set: pluto_featureset::Config,

    /// Enable the in-process simnet mock beacon node. When set, the beacon
    /// clients target an internal `BeaconMock` seeded with the cluster's
    /// validators instead of `beacon_node_addrs`, and empty beacon endpoints
    /// are permitted.
    pub simnet_beacon_mock: bool,

    /// Enable the in-process simnet mock validator client. It loads share
    /// keystores from [`Self::simnet_validator_keys_dir`] and drives this
    /// node's own validator API. Requires [`Self::simnet_beacon_mock`].
    pub simnet_validator_mock: bool,

    /// Configure the simnet beacon mock to return fuzzed responses.
    pub simnet_beacon_mock_fuzz: bool,

    /// Slot duration for the simnet beacon mock (default: 1s).
    pub simnet_slot_duration: Duration,

    /// Directory containing the simnet validator key shares (EIP-2335
    /// keystores plus their password files), loaded when
    /// [`Self::simnet_validator_mock`] is set.
    pub simnet_validator_keys_dir: PathBuf,
}
