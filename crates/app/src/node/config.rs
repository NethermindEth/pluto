//! Configuration for the distributed-validator node.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use pluto_featureset::FeatureSet;
use pluto_p2p::config::P2PConfig;

/// Application configuration for running a distributed-validator node.
///
/// This is the Rust analog of Charon's `app.Config` (`app/app.go`), reduced to
/// the minimal set required to wire and run the core duty workflow.
/// Observability (monitoring/debug API, tracing/OTLP) and simnet/mock-only
/// fields are intentionally omitted for the minimal-runnable wiring.
// TODO(#402 part B): add monitoring/debug addrs, OTLP/Jaeger tracing config,
// simnet (beacon/validator mock) and `TestConfig`-style overrides.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// P2P networking configuration (listen/advertise addresses, relays, ...).
    pub p2p: P2PConfig,

    /// Path to the cluster lock file (`cluster-lock.json`).
    pub lock_file: PathBuf,

    /// Optional path to the cluster manifest file. Takes precedence over
    /// `lock_file` when present, mirroring Charon's `ManifestFile`.
    pub manifest_file: Option<PathBuf>,

    /// Path to the node's secp256k1 P2P private key.
    pub priv_key_file: PathBuf,

    /// Beacon node API endpoints. The first reachable endpoint is used;
    /// multiple addresses enable fallback.
    pub beacon_node_addrs: Vec<String>,

    /// Timeout for general beacon node requests.
    pub beacon_node_timeout: Duration,

    /// Timeout for beacon node submission (broadcast) requests.
    pub beacon_node_submit_timeout: Duration,

    /// Address the validator API HTTP server binds to.
    pub validator_api_addr: SocketAddr,

    /// Data directory for node state.
    pub data_dir: PathBuf,

    /// Whether the builder API (MEV-boost) is enabled.
    pub builder_api: bool,

    /// Target gas limit advertised for validator registrations. When zero, the
    /// value from the cluster lock is used.
    pub target_gas_limit: u64,

    /// Human-readable node nickname, surfaced via the peerinfo protocol.
    pub nickname: String,

    /// Skip cluster lock hash + signature verification.
    pub no_verify: bool,

    /// Execution-layer (eth1) JSON-RPC endpoint, used to verify operator
    /// signatures (including EIP-1271 smart-contract signatures) in the cluster
    /// lock. When `None`, lock verification runs without eth1 and such operator
    /// signatures are not checked. Mirrors Charon's
    /// `--execution-client-rpc-endpoint`.
    pub eth1_endpoint: Option<String>,

    /// Graffiti included in proposed blocks. `None` gives every validator the
    /// default (client) graffiti; a single value applies to all validators; one
    /// value per validator otherwise. Mirrors Charon's `--graffiti`.
    pub graffiti: Option<Vec<String>>,

    /// Disable appending the client version/codex to graffiti. Mirrors Charon's
    /// `--graffiti-disable-client-append`.
    pub graffiti_disable_client_append: bool,

    /// Feature set controlling optional/alpha behaviors (e.g.
    /// `FetchOnlyCommIdx0`, `ChainSplitHalt`). Resolved from the CLI
    /// feature flags (out of scope here).
    pub feature_set: Arc<FeatureSet>,
}
