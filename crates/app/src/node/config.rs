//! Configuration for the distributed-validator node.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use pluto_featureset::FeatureSet;
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

    /// Enable the in-process simnet mock beacon node. When set, the beacon
    /// clients target an internal `BeaconMock` seeded with the cluster's
    /// validators instead of `beacon_node_addrs`, and empty beacon endpoints
    /// are permitted. Mirrors Charon's `--simnet-beacon-mock`.
    pub simnet_beacon_mock: bool,

    /// Enable the in-process simnet mock validator client. It loads share
    /// keystores from [`Self::simnet_validator_keys_dir`] and drives this
    /// node's own validator API. Requires [`Self::simnet_beacon_mock`].
    /// Mirrors Charon's `--simnet-validator-mock`.
    pub simnet_validator_mock: bool,

    /// Configure the simnet beacon mock to return fuzzed responses. Mirrors
    /// Charon's `--simnet-beacon-mock-fuzz`.
    pub simnet_beacon_mock_fuzz: bool,

    /// Slot duration for the simnet beacon mock. Mirrors Charon's
    /// `--simnet-slot-duration` (Charon default: 1s).
    pub simnet_slot_duration: Duration,

    /// Directory containing the simnet validator key shares (EIP-2335
    /// keystores plus their password files), loaded when
    /// [`Self::simnet_validator_mock`] is set. Mirrors Charon's
    /// `--simnet-validator-keys-dir`.
    pub simnet_validator_keys_dir: PathBuf,
}
