use std::{path::PathBuf, time::Duration};

use bon::Builder;
use pluto_p2p::config::P2PConfig;
use libp2p::relay;
use pluto_tracing::TracingConfig;

/// One hour in seconds.
pub const ONE_HOUR_SECONDS: u64 = 60 * 60;
/// One minute in seconds.
pub const ONE_MINUTE_SECONDS: u64 = 60;
/// 32 MB in bytes.
pub const MB_32: u64 = 32 * 1024 * 1024;
/// External host resolve interval.
pub const EXTERNAL_HOST_RESOLVE_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Configuration for the relay P2P layer.
#[derive(Default, Debug, Clone, Builder)]
pub struct Config {
    /// The directory to store the relay data.
    pub data_dir: Option<PathBuf>,
    /// The HTTP address to listen on.
    pub http_addr: Option<String>,
    /// The monitoring address to listen on.
    pub monitoring_addr: Option<String>,
    /// The debug address to listen on.
    pub debug_addr: Option<String>,
    /// The P2P configuration.
    pub p2p_config: P2PConfig,
    /// The logging configuration.
    pub log_config: Option<TracingConfig>,
    /// Whether to automatically generate a P2P key.
    #[builder(default = false)]
    pub auto_p2p_key: bool,
    /// The maximum number of resources per peer.
    pub max_res_per_peer: usize,
    /// The maximum number of connections.
    pub max_conns: usize,
    /// Whether to filter private addresses.
    #[builder(default = false)]
    pub filter_private_addrs: bool,
    /// LibP2PLogLevel.
    #[builder(default = "Info".to_string())]
    pub libp2p_log_level: String,
}

pub(crate) fn create_relay_config(config: &Config) -> relay::Config {
    relay::Config {
        max_reservations: config.max_conns,
        max_reservations_per_peer: config.max_res_per_peer,
        reservation_duration: Duration::from_secs(ONE_HOUR_SECONDS),
        reservation_rate_limiters: vec![],
        // todo(varex83): check if this is correct, since it's aligned with the original
        // implementation, but I'm not sure if it's the correct way to do it.
        // Would it be better to use max_res_per_peer * max_conns?
        max_circuits: config.max_res_per_peer,
        max_circuits_per_peer: config.max_res_per_peer,
        max_circuit_duration: Duration::from_secs(ONE_MINUTE_SECONDS),
        max_circuit_bytes: MB_32,
        circuit_src_rate_limiters: vec![],
    }
}
