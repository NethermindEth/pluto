use std::{num::NonZeroU32, path::PathBuf, time::Duration};

use bon::Builder;
use libp2p::relay;
use pluto_p2p::config::P2PConfig;
use pluto_tracing::TracingConfig;

/// One hour in seconds.
pub const ONE_HOUR_SECONDS: u64 = 60 * 60;
/// One minute in seconds.
pub const ONE_MINUTE_SECONDS: u64 = 60;
/// 32 MB in bytes.
pub const MB_32: u64 = 32 * 1024 * 1024;
/// Per-IP reservation rate limit (token-bucket capacity).
///
/// rust-libp2p's relay has no per-IP reservation *count* cap (unlike Charon's
/// go-libp2p `MaxReservationsPerIP`), so we mirror Charon's intent with the
/// per-IP reservation *rate* limiter instead. `relay::Config::default()` uses
/// 60 reservations / minute per IP; we keep that default capacity as the
/// fallback when the operator leaves `max_res_per_peer` at 0.
pub const RESERVATIONS_PER_IP_PER_MINUTE: u32 = 60;
/// External host resolve interval.
pub const EXTERNAL_HOST_RESOLVE_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Configuration for the relay P2P layer.
#[derive(Default, Debug, Clone, Builder)]
pub struct Config {
    /// The directory to store the relay data.
    #[builder(default = ".charon".into())]
    pub data_dir: PathBuf,
    /// The HTTP address to listen on.
    pub http_addr: Option<String>,
    /// The monitoring address to listen on.
    pub monitoring_addr: Option<String>,
    /// The debug address to listen on.
    pub debug_addr: Option<String>,
    /// The P2P configuration.
    pub p2p_config: P2PConfig,
    /// The logging configuration.
    #[builder(default)]
    pub log_config: TracingConfig,
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
    // Start from rust-libp2p defaults so the per-peer and per-IP reservation /
    // circuit-source rate limiters are preserved (they guard against
    // reservation/circuit floods from a single peer or IP). The defaults are:
    //   - reservation  per-peer: 30 / 2min   - reservation  per-IP: 60 / 1min
    //   - circuit-src  per-peer: 30 / 2min   - circuit-src  per-IP: 60 / 1min
    // We only override the count / duration / byte limits below, matching
    // Charon's `relay.DefaultResources()` + selective overrides
    // (charon@v1.7.1 cmd/relay/p2p.go:61-67).
    let relay_config = relay::Config {
        max_reservations: config.max_conns,
        max_reservations_per_peer: config.max_res_per_peer,
        reservation_duration: Duration::from_secs(ONE_HOUR_SECONDS),
        max_circuits: config.max_res_per_peer,
        max_circuits_per_peer: config.max_res_per_peer,
        max_circuit_duration: Duration::from_secs(ONE_MINUTE_SECONDS),
        max_circuit_bytes: MB_32,
        // Restore the default rate limiters dropped by the previous
        // struct-literal construction.
        ..relay::Config::default()
    };

    // Charon sets MaxReservationsPerIP = MaxResPerPeer. rust-libp2p has no per-IP
    // reservation *count* cap, so we approximate it with an additional per-IP
    // reservation *rate* limiter sized from `max_res_per_peer` (falling back to
    // the default capacity when the operator leaves it at 0). This appends a
    // second per-IP reservation limiter on top of the default one; both must
    // pass, so the effective per-IP rate becomes min(60/min, max_res_per_peer/min).
    let per_ip_limit = u32::try_from(config.max_res_per_peer)
        .ok()
        .and_then(NonZeroU32::new)
        .unwrap_or_else(|| NonZeroU32::new(RESERVATIONS_PER_IP_PER_MINUTE).expect("60 > 0"));

    relay_config.reservation_rate_per_ip(per_ip_limit, Duration::from_secs(ONE_MINUTE_SECONDS))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(max_conns: usize, max_res_per_peer: usize) -> Config {
        Config::builder()
            .p2p_config(P2PConfig::default())
            .max_conns(max_conns)
            .max_res_per_peer(max_res_per_peer)
            .build()
    }

    #[test]
    fn restored_rate_limiters_present() {
        let relay_config = create_relay_config(&test_config(64, 8));
        // 2 default reservation limiters (per-peer, per-IP) + 1 added per-IP.
        assert_eq!(relay_config.reservation_rate_limiters.len(), 3);
        // 2 default circuit-src limiters (per-peer, per-IP) preserved.
        assert_eq!(relay_config.circuit_src_rate_limiters.len(), 2);
    }

    #[test]
    fn count_limits_from_config() {
        let relay_config = create_relay_config(&test_config(64, 8));
        assert_eq!(relay_config.max_reservations, 64);
        assert_eq!(relay_config.max_reservations_per_peer, 8);
        assert_eq!(relay_config.max_circuits, 8);
        assert_eq!(relay_config.max_circuits_per_peer, 8);
        assert_eq!(
            relay_config.reservation_duration,
            Duration::from_secs(ONE_HOUR_SECONDS)
        );
        assert_eq!(
            relay_config.max_circuit_duration,
            Duration::from_secs(ONE_MINUTE_SECONDS)
        );
        assert_eq!(relay_config.max_circuit_bytes, MB_32);
    }

    #[test]
    fn zero_max_res_per_peer_uses_default_per_ip_capacity() {
        // max_res_per_peer = 0 must not panic (NonZeroU32 fallback path) and
        // still yields the restored + added reservation rate limiters.
        let relay_config = create_relay_config(&test_config(64, 0));
        assert_eq!(relay_config.reservation_rate_limiters.len(), 3);
    }
}
