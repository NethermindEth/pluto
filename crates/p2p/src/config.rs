//! # Charon P2P Configuration

use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use libp2p::{Multiaddr, multiaddr, ping};

/// Shared default relay endpoints used by commands and P2P-facing configs.
pub const DEFAULT_RELAYS: [&str; 3] = [
    "https://0.relay.obol.tech",
    "https://2.relay.obol.dev",
    "https://1.relay.obol.tech",
];

/// P2P configuration error.
#[derive(Debug, thiserror::Error)]
pub enum P2PConfigError {
    /// Failed to parse the TCP addresses.
    #[error("Failed to parse the TCP addresses")]
    FailedToParseTcpAddresses(std::net::AddrParseError),

    /// Failed to parse the UDP addresses.
    #[error("Failed to parse the UDP addresses")]
    FailedToParseUdpAddresses(std::net::AddrParseError),

    /// Failed to parse the multiaddress.
    #[error("Failed to parse the multiaddress")]
    FailedToParseMultiaddr(#[from] multiaddr::Error),
}

// Note: this is only for testing purposes!
#[cfg(test)]
impl PartialEq for P2PConfigError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                P2PConfigError::FailedToParseTcpAddresses(x),
                P2PConfigError::FailedToParseTcpAddresses(y),
            ) if x == y => true,
            (
                P2PConfigError::FailedToParseUdpAddresses(x),
                P2PConfigError::FailedToParseUdpAddresses(y),
            ) if x == y => true,
            (
                P2PConfigError::FailedToParseMultiaddr(x),
                P2PConfigError::FailedToParseMultiaddr(y),
            ) if x.to_string() == y.to_string() => true,
            _ => false,
        }
    }
}

type Result<T> = std::result::Result<T, P2PConfigError>;

/// P2P configuration.
#[derive(Debug, Clone, Default)]
pub struct P2PConfig {
    /// Defines the libp2p relay multiaddrs or URLs.
    pub relays: Vec<Multiaddr>,

    /// The external IP address of the node.
    pub external_ip: Option<String>,

    /// The external host of the node.
    pub external_host: Option<String>,

    /// The TCP addresses of the node.
    pub tcp_addrs: Vec<String>,

    /// The UDP addresses of the node.
    pub udp_addrs: Vec<String>,

    /// Whether to disable the reuse port.
    pub disable_reuse_port: bool,
}

impl P2PConfig {
    /// Returns the TCP addresses of the node.
    pub fn parse_tcp_addrs(&self) -> Result<Vec<SocketAddr>> {
        self.tcp_addrs.iter().map(resolve_listen_tcp_addr).collect()
    }

    /// Returns the UDP addresses of the node.
    pub fn parse_udp_addrs(&self) -> Result<Vec<SocketAddr>> {
        self.udp_addrs.iter().map(resolve_listen_udp_addr).collect()
    }

    /// Returns the UDP multiaddresses of the node.
    pub fn udp_multiaddrs(&self) -> Result<Vec<Multiaddr>> {
        let addrs = self.parse_udp_addrs()?;

        addrs.into_iter().map(multi_addr_from_ip_udp_port).collect()
    }

    /// Returns the TCP multiaddresses of the node.
    pub fn tcp_multiaddrs(&self) -> Result<Vec<Multiaddr>> {
        let addrs = self.parse_tcp_addrs()?;

        addrs.into_iter().map(multi_addr_from_ip_tcp_port).collect()
    }

    /// Returns a new builder for configuring a P2P configuration.
    pub fn builder() -> P2PConfigBuilder {
        P2PConfigBuilder::new()
    }
}

/// Returns the default relay endpoints parsed as [`Multiaddr`]s.
pub fn default_relay_multiaddrs() -> Vec<Multiaddr> {
    DEFAULT_RELAYS
        .iter()
        .map(|relay| multiaddr::from_url(relay).expect("default relay should parse"))
        .collect()
}

/// Builder for [`P2PConfig`].
#[derive(Default, Debug, Clone)]
pub struct P2PConfigBuilder {
    config: P2PConfig,
}

impl P2PConfigBuilder {
    /// Creates a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: P2PConfig::default(),
        }
    }

    /// Sets the relay multiaddrs.
    pub fn with_relays(mut self, relays: Vec<Multiaddr>) -> Self {
        self.config.relays = relays;
        self
    }

    /// Sets the external IP address.
    pub fn with_external_ip(mut self, external_ip: String) -> Self {
        self.config.external_ip = Some(external_ip);
        self
    }

    /// Sets the external host.
    pub fn with_external_host(mut self, external_host: String) -> Self {
        self.config.external_host = Some(external_host);
        self
    }

    /// Sets the TCP addresses.
    pub fn with_tcp_addrs(mut self, tcp_addrs: Vec<String>) -> Self {
        self.config.tcp_addrs = tcp_addrs;
        self
    }

    /// Sets the UDP addresses.
    pub fn with_udp_addrs(mut self, udp_addrs: Vec<String>) -> Self {
        self.config.udp_addrs = udp_addrs;
        self
    }

    /// Sets whether to disable the reuse port.
    pub fn with_disable_reuse_port(mut self, disable_reuse_port: bool) -> Self {
        self.config.disable_reuse_port = disable_reuse_port;
        self
    }

    /// Builds the [`P2PConfig`].
    pub fn build(self) -> P2PConfig {
        self.config
    }
}

/// The default ping interval.
pub const DEFAULT_PING_INTERVAL: Duration = Duration::from_secs(1);
/// The default ping timeout.
pub const DEFAULT_PING_TIMEOUT: Duration = Duration::from_secs(10);

/// Returns the default ping configuration.
pub fn default_ping_config() -> ping::Config {
    ping::Config::new()
        .with_interval(DEFAULT_PING_INTERVAL)
        .with_timeout(DEFAULT_PING_TIMEOUT)
}

/// Resolves a TCP address string to a [`SocketAddr`].
fn resolve_listen_tcp_addr(addr: impl AsRef<str>) -> Result<SocketAddr> {
    let socket_addr: SocketAddr = addr
        .as_ref()
        .parse()
        .map_err(P2PConfigError::FailedToParseTcpAddresses)?;

    Ok(socket_addr)
}

/// Resolves a UDP address string to a [`SocketAddr`].
fn resolve_listen_udp_addr(addr: impl AsRef<str>) -> Result<SocketAddr> {
    let socket_addr: SocketAddr = addr
        .as_ref()
        .parse()
        .map_err(P2PConfigError::FailedToParseUdpAddresses)?;

    Ok(socket_addr)
}

pub(crate) fn multi_addr_from_ip_udp_port(socket_addr: SocketAddr) -> Result<Multiaddr> {
    let typ = match socket_addr.ip() {
        IpAddr::V4(_) => "ip4",
        IpAddr::V6(_) => "ip6",
    };

    Multiaddr::from_str(&format!(
        "/{}/{}/udp/{}/quic-v1",
        typ,
        socket_addr.ip(),
        socket_addr.port()
    ))
    .map_err(P2PConfigError::FailedToParseMultiaddr)
}

pub(crate) fn multi_addr_from_ip_tcp_port(socket_addr: SocketAddr) -> Result<Multiaddr> {
    let typ = match socket_addr.ip() {
        IpAddr::V4(_) => "ip4",
        IpAddr::V6(_) => "ip6",
    };

    Multiaddr::from_str(&format!(
        "/{}/{}/tcp/{}",
        typ,
        socket_addr.ip(),
        socket_addr.port()
    ))
    .map_err(P2PConfigError::FailedToParseMultiaddr)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn resolve_listen_addr_p2p_bind_tcp_ip_not_specified() {
        let err = resolve_listen_tcp_addr(":1234").unwrap_err();
        assert!(matches!(err, P2PConfigError::FailedToParseTcpAddresses(_)));
    }

    #[test]
    fn resolve_listen_addr_ip() {
        let addr = resolve_listen_tcp_addr("10.4.3.3:1234").unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 4, 3, 3)), 1234)
        );
    }

    #[test]
    fn resolve_listen_addr_all_interfaces() {
        let tcp_addr = resolve_listen_tcp_addr("0.0.0.0:0").unwrap();
        assert_eq!(
            tcp_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
        );

        let udp_addr = resolve_listen_udp_addr("0.0.0.0:0").unwrap();
        assert_eq!(
            udp_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
        );
    }

    #[test]
    fn config_multiaddrs() {
        let ipv6_linklocal_all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

        let config = P2PConfig {
            tcp_addrs: vec![
                "10.0.0.2:0".to_string(),
                format!("[{}]:0", ipv6_linklocal_all_nodes),
            ],
            udp_addrs: vec![
                "10.0.0.2:0".to_string(),
                format!("[{}]:0", ipv6_linklocal_all_nodes),
            ],
            ..Default::default()
        };

        let tcp_multiaddrs = config.tcp_multiaddrs().unwrap();
        let udp_multiaddrs = config.udp_multiaddrs().unwrap();

        let tcp_addrs_str = tcp_multiaddrs
            .iter()
            .map(|addr| addr.to_string())
            .collect::<Vec<String>>();
        let udp_addrs_str = udp_multiaddrs
            .iter()
            .map(|addr| addr.to_string())
            .collect::<Vec<String>>();

        let merged_addrs_str = tcp_addrs_str
            .into_iter()
            .chain(udp_addrs_str)
            .collect::<Vec<String>>();

        let expected_addrs_str = vec![
            "/ip4/10.0.0.2/tcp/0",
            "/ip6/ff02::1/tcp/0",
            "/ip4/10.0.0.2/udp/0/quic-v1",
            "/ip6/ff02::1/udp/0/quic-v1",
        ];

        assert_eq!(merged_addrs_str, expected_addrs_str);
    }

    #[test]
    fn config_invalid_multiaddrs() {
        let config = P2PConfig {
            tcp_addrs: vec!["not_a_valid_addr".to_string()],
            ..Default::default()
        };

        assert!(config.tcp_multiaddrs().is_err());
    }
}
