//! # Charon P2P Configuration

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use libp2p::{Multiaddr, multiaddr, ping};
use url::Url;

/// Shared default relay endpoints used by commands and P2P-facing configs.
pub const DEFAULT_RELAYS: [&str; 5] = [
    "https://pluto-relay-0.ovh.dev-nethermind.xyz",
    "https://pluto-relay-1.ovh.dev-nethermind.xyz",
    "https://0.relay.obol.tech",
    "https://2.relay.obol.dev",
    "https://1.relay.obol.tech",
];

/// Relay address parse error.
#[derive(Debug, thiserror::Error)]
pub enum RelayAddrError {
    /// The address is empty.
    #[error("empty relay address")]
    Empty,

    /// The `http`-prefixed address is not a valid URL.
    #[error("invalid relay url: {0}")]
    Url(#[source] url::ParseError),

    /// The URL scheme is neither `http` nor `https`.
    #[error("invalid relay url scheme {0:?}, want http or https")]
    Scheme(String),

    /// The address is not a valid libp2p multiaddr.
    #[error("invalid relay multiaddr: {0}")]
    Multiaddr(#[source] multiaddr::Error),
}

/// A configured libp2p relay address.
///
/// A relay is given either as an HTTP(S) endpoint, whose ENR is resolved in the
/// background, or as a libp2p multiaddr that is dialed directly. Modelling that
/// split in the type keeps URL paths intact — a multiaddr cannot represent one,
/// so `http://relay:3640/enr` would otherwise be rejected outright or silently
/// truncated to `http://relay:3640`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAddr {
    /// An HTTP(S) endpoint serving the relay's ENR or multiaddrs.
    ///
    /// [`FromStr`] guarantees an `http`/`https` scheme, but the variant is
    /// publicly constructible, so consumers re-check it rather than relying on
    /// the invariant.
    Url(Url),

    /// A raw libp2p multiaddr, dialed directly.
    Multiaddr(Multiaddr),
}

impl RelayAddr {
    /// Returns true for a plain-`http://` URL, i.e. one whose ENR is fetched
    /// over an unencrypted connection.
    ///
    /// Always false for a [`RelayAddr::Multiaddr`]: only the HTTP resolution
    /// step is at issue here, so a directly dialed relay is never reported as
    /// insecure regardless of the transport it names.
    pub fn is_insecure_url(&self) -> bool {
        matches!(self, Self::Url(url) if url.scheme() != "https")
    }
}

impl FromStr for RelayAddr {
    type Err = RelayAddrError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // The multiaddr parser accepts "" as a zero-component `Multiaddr`, so
        // reject it up front: an empty address must not masquerade as a
        // dialable relay.
        if s.is_empty() {
            return Err(RelayAddrError::Empty);
        }

        // Dispatch on the literal `http` prefix rather than probing both
        // parsers, so classification here matches how the address is later
        // consumed.
        if s.starts_with("http") {
            let url = Url::parse(s).map_err(RelayAddrError::Url)?;

            if !matches!(url.scheme(), "http" | "https") {
                return Err(RelayAddrError::Scheme(url.scheme().to_owned()));
            }

            return Ok(Self::Url(url));
        }

        s.parse()
            .map(Self::Multiaddr)
            .map_err(RelayAddrError::Multiaddr)
    }
}

impl fmt::Display for RelayAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url(url) => url.fmt(f),
            Self::Multiaddr(addr) => addr.fmt(f),
        }
    }
}

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
    pub relays: Vec<RelayAddr>,

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

/// Returns the default relay endpoints parsed as [`RelayAddr`]s.
pub fn default_relays() -> Vec<RelayAddr> {
    DEFAULT_RELAYS
        .iter()
        .map(|relay| relay.parse().expect("default relay should parse"))
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
    pub fn with_relays(mut self, relays: Vec<RelayAddr>) -> Self {
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
    fn relay_addr_parses_url_and_multiaddr_forms() {
        // A path (and query) must survive parsing: `http://relay:3640/enr` is a
        // supported relay address, and no multiaddr can express it.
        let cases = [
            "http://relay:3640/enr",
            "https://relay.example.org/enr",
            "https://relay.example.org/enr?cluster=abc",
            "/ip4/10.0.0.1/tcp/3610/p2p/16Uiu2HAm7ULrTMdiEmQCJ2N9nsuGvfUDvfDGgHXJ4vNjrCwCzGDs",
            "/dns/relay.example.org/tcp/443/p2p/16Uiu2HAm7ULrTMdiEmQCJ2N9nsuGvfUDvfDGgHXJ4vNjrCwCzGDs",
        ];
        for case in cases {
            let addr: RelayAddr = case.parse().expect("relay addr should parse");
            assert_eq!(addr.to_string(), case, "{case} should round-trip");
        }

        // A host-only URL round-trips with the root path the `url` crate
        // normalises it to; the request it produces is identical.
        let addr: RelayAddr = "http://relay:3640"
            .parse()
            .expect("relay addr should parse");
        assert_eq!(addr.to_string(), "http://relay:3640/");
    }

    #[test]
    fn relay_addr_flags_insecure_urls() {
        let insecure: RelayAddr = "http://relay:3640/enr".parse().expect("relay addr");
        assert!(insecure.is_insecure_url());

        let secure: RelayAddr = "https://relay:3640/enr".parse().expect("relay addr");
        assert!(!secure.is_insecure_url());

        let multiaddr: RelayAddr = "/ip4/10.0.0.1/tcp/3610".parse().expect("relay addr");
        assert!(!multiaddr.is_insecure_url());
    }

    #[test]
    fn relay_addr_rejects_invalid_forms() {
        // `http`-prefixed but not a URL: the prefix dispatch classifies it as a
        // URL, so it is rejected as one.
        assert!(matches!(
            "httpfoo".parse::<RelayAddr>(),
            Err(RelayAddrError::Url(_))
        ));
        assert!(matches!(
            "https://".parse::<RelayAddr>(),
            Err(RelayAddrError::Url(_))
        ));

        // `http`-prefixed and a valid URL, but not an HTTP(S) one.
        assert!(matches!(
            "httpx://relay.example.org".parse::<RelayAddr>(),
            Err(RelayAddrError::Scheme(scheme)) if scheme == "httpx"
        ));

        // Everything else must be a multiaddr — including other URL schemes,
        // which never reach the scheme check.
        assert!(matches!(
            "ftp://relay.example.org".parse::<RelayAddr>(),
            Err(RelayAddrError::Multiaddr(_))
        ));
        assert!(matches!(
            "not-an-address".parse::<RelayAddr>(),
            Err(RelayAddrError::Multiaddr(_))
        ));

        // The multiaddr parser accepts "" as a zero-component multiaddr, so an
        // empty address needs its own guard.
        assert!(matches!(
            "".parse::<RelayAddr>(),
            Err(RelayAddrError::Empty)
        ));
        assert!("".parse::<Multiaddr>().is_ok(), "guard is still needed");
    }

    #[test]
    fn relay_addr_error_exposes_its_cause() {
        let err = "not-an-address"
            .parse::<RelayAddr>()
            .expect_err("should not parse");

        // The message is self-contained, and the typed cause stays reachable
        // through the error chain.
        assert!(err.to_string().starts_with("invalid relay multiaddr:"));
        assert!(
            std::error::Error::source(&err)
                .expect("source")
                .downcast_ref::<multiaddr::Error>()
                .is_some()
        );
    }

    #[test]
    fn default_relays_parse() {
        let relays = default_relays();

        assert_eq!(relays.len(), DEFAULT_RELAYS.len());
        assert!(relays.iter().all(|relay| !relay.is_insecure_url()));
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
