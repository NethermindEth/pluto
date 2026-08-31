//! Internal utilities for P2P networking.
//!
//! This module provides helper functions for:
//! - Converting external IP/hostname configuration to multiaddresses
//! - Filtering advertised addresses based on privacy settings
//! - Default libp2p configuration (swarm, TCP)
//! - Cryptographic key conversion between k256 and libp2p formats
//!
//! These utilities are primarily used internally by the [`crate::p2p`] module.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use libp2p::{
    Multiaddr,
    identity::Keypair,
    multiaddr::{self, Protocol as MaProtocol},
};

use crate::metrics::{ConnectionType, Protocol};

use crate::{
    config::{self, P2PConfig},
    manet::Manet,
};

/// Returns the external IP and Hostname fields as TCP multiaddrs on `ports`.
///
/// `ports` must be the ports the node actually listens on: a configured port of
/// 0 means the kernel picks one, so the configured value would advertise
/// nothing dialable.
fn external_tcp_multiaddrs(cfg: &P2PConfig, ports: &[u16]) -> crate::p2p::Result<Vec<Multiaddr>> {
    let mut resp = vec![];

    if let Some(external_ip) = cfg.external_ip.as_ref() {
        let ip = external_ip.parse::<IpAddr>()?;

        for port in ports {
            let maddr = config::multi_addr_from_ip_tcp_port(SocketAddr::new(ip, *port))?;

            resp.push(maddr);
        }
    }

    if let Some(external_host) = cfg.external_host.as_ref() {
        for port in ports {
            resp.push(multiaddr::multiaddr!(Dns(external_host), Tcp(*port)));
        }
    }

    Ok(resp)
}

/// Returns the external IP and Hostname fields as QUIC multiaddrs on `ports`.
///
/// `ports` must be the ports the node actually listens on, as in
/// [`external_tcp_multiaddrs`].
fn external_udp_multiaddrs(cfg: &P2PConfig, ports: &[u16]) -> crate::p2p::Result<Vec<Multiaddr>> {
    let mut resp = vec![];

    if let Some(external_ip) = cfg.external_ip.as_ref() {
        let ip = external_ip.parse::<IpAddr>()?;

        for port in ports {
            let maddr = config::multi_addr_from_ip_udp_port(SocketAddr::new(ip, *port))?;

            resp.push(maddr);
        }
    }

    if let Some(external_host) = cfg.external_host.as_ref() {
        for port in ports {
            resp.push(multiaddr::multiaddr!(
                Dns(external_host),
                Udp(*port),
                QuicV1
            ));
        }
    }

    Ok(resp)
}

/// Returns the external IP and Hostname fields as multiaddrs on the ports of
/// `listen_addrs`, TCP forms first.
pub fn external_multiaddrs(
    cfg: &P2PConfig,
    listen_addrs: &[Multiaddr],
) -> crate::p2p::Result<Vec<Multiaddr>> {
    let tcp_ports: Vec<u16> = listen_addrs.iter().filter_map(tcp_port).collect();
    let udp_ports: Vec<u16> = listen_addrs.iter().filter_map(udp_port).collect();

    let mut addrs = external_tcp_multiaddrs(cfg, &tcp_ports)?;
    addrs.extend(external_udp_multiaddrs(cfg, &udp_ports)?);

    Ok(addrs)
}

/// Returns the TCP port of a multiaddr.
pub fn tcp_port(addr: &Multiaddr) -> Option<u16> {
    addr.iter().find_map(|protocol| match protocol {
        MaProtocol::Tcp(port) => Some(port),
        _ => None,
    })
}

/// Returns the UDP port of a multiaddr.
pub fn udp_port(addr: &Multiaddr) -> Option<u16> {
    addr.iter().find_map(|protocol| match protocol {
        MaProtocol::Udp(port) => Some(port),
        _ => None,
    })
}

pub(crate) struct ExternalAddresses(pub Vec<Multiaddr>);

pub(crate) struct InternalAddresses(pub Vec<Multiaddr>);

/// Returns the unique external and internal addresses to advertise, in source
/// order, optionally excluding private internal addresses.
///
/// External addresses are never dropped for being private: they were configured
/// explicitly. Deduplication spans both groups, so an address listed as both
/// external and internal is advertised once.
///
/// Since the type of external and internal addresses is the same, we use type
/// wrappers to avoid confusion.
pub(crate) fn filter_advertised_addresses(
    external_addrs: ExternalAddresses,
    internal_addrs: InternalAddresses,
    exclude_internal_private: bool,
) -> Vec<Multiaddr> {
    let mut seen = HashSet::new();
    let mut advertised = Vec::new();

    let mut add = |addrs: Vec<Multiaddr>, exclude_private: bool| {
        for addr in addrs {
            if !seen.insert(addr.clone()) {
                continue;
            }

            if exclude_private && addr.is_private() {
                continue;
            }

            advertised.push(addr);
        }
    };

    add(external_addrs.0, false);
    add(internal_addrs.0, exclude_internal_private);

    advertised
}

/// Returns the default swarm configuration.
pub(crate) fn default_swarm_config(cfg: libp2p::swarm::Config) -> libp2p::swarm::Config {
    cfg.with_idle_connection_timeout(Duration::from_secs(300))
}

/// Converts a secret key to a libp2p keypair.
pub fn keypair_from_secret_key(key: k256::SecretKey) -> crate::p2p::Result<Keypair> {
    let mut der = key.to_sec1_der()?;
    let keypair = Keypair::secp256k1_from_der(&mut der)?;
    Ok(keypair)
}

/// Returns the connection type (direct or relay) based on the multiaddr.
pub(crate) fn addr_type(addr: &Multiaddr) -> ConnectionType {
    if is_relay_addr(addr) {
        ConnectionType::Relay
    } else {
        ConnectionType::Direct
    }
}

/// Returns the transport protocol (TCP or QUIC) from the multiaddr.
pub(crate) fn addr_protocol(addr: &Multiaddr) -> Protocol {
    if is_quic_addr(addr) {
        Protocol::Quic
    } else if is_tcp_addr(addr) {
        Protocol::Tcp
    } else {
        Protocol::Unknown
    }
}

/// Returns true if the multiaddr contains a p2p-circuit (relay) component.
pub fn is_relay_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, MaProtocol::P2pCircuit))
}

/// Returns true if the multiaddr contains a QUIC or QUIC-v1 component.
pub fn is_quic_addr(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|p| matches!(p, MaProtocol::Quic | MaProtocol::QuicV1))
}

/// Returns true if the multiaddr is TCP.
pub fn is_tcp_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, MaProtocol::Tcp(_)))
}

/// Returns true if the node has QUIC enabled (listening on QUIC addresses).
pub fn is_quic_enabled<'a>(listen_addrs: impl Iterator<Item = &'a Multiaddr>) -> bool {
    listen_addrs.into_iter().any(is_quic_addr)
}

/// Returns true if there is a direct (non-relay) QUIC connection among the
/// peers.
pub fn has_direct_quic_conn(peers: &[&crate::p2p_context::Peer]) -> bool {
    peers
        .iter()
        .any(|p| is_quic_addr(&p.remote_addr) && !is_relay_addr(&p.remote_addr))
}

/// Returns true if there is a direct (non-relay) TCP connection among the
/// peers.
pub fn has_direct_tcp_conn(peers: &[&crate::p2p_context::Peer]) -> bool {
    peers
        .iter()
        .any(|p| is_tcp_addr(&p.remote_addr) && !is_relay_addr(&p.remote_addr))
}

/// Filters addresses to only direct (non-relay) QUIC addresses.
pub fn filter_direct_quic_addrs(addrs: impl Iterator<Item = Multiaddr>) -> Vec<Multiaddr> {
    addrs
        .filter(|a| is_quic_addr(a) && !is_relay_addr(a))
        .collect()
}

/// Returns true if the multiaddr is a direct (non-relay) address.
pub fn is_direct_addr(addr: &Multiaddr) -> bool {
    !is_relay_addr(addr)
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    /// Config with the external overrides under test.
    fn config(external_ip: Option<&str>, external_host: Option<&str>) -> P2PConfig {
        P2PConfig {
            external_ip: external_ip.map(String::from),
            external_host: external_host.map(String::from),
            ..Default::default()
        }
    }

    fn as_strings(addrs: &[Multiaddr]) -> Vec<String> {
        addrs.iter().map(ToString::to_string).collect()
    }

    const RELAY_ID: &str = "16Uiu2HAkzdQ5Y9SYT91K1ue5SxXwgmajXntfScGnLYeip5hHyWmT";

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn relayed(transport: &str) -> Multiaddr {
        addr(&format!("{transport}/p2p/{RELAY_ID}/p2p-circuit"))
    }

    fn conn(remote_addr: Multiaddr) -> crate::p2p_context::Peer {
        crate::p2p_context::Peer {
            id: libp2p::PeerId::random(),
            connection_id: libp2p::swarm::ConnectionId::new_unchecked(1),
            remote_addr,
        }
    }

    #[test]
    fn is_relay_addr_needs_a_circuit_component() {
        assert!(is_relay_addr(&relayed("/ip4/1.2.3.4/tcp/3610")));
        assert!(is_relay_addr(&relayed("/ip4/1.2.3.4/udp/3610/quic-v1")));

        // A plain address to the relay itself is not a relayed address.
        assert!(!is_relay_addr(&addr(&format!(
            "/ip4/1.2.3.4/tcp/3610/p2p/{RELAY_ID}"
        ))));
        assert!(!is_relay_addr(&addr("/ip4/1.2.3.4/tcp/3610")));

        assert!(is_direct_addr(&addr("/ip4/1.2.3.4/tcp/3610")));
        assert!(!is_direct_addr(&relayed("/ip4/1.2.3.4/tcp/3610")));
    }

    #[test]
    fn is_quic_addr_accepts_both_quic_versions() {
        assert!(is_quic_addr(&addr("/ip4/1.2.3.4/udp/3610/quic-v1")));
        assert!(is_quic_addr(&addr("/ip4/1.2.3.4/udp/3610/quic")));
        // Relaying is the separate axis: relayed QUIC is still QUIC.
        assert!(is_quic_addr(&relayed("/ip4/1.2.3.4/udp/3610/quic-v1")));

        assert!(!is_quic_addr(&addr("/ip4/1.2.3.4/tcp/3610")));
        // UDP alone is not QUIC.
        assert!(!is_quic_addr(&addr("/ip4/1.2.3.4/udp/3610")));
    }

    #[test]
    fn is_tcp_addr_needs_a_tcp_component() {
        assert!(is_tcp_addr(&addr("/ip4/1.2.3.4/tcp/3610")));
        assert!(is_tcp_addr(&addr("/dns/relay.example.com/tcp/3610")));
        assert!(is_tcp_addr(&relayed("/ip4/1.2.3.4/tcp/3610")));

        assert!(!is_tcp_addr(&addr("/ip4/1.2.3.4/udp/3610/quic-v1")));
        assert!(!is_tcp_addr(&addr("/ip4/1.2.3.4")));
    }

    #[test]
    fn addr_type_and_protocol_classify_the_two_axes() {
        assert_eq!(
            addr_type(&addr("/ip4/1.2.3.4/tcp/3610")),
            ConnectionType::Direct
        );
        assert_eq!(
            addr_type(&relayed("/ip4/1.2.3.4/tcp/3610")),
            ConnectionType::Relay
        );

        assert_eq!(
            addr_protocol(&addr("/ip4/1.2.3.4/udp/3610/quic-v1")),
            Protocol::Quic
        );
        assert_eq!(addr_protocol(&addr("/ip4/1.2.3.4/tcp/3610")), Protocol::Tcp);
        assert_eq!(addr_protocol(&addr("/ip4/1.2.3.4")), Protocol::Unknown);
    }

    #[test]
    fn filter_direct_quic_addrs_keeps_only_unrelayed_quic() {
        let quic = addr("/ip4/1.2.3.4/udp/3610/quic-v1");
        let candidates = vec![
            quic.clone(),
            addr("/ip4/1.2.3.4/tcp/3610"),
            relayed("/ip4/1.2.3.4/udp/3610/quic-v1"),
            relayed("/ip4/1.2.3.4/tcp/3610"),
        ];

        assert_eq!(filter_direct_quic_addrs(candidates.into_iter()), vec![quic]);
        assert!(filter_direct_quic_addrs(std::iter::empty()).is_empty());
    }

    #[test]
    fn quic_is_enabled_only_while_listening_on_quic() {
        let tcp = addr("/ip4/1.2.3.4/tcp/3610");
        let quic = addr("/ip4/1.2.3.4/udp/3610/quic-v1");

        assert!(is_quic_enabled([&tcp, &quic].into_iter()));
        assert!(!is_quic_enabled([&tcp].into_iter()));
        assert!(!is_quic_enabled(std::iter::empty()));
    }

    #[test]
    fn direct_conn_checks_ignore_relayed_connections() {
        let quic = conn(addr("/ip4/1.2.3.4/udp/3610/quic-v1"));
        let tcp = conn(addr("/ip4/1.2.3.4/tcp/3610"));
        let relayed_quic = conn(relayed("/ip4/1.2.3.4/udp/3610/quic-v1"));
        let relayed_tcp = conn(relayed("/ip4/1.2.3.4/tcp/3610"));

        assert!(has_direct_quic_conn(&[&quic]));
        assert!(!has_direct_quic_conn(&[&tcp, &relayed_quic]));
        assert!(!has_direct_quic_conn(&[]));

        assert!(has_direct_tcp_conn(&[&tcp]));
        assert!(!has_direct_tcp_conn(&[&quic, &relayed_tcp]));
        assert!(!has_direct_tcp_conn(&[]));
    }

    const PRIV1: &str = "/ip4/192.168.1.1/tcp/80";
    const PRIV2: &str = "/ip4/127.0.0.1/udp/123";
    const PUB1: &str = "/ip4/1.1.1.1/tcp/80";

    /// Charon's `TestFilterAdvertisedAddrs` table (`p2p/p2p_internal_test.go`).
    #[test_case(&[], &[], false, &[] ; "empty")]
    #[test_case(&[], &[PUB1, PRIV1], true, &[PUB1] ; "drop one private")]
    #[test_case(&[], &[PUB1, PRIV1], false, &[PUB1, PRIV1] ; "keep one private")]
    #[test_case(&[PRIV1, PUB1], &[PUB1, PRIV1], true, &[PRIV1, PUB1] ; "duplicate public")]
    #[test_case(&[PRIV2, PRIV1], &[PRIV1, PRIV2], false, &[PRIV2, PRIV1] ; "duplicate private")]
    #[test_case(&[], &[PRIV1, PRIV2], true, &[] ; "drop all private")]
    fn filters_advertised_addresses(
        external: &[&str],
        internal: &[&str],
        exclude_private: bool,
        want: &[&str],
    ) {
        let got = filter_advertised_addresses(
            ExternalAddresses(external.iter().map(|a| addr(a)).collect()),
            InternalAddresses(internal.iter().map(|a| addr(a)).collect()),
            exclude_private,
        );

        assert_eq!(as_strings(&got), want);
    }

    #[test]
    fn external_multiaddrs_keep_the_bound_ports() {
        let cfg = config(Some("1.2.3.4"), Some("relay.example.com"));
        // What libp2p reports once bound: the kernel-assigned ports of a `:0`
        // listen config, which is what must be advertised — not the 0 that was
        // asked for.
        let listen_addrs = vec![
            "/ip4/127.0.0.1/tcp/40001".parse().unwrap(),
            "/ip4/127.0.0.1/tcp/40002".parse().unwrap(),
            "/ip4/127.0.0.1/udp/40003/quic-v1".parse().unwrap(),
        ];

        // The external address replaces the listen IP but keeps its port — one
        // address per listen port, IP forms first, then hostname forms, TCP
        // before QUIC.
        assert_eq!(
            as_strings(&external_multiaddrs(&cfg, &listen_addrs).unwrap()),
            vec![
                "/ip4/1.2.3.4/tcp/40001",
                "/ip4/1.2.3.4/tcp/40002",
                "/dns/relay.example.com/tcp/40001",
                "/dns/relay.example.com/tcp/40002",
                "/ip4/1.2.3.4/udp/40003/quic-v1",
                "/dns/relay.example.com/udp/40003/quic-v1",
            ]
        );
    }

    #[test]
    fn no_external_multiaddrs_without_external_config() {
        let listen_addrs = vec!["/ip4/127.0.0.1/tcp/40001".parse().unwrap()];

        // Nothing to advertise without an override, and nothing to advertise on
        // when the node listens nowhere.
        assert!(
            external_multiaddrs(&config(None, None), &listen_addrs)
                .unwrap()
                .is_empty()
        );
        assert!(
            external_multiaddrs(&config(Some("1.2.3.4"), None), &[])
                .unwrap()
                .is_empty()
        );
    }
}
