use std::net::Ipv4Addr;

use libp2p::{Multiaddr, multiaddr::Protocol};

/// Re-export utilities from the p2p crate.
pub(crate) use pluto_p2p::utils::{is_quic_addr, is_tcp_addr};

/// Returns true if the multiaddr is a public address.
pub(crate) fn is_public_addr(addr: &Multiaddr) -> bool {
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(ip) => {
                return !ip.is_private()
                    && !ip.is_loopback()
                    && !ip.is_link_local()
                    && !ip.is_unspecified();
            }
            Protocol::Ip6(ip) => {
                return !ip.is_loopback() && !ip.is_unspecified();
            }
            _ => continue,
        }
    }
    false
}

/// Extracts IP and TCP port from a multiaddr.
pub(crate) fn extract_ip_and_tcp_port(addr: &Multiaddr) -> Option<(Ipv4Addr, u16)> {
    let mut ip: Option<Ipv4Addr> = None;
    let mut port: Option<u16> = None;

    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(i) => ip = Some(i),
            Protocol::Tcp(p) => port = Some(p),
            _ => {}
        }
    }

    match (ip, port) {
        (Some(i), Some(p)) => Some((i, p)),
        _ => None,
    }
}

/// Extracts IP and UDP port from a QUIC multiaddr.
pub(crate) fn extract_ip_and_udp_port(addr: &Multiaddr) -> Option<(Ipv4Addr, u16)> {
    let mut ip: Option<Ipv4Addr> = None;
    let mut port: Option<u16> = None;

    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(i) => ip = Some(i),
            Protocol::Udp(p) => port = Some(p),
            _ => {}
        }
    }

    match (ip, port) {
        (Some(i), Some(p)) => Some((i, p)),
        _ => None,
    }
}

/// Extracts DNS hostname and TCP port from a `/dns(4|6)/<host>/tcp/<port>`
/// multiaddr.
pub(crate) fn extract_dns_and_tcp_port(addr: &Multiaddr) -> Option<(String, u16)> {
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;

    for protocol in addr.iter() {
        match protocol {
            Protocol::Dns(h) | Protocol::Dns4(h) | Protocol::Dns6(h) => {
                host = Some(h.into_owned());
            }
            Protocol::Tcp(p) => port = Some(p),
            _ => {}
        }
    }

    match (host, port) {
        (Some(h), Some(p)) => Some((h, p)),
        _ => None,
    }
}

/// Extracts DNS hostname and UDP port from a
/// `/dns(4|6)/<host>/udp/<port>/quic-v1` multiaddr.
pub(crate) fn extract_dns_and_udp_port(addr: &Multiaddr) -> Option<(String, u16)> {
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;

    for protocol in addr.iter() {
        match protocol {
            Protocol::Dns(h) | Protocol::Dns4(h) | Protocol::Dns6(h) => {
                host = Some(h.into_owned());
            }
            Protocol::Udp(p) => port = Some(p),
            _ => {}
        }
    }

    match (host, port) {
        (Some(h), Some(p)) => Some((h, p)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn ma(s: &str) -> Multiaddr {
        s.parse().expect("valid multiaddr")
    }

    #[test]
    fn is_public_addr_public_ipv4() {
        assert!(is_public_addr(&ma("/ip4/1.2.3.4/tcp/8000")));
    }

    #[test]
    fn is_public_addr_private_ipv4() {
        assert!(!is_public_addr(&ma("/ip4/10.0.0.1/tcp/8000")));
        assert!(!is_public_addr(&ma("/ip4/192.168.1.1/tcp/8000")));
        assert!(!is_public_addr(&ma("/ip4/172.16.0.1/tcp/8000")));
    }

    #[test]
    fn is_public_addr_loopback_unspecified_linklocal() {
        assert!(!is_public_addr(&ma("/ip4/127.0.0.1/tcp/8000")));
        assert!(!is_public_addr(&ma("/ip4/0.0.0.0/tcp/8000")));
        assert!(!is_public_addr(&ma("/ip4/169.254.1.1/tcp/8000")));
    }

    #[test]
    fn is_public_addr_dns_is_not_public() {
        // No IP component: function falls through to `false`.
        assert!(!is_public_addr(&ma("/dns/example.com/tcp/8000")));
    }

    #[test]
    fn extract_ip_and_tcp_port_happy() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let got = extract_ip_and_tcp_port(&ma("/ip4/1.2.3.4/tcp/8000")).unwrap();
        assert_eq!(got, (ip, 8000));
    }

    #[test]
    fn extract_ip_and_tcp_port_missing_ip() {
        assert!(extract_ip_and_tcp_port(&ma("/dns/example.com/tcp/8000")).is_none());
    }

    #[test]
    fn extract_ip_and_tcp_port_missing_tcp() {
        assert!(extract_ip_and_tcp_port(&ma("/ip4/1.2.3.4/udp/8000/quic-v1")).is_none());
    }

    #[test]
    fn extract_ip_and_udp_port_quic_v1() {
        let ip = Ipv4Addr::new(5, 6, 7, 8);
        let got = extract_ip_and_udp_port(&ma("/ip4/5.6.7.8/udp/9000/quic-v1")).unwrap();
        assert_eq!(got, (ip, 9000));
    }

    #[test]
    fn extract_ip_and_udp_port_ignores_tcp() {
        assert!(extract_ip_and_udp_port(&ma("/ip4/1.2.3.4/tcp/8000")).is_none());
    }

    #[test]
    fn extract_dns_and_tcp_port_dns() {
        let got = extract_dns_and_tcp_port(&ma("/dns/relay.example.com/tcp/3610")).unwrap();
        assert_eq!(got, ("relay.example.com".to_string(), 3610));
    }

    #[test]
    fn extract_dns_and_tcp_port_dns4() {
        let got = extract_dns_and_tcp_port(&ma("/dns4/relay.example.com/tcp/3610")).unwrap();
        assert_eq!(got, ("relay.example.com".to_string(), 3610));
    }

    #[test]
    fn extract_dns_and_tcp_port_dns6() {
        let got = extract_dns_and_tcp_port(&ma("/dns6/relay.example.com/tcp/3610")).unwrap();
        assert_eq!(got, ("relay.example.com".to_string(), 3610));
    }

    #[test]
    fn extract_dns_and_tcp_port_skips_ip4() {
        assert!(extract_dns_and_tcp_port(&ma("/ip4/1.2.3.4/tcp/3610")).is_none());
    }

    #[test]
    fn extract_dns_and_tcp_port_missing_tcp() {
        assert!(extract_dns_and_tcp_port(&ma("/dns/relay.example.com/udp/3610/quic-v1")).is_none());
    }

    #[test]
    fn extract_dns_and_udp_port_quic_v1() {
        let got = extract_dns_and_udp_port(&ma("/dns/relay.example.com/udp/3610/quic-v1")).unwrap();
        assert_eq!(got, ("relay.example.com".to_string(), 3610));
    }

    #[test]
    fn extract_dns_and_udp_port_skips_tcp() {
        assert!(extract_dns_and_udp_port(&ma("/dns/relay.example.com/tcp/3610")).is_none());
    }

    #[test]
    fn extract_dns_and_udp_port_dns4_dns6() {
        let got4 =
            extract_dns_and_udp_port(&ma("/dns4/relay.example.com/udp/3610/quic-v1")).unwrap();
        assert_eq!(got4, ("relay.example.com".to_string(), 3610));

        let got6 =
            extract_dns_and_udp_port(&ma("/dns6/relay.example.com/udp/3610/quic-v1")).unwrap();
        assert_eq!(got6, ("relay.example.com".to_string(), 3610));
    }

    #[test]
    fn ipv6_helpers_do_not_crash() {
        // Sanity: IPv6-shaped multiaddrs don't match the IPv4 extractors but
        // also don't panic.
        let addr: Multiaddr = format!("/ip6/{}/tcp/8000", Ipv6Addr::LOCALHOST)
            .parse()
            .unwrap();
        assert!(extract_ip_and_tcp_port(&addr).is_none());
        assert!(extract_ip_and_udp_port(&addr).is_none());
    }
}
