use std::net::Ipv4Addr;

use libp2p::{Multiaddr, multiaddr::Protocol};

/// Re-export utilities from the p2p crate.
pub(crate) use pluto_p2p::utils::{TransportProtocol, addr_port, is_quic_addr, is_tcp_addr};

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

/// Extracts the IPv4 address and `proto` port from a multiaddr.
pub(crate) fn extract_ip_and_port(
    addr: &Multiaddr,
    proto: TransportProtocol,
) -> Option<(Ipv4Addr, u16)> {
    let mut ip: Option<Ipv4Addr> = None;

    for protocol in addr.iter() {
        if let Protocol::Ip4(i) = protocol {
            ip = Some(i);
        }
    }

    Some((ip?, addr_port(addr, proto)?))
}

/// Extracts the DNS hostname and `proto` port from a `/dns(4|6)/<host>/...`
/// multiaddr.
pub(crate) fn extract_dns_and_port(
    addr: &Multiaddr,
    proto: TransportProtocol,
) -> Option<(String, u16)> {
    let mut host: Option<String> = None;

    for protocol in addr.iter() {
        if let Protocol::Dns(h) | Protocol::Dns4(h) | Protocol::Dns6(h) = protocol {
            host = Some(h.into_owned());
        }
    }

    Some((host?, addr_port(addr, proto)?))
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
    fn extract_ip_and_port_tcp_happy() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let got =
            extract_ip_and_port(&ma("/ip4/1.2.3.4/tcp/8000"), TransportProtocol::Tcp).unwrap();
        assert_eq!(got, (ip, 8000));
    }

    #[test]
    fn extract_ip_and_port_tcp_missing_ip() {
        assert!(
            extract_ip_and_port(&ma("/dns/example.com/tcp/8000"), TransportProtocol::Tcp).is_none()
        );
    }

    #[test]
    fn extract_ip_and_port_tcp_missing_tcp() {
        assert!(
            extract_ip_and_port(&ma("/ip4/1.2.3.4/udp/8000/quic-v1"), TransportProtocol::Tcp)
                .is_none()
        );
    }

    #[test]
    fn extract_ip_and_port_quic_quic_v1() {
        let ip = Ipv4Addr::new(5, 6, 7, 8);
        let got = extract_ip_and_port(
            &ma("/ip4/5.6.7.8/udp/9000/quic-v1"),
            TransportProtocol::Quic,
        )
        .unwrap();
        assert_eq!(got, (ip, 9000));
    }

    #[test]
    fn extract_ip_and_port_quic_ignores_tcp() {
        assert!(
            extract_ip_and_port(&ma("/ip4/1.2.3.4/tcp/8000"), TransportProtocol::Quic).is_none()
        );
    }

    #[test]
    fn extract_dns_and_port_tcp_dns() {
        let got = extract_dns_and_port(
            &ma("/dns/relay.example.com/tcp/3610"),
            TransportProtocol::Tcp,
        )
        .unwrap();
        assert_eq!(got, ("relay.example.com".to_string(), 3610));
    }

    #[test]
    fn extract_dns_and_port_tcp_dns4() {
        let got = extract_dns_and_port(
            &ma("/dns4/relay.example.com/tcp/3610"),
            TransportProtocol::Tcp,
        )
        .unwrap();
        assert_eq!(got, ("relay.example.com".to_string(), 3610));
    }

    #[test]
    fn extract_dns_and_port_tcp_dns6() {
        let got = extract_dns_and_port(
            &ma("/dns6/relay.example.com/tcp/3610"),
            TransportProtocol::Tcp,
        )
        .unwrap();
        assert_eq!(got, ("relay.example.com".to_string(), 3610));
    }

    #[test]
    fn extract_dns_and_port_tcp_skips_ip4() {
        assert!(
            extract_dns_and_port(&ma("/ip4/1.2.3.4/tcp/3610"), TransportProtocol::Tcp).is_none()
        );
    }

    #[test]
    fn extract_dns_and_port_tcp_missing_tcp() {
        assert!(
            extract_dns_and_port(
                &ma("/dns/relay.example.com/udp/3610/quic-v1"),
                TransportProtocol::Tcp
            )
            .is_none()
        );
    }

    #[test]
    fn extract_dns_and_port_quic_quic_v1() {
        let got = extract_dns_and_port(
            &ma("/dns/relay.example.com/udp/3610/quic-v1"),
            TransportProtocol::Quic,
        )
        .unwrap();
        assert_eq!(got, ("relay.example.com".to_string(), 3610));
    }

    #[test]
    fn extract_dns_and_port_quic_skips_tcp() {
        assert!(
            extract_dns_and_port(
                &ma("/dns/relay.example.com/tcp/3610"),
                TransportProtocol::Quic
            )
            .is_none()
        );
    }

    #[test]
    fn extract_dns_and_port_quic_dns4_dns6() {
        let got4 = extract_dns_and_port(
            &ma("/dns4/relay.example.com/udp/3610/quic-v1"),
            TransportProtocol::Quic,
        )
        .unwrap();
        assert_eq!(got4, ("relay.example.com".to_string(), 3610));

        let got6 = extract_dns_and_port(
            &ma("/dns6/relay.example.com/udp/3610/quic-v1"),
            TransportProtocol::Quic,
        )
        .unwrap();
        assert_eq!(got6, ("relay.example.com".to_string(), 3610));
    }

    #[test]
    fn ipv6_helpers_do_not_crash() {
        // Sanity: IPv6-shaped multiaddrs don't match the IPv4 extractors but
        // also don't panic.
        let addr: Multiaddr = format!("/ip6/{}/tcp/8000", Ipv6Addr::LOCALHOST)
            .parse()
            .unwrap();
        assert!(extract_ip_and_port(&addr, TransportProtocol::Tcp).is_none());
        assert!(extract_ip_and_port(&addr, TransportProtocol::Quic).is_none());
    }
}
