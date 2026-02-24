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
