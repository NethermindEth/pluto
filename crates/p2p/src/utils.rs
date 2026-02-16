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
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use libp2p::{Multiaddr, identity::Keypair, multiaddr, multiaddr::Protocol as MaProtocol};

use crate::metrics::{ConnectionType, Protocol};

use crate::{
    config::{self, P2PConfig},
    manet::Manet,
};

/// Returns the external IP and Hostname fields as multiaddrs using the listen
/// TCP addresses ports.
pub(crate) fn external_tcp_multiaddrs(cfg: &P2PConfig) -> crate::p2p::Result<Vec<Multiaddr>> {
    let addrs = cfg.parse_tcp_addrs()?;

    let mut ports = vec![];

    for addr in &addrs {
        ports.push(addr.port());
    }

    let mut resp = vec![];

    if let Some(external_ip) = cfg.external_ip.as_ref() {
        let ip = external_ip.parse::<IpAddr>()?;

        for port in &ports {
            let maddr = config::multi_addr_from_ip_tcp_port(SocketAddr::new(ip, *port))?;

            resp.push(maddr);
        }
    }

    if let Some(external_host) = cfg.external_host.as_ref() {
        for port in &ports {
            resp.push(multiaddr::multiaddr!(Dns(external_host), Tcp(*port)));
        }
    }

    Ok(resp)
}

/// Returns the external IP and Hostname fields as multiaddrs using the listen
/// UDP addresses ports.
pub(crate) fn external_udp_multiaddrs(cfg: &P2PConfig) -> crate::p2p::Result<Vec<Multiaddr>> {
    let addrs = cfg.parse_udp_addrs()?;

    let mut ports = vec![];

    for addr in &addrs {
        ports.push(addr.port());
    }

    let mut resp = vec![];

    if let Some(external_ip) = cfg.external_ip.as_ref() {
        let ip = external_ip.parse::<IpAddr>()?;

        for port in &ports {
            let maddr = config::multi_addr_from_ip_udp_port(SocketAddr::new(ip, *port))?;

            resp.push(maddr);
        }
    }

    if let Some(external_host) = cfg.external_host.as_ref() {
        for port in &ports {
            resp.push(multiaddr::multiaddr!(
                Dns(external_host),
                Udp(*port),
                QuicV1
            ));
        }
    }

    Ok(resp)
}

pub(crate) struct ExternalAddresses(pub Vec<Multiaddr>);

pub(crate) struct InternalAddresses(pub Vec<Multiaddr>);

/// Filters the advertised addresses to exclude private addresses if the
/// `exclude_internal_private` flag is set.
/// Since the type of external and internal addresses is the same, we use type
/// wrappers to avoid confusion.
pub(crate) fn filter_advertised_addresses(
    external_addrs: ExternalAddresses,
    internal_addrs: InternalAddresses,
    exclude_internal_private: bool,
) -> crate::p2p::Result<Vec<Multiaddr>> {
    let mut external_addrs = external_addrs.0;
    let mut internal_addrs = internal_addrs.0;

    external_addrs.sort();
    internal_addrs.sort();

    external_addrs.dedup();
    internal_addrs.dedup();

    if exclude_internal_private {
        internal_addrs.retain(|addr| !addr.is_private());
    }

    Ok(external_addrs.into_iter().chain(internal_addrs).collect())
}

/// Returns the default swarm configuration.
pub(crate) fn default_swarm_config(cfg: libp2p::swarm::Config) -> libp2p::swarm::Config {
    cfg.with_idle_connection_timeout(Duration::from_secs(300))
}

/// Converts a secret key to a libp2p keypair.
pub(crate) fn keypair_from_secret_key(key: k256::SecretKey) -> crate::p2p::Result<Keypair> {
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
    } else {
        Protocol::Tcp
    }
}

/// Returns true if the multiaddr contains a p2p-circuit (relay) component.
pub(crate) fn is_relay_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, MaProtocol::P2pCircuit))
}

/// Returns true if the multiaddr contains a QUIC or QUIC-v1 component.
pub(crate) fn is_quic_addr(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|p| matches!(p, MaProtocol::Quic | MaProtocol::QuicV1))
}
