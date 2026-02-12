//! Core P2P networking primitives for Charon nodes.
//!
//! This module provides the fundamental building blocks for peer-to-peer
//! networking in Charon, built on top of [libp2p](https://docs.rs/libp2p). It handles node creation,
//! transport configuration (TCP and QUIC), and connection management.
//!
//! # Node Types
//!
//! Charon supports two transport types:
//! - **TCP**: Traditional TCP transport with Noise encryption and Yamux
//!   multiplexing
//! - **QUIC**: Modern QUIC transport with built-in encryption and multiplexing
//!
//! # Creating a Node
//!
//! Nodes are created using [`Node::new`] with a custom behaviour function:
//!
//! ```ignore
//! let node = Node::new(
//!     config,
//!     secret_key,
//!     filter_private_addrs,
//!     NodeType::QUIC,
//!     |keypair, relay| MyBehaviour::new(keypair, relay),
//! )?;
//! ```
//!
//! # Relay Support
//!
//! All nodes include relay client support for NAT traversal. For relay server
//! functionality, use [`Node::new_relay_server`].

use libp2p::{
    Swarm, SwarmBuilder, identity::Keypair, noise, relay, swarm::NetworkBehaviour, tcp, yamux,
};
use tracing::warn;

use crate::{
    config::{P2PConfig, P2PConfigError},
    utils,
};

/// P2P error.
#[derive(Debug, thiserror::Error)]
pub enum P2PError {
    /// Failed to build the swarm.
    #[error("Failed to build the swarm: {0}")]
    FailedToBuildSwarm(Box<dyn std::error::Error + Send + Sync>),

    /// Failed to convert the secret key to a libp2p keypair.
    #[error("Failed to convert the secret key to a libp2p keypair: {0}")]
    FailedToConvertSecretKeyToLibp2pKeypair(#[from] k256::pkcs8::der::Error),

    /// Failed to decode the libp2p keypair.
    #[error("Failed to decode the libp2p keypair: {0}")]
    FailedToDecodeLibp2pKeypair(#[from] libp2p::identity::DecodingError),

    /// Failed to listen on address.
    #[error("Failed to listen on address: {0}")]
    FailedToListen(#[from] libp2p::TransportError<std::io::Error>),

    /// Failed to dial peer.
    #[error("Failed to dial peer: {0}")]
    FailedToDialPeer(#[from] libp2p::swarm::DialError),

    /// P2P Config error.
    #[error("P2P Config error: {0}")]
    P2PConfigError(#[from] P2PConfigError),

    /// Failed to parse IP address.
    #[error("Failed to parse IP address: {0}")]
    FailedToParseIpAddress(#[from] std::net::AddrParseError),
}

impl P2PError {
    /// Failed to build the swarm.
    pub fn failed_to_build_swarm(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::FailedToBuildSwarm(Box::new(error))
    }
}

pub(crate) type Result<T> = std::result::Result<T, P2PError>;

/// Node type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// TCP node.
    TCP,
    /// QUIC node.
    QUIC,
}

/// Node.
pub struct Node<B: NetworkBehaviour> {
    /// Swarm.
    pub swarm: Swarm<B>,

    /// Node type.
    pub node_type: NodeType,

    /// Is relay server.
    pub is_relay_server: bool,
}

impl<B: NetworkBehaviour> Node<B> {
    /// Creates a new node.
    pub fn new<F>(
        cfg: P2PConfig,
        key: k256::SecretKey,
        filter_private_addrs: bool,
        node_type: NodeType,
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: Fn(&Keypair, relay::client::Behaviour) -> B,
    {
        let keypair = utils::keypair_from_secret_key(key)?;

        let mut node = match node_type {
            NodeType::TCP => Self::new_with_tcp(keypair, behaviour_fn),
            NodeType::QUIC => Self::new_with_quic(keypair, behaviour_fn),
        }?;

        node.apply_config(&cfg, filter_private_addrs)?;

        Ok(node)
    }

    fn apply_config(&mut self, cfg: &P2PConfig, filter_private_addrs: bool) -> Result<()> {
        let mut addrs = cfg.tcp_multiaddrs()?;
        let mut external_addrs = utils::external_tcp_multiaddrs(cfg)?;

        if self.node_type == NodeType::QUIC {
            let udp_addrs = cfg.udp_multiaddrs()?;

            if udp_addrs.is_empty() {
                warn!("LibP2P QUIC is enabled, but no UDP addresses are configured");
            }

            addrs.extend(udp_addrs);

            let external_udp_addrs = utils::external_udp_multiaddrs(cfg)?;

            external_addrs.extend(external_udp_addrs);
        }

        if addrs.is_empty() {
            warn!(
                "LibP2P not accepting incoming connections since --p2p-udp-addresses and --p2p-tcp-addresses are empty"
            );
        }

        let filtered_addrs = utils::filter_advertised_addresses(
            utils::ExternalAddresses(external_addrs),
            utils::InternalAddresses(addrs),
            filter_private_addrs,
        )?;

        for addr in filtered_addrs {
            self.swarm.listen_on(addr)?;
        }

        Ok(())
    }

    /// Creates a new node with QUIC and TCP.
    fn new_with_quic<F>(keypair: Keypair, behaviour_fn: F) -> Result<Self>
    where
        F: Fn(&Keypair, relay::client::Behaviour) -> B,
    {
        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(P2PError::failed_to_build_swarm)?
            .with_quic()
            .with_dns()
            .map_err(P2PError::failed_to_build_swarm)?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(P2PError::failed_to_build_swarm)?
            .with_behaviour(behaviour_fn)
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(utils::default_swarm_config)
            .build();

        Ok(Node {
            swarm,
            node_type: NodeType::QUIC,
            is_relay_server: false,
        })
    }

    /// Creates a new node with TCP.
    fn new_with_tcp<F>(keypair: Keypair, behaviour_fn: F) -> Result<Self>
    where
        F: Fn(&Keypair, relay::client::Behaviour) -> B,
    {
        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(P2PError::failed_to_build_swarm)?
            .with_dns()
            .map_err(P2PError::failed_to_build_swarm)?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(P2PError::failed_to_build_swarm)?
            .with_behaviour(behaviour_fn)
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(utils::default_swarm_config)
            .build();

        Ok(Node {
            swarm,
            node_type: NodeType::TCP,
            is_relay_server: false,
        })
    }

    /// Creates a new node with relay server.
    pub fn new_relay_server<F>(
        _cfg: &P2PConfig,
        key: k256::SecretKey,
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: Fn(&Keypair) -> B,
    {
        let keypair = utils::keypair_from_secret_key(key)?;

        let swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(P2PError::failed_to_build_swarm)?
            .with_dns()
            .map_err(P2PError::failed_to_build_swarm)?
            .with_behaviour(behaviour_fn)
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(utils::default_swarm_config)
            .build();

        Ok(Node {
            swarm,
            node_type: NodeType::TCP,
            is_relay_server: true,
        })
    }
}
