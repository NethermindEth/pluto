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
//! ## Simple Relay Client Node
//!
//! ```ignore
//! use pluto_p2p::p2p::{Node, NodeType};
//! use pluto_p2p::behaviours::pluto::PlutoBehaviour;
//!
//! let node = Node::new(
//!     P2PConfig::default(),
//!     secret_key,
//!     NodeType::QUIC,
//!     PlutoBehaviour::builder()
//!         .with_ping_interval(Duration::from_secs(15)),
//!     |_keypair, relay_client| relay_client,
//! )?;
//! ```
//!
//! ## Client Node with Custom Behaviours
//!
//! ```ignore
//! let node = Node::new(
//!     P2PConfig::default(),
//!     secret_key,
//!     NodeType::QUIC,
//!     PlutoBehaviour::builder()
//!         .with_ping_interval(Duration::from_secs(15))
//!         .with_user_agent("my-app/1.0.0"),
//!     |keypair, relay_client| {
//!         MyBehaviour {
//!             relay_client,
//!             peerinfo: Peerinfo::new(config, keypair),
//!         }
//!     },
//! )?;
//! ```
//!
//! ## Relay Server Node
//!
//! ```ignore
//! let node = Node::new_server(
//!     P2PConfig::default(),
//!     secret_key,
//!     NodeType::TCP,
//!     PlutoBehaviour::builder(),
//!     |keypair| relay::Behaviour::new(keypair.public().to_peer_id(), relay_config),
//! )?;
//! ```
//!
//! # Relay Support
//!
//! Client nodes include relay client support for NAT traversal via the
//! `relay_client` parameter passed to the build closure.
//! For relay server functionality, use [`Node::new_server`].

use libp2p::{
    Swarm, SwarmBuilder, identity::Keypair, noise, relay, swarm::NetworkBehaviour, yamux,
};

use libp2p::tcp;
use tracing::warn;

use crate::{
    behaviours::pluto::{PlutoBehaviour, PlutoBehaviourBuilder},
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
    pub swarm: Swarm<PlutoBehaviour<B>>,

    /// Node type.
    pub node_type: NodeType,

    /// Is relay server.
    pub is_relay_server: bool,
}

impl<B: NetworkBehaviour> Node<B> {
    /// Creates a new client node with relay client support.
    ///
    /// The `inner_fn` receives the keypair and relay client, and should return
    /// the inner behaviour `B`. This inner behaviour will be wrapped by
    /// `PlutoBehaviour`.
    ///
    /// # Arguments
    ///
    /// * `cfg` - P2P configuration for addresses and networking
    /// * `key` - Secret key for node identity
    /// * `node_type` - Transport type (TCP or QUIC)
    /// * `filter_private_addrs` - Whether to filter private addresses
    /// * `behaviour_builder` - Builder for configuring PlutoBehaviour (ping,
    ///   identify, etc.)
    /// * `inner_fn` - Closure that creates the inner behaviour from keypair and
    ///   relay client
    ///
    /// # Example
    ///
    /// ```ignore
    /// let node = Node::new(
    ///     P2PConfig::default(),
    ///     secret_key,
    ///     NodeType::QUIC,
    ///     PlutoBehaviour::builder()
    ///         .with_ping_interval(Duration::from_secs(15))
    ///         .with_user_agent("my-app/1.0.0"),
    ///     |keypair, relay_client| {
    ///         MyBehaviour { relay_client, peerinfo: ... }
    ///     },
    /// )?;
    /// ```
    pub fn new<F>(
        cfg: P2PConfig,
        key: k256::SecretKey,
        node_type: NodeType,
        filter_private_addrs: bool,
        behaviour_builder: PlutoBehaviourBuilder<B>,
        inner_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(&Keypair, relay::client::Behaviour) -> B,
    {
        let keypair = utils::keypair_from_secret_key(key)?;

        let mut node = match node_type {
            NodeType::TCP => Self::build_tcp_client(keypair, behaviour_builder, inner_fn),
            NodeType::QUIC => Self::build_quic_client(keypair, behaviour_builder, inner_fn),
        }?;

        node.apply_config(&cfg, filter_private_addrs)?;

        Ok(node)
    }

    /// Creates a new server node without relay client.
    ///
    /// Server nodes (like relay servers) don't include relay client support
    /// since they are expected to be publicly reachable.
    pub fn new_server<F>(
        cfg: P2PConfig,
        key: k256::SecretKey,
        node_type: NodeType,
        filter_private_addrs: bool,
        behaviour_builder: PlutoBehaviourBuilder<B>,
        inner_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(&Keypair) -> B,
    {
        let keypair = utils::keypair_from_secret_key(key)?;

        let mut node = match node_type {
            NodeType::TCP => Self::build_tcp_server(keypair, behaviour_builder, inner_fn),
            NodeType::QUIC => Self::build_quic_server(keypair, behaviour_builder, inner_fn),
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

        // Listen on internal addresses only
        for addr in &addrs {
            self.swarm.listen_on(addr.clone())?;
        }

        // Advertise filtered addresses (external + optionally filtered internal)
        let advertised_addrs = utils::filter_advertised_addresses(
            utils::ExternalAddresses(external_addrs),
            utils::InternalAddresses(addrs),
            filter_private_addrs,
        )?;

        for addr in advertised_addrs {
            self.swarm.add_external_address(addr);
        }

        Ok(())
    }

    fn build_quic_client<F>(
        keypair: Keypair,
        behaviour_builder: PlutoBehaviourBuilder<B>,
        inner_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(&Keypair, relay::client::Behaviour) -> B,
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
            .with_behaviour(|key, relay_client| {
                let inner = inner_fn(key, relay_client);
                behaviour_builder.with_inner(inner).build(key)
            })
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(utils::default_swarm_config)
            .build();

        Ok(Node {
            swarm,
            node_type: NodeType::QUIC,
            is_relay_server: false,
        })
    }

    fn build_tcp_client<F>(
        keypair: Keypair,
        behaviour_builder: PlutoBehaviourBuilder<B>,
        inner_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(&Keypair, relay::client::Behaviour) -> B,
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
            .with_behaviour(|key, relay_client| {
                let inner = inner_fn(key, relay_client);
                behaviour_builder.with_inner(inner).build(key)
            })
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(utils::default_swarm_config)
            .build();

        Ok(Node {
            swarm,
            node_type: NodeType::TCP,
            is_relay_server: false,
        })
    }

    fn build_quic_server<F>(
        keypair: Keypair,
        behaviour_builder: PlutoBehaviourBuilder<B>,
        inner_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(&Keypair) -> B,
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
            .with_behaviour(|key| {
                let inner = inner_fn(key);
                behaviour_builder.with_inner(inner).build(key)
            })
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(utils::default_swarm_config)
            .build();

        Ok(Node {
            swarm,
            node_type: NodeType::QUIC,
            is_relay_server: true,
        })
    }

    fn build_tcp_server<F>(
        keypair: Keypair,
        behaviour_builder: PlutoBehaviourBuilder<B>,
        inner_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(&Keypair) -> B,
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
            .with_behaviour(|key| {
                let inner = inner_fn(key);
                behaviour_builder.with_inner(inner).build(key)
            })
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
