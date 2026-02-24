//! Core P2P networking primitives for Pluto nodes.
//!
//! This module provides the fundamental building blocks for peer-to-peer
//! networking in Pluto, built on top of [libp2p](https://docs.rs/libp2p). It handles node creation,
//! transport configuration (TCP and QUIC), and connection management.
//!
//! # Node Types
//!
//! Pluto supports two transport types:
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
//!     false, // filter_private_addrs
//!     PlutoBehaviour::builder()
//!         .with_user_agent("my-app/1.0.0"),
//!     |_keypair, relay_client| relay_client,
//! )?;
//! ```
//!
//! ## Client Node with Custom Behaviours
//!
//! ```ignore
//! use pluto_p2p::p2p::{Node, NodeType};
//! use pluto_p2p::behaviours::pluto::PlutoBehaviour;
//!
//! let node = Node::new(
//!     P2PConfig::default(),
//!     secret_key,
//!     NodeType::QUIC,
//!     false, // filter_private_addrs
//!     PlutoBehaviour::builder()
//!         .with_user_agent("my-app/1.0.0"),
//!     |keypair, relay_client| {
//!         MyBehaviour {
//!             relay: relay_client,
//!             mdns: mdns::tokio::Behaviour::new(
//!                 mdns::Config::default(),
//!                 keypair.public().to_peer_id(),
//!             ).unwrap(),
//!         }
//!     },
//! )?;
//! ```
//!
//! ## Relay Server Node
//!
//! ```ignore
//! use pluto_p2p::p2p::{Node, NodeType};
//! use pluto_p2p::behaviours::pluto::PlutoBehaviour;
//!
//! let node = Node::new_server(
//!     P2PConfig::default(),
//!     secret_key,
//!     NodeType::TCP,
//!     false, // filter_private_addrs
//!     PlutoBehaviour::builder(),
//!     |keypair| relay::Behaviour::new(keypair.public().to_peer_id(), relay_config),
//! )?;
//! ```
//!
//! # Address Filtering
//!
//! The `filter_private_addrs` parameter controls whether private/local
//! addresses (e.g., `127.0.0.1`, `192.168.x.x`) are advertised to peers. Set to
//! `true` for production deployments to only advertise external addresses.
//!
//! # Relay Support
//!
//! Client nodes may include relay client to support connecting via relays.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Stream, StreamExt, stream::FusedStream};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, autonat,
    identity::Keypair,
    noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use tracing::{info, warn};

use crate::{
    behaviours::pluto::{PlutoBehaviour, PlutoBehaviourBuilder, PlutoBehaviourEvent},
    config::{P2PConfig, P2PConfigError},
    metrics::P2P_METRICS,
    name::peer_name,
    p2p_context::P2PContext,
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
    swarm: Swarm<PlutoBehaviour<B>>,

    /// Global context.
    p2p_context: P2PContext,

    /// Node type.
    node_type: NodeType,
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
    /// * `known_peers` - List of known cluster peer IDs for metrics tracking
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
    ///     false,
    ///     vec![peer1, peer2], // known cluster peers
    ///     PlutoBehaviour::builder()
    ///         .with_ping_interval(Duration::from_secs(15))
    ///         .with_user_agent("my-app/1.0.0"),
    ///     |global_ctx, keypair, relay_client| {
    ///         MyBehaviour { relay_client, peerinfo: ... }
    ///     },
    /// )?;
    /// ```
    pub fn new<F>(
        cfg: P2PConfig,
        key: k256::SecretKey,
        node_type: NodeType,
        filter_private_addrs: bool,
        known_peers: impl IntoIterator<Item = PeerId>,
        behaviour_builder: PlutoBehaviourBuilder<B>,
        inner_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(P2PContext, &Keypair, relay::client::Behaviour) -> B,
    {
        let keypair = utils::keypair_from_secret_key(key)?;
        let p2p_context = P2PContext::new(known_peers);

        let mut node = match node_type {
            NodeType::TCP => {
                Self::build_tcp_client(keypair, p2p_context, behaviour_builder, inner_fn)
            }
            NodeType::QUIC => {
                Self::build_quic_client(keypair, p2p_context, behaviour_builder, inner_fn)
            }
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
        known_peers: impl IntoIterator<Item = PeerId>,
        behaviour_builder: PlutoBehaviourBuilder<B>,
        inner_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(P2PContext, &Keypair) -> B,
    {
        let keypair = utils::keypair_from_secret_key(key)?;
        let p2p_context = P2PContext::new(known_peers);

        let mut node = match node_type {
            NodeType::TCP => {
                Self::build_tcp_server(keypair, p2p_context, behaviour_builder, inner_fn)
            }
            NodeType::QUIC => {
                Self::build_quic_server(keypair, p2p_context, behaviour_builder, inner_fn)
            }
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
        p2p_context: P2PContext,
        behaviour_builder: PlutoBehaviourBuilder<B>,
        inner_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(P2PContext, &Keypair, relay::client::Behaviour) -> B,
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
                let inner = inner_fn(p2p_context.clone(), key, relay_client);
                behaviour_builder
                    .with_p2p_context(p2p_context.clone())
                    .with_inner(inner)
                    .build(key)
            })
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(utils::default_swarm_config)
            .build();

        Ok(Node {
            swarm,
            node_type: NodeType::QUIC,
            p2p_context,
        })
    }

    fn build_tcp_client<F>(
        keypair: Keypair,
        p2p_context: P2PContext,
        behaviour_builder: PlutoBehaviourBuilder<B>,
        inner_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(P2PContext, &Keypair, relay::client::Behaviour) -> B,
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
                let inner = inner_fn(p2p_context.clone(), key, relay_client);
                behaviour_builder
                    .with_p2p_context(p2p_context.clone())
                    .with_inner(inner)
                    .build(key)
            })
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(utils::default_swarm_config)
            .build();

        Ok(Node {
            swarm,
            node_type: NodeType::TCP,
            p2p_context,
        })
    }

    fn build_quic_server<F>(
        keypair: Keypair,
        p2p_context: P2PContext,
        behaviour_builder: PlutoBehaviourBuilder<B>,
        inner_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(P2PContext, &Keypair) -> B,
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
                let inner = inner_fn(p2p_context.clone(), key);
                behaviour_builder
                    .with_p2p_context(p2p_context.clone())
                    .with_inner(inner)
                    .build(key)
            })
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(utils::default_swarm_config)
            .build();

        Ok(Node {
            swarm,
            node_type: NodeType::QUIC,
            p2p_context,
        })
    }

    fn build_tcp_server<F>(
        keypair: Keypair,
        p2p_context: P2PContext,
        behaviour_builder: PlutoBehaviourBuilder<B>,
        inner_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(P2PContext, &Keypair) -> B,
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
                let inner = inner_fn(p2p_context.clone(), key);
                behaviour_builder
                    .with_p2p_context(p2p_context.clone())
                    .with_inner(inner)
                    .build(key)
            })
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(utils::default_swarm_config)
            .build();

        Ok(Node {
            swarm,
            node_type: NodeType::TCP,
            p2p_context,
        })
    }

    /// Returns the node type.
    pub fn node_type(&self) -> NodeType {
        self.node_type
    }

    /// Dials a peer.
    pub fn dial(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.dial(addr)?;
        Ok(())
    }

    /// Listens on an address.
    pub fn listen_on(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.listen_on(addr)?;
        Ok(())
    }

    /// Adds an external address to the peer store.
    pub fn add_external_address(&mut self, addr: Multiaddr) {
        self.swarm.add_external_address(addr);
    }

    /// Returns the global context.
    pub fn p2p_context(&self) -> &P2PContext {
        &self.p2p_context
    }

    /// Returns the local peer ID.
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Handles a swarm event to update metrics and logging.
    fn handle_event(&mut self, event: &SwarmEvent<PlutoBehaviourEvent<B>>) {
        match event {
            // Ping metrics
            SwarmEvent::Behaviour(PlutoBehaviourEvent::Ping(ping::Event {
                peer, result, ..
            })) => {
                let peer_label = peer_name(peer);
                match result {
                    Ok(duration) => {
                        P2P_METRICS.ping_latency_secs[&peer_label].observe(duration.as_secs_f64());
                        P2P_METRICS.ping_success[&peer_label].set(1);
                    }
                    Err(_) => {
                        P2P_METRICS.ping_error_total[&peer_label].inc();
                        P2P_METRICS.ping_success[&peer_label].set(0);
                    }
                }
            }

            // AutoNAT reachability status
            SwarmEvent::Behaviour(PlutoBehaviourEvent::Autonat(
                autonat::Event::StatusChanged { new, .. },
            )) => {
                let status = match new {
                    autonat::NatStatus::Unknown => 0,
                    autonat::NatStatus::Public(_) => 1,
                    autonat::NatStatus::Private => 2,
                };
                P2P_METRICS.reachability_status.set(status);
                info!(status = ?new, "NAT status changed");
            }

            // Connection errors
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer) = peer_id {
                    warn!(peer = %peer_name(peer), %error, "outgoing connection failed");
                } else {
                    warn!(%error, "outgoing connection failed");
                }
            }
            SwarmEvent::IncomingConnectionError { error, .. } => {
                warn!(%error, "incoming connection failed");
            }

            // Listen address changes
            SwarmEvent::NewListenAddr { address, .. } => {
                info!(%address, "listening on new address");
            }
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                info!(%address, "listen address expired");
            }

            // External address discovery
            SwarmEvent::ExternalAddrConfirmed { address } => {
                info!(%address, "external address confirmed");
            }
            SwarmEvent::ExternalAddrExpired { address } => {
                info!(%address, "external address expired");
            }

            _ => {}
        }
    }
}

impl<B: NetworkBehaviour> Stream for Node<B> {
    type Item = SwarmEvent<PlutoBehaviourEvent<B>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.swarm.poll_next_unpin(cx) {
            Poll::Ready(Some(event)) => {
                self.handle_event(&event);
                Poll::Ready(Some(event))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<B: NetworkBehaviour> FusedStream for Node<B> {
    fn is_terminated(&self) -> bool {
        false
    }
}
