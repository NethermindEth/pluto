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
//!
//! let node = Node::new(
//!     P2PConfig::default(),
//!     secret_key,
//!     NodeType::QUIC,
//!     false, // filter_private_addrs
//!     P2PContext::default(),
//!     |builder, _keypair, relay_client| {
//!         builder
//!             .with_user_agent("my-app/1.0.0")
//!             .with_inner(relay_client)
//!     },
//! )?;
//! ```
//!
//! ## Client Node with Custom Behaviours
//!
//! ```ignore
//! use pluto_p2p::p2p::{Node, NodeType};
//!
//! let node = Node::new(
//!     P2PConfig::default(),
//!     secret_key,
//!     NodeType::QUIC,
//!     false, // filter_private_addrs
//!     P2PContext::default(),
//!     |builder, keypair, relay_client| {
//!         builder
//!             .with_user_agent("my-app/1.0.0")
//!             .with_inner(MyBehaviour {
//!                 relay: relay_client,
//!                 mdns: mdns::tokio::Behaviour::new(
//!                     mdns::Config::default(),
//!                     keypair.public().to_peer_id(),
//!                 ).unwrap(),
//!             })
//!     },
//! )?;
//! ```
//!
//! ## Relay Server Node
//!
//! ```ignore
//! use pluto_p2p::p2p::{Node, NodeType};
//!
//! let node = Node::new_server(
//!     P2PConfig::default(),
//!     secret_key,
//!     NodeType::TCP,
//!     false, // filter_private_addrs
//!     P2PContext::default(),
//!     |builder, keypair| {
//!         builder.with_inner(
//!             relay::Behaviour::new(keypair.public().to_peer_id(), relay_config)
//!         )
//!     },
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
    Multiaddr, PeerId, Swarm, SwarmBuilder, autonat, identify,
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

const YAMUX_MAX_NUM_STREAMS: usize = 2_048;

fn yamux_config() -> yamux::Config {
    let mut config = yamux::Config::default();
    config.set_max_num_streams(YAMUX_MAX_NUM_STREAMS);
    config
}

/// P2P error.
#[derive(Debug, thiserror::Error)]
pub enum P2PError {
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

    /// The provided P2P context is already bound to a different local peer ID.
    #[error("P2P context local peer ID mismatch: expected {expected}, got {actual}")]
    LocalPeerIdMismatch {
        /// Local peer ID derived from the node keypair.
        expected: Box<PeerId>,
        /// Local peer ID already bound in the shared P2P context.
        actual: Box<PeerId>,
    },

    /// Failed to configure Noise encryption.
    #[error("Failed to configure Noise encryption: {0}")]
    FailedToConfigureNoise(Box<dyn std::error::Error + Send + Sync>),

    /// Failed to configure DNS transport.
    #[error("Failed to configure DNS transport: {0}")]
    FailedToConfigureDns(Box<dyn std::error::Error + Send + Sync>),

    /// Failed to configure TCP transport (includes Noise and Yamux).
    #[error("Failed to configure TCP transport: {0}")]
    FailedToConfigureTcp(Box<dyn std::error::Error + Send + Sync>),

    /// Failed to configure relay client.
    #[error("Failed to configure relay client: {0}")]
    FailedToConfigureRelayClient(Box<dyn std::error::Error + Send + Sync>),

    /// Failed to build behaviour.
    #[error("Failed to build behaviour: {0}")]
    FailedToBuildBehaviour(Box<dyn std::error::Error + Send + Sync>),
}

impl P2PError {
    /// Failed to configure Noise encryption.
    pub fn failed_to_configure_noise(
        error: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::FailedToConfigureNoise(Box::new(error))
    }

    /// Failed to configure DNS transport.
    pub fn failed_to_configure_dns(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::FailedToConfigureDns(Box::new(error))
    }

    /// Failed to configure TCP transport.
    pub fn failed_to_configure_tcp(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::FailedToConfigureTcp(Box::new(error))
    }

    /// Failed to configure relay client.
    pub fn failed_to_configure_relay_client(
        error: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::FailedToConfigureRelayClient(Box::new(error))
    }

    /// Failed to build behaviour.
    pub fn failed_to_build_behaviour(
        error: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::FailedToBuildBehaviour(Box::new(error))
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
    /// The `behaviour_fn` receives a `PlutoBehaviourBuilder`, keypair, and
    /// relay client. It should configure the builder (e.g., set user agent,
    /// inner behaviour) and return it. The builder will then be finalized
    /// internally.
    ///
    /// # Arguments
    ///
    /// * `cfg` - P2P configuration for addresses and networking
    /// * `key` - Secret key for node identity
    /// * `node_type` - Transport type (TCP or QUIC)
    /// * `filter_private_addrs` - Whether to filter private addresses
    /// * `p2p_context` - Shared P2P runtime context for this node
    /// * `behaviour_fn` - Closure that configures and returns the behaviour
    ///   builder
    ///
    /// # Example
    ///
    /// ```ignore
    /// let node = Node::new(
    ///     P2PConfig::default(),
    ///     secret_key,
    ///     NodeType::QUIC,
    ///     false,
    ///     P2PContext::new(vec![peer1, peer2]),
    ///     |builder, _keypair, relay_client| {
    ///         builder
    ///             .with_user_agent("my-app/1.0.0")
    ///             .with_inner(MyBehaviour { relay_client, peerinfo: ... })
    ///     },
    /// )?;
    /// ```
    pub fn new<F>(
        cfg: P2PConfig,
        key: k256::SecretKey,
        node_type: NodeType,
        filter_private_addrs: bool,
        p2p_context: P2PContext,
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(
            PlutoBehaviourBuilder<B>,
            &Keypair,
            relay::client::Behaviour,
        ) -> PlutoBehaviourBuilder<B>,
    {
        let keypair = utils::keypair_from_secret_key(key)?;
        Self::bind_local_peer_id(&p2p_context, keypair.public().to_peer_id())?;

        let mut node = match node_type {
            NodeType::TCP => Self::build_tcp_client(keypair, p2p_context, behaviour_fn),
            NodeType::QUIC => Self::build_quic_client(keypair, p2p_context, behaviour_fn),
        }?;

        node.apply_config(&cfg, filter_private_addrs)?;

        Ok(node)
    }

    /// Creates a new server node without relay client.
    ///
    /// Server nodes (like relay servers) don't include relay client support
    /// since they are expected to be publicly reachable.
    ///
    /// The `behaviour_fn` receives a `PlutoBehaviourBuilder` and keypair. It
    /// should configure the builder (e.g., set user agent, inner behaviour)
    /// and return it.
    ///
    /// Per-peer bandwidth counters
    /// (`relay_p2p_network_sent_bytes_total{peer,peer_cluster}` and
    /// `relay_p2p_network_receive_bytes_total{peer,peer_cluster}`) are tracked
    /// automatically via [`crate::bandwidth::PeerBandwidthTransport`] and
    /// registered as vise globals. `peer_cluster` is always empty since the
    /// relay cannot resolve cluster membership.
    ///
    /// Note: upstream rust-libp2p does not yet expose per-peer callbacks
    /// natively; see <https://github.com/libp2p/rust-libp2p/issues/3262>.
    pub fn new_server<F>(
        cfg: P2PConfig,
        key: k256::SecretKey,
        node_type: NodeType,
        filter_private_addrs: bool,
        p2p_context: P2PContext,
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(PlutoBehaviourBuilder<B>, &Keypair) -> PlutoBehaviourBuilder<B>,
    {
        let keypair = utils::keypair_from_secret_key(key)?;
        Self::bind_local_peer_id(&p2p_context, keypair.public().to_peer_id())?;

        let mut node = match node_type {
            NodeType::TCP => Self::build_tcp_server(keypair, p2p_context, behaviour_fn),
            NodeType::QUIC => Self::build_quic_server(keypair, p2p_context, behaviour_fn),
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

    fn bind_local_peer_id(p2p_context: &P2PContext, local_peer_id: PeerId) -> Result<()> {
        match p2p_context.local_peer_id() {
            Some(existing_peer_id) if existing_peer_id != local_peer_id => {
                Err(P2PError::LocalPeerIdMismatch {
                    expected: Box::new(local_peer_id),
                    actual: Box::new(existing_peer_id),
                })
            }
            Some(_) => Ok(()),
            None => {
                p2p_context.set_local_peer_id(local_peer_id);
                Ok(())
            }
        }
    }

    fn build_quic_client<F>(
        keypair: Keypair,
        p2p_context: P2PContext,
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(
            PlutoBehaviourBuilder<B>,
            &Keypair,
            relay::client::Behaviour,
        ) -> PlutoBehaviourBuilder<B>,
    {
        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux_config)
            .map_err(P2PError::failed_to_configure_tcp)?
            .with_quic()
            .with_dns()
            .map_err(P2PError::failed_to_configure_dns)?
            .with_relay_client(noise::Config::new, yamux_config)
            .map_err(P2PError::failed_to_configure_relay_client)?
            .with_behaviour(|key, relay_client| {
                let builder =
                    PlutoBehaviourBuilder::new(p2p_context.clone()).with_quic_enabled(true);
                behaviour_fn(builder, key, relay_client).build(key)
            })
            .map_err(P2PError::failed_to_build_behaviour)?
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
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(
            PlutoBehaviourBuilder<B>,
            &Keypair,
            relay::client::Behaviour,
        ) -> PlutoBehaviourBuilder<B>,
    {
        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux_config)
            .map_err(P2PError::failed_to_configure_tcp)?
            .with_dns()
            .map_err(P2PError::failed_to_configure_dns)?
            .with_relay_client(noise::Config::new, yamux_config)
            .map_err(P2PError::failed_to_configure_relay_client)?
            .with_behaviour(|key, relay_client| {
                let builder = PlutoBehaviourBuilder::new(p2p_context.clone());
                behaviour_fn(builder, key, relay_client).build(key)
            })
            .map_err(P2PError::failed_to_build_behaviour)?
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
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(PlutoBehaviourBuilder<B>, &Keypair) -> PlutoBehaviourBuilder<B>,
    {
        let swarm = Self::build_server_swarm(keypair, p2p_context.clone(), behaviour_fn)?;
        Ok(Node {
            swarm,
            node_type: NodeType::QUIC,
            p2p_context,
        })
    }

    fn build_tcp_server<F>(
        keypair: Keypair,
        p2p_context: P2PContext,
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: FnOnce(PlutoBehaviourBuilder<B>, &Keypair) -> PlutoBehaviourBuilder<B>,
    {
        let swarm = Self::build_server_swarm(keypair, p2p_context.clone(), behaviour_fn)?;
        Ok(Node {
            swarm,
            node_type: NodeType::TCP,
            p2p_context,
        })
    }

    fn build_server_swarm<F>(
        keypair: Keypair,
        p2p_context: P2PContext,
        behaviour_fn: F,
    ) -> Result<Swarm<PlutoBehaviour<B>>>
    where
        F: FnOnce(PlutoBehaviourBuilder<B>, &Keypair) -> PlutoBehaviourBuilder<B>,
    {
        use libp2p::{
            core::{Transport as _, muxing::StreamMuxerBox, upgrade::Version},
            dns, quic,
        };
        let local_peer_id = keypair.public().to_peer_id();

        let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default())
            .upgrade(Version::V1Lazy)
            .authenticate(
                noise::Config::new(&keypair).map_err(P2PError::failed_to_configure_noise)?,
            )
            .multiplex(yamux_config())
            .map(|(p, c), _| (p, StreamMuxerBox::new(c)));

        let quic_transport = quic::tokio::Transport::new(quic::Config::new(&keypair))
            .map(|(peer_id, conn), _| (peer_id, StreamMuxerBox::new(conn)));

        let combined = tcp_transport
            .or_transport(quic_transport)
            .map(|either, _| either.into_inner());

        let dns =
            dns::tokio::Transport::system(combined).map_err(P2PError::failed_to_configure_dns)?;

        let transport = crate::bandwidth::PeerBandwidthTransport::new(dns)
            .map(|(peer_id, conn), _| (peer_id, StreamMuxerBox::new(conn)))
            .boxed();

        let behaviour =
            behaviour_fn(PlutoBehaviourBuilder::new(p2p_context), &keypair).build(&keypair);

        Ok(Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            utils::default_swarm_config(libp2p::swarm::Config::with_tokio_executor()),
        ))
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
            // Identify - update peer addresses in the peer store
            SwarmEvent::Behaviour(PlutoBehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                // The peer addresses will be available in the next poll of the node.
                self.p2p_context
                    .peer_store_write_lock()
                    .set_peer_addresses(*peer_id, info.listen_addrs.clone());
            }

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
