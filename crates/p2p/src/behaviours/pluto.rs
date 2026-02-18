//! Pluto behaviour.
//!
//! This module defines the core network behaviour for Pluto nodes, combining
//! multiple libp2p protocols into a unified behaviour.

use std::{sync::LazyLock, time::Duration};

use libp2p::{autonat, identify, identity::Keypair, ping, swarm::NetworkBehaviour};

use crate::{
    config::{DEFAULT_PING_INTERVAL, DEFAULT_PING_TIMEOUT},
    gater::ConnGater,
};

pub use super::optional::OptionalBehaviour;

/// The default user agent for the Pluto network.
pub static DEFAULT_USER_AGENT: LazyLock<String> =
    LazyLock::new(|| format!("pluto/{}", *pluto_core::version::VERSION));

/// The default identify protocol for the Pluto network.
pub static DEFAULT_IDENTIFY_PROTOCOL: LazyLock<String> =
    LazyLock::new(|| format!("/pluto/{}", *pluto_core::version::VERSION));

/// Default identify interval (5 minutes).
pub const DEFAULT_IDENTIFY_INTERVAL: Duration = Duration::from_secs(300);

/// Default identify cache size (100 entries).
pub const DEFAULT_IDENTIFY_CACHE_SIZE: usize = 100;

/// Pluto network behaviour.
///
/// Combines multiple libp2p protocols:
/// - **Connection gating**: Controls which connections are allowed
/// - **Relay client**: Enables NAT traversal via relay servers
/// - **Identify**: Exchanges peer information and supported protocols
/// - **Ping**: Measures latency and keeps connections alive
/// - **AutoNAT**: Detects NAT status and public reachability
#[derive(NetworkBehaviour)]
pub struct PlutoBehaviour<B: NetworkBehaviour> {
    /// Connection gater behaviour.
    pub gater: ConnGater,
    /// Identify behaviour.
    pub identify: identify::Behaviour,
    /// Ping behaviour.
    pub ping: ping::Behaviour,
    /// AutoNAT behaviour for NAT detection.
    pub autonat: autonat::Behaviour,
    /// Inner behaviour.
    pub inner: OptionalBehaviour<B>,
}

impl<B: NetworkBehaviour> PlutoBehaviour<B> {
    /// Returns a new builder for configuring a PlutoBehaviour.
    pub fn builder() -> PlutoBehaviourBuilder<B> {
        PlutoBehaviourBuilder::default()
    }
}

/// Builder for [`PlutoBehaviour`].
///
/// Provides comprehensive configuration for all sub-behaviours:
/// - **Gater**: Connection filtering (allowlist/blocklist)
/// - **Identify**: Protocol and agent identification
/// - **Ping**: Latency measurement and keepalive
/// - **AutoNAT**: NAT traversal detection
#[derive(Debug, Clone)]
pub struct PlutoBehaviourBuilder<B> {
    // Gater config
    gater: Option<ConnGater>,

    // Identify config
    identify_protocol: String,
    user_agent: String,

    // AutoNAT config
    autonat_config: autonat::Config,

    // Inner behaviour
    inner: Option<B>,
}

impl<B> Default for PlutoBehaviourBuilder<B> {
    fn default() -> Self {
        Self {
            gater: None,
            identify_protocol: DEFAULT_IDENTIFY_PROTOCOL.clone(),
            user_agent: DEFAULT_USER_AGENT.clone(),
            autonat_config: autonat::Config::default(),
            inner: None,
        }
    }
}

impl<B: NetworkBehaviour> PlutoBehaviourBuilder<B> {
    /// Creates a new builder with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the connection gater.
    ///
    /// The gater controls which peers are allowed to connect. By default,
    /// an open gater is used that allows all connections.
    pub fn with_gater(mut self, gater: ConnGater) -> Self {
        self.gater = Some(gater);
        self
    }

    /// Sets the identify protocol string.
    ///
    /// This is exchanged with peers during the identify handshake.
    /// Default: `/pluto/{version}`
    pub fn with_identify_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.identify_protocol = protocol.into();
        self
    }

    /// Sets the user agent string.
    ///
    /// This is sent to peers during the identify handshake.
    /// Default: `pluto/{version}`
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Sets the AutoNAT configuration.
    ///
    /// AutoNAT is used to detect NAT status and public reachability.
    pub fn with_autonat_config(mut self, config: autonat::Config) -> Self {
        self.autonat_config = config;
        self
    }

    /// Sets the inner behaviour.
    ///
    /// The inner behaviour is wrapped by PlutoBehaviour and can be any
    /// type implementing `NetworkBehaviour`. Common choices include:
    /// - `relay::client::Behaviour` for relay client support
    /// - A custom composed behaviour with multiple protocols
    pub fn with_inner(mut self, inner: B) -> Self {
        self.inner = Some(inner);
        self
    }

    /// Builds the [`PlutoBehaviour`] with the provided keypair.
    ///
    /// # Arguments
    ///
    /// * `key` - The keypair for this node, used for identify and autonat
    pub fn build(self, key: &Keypair) -> PlutoBehaviour<B> {
        let identify_config = identify::Config::new(self.identify_protocol, key.public())
            .with_agent_version(self.user_agent)
            .with_interval(DEFAULT_IDENTIFY_INTERVAL)
            .with_cache_size(DEFAULT_IDENTIFY_CACHE_SIZE);

        PlutoBehaviour {
            gater: self.gater.unwrap_or_else(ConnGater::new_open_gater),
            identify: identify::Behaviour::new(identify_config),
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(DEFAULT_PING_INTERVAL)
                    .with_timeout(DEFAULT_PING_TIMEOUT),
            ),
            autonat: autonat::Behaviour::new(key.public().to_peer_id(), self.autonat_config),
            inner: self.inner.into(),
        }
    }
}
