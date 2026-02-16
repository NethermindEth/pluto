//! Pluto behaviour.
//!
//! This module defines the core network behaviour for Pluto nodes, combining
//! multiple libp2p protocols into a unified behaviour.

use std::sync::LazyLock;

use libp2p::{autonat, identify, identity::Keypair, ping, relay, swarm::NetworkBehaviour};

use crate::{config::default_ping_config, gater::ConnGater};

pub use super::optional::OptionalBehaviour;

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
    /// Relay client behaviour.
    pub relay: relay::client::Behaviour,
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

/// The default user agent for the Pluto network.
pub static DEFAULT_USER_AGENT: LazyLock<String> =
    LazyLock::new(|| format!("pluto/{}", *pluto_core::version::VERSION));

/// The default identify protocol for the Pluto network.
pub static DEFAULT_IDENTIFY_PROTOCOL: LazyLock<String> =
    LazyLock::new(|| format!("/pluto/{}", *pluto_core::version::VERSION));

/// Builder for [`PlutoBehaviour`].
#[derive(Debug, Clone)]
pub struct PlutoBehaviourBuilder<B> {
    gater: Option<ConnGater>,
    identify_protocol: String,
    user_agent: String,
    autonat_config: autonat::Config,
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
    pub fn with_gater(mut self, gater: ConnGater) -> Self {
        self.gater = Some(gater);
        self
    }

    /// Sets the identify protocol string.
    pub fn with_identify_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.identify_protocol = protocol.into();
        self
    }

    /// Sets the user agent string.
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Sets the AutoNAT configuration.
    pub fn with_autonat_config(mut self, config: autonat::Config) -> Self {
        self.autonat_config = config;
        self
    }

    /// Sets the inner behaviour.
    pub fn with_inner(mut self, inner: B) -> Self {
        self.inner = Some(inner);
        self
    }

    /// Builds the [`PlutoBehaviour`] with the provided keypair and relay
    /// client.
    pub fn build(self, key: &Keypair, relay_client: relay::client::Behaviour) -> PlutoBehaviour<B> {
        PlutoBehaviour {
            gater: self.gater.unwrap_or_else(ConnGater::new_open_gater),
            relay: relay_client,
            identify: identify::Behaviour::new(
                identify::Config::new(self.identify_protocol, key.public())
                    .with_agent_version(self.user_agent),
            ),
            ping: ping::Behaviour::new(default_ping_config()),
            autonat: autonat::Behaviour::new(key.public().to_peer_id(), self.autonat_config),
            inner: self.inner.into(),
        }
    }
}
