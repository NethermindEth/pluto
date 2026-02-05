#![allow(missing_docs)] // we need to allow missing docs for the derive macro
//! Relay server behaviour.

use std::sync::LazyLock;

use libp2p::{identify, identity::Keypair, ping, relay, swarm::NetworkBehaviour};

use pluto_p2p::gater::ConnGater;

/// Relay server network behaviour.
#[derive(NetworkBehaviour)]
pub struct RelayServerBehaviour {
    /// Relay server.
    pub relay: relay::Behaviour,
    /// Identify behaviour.
    pub identify: identify::Behaviour,
    /// Ping behaviour.
    pub ping: ping::Behaviour,
    /// Gater behaviour.
    pub gater: ConnGater,
}

impl RelayServerBehaviour {
    /// Creates a new `RelayServerBehaviour` with default configuration.
    #[must_use]
    pub fn new(key: &Keypair) -> Self {
        RelayServerBehaviourBuilder::default().build(key)
    }

    /// Returns a new builder for configuring a `RelayServerBehaviour`.
    #[must_use]
    pub fn builder() -> RelayServerBehaviourBuilder {
        RelayServerBehaviourBuilder::default()
    }
}

/// Builder for [`RelayServerBehaviour`].
pub struct RelayServerBehaviourBuilder {
    gater: Option<ConnGater>,
    identify_protocol: String,
    relay_config: Option<relay::Config>,
    user_agent: Option<String>,
}

/// The default identify protocol for the Pluto network.
pub static DEFAULT_IDENTIFY_PROTOCOL: LazyLock<String> =
    LazyLock::new(|| format!("/pluto/relay/{}", *pluto_core::version::VERSION));

impl Default for RelayServerBehaviourBuilder {
    fn default() -> Self {
        Self {
            gater: None,
            identify_protocol: DEFAULT_IDENTIFY_PROTOCOL.clone(),
            relay_config: None,
            user_agent: None,
        }
    }
}

impl RelayServerBehaviourBuilder {
    /// Creates a new builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the connection gater.
    #[must_use]
    pub fn with_gater(mut self, gater: ConnGater) -> Self {
        self.gater = Some(gater);
        self
    }

    /// Sets the identify protocol string.
    pub fn with_identify_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.identify_protocol = protocol.into();
        self
    }

    /// Sets the relay server configuration.
    #[must_use]
    pub fn with_relay_config(mut self, config: relay::Config) -> Self {
        self.relay_config = Some(config);
        self
    }

    /// Sets the user agent string.
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Builds the [`RelayServerBehaviour`] with the provided keypair.
    #[must_use]
    pub fn build(self, key: &Keypair) -> RelayServerBehaviour {
        RelayServerBehaviour {
            relay: relay::Behaviour::new(
                key.public().to_peer_id(),
                self.relay_config.unwrap_or_default(),
            ),
            identify: identify::Behaviour::new(
                identify::Config::new(self.identify_protocol, key.public()).with_agent_version(
                    self.user_agent.unwrap_or_else(|| {
                        pluto_p2p::behaviours::pluto::DEFAULT_USER_AGENT.clone()
                    }),
                ),
            ),
            ping: ping::Behaviour::new(pluto_p2p::config::default_ping_config()),
            gater: self
                .gater
                .unwrap_or_else(|| ConnGater::new_conn_gater(vec![], vec![])),
        }
    }
}
