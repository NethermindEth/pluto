//! Pluto behaviour.

use std::sync::LazyLock;

use libp2p::{identify, identity::Keypair, ping, relay, swarm::NetworkBehaviour};

use crate::{config::default_ping_config, gater::ConnGater};

/// Pluto network behaviour.
#[derive(NetworkBehaviour)]
pub struct PlutoBehaviour {
    /// Connection gater behaviour.
    pub gater: ConnGater,
    /// Relay client behaviour.
    pub relay: relay::client::Behaviour,
    /// Identify behaviour.
    pub identify: identify::Behaviour,
    /// Ping behaviour.
    pub ping: ping::Behaviour,
}

impl PlutoBehaviour {
    /// Creates a new Pluto behaviour with default configuration.
    pub fn new(key: &Keypair, relay_client: relay::client::Behaviour) -> Self {
        PlutoBehaviourBuilder::default().build(key, relay_client)
    }

    /// Returns a new builder for configuring a PlutoBehaviour.
    pub fn builder() -> PlutoBehaviourBuilder {
        PlutoBehaviourBuilder::default()
    }
}

/// The default user agent for the Pluto network.
pub static DEFAULT_USER_AGENT: LazyLock<String> =
    LazyLock::new(|| format!("pluto/{}", *charon_core::version::VERSION));

/// The default identify protocol for the Pluto network.
pub static DEFAULT_IDENTIFY_PROTOCOL: LazyLock<String> =
    LazyLock::new(|| format!("/pluto/{}", *charon_core::version::VERSION));

/// Builder for [`PlutoBehaviour`].
#[derive(Debug, Clone)]
pub struct PlutoBehaviourBuilder {
    gater: Option<ConnGater>,
    identify_protocol: String,
    user_agent: String,
}

impl Default for PlutoBehaviourBuilder {
    fn default() -> Self {
        Self {
            gater: None,
            identify_protocol: DEFAULT_IDENTIFY_PROTOCOL.clone(),
            user_agent: DEFAULT_USER_AGENT.clone(),
        }
    }
}

impl PlutoBehaviourBuilder {
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

    /// Builds the [`PlutoBehaviour`] with the provided keypair and relay
    /// client.
    pub fn build(self, key: &Keypair, relay_client: relay::client::Behaviour) -> PlutoBehaviour {
        PlutoBehaviour {
            gater: self
                .gater
                .unwrap_or_else(|| ConnGater::new_conn_gater(vec![], vec![])),
            relay: relay_client,
            identify: identify::Behaviour::new(
                identify::Config::new(self.identify_protocol, key.public())
                    .with_agent_version(self.user_agent),
            ),
            ping: ping::Behaviour::new(default_ping_config()),
        }
    }
}
