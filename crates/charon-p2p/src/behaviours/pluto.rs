//! Pluto behaviour.

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

/// Builder for [`PlutoBehaviour`].
#[derive(Debug, Clone)]
pub struct PlutoBehaviourBuilder {
    gater: Option<ConnGater>,
    identify_protocol: String,
}

impl Default for PlutoBehaviourBuilder {
    fn default() -> Self {
        Self {
            gater: None,
            identify_protocol: "/pluto/1.0.0-alpha".into(),
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

    /// Builds the [`PlutoBehaviour`] with the provided keypair and relay
    /// client.
    pub fn build(self, key: &Keypair, relay_client: relay::client::Behaviour) -> PlutoBehaviour {
        PlutoBehaviour {
            gater: self
                .gater
                .unwrap_or_else(|| ConnGater::new_conn_gater(vec![], vec![])),
            relay: relay_client,
            identify: identify::Behaviour::new(identify::Config::new(
                self.identify_protocol,
                key.public(),
            )),
            ping: ping::Behaviour::new(default_ping_config()),
        }
    }
}
