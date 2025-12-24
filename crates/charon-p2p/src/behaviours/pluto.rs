//! Pluto behaviour.

use std::time::Duration;

use libp2p::{identify, identity::Keypair, ping, relay, swarm::NetworkBehaviour};

use crate::gater::ConnGater;

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
#[derive(Clone)]
pub struct PlutoBehaviourBuilder {
    gater: Option<ConnGater>,
    identify_protocol: String,
    ping_interval: Duration,
    ping_timeout: Duration,
}

impl Default for PlutoBehaviourBuilder {
    fn default() -> Self {
        Self {
            gater: None,
            identify_protocol: "/pluto/1.0.0-alpha".into(),
            ping_interval: Duration::from_secs(1),
            ping_timeout: Duration::from_secs(2),
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

    /// Sets the ping interval.
    pub fn with_ping_interval(mut self, interval: Duration) -> Self {
        self.ping_interval = interval;
        self
    }

    /// Sets the ping timeout.
    pub fn with_ping_timeout(mut self, timeout: Duration) -> Self {
        self.ping_timeout = timeout;
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
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(self.ping_interval)
                    .with_timeout(self.ping_timeout),
            ),
        }
    }
}
