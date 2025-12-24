//! Pluto Mdns behaviour.

use libp2p::{identity::Keypair, mdns, relay, swarm::NetworkBehaviour};

use crate::behaviours::pluto::{PlutoBehaviour, PlutoBehaviourBuilder};

/// Pluto network behaviour with mDNS discovery.
#[derive(NetworkBehaviour)]
pub struct PlutoMdnsBehaviour {
    /// Pluto behaviour.
    pub pluto: PlutoBehaviour,
    /// Mdns behaviour.
    pub mdns: mdns::tokio::Behaviour,
}

impl PlutoMdnsBehaviour {
    /// Creates a new Pluto Mdns behaviour with default configuration.
    pub fn new(key: &Keypair, relay_client: relay::client::Behaviour) -> Self {
        PlutoMdnsBehaviourBuilder::default().build(key, relay_client)
    }

    /// Returns a new builder for configuring a PlutoMdnsBehaviour.
    pub fn builder() -> PlutoMdnsBehaviourBuilder {
        PlutoMdnsBehaviourBuilder::default()
    }
}

/// Builder for [`PlutoMdnsBehaviour`].
pub struct PlutoMdnsBehaviourBuilder {
    pluto: PlutoBehaviourBuilder,
    mdns_config: mdns::Config,
}

impl Default for PlutoMdnsBehaviourBuilder {
    fn default() -> Self {
        Self {
            pluto: PlutoBehaviourBuilder::default(),
            mdns_config: mdns::Config::default(),
        }
    }
}

impl PlutoMdnsBehaviourBuilder {
    /// Creates a new builder with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the inner [`PlutoBehaviourBuilder`] entirely.
    pub fn with_pluto(mut self, pluto: PlutoBehaviourBuilder) -> Self {
        self.pluto = pluto;
        self
    }

    /// Configures the inner [`PlutoBehaviourBuilder`] via a closure.
    ///
    /// This is ergonomic for inline configuration:
    /// ```ignore
    /// PlutoMdnsBehaviourBuilder::new()
    ///     .configure_pluto(|p| p.with_ping_interval(Duration::from_secs(5)))
    ///     .build(&key, relay_client)
    /// ```
    pub fn configure_pluto(
        mut self,
        f: impl FnOnce(PlutoBehaviourBuilder) -> PlutoBehaviourBuilder,
    ) -> Self {
        self.pluto = f(self.pluto);
        self
    }

    /// Sets the mDNS configuration.
    pub fn with_mdns_config(mut self, config: mdns::Config) -> Self {
        self.mdns_config = config;
        self
    }

    /// Builds the [`PlutoMdnsBehaviour`] with the provided keypair and relay
    /// client.
    pub fn build(
        self,
        key: &Keypair,
        relay_client: relay::client::Behaviour,
    ) -> PlutoMdnsBehaviour {
        PlutoMdnsBehaviour {
            pluto: self.pluto.build(key, relay_client),
            mdns: mdns::tokio::Behaviour::new(self.mdns_config, key.public().to_peer_id())
                .expect("Failed to create mDNS behaviour"),
        }
    }
}
