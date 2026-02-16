//! Pluto Mdns behaviour.

use libp2p::{identity::Keypair, mdns, relay};

use crate::behaviours::pluto::{PlutoBehaviour, PlutoBehaviourBuilder};

pub type PlutoMdnsBehaviour = PlutoBehaviour<mdns::tokio::Behaviour>;

/// Builder for [`PlutoMdnsBehaviour`].
#[derive(Default)]
pub struct PlutoMdnsBehaviourBuilder {
    pluto: PlutoBehaviourBuilder<mdns::tokio::Behaviour>,
    mdns_config: mdns::Config,
}

impl PlutoMdnsBehaviourBuilder {
    /// Creates a new builder with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the inner [`PlutoBehaviourBuilder`] entirely.
    pub fn with_pluto(mut self, pluto: PlutoBehaviourBuilder<mdns::tokio::Behaviour>) -> Self {
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
        f: impl FnOnce(
            PlutoBehaviourBuilder<mdns::tokio::Behaviour>,
        ) -> PlutoBehaviourBuilder<mdns::tokio::Behaviour>,
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
        self.pluto
            .with_inner(
                mdns::tokio::Behaviour::new(self.mdns_config, key.public().to_peer_id())
                    .expect("Failed to create mDNS behaviour"),
            )
            .build(key, relay_client)
    }
}
