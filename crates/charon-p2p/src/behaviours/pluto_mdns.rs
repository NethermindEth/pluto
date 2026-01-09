//! Pluto Mdns behaviour.
use libp2p::{identity::Keypair, mdns, relay, swarm::NetworkBehaviour};

use crate::behaviours::pluto::PlutoBehaviour;

/// Pluto network behaviour.
#[derive(NetworkBehaviour)]
pub struct PlutoMdnsBehaviour {
    /// Pluto behaviour.
    pub pluto: PlutoBehaviour,
    /// Mdns behaviour.
    pub mdns: mdns::tokio::Behaviour,
}

impl PlutoMdnsBehaviour {
    /// Creates a new Pluto Mdns behaviour.
    pub fn new(key: &Keypair, relay_client: relay::client::Behaviour) -> Self {
        Self {
            pluto: PlutoBehaviour::new(key, relay_client),
            mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                .expect("Failed to create mDNS behaviour"),
        }
    }
}
