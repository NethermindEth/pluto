//! Pluto behaviour.

use std::time::Duration;

use libp2p::{identify, identity::Keypair, ping, relay, swarm::NetworkBehaviour};

#[derive(NetworkBehaviour)]
pub struct PlutoBehaviour {
    /// Relay client behaviour.
    pub relay: relay::client::Behaviour,
    /// Identify behaviour.
    pub identify: identify::Behaviour,
    /// Ping behaviour.
    pub ping: ping::Behaviour,
}

impl PlutoBehaviour {
    /// Creates a new Pluto behaviour.
    pub fn new(key: &Keypair, relay_client: relay::client::Behaviour) -> Self {
        Self {
            relay: relay_client,
            identify: identify::Behaviour::new(identify::Config::new(
                "/pluto/1.0.0-alpha".into(),
                key.public(),
            )),
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(1))
                    .with_timeout(Duration::from_secs(2)),
            ),
        }
    }
}
