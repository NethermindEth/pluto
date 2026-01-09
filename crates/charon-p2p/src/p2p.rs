//! P2P core concepts

use std::time::Duration;

use libp2p::{
    Swarm, SwarmBuilder, identity::Keypair, noise, relay, swarm::NetworkBehaviour, tcp, yamux,
};

use crate::{config::P2PConfig, gater::ConnGater};

/// P2P error.
#[derive(Debug, thiserror::Error)]
pub enum P2PError {
    /// Failed to build the swarm.
    #[error("Failed to build the swarm: {0}")]
    FailedToBuildSwarm(Box<dyn std::error::Error + Send + Sync>),

    /// Failed to convert the secret key to a libp2p keypair.
    #[error("Failed to convert the secret key to a libp2p keypair: {0}")]
    FailedToConvertSecretKeyToLibp2pKeypair(#[from] k256::pkcs8::der::Error),

    /// Failed to decode the libp2p keypair.
    #[error("Failed to decode the libp2p keypair: {0}")]
    FailedToDecodeLibp2pKeypair(#[from] libp2p::identity::DecodingError),
}

impl P2PError {
    /// Failed to build the swarm.
    pub fn failed_to_build_swarm(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::FailedToBuildSwarm(Box::new(error))
    }
}

type Result<T> = std::result::Result<T, P2PError>;

/// Node type.
pub enum NodeType {
    /// TCP node.
    TCP,
    /// QUIC node.
    QUIC,
}

/// Node.
pub struct Node<B: NetworkBehaviour> {
    /// Swarm.
    pub swarm: Swarm<B>,
}

impl<B: NetworkBehaviour> Node<B> {
    /// Creates a new node.
    pub fn new<F>(
        cfg: P2PConfig,
        key: k256::SecretKey,
        conn_gater: ConnGater,
        filter_private_addrs: bool,
        node_type: NodeType,
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: Fn(&Keypair, relay::client::Behaviour) -> B,
    {
        match node_type {
            NodeType::TCP => {
                Self::new_with_tcp(cfg, key, conn_gater, filter_private_addrs, behaviour_fn)
            }
            NodeType::QUIC => {
                Self::new_with_quic(cfg, key, conn_gater, filter_private_addrs, behaviour_fn)
            }
        }
    }

    fn default_swarm_config(cfg: libp2p::swarm::Config) -> libp2p::swarm::Config {
        cfg.with_idle_connection_timeout(Duration::from_secs(300))
    }

    fn default_tcp_config() -> tcp::Config {
        tcp::Config::default()
    }

    /// Creates a new node with QUIC.
    fn new_with_quic<F>(
        _cfg: P2PConfig,
        key: k256::SecretKey,
        _conn_gater: ConnGater,
        _filter_private_addrs: bool,
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: Fn(&Keypair, relay::client::Behaviour) -> B,
    {
        let mut der = key.to_sec1_der()?;
        let keypair = Keypair::secp256k1_from_der(&mut der)?;

        let swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                Self::default_tcp_config(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(P2PError::failed_to_build_swarm)?
            .with_quic()
            .with_dns()
            .map_err(P2PError::failed_to_build_swarm)?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(P2PError::failed_to_build_swarm)?
            .with_behaviour(behaviour_fn)
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(Self::default_swarm_config)
            .build();

        Ok(Node { swarm })
    }

    /// Creates a new node with TCP.
    fn new_with_tcp<F>(
        _cfg: P2PConfig,
        key: k256::SecretKey,
        _conn_gater: ConnGater,
        _filter_private_addrs: bool,
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: Fn(&Keypair, relay::client::Behaviour) -> B,
    {
        let mut der = key.to_sec1_der()?;
        let keypair = Keypair::secp256k1_from_der(&mut der)?;

        let swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                Self::default_tcp_config(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(P2PError::failed_to_build_swarm)?
            .with_dns()
            .map_err(P2PError::failed_to_build_swarm)?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(P2PError::failed_to_build_swarm)?
            .with_behaviour(behaviour_fn)
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(Self::default_swarm_config)
            .build();

        Ok(Node { swarm })
    }
}
