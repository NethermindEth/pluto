#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(unused)]

//! P2P core concepts

use std::{sync::Once, time::Duration};

use libp2p::{
    Swarm, SwarmBuilder, identify,
    identity::Keypair,
    noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};

use libp2p::mdns;

use crate::{config::P2PConfig, gater::ConnGater};

pub enum NodeType {
    TCP,
    QUIC,
}

#[derive(NetworkBehaviour)]
pub struct PlutoBehavior {
    pub relay: relay::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

pub trait LoopBehavior {
    fn spawn_loop(&self) -> impl Future<Output = ()>;
}

impl LoopBehavior for Node<PlutoBehavior> {
    async fn spawn_loop(&self) {}
}

impl PlutoBehavior {
    pub fn new(key: &Keypair) -> Self {
        Self {
            relay: relay::Behaviour::new(key.public().to_peer_id(), Default::default()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/pluto/1.0.0-alpha".into(),
                key.public(),
            )),
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(1))
                    .with_timeout(Duration::from_secs(2)),
            ),
            mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                .unwrap(),
        }
    }
}

pub struct Node<B: NetworkBehaviour> {
    pub swarm: Swarm<B>,
    pub callbacks: Vec<Box<dyn Fn(&SwarmEvent<B>) + Send + Sync>>,
}

impl<B: NetworkBehaviour> Node<B> {
    pub fn new<F>(
        cfg: P2PConfig,
        key: k256::SecretKey,
        conn_gater: ConnGater,
        filter_private_addrs: bool,
        node_type: NodeType,
        behavior_fn: F,
    ) -> Self
    where
        F: Fn(&Keypair) -> B,
    {
        match node_type {
            NodeType::TCP => {
                Self::new_with_tcp(cfg, key, conn_gater, filter_private_addrs, behavior_fn)
            }
            NodeType::QUIC => {
                Self::new_with_quic(cfg, key, conn_gater, filter_private_addrs, behavior_fn)
            }
        }
    }

    pub fn new_with_quic<F>(
        cfg: P2PConfig,
        key: k256::SecretKey,
        conn_gater: ConnGater,
        filter_private_addrs: bool,
        behavior_fn: F,
    ) -> Self
    where
        F: Fn(&Keypair) -> B,
    {
        let mut der = key.to_sec1_der().unwrap();
        let keypair = Keypair::secp256k1_from_der(&mut der).unwrap();

        let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_quic()
            .with_behaviour(behavior_fn)
            .unwrap()
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(300)))
            .build();

        Node {
            swarm,
            callbacks: vec![],
        }
    }

    pub fn new_with_tcp<F>(
        cfg: P2PConfig,
        key: k256::SecretKey,
        conn_gater: ConnGater,
        filter_private_addrs: bool,
        behavior_fn: F,
    ) -> Self
    where
        F: Fn(&Keypair) -> B,
    {
        let mut der = key.to_sec1_der().unwrap();
        let keypair = Keypair::secp256k1_from_der(&mut der).unwrap();

        let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(behavior_fn)
            .unwrap()
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(300)))
            .build();

        Node {
            swarm,
            callbacks: vec![],
        }
    }

    pub fn add_callback(&mut self, callback: Box<dyn Fn(&SwarmEvent<B>) + Send + Sync>) {}
}
