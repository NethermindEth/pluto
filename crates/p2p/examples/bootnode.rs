#![allow(missing_docs)]
//! Bootnode example

use std::{path::PathBuf, str::FromStr};

use anyhow::Result;
use clap::Parser;
use futures::StreamExt;
use libp2p::{
    PeerId,
    relay::{self},
    swarm::NetworkBehaviour,
};
use pluto_cluster::lock::Lock;
use pluto_p2p::{
    bootnode,
    config::P2PConfig,
    gater, k1,
    p2p::{Node, NodeType},
    relay::{MutableRelayReservation, RelayRouter},
};
use pluto_tracing::TracingConfig;
use tokio::{fs, signal};
use tokio_util::sync::CancellationToken;
use tracing::info;

#[derive(NetworkBehaviour)]
pub struct ExampleBehaviour {
    pub relay: relay::client::Behaviour,
    pub relay_reservation: MutableRelayReservation,
    pub relay_router: RelayRouter,
}

#[derive(Debug, Parser)]
pub struct Args {
    /// The relay URLs to use
    #[arg(long)]
    relays: Vec<String>,

    /// The data directory to use
    #[arg(long)]
    data_dir: PathBuf,

    #[arg(long)]
    known_peers: Vec<String>,

    #[arg(short, long, default_value = "false")]
    filter_private_addrs: bool,

    /// The external IP address of the node.
    #[arg(long)]
    external_ip: Option<String>,

    /// The external host of the node.
    #[arg(long)]
    external_host: Option<String>,

    /// The TCP addresses of the node.
    #[arg(long)]
    tcp_addrs: Vec<String>,

    /// The UDP addresses of the node.
    #[arg(long)]
    udp_addrs: Vec<String>,

    /// Whether to disable the reuse port.
    #[arg(long, default_value = "false")]
    disable_reuse_port: bool,
}

#[tokio::main]
pub async fn main() -> Result<()> {
    pluto_tracing::init(&TracingConfig::default()).expect("Failed to initialize tracing");

    let args = Args::parse();
    let pk = k1::load_priv_key(&args.data_dir).expect("Failed to load private key");
    let ct = CancellationToken::new();

    let lock_str = fs::read_to_string(&args.data_dir.join("cluster-lock.json"))
        .await
        .expect("Failed to load lock");
    let lock: Lock = serde_json::from_str(&lock_str).expect("Failed to parse lock");

    let lock_hash_str = hex::encode(&lock.lock_hash);

    let relays: Vec<pluto_p2p::peer::MutablePeer> =
        bootnode::new_relays(ct.child_token(), &args.relays, &lock_hash_str).await?;
    let mut known_peers: Vec<PeerId> = args
        .known_peers
        .iter()
        .map(|p| PeerId::from_str(p).expect("Failed to parse peer ID"))
        .collect();

    let lock_peer_ids = lock.peer_ids().expect("Failed to get lock peer IDs");
    known_peers.extend(lock_peer_ids);

    let conn_gater = gater::ConnGater::new(
        gater::Config::closed()
            .with_relays(relays.clone())
            .with_peer_ids(known_peers.clone()),
    );

    let p2p_config = P2PConfig {
        relays: vec![],
        external_ip: args.external_ip,
        external_host: args.external_host,
        tcp_addrs: args.tcp_addrs,
        udp_addrs: args.udp_addrs,
        disable_reuse_port: args.disable_reuse_port,
    };

    info!(known_peers = ?known_peers, "Known peers");

    let mut node: Node<ExampleBehaviour> = Node::new(
        p2p_config,
        pk,
        NodeType::QUIC,
        false,
        known_peers.clone(),
        |builder, keypair, relay_client| {
            let p2p_context = builder.p2p_context();
            builder.with_gater(conn_gater).with_inner(ExampleBehaviour {
                relay: relay_client,
                relay_reservation: MutableRelayReservation::new(relays.clone()),
                relay_router: RelayRouter::new(relays, p2p_context, keypair.public().to_peer_id()),
            })
        },
    )?;

    loop {
        tokio::select! {
            event = node.select_next_some() => {
                println!("Event: {:?}", event);
            }
            _ = signal::ctrl_c() => {
                println!("Ctrl+C received, shutting down...");
                break;
            }
        }
    }

    Ok(())
}
