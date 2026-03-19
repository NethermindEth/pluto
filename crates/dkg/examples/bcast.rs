//! Runnable example for the DKG reliable-broadcast protocol.
//!
//! Run this example in 3 separate terminals. Each process starts one node from
//! a fixed demo cluster of 3 peers, waits until all peers are connected, and
//! then rebroadcasts the same signed `DemoTick` message every 10 seconds.
//!
//! Example:
//!
//! ```text
//! # Terminal 1
//! cargo run -p pluto-dkg --example bcast -- \
//!   --node 1 \
//!   --listen-port 25100 \
//!   --dial /ip4/127.0.0.1/tcp/25101 \
//!   --dial /ip4/127.0.0.1/tcp/25102
//!
//! # Terminal 2
//! cargo run -p pluto-dkg --example bcast -- \
//!   --node 2 \
//!   --listen-port 25101 \
//!   --dial /ip4/127.0.0.1/tcp/25100 \
//!   --dial /ip4/127.0.0.1/tcp/25102
//!
//! # Terminal 3
//! cargo run -p pluto-dkg --example bcast -- \
//!   --node 3 \
//!   --listen-port 25102 \
//!   --dial /ip4/127.0.0.1/tcp/25100 \
//!   --dial /ip4/127.0.0.1/tcp/25101
//! ```
//!
//! Expected flow:
//!
//! 1. Each node prints the same cluster peer order.
//! 2. Nodes keep dialing until all 3 peers are connected.
//! 3. Each node starts broadcasting its own fixed `DemoTick`.
//! 4. Other nodes first print `validated signature request ...`.
//! 5. Then they print `accepted broadcast ...`.
//!
//! The message ID defaults to `demo.tick`. The payload includes:
//!
//! - `node_id`: which demo node created the message
//! - `timestamp_seconds`: fixed once at startup of that node's broadcast task
//!
//! The timestamp is intentionally stable for each sender. `bcast` deduplicates
//! by `(sender_peer_id, msg_id)` and rejects a different payload for the same
//! logical message ID.
#![allow(missing_docs)]

use std::{collections::HashSet, time::Duration};

use anyhow::{Context as _, bail};
use clap::Parser;
use futures::StreamExt;
use k256::SecretKey;
use libp2p::{Multiaddr, PeerId, swarm::SwarmEvent};
use pluto_dkg::bcast::{Component, new};
use pluto_p2p::{
    config::P2PConfig,
    p2p::{Node, NodeType},
    peer::peer_id_from_key,
};
use pluto_testutil::random::ConstReader;
use prost::Name;
use tokio::signal;

const BROADCAST_INTERVAL: Duration = Duration::from_secs(10);
const REDIAL_INTERVAL: Duration = Duration::from_secs(3);

#[derive(Debug, Parser)]
#[command(name = "bcast-example")]
#[command(about = "Run one node from a 3-terminal DKG bcast demo cluster")]
struct Args {
    /// Demo node number. Valid values are 1, 2, or 3.
    #[arg(long)]
    node: u8,

    /// TCP port to listen on.
    #[arg(long, default_value_t = 25100)]
    listen_port: u16,

    /// Peer multiaddrs to dial. Can be repeated.
    #[arg(long)]
    dial: Vec<Multiaddr>,

    /// Registered logical message ID.
    #[arg(long, default_value = "demo.tick")]
    msg_id: String,
}

#[derive(Debug, Clone)]
struct DemoIdentity {
    node: u8,
    secret: SecretKey,
    peer_id: PeerId,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct DemoTick {
    #[prost(uint32, tag = "1")]
    node_id: u32,
    #[prost(int64, tag = "2")]
    timestamp_seconds: i64,
}

impl Name for DemoTick {
    const NAME: &'static str = "DemoTick";
    const PACKAGE: &'static str = "dkg.example";

    fn full_name() -> String {
        "dkg.example.DemoTick".to_string()
    }

    fn type_url() -> String {
        "type.googleapis.com/dkg.example.DemoTick".to_string()
    }
}

fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn demo_key(seed: u8) -> SecretKey {
    let mut rng = ConstReader(seed.wrapping_add(1));
    SecretKey::random(&mut rng)
}

fn build_identities() -> anyhow::Result<Vec<DemoIdentity>> {
    const DEMO_NODES: [u8; 3] = [1, 2, 3];

    DEMO_NODES
        .into_iter()
        .map(|node| {
            let secret = demo_key(node);
            let peer_id = peer_id_from_key(secret.public_key()).map_err(anyhow::Error::from)?;
            Ok::<DemoIdentity, anyhow::Error>(DemoIdentity {
                node,
                secret,
                peer_id,
            })
        })
        .collect()
}

async fn register_message(
    component: &Component,
    local_node: u8,
    msg_id: &str,
) -> pluto_dkg::bcast::Result<()> {
    let callback_id = msg_id.to_string();
    component
        .register_message::<DemoTick>(
        msg_id,
        Box::new(move |peer_id, msg| {
            println!(
                "node {local_node} received signature request from {peer_id}: {} node_id={} ts={}",
                callback_id, msg.node_id, msg.timestamp_seconds
            );
            Ok(())
        }),
        Box::new(move |peer_id, received_msg_id, msg| {
            println!(
                "node {local_node} received broadcast `{received_msg_id}` from {peer_id}: node_id={} ts={}",
                msg.node_id, msg.timestamp_seconds
            );
            Ok(())
        }),
    )
    .await
}

fn print_cluster_overview(identities: &[DemoIdentity], local_node: u8, listen_addr: &Multiaddr) {
    println!("cluster peer order:");
    for (index, identity) in identities.iter().enumerate() {
        let local_marker = if identity.node == local_node {
            " (local)"
        } else {
            ""
        };
        println!(
            "  [{index}] node={} peer_id={}{}",
            identity.node, identity.peer_id, local_marker
        );
    }
    println!("local listen addr: {listen_addr}");
}

fn handle_swarm_event<E: std::fmt::Debug>(
    event: SwarmEvent<E>,
    connected: &mut HashSet<PeerId>,
) -> bool {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            println!("listening on {address}");
            true
        }
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            println!(
                "connected to {peer_id} via {}",
                endpoint.get_remote_address()
            );
            connected.insert(peer_id);
            false
        }
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            println!("connection closed with {peer_id}: {cause:?}");
            connected.remove(&peer_id);
            false
        }
        SwarmEvent::Behaviour(_) => false,
        other => {
            println!("event: {other:?}");
            false
        }
    }
}

async fn wait_for_full_connectivity(
    node: &mut Node<pluto_dkg::bcast::Behaviour>,
    dial_targets: &[Multiaddr],
    expected_connections: usize,
) -> anyhow::Result<HashSet<PeerId>> {
    let mut connected = HashSet::<PeerId>::new();
    let mut listener_ready = false;
    let mut redial = tokio::time::interval(REDIAL_INTERVAL);
    redial.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let shutdown = signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        if connected.len() == expected_connections {
            println!("all peers connected");
            return Ok(connected);
        }

        tokio::select! {
            _ = &mut shutdown => {
                bail!("ctrl-c received before full connectivity");
            }
            _ = redial.tick(), if listener_ready && !dial_targets.is_empty() => {
                for addr in dial_targets {
                    println!("dialing {addr}");
                    if let Err(error) = node.dial(addr.clone()) {
                        println!("dial attempt failed for {addr}: {error}");
                    }
                }
            }
            event = node.select_next_some() => {
                listener_ready |= handle_swarm_event(event, &mut connected);
            }
        }
    }
}

async fn run_broadcast_loop(
    node: &mut Node<pluto_dkg::bcast::Behaviour>,
    component: &Component,
    local_node: u8,
    msg_id: &str,
    mut connected: HashSet<PeerId>,
) -> anyhow::Result<()> {
    println!(
        "starting periodic broadcast for `{msg_id}` every {}s",
        BROADCAST_INTERVAL.as_secs()
    );

    let msg = DemoTick {
        node_id: u32::from(local_node),
        timestamp_seconds: now_unix_seconds(),
    };
    let component = component.clone();
    let msg_id = msg_id.to_string();
    let broadcast_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(BROADCAST_INTERVAL);

        loop {
            interval.tick().await;
            println!(
                "node {local_node} broadcasting `{msg_id}`: node_id={} ts={}",
                msg.node_id, msg.timestamp_seconds
            );
            if let Err(error) = component.broadcast(&msg_id, &msg).await {
                eprintln!("broadcast failed: {error:#}");
            }
        }
    });
    let shutdown = signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                println!("ctrl-c received, shutting down");
                broadcast_task.abort();
                let _ = broadcast_task.await;
                return Ok(());
            }
            event = node.select_next_some() => {
                let _ = handle_swarm_event(event, &mut connected);
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if !(1..=3).contains(&args.node) {
        bail!("--node must be 1, 2, or 3");
    }

    let identities = build_identities()?;
    let local_identity = identities
        .iter()
        .find(|identity| identity.node == args.node)
        .cloned()
        .context("local node is not present in demo cluster")?;
    let peer_ids = identities
        .iter()
        .map(|identity| identity.peer_id)
        .collect::<Vec<_>>();

    let (behaviour, component) = new(
        local_identity.peer_id,
        peer_ids.clone(),
        local_identity.secret.clone(),
    );
    register_message(&component, args.node, &args.msg_id).await?;

    let mut node = Node::new_server(
        P2PConfig::default(),
        local_identity.secret,
        NodeType::TCP,
        false,
        peer_ids.clone(),
        |builder, _keypair| builder.with_inner(behaviour),
    )?;
    let listen_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", args.listen_port).parse()?;
    node.listen_on(listen_addr.clone())?;

    print_cluster_overview(&identities, args.node, &listen_addr);
    if args.dial.is_empty() {
        println!("no dial targets configured");
    } else {
        println!("dial targets:");
        for addr in &args.dial {
            println!("  {addr}");
        }
    }

    let expected_connections = peer_ids.len().saturating_sub(1);
    let dial_targets = args.dial.clone();
    let connected =
        wait_for_full_connectivity(&mut node, &dial_targets, expected_connections).await?;
    run_broadcast_loop(&mut node, &component, args.node, &args.msg_id, connected).await?;

    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}
