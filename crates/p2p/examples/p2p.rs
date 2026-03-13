//! P2P example
//!
//! This example creates a Pluto P2P node and connects to a relay.
//! Also, it discovers other Pluto nodes using mDNS (requires the `mdns`
//! feature).

use anyhow::Result;
use clap::Parser;
use k256::elliptic_curve::rand_core::OsRng;
use libp2p::{
    Multiaddr,
    futures::StreamExt,
    identify, mdns,
    multiaddr::Protocol,
    relay,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use pluto_eth2util::enr::Record;
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    config::P2PConfig,
    p2p::{Node, NodeType},
};
use tokio::signal;

/// Combined behaviour with relay client and mDNS discovery.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "CombinedBehaviourEvent")]
pub struct CombinedBehaviour {
    /// Relay client for NAT traversal.
    pub relay: relay::client::Behaviour,
    /// mDNS for local peer discovery.
    pub mdns: mdns::tokio::Behaviour,
}

/// Events emitted by the combined behaviour.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum CombinedBehaviourEvent {
    Relay(relay::client::Event),
    Mdns(mdns::Event),
}

impl From<relay::client::Event> for CombinedBehaviourEvent {
    fn from(event: relay::client::Event) -> Self {
        CombinedBehaviourEvent::Relay(event)
    }
}

impl From<mdns::Event> for CombinedBehaviourEvent {
    fn from(event: mdns::Event) -> Self {
        CombinedBehaviourEvent::Mdns(event)
    }
}

/// Command line arguments
#[derive(Debug, Parser)]
pub struct Args {
    /// The port to listen on
    #[arg(short, long, default_value = "1050")]
    pub port: u16,
    /// The ENRs to listen on
    #[arg(short, long)]
    pub enrs: Vec<String>,
    /// The relay URL to dial
    #[arg(short, long)]
    pub relay_url: Option<Multiaddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let key = k256::SecretKey::random(&mut OsRng);

    // Create node with composed behaviour
    // No known cluster peers in this example
    let known_peers: Vec<libp2p::PeerId> = vec![];
    let mut p2p = Node::new(
        P2PConfig::default(),
        key.clone(),
        NodeType::QUIC,
        false,
        known_peers,
        |builder, keypair, relay_client| {
            builder
                .with_user_agent("pluto-p2p-example/1.0.0")
                .with_inner(CombinedBehaviour {
                    relay: relay_client,
                    mdns: mdns::tokio::Behaviour::new(
                        mdns::Config::default(),
                        keypair.public().to_peer_id(),
                    )
                    .expect("Failed to create mDNS behaviour"),
                })
        },
    )?;

    let args = Args::parse();

    let enr = Record::new(&key, vec![])?;

    if let Some(relay_url) = &args.relay_url {
        p2p.dial(relay_url.clone())?;
        println!("Dialed relay");
        let mut learned_observed_addr = false;
        let mut told_relay_observed_addr = false;

        loop {
            match p2p
                .next()
                .await
                .ok_or(anyhow::anyhow!("Swarm event is None"))?
            {
                SwarmEvent::NewListenAddr { .. } => {}
                SwarmEvent::Dialing { .. } => {}
                SwarmEvent::ConnectionEstablished { .. } => {}
                SwarmEvent::Behaviour(PlutoBehaviourEvent::Ping(_)) => {}
                SwarmEvent::Behaviour(PlutoBehaviourEvent::Identify(identify::Event::Sent {
                    ..
                })) => {
                    println!("Told relay its public address");
                    told_relay_observed_addr = true;
                }
                SwarmEvent::Behaviour(PlutoBehaviourEvent::Identify(
                    identify::Event::Received {
                        info: identify::Info { observed_addr, .. },
                        ..
                    },
                )) => {
                    println!("Relay told us our observed address: {}", observed_addr);
                    learned_observed_addr = true;
                }
                event => panic!("{event:?}"),
            }
            if learned_observed_addr && told_relay_observed_addr {
                break;
            }
        }
    }

    println!("ENR: {}", enr);

    p2p.listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", args.port).parse()?)?;
    p2p.listen_on(format!("/ip4/0.0.0.0/tcp/{}", args.port).parse()?)?;
    if let Some(relay_url) = args.relay_url {
        p2p.listen_on(relay_url.with(Protocol::P2pCircuit))?;
    }

    loop {
        tokio::select! {
            event = p2p.select_next_some() => match event {
                SwarmEvent::Behaviour(PlutoBehaviourEvent::Identify(identify::Event::Received { info: identify::Info { observed_addr, .. }, .. })) => {
                    p2p.add_external_address(observed_addr.clone());
                    println!("Address observed {}", observed_addr);
                }
                SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(CombinedBehaviourEvent::Relay(event))) => {
                    println!("Got relay event: {:?}", event);
                },
                SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(CombinedBehaviourEvent::Mdns(mdns::Event::Discovered(nodes)))) => {
                    for node in nodes {
                        println!("Discovered node: {:?}", node);
                        p2p.dial(node.1)?;
                    }
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                }
                SwarmEvent::Behaviour(PlutoBehaviourEvent::Ping(ping_event)) => {
                    println!("Got ping event: {:?}", ping_event);
                }
                SwarmEvent::IncomingConnection { connection_id, local_addr, send_back_addr } => {
                    println!("Incoming connection (id={connection_id}) from {:?} (send on {:?})", local_addr, send_back_addr);
                }
                SwarmEvent::IncomingConnectionError {peer_id,connection_id,error, local_addr, send_back_addr } => {
                    println!("Incoming connection (id={connection_id}) error from {:?} (send on {:?} to {:?}): {:?}", peer_id, local_addr, send_back_addr, error);
                }
                event => {
                    println!("{:?}", event);
                }
            },
            _ = signal::ctrl_c() => {
                println!("\nReceived Ctrl+C, shutting down gracefully...");
                drop(p2p);
                println!("Shutdown complete");
                break;
            }
        }
    }

    Ok(())
}
