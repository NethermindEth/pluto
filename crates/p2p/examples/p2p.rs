//! P2P example
//!
//! This example creates a Pluto P2P node and connects to a relay.
//! Also, it discovers other Pluto nodes using mDNS (requires the `mdns`
//! feature).

use anyhow::Result;
use clap::Parser;
use k256::elliptic_curve::rand_core::OsRng;
use libp2p::{Multiaddr, futures::StreamExt, identify, multiaddr::Protocol, swarm::SwarmEvent};
use pluto_eth2util::enr::Record;
use pluto_p2p::{
    behaviours::{
        pluto::PlutoBehaviourEvent,
        pluto_mdns::{PlutoMdnsBehaviour, PlutoMdnsBehaviourEvent},
    },
    config::P2PConfig,
    p2p::{Node, NodeType},
};
use tokio::signal;

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
    let mut p2p: Node<_> = Node::new(
        P2PConfig::default(),
        key.clone(),
        false,
        NodeType::QUIC,
        PlutoMdnsBehaviour::new,
    )?;

    let args = Args::parse();

    let swarm = &mut p2p.swarm;

    let enr = Record::new(key.clone(), vec![])?;

    if let Some(relay_url) = &args.relay_url {
        swarm.dial(relay_url.clone())?;
        println!("Dialed relay");
        let mut learned_observed_addr = false;
        let mut told_relay_observed_addr = false;

        loop {
            match swarm
                .next()
                .await
                .ok_or(anyhow::anyhow!("Swarm event is None"))?
            {
                SwarmEvent::NewListenAddr { .. } => {}
                SwarmEvent::Dialing { .. } => {}
                SwarmEvent::ConnectionEstablished { .. } => {}
                SwarmEvent::Behaviour(PlutoMdnsBehaviourEvent::Pluto(
                    PlutoBehaviourEvent::Ping(_),
                )) => {}
                SwarmEvent::Behaviour(PlutoMdnsBehaviourEvent::Pluto(
                    PlutoBehaviourEvent::Identify(identify::Event::Sent { .. }),
                )) => {
                    println!("Told relay its public address");
                    told_relay_observed_addr = true;
                }
                SwarmEvent::Behaviour(PlutoMdnsBehaviourEvent::Pluto(
                    PlutoBehaviourEvent::Identify(identify::Event::Received {
                        info: identify::Info { observed_addr, .. },
                        ..
                    }),
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

    swarm.listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", args.port).parse()?)?;
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", args.port).parse()?)?;
    if let Some(relay_url) = args.relay_url {
        swarm.listen_on(relay_url.with(Protocol::P2pCircuit))?;
    }

    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(PlutoMdnsBehaviourEvent::Pluto(PlutoBehaviourEvent::Identify(identify::Event::Received { info: identify::Info { observed_addr, .. }, .. }))) => {
                    swarm.add_external_address(observed_addr.clone());
                    println!("Address observed {}", observed_addr);
                }
                SwarmEvent::Behaviour(PlutoMdnsBehaviourEvent::Pluto(PlutoBehaviourEvent::Relay(event))) => {
                    println!("Got relay event: {:?}", event);
                },
                SwarmEvent::Behaviour(PlutoMdnsBehaviourEvent::Mdns(libp2p::mdns::Event::Discovered(nodes))) => {
                    for node in nodes {
                        println!("Discovered node: {:?}", node);
                        swarm.dial(node.1)?;
                    }
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                }
                SwarmEvent::Behaviour(PlutoMdnsBehaviourEvent::Pluto(PlutoBehaviourEvent::Ping(ping_event))) => {
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

                // Perform cleanup
                let _ = swarm;
                drop(p2p);

                println!("Shutdown complete");
                break;
            }
        }
    }

    Ok(())
}
