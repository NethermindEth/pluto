#![allow(missing_docs)]

use std::net::Ipv4Addr;

use anyhow::Result;
use charon_eth2::enr::{Record, with_ip_impl, with_tcp_impl, with_udp_impl};
use charon_p2p::{
    config::P2PConfig,
    gater::ConnGater,
    peer::peer_id_from_key,
    p2p::{Node, NodeType, PlutoBehavior, PlutoBehaviorEvent},
};
use k256::elliptic_curve::rand_core::OsRng;
use libp2p::{Multiaddr, futures::StreamExt, identify, swarm::SwarmEvent};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    let key = k256::SecretKey::random(&mut OsRng);
    let mut p2p: Node<PlutoBehavior> = Node::new(
        P2PConfig::default(),
        key.clone(),
        ConnGater,
        false,
        NodeType::QUIC,
        PlutoBehavior::new,
    );

    let swarm = &mut p2p.swarm;

    // Get port from environment variable or default to 1050
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(1050);

    let enr = Record::new(
        key.clone(),
        vec![
            with_tcp_impl(port),
            with_udp_impl(port),
            with_ip_impl(Ipv4Addr::new(0, 0, 0, 0)),
        ],
    )
    .unwrap();

    println!("ENR: {}", enr);

    swarm.listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", port).parse()?)?;
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", port).parse()?)?;

    // Fetch peers from CLI arguments (ENR strings)
    // Usage: cargo run --example p2p -- <enr1> <enr2> ...
    for enr_str in std::env::args().skip(1) {
        match Record::try_from(enr_str.as_str()) {
            Ok(enr) => {
                println!("Adding peer: {:?}", enr);
                // Extract public key and convert to PeerId
                let Some(public_key) = enr.public_key else {
                    eprintln!("ENR missing public key");
                    continue;
                };

                let peer_id = match peer_id_from_key(public_key) {
                    Ok(peer_id) => peer_id,
                    Err(e) => {
                        eprintln!("Failed to convert ENR public key to PeerId: {}", e);
                        continue;
                    }
                };

                // Extract IP and ports from ENR
                let ip = enr.ip().unwrap_or(Ipv4Addr::new(0, 0, 0, 0));

                // Try to add TCP address if available
                let tcp_port = enr.tcp().unwrap_or(3610);
                let udp_port = enr.udp().unwrap_or(3610);

                if enr.tcp().is_none() && enr.udp().is_none() {
                    eprintln!("ENR missing both TCP and UDP ports");
                }

                swarm.add_peer_address(peer_id, format!("/ip4/{}/udp/{}", ip, udp_port).parse().unwrap());
                swarm.add_peer_address(peer_id, format!("/ip4/{}/tcp/{}", ip, tcp_port).parse().unwrap());
            }
            Err(e) => {
                eprintln!("Failed to parse ENR: {} (error: {})", enr_str, e);
            }
        }
    }

    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(PlutoBehaviorEvent::Relay(event)) => {
                    println!("Got relay event: {:?}", event);
                },
                SwarmEvent::Behaviour(PlutoBehaviorEvent::Identify(identify::Event::Received {
                    info: identify::Info { observed_addr, ..}, ..
                })) => {
                    println!("Address observed {}", observed_addr);
                }
                SwarmEvent::Behaviour(PlutoBehaviorEvent::Mdns(libp2p::mdns::Event::Discovered(nodes))) => {
                    for node in nodes {
                        println!("Discovered node: {:?}", node);
                        swarm.dial(node.1).unwrap();
                    }
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                }
                SwarmEvent::Behaviour(PlutoBehaviorEvent::Ping(ping_event)) => {
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
