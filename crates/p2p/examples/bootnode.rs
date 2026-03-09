#![allow(missing_docs)]
//! Bootnode example

use std::{path::PathBuf, str::FromStr};

use anyhow::Result;
use clap::Parser;
use futures::StreamExt;
use libp2p::{
    PeerId, identify, ping,
    relay::{self},
    swarm::{NetworkBehaviour, SwarmEvent},
};
use pluto_cluster::lock::Lock;
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
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
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}

#[derive(Debug, Parser)]
pub struct Args {
    /// The relay URLs to use
    #[arg(long, value_delimiter = ',')]
    relays: Vec<String>,

    /// The data directory to use
    #[arg(long)]
    data_dir: PathBuf,

    #[arg(long, value_delimiter = ',')]
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
            let local_peer_id = keypair.public().to_peer_id();

            // Create identify config
            let identify_config =
                identify::Config::new("/charon/1.0.0".to_string(), keypair.public());

            builder.with_gater(conn_gater).with_inner(ExampleBehaviour {
                relay: relay_client,
                relay_reservation: MutableRelayReservation::new(relays.clone()),
                relay_router: RelayRouter::new(relays.clone(), p2p_context, local_peer_id),
                identify: identify::Behaviour::new(identify_config),
                ping: ping::Behaviour::new(ping::Config::new()),
            })
        },
    )?;

    // Track relay peer IDs for logging
    let relay_peer_ids: std::collections::HashSet<PeerId> = relays
        .iter()
        .filter_map(|r| r.peer().ok().flatten().map(|p| p.id))
        .collect();

    loop {
        tokio::select! {
            event = node.select_next_some() => {
                // Helper function to determine peer type
                let get_peer_type = |peer: &PeerId| -> &str {
                    if relay_peer_ids.contains(peer) {
                        "RELAY"
                    } else if known_peers.contains(peer) {
                        "PEER"
                    } else {
                        "UNKNOWN"
                    }
                };

                match event {
                    // Relay client events
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        ExampleBehaviourEvent::Relay(relay_event),
                    )) => {
                        match relay_event {
                            relay::client::Event::ReservationReqAccepted {
                                relay_peer_id,
                                renewal,
                                limit,
                            } => {
                                info!(
                                    relay_peer_id = %relay_peer_id,
                                    peer_type = get_peer_type(&relay_peer_id),
                                    renewal = renewal,
                                    limit = ?limit,
                                    "Relay reservation request ACCEPTED - can now be reached via this relay"
                                );
                            }
                            relay::client::Event::OutboundCircuitEstablished {
                                relay_peer_id,
                                limit,
                            } => {
                                info!(
                                    relay_peer_id = %relay_peer_id,
                                    peer_type = get_peer_type(&relay_peer_id),
                                    limit = ?limit,
                                    "Outbound relay circuit ESTABLISHED - connected to peer via relay"
                                );
                            }
                            relay::client::Event::InboundCircuitEstablished {
                                src_peer_id,
                                limit,
                            } => {
                                info!(
                                    src_peer_id = %src_peer_id,
                                    peer_type = get_peer_type(&src_peer_id),
                                    limit = ?limit,
                                    "Inbound relay circuit ESTABLISHED - peer connected to us via relay"
                                );
                            }
                        }
                    }

                    // Connection established events - track relay connections
                    SwarmEvent::ConnectionEstablished {
                        peer_id,
                        endpoint,
                        num_established,
                        ..
                    } => {
                        let peer_type = get_peer_type(&peer_id);
                        let addr = match &endpoint {
                            libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
                            libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => {
                                send_back_addr
                            }
                        };

                        let is_relay_circuit = addr.to_string().contains("/p2p-circuit");
                        let connection_type = if is_relay_circuit {
                            "RELAY_CIRCUIT"
                        } else if addr.to_string().contains("/quic") {
                            "QUIC"
                        } else {
                            "TCP"
                        };

                        info!(
                            peer_id = %peer_id,
                            peer_type = peer_type,
                            connection_type = connection_type,
                            address = %addr,
                            num_established = num_established,
                            "Connection ESTABLISHED"
                        );
                    }

                    // Connection closed events - track relay disconnections
                    SwarmEvent::ConnectionClosed {
                        peer_id,
                        endpoint,
                        num_established,
                        cause,
                        ..
                    } => {
                        let peer_type = get_peer_type(&peer_id);
                        let addr = match &endpoint {
                            libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
                            libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => {
                                send_back_addr
                            }
                        };

                        let is_relay_circuit = addr.to_string().contains("/p2p-circuit");
                        let connection_type = if is_relay_circuit {
                            "RELAY_CIRCUIT"
                        } else if addr.to_string().contains("/quic") {
                            "QUIC"
                        } else {
                            "TCP"
                        };

                        info!(
                            peer_id = %peer_id,
                            peer_type = peer_type,
                            connection_type = connection_type,
                            address = %addr,
                            num_established = num_established,
                            cause = ?cause,
                            "Connection CLOSED"
                        );
                    }

                    // Outgoing connection errors - important for debugging relay issues
                    SwarmEvent::OutgoingConnectionError {
                        peer_id,
                        error,
                        connection_id,
                    } => {
                        let peer_type = peer_id.as_ref().map(get_peer_type).unwrap_or("UNKNOWN");
                        tracing::error!(
                            peer_id = ?peer_id,
                            peer_type = peer_type,
                            connection_id = ?connection_id,
                            error = %error,
                            "Outgoing connection ERROR - check if relay is reachable"
                        );
                    }

                    // Incoming connection errors
                    SwarmEvent::IncomingConnectionError {
                        connection_id,
                        local_addr,
                        send_back_addr,
                        error,
                        ..
                    } => {
                        tracing::error!(
                            connection_id = ?connection_id,
                            local_addr = %local_addr,
                            send_back_addr = %send_back_addr,
                            error = %error,
                            "Incoming connection ERROR"
                        );
                    }

                    // Ping events with peer type
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Ping(ping::Event {
                        peer,
                        result,
                        ..
                    })) => {
                        let peer_type = get_peer_type(&peer);

                        match result {
                            Ok(rtt) => {
                                info!(
                                    peer_id = %peer,
                                    peer_type = peer_type,
                                    rtt = ?rtt,
                                    "Received ping"
                                );
                            }
                            Err(err) => {
                                tracing::warn!(
                                    peer_id = %peer,
                                    peer_type = peer_type,
                                    error = %err,
                                    "Ping FAILED"
                                );
                            }
                        }
                    }

                    // Identify events - shows peer addresses
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. },
                    )) => {
                        let peer_type = get_peer_type(&peer_id);
                        info!(
                            peer_id = %peer_id,
                            peer_type = peer_type,
                            agent_version = %info.agent_version,
                            protocol_version = %info.protocol_version,
                            num_addresses = info.listen_addrs.len(),
                            "Received IDENTIFY from peer"
                        );

                        for addr in &info.listen_addrs {
                            tracing::debug!(
                                peer_id = %peer_id,
                                address = %addr,
                                "Peer address"
                            );
                        }
                    }

                    // New listen address
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!(
                            address = %address,
                            "Now listening on address"
                        );
                    }

                    // Expired listen address
                    SwarmEvent::ExpiredListenAddr { address, .. } => {
                        tracing::warn!(
                            address = %address,
                            "Listen address EXPIRED"
                        );
                    }

                    _ => {}
                }
            }
            _ = signal::ctrl_c() => {
                println!("Ctrl+C received, shutting down...");
                break;
            }
        }
    }

    Ok(())
}
