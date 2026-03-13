//! Relay P2P node implementation.

use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k256::SecretKey;
use libp2p::{PeerId, relay, swarm::SwarmEvent};
use pluto_p2p::behaviours::pluto::PlutoBehaviourEvent;
use pluto_p2p::name::peer_name;
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};

use crate::{
    Result,
    config::{Config, create_relay_config},
    metrics::{RELAY_METRICS, PeerWithPeerClusterLabels},
    web::{enr_server, monitoring_server},
};
use pluto_p2p::p2p::{Node, NodeType};

/// Runs a relay P2P node.
#[instrument(skip(config, key, ct))]
pub async fn run_relay_p2p_node(
    config: &Config,
    key: SecretKey,
    ct: CancellationToken,
) -> Result<Node<relay::Behaviour>> {
    let relay_config = create_relay_config(config);
    // Relay servers don't track cluster peers - they serve all connections
    let known_peers: Vec<libp2p::PeerId> = vec![];
    let mut node = Node::new_server(
        config.p2p_config.clone(),
        key.clone(),
        NodeType::TCP,
        false,
        known_peers,
        |builder, keypair| {
            builder.with_inner(relay::Behaviour::new(
                keypair.public().to_peer_id(),
                relay_config,
            ))
        },
    )?;

    let (git_hash, build_time) = pluto_core::version::git_commit();
    info!(
        version = %pluto_core::version::VERSION,
        git_hash = %git_hash,
        build_time = %build_time,
        "Pluto relay starting"
    );

    for tcp_addr in config.p2p_config.tcp_multiaddrs()? {
        debug!("Listening on TCP address {}", tcp_addr);
        node.listen_on(tcp_addr)?;
    }

    for udp_addr in config.p2p_config.udp_multiaddrs()? {
        debug!("Listening on UDP address {}", udp_addr);
        node.listen_on(udp_addr)?;
    }

    let (server_errors, mut server_errors_receiver) = mpsc::channel(3);

    let listeners = Arc::new(RwLock::new(Vec::new()));

    let enr_server_handle = tokio::spawn(enr_server(
        server_errors.clone(),
        config.clone(),
        key.clone(),
        *node.local_peer_id(),
        listeners.clone(),
        ct.child_token(),
    ));

    if let Some(http_addr) = config.http_addr.clone() {
        info!("Runtime multiaddrs available via http at {http_addr}");
    } else {
        info!("Runtime multiaddrs not available via http, since http-address flag is not set");
    }

    // Start monitoring server if configured
    let monitoring_handle = if let Some(monitoring_addr) = config.monitoring_addr.clone() {
        Some(tokio::spawn(monitoring_server(
            monitoring_addr,
            ct.child_token(),
        )))
    } else {
        info!("Prometheus monitoring not available, since monitoring-address flag is not set");
        None
    };

    loop {
        tokio::select! {
            biased;
            _ = ct.cancelled() => {
                info!("Relay server shutdown signal received, shutting down gracefully");
                break;
            },
            error = server_errors_receiver.recv() => {
                if let Some(error) = error {
                    warn!("Server error: {}", error);
                    return Err(error);
                }
            },
            event = node.select_next_some() => {
                let address_update = handle_swarm_event(&event);

                // Update listener address list
                match address_update {
                    AddrUpdate::Add(address) => {
                        listeners.write().await.push(address);
                    }
                    AddrUpdate::Remove(address) => {
                        listeners.write().await.retain(|a| *a != address);
                    }
                    AddrUpdate::RemoveAll(addresses) => {
                        listeners
                            .write()
                            .await
                            .retain(|a| !addresses.contains(a));
                    }
                    AddrUpdate::None => {}
                }
            }
        }
    }

    ct.cancel();

    match tokio::time::timeout(Duration::from_secs(2), enr_server_handle).await {
        Ok(Ok(())) => {
            info!("ENR server shutdown complete");
        }
        Ok(Err(e)) => {
            warn!("ENR server shutdown error: {}", e);
        }
        Err(_) => {
            warn!("ENR server shutdown timeout");
        }
    }

    if let Some(handle) = monitoring_handle {
        match tokio::time::timeout(Duration::from_secs(2), handle).await {
            Ok(Ok(())) => {
                info!("Monitoring server shutdown complete");
            }
            Ok(Err(e)) => {
                warn!("Monitoring server shutdown error: {}", e);
            }
            Err(_) => {
                warn!("Monitoring server shutdown timeout");
            }
        }
    }

    Ok(node)
}

/// Result of a swarm event that may require updating the listener address list.
enum AddrUpdate {
    /// Add an address.
    Add(libp2p::Multiaddr),
    /// Remove a specific address.
    Remove(libp2p::Multiaddr),
    /// Remove all addresses in the list.
    RemoveAll(Vec<libp2p::Multiaddr>),
    /// No address update needed.
    None,
}

/// Handles a relay swarm event, updating metrics and logging.
///
/// Returns an [`AddrUpdate`] describing any change to the listener address
/// list that the caller should apply.
fn handle_swarm_event(event: &SwarmEvent<PlutoBehaviourEvent<relay::Behaviour>>) -> AddrUpdate {
    match event {
        // Track listener address changes
        SwarmEvent::NewListenAddr { address, .. } => {
            debug!(%address, "listening on new address");
            AddrUpdate::Add(address.clone())
        }
        SwarmEvent::ListenerClosed { addresses, .. } => {
            AddrUpdate::RemoveAll(addresses.clone())
        }
        SwarmEvent::ExpiredListenAddr { address, .. } => {
            debug!(%address, "listen address expired");
            AddrUpdate::Remove(address.clone())
        }

        // Track connections for metrics
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            debug!(peer = %peer_name(peer_id), "connection established");
            let labels = relay_labels(peer_id);
            RELAY_METRICS.connection_total[&labels].inc();
            RELAY_METRICS.active_connections[&labels].inc();
            AddrUpdate::None
        }
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            debug!(peer = %peer_name(peer_id), cause = ?cause, "connection closed");
            let labels = relay_labels(peer_id);
            RELAY_METRICS.active_connections[&labels].dec();
            AddrUpdate::None
        }

        // Relay-specific events
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(relay::Event::ReservationReqAccepted {
            src_peer_id,
            renewed,
        })) => {
            info!(peer = %peer_name(src_peer_id), renewed, "relay reservation accepted");
            AddrUpdate::None
        }
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
            relay::Event::ReservationReqDenied { src_peer_id },
        )) => {
            warn!(peer = %peer_name(src_peer_id), "relay reservation denied");
            AddrUpdate::None
        }
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(relay::Event::ReservationTimedOut {
            src_peer_id,
        })) => {
            debug!(peer = %peer_name(src_peer_id), "relay reservation timed out");
            AddrUpdate::None
        }
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(relay::Event::CircuitReqAccepted {
            src_peer_id,
            dst_peer_id,
        })) => {
            info!(
                src = %peer_name(src_peer_id),
                dst = %peer_name(dst_peer_id),
                "relay circuit accepted"
            );
            AddrUpdate::None
        }
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(relay::Event::CircuitReqDenied {
            src_peer_id,
            dst_peer_id,
        })) => {
            warn!(
                src = %peer_name(src_peer_id),
                dst = %peer_name(dst_peer_id),
                "relay circuit denied"
            );
            AddrUpdate::None
        }
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(relay::Event::CircuitClosed {
            src_peer_id,
            dst_peer_id,
            error,
        })) => {
            debug!(
                src = %peer_name(src_peer_id),
                dst = %peer_name(dst_peer_id),
                error = ?error,
                "relay circuit closed"
            );
            AddrUpdate::None
        }
        _ => AddrUpdate::None,
    }
}

/// Returns relay metric labels for a peer.
///
/// The `peer_cluster` label is left empty since the relay server does not
/// track cluster membership.
fn relay_labels(peer_id: &PeerId) -> PeerWithPeerClusterLabels {
    PeerWithPeerClusterLabels::new(peer_name(peer_id), "")
}
