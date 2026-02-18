#![allow(missing_docs)]

use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k256::SecretKey;
use libp2p::{relay, swarm::SwarmEvent};
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};

use crate::{
    Result,
    config::{Config, create_relay_config},
    web::enr_server,
};
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviour,
    p2p::{Node, NodeType},
};

/// Runs a relay P2P node.
#[instrument(skip(config, key, ct))]
pub async fn run_relay_p2p_node(
    config: &Config,
    key: SecretKey,
    ct: CancellationToken,
) -> Result<Node<relay::Behaviour>> {
    let relay_config = create_relay_config(config);
    let mut node = Node::new_server(
        config.p2p_config.clone(),
        key.clone(),
        NodeType::TCP,
        false,
        PlutoBehaviour::builder(),
        |keypair| relay::Behaviour::new(keypair.public().to_peer_id(), relay_config),
    )?;

    // todo: change to version::log_info
    info!("Charon relay starting");

    // todo: monitor connections

    for tcp_addr in config.p2p_config.tcp_addrs.iter() {
        debug!("Listening on TCP address {}", tcp_addr);
        node.listen_on(tcp_addr.parse()?)?;
    }
    for udp_addr in config.p2p_config.udp_addrs.iter() {
        debug!("Listening on UDP address {}", udp_addr);
        node.listen_on(udp_addr.parse()?)?;
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
        info!("Runtime multiaddrs available via http at {http_addr}",);
    } else {
        info!("Runtime multiaddrs not available via http, since http-address flag is not set");
    }

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
                // todo: handle swarm events
                debug!(?event, "Swarm event");

                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let mut listeners = listeners.write().await;
                        listeners.push(address);
                    }
                    SwarmEvent::ListenerClosed { addresses, .. } => {
                        let mut listeners = listeners.write().await;
                        listeners.retain(|addr| !addresses.contains(addr));
                    }
                    SwarmEvent::ExpiredListenAddr { address, .. } => {
                        let mut listeners = listeners.write().await;
                        listeners.retain(|addr| *addr != address);
                    }
                    _ => {}
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

    Ok(node)
}
