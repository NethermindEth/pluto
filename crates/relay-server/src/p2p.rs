#![allow(missing_docs)]

use std::{sync::Arc, time::Duration};

use k256::SecretKey;
use libp2p::{futures::StreamExt, swarm::SwarmEvent};
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};

use crate::{
    Result,
    behaviour::RelayServerBehaviour,
    config::{Config, create_relay_config},
    error::RelayP2PError,
    web::enr_server,
};
use pluto_p2p::{gater::ConnGater, p2p::Node};

/// Runs a relay P2P node.
#[instrument(skip(config, key, ct))]
pub async fn run_relay_p2p_node(
    config: &Config,
    key: SecretKey,
    ct: CancellationToken,
) -> Result<Node<RelayServerBehaviour>> {
    let mut node = Node::new_relay_server(&config.p2p_config, key.clone(), |key| {
        RelayServerBehaviour::builder()
            .with_gater(ConnGater::new_open_gater())
            .with_relay_config(create_relay_config(config))
            .build(key)
    })?;

    // todo: change to version::log_info
    info!("Pluto relay starting");

    // todo: configure libp2p log level

    // todo: monitor connections

    for tcp_addr in config.p2p_config.tcp_multiaddrs()? {
        debug!("Listening on TCP address {}", tcp_addr);
        node.swarm
            .listen_on(tcp_addr)
            .map_err(RelayP2PError::FailedToListenOnAddress)?;
    }

    for udp_addr in config.p2p_config.udp_multiaddrs()? {
        debug!("Listening on UDP address {}", udp_addr);
        node.swarm
            .listen_on(udp_addr)
            .map_err(RelayP2PError::FailedToListenOnAddress)?;
    }

    let (server_errors, mut server_errors_receiver) = mpsc::channel(3);

    let listeners = Arc::new(RwLock::new(Vec::new()));

    let enr_server_handle = tokio::spawn(enr_server(
        server_errors.clone(),
        config.clone(),
        key.clone(),
        *node.swarm.local_peer_id(),
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
            event = node.swarm.select_next_some() => {
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
