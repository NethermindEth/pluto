//! Relay P2P node implementation.

use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use futures::{StreamExt, future::OptionFuture};
use k256::SecretKey;
use libp2p::{Multiaddr, PeerId, core::transport::ListenerId, relay, swarm::SwarmEvent};
use pluto_p2p::{behaviours::pluto::PlutoBehaviourEvent, name::peer_name};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};
use vise_exporter::MetricsServer;

use crate::{
    Result,
    config::{Config, create_relay_config},
    error::RelayP2PError,
    metrics::{PeerWithPeerClusterLabels, RELAY_METRICS},
    web::{AppState, bind_monitoring_server, enr_server, serve_monitoring_server},
};
use pluto_p2p::{
    BandwidthFactory, PeerConnectionMetrics,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    utils::external_multiaddrs,
};

/// Budget for an HTTP server to stop once shutdown has been signalled.
const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// A relay whose listeners are all bound, ready to be served by
/// [`RelayServer::run`].
///
/// Binding is separate from serving so that every startup failure — an
/// unusable address, a port already taken — is reported by
/// [`RelayServer::bind`] while nothing has been spawned yet, and so that the
/// addresses the relay actually got are known before it starts serving. The
/// bound listeners are owned by this struct, so a relay that fails to start
/// leaves nothing bound behind it.
pub struct RelayServer {
    /// The libp2p node, listening on the configured TCP and UDP addresses.
    node: Node<relay::Behaviour>,
    /// The addresses libp2p listens on, published to the HTTP handlers.
    listen_addrs: watch::Sender<Vec<Multiaddr>>,
    /// State shared with the HTTP handlers.
    state: Arc<AppState>,
    /// The bound ENR/multiaddr HTTP listener and the address it got, if
    /// `http_addr` is configured.
    http: Option<(TcpListener, SocketAddr)>,
    /// The bound Prometheus monitoring server, if `monitoring_addr` is
    /// configured.
    monitoring: Option<MetricsServer<'static>>,
    /// Stops the relay when cancelled.
    ct: CancellationToken,
}

impl RelayServer {
    /// Binds every listener the relay is configured with.
    #[instrument(skip_all)]
    pub async fn bind(config: &Config, key: SecretKey, ct: CancellationToken) -> Result<Self> {
        let relay_config = create_relay_config(config);
        let bandwidth: BandwidthFactory = Arc::new(|peer_id| PeerConnectionMetrics {
            sent: RELAY_METRICS.network_sent_bytes_total[&relay_labels(peer_id)].clone(),
            received: RELAY_METRICS.network_receive_bytes_total[&relay_labels(peer_id)].clone(),
        });
        let mut node = Node::new_server(
            config.p2p_config.clone(),
            key.clone(),
            NodeType::TCP,
            config.filter_private_addrs,
            // Relay servers don't track cluster peers - they serve all connections.
            P2PContext::default(),
            Some(bandwidth),
            |builder, keypair| {
                builder.with_inner(relay::Behaviour::new(
                    keypair.public().to_peer_id(),
                    relay_config,
                ))
            },
        )?;

        let (git_hash, build_time) = pluto_core::version::git_commit();
        info!(
            version = %*pluto_core::version::VERSION,
            git_hash = %git_hash,
            build_time = %build_time,
            "Pluto relay starting"
        );

        for udp_addr in config.p2p_config.udp_multiaddrs()? {
            debug!("Listening on UDP address {}", udp_addr);
            node.listen_on(udp_addr)?;
        }

        let (listen_addrs, listen_addrs_rx) = watch::channel(Vec::new());
        wait_for_listen_addrs(&mut node, &listen_addrs).await?;

        // Advertise the ports libp2p bound rather than the configured ones,
        // which carry port 0 when the kernel assigns the port.
        let bound_addrs = listen_addrs.borrow().clone();
        node.set_advertised_addrs(
            &config.p2p_config,
            config.filter_private_addrs,
            &bound_addrs,
        )?;

        // External multiaddrs from external_ip / external_host config are
        // advertised on `/` and folded into ENR responses on `/enr` even when
        // libp2p only sees private listen addresses (e.g., K8s pods behind
        // NodePort).
        let external_addrs = external_multiaddrs(&config.p2p_config, &bound_addrs)?;

        let state = Arc::new(AppState::new(
            config.p2p_config.clone(),
            key,
            *node.local_peer_id(),
            listen_addrs_rx,
            external_addrs,
            config.filter_private_addrs,
        ));

        let http = match config.http_addr.as_ref() {
            Some(http_addr) => {
                let bind_error = |source| RelayP2PError::FailedToBindHttpListener {
                    addr: http_addr.clone(),
                    source,
                };

                let listener = TcpListener::bind(http_addr).await.map_err(bind_error)?;
                let addr = listener.local_addr().map_err(bind_error)?;

                info!("Runtime multiaddrs available via http at {addr}");

                Some((listener, addr))
            }
            None => {
                info!(
                    "Runtime multiaddrs not available via http, since http-address flag is not set"
                );
                None
            }
        };

        let monitoring = match config.monitoring_addr.as_ref() {
            Some(monitoring_addr) => {
                let bind_addr = monitoring_addr.parse::<SocketAddr>().map_err(|_| {
                    RelayP2PError::FailedToParseMonitoringAddr(monitoring_addr.clone())
                })?;

                Some(bind_monitoring_server(bind_addr, ct.child_token()).await?)
            }
            None => {
                info!(
                    "Prometheus monitoring not available, since monitoring-address flag is not set"
                );
                None
            }
        };

        Ok(Self {
            node,
            listen_addrs,
            state,
            http,
            monitoring,
            ct,
        })
    }

    /// Returns the address the ENR/multiaddr HTTP server is bound to.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http.as_ref().map(|(_, addr)| *addr)
    }

    /// Returns the address the Prometheus monitoring server is bound to.
    pub fn monitoring_addr(&self) -> Option<SocketAddr> {
        self.monitoring.as_ref().map(MetricsServer::local_addr)
    }

    /// Returns the addresses libp2p is listening on.
    pub fn p2p_addrs(&self) -> Vec<Multiaddr> {
        self.listen_addrs.borrow().clone()
    }

    /// Serves the bound listeners until the relay is cancelled or one of the
    /// HTTP servers fails.
    #[instrument(skip_all)]
    pub async fn run(self) -> Result<()> {
        let Self {
            mut node,
            listen_addrs,
            state,
            http,
            monitoring,
            ct,
        } = self;

        let mut enr_handle =
            http.map(|(listener, _)| tokio::spawn(enr_server(listener, state, ct.child_token())));
        let mut monitoring_handle =
            monitoring.map(|server| tokio::spawn(serve_monitoring_server(server)));

        // Set when one of the HTTP servers fails; returned once the shutdown
        // below has run, so a failed relay never leaves listeners bound behind
        // it.
        let mut server_error = None;
        let mut enr_exited = false;
        let mut monitoring_exited = false;

        loop {
            tokio::select! {
                biased;
                _ = ct.cancelled() => {
                    info!("Relay server shutdown signal received, shutting down gracefully");
                    break;
                },
                Some(joined) = OptionFuture::from(enr_handle.as_mut()) => {
                    enr_exited = true;
                    server_error = server_exit("ENR", joined);
                    break;
                },
                Some(joined) = OptionFuture::from(monitoring_handle.as_mut()) => {
                    monitoring_exited = true;
                    server_error = server_exit("monitoring", joined);
                    break;
                },
                event = node.select_next_some() => {
                    apply_addr_update(&listen_addrs, handle_swarm_event(&event));
                }
            }
        }

        ct.cancel();

        if !enr_exited {
            await_server_shutdown("ENR", enr_handle).await;
        }

        if !monitoring_exited {
            await_server_shutdown("monitoring", monitoring_handle).await;
        }

        match server_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

/// Runs a relay P2P node.
pub async fn run_relay_p2p_node(
    config: &Config,
    key: SecretKey,
    ct: CancellationToken,
) -> Result<()> {
    RelayServer::bind(config, key, ct).await?.run().await
}

/// Waits until every listener registered on `node` has reported the address it
/// bound, publishing them on `listen_addrs`.
///
/// libp2p binds inside `listen_on` but reports the bound address — the
/// kernel-assigned one for port 0 — as a swarm event, so this is what turns a
/// bound relay into one that can answer `/enr`.
async fn wait_for_listen_addrs(
    node: &mut Node<relay::Behaviour>,
    listen_addrs: &watch::Sender<Vec<Multiaddr>>,
) -> Result<()> {
    let mut pending: HashSet<ListenerId> = node.listener_ids().iter().copied().collect();

    while !pending.is_empty() {
        let event = node.select_next_some().await;

        match &event {
            SwarmEvent::NewListenAddr { listener_id, .. } => {
                pending.remove(listener_id);
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                reason,
                ..
            } => {
                pending.remove(listener_id);

                if let Err(err) = reason {
                    return Err(RelayP2PError::ListenerClosedDuringStartup {
                        reason: err.to_string(),
                    });
                }
            }
            _ => {}
        }

        apply_addr_update(listen_addrs, handle_swarm_event(&event));
    }

    Ok(())
}

/// Turns the exit of an HTTP server task into the error that should take the
/// relay down, if any.
fn server_exit(
    name: &str,
    joined: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Option<RelayP2PError> {
    match joined {
        Ok(Ok(())) => {
            info!("{name} server shutdown complete");
            None
        }
        Ok(Err(err)) => {
            warn!("{name} server error: {err}");
            Some(err)
        }
        Err(err) => {
            warn!("{name} server task failed: {err}");
            Some(RelayP2PError::ServerTaskFailed(err))
        }
    }
}

/// Waits for an HTTP server task to stop after shutdown was signalled.
async fn await_server_shutdown(name: &str, handle: Option<JoinHandle<Result<()>>>) {
    let Some(handle) = handle else {
        return;
    };

    match tokio::time::timeout(SERVER_SHUTDOWN_TIMEOUT, handle).await {
        Ok(joined) => {
            server_exit(name, joined);
        }
        Err(_) => warn!("{name} server shutdown timeout"),
    }
}

/// Applies an [`AddrUpdate`] to the published listen addresses.
fn apply_addr_update(listen_addrs: &watch::Sender<Vec<Multiaddr>>, update: AddrUpdate) {
    match update {
        AddrUpdate::Add(address) => listen_addrs.send_modify(|addrs| addrs.push(address)),
        AddrUpdate::Remove(address) => {
            listen_addrs.send_modify(|addrs| addrs.retain(|addr| *addr != address));
        }
        AddrUpdate::RemoveAll(addresses) => {
            listen_addrs.send_modify(|addrs| addrs.retain(|addr| !addresses.contains(addr)));
        }
        AddrUpdate::None => {}
    }
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
/// Returns an [`AddrUpdate`] describing any change to the listen address list
/// that the caller should apply.
fn handle_swarm_event(event: &SwarmEvent<PlutoBehaviourEvent<relay::Behaviour>>) -> AddrUpdate {
    match event {
        // Track listener address changes
        SwarmEvent::NewListenAddr { address, .. } => {
            debug!(%address, "listening on new address");
            AddrUpdate::Add(address.clone())
        }
        SwarmEvent::ListenerClosed { addresses, .. } => {
            for address in addresses {
                debug!(%address, "listener closed");
            }
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
            RELAY_METRICS.active_connections[&labels].inc_by(1);
            AddrUpdate::None
        }
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            debug!(peer = %peer_name(peer_id), cause = ?cause, "connection closed");
            let labels = relay_labels(peer_id);
            RELAY_METRICS.active_connections[&labels].dec_by(1);
            AddrUpdate::None
        }

        // Relay-specific events
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
            relay::Event::ReservationReqAccepted {
                src_peer_id,
                renewed,
            },
        )) => {
            info!(peer = %peer_name(src_peer_id), renewed, "relay reservation accepted");
            AddrUpdate::None
        }
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(relay::Event::ReservationReqDenied {
            src_peer_id,
            status,
        })) => {
            warn!(peer = %peer_name(src_peer_id), ?status, "relay reservation denied");
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
            status,
        })) => {
            // `NoReservation` is the common, benign case: a peer optimistically
            // dials a circuit to a destination that has not (yet) reserved on
            // this relay (e.g. during cluster startup/reconnect). Log it at
            // debug so real capacity issues (`ResourceLimitExceeded`) remain
            // visible at warn.
            if matches!(status, relay::StatusCode::NoReservation) {
                debug!(
                    src = %peer_name(src_peer_id),
                    dst = %peer_name(dst_peer_id),
                    ?status,
                    "relay circuit denied"
                );
            } else {
                warn!(
                    src = %peer_name(src_peer_id),
                    dst = %peer_name(dst_peer_id),
                    ?status,
                    "relay circuit denied"
                );
            }
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
        SwarmEvent::ListenerError { listener_id, error } => {
            warn!(?listener_id, ?error, "listener error");
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
