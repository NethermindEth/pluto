//! Relay P2P node implementation.

use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use futures::StreamExt;
use k256::SecretKey;
use libp2p::{Multiaddr, PeerId, core::transport::ListenerId, relay, swarm::SwarmEvent};
use pluto_p2p::{behaviours::pluto::PlutoBehaviourEvent, name::peer_name};
use tokio::{
    net::TcpListener,
    sync::{RwLock, mpsc},
    task::JoinHandle,
};
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

/// Runs a relay P2P node: binds every listener, then serves until `ct` is
/// cancelled or a server fails.
#[instrument(skip(config, key, ct))]
pub async fn run_relay_p2p_node(
    config: &Config,
    key: SecretKey,
    ct: CancellationToken,
) -> Result<Node<relay::Behaviour>> {
    bind_relay(config, key, ct).await?.serve().await
}

/// A relay whose listeners are all bound, but which is not serving yet.
///
/// Startup is split in two so that binding — the fallible, all-or-nothing part
/// — completes before anything is served. A caller therefore learns of an
/// unusable or already-taken address while there is still nothing to clean up,
/// and can read back the addresses that were actually bound.
///
/// "Before anything is served" includes p2p: [`bind_relay`] binds the HTTP
/// listeners before it creates the swarm, so no peer is ever accepted by a
/// relay that then fails to start.
///
/// Dropping a `BoundRelay` without calling [`BoundRelay::serve`] releases every
/// listener it holds, but does not cancel the [`CancellationToken`] passed to
/// [`bind_relay`] — that token belongs to the caller.
///
/// Production code should use [`run_relay_p2p_node`]; the halves are only
/// pulled apart by tests that need the ports the kernel assigned.
#[doc(hidden)]
pub struct BoundRelay {
    /// The relay swarm, listening on every configured address and having
    /// reported each of them.
    node: Node<relay::Behaviour>,
    /// Addresses libp2p is listening on, shared with the HTTP handlers.
    listen_addrs: Arc<RwLock<Vec<Multiaddr>>>,
    /// State the HTTP handlers answer from.
    state: Arc<AppState>,
    /// Bound ENR/multiaddr HTTP listener, unless no HTTP address is configured.
    enr_listener: Option<TcpListener>,
    /// Bound Prometheus monitoring server, unless monitoring is disabled.
    monitoring_server: Option<MetricsServer<'static>>,
    /// Cancels the relay and everything it spawns.
    ct: CancellationToken,
}

impl BoundRelay {
    /// Address the ENR/multiaddr HTTP server is bound to, or `None` when no
    /// HTTP address is configured.
    ///
    /// This is the address that was actually bound, which is the configured one
    /// only when it named a fixed port.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.enr_listener
            .as_ref()
            .and_then(|listener| listener.local_addr().ok())
    }

    /// Address the Prometheus monitoring server is bound to, or `None` when
    /// monitoring is disabled.
    pub fn monitoring_addr(&self) -> Option<SocketAddr> {
        self.monitoring_server
            .as_ref()
            .map(|server| server.local_addr())
    }

    /// Addresses libp2p is listening on, as it reported them — so the
    /// kernel-assigned ports when the configured ones were 0.
    pub async fn p2p_addrs(&self) -> Vec<Multiaddr> {
        self.listen_addrs.read().await.clone()
    }

    /// Serves every bound listener until the relay is cancelled or one of its
    /// servers fails.
    pub async fn serve(self) -> Result<Node<relay::Behaviour>> {
        let http_addr = self.http_addr();
        let Self {
            mut node,
            listen_addrs,
            state,
            enr_listener,
            monitoring_server,
            ct,
        } = self;

        let (server_errors, mut server_errors_receiver) = mpsc::channel(3);

        let enr_server_handle = enr_listener.map(|listener| {
            tokio::spawn(enr_server(
                server_errors.clone(),
                listener,
                state,
                ct.child_token(),
            ))
        });

        // The bound address, not the configured one: they differ whenever the
        // configured port was 0.
        if let Some(http_addr) = http_addr {
            info!("Runtime multiaddrs available via http at {http_addr}");
        } else {
            info!("Runtime multiaddrs not available via http, since http-address flag is not set");
        }

        // Serve the monitoring listener bound by `bind_relay`.
        let monitoring_handle = monitoring_server
            .map(|server| tokio::spawn(serve_monitoring_server(server_errors.clone(), server)));

        // A server failure is returned only once the shutdown below has run, so
        // a failed relay never leaves listeners bound behind it.
        let server_error = loop {
            tokio::select! {
                biased;
                _ = ct.cancelled() => {
                    info!("Relay server shutdown signal received, shutting down gracefully");
                    break None;
                },
                error = server_errors_receiver.recv() => {
                    if let Some(error) = error {
                        warn!("Server error: {}", error);
                        break Some(error);
                    }
                },
                event = node.select_next_some() => {
                    apply_addr_update(&listen_addrs, handle_swarm_event(&event)).await;
                }
            }
        };

        ct.cancel();

        if let Some(handle) = enr_server_handle {
            join_or_abort("ENR server", handle).await;
        }

        if let Some(handle) = monitoring_handle {
            join_or_abort("Monitoring server", handle).await;
        }

        match server_error {
            Some(error) => Err(error),
            None => Ok(node),
        }
    }
}

/// Binds every listener the relay is configured with, without serving any of
/// them.
///
/// Returns once the swarm, the ENR HTTP listener and the monitoring listener
/// are all bound, so any bind failure — an unusable address, or a port another
/// process holds — fails here rather than partway through a running relay.
///
/// Order matters: the HTTP listeners are bound before the swarm is created, and
/// the swarm is polled only once they are. Polling is what makes the relay
/// service p2p connections, so a bind that failed after it would take down
/// peers the relay had already accepted.
#[doc(hidden)]
#[instrument(skip(config, key, ct))]
pub async fn bind_relay(
    config: &Config,
    key: SecretKey,
    ct: CancellationToken,
) -> Result<BoundRelay> {
    let (git_hash, build_time) = pluto_core::version::git_commit();
    info!(
        version = %*pluto_core::version::VERSION,
        git_hash = %git_hash,
        build_time = %build_time,
        "Pluto relay starting"
    );

    // The HTTP listeners are bound before the swarm exists, and the swarm is not
    // polled until they are. Polling accepts and services p2p connections — it
    // completes handshakes, counts them, and can hand out circuit reservations —
    // so binding these afterwards would mean a bind failure tore down peers the
    // relay had already taken on.
    //
    // Binding here rather than inside each server's task is also what lets an
    // unusable address or a lost race for a port fail the relay while nothing
    // has been spawned.
    let monitoring_server = match config.monitoring_addr.clone() {
        Some(monitoring_addr) => {
            let bind_addr = monitoring_addr
                .parse::<SocketAddr>()
                .map_err(|_| RelayP2PError::FailedToParseMonitoringAddr(monitoring_addr))?;

            Some(bind_monitoring_server(bind_addr, ct.child_token()).await?)
        }
        None => {
            info!("Prometheus monitoring not available, since monitoring-address flag is not set");
            None
        }
    };

    let enr_listener = match config.http_addr.as_deref() {
        Some(http_addr) => {
            info!("Binding ENR server on {http_addr}");
            let listener = TcpListener::bind(http_addr).await.map_err(|source| {
                RelayP2PError::FailedToBindHttpListener {
                    addr: http_addr.to_owned(),
                    source,
                }
            })?;
            Some(listener)
        }
        None => {
            warn!("HTTP address is not set, skipping ENR server");
            None
        }
    };

    let relay_config = create_relay_config(config);
    let bandwidth: BandwidthFactory = std::sync::Arc::new(|peer_id| PeerConnectionMetrics {
        sent: RELAY_METRICS.network_sent_bytes_total[&relay_labels(peer_id)].clone(),
        received: RELAY_METRICS.network_receive_bytes_total[&relay_labels(peer_id)].clone(),
    });
    // Binds the configured TCP listeners; `listen_on` below binds the UDP ones.
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

    for udp_addr in config.p2p_config.udp_multiaddrs()? {
        debug!("Listening on UDP address {}", udp_addr);
        node.listen_on(udp_addr)?;
    }

    // First poll of the swarm, and so the first point at which this relay
    // services anything. Every other listener is already bound.
    let listen_addrs = Arc::new(RwLock::new(Vec::new()));
    wait_for_listen_addrs(&mut node, &listen_addrs).await?;
    let bound_addrs = listen_addrs.read().await.clone();

    // Advertise the ports libp2p bound rather than the configured ones, which
    // carry port 0 whenever the kernel picked the port.
    node.set_advertised_addrs(
        &config.p2p_config,
        config.filter_private_addrs,
        &bound_addrs,
    )?;

    // Compute external multiaddrs from external_ip / external_host config so
    // they're advertised on `/` and folded into ENR responses on `/enr` even
    // when libp2p only sees private listen addresses (e.g., K8s pods behind
    // NodePort).
    let external_addrs = external_multiaddrs(&config.p2p_config, &bound_addrs)?;

    let state = Arc::new(AppState::new(
        config.p2p_config.clone(),
        key,
        *node.local_peer_id(),
        listen_addrs.clone(),
        external_addrs,
        config.filter_private_addrs,
    ));

    Ok(BoundRelay {
        node,
        listen_addrs,
        state,
        enr_listener,
        monitoring_server,
        ct,
    })
}

/// Waits until every listener registered on `node` has reported the address it
/// bound, collecting them into `listen_addrs`.
///
/// libp2p binds inside `listen_on` but reports the bound address — the
/// kernel-assigned one when the configured port was 0 — only as a swarm event,
/// so this is what turns a bound relay into one that knows its own addresses
/// and can answer `/enr`.
///
/// This terminates for any listener that bound, whether its address is public
/// or private: private addresses are withheld when the ENR is rendered, not
/// when they are ingested, so a node that only ever listens on RFC 1918
/// addresses still finishes starting.
async fn wait_for_listen_addrs(
    node: &mut Node<relay::Behaviour>,
    listen_addrs: &Arc<RwLock<Vec<Multiaddr>>>,
) -> Result<()> {
    let mut pending: HashSet<ListenerId> = node.listener_ids().iter().copied().collect();

    while !pending.is_empty() {
        let event = node.select_next_some().await;

        match &event {
            SwarmEvent::NewListenAddr { listener_id, .. } => {
                pending.remove(listener_id);
            }
            // A listener that closes will never report an address. If it closed
            // because of an error the relay cannot start; a clean close just
            // means one fewer listener to wait for.
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

        apply_addr_update(listen_addrs, handle_swarm_event(&event)).await;
    }

    Ok(())
}

/// Applies an [`AddrUpdate`] to the listen addresses shared with the HTTP
/// handlers.
async fn apply_addr_update(listen_addrs: &Arc<RwLock<Vec<Multiaddr>>>, update: AddrUpdate) {
    match update {
        AddrUpdate::Add(address) => listen_addrs.write().await.push(address),
        AddrUpdate::Remove(address) => {
            listen_addrs.write().await.retain(|addr| *addr != address);
        }
        AddrUpdate::RemoveAll(addresses) => {
            listen_addrs
                .write()
                .await
                .retain(|addr| !addresses.contains(addr));
        }
        AddrUpdate::None => {}
    }
}

/// Grace period for a server task to finish shutting down before it is aborted.
const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// Waits for a server task to shut down, aborting it if it overruns
/// [`SERVER_SHUTDOWN_TIMEOUT`].
///
/// The abort is awaited: dropping a `JoinHandle` only *detaches* the task,
/// which would leave it holding its listener after the relay has reported that
/// it stopped.
async fn join_or_abort(name: &str, mut handle: JoinHandle<()>) {
    match tokio::time::timeout(SERVER_SHUTDOWN_TIMEOUT, &mut handle).await {
        Ok(Ok(())) => info!("{name} shutdown complete"),
        Ok(Err(err)) => warn!("{name} shutdown error: {err}"),
        Err(_) => {
            warn!("{name} shutdown timed out, aborting");
            handle.abort();
            let _ = handle.await;
        }
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
/// Returns an [`AddrUpdate`] describing any change to the listener address
/// list that the caller should apply.
///
/// Every listen address is tracked, private ones included; whether they are
/// advertised is decided when a response is rendered.
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
