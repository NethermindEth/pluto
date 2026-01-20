use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use crate::utils;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use k256::SecretKey;
use libp2p::{Multiaddr, PeerId, multiaddr};
use tokio::{
    net::TcpListener,
    sync::{RwLock, mpsc},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};

use crate::{
    config::{Config, EXTERNAL_HOST_RESOLVE_INTERVAL},
    error::RelayP2PError,
};
use charon_p2p::{config::P2PConfig, name::peer_name};

/// Shared application state for HTTP handlers.
#[derive(Clone)]
pub struct AppState {
    /// The P2P configuration.
    p2p_config: P2PConfig,
    /// The secret key for signing ENR records.
    secret_key: SecretKey,
    /// The peer ID of this node.
    peer_id: PeerId,
    /// The addresses of this node.
    addrs: Arc<RwLock<Vec<Multiaddr>>>,
    /// The resolved external host IP (if configured).
    external_host_ip: Arc<RwLock<Option<Ipv4Addr>>>,
}

impl AppState {
    /// Creates a new AppState.
    pub fn new(
        p2p_config: P2PConfig,
        secret_key: SecretKey,
        peer_id: PeerId,
        addrs: Arc<RwLock<Vec<Multiaddr>>>,
    ) -> Self {
        Self {
            p2p_config,
            secret_key,
            peer_id,
            addrs,
            external_host_ip: Arc::new(RwLock::new(None)),
        }
    }

    /// Gets the external host IP if set.
    async fn get_external_host_ip(&self) -> Option<Ipv4Addr> {
        *self.external_host_ip.read().await
    }

    /// Sets the external host IP.
    async fn set_external_host_ip(&self, ip: Option<Ipv4Addr>) {
        let mut ext_ip = self.external_host_ip.write().await;
        *ext_ip = ip;
    }
}

/// Starts the ENR HTTP server.
#[instrument(skip(server_errors, config, secret_key, peer_id, addrs, ct))]
pub async fn enr_server(
    server_errors: mpsc::Sender<RelayP2PError>,
    config: Config,
    secret_key: SecretKey,
    peer_id: PeerId,
    addrs: Arc<RwLock<Vec<Multiaddr>>>,
    ct: CancellationToken,
) {
    let Some(http_addr) = config.http_addr.clone() else {
        warn!("HTTP address is not set, skipping ENR server");
        return;
    };

    info!("Starting ENR server");

    let state = AppState::new(config.p2p_config.clone(), secret_key, peer_id, addrs);
    let state_arc = Arc::new(state);

    // Start external host resolver task if configured
    let resolver_handle = if let Some(external_host) = config.p2p_config.external_host {
        let state_clone = state_arc.clone();
        let ct_clone = ct.child_token();
        Some(tokio::spawn(async move {
            resolve_external_host_periodically(state_clone, external_host, ct_clone).await;
        }))
    } else {
        None
    };

    let router = Router::new()
        .route("/", get(multiaddr_handler))
        .route("/enr", get(enr_handler))
        .with_state(state_arc);

    let Ok(listener) = TcpListener::bind(&http_addr).await else {
        warn!("Failed to bind HTTP listener to {}", http_addr);
        let _ = server_errors
            .send(RelayP2PError::FailedToBindHttpListener(http_addr))
            .await;
        return;
    };

    info!(
        "Relay started {peer_name} on {tcp_addrs} and {udp_addrs}",
        peer_name = peer_name(&peer_id),
        tcp_addrs = config.p2p_config.tcp_addrs.join(", "),
        udp_addrs = config.p2p_config.udp_addrs.join(", "),
    );

    let ct_clone = ct.child_token();
    if let Err(e) = axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            ct_clone.cancelled().await;
            info!("ENR server shutdown complete");
        })
        .await
    {
        warn!("HTTP server error: {}", e);
        let _ = server_errors
            .send(RelayP2PError::FailedToServeHTTP(e))
            .await;
    }

    ct.cancel();

    if let Some(resolver_handle) = resolver_handle {
        let _ = resolver_handle.await;
    }
}

/// Error response for HTTP handlers.
pub struct HandlerError {
    status: StatusCode,
    message: String,
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

/// Handler that returns the node's ENR.
#[instrument(skip(state))]
pub async fn enr_handler(
    State(state): State<Arc<AppState>>,
) -> std::result::Result<String, HandlerError> {
    debug!("Getting ENR for node {}", state.peer_id);

    let addrs = state.addrs.read().await;

    // Sort addresses with public addresses first
    let mut sorted_addrs: Vec<Multiaddr> = addrs.clone();
    drop(addrs);

    if sorted_addrs.is_empty() {
        return Err(HandlerError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "no addresses".to_string(),
        });
    }

    sorted_addrs.sort_by(|a, b| {
        let a_public = utils::is_public_addr(a);
        let b_public = utils::is_public_addr(b);
        // Public addresses should come first
        b_public.cmp(&a_public)
    });

    // Find TCP and UDP addresses
    let mut tcp_addr: Option<(Ipv4Addr, u16)> = None;
    let mut udp_addr: Option<(Ipv4Addr, u16)> = None;

    for addr in &sorted_addrs {
        if tcp_addr.is_none()
            && utils::is_tcp_addr(addr)
            && let Some((ip, port)) = utils::extract_ip_and_tcp_port(addr)
        {
            tcp_addr = Some((apply_ip_override(&state, ip).await, port));
        }

        if udp_addr.is_none()
            && utils::is_quic_addr(addr)
            && let Some((ip, port)) = utils::extract_ip_and_udp_port(addr)
        {
            udp_addr = Some((apply_ip_override(&state, ip).await, port));
        }

        if tcp_addr.is_some() && udp_addr.is_some() {
            break;
        }
    }

    // Determine final IP, TCP port, and UDP port
    let (ip, tcp_port, udp_port) = match (tcp_addr, udp_addr) {
        (Some((tcp_ip, tcp_p)), Some((udp_ip, udp_p))) => {
            if tcp_ip != udp_ip {
                return Err(HandlerError {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    message: format!("conflicting IP addresses: tcp={}, udp={}", tcp_ip, udp_ip),
                });
            }
            (tcp_ip, tcp_p, udp_p)
        }
        (Some((ip, tcp_p)), None) => (ip, tcp_p, 9999), // Dummy UDP port
        (None, Some((ip, udp_p))) => (ip, 9999, udp_p), // Dummy TCP port
        (None, None) => {
            return Err(HandlerError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "no udp or tcp addresses provided".to_string(),
            });
        }
    };

    // Create ENR record
    let record = charon_eth2::enr::Record::new(
        state.secret_key.clone(),
        vec![
            charon_eth2::enr::with_ip_impl(ip),
            charon_eth2::enr::with_tcp_impl(tcp_port),
            charon_eth2::enr::with_udp_impl(udp_port),
        ],
    )
    .map_err(|e| HandlerError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: format!("failed to create ENR: {}", e),
    })?;

    Ok(record.to_string())
}

/// Applies IP override from config (external_ip or resolved external_host).
async fn apply_ip_override(state: &AppState, original_ip: Ipv4Addr) -> Ipv4Addr {
    // First check external_ip config
    if let Some(external_ip) = &state.p2p_config.external_ip
        && let Ok(ip) = external_ip.parse::<Ipv4Addr>()
    {
        return ip;
    }

    // Then check resolved external_host
    if let Some(ip) = state.get_external_host_ip().await {
        return ip;
    }

    original_ip
}

/// Handler that returns the node's multiaddrs as JSON.
#[instrument(skip(state))]
pub async fn multiaddr_handler(
    State(state): State<Arc<AppState>>,
) -> std::result::Result<Json<Vec<String>>, HandlerError> {
    debug!("Getting multiaddrs for node {}", state.peer_id);

    let addrs = state.addrs.read().await.clone();

    // Encapsulate peer ID into each address
    let full_addrs: Vec<String> = addrs
        .into_iter()
        .map(|addr| addr.with(multiaddr::Protocol::P2p(state.peer_id)))
        .map(|addr| addr.to_string())
        .collect();

    Ok(Json(full_addrs))
}

/// Periodically resolves the external host to an IP address.
#[instrument(skip(state, ct))]
async fn resolve_external_host_periodically(
    state: Arc<AppState>,
    external_host: String,
    ct: CancellationToken,
) {
    info!("Starting external host resolver");

    let mut interval = tokio::time::interval(EXTERNAL_HOST_RESOLVE_INTERVAL);

    loop {
        tokio::select! {
            biased;
            _ = ct.cancelled() => {
                info!("External host resolver shutdown complete");
                break;
            }
            _ = interval.tick() => {
                resolve_external_host(state.clone(), &external_host).await;
            }
        }
    }
}

/// Resolves the external host to an IP address.
async fn resolve_external_host(state: Arc<AppState>, external_host: &str) {
    match tokio::net::lookup_host(external_host).await {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next()
                && let IpAddr::V4(ipv4) = addr.ip()
            {
                debug!("Resolved external host {external_host} to {ipv4}");
                state.set_external_host_ip(Some(ipv4)).await;
            }
        }
        Err(e) => {
            warn!("Failed to resolve external host {}: {}", external_host, e);
        }
    }
}
