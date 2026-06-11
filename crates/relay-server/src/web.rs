use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
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
use pluto_eth2util::enr::{EnrEntry, Record};
use tokio::{
    net::TcpListener,
    sync::{RwLock, mpsc},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};
use vise_exporter::MetricsExporter;

use crate::{
    config::{Config, EXTERNAL_HOST_RESOLVE_INTERVAL},
    error::RelayP2PError,
};
use pluto_p2p::{config::P2PConfig, name::peer_name};

/// Shared application state for HTTP handlers.
#[derive(Clone)]
pub struct AppState {
    /// The P2P configuration.
    p2p_config: P2PConfig,
    /// The secret key for signing ENR records.
    secret_key: SecretKey,
    /// The peer ID of this node.
    peer_id: PeerId,
    /// The libp2p-discovered listen addresses of this node.
    addrs: Arc<RwLock<Vec<Multiaddr>>>,
    /// External multiaddrs derived from `external_ip` / `external_host` config.
    /// Fixed at startup. Includes `/ip4/<external_ip>/...` and
    /// `/dns/<external_host>/...` variants for both TCP and UDP/QUIC.
    external_addrs: Vec<Multiaddr>,
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
        external_addrs: Vec<Multiaddr>,
    ) -> Self {
        Self {
            p2p_config,
            secret_key,
            peer_id,
            addrs,
            external_addrs,
            external_host_ip: Arc::new(RwLock::new(None)),
        }
    }

    /// Returns the union of configured external multiaddrs and the live
    /// libp2p listen addresses, externals first, deduped while preserving
    /// order. Mirrors Go charon's `filterAdvertisedAddrs(externalAddrs,
    /// internalAddrs, …)` — listeners are already filtered for private
    /// addresses at ingest time when `filter_private_addrs` is set.
    async fn advertised_addrs(&self) -> Vec<Multiaddr> {
        let listeners = self.addrs.read().await;
        let mut seen: HashSet<&Multiaddr> = HashSet::new();
        let mut union: Vec<Multiaddr> = Vec::new();
        for addr in self.external_addrs.iter().chain(listeners.iter()) {
            if seen.insert(addr) {
                union.push(addr.clone());
            }
        }
        union
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
#[instrument(skip(server_errors, config, secret_key, peer_id, addrs, external_addrs, ct))]
pub async fn enr_server(
    server_errors: mpsc::Sender<RelayP2PError>,
    config: Config,
    secret_key: SecretKey,
    peer_id: PeerId,
    addrs: Arc<RwLock<Vec<Multiaddr>>>,
    external_addrs: Vec<Multiaddr>,
    ct: CancellationToken,
) {
    let Some(http_addr) = config.http_addr.clone() else {
        warn!("HTTP address is not set, skipping ENR server");
        return;
    };

    info!("Starting ENR server");

    let state = AppState::new(
        config.p2p_config.clone(),
        secret_key,
        peer_id,
        addrs,
        external_addrs,
    );
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

/// Starts the Prometheus monitoring server on the given address.
#[instrument(skip(ct))]
pub async fn monitoring_server(bind_addr: SocketAddr, ct: CancellationToken) {
    info!("Starting monitoring server on {bind_addr}");

    MetricsExporter::default()
        .with_graceful_shutdown(ct.cancelled_owned())
        .start(bind_addr)
        .await
        .unwrap_or_else(|e| warn!("Monitoring server error: {e}"));
}

/// Error response for HTTP handlers.
#[derive(Debug)]
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

    let mut sorted_addrs = state.advertised_addrs().await;

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
        if tcp_addr.is_none() && utils::is_tcp_addr(addr) {
            if let Some((ip, port)) = utils::extract_ip_and_tcp_port(addr) {
                tcp_addr = Some((apply_ip_override(&state, ip).await, port));
            } else if let Some((_host, port)) = utils::extract_dns_and_tcp_port(addr)
                && let Some(resolved) = state.get_external_host_ip().await
            {
                tcp_addr = Some((resolved, port));
            }
        }

        if udp_addr.is_none() && utils::is_quic_addr(addr) {
            if let Some((ip, port)) = utils::extract_ip_and_udp_port(addr) {
                udp_addr = Some((apply_ip_override(&state, ip).await, port));
            } else if let Some((_host, port)) = utils::extract_dns_and_udp_port(addr)
                && let Some(resolved) = state.get_external_host_ip().await
            {
                udp_addr = Some((resolved, port));
            }
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
        (Some(_), None) => {
            return Err(HandlerError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "no udp address available".to_string(),
            });
        }
        (None, Some(_)) => {
            return Err(HandlerError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "no tcp address available".to_string(),
            });
        }
        (None, None) => {
            return Err(HandlerError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "no udp or tcp addresses provided".to_string(),
            });
        }
    };

    // Create ENR record
    let record = Record::new(
        &state.secret_key,
        vec![
            EnrEntry::Ipv4(ip),
            EnrEntry::Tcp(tcp_port),
            EnrEntry::Udp(udp_port),
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

    let addrs = state.advertised_addrs().await;

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
    // `tokio::net::lookup_host` requires a `host:port` input, but we only need
    // the IP — use a dummy port of 0 so a bare hostname resolves correctly.
    match tokio::net::lookup_host((external_host, 0)).await {
        Ok(addrs) => {
            let ipv4 = addrs
                .filter_map(|a| match a.ip() {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(_) => None,
                })
                .next();

            if let Some(ipv4) = ipv4 {
                debug!("Resolved external host {external_host} to {ipv4}");
                state.set_external_host_ip(Some(ipv4)).await;
            } else {
                warn!("External host {external_host} resolved with no IPv4 address");
            }
        }
        Err(e) => {
            warn!("Failed to resolve external host {}: {}", external_host, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use libp2p::identity::Keypair;
    use pluto_eth2util::enr::Record;
    use rand::rngs::OsRng;

    fn ma(s: &str) -> Multiaddr {
        s.parse().expect("valid multiaddr")
    }

    fn test_state(
        external_ip: Option<&str>,
        external_host: Option<&str>,
        external_addrs: Vec<Multiaddr>,
        listeners: Vec<Multiaddr>,
    ) -> (Arc<AppState>, PeerId) {
        let secret_key = SecretKey::random(&mut OsRng);
        let peer_id = Keypair::generate_secp256k1().public().to_peer_id();
        let p2p_config = P2PConfig {
            external_ip: external_ip.map(String::from),
            external_host: external_host.map(String::from),
            ..Default::default()
        };
        let state = AppState::new(
            p2p_config,
            secret_key,
            peer_id,
            Arc::new(RwLock::new(listeners)),
            external_addrs,
        );
        (Arc::new(state), peer_id)
    }

    // ------ AppState::advertised_addrs ------

    #[tokio::test]
    async fn advertised_addrs_externals_only() {
        let externals = vec![ma("/dns/example.com/tcp/3610")];
        let (state, _) = test_state(None, Some("example.com"), externals.clone(), vec![]);
        assert_eq!(state.advertised_addrs().await, externals);
    }

    #[tokio::test]
    async fn advertised_addrs_listeners_only() {
        let listeners = vec![ma("/ip4/127.0.0.1/tcp/3610")];
        let (state, _) = test_state(None, None, vec![], listeners.clone());
        assert_eq!(state.advertised_addrs().await, listeners);
    }

    #[tokio::test]
    async fn advertised_addrs_externals_first_then_listeners() {
        let externals = vec![ma("/ip4/1.2.3.4/tcp/3610"), ma("/dns/example.com/tcp/3610")];
        let listeners = vec![ma("/ip4/127.0.0.1/tcp/3610")];
        let (state, _) = test_state(
            Some("1.2.3.4"),
            Some("example.com"),
            externals.clone(),
            listeners.clone(),
        );
        let got = state.advertised_addrs().await;
        // Externals first, in order, then listeners.
        assert_eq!(got[0], externals[0]);
        assert_eq!(got[1], externals[1]);
        assert_eq!(got[2], listeners[0]);
        assert_eq!(got.len(), 3);
    }

    #[tokio::test]
    async fn advertised_addrs_dedupes_listener_matching_external() {
        let dup = ma("/ip4/1.2.3.4/tcp/3610");
        let externals = vec![dup.clone()];
        // A listener that's byte-equal to an existing external must not be
        // emitted twice.
        let listeners = vec![dup.clone(), ma("/ip4/10.0.0.1/tcp/3610")];
        let (state, _) = test_state(Some("1.2.3.4"), None, externals, listeners);

        let got = state.advertised_addrs().await;
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], dup);
        assert_eq!(got[1], ma("/ip4/10.0.0.1/tcp/3610"));
    }

    #[tokio::test]
    async fn advertised_addrs_dedupes_within_externals() {
        let dup = ma("/ip4/1.2.3.4/tcp/3610");
        let externals = vec![dup.clone(), dup.clone(), ma("/dns/example.com/tcp/3610")];
        let (state, _) = test_state(Some("1.2.3.4"), Some("example.com"), externals, vec![]);

        let got = state.advertised_addrs().await;
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], dup);
        assert_eq!(got[1], ma("/dns/example.com/tcp/3610"));
    }

    #[tokio::test]
    async fn advertised_addrs_empty_when_nothing_configured() {
        let (state, _) = test_state(None, None, vec![], vec![]);
        assert!(state.advertised_addrs().await.is_empty());
    }

    // ------ multiaddr_handler ------

    #[tokio::test]
    async fn multiaddr_handler_returns_externals_with_peer_id() {
        let externals = vec![
            ma("/dns/example.com/tcp/3610"),
            ma("/dns/example.com/udp/3610/quic-v1"),
        ];
        let (state, peer_id) = test_state(None, Some("example.com"), externals, vec![]);

        let Json(addrs) = multiaddr_handler(State(state)).await.expect("ok");
        let peer = peer_id.to_string();
        assert_eq!(
            addrs,
            vec![
                format!("/dns/example.com/tcp/3610/p2p/{peer}"),
                format!("/dns/example.com/udp/3610/quic-v1/p2p/{peer}"),
            ]
        );
    }

    #[tokio::test]
    async fn multiaddr_handler_empty_when_nothing_configured() {
        let (state, _) = test_state(None, None, vec![], vec![]);
        let Json(addrs) = multiaddr_handler(State(state)).await.expect("ok");
        assert!(addrs.is_empty());
    }

    #[tokio::test]
    async fn multiaddr_handler_union_external_ip_only() {
        let externals = vec![
            ma("/ip4/1.2.3.4/tcp/3610"),
            ma("/ip4/1.2.3.4/udp/3610/quic-v1"),
        ];
        let (state, peer_id) = test_state(Some("1.2.3.4"), None, externals, vec![]);

        let Json(addrs) = multiaddr_handler(State(state)).await.expect("ok");
        let peer = peer_id.to_string();
        assert!(
            addrs.contains(&format!("/ip4/1.2.3.4/tcp/3610/p2p/{peer}")),
            "got {addrs:?}"
        );
        assert!(
            addrs.contains(&format!("/ip4/1.2.3.4/udp/3610/quic-v1/p2p/{peer}")),
            "got {addrs:?}"
        );
    }

    // ------ enr_handler ------

    fn parse_enr(s: &str) -> Record {
        Record::try_from(s).expect("valid ENR string")
    }

    #[tokio::test]
    async fn enr_handler_500_when_nothing_configured() {
        let (state, _) = test_state(None, None, vec![], vec![]);
        let err = enr_handler(State(state)).await.expect_err("should be 500");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn enr_handler_uses_external_ip() {
        let externals = vec![
            ma("/ip4/1.2.3.4/tcp/3610"),
            ma("/ip4/1.2.3.4/udp/3610/quic-v1"),
        ];
        let (state, _) = test_state(Some("1.2.3.4"), None, externals, vec![]);

        let s = enr_handler(State(state)).await.expect("ok");
        let record = parse_enr(&s);
        assert_eq!(record.ip().unwrap(), Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(record.tcp().unwrap(), 3610);
        assert_eq!(record.udp().unwrap(), 3610);
    }

    #[tokio::test]
    async fn enr_handler_external_ip_overrides_listener_ip() {
        let externals = vec![ma("/ip4/1.2.3.4/tcp/3610")];
        // Listener has a different IP — `apply_ip_override` must rewrite it.
        let listeners = vec![ma("/ip4/127.0.0.1/udp/3610/quic-v1")];
        let (state, _) = test_state(Some("1.2.3.4"), None, externals, listeners);

        let s = enr_handler(State(state)).await.expect("ok");
        let record = parse_enr(&s);
        assert_eq!(record.ip().unwrap(), Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(record.tcp().unwrap(), 3610);
        assert_eq!(record.udp().unwrap(), 3610);
    }

    #[tokio::test]
    async fn enr_handler_dns_fallback_uses_resolved_external_host() {
        let externals = vec![
            ma("/dns/example.com/tcp/3610"),
            ma("/dns/example.com/udp/3610/quic-v1"),
        ];
        let (state, _) = test_state(None, Some("example.com"), externals, vec![]);

        // Simulate the resolver loop populating the cache with a resolved IP.
        state
            .set_external_host_ip(Some(Ipv4Addr::new(5, 6, 7, 8)))
            .await;

        let s = enr_handler(State(state)).await.expect("ok");
        let record = parse_enr(&s);
        assert_eq!(record.ip().unwrap(), Ipv4Addr::new(5, 6, 7, 8));
        assert_eq!(record.tcp().unwrap(), 3610);
        assert_eq!(record.udp().unwrap(), 3610);
    }

    #[tokio::test]
    async fn enr_handler_dns_only_without_resolved_ip_returns_500() {
        let externals = vec![
            ma("/dns/example.com/tcp/3610"),
            ma("/dns/example.com/udp/3610/quic-v1"),
        ];
        // No listeners, resolver hasn't populated external_host_ip yet — both
        // TCP and UDP scan attempts skip, so the handler bails out.
        let (state, _) = test_state(None, Some("example.com"), externals, vec![]);

        let err = enr_handler(State(state)).await.expect_err("should be 500");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn enr_handler_external_ip_wins_over_external_host() {
        // Both external_ip and external_host configured. The IP-form multiaddr
        // sorts first (public IP), and apply_ip_override returns external_ip
        // before any DNS fallback runs.
        let externals = vec![
            ma("/ip4/1.2.3.4/tcp/3610"),
            ma("/ip4/1.2.3.4/udp/3610/quic-v1"),
            ma("/dns/example.com/tcp/3610"),
            ma("/dns/example.com/udp/3610/quic-v1"),
        ];
        let (state, _) = test_state(Some("1.2.3.4"), Some("example.com"), externals, vec![]);
        state
            .set_external_host_ip(Some(Ipv4Addr::new(9, 9, 9, 9)))
            .await;

        let s = enr_handler(State(state)).await.expect("ok");
        let record = parse_enr(&s);
        // external_ip beats the resolver-cached external_host IP.
        assert_eq!(record.ip().unwrap(), Ipv4Addr::new(1, 2, 3, 4));
    }

    #[tokio::test]
    async fn enr_handler_public_listener_used_when_no_externals() {
        let listeners = vec![
            ma("/ip4/8.8.8.8/tcp/3610"),
            ma("/ip4/8.8.8.8/udp/3610/quic-v1"),
        ];
        let (state, _) = test_state(None, None, vec![], listeners);

        let s = enr_handler(State(state)).await.expect("ok");
        let record = parse_enr(&s);
        assert_eq!(record.ip().unwrap(), Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(record.tcp().unwrap(), 3610);
        assert_eq!(record.udp().unwrap(), 3610);
    }
}
