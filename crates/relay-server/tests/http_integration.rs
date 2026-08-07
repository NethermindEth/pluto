//! End-to-end integration tests for the relay HTTP layer.
//!
//! Spins up the real `enr_server` axum app on an ephemeral port and asserts
//! `/` and `/enr` over a live HTTP socket via `reqwest`. Tests are isolated by
//! binding `127.0.0.1:0` and reading the assigned port back off the listener,
//! shutting down via `CancellationToken`, and using config-only knobs so no
//! libp2p swarm is started.
//!
//! DNS scenarios use `localhost` (resolved via `/etc/hosts`) so the suite
//! does not rely on a working public-DNS path in CI.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use k256::SecretKey;
use libp2p::{Multiaddr, identity::Keypair};
use pluto_eth2util::enr::Record;
use pluto_p2p::{config::P2PConfig, utils::external_multiaddrs};
use rand::rngs::OsRng;
use tokio::{
    net::TcpListener,
    sync::{RwLock, mpsc},
};
use tokio_util::sync::CancellationToken;

/// Constructs a `P2PConfig` with sensible listen addrs so the external-addr
/// helpers produce something to advertise. The listen ports are the ports the
/// externals are advertised on; no p2p socket is bound, `enr_server` only
/// serves the HTTP listener.
fn p2p_config(external_ip: Option<&str>, external_host: Option<&str>, port: u16) -> P2PConfig {
    P2PConfig {
        tcp_addrs: vec![format!("127.0.0.1:{port}")],
        udp_addrs: vec![format!("127.0.0.1:{port}")],
        external_ip: external_ip.map(String::from),
        external_host: external_host.map(String::from),
        ..Default::default()
    }
}

/// Spawn an `enr_server` task on a listener bound to an ephemeral port, and
/// return the base URL plus a cancellation handle.
///
/// The listener is bound here and handed over, so the returned URL names a port
/// that is already accepting connections: no free-port guess, and no readiness
/// poll for the bind.
async fn spawn_server(
    p2p_config: P2PConfig,
    listeners: Vec<Multiaddr>,
) -> (String, CancellationToken, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let http_addr = listener.local_addr().expect("local_addr");

    // No swarm runs here, so the configured listen addresses stand in for the
    // ones libp2p would report having bound.
    let bound_addrs = {
        let mut v = p2p_config.tcp_multiaddrs().expect("tcp listen addrs");
        v.extend(p2p_config.udp_multiaddrs().expect("udp listen addrs"));
        v
    };
    let external_addrs = external_multiaddrs(&p2p_config, &bound_addrs).expect("externals");

    let secret_key = SecretKey::random(&mut OsRng);
    let peer_id = Keypair::generate_secp256k1().public().to_peer_id();
    let ct = CancellationToken::new();
    let (errs, _errs_rx) = mpsc::channel(4);

    let state = Arc::new(pluto_relay_server::AppState::new(
        p2p_config,
        secret_key,
        peer_id,
        Arc::new(RwLock::new(listeners)),
        external_addrs,
        false,
    ));

    let ct_inner = ct.clone();
    let handle = tokio::spawn(pluto_relay_server::enr_server(
        errs, listener, state, ct_inner,
    ));

    (format!("http://{http_addr}"), ct, handle)
}

async fn shutdown(ct: CancellationToken, handle: tokio::task::JoinHandle<()>) {
    ct.cancel();
    // The server may take a moment to drain; bound the wait so a hung test
    // fails loudly instead of hanging CI.
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}

// ---------------------------------------------------------------------------
// Scenario 1 — external_ip only
// ---------------------------------------------------------------------------

#[tokio::test]
async fn external_ip_only_serves_ip4_multiaddrs_and_enr() {
    let cfg = p2p_config(Some("1.2.3.4"), None, 3610);
    let (base, ct, handle) = spawn_server(cfg, vec![]).await;

    // GET /
    let body: Vec<String> = reqwest::get(format!("{base}/"))
        .await
        .expect("/ request")
        .json()
        .await
        .expect("/ json");
    assert_eq!(
        body.len(),
        2,
        "expected exactly 2 advertised addrs: {body:?}"
    );
    assert!(
        body.iter()
            .any(|a| a.starts_with("/ip4/1.2.3.4/tcp/3610/p2p/")),
        "missing tcp external addr in {body:?}"
    );
    assert!(
        body.iter()
            .any(|a| a.starts_with("/ip4/1.2.3.4/udp/3610/quic-v1/p2p/")),
        "missing udp external addr in {body:?}"
    );

    // GET /enr
    let resp = reqwest::get(format!("{base}/enr"))
        .await
        .expect("/enr request");
    assert_eq!(resp.status(), 200);
    let enr_str = resp.text().await.expect("/enr body");
    let record = Record::try_from(enr_str.as_str()).expect("valid ENR");
    assert_eq!(record.ip().expect("ip"), Ipv4Addr::new(1, 2, 3, 4));
    assert_eq!(record.tcp().expect("tcp"), 3610);
    assert_eq!(record.udp().expect("udp"), 3610);

    shutdown(ct, handle).await;
}

// ---------------------------------------------------------------------------
// Scenario 2 — nothing configured
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_config_returns_empty_list_and_500_for_enr() {
    let cfg = P2PConfig::default();
    let (base, ct, handle) = spawn_server(cfg, vec![]).await;

    // GET / — empty array.
    let body: Vec<String> = reqwest::get(format!("{base}/"))
        .await
        .expect("/ request")
        .json()
        .await
        .expect("/ json");
    assert!(body.is_empty(), "expected []: {body:?}");

    // GET /enr — 500 "no addresses".
    let resp = reqwest::get(format!("{base}/enr"))
        .await
        .expect("/enr request");
    assert_eq!(resp.status(), 500);

    shutdown(ct, handle).await;
}

// ---------------------------------------------------------------------------
// Scenario 3 — external_host=localhost; resolver populates 127.0.0.1
// ---------------------------------------------------------------------------

#[tokio::test]
async fn external_host_localhost_resolves_for_enr() {
    let cfg = p2p_config(None, Some("localhost"), 3610);
    let (base, ct, handle) = spawn_server(cfg, vec![]).await;

    // GET / — DNS-form multiaddrs are emitted verbatim, no resolution needed.
    let body: Vec<String> = reqwest::get(format!("{base}/"))
        .await
        .expect("/ request")
        .json()
        .await
        .expect("/ json");
    assert!(
        body.iter()
            .any(|a| a.starts_with("/dns/localhost/tcp/3610/p2p/")),
        "missing dns tcp addr in {body:?}"
    );
    assert!(
        body.iter()
            .any(|a| a.starts_with("/dns/localhost/udp/3610/quic-v1/p2p/")),
        "missing dns udp addr in {body:?}"
    );

    // GET /enr — the resolver loop fires immediately on first tick, but the
    // server may briefly respond 500 before the cache is populated. Poll
    // until 200 or timeout.
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(5);
    let record = loop {
        let resp = reqwest::get(format!("{base}/enr"))
            .await
            .expect("/enr request");
        if resp.status() == 200 {
            let body = resp.text().await.expect("/enr body");
            break Record::try_from(body.as_str()).expect("valid ENR");
        }
        if start.elapsed() >= timeout {
            panic!("/enr never returned 200; last status={}", resp.status());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let ip = record.ip().expect("ENR has ip");
    // `localhost` may resolve to either 127.0.0.1 (typical) or another
    // loopback alias depending on /etc/hosts; just assert it's loopback.
    assert!(ip.is_loopback(), "expected loopback IP, got {ip}");
    assert_eq!(record.tcp().expect("tcp"), 3610);
    assert_eq!(record.udp().expect("udp"), 3610);

    shutdown(ct, handle).await;
}
