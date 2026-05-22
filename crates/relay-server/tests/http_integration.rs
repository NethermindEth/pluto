//! End-to-end integration tests for the relay HTTP layer.
//!
//! Spins up the real `enr_server` axum app on an ephemeral port and asserts
//! `/` and `/enr` over a live HTTP socket via `reqwest`. Tests are isolated
//! by binding to `127.0.0.1:0`-equivalent (find free port, then bind),
//! shutting down via `CancellationToken`, and using config-only knobs so no
//! libp2p swarm is started.
//!
//! DNS scenarios use `localhost` (resolved via `/etc/hosts`) so the suite
//! does not rely on a working public-DNS path in CI.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use k256::SecretKey;
use libp2p::{Multiaddr, identity::Keypair};
use pluto_eth2util::enr::Record;
use pluto_p2p::{
    config::P2PConfig,
    utils::{external_tcp_multiaddrs, external_udp_multiaddrs},
};
use pluto_relay_server::config::Config;
use rand::rngs::OsRng;
use tokio::{
    net::TcpListener,
    sync::{RwLock, mpsc},
};
use tokio_util::sync::CancellationToken;

/// Ephemeral port helper: bind 127.0.0.1:0, capture the assigned port, then
/// drop the listener so `enr_server` can bind it. Small TOCTOU window, fine
/// for tests.
async fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let port = l.local_addr().expect("local_addr").port();
    drop(l);
    port
}

/// Constructs a `P2PConfig` with sensible listen addrs so the external-addr
/// helpers produce something to advertise. The listen ports are advisory:
/// `enr_server` only binds the HTTP listener, not p2p sockets.
fn p2p_config(external_ip: Option<&str>, external_host: Option<&str>, port: u16) -> P2PConfig {
    P2PConfig {
        tcp_addrs: vec![format!("127.0.0.1:{port}")],
        udp_addrs: vec![format!("127.0.0.1:{port}")],
        external_ip: external_ip.map(String::from),
        external_host: external_host.map(String::from),
        ..Default::default()
    }
}

/// Spawn an `enr_server` task bound to a free port and return the base URL
/// plus a cancellation handle.
async fn spawn_server(
    p2p_config: P2PConfig,
    listeners: Vec<Multiaddr>,
) -> (String, CancellationToken, tokio::task::JoinHandle<()>) {
    let http_port = pick_free_port().await;
    let http_addr = format!("127.0.0.1:{http_port}");

    let config = Config::builder()
        .http_addr(http_addr.clone())
        .p2p_config(p2p_config.clone())
        .max_res_per_peer(8)
        .max_conns(64)
        .build();

    let external_addrs = {
        let mut v = external_tcp_multiaddrs(&p2p_config).expect("tcp externals");
        v.extend(external_udp_multiaddrs(&p2p_config).expect("udp externals"));
        v
    };

    let secret_key = SecretKey::random(&mut OsRng);
    let peer_id = Keypair::generate_secp256k1().public().to_peer_id();
    let listeners = Arc::new(RwLock::new(listeners));
    let ct = CancellationToken::new();
    let (errs, _errs_rx) = mpsc::channel(4);

    let ct_inner = ct.clone();
    let handle = tokio::spawn(pluto_relay_server::enr_server(
        errs,
        config,
        secret_key,
        peer_id,
        listeners,
        external_addrs,
        ct_inner,
    ));

    // Wait until the server is actually accepting connections — the spawn is
    // racy with the bind, and `reqwest` would otherwise hit `ConnectionRefused`.
    let base_url = format!("http://{http_addr}");
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(5);
    loop {
        match reqwest::Client::new()
            .get(format!("{base_url}/"))
            .timeout(Duration::from_millis(200))
            .send()
            .await
        {
            Ok(_) => break,
            Err(_) if start.elapsed() < timeout => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => panic!("server never came up: {e}"),
        }
    }

    (base_url, ct, handle)
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
