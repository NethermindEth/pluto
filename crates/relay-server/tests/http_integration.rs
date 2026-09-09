//! End-to-end integration tests for the relay HTTP layer.
//!
//! Two kinds of test live here.
//!
//! The first spins up the real `enr_server` axum app on an ephemeral port and
//! asserts `/` and `/enr` over a live HTTP socket via `reqwest`, using
//! config-only knobs so no libp2p swarm is started. These cover the
//! external-address rendering paths cheaply.
//!
//! The second (see "full relay" below) starts a whole relay — swarm included —
//! from a `Config` carrying both a TCP and a UDP listen address, and asserts
//! that `/` and `/enr` report the ports libp2p actually bound. That is the path
//! `run_relay_p2p_node` takes, so it exercises the wiring the config-only tests
//! stand in for: both the TCP and the UDP listeners bound by
//! `Node::new_server` from the node's `NodeType`, and both folded into what
//! the HTTP handlers advertise.
//!
//! Tests are isolated by binding `127.0.0.1:0` everywhere and reading the
//! assigned ports back off the bound listeners, and shut down via
//! `CancellationToken`.
//!
//! DNS scenarios use `localhost` (resolved via `/etc/hosts`) so the suite
//! does not rely on a working public-DNS path in CI.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use k256::SecretKey;
use libp2p::{Multiaddr, identity::Keypair};
use pluto_eth2util::enr::Record;
use pluto_p2p::{
    config::P2PConfig,
    utils::{TransportProtocol, addr_port, external_multiaddrs, keypair_from_secret_key},
};
use pluto_relay_server::{config::Config, p2p::bind_relay};
use rand::rngs::OsRng;
use tokio::{net::TcpListener, sync::RwLock};
use tokio_util::sync::CancellationToken;

/// Loopback address with an ephemeral port, used for every listener these tests
/// bind: the kernel picks the port, so no test can lose a race for one.
const ANY_ADDR: &str = "127.0.0.1:0";

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
) -> (String, CancellationToken, ServerHandle) {
    let listener = TcpListener::bind(ANY_ADDR).await.expect("bind ephemeral");
    let http_addr = listener.local_addr().expect("local_addr");

    // No swarm runs here, so the configured listen addresses stand in for the
    // ones libp2p would report having bound.
    let bound_addrs = {
        let mut v = p2p_config
            .multiaddrs(TransportProtocol::Tcp)
            .expect("tcp listen addrs");
        v.extend(
            p2p_config
                .multiaddrs(TransportProtocol::Quic)
                .expect("udp listen addrs"),
        );
        v
    };
    let external_addrs = external_multiaddrs(&p2p_config, &bound_addrs).expect("externals");

    let secret_key = SecretKey::random(&mut OsRng);
    let peer_id = Keypair::generate_secp256k1().public().to_peer_id();
    let ct = CancellationToken::new();

    let state = Arc::new(pluto_relay_server::AppState::new(
        p2p_config,
        secret_key,
        peer_id,
        Arc::new(RwLock::new(listeners)),
        external_addrs,
        false,
    ));

    let ct_inner = ct.clone();
    let handle = tokio::spawn(pluto_relay_server::enr_server(listener, state, ct_inner));

    (format!("http://{http_addr}"), ct, handle)
}

/// Task the `enr_server` runs on, resolving with the server's exit status.
type ServerHandle = tokio::task::JoinHandle<Result<(), pluto_relay_server::RelayP2PError>>;

async fn shutdown(ct: CancellationToken, handle: ServerHandle) {
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

// ---------------------------------------------------------------------------
// Full relay — a real swarm listening on both a TCP and a UDP address
// ---------------------------------------------------------------------------

/// A relay serving for as long as this value is alive: swarm, ENR HTTP server
/// and all.
///
/// It is already serving when a test receives it — `bind_relay` returns only
/// once every listener is bound *and* libp2p has reported the address it got —
/// so a test body is requests and assertions, with no readiness poll and no
/// startup race to mistake for a failure.
struct FullRelay {
    /// Base URL of the ENR/multiaddr HTTP server, on the port the kernel
    /// assigned.
    base_url: String,
    /// Peer ID the relay advertises, derived from the key it was given.
    peer_id: libp2p::PeerId,
    /// TCP port libp2p bound, as it reported it.
    tcp_port: u16,
    /// UDP port libp2p bound, as it reported it.
    udp_port: u16,
    /// Cancels the relay.
    ct: CancellationToken,
    /// Relay task, resolving with the relay's exit status.
    handle: tokio::task::JoinHandle<Result<(), pluto_relay_server::RelayP2PError>>,
}

impl FullRelay {
    /// Starts a relay with one TCP and one UDP listen address, both on loopback
    /// with a kernel-assigned port, and its HTTP server likewise.
    ///
    /// Port 0 throughout means nothing here names a port another process could
    /// hold, and the ports that were actually bound are read back off the bound
    /// relay — which is also what makes them assertable.
    async fn start() -> Self {
        let p2p_config = P2PConfig::builder()
            .with_tcp_addrs(vec![ANY_ADDR.to_string()])
            .with_udp_addrs(vec![ANY_ADDR.to_string()])
            .build();

        let config = Config::builder()
            .p2p_config(p2p_config)
            .http_addr(ANY_ADDR.to_string())
            .max_conns(16)
            .max_res_per_peer(4)
            .build();

        let secret_key = SecretKey::random(&mut OsRng);
        // The relay derives its identity from this same key, so the peer ID its
        // handlers append is known here without asking the relay for it.
        let peer_id = keypair_from_secret_key(secret_key.clone())
            .expect("keypair from secret key")
            .public()
            .to_peer_id();

        let bound = bind_relay(&config, secret_key)
            .await
            .expect("relay binds on loopback ephemeral ports");

        // Read the addresses off the bound relay before `serve` consumes it.
        let http_addr = bound.http_addr().expect("http address is configured above");
        let p2p_addrs = bound.p2p_addrs().await;
        let tcp_port = p2p_addrs
            .iter()
            .find_map(|addr| addr_port(addr, TransportProtocol::Tcp))
            .expect("a tcp listener was configured");
        let udp_port = p2p_addrs
            .iter()
            .find_map(|addr| addr_port(addr, TransportProtocol::Quic))
            .expect("a udp listener was configured");
        // Port 0 is what was configured; libp2p must report what it bound.
        assert_ne!(tcp_port, 0, "tcp listener reported the configured port 0");
        assert_ne!(udp_port, 0, "udp listener reported the configured port 0");

        let ct = CancellationToken::new();
        let serve_ct = ct.child_token();
        let handle = tokio::spawn(async move { bound.serve(serve_ct).await });

        Self {
            base_url: format!("http://{http_addr}"),
            peer_id,
            tcp_port,
            udp_port,
            ct,
            handle,
        }
    }

    /// URL for `path` on the relay's HTTP server.
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Cancels the relay and waits for it to stop, asserting a clean exit.
    async fn stop(self) {
        self.ct.cancel();
        match tokio::time::timeout(Duration::from_secs(5), self.handle).await {
            Ok(Ok(exit)) => exit.expect("relay exited cleanly"),
            Ok(Err(err)) => panic!("relay task did not join: {err}"),
            Err(_) => panic!("relay did not shut down in time"),
        }
    }
}

#[tokio::test]
async fn full_relay_serves_bound_tcp_and_udp_multiaddrs() {
    let relay = FullRelay::start().await;

    let body: Vec<String> = reqwest::get(relay.url("/"))
        .await
        .expect("/ request")
        .json()
        .await
        .expect("/ json");

    assert!(!body.is_empty(), "expected at least one multiaddr");
    for addr in &body {
        addr.parse::<Multiaddr>()
            .unwrap_or_else(|err| panic!("advertised addr {addr} does not parse: {err}"));
    }

    // Both configured transports are advertised, on the ports libp2p bound and
    // with the relay's peer ID appended so the entries are dialable as they
    // stand.
    let peer = relay.peer_id;
    let tcp = format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer}", relay.tcp_port);
    let udp = format!("/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{peer}", relay.udp_port);
    assert!(body.contains(&tcp), "missing {tcp} in {body:?}");
    assert!(body.contains(&udp), "missing {udp} in {body:?}");

    relay.stop().await;
}

#[tokio::test]
async fn full_relay_serves_enr_with_bound_tcp_and_udp_ports() {
    let relay = FullRelay::start().await;

    let resp = reqwest::get(relay.url("/enr")).await.expect("/enr request");
    assert_eq!(resp.status(), 200);

    let record =
        Record::try_from(resp.text().await.expect("/enr body").as_str()).expect("valid ENR");
    assert_eq!(record.ip().expect("ip"), Ipv4Addr::LOCALHOST);
    assert_eq!(record.tcp().expect("tcp"), relay.tcp_port);
    assert_eq!(record.udp().expect("udp"), relay.udp_port);

    relay.stop().await;
}
