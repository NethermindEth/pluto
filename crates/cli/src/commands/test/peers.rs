//! Peer connectivity tests.

use std::{
    collections::HashMap,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

use clap::Args;
use futures::{StreamExt as _, future::join_all, stream::FuturesUnordered};
use libp2p::{
    Multiaddr, PeerId, identify,
    multiaddr::Protocol,
    ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use pluto_cluster::{definition::Definition, lock::Lock};
use pluto_eth2util::enr::Record;
use pluto_k1util::load as load_key;
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    bootnode::new_relays,
    config::{DEFAULT_RELAYS, P2PConfig},
    gater::ConnGater,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::{MutablePeer, Peer, peer_id_from_key, verify_p2p_key},
    relay::MutableRelayReservation,
    utils::is_relay_addr,
};
use reqwest::Method;
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{
    AllCategoriesResult, TestCaseName, TestCategory, TestCategoryResult, TestConfigArgs,
    TestResult, TestResultError, calculate_score, evaluate_highest_rtt, evaluate_rtt,
    must_output_to_file_on_quiet, publish_result_to_obol_api, write_result_to_file,
    write_result_to_writer,
};
use crate::{
    duration::Duration as CliDuration,
    error::{CliError, Result},
};

/// Combined inner behaviour: relay client + relay reservation.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "TestBehaviourEvent")]
struct TestBehaviour {
    relay: relay::client::Behaviour,
    reservation: MutableRelayReservation,
}

#[derive(Debug)]
enum TestBehaviourEvent {
    Relay(relay::client::Event),
}

impl From<relay::client::Event> for TestBehaviourEvent {
    fn from(e: relay::client::Event) -> Self {
        Self::Relay(e)
    }
}

impl From<std::convert::Infallible> for TestBehaviourEvent {
    fn from(i: std::convert::Infallible) -> Self {
        match i {}
    }
}

const THRESHOLD_MEASURE_AVG: Duration = Duration::from_millis(50);
const THRESHOLD_MEASURE_POOR: Duration = Duration::from_millis(240);
const THRESHOLD_LOAD_AVG: Duration = Duration::from_millis(50);
const THRESHOLD_LOAD_POOR: Duration = Duration::from_millis(240);
const THRESHOLD_RELAY_MEASURE_AVG: Duration = Duration::from_millis(50);
const THRESHOLD_RELAY_MEASURE_POOR: Duration = Duration::from_millis(240);
const SELF_TEST_NODE_BIND_DELAY: Duration = Duration::from_millis(500);

// rust-libp2p multistream-select V1: the listener waits for the dialer to send
// the header first, then echoes it back. Wire format: varint(len) + message,
// so "/multistream/1.0.0\n" (19 bytes) is sent as 0x13 + 19 bytes = 20 bytes.
const MULTISTREAM_HEADER: &[u8] = b"\x13/multistream/1.0.0\n";

/// Arguments for the peers test command.
#[derive(Args, Clone, Debug)]
pub struct TestPeersArgs {
    #[command(flatten)]
    pub test_config: TestConfigArgs,

    /// [REQUIRED] Comma-separated list of each peer ENR address.
    #[arg(long = "enrs", value_delimiter = ',')]
    pub enrs: Option<Vec<String>>,

    /// The path to the cluster lock file defining the distributed validator
    /// cluster.
    #[arg(long = "lock-file")]
    pub lock_file: Option<PathBuf>,

    /// The path to the cluster definition file or an HTTP URL.
    #[arg(long = "definition-file")]
    pub definition_file: Option<String>,

    /// The path to the charon enr private key file.
    #[arg(
        long = "private-key-file",
        default_value = ".charon/charon-enr-private-key"
    )]
    pub private_key_file: PathBuf,

    /// Time to keep TCP node alive after test completion, so connection is open
    /// for other peers to test on their end.
    #[arg(
        long = "keep-alive",
        default_value = "30m",
        value_parser = humantime::parse_duration
    )]
    pub keep_alive: Duration,

    /// Time to keep running the load tests in seconds. For each second a new
    /// continuous ping instance is spawned.
    #[arg(
        long = "load-test-duration",
        default_value = "30s",
        value_parser = humantime::parse_duration
    )]
    pub load_test_duration: Duration,

    /// Time to keep trying to establish direct connection to peer.
    #[arg(
        long = "direct-connection-timeout",
        default_value = "2m",
        value_parser = humantime::parse_duration
    )]
    pub direct_connection_timeout: Duration,

    /// Comma-separated list of listening TCP addresses (ip and port) for libP2P
    /// traffic. Empty default doesn't bind to local port therefore only
    /// supports outgoing connections.
    #[arg(long = "p2p-tcp-address", value_delimiter = ',')]
    pub p2p_tcp_addrs: Vec<String>,

    /// Comma-separated list of libp2p relay URLs or multiaddrs.
    #[arg(
        long = "p2p-relays",
        value_delimiter = ',',
        default_values = DEFAULT_RELAYS
    )]
    pub p2p_relays: Vec<String>,

    /// The IP address advertised by libp2p. This may be used to advertise an
    /// external IP.
    #[arg(long = "p2p-external-ip")]
    pub p2p_external_ip: Option<String>,

    /// The DNS hostname advertised by libp2p. This may be used to advertise an
    /// external DNS.
    #[arg(long = "p2p-external-hostname")]
    pub p2p_external_hostname: Option<String>,

    /// Comma-separated list of listening UDP addresses (ip and port) for libP2P
    /// traffic. Empty default doesn't bind to local port therefore only
    /// supports outgoing connections.
    #[arg(long = "p2p-udp-address", value_delimiter = ',')]
    pub p2p_udp_addrs: Vec<String>,

    /// Disables TCP port reuse for outgoing libp2p connections.
    #[arg(long = "p2p-disable-reuseport")]
    pub p2p_disable_reuseport: bool,
}

pub(super) fn supported_peer_test_cases() -> Vec<TestCaseName> {
    vec![
        TestCaseName::new("Ping", 1),
        TestCaseName::new("PingMeasure", 2),
        TestCaseName::new("PingLoad", 3),
        TestCaseName::new("DirectConn", 4),
    ]
}

pub(super) fn supported_self_test_cases() -> Vec<TestCaseName> {
    vec![TestCaseName::new("Libp2pTCPPortOpen", 1)]
}

pub(super) fn supported_relay_test_cases() -> Vec<TestCaseName> {
    vec![
        TestCaseName::new("PingRelay", 1),
        TestCaseName::new("PingMeasureRelay", 2),
    ]
}

/// Runs the peer connectivity tests.
pub async fn run(
    args: TestPeersArgs,
    writer: &mut dyn Write,
    ct: CancellationToken,
) -> Result<TestCategoryResult> {
    let enrs_empty = args.enrs.as_ref().is_none_or(Vec::is_empty);
    let lock_empty = args.lock_file.is_none();
    let def_empty = args.definition_file.is_none();

    if enrs_empty && lock_empty && def_empty {
        return Err(CliError::Other(
            "--enrs, --lock-file or --definition-file must be specified".to_string(),
        ));
    }

    let conflicts = [!enrs_empty, !lock_empty, !def_empty];
    if conflicts.iter().filter(|&&v| v).count() > 1 {
        return Err(CliError::Other(
            "only one of --enrs, --lock-file or --definition-file may be specified".to_string(),
        ));
    }

    must_output_to_file_on_quiet(args.test_config.quiet, &args.test_config.output_json)?;

    tracing::info!("Starting pluto peers and relays test");

    let timeout_ct = ct.child_token();
    let timeout_cancel = timeout_ct.clone();
    tokio::spawn(async move {
        tokio::time::sleep(args.test_config.timeout).await;
        timeout_cancel.cancel();
    });

    let start_time = tokio::time::Instant::now();

    let peer_tests = super::filter_tests(
        &supported_peer_test_cases(),
        args.test_config.test_cases.as_deref(),
    );
    let self_tests = super::filter_tests(
        &supported_self_test_cases(),
        args.test_config.test_cases.as_deref(),
    );
    let relay_tests = super::filter_tests(
        &supported_relay_test_cases(),
        args.test_config.test_cases.as_deref(),
    );

    if peer_tests.is_empty() && self_tests.is_empty() && relay_tests.is_empty() {
        return Err(CliError::TestCaseNotSupported);
    }

    let enr_strings = fetch_enrs(&args).await?;
    tracing::debug!("enr_strings: {:?}", enr_strings);
    let cluster_peers = parse_peers(&enr_strings)?;

    let private_key = load_key(&args.private_key_file)?;

    verify_p2p_key(&cluster_peers, &private_key)?;

    let self_peer_id = peer_id_from_key(private_key.public_key())?;

    if let Some(self_peer) = cluster_peers.iter().find(|p| p.id == self_peer_id) {
        tracing::info!(name = %self_peer.name, "Self p2p name resolved");
    }

    // Build ENR hash (sorted all-ENRs including self) for relay routing.
    let enr_hash = build_enr_hash(&private_key, &enr_strings)?;

    let p2p_cfg = P2PConfig {
        relays: vec![],
        external_ip: args.p2p_external_ip.clone(),
        external_host: args.p2p_external_hostname.clone(),
        tcp_addrs: args.p2p_tcp_addrs.clone(),
        udp_addrs: args.p2p_udp_addrs.clone(),
        disable_reuse_port: args.p2p_disable_reuseport,
    };

    let (node, relay_peers) = setup_p2p(
        timeout_ct.clone(),
        private_key,
        p2p_cfg,
        &args.p2p_relays,
        &cluster_peers,
        self_peer_id,
        &enr_hash,
    )
    .await?;

    let tcp_addrs = args.p2p_tcp_addrs.clone();
    let self_tests_clone = self_tests.clone();

    let only_self_tests = peer_tests.is_empty();
    let ((peer_results, mut node), self_results, relay_results) = tokio::join!(
        run_peer_event_loop(
            node,
            &cluster_peers,
            self_peer_id,
            &peer_tests,
            &relay_peers,
            &enr_strings,
            &args,
            timeout_ct.clone(),
        ),
        run_self_tests_in_new_task(
            timeout_ct.clone(),
            tcp_addrs,
            self_tests_clone,
            only_self_tests,
        ),
        run_relay_http_tests(&args.p2p_relays, &relay_tests, timeout_ct.clone()),
    );
    let self_results = self_results.expect("self-test task should not panic");
    let mut all_targets: HashMap<String, Vec<TestResult>> = HashMap::new();
    all_targets.extend(relay_results);
    all_targets.extend(self_results);
    all_targets.extend(peer_results);

    let score = all_targets
        .values()
        .map(|r| calculate_score(r))
        .max()
        .unwrap_or(super::CategoryScore::A);

    let elapsed = start_time.elapsed();
    let mut res = TestCategoryResult::new(TestCategory::Peers);
    res.targets = all_targets;
    res.execution_time = Some(CliDuration::new(elapsed));
    res.score = Some(score);

    write_and_publish_results(&res, writer, &args).await?;
    keep_node_alive(&mut node, args.keep_alive, ct).await;

    Ok(res)
}

fn run_self_tests_in_new_task(
    cancel: CancellationToken,
    tcp_addrs: Vec<String>,
    self_tests: Vec<TestCaseName>,
    only_self_tests: bool,
) -> JoinHandle<HashMap<String, Vec<TestResult>>> {
    // Self tests run concurrently with peer tests; give the node a moment to bind.
    tokio::spawn(async move {
        tokio::time::sleep(SELF_TEST_NODE_BIND_DELAY).await;
        let res = run_self_tests(&tcp_addrs, &self_tests).await;
        if only_self_tests {
            cancel.cancel();
        }
        res
    })
}

async fn fetch_enrs(args: &TestPeersArgs) -> Result<Vec<String>> {
    if let Some(enrs) = &args.enrs
        && !enrs.is_empty()
    {
        return Ok(enrs.clone());
    }
    if let Some(path) = &args.definition_file {
        return fetch_enrs_from_definition(path).await;
    }
    if let Some(path) = &args.lock_file {
        return fetch_enrs_from_lock(path).await;
    }
    Err(CliError::Other(
        "--enrs, --lock-file or --definition-file must be specified".to_string(),
    ))
}

async fn fetch_enrs_from_lock(path: impl AsRef<std::path::Path>) -> Result<Vec<String>> {
    let content = tokio::fs::read_to_string(path).await?;
    let lock: Lock = serde_json::from_str(&content)?;
    let enrs: Vec<String> = lock
        .definition
        .operators
        .iter()
        .map(|op| op.enr.clone())
        .filter(|e| !e.is_empty())
        .collect();
    if enrs.is_empty() {
        return Err(CliError::Other("no peers found in lock file".to_string()));
    }
    Ok(enrs)
}

async fn fetch_enrs_from_definition(path: &str) -> Result<Vec<String>> {
    let definition: Definition = if path.starts_with("http://") || path.starts_with("https://") {
        pluto_cluster::helpers::fetch_definition(path).await?
    } else {
        let content = tokio::fs::read_to_string(path).await?;
        serde_json::from_str(&content)?
    };

    let enrs: Vec<String> = definition
        .operators
        .iter()
        .map(|op| op.enr.clone())
        .filter(|e| !e.is_empty())
        .collect();

    if enrs.is_empty() {
        return Err(CliError::Other(
            "no peers found in definition file".to_string(),
        ));
    }
    Ok(enrs)
}

fn parse_peers(enr_strings: &[String]) -> Result<Vec<Peer>> {
    enr_strings
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let record = Record::try_from(s.as_str())?;
            Ok(Peer::from_enr(&record, i)?)
        })
        .collect()
}

// enr must be ASCII-only
fn format_enr(enr: &str) -> String {
    if enr.len() <= 17 {
        return enr.to_string();
    }
    let bytes = enr.as_bytes();
    format!(
        "{}...{}",
        std::str::from_utf8(&bytes[..13]).expect("ENR must be ASCII"),
        std::str::from_utf8(&bytes[enr.len().saturating_sub(4)..]).expect("ENR must be ASCII"),
    )
}

fn peer_target_name(peer: &Peer, enr_str: &str) -> String {
    format!("peer {} {}", peer.name, format_enr(enr_str))
}

async fn run_relay_http_tests(
    relay_urls: &[String],
    queued: &[TestCaseName],
    ct: CancellationToken,
) -> HashMap<String, Vec<TestResult>> {
    if queued.is_empty() {
        return HashMap::new();
    }

    let mut futs: FuturesUnordered<_> = relay_urls
        .iter()
        .map(|url| {
            let url = url.clone();
            let ct = ct.clone();
            let queued = queued.to_vec();
            tokio::spawn(async move {
                let key = format!("relay {url}");
                let mut target_results = Vec::new();
                for test in &queued {
                    if ct.is_cancelled() {
                        target_results
                            .push(TestResult::new(test.name).fail(CliError::TimeoutInterrupted));
                        continue;
                    }
                    let result = match test.name {
                        "PingRelay" => relay_ping_test(&url, &ct).await,
                        "PingMeasureRelay" => relay_ping_measure_test(&url, &ct).await,
                        _ => TestResult::new(test.name)
                            .fail(TestResultError::from_string("unsupported relay test")),
                    };
                    target_results.push(result);
                }
                (key, target_results)
            })
        })
        .collect();

    let mut results = HashMap::new();
    while let Some(res) = futs.next().await {
        let (key, target_results) = res.expect("relay test task should not panic");
        results.insert(key, target_results);
    }
    results
}

async fn relay_ping_test(url: &str, ct: &CancellationToken) -> TestResult {
    let result = TestResult::new("PingRelay");
    let client = reqwest::Client::new();
    tokio::select! {
        res = client.get(url).send() => match res {
            Ok(resp) if resp.status().is_success() => result.ok(),
            Ok(resp) => result.fail(TestResultError::from_string(format!("HTTP status {}", resp.status()))),
            Err(e) => result.fail(e),
        },
        _ = ct.cancelled() => result.fail(CliError::TimeoutInterrupted),
    }
}

async fn relay_ping_measure_test(url: &str, ct: &CancellationToken) -> TestResult {
    let result = TestResult::new("PingMeasureRelay");
    let rtt_fut = super::request_rtt(url, Method::GET, None, reqwest::StatusCode::OK);
    tokio::select! {
        res = rtt_fut => match res {
            Ok(rtt) => evaluate_rtt(rtt, result, THRESHOLD_RELAY_MEASURE_AVG, THRESHOLD_RELAY_MEASURE_POOR),
            Err(e) => result.fail(e),
        },
        _ = ct.cancelled() => result.fail(CliError::TimeoutInterrupted),
    }
}

async fn run_self_tests(
    tcp_addrs: &[String],
    queued: &[TestCaseName],
) -> HashMap<String, Vec<TestResult>> {
    if queued.is_empty() {
        return HashMap::new();
    }

    let mut results = Vec::new();
    for test in queued {
        let result = match test.name {
            "Libp2pTCPPortOpen" => libp2p_tcp_port_open_test(tcp_addrs).await,
            _ => TestResult::new(test.name)
                .fail(TestResultError::from_string("unsupported self test")),
        };
        results.push(result);
    }

    HashMap::from([("self".to_string(), results)])
}

async fn libp2p_tcp_port_open_test(addrs: &[String]) -> TestResult {
    let result = TestResult::new("Libp2pTCPPortOpen");

    if addrs.is_empty() {
        return result.fail(TestResultError::from_string(
            "no --p2p-tcp-address configured",
        ));
    }

    // Retry to tolerate slow libp2p stack startup: the TCP port may be bound
    // before the event loop is ready to complete the multistream handshake.
    let outcomes = join_all(addrs.iter().map(|addr| {
        let connect_addr = addr.replace("0.0.0.0", "127.0.0.1");
        async move {
            for attempt in 0..5 {
                tracing::debug!(attempt, addr = connect_addr, "libp2p TCP self-test attempt");
                match try_multistream_handshake(attempt, &connect_addr, MULTISTREAM_HEADER).await {
                    Ok(true) => return Ok(()),
                    Ok(false) => {
                        if attempt == 4 {
                            return Err(TestResultError::from_string(
                                "timeout reading multistream header",
                            ));
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        }
    }))
    .await;

    if let Some(e) = outcomes.into_iter().find_map(|r| r.err()) {
        return result.fail(e);
    }

    result.ok()
}

/// Attempts a single multistream handshake on `addr`.
///
/// Returns `Ok(true)` on success, `Ok(false)` when the read timed out and the
/// caller should retry, or `Err` on a non-recoverable failure.
async fn try_multistream_handshake(attempt: usize, addr: &str, header: &[u8]) -> Result<bool> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => {
            tracing::debug!(attempt, addr, "TCP connected, sending multistream header");
            s
        }
        Err(e) => {
            tracing::debug!(attempt, addr, err = %e, "TCP connect failed");
            return Err(CliError::from(e));
        }
    };

    if let Err(e) = stream.write_all(header).await {
        tracing::debug!(attempt, addr, err = %e, "write error");
        return Err(CliError::from(e));
    }

    let mut buf = [0u8; MULTISTREAM_HEADER.len()];
    match tokio::time::timeout(Duration::from_millis(500), stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {
            tracing::debug!(attempt, addr, raw = ?buf, "received echo");
            if buf
                .windows(b"/multistream/1.0.0".len())
                .any(|w| w == b"/multistream/1.0.0")
            {
                Ok(true)
            } else {
                Err(CliError::Other(format!(
                    "multistream header not found in: {:?}",
                    buf
                )))
            }
        }
        Ok(Err(e)) => {
            tracing::debug!(attempt, addr, err = %e, "read error");
            Err(CliError::from(e))
        }
        Err(_) => {
            tracing::debug!(attempt, addr, "read timeout, retrying");
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok(false)
        }
    }
}

/// Per-peer state tracked during the event loop.
#[derive(Default)]
struct PeerState {
    /// Time of first successful connection (relay or direct).
    connect_time: Option<Instant>,
    /// Whether any connection to this peer is established.
    connected: bool,
    /// Error from last failed outgoing connection attempt.
    connection_error: Option<String>,
    /// All ping RTTs with the time they were observed.
    ping_rtts: Vec<(Instant, Duration)>,
    /// Whether a direct (non-relay) connection is established.
    direct_connected: bool,
    /// Whether we have already attempted a direct dial using identify
    /// addresses.
    direct_dial_attempted: bool,
    /// Whether we received an identify response from this peer.
    identify_received: bool,
}

#[allow(clippy::too_many_arguments)]
async fn run_peer_event_loop(
    mut node: Node<TestBehaviour>,
    cluster_peers: &[Peer],
    self_peer_id: PeerId,
    queued_tests: &[TestCaseName],
    relay_peers: &[MutablePeer],
    enr_strings: &[String],
    args: &TestPeersArgs,
    ct: CancellationToken,
) -> (HashMap<String, Vec<TestResult>>, Node<TestBehaviour>) {
    let target_peers: Vec<(&Peer, &str)> = cluster_peers
        .iter()
        .zip(enr_strings.iter().map(String::as_str))
        .filter(|(p, _)| p.id != self_peer_id)
        .collect();

    if queued_tests.is_empty() {
        return (HashMap::new(), node);
    }

    let mut states: HashMap<PeerId, PeerState> = target_peers
        .iter()
        .map(|(p, _)| (p.id, PeerState::default()))
        .collect();

    let needs_direct = queued_tests.iter().any(|t| t.name == "DirectConn");

    let deadline = tokio::time::Instant::now()
        .checked_add(args.test_config.timeout)
        .unwrap_or_else(tokio::time::Instant::now);

    // Dial target peers once our relay reservation is established.
    let mut dialed_via_relay = false;

    // Retry unconnected peers every 5s to handle races where the remote
    // hasn't made its relay reservation yet when we first dial.
    let retry_delay = Duration::from_secs(5);
    let mut retry = tokio::time::interval_at(
        tokio::time::Instant::now()
            .checked_add(retry_delay)
            .unwrap_or_else(tokio::time::Instant::now),
        retry_delay,
    );

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        tokio::select! {
            event = node.select_next_some() => {
                // Once we have a relay circuit listen address our reservation is
                // active and other nodes can reach us. Trigger outbound dials.
                if let SwarmEvent::NewListenAddr { ref address, .. } = event
                    && is_relay_addr(address)
                    && !dialed_via_relay
                    && !queued_tests.is_empty()
                {
                    dialed_via_relay = true;
                    dial_peers_via_relay(&target_peers, relay_peers, &mut node);
                }
                handle_swarm_event(event, &mut states, &mut node, needs_direct, &target_peers, args.direct_connection_timeout);
            }
            _ = retry.tick() => {
                if dialed_via_relay && !queued_tests.is_empty() {
                    let unconnected: Vec<(&Peer, &str)> = target_peers
                        .iter()
                        .filter(|(p, _)| {
                            states.get(&p.id).is_none_or(|s| !s.connected)
                        })
                        .copied()
                        .collect();
                    if !unconnected.is_empty() {
                        // Clear stale errors so the final result reflects
                        // the last attempt.
                        for (peer, _) in &unconnected {
                            if let Some(s) = states.get_mut(&peer.id) {
                                s.connection_error = None;
                            }
                        }
                        dial_peers_via_relay(&unconnected, relay_peers, &mut node);
                    }
                }
            }
            _ = tokio::time::sleep(remaining) => {
                break;
            }
            _ = ct.cancelled() => {
                break;
            }
        }

        if !queued_tests.is_empty() && all_peers_done(&states, queued_tests, args) {
            break;
        }
    }

    let mut results = HashMap::new();
    for (peer, enr_str) in &target_peers {
        let state = &states[&peer.id];
        let target_name = peer_target_name(peer, enr_str);
        if queued_tests.iter().any(|t| t.name == "PingLoad") {
            tracing::info!(duration = ?args.load_test_duration, target = %target_name, "Running ping load tests...");
        }
        let test_results = build_peer_results(state, queued_tests, args);
        if queued_tests.iter().any(|t| t.name == "PingLoad") {
            tracing::info!(target = %target_name, "Ping load tests finished");
        }
        results.insert(target_name, test_results);
    }
    (results, node)
}

fn dial_peers_via_relay(
    target_peers: &[(&Peer, &str)],
    relay_peers: &[MutablePeer],
    node: &mut Node<TestBehaviour>,
) {
    for (peer, _) in target_peers {
        for relay_peer in relay_peers.iter().filter_map(|r| r.peer().ok().flatten()) {
            for relay_addr in &relay_peer.addresses {
                let mut circuit_addr = relay_addr.clone();
                circuit_addr.push(Protocol::P2p(relay_peer.id));
                circuit_addr.push(Protocol::P2pCircuit);
                circuit_addr.push(Protocol::P2p(peer.id));
                if let Err(e) = node.dial(circuit_addr.clone()) {
                    tracing::warn!(?e, %circuit_addr, "relay dial attempt failed");
                }
            }
        }
    }
}

fn handle_swarm_event(
    event: SwarmEvent<PlutoBehaviourEvent<TestBehaviour>>,
    states: &mut HashMap<PeerId, PeerState>,
    node: &mut Node<TestBehaviour>,
    needs_direct: bool,
    target_peers: &[(&Peer, &str)],
    direct_connection_timeout: Duration,
) {
    match event {
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            if let Some(state) = states.get_mut(&peer_id) {
                let addr = endpoint_addr(&endpoint);
                let is_relay = is_relay_addr(addr);

                if state.connect_time.is_none() {
                    state.connect_time = Some(Instant::now());
                    state.connected = true;
                }

                if !is_relay {
                    if let Some((peer, enr_str)) =
                        target_peers.iter().find(|(p, _)| p.id == peer_id)
                    {
                        tracing::info!(target = %peer_target_name(peer, enr_str), "Direct connection established");
                    }
                    state.direct_connected = true;
                }
            }
        }

        SwarmEvent::OutgoingConnectionError {
            peer_id: Some(peer_id),
            error,
            ..
        } => {
            if let Some(state) = states.get_mut(&peer_id)
                && !state.connected
            {
                state.connection_error = Some(error.to_string());
            }
        }

        SwarmEvent::Behaviour(PlutoBehaviourEvent::Ping(ping::Event {
            peer,
            result: Ok(rtt),
            ..
        })) => {
            if let Some(state) = states.get_mut(&peer) {
                state.ping_rtts.push((Instant::now(), rtt));
            }
        }

        SwarmEvent::Behaviour(PlutoBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            if let Some(state) = states.get_mut(&peer_id) {
                state.identify_received = true;
                if needs_direct && !state.direct_dial_attempted && !state.direct_connected {
                    state.direct_dial_attempted = true;
                    if let Some((peer, enr_str)) =
                        target_peers.iter().find(|(p, _)| p.id == peer_id)
                    {
                        tracing::info!(timeout = ?direct_connection_timeout, target = %peer_target_name(peer, enr_str), "Trying to establish direct connection...");
                    }
                    for addr in &info.listen_addrs {
                        if !is_relay_addr(addr) {
                            let mut direct_addr = addr.clone();
                            direct_addr.push(Protocol::P2p(peer_id));
                            if let Err(e) = node.dial(direct_addr.clone()) {
                                tracing::debug!(?e, %direct_addr, "direct dial attempt failed");
                            }
                        }
                    }
                }
            }
        }

        _ => {}
    }
}

fn endpoint_addr(endpoint: &libp2p::core::ConnectedPoint) -> &Multiaddr {
    match endpoint {
        libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
        libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
    }
}

fn all_peers_done(
    states: &HashMap<PeerId, PeerState>,
    queued_tests: &[TestCaseName],
    args: &TestPeersArgs,
) -> bool {
    states.values().all(|s| peer_is_done(s, queued_tests, args))
}

fn peer_is_done(state: &PeerState, queued_tests: &[TestCaseName], args: &TestPeersArgs) -> bool {
    for test in queued_tests {
        match test.name {
            "Ping" if !state.connected => return false,
            "Ping" => {}
            "PingMeasure" if state.ping_rtts.is_empty() => return false,
            "PingMeasure" => {}
            "PingLoad" => {
                let Some(ct) = state.connect_time else {
                    return false;
                };
                if ct.elapsed() < args.load_test_duration {
                    return false;
                }
            }
            "DirectConn" => {
                if state.direct_connected {
                    continue;
                }
                let Some(ct) = state.connect_time else {
                    return false;
                };
                if ct.elapsed() < args.direct_connection_timeout {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

fn build_peer_results(
    state: &PeerState,
    queued_tests: &[TestCaseName],
    args: &TestPeersArgs,
) -> Vec<TestResult> {
    queued_tests
        .iter()
        .map(|test| match test.name {
            "Ping" => {
                let r = TestResult::new("Ping");
                if state.connected {
                    r.ok()
                } else if let Some(ref err) = state.connection_error {
                    r.fail(TestResultError::from_string(err))
                } else {
                    r.fail(CliError::TimeoutInterrupted)
                }
            }
            "PingMeasure" => {
                let r = TestResult::new("PingMeasure");
                // Use the most recent ping rather than the first: we cannot issue
                // an on-demand ping (pings are driven by the libp2p keepalive schedule),
                // so .last() is the closest approximation to a fresh measurement.
                if let Some(&(_, rtt)) = state.ping_rtts.last() {
                    evaluate_rtt(rtt, r, THRESHOLD_MEASURE_AVG, THRESHOLD_MEASURE_POOR)
                } else {
                    r.fail(TestResultError::from_string("no ping result received"))
                }
            }
            "PingLoad" => {
                // Gap vs charon: charon issues on-demand pings during load; libp2p drives
                // pings on its own keepalive schedule so we can only filter existing RTTs.
                let r = TestResult::new("PingLoad");
                let load_rtts: Vec<Duration> = if let Some(ct) = state.connect_time {
                    state
                        .ping_rtts
                        .iter()
                        .filter(|(t, _)| t.saturating_duration_since(ct) < args.load_test_duration)
                        .map(|(_, rtt)| *rtt)
                        .collect()
                } else {
                    vec![]
                };
                if load_rtts.is_empty() {
                    r.fail(TestResultError::from_string(
                        "no ping results during load test",
                    ))
                } else {
                    evaluate_highest_rtt(load_rtts, r, THRESHOLD_LOAD_AVG, THRESHOLD_LOAD_POOR)
                }
            }
            "DirectConn" => {
                let r = TestResult::new("DirectConn");
                if state.direct_connected {
                    r.ok()
                } else if !state.connected {
                    r.fail(TestResultError::from_string(
                        "no relay connection established",
                    ))
                } else if state.identify_received && !state.direct_dial_attempted {
                    r.fail(TestResultError::from_string(
                        "no direct addresses available from identify",
                    ))
                } else {
                    r.fail(TestResultError::from_string(
                        "direct connection not established within timeout",
                    ))
                }
            }
            name => {
                TestResult::new(name).fail(TestResultError::from_string("unsupported test case"))
            }
        })
        .collect()
}

fn build_enr_hash(private_key: &k256::SecretKey, enr_strings: &[String]) -> Result<String> {
    let self_enr = Record::from_key(private_key)?.to_string();
    let mut all_enrs = enr_strings.to_vec();
    if !all_enrs.contains(&self_enr) {
        all_enrs.push(self_enr);
    }
    all_enrs.sort();
    Ok(hex::encode(Sha256::digest(all_enrs.join(",").as_bytes())))
}

async fn write_and_publish_results(
    res: &TestCategoryResult,
    writer: &mut dyn Write,
    args: &TestPeersArgs,
) -> Result<()> {
    if !args.test_config.quiet {
        write_result_to_writer(res, writer)?;
    }

    if !args.test_config.output_json.is_empty() {
        write_result_to_file(res, args.test_config.output_json.as_ref()).await?;
    }

    if args.test_config.publish {
        let all = AllCategoriesResult {
            peers: Some(res.clone()),
            ..Default::default()
        };
        publish_result_to_obol_api(
            all,
            &args.test_config.publish_addr,
            &args.test_config.publish_private_key_file,
        )
        .await?;
    }

    Ok(())
}

async fn keep_node_alive(
    node: &mut Node<TestBehaviour>,
    keep_alive: Duration,
    ct: CancellationToken,
) {
    tracing::info!("Keeping TCP node alive until keep-alive time is reached...");
    #[allow(clippy::arithmetic_side_effects)]
    let deadline = tokio::time::Instant::now() + keep_alive;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        tokio::select! {
            _ = node.select_next_some() => {}
            _ = tokio::time::sleep(remaining) => { break; }
            _ = ct.cancelled() => { break; }
        }
    }
}

async fn setup_p2p(
    cancel: CancellationToken,
    private_key: k256::SecretKey,
    p2p_cfg: P2PConfig,
    relay_urls: &[String],
    cluster_peers: &[Peer],
    self_peer_id: PeerId,
    enr_hash: &str,
) -> Result<(Node<TestBehaviour>, Vec<MutablePeer>)> {
    let relay_peers = new_relays(cancel.clone(), relay_urls, enr_hash).await?;

    let mut all_peer_ids: Vec<PeerId> = cluster_peers.iter().map(|p| p.id).collect();
    all_peer_ids.push(self_peer_id);

    let p2p_context = P2PContext::new(all_peer_ids.clone());
    let gater = ConnGater::new_conn_gater(all_peer_ids, relay_peers.clone());

    let node: Node<TestBehaviour> = Node::new(
        p2p_cfg,
        private_key,
        NodeType::TCP,
        false,
        p2p_context,
        |builder, _keypair, relay_client| {
            builder.with_gater(gater).with_inner(TestBehaviour {
                relay: relay_client,
                reservation: MutableRelayReservation::new(relay_peers.clone()),
            })
        },
    )?;

    Ok((node, relay_peers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_cluster::test_cluster;
    use std::{io::Write, time::Duration as StdDuration};
    use tempfile::NamedTempFile;
    use tokio_util::sync::CancellationToken;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path as wm_path},
    };

    fn default_test_config() -> TestConfigArgs {
        TestConfigArgs {
            output_json: String::new(),
            quiet: false,
            test_cases: None,
            timeout: StdDuration::from_secs(60),
            publish: false,
            publish_addr: String::new(),
            publish_private_key_file: std::path::PathBuf::new(),
        }
    }

    fn no_source_peers_args() -> TestPeersArgs {
        TestPeersArgs {
            test_config: default_test_config(),
            enrs: None,
            lock_file: None,
            definition_file: None,
            private_key_file: std::path::PathBuf::new(),
            keep_alive: StdDuration::ZERO,
            load_test_duration: StdDuration::from_secs(1),
            direct_connection_timeout: StdDuration::from_secs(1),
            p2p_tcp_addrs: vec![],
            p2p_relays: vec![],
            p2p_external_ip: None,
            p2p_external_hostname: None,
            p2p_udp_addrs: vec![],
            p2p_disable_reuseport: false,
        }
    }

    #[tokio::test]
    async fn run_no_source_flag_returns_error() {
        let args = no_source_peers_args();
        let mut output = Vec::new();
        let err = run(args, &mut output, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("--enrs, --lock-file or --definition-file must be specified")
        );
    }

    #[tokio::test]
    async fn run_conflicting_flags_enrs_and_lock_returns_error() {
        let mut args = no_source_peers_args();
        args.enrs = Some(vec!["enr:test".into()]);
        args.lock_file = Some("foo.json".into());
        let mut output = Vec::new();
        let err = run(args, &mut output, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("only one of --enrs, --lock-file or --definition-file may be specified")
        );
    }

    #[tokio::test]
    async fn run_conflicting_flags_enrs_and_definition_returns_error() {
        let mut args = no_source_peers_args();
        args.enrs = Some(vec!["enr:test".into()]);
        args.definition_file = Some("foo.json".into());
        let mut output = Vec::new();
        let err = run(args, &mut output, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("only one of --enrs, --lock-file or --definition-file may be specified")
        );
    }

    #[tokio::test]
    async fn run_conflicting_flags_lock_and_definition_returns_error() {
        let mut args = no_source_peers_args();
        args.lock_file = Some("foo.json".into());
        args.definition_file = Some("bar.json".into());
        let mut output = Vec::new();
        let err = run(args, &mut output, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("only one of --enrs, --lock-file or --definition-file may be specified")
        );
    }

    #[tokio::test]
    async fn run_quiet_without_output_json_returns_error() {
        let mut args = no_source_peers_args();
        args.enrs = Some(vec!["enr:test".into()]);
        args.test_config.quiet = true;
        let mut output = Vec::new();
        let err = run(args, &mut output, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("on --quiet, an --output-json is required")
        );
    }

    #[tokio::test]
    async fn fetch_enrs_from_lock_valid() {
        let (lock, ..) = test_cluster::new_for_test(1, 2, 3, 42);
        let json = serde_json::to_string(&lock).unwrap();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();

        let path = file.path().to_str().unwrap();
        let enrs = fetch_enrs_from_lock(path).await.unwrap();

        let expected: Vec<String> = lock
            .definition
            .operators
            .iter()
            .map(|op| op.enr.clone())
            .filter(|e| !e.is_empty())
            .collect();
        assert_eq!(enrs, expected);
        assert!(!enrs.is_empty());
    }

    #[tokio::test]
    async fn fetch_enrs_from_lock_empty_enrs() {
        let (mut lock, ..) = test_cluster::new_for_test(1, 2, 3, 42);
        lock.definition.operators.clear();
        let json = serde_json::to_string(&lock).unwrap();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();

        let path = file.path().to_str().unwrap();
        let err = fetch_enrs_from_lock(path).await.unwrap_err();
        assert!(err.to_string().contains("no peers found in lock file"));
    }

    #[tokio::test]
    async fn fetch_enrs_from_lock_invalid_json() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"not json").unwrap();

        let path = file.path().to_str().unwrap();
        let err = fetch_enrs_from_lock(path).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn fetch_enrs_from_lock_file_not_found() {
        let err = fetch_enrs_from_lock("/nonexistent/path/lock.json").await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn fetch_enrs_from_definition_local_valid() {
        let (lock, ..) = test_cluster::new_for_test(1, 2, 3, 42);
        let json = serde_json::to_string(&lock.definition).unwrap();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();

        let path = file.path().to_str().unwrap();
        let enrs = fetch_enrs_from_definition(path).await.unwrap();

        let expected: Vec<String> = lock
            .definition
            .operators
            .iter()
            .map(|op| op.enr.clone())
            .filter(|e| !e.is_empty())
            .collect();
        assert_eq!(enrs, expected);
        assert!(!enrs.is_empty());
    }

    #[tokio::test]
    async fn fetch_enrs_from_definition_local_empty_enrs() {
        let (lock, ..) = test_cluster::new_for_test(1, 2, 3, 42);
        let mut def = lock.definition;
        def.operators.clear();
        let json = serde_json::to_string(&def).unwrap();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();

        let path = file.path().to_str().unwrap();
        let err = fetch_enrs_from_definition(path).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("no peers found in definition file")
        );
    }

    #[tokio::test]
    async fn fetch_enrs_from_definition_local_invalid_json() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"garbage").unwrap();

        let path = file.path().to_str().unwrap();
        let err = fetch_enrs_from_definition(path).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn fetch_enrs_from_definition_local_file_not_found() {
        let err = fetch_enrs_from_definition("/nonexistent/path/def.json").await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn fetch_enrs_from_definition_http_valid() {
        let (lock, ..) = test_cluster::new_for_test(1, 2, 3, 42);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/def"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&lock.definition))
            .mount(&server)
            .await;

        let url = format!("{}/def", server.uri());
        let enrs = fetch_enrs_from_definition(&url).await.unwrap();

        let expected: Vec<String> = lock
            .definition
            .operators
            .iter()
            .map(|op| op.enr.clone())
            .filter(|e| !e.is_empty())
            .collect();
        assert_eq!(enrs, expected);
    }

    #[tokio::test]
    async fn fetch_enrs_from_definition_http_error_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/error"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let url = format!("{}/error", server.uri());
        let err = fetch_enrs_from_definition(&url).await.unwrap_err();
        assert!(err.to_string().contains("Fetch definition error"));
    }

    #[tokio::test]
    async fn fetch_enrs_uses_enrs_when_set() {
        let mut args = no_source_peers_args();
        args.enrs = Some(vec!["enr:test1".to_string(), "enr:test2".to_string()]);
        let enrs = fetch_enrs(&args).await.unwrap();
        assert_eq!(enrs, vec!["enr:test1", "enr:test2"]);
    }

    #[tokio::test]
    async fn fetch_enrs_uses_definition_file_when_set() {
        let (lock, ..) = test_cluster::new_for_test(1, 2, 3, 42);
        let json = serde_json::to_string(&lock.definition).unwrap();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();

        let mut args = no_source_peers_args();
        args.definition_file = Some(file.path().to_str().unwrap().to_string());
        let enrs = fetch_enrs(&args).await.unwrap();

        let expected: Vec<String> = lock
            .definition
            .operators
            .iter()
            .map(|op| op.enr.clone())
            .filter(|e| !e.is_empty())
            .collect();
        assert_eq!(enrs, expected);
    }

    #[tokio::test]
    async fn fetch_enrs_uses_lock_file_when_set() {
        let (lock, ..) = test_cluster::new_for_test(1, 2, 3, 42);
        let json = serde_json::to_string(&lock).unwrap();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();

        let mut args = no_source_peers_args();
        args.lock_file = Some(file.path().to_owned());
        let enrs = fetch_enrs(&args).await.unwrap();

        let expected: Vec<String> = lock
            .definition
            .operators
            .iter()
            .map(|op| op.enr.clone())
            .filter(|e| !e.is_empty())
            .collect();
        assert_eq!(enrs, expected);
    }
}
