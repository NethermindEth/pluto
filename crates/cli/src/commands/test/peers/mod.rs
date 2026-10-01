//! Peer connectivity tests.

mod probe;

use std::{collections::HashMap, io::Write, path::PathBuf, time::Duration};

use clap::Args;
use futures::{StreamExt as _, future::join_all, stream::FuturesUnordered};
use libp2p::{PeerId, relay, swarm::NetworkBehaviour};
use pluto_cluster::{definition::Definition, lock::Lock};
use pluto_eth2util::enr::Record;
use pluto_p2p::{
    bootnode,
    config::{DEFAULT_RELAYS, P2PConfig, RelayAddr},
    gater::ConnGater,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::{self, Peer},
    relay::RelayManager,
};
use rand::Rng as _;
use reqwest::Method;
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use self::probe::{PeerProbe, PeerProbeHandle};

use super::{
    AllCategoriesResult, TestCaseName, TestCategory, TestCategoryResult, TestConfigArgs,
    TestResult, TestResultError, calculate_score, evaluate_highest_rtt, evaluate_rtt,
    must_output_to_file_on_quiet, publish_result_to_obol_api, write_result_to_file,
    write_result_to_writer,
};
use crate::{
    commands::common,
    duration::Duration as CliDuration,
    error::{CliError, Result},
};

/// Combined inner behaviour: relay client, relay reservation/routing and the
/// on-demand test probes.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "TestBehaviourEvent")]
struct TestBehaviour {
    relay: relay::client::Behaviour,
    relay_manager: RelayManager,
    probe: PeerProbe,
}

#[derive(Debug)]
enum TestBehaviourEvent {
    Relay(relay::client::Event),
    RelayManager(
        #[expect(
            dead_code,
            reason = "event payload is never read; only the variant tag matters"
        )]
        pluto_p2p::relay::RelayManagerEvent,
    ),
}

impl From<relay::client::Event> for TestBehaviourEvent {
    fn from(e: relay::client::Event) -> Self {
        Self::Relay(e)
    }
}

impl From<pluto_p2p::relay::RelayManagerEvent> for TestBehaviourEvent {
    fn from(e: pluto_p2p::relay::RelayManagerEvent) -> Self {
        Self::RelayManager(e)
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

/// How long the Ping test retries an unreachable peer.
const PING_TEST_TIMEOUT: Duration = Duration::from_secs(60);
const PING_RETRY_INTERVAL: Duration = Duration::from_secs(3);
/// The PingLoad test starts one more continuous pinger per interval.
const PING_LOAD_SPAWN_INTERVAL: Duration = Duration::from_secs(1);
const PING_LOAD_MAX_PAUSE_MS: u64 = 100;
const DIRECT_CONN_RETRY_INTERVAL: Duration = Duration::from_secs(1);

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
    #[expect(
        rustdoc::broken_intra_doc_links,
        reason = "doc comment doubles as clap help text, so the brackets must stay literal rather than becoming a rustdoc link"
    )]
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
        value_parser = crate::duration::parse_go_duration
    )]
    pub keep_alive: Duration,

    /// Time to keep running the load tests in seconds. For each second a new
    /// continuous ping instance is spawned.
    #[arg(
        long = "load-test-duration",
        default_value = "30s",
        value_parser = crate::duration::parse_go_duration
    )]
    pub load_test_duration: Duration,

    /// Time to keep trying to establish direct connection to peer.
    #[arg(
        long = "direct-connection-timeout",
        default_value = "2m",
        value_parser = crate::duration::parse_go_duration
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

    let test_cases = args.test_config.test_cases.as_deref();
    let mut relay_tests = super::filter_tests(&supported_relay_test_cases(), test_cases);
    super::sort_tests(&mut relay_tests);
    let mut peer_tests = super::filter_tests(&supported_peer_test_cases(), test_cases);
    super::sort_tests(&mut peer_tests);
    let mut self_tests = super::filter_tests(&supported_self_test_cases(), test_cases);
    super::sort_tests(&mut self_tests);

    if peer_tests.is_empty() && self_tests.is_empty() {
        return Err(CliError::TestCaseNotSupported);
    }

    let enr_strings = fetch_enrs(&args).await?;
    let cluster_peers = parse_peers(&enr_strings)?;

    let private_key = pluto_k1util::load(&args.private_key_file)?;

    peer::verify_p2p_key(&cluster_peers, &private_key)?;

    let self_peer_id = peer::peer_id_from_key(private_key.public_key())?;

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

    let relay_addrs = common::parse_relay_addrs(&args.p2p_relays)?;

    // The node outlives the test phase: it keeps serving other peers' tests
    // during keep-alive, so it is stopped by its own token.
    let node_ct = ct.child_token();
    let _stop_node = node_ct.clone().drop_guard();

    let (node, probe) = setup_p2p(
        node_ct.clone(),
        private_key,
        p2p_cfg,
        &relay_addrs,
        &cluster_peers,
        self_peer_id,
        &enr_hash,
    )
    .await?;
    let node_task =
        tokio::spawn(drive_node(node, node_ct.clone()).instrument(tracing::Span::current()));

    let timeout_ct = ct.child_token();
    let _stop_timeout = timeout_ct.clone().drop_guard();
    tokio::spawn({
        let timeout_ct = timeout_ct.clone();
        let timeout = args.test_config.timeout;
        async move {
            tokio::select! {
                () = tokio::time::sleep(timeout) => timeout_ct.cancel(),
                () = timeout_ct.cancelled() => {}
            }
        }
    });

    // Charon tests every ENR, but the local node cannot ping itself: it is
    // covered by the `self` target instead.
    let target_peers: Vec<(&Peer, &str)> = cluster_peers
        .iter()
        .zip(enr_strings.iter().map(String::as_str))
        .filter(|(p, _)| p.id != self_peer_id)
        .collect();

    let start_time = tokio::time::Instant::now();

    let (relay_results, peer_results, self_results) = tokio::join!(
        run_relay_http_tests(&relay_addrs, &relay_tests, timeout_ct.clone()),
        run_all_peer_tests(&probe, &target_peers, &peer_tests, &args, &timeout_ct),
        run_self_tests(&args.p2p_tcp_addrs, &self_tests, &timeout_ct),
    );

    let elapsed = start_time.elapsed();

    let mut all_targets: HashMap<String, Vec<TestResult>> = HashMap::new();
    all_targets.extend(relay_results);
    all_targets.extend(self_results);
    all_targets.extend(peer_results);

    // Use the worst score of all targets as the category score.
    let score = all_targets
        .values()
        .map(|r| calculate_score(r))
        .max()
        .unwrap_or(super::CategoryScore::A);

    let mut res = TestCategoryResult::new(TestCategory::Peers);
    res.targets = all_targets;
    res.execution_time = Some(CliDuration::new(elapsed));
    res.score = Some(score);

    write_and_publish_results(&res, writer, &args).await?;

    tracing::info!("Keeping TCP node alive for peers until keep-alive time is reached...");
    tokio::select! {
        () = tokio::time::sleep(args.keep_alive) => tracing::info!("Await time reached or interrupted"),
        () = ct.cancelled() => tracing::info!("Forcefully stopped"),
    }

    node_ct.cancel();
    if let Err(e) = node_task.await {
        tracing::warn!(err = %e, "P2P node task failed");
    }

    Ok(res)
}

/// Polls the node until `ct` is cancelled.
async fn drive_node(mut node: Node<TestBehaviour>, ct: CancellationToken) {
    loop {
        tokio::select! {
            _ = node.select_next_some() => {}
            () = ct.cancelled() => return,
        }
    }
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
            Ok(Peer::from_enr(&record, i as u64)?)
        })
        .collect()
}

/// Shortens an ENR to `<first 13 bytes>...<last 4 bytes>` for display.
///
/// ENRs are base64 so in practice ASCII, but the string comes from `--enrs`
/// config input: `str::get` returns `None` mid-code-point, so walk inwards to
/// the nearest boundary rather than slicing bytes and panicking.
fn format_enr(enr: &str) -> String {
    if enr.len() <= 17 {
        return enr.to_string();
    }
    let head = (0..=13)
        .rev()
        .find_map(|i| enr.get(..i))
        .unwrap_or_default();
    let tail = (enr.len().saturating_sub(4)..=enr.len())
        .find_map(|i| enr.get(i..))
        .unwrap_or_default();
    format!("{head}...{tail}")
}

fn peer_target_name(peer: &Peer, enr_str: &str) -> String {
    format!("peer {} {}", peer.name, format_enr(enr_str))
}

/// Probes every configured relay over HTTP.
///
/// Targets are derived from the parsed addresses rather than the raw
/// `--p2p-relays` strings so that this and the P2P stack agree on what was
/// configured — probing the raw strings reported a bogus target when relaying
/// was disabled with `--p2p-relays=""`. Multiaddr relays are probed too: they
/// have no HTTP endpoint, so the probe reports a failure for them instead of
/// quietly leaving them untested.
async fn run_relay_http_tests(
    relays: &[RelayAddr],
    queued: &[TestCaseName],
    ct: CancellationToken,
) -> HashMap<String, Vec<TestResult>> {
    let mut futs: FuturesUnordered<_> = relays
        .iter()
        .map(|relay| {
            let url = relay.to_string();
            let ct = ct.clone();
            let queued = queued.to_vec();
            tokio::spawn(
                async move {
                    let key = format!("relay {url}");
                    let mut target_results = Vec::new();
                    for test in &queued {
                        if ct.is_cancelled() {
                            target_results.push(
                                TestResult::new(test.name).fail(CliError::TimeoutInterrupted),
                            );
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
                }
                .instrument(tracing::Span::current()),
            )
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
    tokio::select! {
        res = super::http_client().get(url).send() => match res {
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

/// Runs the queued self tests in order, reporting them under the `self`
/// target.
async fn run_self_tests(
    tcp_addrs: &[String],
    queued: &[TestCaseName],
    ct: &CancellationToken,
) -> HashMap<String, Vec<TestResult>> {
    let mut results = Vec::with_capacity(queued.len());
    for test in queued {
        let test_fut = async {
            match test.name {
                "Libp2pTCPPortOpen" => libp2p_tcp_port_open_test(tcp_addrs).await,
                _ => TestResult::new(test.name)
                    .fail(TestResultError::from_string("unsupported self test")),
            }
        };

        tokio::select! {
            result = test_fut => results.push(result),
            () = ct.cancelled() => {
                results.push(TestResult::new(test.name).fail(CliError::TimeoutInterrupted));
                break;
            }
        }
    }

    HashMap::from([("self".to_string(), results)])
}

/// Checks that every `--p2p-tcp-address` answers the multistream handshake.
///
/// Without listen addresses there is nothing to check and the test passes, as
/// in Charon.
async fn libp2p_tcp_port_open_test(addrs: &[String]) -> TestResult {
    let result = TestResult::new("Libp2pTCPPortOpen");

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

/// Runs the queued tests against every target peer concurrently.
async fn run_all_peer_tests(
    probe: &PeerProbeHandle,
    target_peers: &[(&Peer, &str)],
    queued: &[TestCaseName],
    args: &TestPeersArgs,
    ct: &CancellationToken,
) -> HashMap<String, Vec<TestResult>> {
    join_all(target_peers.iter().map(|(peer, enr_str)| async move {
        let target_name = peer_target_name(peer, enr_str);
        let results = run_single_peer_tests(probe, peer, &target_name, queued, args, ct).await;
        (target_name, results)
    }))
    .await
    .into_iter()
    .collect()
}

/// Runs the queued tests against one peer in order.
///
/// Once `ct` fires, the interrupted test is reported as timed out and the
/// remaining ones are dropped, as in Charon.
async fn run_single_peer_tests(
    probe: &PeerProbeHandle,
    peer: &Peer,
    target_name: &str,
    queued: &[TestCaseName],
    args: &TestPeersArgs,
    ct: &CancellationToken,
) -> Vec<TestResult> {
    let mut results = Vec::with_capacity(queued.len());
    for test in queued {
        let test_fut = async {
            match test.name {
                "Ping" => peer_ping_test(probe, peer).await,
                "PingMeasure" => peer_ping_measure_test(probe, peer).await,
                "PingLoad" => {
                    peer_ping_load_test(probe, peer, target_name, args.load_test_duration).await
                }
                "DirectConn" => {
                    peer_direct_conn_test(probe, peer, target_name, args.direct_connection_timeout)
                        .await
                }
                name => TestResult::new(name)
                    .fail(TestResultError::from_string("unsupported test case")),
            }
        };

        tokio::select! {
            result = test_fut => results.push(result),
            () = ct.cancelled() => {
                results.push(TestResult::new(test.name).fail(CliError::TimeoutInterrupted));
                break;
            }
        }
    }
    results
}

/// Pings the peer, retrying every [`PING_RETRY_INTERVAL`] for up to
/// [`PING_TEST_TIMEOUT`].
///
/// Charon retries until the global `--timeout`; the bound keeps an unreachable
/// peer from holding up the whole run.
async fn peer_ping_test(probe: &PeerProbeHandle, peer: &Peer) -> TestResult {
    let result = TestResult::new("Ping");

    let mut last_err = None;
    let retry = async {
        loop {
            match probe.ping(peer.id).await {
                Ok(_) => return Ok(()),
                Err(e) if e.is_relay_error() => return Err(e),
                Err(e) => {
                    tracing::warn!(peer_name = %peer.name, err = %e, "Ping to peer failed, retrying in 3 sec...");
                    last_err = Some(e);
                    tokio::time::sleep(PING_RETRY_INTERVAL).await;
                }
            }
        }
    };

    match tokio::time::timeout(PING_TEST_TIMEOUT, retry).await {
        Ok(Ok(())) => result.ok(),
        Ok(Err(e)) => result.fail(e),
        Err(_) => match last_err {
            Some(e) => result.fail(e),
            None => result.fail(CliError::TimeoutInterrupted),
        },
    }
}

/// Grades the RTT of a single ping.
async fn peer_ping_measure_test(probe: &PeerProbeHandle, peer: &Peer) -> TestResult {
    let result = TestResult::new("PingMeasure");
    match probe.ping(peer.id).await {
        Ok(rtt) => evaluate_rtt(rtt, result, THRESHOLD_MEASURE_AVG, THRESHOLD_MEASURE_POOR),
        Err(e) => result.fail(e),
    }
}

/// Starts one more continuous pinger every second for `load_duration` and
/// grades the highest RTT observed.
async fn peer_ping_load_test(
    probe: &PeerProbeHandle,
    peer: &Peer,
    target_name: &str,
    load_duration: Duration,
) -> TestResult {
    tracing::info!(duration = ?load_duration, target = %target_name, "Running ping load tests...");
    let result = TestResult::new("PingLoad");

    let now = tokio::time::Instant::now();
    let deadline = now.checked_add(load_duration).unwrap_or(now);
    let mut ticker = tokio::time::interval_at(
        now.checked_add(PING_LOAD_SPAWN_INTERVAL).unwrap_or(now),
        PING_LOAD_SPAWN_INTERVAL,
    );

    let mut pingers = JoinSet::new();
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            _ = ticker.tick() => {
                pingers.spawn(
                    ping_continuously(probe.clone(), peer.id, deadline)
                        .instrument(tracing::Span::current()),
                );
            }
        }
    }
    let rtts: Vec<Duration> = pingers.join_all().await.into_iter().flatten().collect();

    tracing::info!(target = %target_name, "Ping load tests finished");

    if rtts.is_empty() {
        return result.fail(TestResultError::from_string(
            "no successful pings during load test",
        ));
    }
    evaluate_highest_rtt(rtts, result, THRESHOLD_LOAD_AVG, THRESHOLD_LOAD_POOR)
}

/// Pings `peer` back to back, with a random pause of up to 100ms between
/// pings, until `deadline` or the first failed ping.
///
/// Failed pings are not recorded: Charon records them with a zero RTT, which
/// grades a dead peer as "Good".
async fn ping_continuously(
    probe: PeerProbeHandle,
    peer: PeerId,
    deadline: tokio::time::Instant,
) -> Vec<Duration> {
    let mut rtts = Vec::new();
    while let Ok(Ok(rtt)) = tokio::time::timeout_at(deadline, probe.ping(peer)).await {
        rtts.push(rtt);
        let pause = Duration::from_millis(rand::thread_rng().gen_range(0..PING_LOAD_MAX_PAUSE_MS));
        if tokio::time::timeout_at(deadline, tokio::time::sleep(pause))
            .await
            .is_err()
        {
            break;
        }
    }
    rtts
}

/// Retries a direct dial every second for up to `timeout`, then checks that
/// both the relay and the direct connection are open.
async fn peer_direct_conn_test(
    probe: &PeerProbeHandle,
    peer: &Peer,
    target_name: &str,
    timeout: Duration,
) -> TestResult {
    tracing::info!(timeout = ?timeout, target = %target_name, "Trying to establish direct connection...");
    let result = TestResult::new("DirectConn");

    let now = tokio::time::Instant::now();
    let deadline = now.checked_add(timeout).unwrap_or(now);
    loop {
        let err = match tokio::time::timeout_at(deadline, probe.dial_direct(peer.id)).await {
            Ok(Ok(())) => break,
            Ok(Err(e)) => TestResultError::from(e),
            Err(_) => {
                TestResultError::from_string("direct connection not established within timeout")
            }
        };
        if tokio::time::timeout_at(deadline, tokio::time::sleep(DIRECT_CONN_RETRY_INTERVAL))
            .await
            .is_err()
        {
            return result.fail(err);
        }
    }

    tracing::info!(target = %target_name, "Direct connection established");

    let connections = probe.connection_count(&peer.id);
    if connections < 2 {
        return result.fail(TestResultError::from_string(format!(
            "expected 2 connections to peer (relay and direct): connections={connections}"
        )));
    }

    result.ok()
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

async fn setup_p2p(
    cancel: CancellationToken,
    private_key: k256::SecretKey,
    p2p_cfg: P2PConfig,
    relay_addrs: &[RelayAddr],
    cluster_peers: &[Peer],
    self_peer_id: PeerId,
    enr_hash: &str,
) -> Result<(Node<TestBehaviour>, PeerProbeHandle)> {
    let relay_peers = bootnode::new_relays(cancel.clone(), relay_addrs, enr_hash).await?;

    let mut all_peer_ids: Vec<PeerId> = cluster_peers.iter().map(|p| p.id).collect();
    all_peer_ids.push(self_peer_id);

    let p2p_context = P2PContext::new(all_peer_ids.clone());
    let gater = ConnGater::new_conn_gater(all_peer_ids, relay_peers.clone());
    let (probe, probe_handle) = PeerProbe::new(p2p_context.clone());

    let node: Node<TestBehaviour> = Node::new(
        p2p_cfg,
        private_key,
        NodeType::TCP,
        false,
        p2p_context,
        |builder, _keypair, relay_client| {
            let p2p_context = builder.p2p_context();
            builder.with_gater(gater).with_inner(TestBehaviour {
                relay: relay_client,
                relay_manager: RelayManager::new(relay_peers, p2p_context),
                probe,
            })
        },
    )?;

    Ok((node, probe_handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test::TestVerdict;
    use k256::{SecretKey, elliptic_curve::rand_core::OsRng};
    use libp2p::{Multiaddr, multiaddr::Protocol};
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

    #[tokio::test]
    async fn relay_http_tests_report_nothing_when_relaying_is_disabled() {
        // `--p2p-relays=""` parses to no relays, so there is nothing to probe.
        // Probing the raw flag strings instead used to key a target off the
        // empty string and report it as a failing relay.
        let relays = common::parse_relay_addrs(&["".to_string()]).expect("relays");
        let queued = [TestCaseName::new("PingRelay", 1)];

        let results = run_relay_http_tests(&relays, &queued, CancellationToken::new()).await;

        assert!(results.is_empty(), "unexpected relay targets: {results:?}");
    }

    #[tokio::test]
    async fn relay_http_tests_key_targets_by_address() {
        let relays = common::parse_relay_addrs(&[
            "http://127.0.0.1:1/enr".to_string(),
            "/ip4/127.0.0.1/tcp/3610/p2p/16Uiu2HAm7ULrTMdiEmQCJ2N9nsuGvfUDvfDGgHXJ4vNjrCwCzGDs"
                .to_string(),
        ])
        .expect("relays");
        let queued = [TestCaseName::new("PingRelay", 1)];

        let results = run_relay_http_tests(&relays, &queued, CancellationToken::new()).await;

        // Both forms are probed, and the path survives into the target key.
        assert_eq!(results.len(), 2);
        assert!(
            results.contains_key("relay http://127.0.0.1:1/enr"),
            "unexpected targets: {:?}",
            results.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn format_enr_pins_ascii_output() {
        assert_eq!(format_enr("enr:short"), "enr:short");
        // 17 bytes is still returned verbatim.
        assert_eq!(format_enr("enr:-abcdefghijkl"), "enr:-abcdefghijkl");
        assert_eq!(
            format_enr("enr:-Ku4QHqVeJ8PPzcvW1234567890"),
            "enr:-Ku4QHqVe...7890"
        );
    }

    #[test]
    fn format_enr_truncates_on_char_boundaries() {
        // A 2-byte code point straddles byte 13 (the head cut).
        let head = format!("{}{}", "a".repeat(12), "é".repeat(6));
        assert_eq!(format_enr(&head), format!("{}...éé", "a".repeat(12)));

        // A 2-byte code point straddles the tail cut (len - 4).
        let tail = format!("{}{}", "a".repeat(17), "é".repeat(3));
        assert_eq!(format_enr(&tail), format!("{}...éé", "a".repeat(13)));

        // All multi-byte, both cuts land mid-code-point.
        assert_eq!(format_enr(&"€".repeat(10)), "€€€€...€");
    }

    /// Returns a localhost TCP address that was free a moment ago.
    fn free_tcp_addr() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    }

    fn tcp_multiaddr(addr: &str, peer: PeerId) -> Multiaddr {
        let addr: std::net::SocketAddr = addr.parse().unwrap();
        Multiaddr::empty()
            .with(Protocol::from(addr.ip()))
            .with(Protocol::Tcp(addr.port()))
            .with(Protocol::P2p(peer))
    }

    fn enr(key: &SecretKey) -> String {
        Record::from_key(key).unwrap().to_string()
    }

    /// Starts a test node listening on `tcp_addr`. While `dial` is set, the
    /// node keeps dialing it until it holds two connections to its peer, so
    /// the remote sees a relay-free "relay and direct" pair.
    async fn start_node(
        key: SecretKey,
        cluster: &[Peer],
        tcp_addr: &str,
        dial: Option<(Multiaddr, PeerId)>,
        ct: CancellationToken,
    ) -> PeerProbeHandle {
        let self_id = peer::peer_id_from_key(key.public_key()).unwrap();
        let cfg = P2PConfig {
            relays: vec![],
            external_ip: None,
            external_host: None,
            tcp_addrs: vec![tcp_addr.to_string()],
            udp_addrs: vec![],
            disable_reuse_port: false,
        };
        let (mut node, probe) = setup_p2p(ct.clone(), key, cfg, &[], cluster, self_id, "test")
            .await
            .unwrap();

        let dialer = probe.clone();
        tokio::spawn(async move {
            let mut redial = tokio::time::interval(StdDuration::from_millis(100));
            loop {
                tokio::select! {
                    _ = node.select_next_some() => {}
                    _ = redial.tick() => {
                        if let Some((addr, target)) = &dial
                            && dialer.connection_count(target) < 2
                        {
                            let _ = node.dial(addr.clone());
                        }
                    }
                    () = ct.cancelled() => return,
                }
            }
        });

        probe
    }

    async fn wait_for_connections(probe: &PeerProbeHandle, peer: &PeerId, want: usize) {
        tokio::time::timeout(StdDuration::from_secs(10), async {
            while probe.connection_count(peer) < want {
                tokio::time::sleep(StdDuration::from_millis(50)).await;
            }
        })
        .await
        .expect("nodes did not connect");
    }

    fn peers_args(enrs: Vec<String>, key_file: PathBuf, tcp_addr: String) -> TestPeersArgs {
        let mut args = no_source_peers_args();
        args.enrs = Some(enrs);
        args.private_key_file = key_file;
        args.p2p_tcp_addrs = vec![tcp_addr];
        args.load_test_duration = StdDuration::from_secs(2);
        args.direct_connection_timeout = StdDuration::from_secs(2);
        args
    }

    fn results_for<'a>(res: &'a TestCategoryResult, prefix: &str) -> &'a [TestResult] {
        res.targets
            .iter()
            .find(|(name, _)| name.starts_with(prefix))
            .map(|(_, results)| results.as_slice())
            .unwrap_or_else(|| panic!("no target {prefix}: {:?}", res.targets.keys()))
    }

    #[tokio::test]
    async fn probes_measure_a_connected_peer() {
        let (key_a, key_b) = (SecretKey::random(&mut OsRng), SecretKey::random(&mut OsRng));
        let cluster = parse_peers(&[enr(&key_a), enr(&key_b)]).unwrap();
        let (addr_a, addr_b) = (free_tcp_addr(), free_tcp_addr());
        let ct = CancellationToken::new();
        let _stop = ct.clone().drop_guard();

        let probe_a = start_node(key_a, &cluster, &addr_a, None, ct.clone()).await;
        let _probe_b = start_node(
            key_b,
            &cluster,
            &addr_b,
            Some((tcp_multiaddr(&addr_a, cluster[0].id), cluster[0].id)),
            ct.clone(),
        )
        .await;
        let peer_b = &cluster[1];
        wait_for_connections(&probe_a, &peer_b.id, 2).await;

        let rtt = probe_a.ping(peer_b.id).await.unwrap();
        assert!(!rtt.is_zero());

        assert_eq!(
            peer_ping_test(&probe_a, peer_b).await.verdict,
            TestVerdict::Ok
        );

        let measure = peer_ping_measure_test(&probe_a, peer_b).await;
        assert_eq!(measure.verdict, TestVerdict::Good, "{measure:?}");
        assert!(!measure.measurement.is_empty());

        let load = peer_ping_load_test(&probe_a, peer_b, "peer b", StdDuration::from_secs(2)).await;
        assert_eq!(load.verdict, TestVerdict::Good, "{load:?}");

        let direct =
            peer_direct_conn_test(&probe_a, peer_b, "peer b", StdDuration::from_secs(2)).await;
        assert_eq!(direct.verdict, TestVerdict::Ok, "{direct:?}");
    }

    #[tokio::test]
    async fn direct_conn_fails_without_direct_addresses() {
        let (key_a, key_b) = (SecretKey::random(&mut OsRng), SecretKey::random(&mut OsRng));
        let cluster = parse_peers(&[enr(&key_a), enr(&key_b)]).unwrap();
        let (addr_a, addr_b) = (free_tcp_addr(), free_tcp_addr());
        let ct = CancellationToken::new();
        let _stop = ct.clone().drop_guard();

        let probe_a = start_node(key_a, &cluster, &addr_a, None, ct.clone()).await;
        let _probe_b = start_node(key_b, &cluster, &addr_b, None, ct.clone()).await;
        let peer_b = &cluster[1];

        // Neither node dials, so identify never reports `b`'s addresses.
        let res = probe_a.dial_direct(peer_b.id).await;
        assert!(
            matches!(res, Err(probe::ProbeError::NoDirectAddrs)),
            "{res:?}"
        );

        let direct =
            peer_direct_conn_test(&probe_a, peer_b, "peer b", StdDuration::from_secs(2)).await;
        assert_eq!(direct.verdict, TestVerdict::Fail);
        assert_eq!(
            direct.error.message(),
            Some("no direct addresses known for peer")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ping_test_gives_up_on_unreachable_peer() {
        let (key_a, key_dead) = (SecretKey::random(&mut OsRng), SecretKey::random(&mut OsRng));
        let cluster = parse_peers(&[enr(&key_a), enr(&key_dead)]).unwrap();
        let ct = CancellationToken::new();
        let _stop = ct.clone().drop_guard();
        let probe_a = start_node(key_a, &cluster, &free_tcp_addr(), None, ct.clone()).await;

        let started = tokio::time::Instant::now();
        let ping = peer_ping_test(&probe_a, &cluster[1]).await;

        assert_eq!(ping.verdict, TestVerdict::Fail);
        assert_eq!(ping.error.message(), Some("no connection to peer"));
        let elapsed = started.elapsed();
        assert!(
            elapsed >= PING_TEST_TIMEOUT
                && elapsed < PING_TEST_TIMEOUT.saturating_add(PING_RETRY_INTERVAL),
            "{elapsed:?}"
        );
    }

    #[tokio::test]
    async fn run_measures_a_reachable_peer() {
        let (key_a, key_b) = (SecretKey::random(&mut OsRng), SecretKey::random(&mut OsRng));
        let enrs = vec![enr(&key_a), enr(&key_b)];
        let cluster = parse_peers(&enrs).unwrap();
        let (addr_a, addr_b) = (free_tcp_addr(), free_tcp_addr());
        let ct = CancellationToken::new();
        let _stop = ct.clone().drop_guard();

        let key_file = tempfile::tempdir().unwrap();
        let key_path = key_file.path().join("key");
        pluto_k1util::save(&key_a, &key_path).unwrap();

        let _probe_b = start_node(
            key_b,
            &cluster,
            &addr_b,
            Some((tcp_multiaddr(&addr_a, cluster[0].id), cluster[0].id)),
            ct.clone(),
        )
        .await;

        let args = peers_args(enrs, key_path, addr_a);
        let mut output = Vec::new();
        let res = run(args, &mut output, ct.clone()).await.unwrap();

        let peer = results_for(&res, &format!("peer {}", cluster[1].name));
        let verdicts: Vec<_> = peer.iter().map(|r| (r.name.as_str(), r.verdict)).collect();
        assert_eq!(
            verdicts,
            [
                ("Ping", TestVerdict::Ok),
                ("PingMeasure", TestVerdict::Good),
                ("PingLoad", TestVerdict::Good),
                ("DirectConn", TestVerdict::Ok),
            ],
            "{peer:?}"
        );
        let self_results = results_for(&res, "self");
        assert_eq!(self_results[0].verdict, TestVerdict::Ok, "{self_results:?}");
        assert!(!output.is_empty());
    }

    #[tokio::test]
    async fn run_fails_a_dead_peer_within_test_timeouts() {
        let (key_a, key_dead) = (SecretKey::random(&mut OsRng), SecretKey::random(&mut OsRng));
        let enrs = vec![enr(&key_a), enr(&key_dead)];
        let dead_name = parse_peers(&enrs).unwrap()[1].name.clone();

        let key_file = tempfile::tempdir().unwrap();
        let key_path = key_file.path().join("key");
        pluto_k1util::save(&key_a, &key_path).unwrap();

        // Ping alone would retry for a minute; the rest are bounded by the
        // short load and direct-connection durations.
        let mut args = peers_args(enrs, key_path, free_tcp_addr());
        args.test_config.test_cases = Some(
            ["PingMeasure", "PingLoad", "DirectConn"]
                .map(String::from)
                .to_vec(),
        );

        let started = tokio::time::Instant::now();
        let mut output = Vec::new();
        let res = run(args, &mut output, CancellationToken::new())
            .await
            .unwrap();
        assert!(started.elapsed() < StdDuration::from_secs(15));

        let peer = results_for(&res, &format!("peer {dead_name}"));
        assert_eq!(peer.len(), 3);
        assert!(
            peer.iter().all(|r| r.verdict == TestVerdict::Fail),
            "{peer:?}"
        );
    }
}
