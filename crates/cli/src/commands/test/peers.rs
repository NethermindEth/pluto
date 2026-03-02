//! Peer connectivity tests.

use std::{
    collections::HashMap,
    io::Write,
    net::{IpAddr, SocketAddr, TcpStream},
    time::Duration,
};

use clap::Args;
use libp2p::{Multiaddr, multiaddr};
use pluto_eth2util::enr::Record;
use pluto_p2p::peer::Peer;

use super::{
    TestCaseName, TestCategoryResult, TestConfigArgs, TestResult, TestVerdict,
    calculate_score, evaluate_highest_rtt, filter_tests, must_output_to_file_on_quiet,
    sort_tests, write_result_to_file, write_result_to_writer,
};
use crate::{
    duration::Duration as GoDuration,
    error::{CliError, Result},
};

/// Default relay addresses for peer connectivity tests.
const DEFAULT_RELAYS: [&str; 3] = [
    "https://0.relay.obol.tech",
    "https://2.relay.obol.dev",
    "https://1.relay.obol.tech",
];

/// RTT threshold for "average" verdict.
const PING_AVG_THRESHOLD: Duration = Duration::from_millis(200);
/// RTT threshold for "poor" verdict.
const PING_POOR_THRESHOLD: Duration = Duration::from_millis(1000);

/// Arguments for the peers test command.
#[derive(Args, Clone, Debug)]
pub struct TestPeersArgs {
    #[command(flatten)]
    /// Common test configuration options.
    pub test_config: TestConfigArgs,

    /// Comma-separated list of each peer ENR address.
    #[arg(
        long = "enrs",
        value_delimiter = ',',
        help = "[REQUIRED] Comma-separated list of each peer ENR address."
    )]
    pub enrs: Option<Vec<String>>,

    /// Time to keep running the load tests.
    #[arg(
        long = "load-test-duration",
        default_value = "5s",
        value_parser = humantime::parse_duration,
        help = "Time to keep running the load tests. For each second a new continuous ping instance is spawned."
    )]
    pub load_test_duration: Duration,

    /// Comma-separated list of libp2p relay URLs or multiaddrs.
    #[arg(
        long = "p2p-relays",
        value_delimiter = ',',
        default_values_t = DEFAULT_RELAYS.map(String::from),
        help = "Comma-separated list of libp2p relay URLs or multiaddrs."
    )]
    pub p2p_relays: Vec<String>,

    /// Comma-separated list of listening TCP addresses for libp2p traffic.
    #[arg(
        long = "p2p-tcp-address",
        value_delimiter = ',',
        help = "Comma-separated list of listening TCP addresses (ip and port) for libP2P traffic. Empty default doesn't bind to local port therefore only supports outgoing connections."
    )]
    pub p2p_tcp_address: Vec<String>,

    /// Disables TCP port reuse for outgoing libp2p connections.
    #[arg(
        long = "p2p-disable-reuseport",
        default_value_t = false,
        help = "Disables TCP port reuse for outgoing libp2p connections."
    )]
    pub p2p_disable_reuseport: bool,
}

/// Returns the supported peer test cases (executed once per peer).
///
/// The map keys are `TestCaseName` ordered by execution priority; the unit
/// value indicates dispatch is performed through `run_peer_test`.
pub(super) fn supported_peer_test_cases() -> HashMap<TestCaseName, ()> {
    [
        TestCaseName::new("Ping", 1),
        TestCaseName::new("PingMeasure", 2),
        TestCaseName::new("PingLoad", 3),
        TestCaseName::new("DirectConn", 4),
        TestCaseName::new("Libp2pTCPPortOpen", 5),
    ]
    .into_iter()
    .map(|name| (name, ()))
    .collect()
}

/// Returns the supported self test cases (executed once, independent of peers).
pub(super) fn supported_self_test_cases() -> HashMap<TestCaseName, ()> {
    HashMap::new()
}

/// Dispatches a named peer test and returns the result.
async fn run_peer_test(name: &str, peer: Peer) -> TestResult {
    match name {
        "Ping" => test_ping(peer).await,
        "PingMeasure" => test_ping_measure(peer).await,
        "PingLoad" => test_ping_load(peer).await,
        "DirectConn" => test_direct_conn(peer).await,
        "Libp2pTCPPortOpen" => test_libp2p_tcp_port_open(peer).await,
        other => {
            TestResult::new(other).fail(CliError::Other(format!("unsupported test case: {other}")))
        }
    }
}

/// Pings a peer to verify basic connectivity.
async fn test_ping(peer: Peer) -> TestResult {
    let result = TestResult::new("Ping");
    // Full libp2p swarm setup is needed for an actual ping; marked as skipped
    // until swarm integration is available.
    let _peer = peer;
    TestResult {
        verdict: TestVerdict::Skip,
        ..result
    }
}

/// Measures round-trip time to a peer.
async fn test_ping_measure(peer: Peer) -> TestResult {
    let result = TestResult::new("PingMeasure");
    let _peer = peer;
    TestResult {
        verdict: TestVerdict::Skip,
        ..result
    }
}

/// Runs a load test by pinging a peer repeatedly.
async fn test_ping_load(peer: Peer) -> TestResult {
    let result = TestResult::new("PingLoad");
    let _peer = peer;
    TestResult {
        verdict: TestVerdict::Skip,
        ..result
    }
}

/// Tests a direct TCP connection to a peer.
async fn test_direct_conn(peer: Peer) -> TestResult {
    let result = TestResult::new("DirectConn");
    let ip = match peer.addresses.first().and_then(|a| extract_ip_from_multiaddr(a)) {
        Some(ip) => ip,
        None => {
            return TestResult {
                verdict: TestVerdict::Skip,
                ..result
            };
        }
    };
    let port = match peer
        .addresses
        .first()
        .and_then(|a| extract_tcp_port_from_multiaddr(a))
    {
        Some(port) => port,
        None => {
            return TestResult {
                verdict: TestVerdict::Skip,
                ..result
            };
        }
    };

    let addr = SocketAddr::new(ip, port);
    let start = std::time::Instant::now();
    match tokio::task::spawn_blocking(move || {
        TcpStream::connect_timeout(&addr, Duration::from_secs(5))
    })
    .await
    {
        Ok(Ok(_)) => {
            let rtt = start.elapsed();
            evaluate_highest_rtt(vec![rtt], result, PING_AVG_THRESHOLD, PING_POOR_THRESHOLD)
        }
        Ok(Err(e)) => result.fail(e),
        Err(e) => result.fail(CliError::Other(format!("spawn_blocking: {e}"))),
    }
}

/// Tests that the libp2p TCP port is reachable from the network.
async fn test_libp2p_tcp_port_open(peer: Peer) -> TestResult {
    let result = TestResult::new("Libp2pTCPPortOpen");
    let _peer = peer;
    TestResult {
        verdict: TestVerdict::Skip,
        ..result
    }
}

/// Parses ENR strings into [`Peer`] objects.
pub(super) fn parse_peers(enrs: &[String]) -> Result<Vec<Peer>> {
    enrs.iter()
        .enumerate()
        .map(|(i, enr_str)| {
            let record = Record::try_from(enr_str.as_str()).map_err(|e| {
                CliError::Other(format!("failed to parse ENR at index {i}: {e}"))
            })?;
            Peer::from_enr(&record, i).map_err(|e| {
                CliError::Other(format!("failed to create peer from ENR at index {i}: {e}"))
            })
        })
        .collect()
}

/// Parses relay address strings into [`Multiaddr`] values.
pub(super) fn parse_relays(relays: &[String]) -> Result<Vec<Multiaddr>> {
    relays
        .iter()
        .map(|r| {
            multiaddr::from_url(r)
                .or_else(|_| r.parse::<Multiaddr>())
                .map_err(CliError::InvalidMultiaddr)
        })
        .collect()
}

/// Extracts the IP address component from a [`Multiaddr`].
fn extract_ip_from_multiaddr(addr: &Multiaddr) -> Option<IpAddr> {
    use libp2p::multiaddr::Protocol;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
            _ => {}
        }
    }
    None
}

/// Extracts the TCP port component from a [`Multiaddr`].
fn extract_tcp_port_from_multiaddr(addr: &Multiaddr) -> Option<u16> {
    use libp2p::multiaddr::Protocol;
    for proto in addr.iter() {
        if let Protocol::Tcp(port) = proto {
            return Some(port);
        }
    }
    None
}

/// Returns a human-readable label for a peer, used as the test target name.
fn peer_target_name(peer: &Peer) -> String {
    peer.name.clone()
}

/// Runs the peer connectivity tests.
pub async fn run(args: TestPeersArgs, writer: &mut dyn Write) -> Result<TestCategoryResult> {
    must_output_to_file_on_quiet(args.test_config.quiet, &args.test_config.output_json)?;

    let enrs = args.enrs.as_deref().unwrap_or_default();
    let peers = parse_peers(enrs)?;
    let _relays = parse_relays(&args.p2p_relays)?;

    let peer_cases = supported_peer_test_cases();

    let mut result = TestCategoryResult::new(super::TestCategory::Peers);
    let start = std::time::Instant::now();

    // Run peer tests for each peer.
    let mut filtered_peer = filter_tests(&peer_cases, args.test_config.test_cases.as_deref());
    sort_tests(&mut filtered_peer);

    let mut all_peer_results: Vec<TestResult> = Vec::new();
    for peer in &peers {
        let mut peer_results: Vec<TestResult> = Vec::new();
        for case_name in &filtered_peer {
            let test_result = run_peer_test(&case_name.name, peer.clone()).await;
            peer_results.push(test_result.clone());
            all_peer_results.push(test_result);
        }
        let target = peer_target_name(peer);
        result.targets.insert(target, peer_results);
    }

    result.score = Some(calculate_score(&all_peer_results));
    result.execution_time = Some(GoDuration::new(start.elapsed()));

    if !args.test_config.quiet {
        write_result_to_writer(&result, writer)?;
    }

    if !args.test_config.output_json.is_empty() {
        let path = std::path::Path::new(&args.test_config.output_json);
        write_result_to_file(&result, path).await?;
    }

    if args.test_config.publish {
        // TODO: Implement publishing to Obol API
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        path::PathBuf,
        time::Duration,
    };

    use libp2p::Multiaddr;

    use crate::commands::test::{
        CategoryScore, TestCategory, TestCategoryResult, TestConfigArgs, TestResult,
        TestResultError, TestVerdict, calculate_score, filter_tests,
    };

    use super::{
        DEFAULT_RELAYS, TestPeersArgs, extract_ip_from_multiaddr, extract_tcp_port_from_multiaddr,
        parse_peers, parse_relays, run, supported_peer_test_cases, supported_self_test_cases,
    };

    fn make_test_config() -> TestConfigArgs {
        TestConfigArgs {
            output_json: String::new(),
            quiet: false,
            test_cases: None,
            timeout: Duration::from_secs(3600),
            publish: false,
            publish_addr: "https://api.obol.tech/v1".to_string(),
            publish_private_key_file: PathBuf::from(".charon/charon-enr-private-key"),
        }
    }

    #[test]
    fn supported_peer_test_cases_names() {
        let cases = supported_peer_test_cases();
        let mut names: Vec<String> = cases.keys().map(|k| k.name.clone()).collect();
        names.sort();

        assert_eq!(
            names,
            vec!["DirectConn", "Libp2pTCPPortOpen", "Ping", "PingLoad", "PingMeasure"]
        );
    }

    #[test]
    fn supported_peer_test_cases_ordered() {
        let cases = supported_peer_test_cases();
        let mut keys: Vec<_> = cases.keys().collect();
        keys.sort_by_key(|k| k.order);

        let ordered_names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
        assert_eq!(
            ordered_names,
            vec!["Ping", "PingMeasure", "PingLoad", "DirectConn", "Libp2pTCPPortOpen"]
        );
    }

    #[test]
    fn supported_self_test_cases_empty() {
        assert!(supported_self_test_cases().is_empty());
    }

    #[test]
    fn filter_peer_test_cases_all() {
        let cases = supported_peer_test_cases();
        let filtered = filter_tests(&cases, None);
        assert_eq!(filtered.len(), cases.len());
    }

    #[test]
    fn filter_peer_test_cases_subset() {
        let cases = supported_peer_test_cases();
        let test_names = vec!["Ping".to_string(), "PingMeasure".to_string()];
        let filtered = filter_tests(&cases, Some(&test_names));
        assert_eq!(filtered.len(), 2);

        let mut names: Vec<String> = filtered.iter().map(|k| k.name.clone()).collect();
        names.sort();
        assert_eq!(names, vec!["Ping", "PingMeasure"]);
    }

    #[test]
    fn filter_peer_test_cases_empty_subset() {
        let cases = supported_peer_test_cases();
        let filtered = filter_tests(&cases, Some(&[]));
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_peer_test_cases_unknown_test() {
        let cases = supported_peer_test_cases();
        let test_names = vec!["UnknownTest".to_string()];
        let filtered = filter_tests(&cases, Some(&test_names));
        assert!(filtered.is_empty());
    }

    #[test]
    fn parse_peers_empty() {
        let peers = parse_peers(&[]).expect("should succeed with empty list");
        assert!(peers.is_empty());
    }

    #[test]
    fn parse_peers_invalid_enr() {
        let result = parse_peers(&["not-an-enr".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_peers_valid_enr() {
        // Known valid ENR taken from the eth2util ENR tests.
        let enr = "enr:-Iu4QJyserRukhG0Vgi2csu7GjpHYUGufNEbZ8Q7ZBrcZUb0KqpL5QzHonkh1xxHlxatTxrIcX_IS5J3SEWR_sa0ptGAgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMAUgEqczOjevyculnUIofhCj0DkgJudErM7qCYIvIkzIN0Y3CCDhqDdWRwgg4u".to_string();
        let peers = parse_peers(&[enr]).expect("should parse valid ENR");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].index, 0);
    }

    #[test]
    fn parse_peers_multiple_enrs() {
        let enr1 = "enr:-Iu4QJyserRukhG0Vgi2csu7GjpHYUGufNEbZ8Q7ZBrcZUb0KqpL5QzHonkh1xxHlxatTxrIcX_IS5J3SEWR_sa0ptGAgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMAUgEqczOjevyculnUIofhCj0DkgJudErM7qCYIvIkzIN0Y3CCDhqDdWRwgg4u".to_string();
        let enr2 = "enr:-HW4QEp-BLhP30tqTGFbR9n2PdUKWP9qc0zphIRmn8_jpm4BYkgekztXQaPA_znRW8RvNYHo0pUwyPEwUGGeZu26XlKAgmlkgnY0iXNlY3AyNTZrMaEDG4TFVnsSZECZXT7VqroFZdceGDRgSBn_nBf16dXdB48".to_string();
        let peers = parse_peers(&[enr1, enr2]).expect("should parse both ENRs");
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].index, 0);
        assert_eq!(peers[1].index, 1);
    }

    #[test]
    fn parse_relays_empty() {
        let relays = parse_relays(&[]).expect("should succeed with empty list");
        assert!(relays.is_empty());
    }

    #[test]
    fn parse_relays_invalid() {
        let result = parse_relays(&["not-a-relay".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_relays_valid_https() {
        let relays = parse_relays(&["https://0.relay.obol.tech".to_string()])
            .expect("should parse https relay URL");
        assert_eq!(relays.len(), 1);
    }

    #[test]
    fn extract_ip_from_multiaddr_ipv4() {
        let addr: Multiaddr = "/ip4/192.168.1.1/tcp/3610".parse().expect("valid multiaddr");
        let ip = extract_ip_from_multiaddr(&addr);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn extract_ip_from_multiaddr_missing() {
        let addr: Multiaddr = "/dns4/example.com/tcp/3610".parse().expect("valid multiaddr");
        let ip = extract_ip_from_multiaddr(&addr);
        assert_eq!(ip, None);
    }

    #[test]
    fn extract_tcp_port_from_multiaddr_valid() {
        let addr: Multiaddr = "/ip4/192.168.1.1/tcp/3610".parse().expect("valid multiaddr");
        let port = extract_tcp_port_from_multiaddr(&addr);
        assert_eq!(port, Some(3610));
    }

    #[test]
    fn extract_tcp_port_from_multiaddr_no_tcp() {
        let addr: Multiaddr = "/ip4/192.168.1.1/udp/3610/quic-v1"
            .parse()
            .expect("valid multiaddr");
        let port = extract_tcp_port_from_multiaddr(&addr);
        assert_eq!(port, None);
    }

    #[test]
    fn peers_score_all_skip() {
        let results = vec![
            TestResult {
                name: "Ping".to_string(),
                verdict: TestVerdict::Skip,
                measurement: String::new(),
                suggestion: String::new(),
                error: TestResultError::empty(),
                is_acceptable: false,
            },
            TestResult {
                name: "PingMeasure".to_string(),
                verdict: TestVerdict::Skip,
                measurement: String::new(),
                suggestion: String::new(),
                error: TestResultError::empty(),
                is_acceptable: false,
            },
        ];
        assert_eq!(calculate_score(&results), CategoryScore::A);
    }

    #[test]
    fn peers_score_all_good() {
        let results = vec![
            TestResult {
                name: "Ping".to_string(),
                verdict: TestVerdict::Good,
                measurement: String::new(),
                suggestion: String::new(),
                error: TestResultError::empty(),
                is_acceptable: false,
            },
            TestResult {
                name: "PingMeasure".to_string(),
                verdict: TestVerdict::Good,
                measurement: String::new(),
                suggestion: String::new(),
                error: TestResultError::empty(),
                is_acceptable: false,
            },
        ];
        assert_eq!(calculate_score(&results), CategoryScore::A);
    }

    #[test]
    fn peers_score_poor_gives_c() {
        let results = vec![TestResult {
            name: "DirectConn".to_string(),
            verdict: TestVerdict::Poor,
            measurement: String::new(),
            suggestion: String::new(),
            error: TestResultError::empty(),
            is_acceptable: false,
        }];
        assert_eq!(calculate_score(&results), CategoryScore::C);
    }

    #[test]
    fn peers_test_category_name() {
        let result = TestCategoryResult::new(TestCategory::Peers);
        assert_eq!(result.category_name, Some(TestCategory::Peers));
        assert!(result.targets.is_empty());
        assert!(result.score.is_none());
    }

    #[tokio::test]
    async fn run_peers_no_enrs() {
        let args = TestPeersArgs {
            test_config: make_test_config(),
            enrs: None,
            load_test_duration: Duration::from_secs(5),
            p2p_relays: DEFAULT_RELAYS.map(String::from).to_vec(),
            p2p_tcp_address: vec![],
            p2p_disable_reuseport: false,
        };

        let mut buf = Vec::new();
        let result = run(args, &mut buf)
            .await
            .expect("run should succeed with no ENRs");

        assert_eq!(result.category_name, Some(TestCategory::Peers));
        assert_eq!(result.score, Some(CategoryScore::A));
    }

    #[tokio::test]
    async fn run_peers_invalid_enr_returns_error() {
        let args = TestPeersArgs {
            test_config: make_test_config(),
            enrs: Some(vec!["not-a-valid-enr".to_string()]),
            load_test_duration: Duration::from_secs(5),
            p2p_relays: vec![],
            p2p_tcp_address: vec![],
            p2p_disable_reuseport: false,
        };

        let mut buf = Vec::new();
        let result = run(args, &mut buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_peers_quiet_without_output_json_returns_error() {
        let mut config = make_test_config();
        config.quiet = true;
        config.output_json = String::new();

        let args = TestPeersArgs {
            test_config: config,
            enrs: None,
            load_test_duration: Duration::from_secs(5),
            p2p_relays: vec![],
            p2p_tcp_address: vec![],
            p2p_disable_reuseport: false,
        };

        let mut buf = Vec::new();
        let result = run(args, &mut buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_peers_with_valid_enr_runs_all_cases() {
        let enr = "enr:-Iu4QJyserRukhG0Vgi2csu7GjpHYUGufNEbZ8Q7ZBrcZUb0KqpL5QzHonkh1xxHlxatTxrIcX_IS5J3SEWR_sa0ptGAgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMAUgEqczOjevyculnUIofhCj0DkgJudErM7qCYIvIkzIN0Y3CCDhqDdWRwgg4u".to_string();
        let args = TestPeersArgs {
            test_config: make_test_config(),
            enrs: Some(vec![enr]),
            load_test_duration: Duration::from_secs(5),
            p2p_relays: vec![],
            p2p_tcp_address: vec![],
            p2p_disable_reuseport: false,
        };

        let mut buf = Vec::new();
        let result = run(args, &mut buf)
            .await
            .expect("run should succeed with a valid ENR");

        assert_eq!(result.category_name, Some(TestCategory::Peers));
        assert_eq!(result.targets.len(), 1);
        let peer_results = result.targets.values().next().expect("one peer entry");
        assert_eq!(peer_results.len(), supported_peer_test_cases().len());
    }

    #[tokio::test]
    async fn run_peers_filtered_test_cases() {
        let enr = "enr:-Iu4QJyserRukhG0Vgi2csu7GjpHYUGufNEbZ8Q7ZBrcZUb0KqpL5QzHonkh1xxHlxatTxrIcX_IS5J3SEWR_sa0ptGAgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMAUgEqczOjevyculnUIofhCj0DkgJudErM7qCYIvIkzIN0Y3CCDhqDdWRwgg4u".to_string();
        let mut config = make_test_config();
        config.test_cases = Some(vec!["Ping".to_string()]);

        let args = TestPeersArgs {
            test_config: config,
            enrs: Some(vec![enr]),
            load_test_duration: Duration::from_secs(5),
            p2p_relays: vec![],
            p2p_tcp_address: vec![],
            p2p_disable_reuseport: false,
        };

        let mut buf = Vec::new();
        let result = run(args, &mut buf)
            .await
            .expect("run should succeed with filtered test cases");

        let peer_results = result.targets.values().next().expect("one peer entry");
        assert_eq!(peer_results.len(), 1);
        assert_eq!(peer_results[0].name, "Ping");
    }

    #[tokio::test]
    async fn run_peers_writes_output_to_buffer() {
        let args = TestPeersArgs {
            test_config: make_test_config(),
            enrs: None,
            load_test_duration: Duration::from_secs(5),
            p2p_relays: vec![],
            p2p_tcp_address: vec![],
            p2p_disable_reuseport: false,
        };

        let mut buf = Vec::new();
        run(args, &mut buf).await.expect("run should succeed");
        assert!(!buf.is_empty());
    }
}
