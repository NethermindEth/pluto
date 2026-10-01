//! Run all test categories.

use std::{io::Write, path::PathBuf, time::Duration};

use clap::Args;
use pluto_p2p::config::DEFAULT_RELAYS;
use tokio_util::sync::CancellationToken;

use super::{
    TestCategoryResult, TestConfigArgs, beacon::TestBeaconArgs, constants::SLOTS_IN_EPOCH,
    infra::TestInfraArgs, mev::TestMevArgs, peers::TestPeersArgs, validator::TestValidatorArgs,
    write_result_to_writer,
};
use crate::error::{CliError, Result};

/// Arguments for the all tests command.
///
/// Each category's own flags are prefixed with its name (`--beacon-endpoints`,
/// `--peers-enrs`, ...) as in Charon; the test and P2P flags are shared.
#[derive(Args, Clone, Debug)]
pub struct TestAllArgs {
    #[command(flatten)]
    pub test_config: TestConfigArgs,

    #[command(flatten)]
    pub peers: TestAllPeersArgs,

    #[command(flatten)]
    pub beacon: TestAllBeaconArgs,

    #[command(flatten)]
    pub validator: TestAllValidatorArgs,

    #[command(flatten)]
    pub mev: TestAllMevArgs,

    #[command(flatten)]
    pub infra: TestAllInfraArgs,
}

/// Peers flags of `alpha test all`, see [`TestPeersArgs`].
#[derive(Args, Clone, Debug)]
pub struct TestAllPeersArgs {
    /// [REQUIRED] Comma-separated list of each peer ENR address.
    #[expect(
        rustdoc::broken_intra_doc_links,
        reason = "doc comment doubles as clap help text, so the brackets must stay literal rather than becoming a rustdoc link"
    )]
    #[arg(long = "peers-enrs", value_delimiter = ',')]
    pub enrs: Option<Vec<String>>,

    /// Time to keep TCP node alive after test completion, so connection is open
    /// for other peers to test on their end.
    #[arg(
        long = "peers-keep-alive",
        default_value = "30m",
        value_parser = crate::duration::parse_go_duration
    )]
    pub keep_alive: Duration,

    /// Time to keep running the load tests in seconds. For each second a new
    /// continuous ping instance is spawned.
    #[arg(
        long = "peers-load-test-duration",
        id = "peers-load-test-duration",
        value_name = "LOAD_TEST_DURATION",
        default_value = "30s",
        value_parser = crate::duration::parse_go_duration
    )]
    pub load_test_duration: Duration,

    /// Time to keep trying to establish direct connection to peer.
    #[arg(
        long = "peers-direct-connection-timeout",
        default_value = "2m",
        value_parser = crate::duration::parse_go_duration
    )]
    pub direct_connection_timeout: Duration,

    /// The path to the cluster lock file defining the distributed validator
    /// cluster.
    #[arg(long = "peers-lock-file")]
    pub lock_file: Option<PathBuf>,

    /// The path to the charon enr private key file.
    #[arg(
        long = "peers-private-key-file",
        default_value = ".charon/charon-enr-private-key"
    )]
    pub private_key_file: PathBuf,

    /// The path to the cluster definition file or an HTTP URL.
    #[arg(long = "peers-definition-file")]
    pub definition_file: Option<String>,

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

/// Beacon flags of `alpha test all`, see [`TestBeaconArgs`].
#[derive(Args, Clone, Debug)]
pub struct TestAllBeaconArgs {
    #[arg(
        long = "beacon-endpoints",
        id = "beacon-endpoints",
        value_name = "ENDPOINTS",
        value_delimiter = ',',
        required = true,
        help = "Comma separated list of one or more beacon node endpoint URLs."
    )]
    pub endpoints: Vec<String>,

    #[arg(
        long = "beacon-load-test",
        id = "beacon-load-test",
        help = "Enable load test."
    )]
    pub load_test: bool,

    #[arg(
        long = "beacon-load-test-duration",
        id = "beacon-load-test-duration",
        value_name = "LOAD_TEST_DURATION",
        default_value = "5s",
        value_parser = crate::duration::parse_go_duration,
        help = "Time to keep running the load tests. For each second a new continuous ping instance is spawned."
    )]
    pub load_test_duration: Duration,

    #[arg(
        long = "beacon-simulation-duration-in-slots",
        default_value_t = SLOTS_IN_EPOCH.get(),
        help = "Time to keep running the simulation in slots."
    )]
    pub simulation_duration: u64,

    #[arg(
        long = "beacon-simulation-file-dir",
        default_value = "./",
        help = "Directory to write simulation result JSON files."
    )]
    pub simulation_file_dir: PathBuf,

    #[arg(
        long = "beacon-simulation-verbose",
        help = "Show results for each request and each validator."
    )]
    pub simulation_verbose: bool,

    #[arg(
        long = "beacon-simulation-custom",
        default_value_t = 0,
        help = "Run custom simulation with the specified amount of validators."
    )]
    pub simulation_custom: u64,
}

/// Validator flags of `alpha test all`, see [`TestValidatorArgs`].
#[derive(Args, Clone, Debug)]
pub struct TestAllValidatorArgs {
    // Charon prefixes the already prefixed flag, hence the doubled name.
    #[arg(
        long = "validator-validator-api-address",
        default_value = "127.0.0.1:3600",
        help = "Listening address (ip and port) for validator-facing traffic proxying the beacon-node API."
    )]
    pub api_address: String,

    #[arg(
        long = "validator-load-test-duration",
        id = "validator-load-test-duration",
        value_name = "LOAD_TEST_DURATION",
        default_value = "5s",
        value_parser = crate::duration::parse_go_duration,
        help = "Time to keep running the load tests. For each second a new continuous ping instance is spawned."
    )]
    pub load_test_duration: Duration,
}

/// MEV flags of `alpha test all`, see [`TestMevArgs`].
#[derive(Args, Clone, Debug)]
pub struct TestAllMevArgs {
    #[arg(
        long = "mev-endpoints",
        id = "mev-endpoints",
        value_name = "ENDPOINTS",
        value_delimiter = ',',
        required = true,
        help = "Comma separated list of one or more MEV relay endpoint URLs."
    )]
    pub endpoints: Vec<String>,

    #[arg(
        long = "mev-beacon-node-endpoint",
        help = "[REQUIRED] Beacon node endpoint URL used for block creation test."
    )]
    pub beacon_node_endpoint: Option<String>,

    #[arg(
        long = "mev-load-test",
        id = "mev-load-test",
        help = "Enable load test."
    )]
    pub load_test: bool,

    #[arg(
        long = "mev-number-of-payloads",
        default_value = "1",
        help = "Increases the accuracy of the load test by asking for multiple payloads. Increases test duration."
    )]
    pub number_of_payloads: u32,
}

/// Infra flags of `alpha test all`, see [`TestInfraArgs`].
#[derive(Args, Clone, Debug)]
pub struct TestAllInfraArgs {
    #[arg(
        long = "infra-disk-io-test-file-dir",
        help = "Directory at which disk performance will be measured. If none specified, current user's home directory will be used."
    )]
    pub disk_io_test_file_dir: Option<String>,

    #[arg(
        long = "infra-disk-io-block-size-kb",
        default_value = "4096",
        help = "The block size in kilobytes used for I/O units. Same value applies for both reads and writes."
    )]
    pub disk_io_block_size_kb: i32,

    #[arg(
        long = "infra-internet-test-servers-only",
        value_delimiter = ',',
        help = "List of specific server names to be included for the internet tests, the best performing one is chosen. If not provided, closest and best performing servers are chosen automatically."
    )]
    pub internet_test_servers_only: Vec<String>,

    #[arg(
        long = "infra-internet-test-servers-exclude",
        value_delimiter = ',',
        help = "List of server names to be excluded from the tests. To be specified only if you experience issues with a server that is wrongly considered best performing."
    )]
    pub internet_test_servers_exclude: Vec<String>,
}

impl TestAllArgs {
    /// Checks the shared test config, then rejects `--test-cases`, which
    /// cannot select tests across categories.
    pub(crate) fn validate(&self) -> Result<()> {
        self.test_config.validate()?;
        if self.test_config.test_cases.is_some() {
            return Err(CliError::Other(
                "test-cases cannot be specified when explicitly running all test cases."
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// The shared test config with `quiet` forced: results are printed
    /// together once every category has run.
    fn category_test_config(&self) -> TestConfigArgs {
        TestConfigArgs {
            quiet: true,
            ..self.test_config.clone()
        }
    }

    fn beacon_args(&self) -> TestBeaconArgs {
        let b = self.beacon.clone();
        TestBeaconArgs {
            test_config: self.category_test_config(),
            endpoints: b.endpoints,
            load_test: b.load_test,
            load_test_duration: b.load_test_duration,
            simulation_duration: b.simulation_duration,
            simulation_file_dir: b.simulation_file_dir,
            simulation_verbose: b.simulation_verbose,
            simulation_custom: b.simulation_custom,
        }
    }

    fn validator_args(&self) -> TestValidatorArgs {
        let v = self.validator.clone();
        TestValidatorArgs {
            test_config: self.category_test_config(),
            api_address: v.api_address,
            load_test_duration: v.load_test_duration,
        }
    }

    fn mev_args(&self) -> TestMevArgs {
        let m = self.mev.clone();
        TestMevArgs {
            test_config: self.category_test_config(),
            endpoints: m.endpoints,
            beacon_node_endpoint: m.beacon_node_endpoint,
            load_test: m.load_test,
            number_of_payloads: m.number_of_payloads,
        }
    }

    fn infra_args(&self) -> TestInfraArgs {
        let i = self.infra.clone();
        TestInfraArgs {
            test_config: self.category_test_config(),
            disk_io_test_file_dir: i.disk_io_test_file_dir,
            disk_io_block_size_kb: i.disk_io_block_size_kb,
            internet_test_servers_only: i.internet_test_servers_only,
            internet_test_servers_exclude: i.internet_test_servers_exclude,
        }
    }

    fn peers_args(&self) -> TestPeersArgs {
        let p = self.peers.clone();
        TestPeersArgs {
            test_config: self.category_test_config(),
            enrs: p.enrs,
            lock_file: p.lock_file,
            definition_file: p.definition_file,
            private_key_file: p.private_key_file,
            keep_alive: p.keep_alive,
            load_test_duration: p.load_test_duration,
            direct_connection_timeout: p.direct_connection_timeout,
            p2p_tcp_addrs: p.p2p_tcp_addrs,
            p2p_relays: p.p2p_relays,
            p2p_external_ip: p.p2p_external_ip,
            p2p_external_hostname: p.p2p_external_hostname,
            p2p_udp_addrs: p.p2p_udp_addrs,
            p2p_disable_reuseport: p.p2p_disable_reuseport,
        }
    }
}

/// Runs beacon, validator, MEV, infra and peers tests in order, then prints
/// all results unless `--quiet`.
pub async fn run(args: TestAllArgs, writer: &mut dyn Write, ct: CancellationToken) -> Result<()> {
    // Each category writes its own results to `--output-json` and publishes
    // them; only stdout output is deferred.
    let results: [TestCategoryResult; 5] = [
        super::beacon::run(args.beacon_args(), writer, ct.clone()).await?,
        super::validator::run(args.validator_args(), writer, ct.clone()).await?,
        super::mev::run(args.mev_args(), writer, ct.clone()).await?,
        super::infra::run(args.infra_args(), writer, ct.clone()).await?,
        super::peers::run(args.peers_args(), writer, ct).await?,
    ];

    if !args.test_config.quiet {
        for res in &results {
            write_result_to_writer(res, writer)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cli::{AlphaCommands, Cli, Commands, TestCommands},
        commands::test::{TestCategory, list_test_cases},
    };
    use clap::FromArgMatches as _;

    /// Parses `pluto alpha test <args>`.
    fn parse_test(args: &[&str]) -> TestCommands {
        let args = ["pluto", "alpha", "test"]
            .into_iter()
            .chain(args.iter().copied());
        let matches = crate::cli::build_command()
            .try_get_matches_from(args)
            .unwrap();
        match Cli::from_arg_matches(&matches).unwrap().command {
            Commands::Alpha(alpha) => match alpha.command {
                AlphaCommands::Test(test) => test.command,
            },
            _ => panic!("not the alpha command"),
        }
    }

    fn parse(extra: &[&str]) -> TestAllArgs {
        let args = [
            "all",
            "--beacon-endpoints=http://beacon",
            "--mev-endpoints=http://mev",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .collect::<Vec<_>>();
        match parse_test(&args) {
            TestCommands::All(args) => *args,
            _ => panic!("not the all command"),
        }
    }

    #[test]
    fn defaults_match_the_standalone_commands() {
        let all = parse(&[]);
        let standalone = parse_test;

        let TestCommands::Peers(mut peers) = standalone(&["peers"]) else {
            unreachable!()
        };
        let TestCommands::Beacon(mut beacon) = standalone(&["beacon", "--endpoints=http://beacon"])
        else {
            unreachable!()
        };
        let TestCommands::Validator(mut validator) = standalone(&["validator"]) else {
            unreachable!()
        };
        let TestCommands::Mev(mut mev) = standalone(&["mev", "--endpoints=http://mev"]) else {
            unreachable!()
        };
        let TestCommands::Infra(mut infra) = standalone(&["infra"]) else {
            unreachable!()
        };

        peers.test_config.quiet = true;
        beacon.test_config.quiet = true;
        validator.test_config.quiet = true;
        mev.test_config.quiet = true;
        infra.test_config.quiet = true;

        assert_eq!(format!("{:?}", all.peers_args()), format!("{peers:?}"));
        assert_eq!(format!("{:?}", all.beacon_args()), format!("{beacon:?}"));
        assert_eq!(
            format!("{:?}", all.validator_args()),
            format!("{validator:?}")
        );
        assert_eq!(format!("{:?}", all.mev_args()), format!("{mev:?}"));
        assert_eq!(format!("{:?}", all.infra_args()), format!("{infra:?}"));
    }

    #[test]
    fn command_definitions_are_valid() {
        crate::cli::build_command().debug_assert();
    }

    #[test]
    fn prefixed_flags_reach_their_category() {
        let args = parse(&[
            "--peers-load-test-duration=7s",
            "--beacon-load-test-duration=3s",
            "--validator-load-test-duration=2s",
            "--mev-load-test",
            "--timeout=10m",
        ]);

        assert_eq!(args.peers_args().load_test_duration, Duration::from_secs(7));
        assert_eq!(
            args.beacon_args().load_test_duration,
            Duration::from_secs(3)
        );
        assert!(!args.beacon_args().load_test);
        assert_eq!(
            args.validator_args().load_test_duration,
            Duration::from_secs(2)
        );
        assert!(args.mev_args().load_test);
        assert_eq!(args.mev_args().endpoints, ["http://mev"]);
        assert_eq!(args.beacon_args().endpoints, ["http://beacon"]);
    }

    #[test]
    fn categories_share_the_test_config_and_run_quiet() {
        let args = parse(&["--timeout=10m", "--output-json=out.json"]);
        assert!(!args.test_config.quiet);

        for config in [
            args.beacon_args().test_config,
            args.validator_args().test_config,
            args.mev_args().test_config,
            args.infra_args().test_config,
            args.peers_args().test_config,
        ] {
            assert!(config.quiet);
            assert_eq!(config.timeout, Duration::from_secs(600));
            assert_eq!(config.output_json, "out.json");
        }
    }

    #[test]
    fn explicit_test_cases_are_rejected() {
        let err = parse(&["--test-cases=Ping"]).validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("test-cases cannot be specified when explicitly running all test cases."),
            "{err}"
        );
        assert!(parse(&[]).validate().is_ok());
    }

    #[test]
    fn mev_flag_combinations_are_only_checked_standalone() {
        // Charon applies this check in the standalone `mev` command's
        // `PreRunE` only.
        assert!(parse(&["--mev-load-test"]).validate().is_ok());
        assert!(
            parse_test(&["mev", "--endpoints=http://mev", "--load-test"])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn quiet_requires_output_json() {
        assert!(parse(&["--quiet"]).validate().is_err());
        assert!(
            parse(&["--quiet", "--output-json=out.json"])
                .validate()
                .is_ok()
        );
    }

    /// `test all` arguments against unreachable endpoints, bounded by a short
    /// `--timeout` so every category finishes quickly.
    fn run_args(dir: &std::path::Path, extra: &[&str]) -> TestAllArgs {
        let key = k256::SecretKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let dead = k256::SecretKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        let key_file = dir.join("key");
        pluto_k1util::save(&key, &key_file).unwrap();
        let enrs = [&key, &dead]
            .map(|k| {
                pluto_eth2util::enr::Record::from_key(k)
                    .unwrap()
                    .to_string()
            })
            .join(",");

        let flags = [
            "all".to_string(),
            "--timeout=1s".to_string(),
            format!("--output-json={}", dir.join("out.json").display()),
            // Distinct ports tell the categories' targets apart.
            "--beacon-endpoints=http://127.0.0.1:1".to_string(),
            "--validator-validator-api-address=127.0.0.1:3".to_string(),
            "--mev-endpoints=http://127.0.0.1:2".to_string(),
            format!("--infra-disk-io-test-file-dir={}", dir.display()),
            format!("--peers-enrs={enrs}"),
            format!("--peers-private-key-file={}", key_file.display()),
            "--peers-keep-alive=0s".to_string(),
            "--p2p-relays=".to_string(),
        ];
        let args: Vec<&str> = flags
            .iter()
            .map(String::as_str)
            .chain(extra.iter().copied())
            .collect();
        match parse_test(&args) {
            TestCommands::All(args) => *args,
            _ => panic!("not the all command"),
        }
    }

    fn read_output_json(dir: &std::path::Path) -> super::super::AllCategoriesResult {
        serde_json::from_slice(&std::fs::read(dir.join("out.json")).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn run_prints_and_writes_every_category_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let args = run_args(dir.path(), &[]);
        args.validate().unwrap();

        let mut output = Vec::new();
        run(args, &mut output, CancellationToken::new())
            .await
            .unwrap();

        // Each category's target, in the order Charon runs them.
        let output = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output.lines().map(str::trim).collect();
        let positions: Vec<usize> = [
            "http://127.0.0.1:1",
            "127.0.0.1:3",
            "http://127.0.0.1:2",
            "local",
            "self",
        ]
        .iter()
        .map(|target| {
            lines
                .iter()
                .position(|l| l == target)
                .unwrap_or_else(|| panic!("{target} missing:\n{output}"))
        })
        .collect();
        assert!(positions.is_sorted(), "{positions:?}:\n{output}");

        let file = read_output_json(dir.path());
        let mev = file.mev.expect("mev results");
        assert!(file.beacon.is_some());
        assert!(file.validator.is_some());
        assert!(file.infra.is_some());
        assert!(file.peers.is_some());

        // Beacon's timeout must not cancel the categories that run after it.
        let mev_ping = &mev.targets["http://127.0.0.1:2"][0];
        assert_ne!(
            mev_ping.error.message(),
            Some(CliError::TimeoutInterrupted.to_string().as_str()),
            "{mev_ping:?}"
        );
    }

    #[tokio::test]
    async fn run_quiet_only_writes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let args = run_args(dir.path(), &["--quiet"]);
        args.validate().unwrap();

        let mut output = Vec::new();
        run(args, &mut output, CancellationToken::new())
            .await
            .unwrap();

        assert!(output.is_empty(), "{}", String::from_utf8_lossy(&output));
        let file = read_output_json(dir.path());
        assert!(
            file.beacon.is_some()
                && file.validator.is_some()
                && file.mev.is_some()
                && file.infra.is_some()
                && file.peers.is_some(),
            "{file:?}"
        );
    }

    #[test]
    fn all_lists_every_category() {
        let all = list_test_cases(TestCategory::All);
        for name in [
            "DirectConn",
            "Libp2pTCPPortOpen",
            "PingMeasureRelay",
            "CreateBlock",
        ] {
            assert!(all.iter().any(|n| n == name), "{name} missing: {all:?}");
        }
        for category in [
            TestCategory::Beacon,
            TestCategory::Validator,
            TestCategory::Infra,
        ] {
            let cases = list_test_cases(category);
            assert!(!cases.is_empty());
            assert!(cases.iter().all(|c| all.contains(c)));
        }
    }
}
