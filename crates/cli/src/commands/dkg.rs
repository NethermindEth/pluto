//! DKG command implementation.

use std::{future::Future, path::PathBuf};

use crate::{
    commands::common::{ConsoleColor, LICENSE, build_console_tracing_config, parse_relay_addr},
    duration::Duration,
    error::{CliError, Result},
};
use libp2p::multiaddr::Protocol;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Arguments for the `dkg` command.
#[derive(clap::Args, Clone, Debug)]
pub struct DkgArgs {
    #[arg(
        long = "data-dir",
        env = "CHARON_DATA_DIR",
        default_value = ".charon",
        help = "The directory where charon will store all its internal data."
    )]
    pub data_dir: PathBuf,

    #[arg(
        long = "definition-file",
        env = "CHARON_DEFINITION_FILE",
        default_value = ".charon/cluster-definition.json",
        help = "The path to the cluster definition file or an HTTP URL."
    )]
    pub definition_file: String,

    #[arg(
        long = "no-verify",
        env = "CHARON_NO_VERIFY",
        default_value_t = false,
        help = "Disables cluster definition and lock file verification."
    )]
    pub no_verify: bool,

    #[arg(
        long = "keymanager-address",
        env = "CHARON_KEYMANAGER_ADDRESS",
        default_value = "",
        help = "The keymanager URL to import validator keyshares."
    )]
    pub keymanager_address: String,

    #[arg(
        long = "keymanager-auth-token",
        env = "CHARON_KEYMANAGER_AUTH_TOKEN",
        default_value = "",
        help = "Authentication bearer token to interact with keymanager API. Don't include the \"Bearer\" symbol, only include the api-token."
    )]
    pub keymanager_auth_token: String,

    #[command(flatten)]
    pub p2p: DkgP2PArgs,

    #[command(flatten)]
    pub log: DkgLogArgs,

    #[arg(
        long = "publish-address",
        env = "CHARON_PUBLISH_ADDRESS",
        default_value = "https://api.obol.tech/v1",
        help = "The URL to publish the cluster to."
    )]
    pub publish_address: String,

    #[arg(
        long = "publish-timeout",
        env = "CHARON_PUBLISH_TIMEOUT",
        default_value = "30s",
        help = "Timeout for publishing a cluster, consider increasing if the cluster contains more than 200 validators."
    )]
    pub publish_timeout: Duration,

    #[arg(
        long = "publish",
        env = "CHARON_PUBLISH",
        default_value_t = false,
        help = "Publish the created cluster to a remote API."
    )]
    pub publish: bool,

    #[arg(
        long = "shutdown-delay",
        env = "CHARON_SHUTDOWN_DELAY",
        default_value = "1s",
        help = "Graceful shutdown delay."
    )]
    pub shutdown_delay: Duration,

    #[arg(
        long = "execution-client-rpc-endpoint",
        env = "CHARON_EXECUTION_CLIENT_RPC_ENDPOINT",
        default_value = "",
        help = "The address of the execution engine JSON-RPC API."
    )]
    pub execution_client_rpc_endpoint: String,

    #[arg(
        long = "timeout",
        env = "CHARON_TIMEOUT",
        default_value = "1m0s",
        help = "Timeout for the DKG process, should be increased if DKG times out."
    )]
    pub timeout: Duration,

    #[arg(
        long = "zipped",
        env = "CHARON_ZIPPED",
        default_value_t = false,
        help = "Create a tar archive compressed with gzip of the target directory after creation."
    )]
    pub zipped: bool,
}

impl DkgArgs {
    /// Converts CLI arguments into the DKG crate configuration.
    pub fn into_config(self) -> Result<pluto_dkg::dkg::Config> {
        validate_p2p_args(&self.p2p)?;

        let tracing_config = build_console_tracing_config(self.log.level.clone(), &self.log.color);
        let p2p_config = {
            let mut relays = Vec::new();

            for relay in &self.p2p.relays {
                let multiaddr = parse_relay_addr(relay)?;

                if multiaddr.iter().any(|protocol| protocol == Protocol::Http) {
                    warn!(address = %relay, "Insecure relay address provided, not HTTPS");
                }

                relays.push(multiaddr);
            }

            pluto_p2p::config::P2PConfig {
                relays,
                external_ip: self.p2p.external_ip,
                external_host: self.p2p.external_host,
                tcp_addrs: self.p2p.tcp_addrs,
                udp_addrs: self.p2p.udp_addrs,
                disable_reuse_port: self.p2p.disable_reuseport,
            }
        };

        Ok(pluto_dkg::dkg::Config::builder()
            .def_file(self.definition_file)
            .no_verify(self.no_verify)
            .data_dir(self.data_dir)
            .p2p(p2p_config)
            .log(tracing_config)
            .keymanager(
                pluto_dkg::dkg::KeymanagerConfig::builder()
                    .address(self.keymanager_address)
                    .auth_token(self.keymanager_auth_token)
                    .build(),
            )
            .publish(
                pluto_dkg::dkg::PublishConfig::builder()
                    .address(self.publish_address)
                    .timeout(self.publish_timeout.into())
                    .enabled(self.publish)
                    .build(),
            )
            .shutdown_delay(self.shutdown_delay.into())
            .timeout(self.timeout.into())
            .execution_engine_addr(self.execution_client_rpc_endpoint)
            .zipped(self.zipped)
            .test_config(pluto_dkg::dkg::TestConfig::builder().build())
            .build())
    }
}

/// P2P arguments for the `dkg` command.
#[derive(clap::Args, Clone, Debug)]
pub struct DkgP2PArgs {
    #[arg(
        long = "p2p-relays",
        env = "CHARON_P2P_RELAYS",
        value_delimiter = ',',
        default_values_t = pluto_p2p::config::DEFAULT_RELAYS.map(String::from),
        help = "Comma-separated list of libp2p relay URLs or multiaddrs."
    )]
    pub relays: Vec<String>,

    #[arg(
        long = "p2p-external-ip",
        env = "CHARON_P2P_EXTERNAL_IP",
        help = "The IP address advertised by libp2p. This may be used to advertise an external IP."
    )]
    pub external_ip: Option<String>,

    #[arg(
        long = "p2p-external-hostname",
        env = "CHARON_P2P_EXTERNAL_HOSTNAME",
        help = "The DNS hostname advertised by libp2p. This may be used to advertise an external DNS."
    )]
    pub external_host: Option<String>,

    #[arg(
        long = "p2p-tcp-address",
        env = "CHARON_P2P_TCP_ADDRESS",
        value_delimiter = ',',
        help = "Comma-separated list of listening TCP addresses (ip and port) for libP2P traffic. Empty default doesn't bind to local port therefore only supports outgoing connections."
    )]
    pub tcp_addrs: Vec<String>,

    #[arg(
        long = "p2p-udp-address",
        env = "CHARON_P2P_UDP_ADDRESS",
        value_delimiter = ',',
        help = "Comma-separated list of listening UDP addresses (ip and port) for libP2P traffic. Empty default doesn't bind to local port therefore only supports outgoing connections."
    )]
    pub udp_addrs: Vec<String>,

    #[arg(
        long = "p2p-disable-reuseport",
        env = "CHARON_P2P_DISABLE_REUSEPORT",
        default_value_t = false,
        help = "Disables TCP port reuse for outgoing libp2p connections."
    )]
    pub disable_reuseport: bool,
}

/// Logging arguments for the `dkg` command.
#[derive(clap::Args, Clone, Debug)]
pub struct DkgLogArgs {
    #[arg(
        long = "log-format",
        env = "CHARON_LOG_FORMAT",
        default_value = "console",
        help = "Log format; console, logfmt or json"
    )]
    pub format: String,

    #[arg(
        long = "log-level",
        env = "CHARON_LOG_LEVEL",
        default_value = "info",
        help = "Log level; debug, info, warn or error"
    )]
    pub level: String,

    #[arg(
        long = "log-color",
        env = "CHARON_LOG_COLOR",
        default_value = "auto",
        help = "Log color; auto, force, disable."
    )]
    pub color: ConsoleColor,

    #[arg(
        long = "log-output-path",
        env = "CHARON_LOG_OUTPUT_PATH",
        help = "Path in which to write on-disk logs."
    )]
    pub log_output_path: Option<PathBuf>,
}

/// Runs the `dkg` command from an already-built configuration.
pub async fn run(config: pluto_dkg::dkg::Config, ct: CancellationToken) -> Result<()> {
    run_with_runner(config, ct, pluto_dkg::dkg::run).await
}

async fn run_with_runner<Runner, Fut>(
    config: pluto_dkg::dkg::Config,
    ct: CancellationToken,
    runner: Runner,
) -> Result<()>
where
    Runner: FnOnce(pluto_dkg::dkg::Config, CancellationToken) -> Fut,
    Fut: Future<Output = std::result::Result<(), pluto_dkg::dkg::DkgError>>,
{
    info!("{LICENSE}");

    runner(config, ct).await.map_err(Into::into)
}

fn validate_p2p_args(args: &DkgP2PArgs) -> Result<()> {
    if let Some(host) = &args.external_host {
        url::Host::parse(host)
            .map_err(|err| CliError::Other(format!("invalid hostname: {host}: {err}")))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};
    use clap::Parser;
    use libp2p::{Multiaddr, multiaddr};
    use std::{str::FromStr, sync::Arc, time::Duration as StdDuration};

    #[test]
    fn dkg_is_registered_as_top_level_subcommand() {
        let cli = Cli::try_parse_from(["pluto", "dkg"]).expect("dkg command should parse");

        match cli.command {
            Commands::Dkg(_) => {}
            _ => panic!("expected dkg command"),
        }
    }

    #[test]
    fn dkg_defaults_match_go() {
        let cli = Cli::try_parse_from(["pluto", "dkg"]).expect("dkg command should parse");

        let Commands::Dkg(args) = cli.command else {
            panic!("expected dkg command");
        };
        let args = *args;

        assert_eq!(args.data_dir, PathBuf::from(".charon"));
        assert_eq!(args.definition_file, ".charon/cluster-definition.json");
        assert!(!args.no_verify);
        assert_eq!(args.timeout, Duration::new(StdDuration::from_secs(60)));
        assert_eq!(
            args.publish_timeout,
            Duration::new(StdDuration::from_secs(30))
        );
        assert_eq!(
            args.shutdown_delay,
            Duration::new(StdDuration::from_secs(1))
        );
        assert_eq!(args.publish_address, "https://api.obol.tech/v1");
        assert!(!args.publish);
        assert!(!args.zipped);
        assert_eq!(
            args.p2p.relays,
            pluto_p2p::config::DEFAULT_RELAYS.map(String::from).to_vec(),
        );
        assert_eq!(args.log.level, "info");
        assert_eq!(args.log.format, "console");
    }

    #[test]
    fn invalid_duration_fails_during_parse() {
        let err = match Cli::try_parse_from(["pluto", "dkg", "--timeout=not-a-duration"]) {
            Ok(_) => panic!("invalid duration should fail"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn dkg_args_expose_expected_env_bindings() {
        use clap::CommandFactory;

        let command = Cli::command();
        let dkg = command
            .get_subcommands()
            .find(|subcommand| subcommand.get_name() == "dkg")
            .expect("dkg subcommand should exist");

        let expected = [
            ("data-dir", "CHARON_DATA_DIR"),
            ("definition-file", "CHARON_DEFINITION_FILE"),
            ("no-verify", "CHARON_NO_VERIFY"),
            ("keymanager-address", "CHARON_KEYMANAGER_ADDRESS"),
            ("keymanager-auth-token", "CHARON_KEYMANAGER_AUTH_TOKEN"),
            ("p2p-relays", "CHARON_P2P_RELAYS"),
            ("log-level", "CHARON_LOG_LEVEL"),
            ("publish", "CHARON_PUBLISH"),
            ("publish-timeout", "CHARON_PUBLISH_TIMEOUT"),
            ("timeout", "CHARON_TIMEOUT"),
        ];

        for (arg_name, env_name) in expected {
            let arg = dkg
                .get_arguments()
                .find(|arg| arg.get_long() == Some(arg_name))
                .unwrap_or_else(|| panic!("missing argument: {arg_name}"));

            let actual = arg
                .get_env()
                .map(|value| value.to_string_lossy().into_owned());
            assert_eq!(actual.as_deref(), Some(env_name));
        }
    }

    #[test]
    fn config_mapping_preserves_fields() {
        let cli = Cli::try_parse_from([
            "pluto",
            "dkg",
            "--data-dir=/tmp/charon",
            "--definition-file=/tmp/definition.json",
            "--no-verify",
            "--keymanager-address=https://keymanager.example",
            "--keymanager-auth-token=token",
            "--p2p-relays=https://relay.one,/ip4/127.0.0.1/tcp/9000",
            "--p2p-external-ip=1.2.3.4",
            "--p2p-external-hostname=example.com",
            "--p2p-tcp-address=0.0.0.0:9000",
            "--p2p-udp-address=0.0.0.0:9000",
            "--p2p-disable-reuseport",
            "--log-format=json",
            "--log-level=debug",
            "--log-color=force",
            "--log-output-path=/tmp/pluto.log",
            "--publish",
            "--publish-address=https://api.example/v1",
            "--publish-timeout=40s",
            "--shutdown-delay=2s",
            "--execution-client-rpc-endpoint=http://127.0.0.1:8545",
            "--timeout=90s",
            "--zipped",
        ])
        .expect("dkg command should parse");

        let Commands::Dkg(args) = cli.command else {
            panic!("expected dkg command");
        };
        let args = *args;

        let config = args.into_config().expect("config should map");

        assert_eq!(config.data_dir, PathBuf::from("/tmp/charon"));
        assert_eq!(config.def_file, "/tmp/definition.json");
        assert!(config.no_verify);
        assert_eq!(config.keymanager.address, "https://keymanager.example");
        assert_eq!(config.keymanager.auth_token, "token");
        assert_eq!(
            config.p2p.relays,
            vec![
                multiaddr::from_url("https://relay.one").expect("relay url"),
                Multiaddr::from_str("/ip4/127.0.0.1/tcp/9000").expect("relay multiaddr")
            ]
        );
        assert_eq!(config.p2p.external_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(config.p2p.external_host.as_deref(), Some("example.com"));
        assert_eq!(config.p2p.tcp_addrs, vec!["0.0.0.0:9000".to_string()]);
        assert_eq!(config.p2p.udp_addrs, vec!["0.0.0.0:9000".to_string()]);
        assert!(config.p2p.disable_reuse_port);
        assert_eq!(config.log.override_env_filter.as_deref(), Some("debug"));
        let console = config.log.console.as_ref().expect("console config");
        assert!(console.with_ansi);
        assert!(config.publish.enabled);
        assert_eq!(config.publish.address, "https://api.example/v1");
        assert_eq!(config.publish.timeout, StdDuration::from_secs(40));
        assert_eq!(config.shutdown_delay, StdDuration::from_secs(2));
        assert_eq!(config.execution_engine_addr, "http://127.0.0.1:8545");
        assert_eq!(config.timeout, StdDuration::from_secs(90));
        assert!(config.zipped);
    }

    #[tokio::test]
    async fn run_passes_config_and_token_to_runner() {
        let cli = Cli::try_parse_from([
            "pluto",
            "dkg",
            "--log-level=debug",
            "--log-color=disable",
            "--log-format=json",
            "--log-output-path=/tmp/pluto.log",
        ])
        .expect("dkg command should parse");
        let Commands::Dkg(args) = cli.command else {
            panic!("expected dkg command");
        };
        let config = (*args).into_config().expect("config should map");

        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ct = CancellationToken::new();

        run_with_runner(config, ct.clone(), {
            let events = events.clone();
            move |config, token| async move {
                assert!(!token.is_cancelled());
                assert_eq!(config.def_file, ".charon/cluster-definition.json");
                assert_eq!(config.log.override_env_filter.as_deref(), Some("debug"));
                let console = config.log.console.as_ref().expect("console config");
                assert!(!console.with_ansi);
                events.lock().expect("lock").push("runner");
                Ok(())
            }
        })
        .await
        .expect("dkg run should succeed");

        assert_eq!(*events.lock().expect("lock"), vec!["runner"]);
    }
}
