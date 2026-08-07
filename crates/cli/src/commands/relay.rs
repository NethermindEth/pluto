use crate::{
    commands::common::{ConsoleColor, LICENSE, build_console_tracing_config, parse_relay_addr},
    error::CliError,
};
use libp2p::multiaddr::Protocol;
use pluto_p2p::k1;
use std::{collections::HashMap, path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// Grace period given to the Loki background task to flush buffered logs
/// once `BackgroundTaskController::shutdown` has been signalled.
const LOKI_FLUSH_TIMEOUT: Duration = Duration::from_secs(3);

/// Arguments for the relay command.
#[derive(clap::Args, Clone)]
pub struct RelayArgs {
    #[clap(flatten)]
    pub data_dir: RelayDataDirArgs,

    #[clap(flatten)]
    pub relay: RelayRelayArgs,

    #[clap(flatten)]
    pub debug_monitoring: RelayDebugMonitoringArgs,

    #[clap(flatten)]
    pub p2p: RelayP2PArgs,

    #[clap(flatten)]
    pub log: RelayLogFlags,

    #[clap(flatten)]
    pub loki: RelayLokiArgs,
}

impl TryInto<pluto_relay_server::config::Config> for RelayArgs {
    type Error = CliError;

    fn try_into(self) -> std::result::Result<pluto_relay_server::config::Config, Self::Error> {
        let p2p_config = {
            let mut relays = Vec::new();

            for relay in &self.p2p.relays {
                let multiaddr = parse_relay_addr(relay)?;

                if multiaddr.iter().any(|protocol| protocol == Protocol::Http) {
                    tracing::warn!(
                      address = %relay,
                      "Insecure relay address provided, not HTTPS"
                    );
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

        let loki_config = match self.loki.loki_addresses.as_slice() {
            [] => None,
            [loki_url, rest @ ..] => {
                if !rest.is_empty() {
                    // Charon fans logs out to every entry in `loki-addresses`, but
                    // `pluto_tracing::TracingConfig` only supports a single Loki
                    // layer today. `tracing::warn!` would be a no-op here because
                    // no subscriber is installed yet (init happens later inside
                    // `commands::relay::run`), so write directly to stderr.
                    eprintln!(
                        "warning: {extra} additional --loki-addresses ignored; only the first is used",
                        extra = rest.len(),
                    );
                }

                let labels =
                    HashMap::from([("service".to_string(), self.loki.loki_service.clone())]);

                Some(pluto_tracing::LokiConfig {
                    loki_url: loki_url.clone(),
                    labels,
                    extra_fields: HashMap::new(),
                })
            }
        };

        let log_config =
            build_console_tracing_config(self.log.level.clone(), &self.log.color, loki_config);

        let builder = pluto_relay_server::config::Config::builder()
            .data_dir(self.data_dir.data_dir)
            .http_addr(self.relay.http_address)
            .auto_p2p_key(self.relay.auto_p2p_key)
            .libp2p_log_level(self.relay.p2p_relay_log_level)
            .max_res_per_peer(self.relay.max_res_per_peer)
            .max_conns(self.relay.max_conns)
            // Invert p2p-advertise-private-addresses flag boolean:
            // -- Do not ADVERTISE private addresses by default in the binary.
            // -- Do not FILTER private addresses in unit tests.
            .filter_private_addrs(!self.relay.advertise_priv)
            .maybe_monitoring_addr(self.debug_monitoring.monitor_addr)
            .maybe_debug_addr(self.debug_monitoring.debug_addr)
            .p2p_config(p2p_config)
            .log_config(log_config);

        Ok(builder.build())
    }
}

#[derive(clap::Args, Clone)]
pub struct RelayDataDirArgs {
    #[arg(
        long = "data-dir",
        env = "CHARON_DATA_DIR",
        default_value = ".charon",
        help = "The directory where pluto will store all its internal data."
    )]
    pub data_dir: PathBuf,
}

#[derive(clap::Args, Clone)]
pub struct RelayRelayArgs {
    #[arg(
        long = "http-address",
        env = "CHARON_HTTP_ADDRESS",
        default_value = "127.0.0.1:3640",
        help = "Listening address (ip and port) for the relay http server serving runtime ENR."
    )]
    pub http_address: String,

    #[arg(
        long = "auto-p2pkey",
        env = "CHARON_AUTO_P2PKEY",
        default_value_t = true,
        help = "Automatically generate and persist a p2p key if one does not exist."
    )]
    pub auto_p2p_key: bool,

    #[arg(
        long = "p2p-relay-loglevel",
        env = "CHARON_P2P_RELAY_LOGLEVEL",
        default_value = "",
        help = "Libp2p circuit relay log level. E.g., debug, info, warn, error."
    )]
    pub p2p_relay_log_level: String,

    // TODO: Check if https://github.com/libp2p/go-libp2p/issues/1713 is relevant for the Rust libp2p implementation
    // If so, decrease defaults after this has been addressed
    #[arg(
        long = "p2p-max-reservations",
        env = "CHARON_P2P_MAX_RESERVATIONS",
        default_value_t = 512,
        help = "Updates max circuit reservations per peer (each valid for 30min)"
    )]
    pub max_res_per_peer: usize,

    #[arg(
        long = "p2p-max-connections",
        env = "CHARON_P2P_MAX_CONNECTIONS",
        default_value_t = 16384,
        help = "Libp2p maximum number of peers that can connect to this relay."
    )]
    pub max_conns: usize,

    #[arg(
        long = "p2p-advertise-private-addresses",
        env = "CHARON_P2P_ADVERTISE_PRIVATE_ADDRESSES",
        help = "Enable advertising of libp2p auto-detected private addresses. This doesn't affect manually provided p2p-external-ip/hostname."
    )]
    pub advertise_priv: bool,
}

#[derive(clap::Args, Clone)]
pub struct RelayDebugMonitoringArgs {
    #[arg(
        long = "monitoring-address",
        env = "CHARON_MONITORING_ADDRESS",
        help = "Listening address (ip and port) for the monitoring API (prometheus)."
    )]
    pub monitor_addr: Option<String>,

    #[arg(
        long = "debug-address",
        env = "CHARON_DEBUG_ADDRESS",
        default_value = "",
        help = "Listening address (ip and port) for the pprof and QBFT debug API. It is not enabled by default."
    )]
    pub debug_addr: Option<String>,
}

#[derive(clap::Args, Clone)]
pub struct RelayP2PArgs {
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

#[derive(clap::Args, Clone)]
pub struct RelayLogFlags {
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

    #[arg(long = "log-color", default_value = "auto", help = "Log color")]
    pub color: ConsoleColor,

    #[arg(
        long = "log-output-path",
        env = "CHARON_LOG_OUTPUT_PATH",
        help = "Path in which to write on-disk logs."
    )]
    pub log_output_path: Option<PathBuf>,
}

#[derive(clap::Args, Clone)]
pub struct RelayLokiArgs {
    #[arg(
        long = "loki-addresses",
        env = "CHARON_LOKI_ADDRESSES",
        value_delimiter = ',',
        help = "Enables sending of logfmt structured logs to these Loki log aggregation server addresses. This is in addition to normal stderr logs."
    )]
    pub loki_addresses: Vec<String>,

    #[arg(
        long = "loki-service",
        env = "CHARON_LOKI_SERVICE",
        default_value = "pluto",
        help = "Service label sent with logs to Loki."
    )]
    pub loki_service: String,
}

pub async fn run(
    config: pluto_relay_server::config::Config,
    ct: CancellationToken,
) -> Result<(), CliError> {
    let loki_shutdown = match pluto_tracing::init(&config.log_config) {
        Ok(Some(loki)) => {
            let controller = loki.controller;
            let handle = tokio::spawn(loki.task);
            Some((controller, handle))
        }
        Ok(None) => None,
        // In tests, the global tracing subscriber is shared across runs in the
        // same process, so reinitializing fails. In production this would mean
        // the relay silently uses an unrelated subscriber and Loki forwarding
        // is dropped — fail loudly instead.
        #[cfg(test)]
        Err(pluto_tracing::init::Error::Init(_)) => None,
        Err(err) => return Err(err.into()),
    };

    // Run the relay in an inner scope so every early `?` / `return Err(..)` is
    // captured into `result` and the Loki cleanup below always runs.
    let result = serve_relay(&config, ct).await;

    if let Err(err) = &result {
        // Surface the shutdown reason through the subscriber so it reaches
        // Loki before we close the worker; `main` only `eprintln!`s the
        // returned error and that path bypasses the tracing subscriber.
        error!(error = %err, "relay exited with error");
    }

    // Drain the Loki worker under a single budget so a hung Loki endpoint
    // (e.g. `controller.shutdown` blocked on a full mpsc) cannot wedge
    // process exit. After the budget elapses we hard-abort the worker.
    if let Some((controller, handle)) = loki_shutdown {
        let abort_handle = handle.abort_handle();
        let _ = tokio::time::timeout(LOKI_FLUSH_TIMEOUT, async {
            controller.shutdown().await;
            let _ = handle.await;
        })
        .await;
        abort_handle.abort();
    }

    result
}

async fn serve_relay(
    config: &pluto_relay_server::config::Config,
    ct: CancellationToken,
) -> Result<(), CliError> {
    info!("{LICENSE}");
    info!(config = ?config);

    let key = load_or_create_key(config)?;

    pluto_relay_server::p2p::run_relay_p2p_node(config, key, ct)
        .await
        .map(|_| ())
        .map_err(Into::into)
}

/// Loads the relay's p2p key from its data dir, generating and persisting one
/// when it is missing and `--auto-p2pkey` is set.
fn load_or_create_key(
    config: &pluto_relay_server::config::Config,
) -> Result<k256::SecretKey, CliError> {
    let key = match pluto_p2p::k1::load_priv_key(&config.data_dir) {
        Ok(key) => Ok(key),
        Err(pluto_p2p::k1::K1Error::K1UtilError(pluto_k1util::K1UtilError::FailedToReadFile(
            io_err,
        ))) if io_err.kind() == std::io::ErrorKind::NotFound => {
            if !config.auto_p2p_key {
                error!(
                    "charon-enr-private-key not found in data dir (run with --auto-p2pkey to auto generate)."
                );
                let err = pluto_p2p::k1::K1Error::K1UtilError(
                    pluto_k1util::K1UtilError::FailedToReadFile(io_err),
                );
                return Err(pluto_relay_server::RelayP2PError::FailedToLoadPrivateKey(err).into());
            }

            let path = k1::key_path(&config.data_dir);
            info!(path = ?path, "Automatically creating charon-enr-private-key");

            k1::new_saved_priv_key(&config.data_dir)
        }
        e => e,
    }?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        path::Path,
        str::FromStr,
        sync::LazyLock,
        time::{Duration, Instant},
    };
    use tokio::{net, task::JoinHandle};
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn run_bootnode() {
        // Relay server starts with the existing p2p key.
        let _relay = test_relay_server_with(|args| {
            args.relay.auto_p2p_key = false;
            pluto_p2p::k1::new_saved_priv_key(&args.data_dir.data_dir).unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn run_bootnode_auto_p2p() {
        // Relay server does not start due to the missing p2p key.
        let missing_key = test_relay_server_with(|args| args.relay.auto_p2p_key = false).await;
        assert!(matches!(
            missing_key,
            Err(super::CliError::RelayP2PError(
                pluto_relay_server::RelayP2PError::FailedToLoadPrivateKey(..)
            ))
        ));

        // The success path — starting with an auto-generated key — is what
        // every other test here does, since `relay_args` sets
        // `auto_p2p_key`.
    }

    #[tokio::test]
    async fn run_exits_when_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let args = relay_args(dir.path());

        // Covers the CLI entry point that the fixture bypasses: tracing init and
        // the Loki drain. A pre-cancelled token is deterministic because the
        // shutdown arm of the serve loop is the `biased` first branch — the same
        // way charon's relay test starts (`cmd/relay/relay_internal_test.go:40`).
        let ct = CancellationToken::new();
        ct.cancel();

        super::run(args.try_into().unwrap(), ct).await.unwrap();
    }

    #[tokio::test]
    async fn serve_addr_multiaddrs() {
        let relay = test_relay_server().await.unwrap();

        let response = http_get(&relay.url("/")).await.unwrap();
        let body = response.text().await.unwrap();
        let addresses: Vec<String> = serde_json::from_str(&body).unwrap();

        assert!(
            !addresses.is_empty(),
            "Expected at least one multiaddr in response"
        );

        for addr in addresses {
            libp2p::Multiaddr::from_str(&addr).unwrap_or_else(|err| {
                panic!("Failed to parse multiaddr '{}': {}", addr, err);
            });
        }
    }

    #[tokio::test]
    async fn serve_addr_enr() {
        let relay = test_relay_server().await.unwrap();

        let response = http_get(&relay.url("/enr")).await.unwrap();
        let enr = parse_enr(&response.text().await.unwrap());

        assert_eq!(enr.ip(), Some(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[tokio::test]
    async fn serve_addr_enr_ext_ip() {
        let relay =
            test_relay_server_with(|args| args.p2p.external_ip = Some("222.222.222.222".into()))
                .await
                .unwrap();

        let response = http_get(&relay.url("/enr")).await.unwrap();
        let enr = parse_enr(&response.text().await.unwrap());

        assert_eq!(enr.ip(), Some(Ipv4Addr::new(222, 222, 222, 222)));
        // The external IP is advertised on the ports libp2p bound, not on the
        // port 0 that was configured — which would be undialable.
        assert_eq!(enr.tcp(), Some(relay.p2p_port(pluto_p2p::utils::tcp_port)));
        assert_eq!(enr.udp(), Some(relay.p2p_port(pluto_p2p::utils::udp_port)));
    }

    #[tokio::test]
    async fn serve_addr_enr_ext_host() {
        let relay =
            test_relay_server_with(|args| args.p2p.external_host = Some("www.google.com".into()))
                .await
                .unwrap();

        // Resolution happens asynchronously on a tick, so wait until the ENR
        // reflects a non-loopback IP (mirrors the Go test using
        // `assert.Eventually`).
        relay
            .get_until("/enr", |body| !parse_enr(body).ip().unwrap().is_loopback())
            .await;
    }

    #[tokio::test]
    async fn serve_addr_metrics() {
        // The monitoring port used to be guessed by the fixture, and losing the
        // race for it was the most frequent pre-fix failure. It is now assigned
        // by the kernel inside the relay's own bind and read back off it.
        let relay = test_relay_server_with(|args| {
            args.debug_monitoring.monitor_addr = Some(ANY_ADDR.into());
        })
        .await
        .unwrap();

        let monitoring_addr = relay.monitoring_addr.expect("monitoring was configured");
        let response = http_get(&format!("http://{monitoring_addr}/metrics"))
            .await
            .unwrap();
        let body = response.text().await.unwrap();

        assert!(body.contains("relay_p2p_connection_total"));
        assert!(body.contains("relay_p2p_active_connections"));
        assert!(body.contains("relay_p2p_ping_latency"));
        assert!(body.contains("relay_p2p_network_sent_bytes"));
        assert!(body.contains("relay_p2p_network_receive_bytes"));
        assert!(body.ends_with("# EOF\n"));
    }

    #[tokio::test]
    async fn taken_http_port_fails_the_relay() {
        let (_taken, addr) = squat_tcp_addr().await;

        let err = test_relay_server_with(|args| args.relay.http_address = addr)
            .await
            .expect_err("relay must not start while its http port is taken");

        assert!(
            matches!(
                err,
                super::CliError::RelayP2PError(
                    pluto_relay_server::RelayP2PError::FailedToBindHttpListener { .. }
                )
            ),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn taken_monitoring_port_fails_the_relay() {
        let (_taken, addr) = squat_tcp_addr().await;

        let err = test_relay_server_with(|args| args.debug_monitoring.monitor_addr = Some(addr))
            .await
            .expect_err("relay must not start while its monitoring port is taken");

        // A monitoring bind failure used to be only `warn!`-ed, which left the
        // relay running with the port unserved.
        assert!(
            matches!(
                err,
                super::CliError::RelayP2PError(
                    pluto_relay_server::RelayP2PError::FailedToBindMonitoringListener { .. }
                )
            ),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn unusable_monitoring_addr_fails_the_relay() {
        let err = test_relay_server_with(|args| {
            args.debug_monitoring.monitor_addr = Some("not-an-address".into());
        })
        .await
        .expect_err("an unusable monitoring address must fail the relay");

        assert!(
            matches!(
                err,
                super::CliError::RelayP2PError(
                    pluto_relay_server::RelayP2PError::FailedToParseMonitoringAddr(..)
                )
            ),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn stopping_the_relay_releases_its_http_port() {
        let mut relay = test_relay_server().await.unwrap();
        let http_addr = relay.http_addr;

        relay.stop().await.unwrap();

        // The relay task has joined, and with it its listener must be gone.
        net::TcpListener::bind(http_addr)
            .await
            .unwrap_or_else(|err| panic!("relay did not release {http_addr}: {err}"));
    }

    #[test]
    fn advertise_priv_inverts_filter_private_addrs() {
        // The flag is the inverse of the config knob it feeds, and every test
        // above depends on the inversion holding: with private addresses
        // filtered, the loopback listeners never reach `/enr`.
        let dir = tempfile::tempdir().unwrap();
        let mut args = relay_args(dir.path());

        let config: pluto_relay_server::config::Config = args.clone().try_into().unwrap();
        assert!(!config.filter_private_addrs, "advertise_priv: true");

        args.relay.advertise_priv = false;
        let config: pluto_relay_server::config::Config = args.try_into().unwrap();
        assert!(config.filter_private_addrs, "advertise_priv: false");
    }

    /// Budget for the relay to stop once a test is done with it.
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

    /// Budget for an endpoint to reach the state a test waits for. Sized for a
    /// heavily loaded CI machine.
    const SERVING_TIMEOUT: Duration = Duration::from_secs(30);

    /// Per-request budget, so a server that accepts the connection but never
    /// answers fails the test instead of hanging it until the harness gives up.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

    /// Loopback address with an ephemeral port, used for *every* listener in
    /// these tests.
    ///
    /// Port 0 lets the kernel assign the port inside the relay's own `bind` and
    /// [`TestRelay`] reads back what was bound, so nothing here names a port
    /// another process could take first. That is what makes the bind race these
    /// tests used to lose unrepresentable rather than merely unlikely.
    const ANY_ADDR: &str = "127.0.0.1:0";

    /// Shared HTTP client: building one per request re-reads the system CA
    /// store and throws away the connection pool.
    static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

    /// Relay arguments every test starts from: all listeners on [`ANY_ADDR`],
    /// quiet logs, no relays to dial.
    ///
    /// `advertise_priv` is load-bearing: without it, `filter_private_addrs`
    /// drops the loopback listen addresses, and `/enr` answers 500 forever.
    fn relay_args(data_dir: &Path) -> super::RelayArgs {
        super::RelayArgs {
            data_dir: super::RelayDataDirArgs {
                data_dir: data_dir.to_path_buf(),
            },
            relay: super::RelayRelayArgs {
                http_address: ANY_ADDR.into(),
                auto_p2p_key: true,
                p2p_relay_log_level: "info".into(),
                max_res_per_peer: 0,
                max_conns: 0,
                advertise_priv: true,
            },
            debug_monitoring: super::RelayDebugMonitoringArgs {
                monitor_addr: None,
                debug_addr: None,
            },
            p2p: super::RelayP2PArgs {
                relays: vec![],
                external_ip: None,
                external_host: None,
                tcp_addrs: vec![ANY_ADDR.into()],
                udp_addrs: vec![ANY_ADDR.into()],
                disable_reuseport: false,
            },
            log: super::RelayLogFlags {
                format: "console".into(),
                level: "error".into(),
                color: super::ConsoleColor::Disable,
                log_output_path: None,
            },
            loki: super::RelayLokiArgs {
                loki_addresses: vec![],
                loki_service: "".into(),
            },
        }
    }

    /// A relay that serves for as long as this value is alive.
    ///
    /// It is already serving when a test receives it, and stops when the value
    /// goes out of scope, so a test body is just requests and assertions.
    #[derive(Debug)]
    struct TestRelay {
        /// Address the ENR/multiaddr HTTP server is bound to — the one the
        /// kernel assigned, read back off the bound listener.
        http_addr: SocketAddr,
        /// Address the monitoring server is bound to, when one was configured.
        monitoring_addr: Option<SocketAddr>,
        /// Addresses libp2p bound, with the ports the kernel assigned.
        p2p_addrs: Vec<libp2p::Multiaddr>,
        /// Cancels the relay.
        ct: CancellationToken,
        /// Relay task, resolving with the relay's exit status.
        handle: JoinHandle<Result<(), super::CliError>>,
        /// Data dir, kept alive for as long as the relay is.
        _dir: tempfile::TempDir,
    }

    /// Starts a serving relay with the default test arguments. See
    /// [`test_relay_server_with`].
    async fn test_relay_server() -> Result<TestRelay, super::CliError> {
        test_relay_server_with(|_| {}).await
    }

    /// Starts a relay in a fresh data dir, letting `configure` adjust the
    /// [`super::RelayArgs`] it is built from.
    ///
    /// Returns once every listener is bound *and* libp2p has reported the
    /// addresses it got, so requests against the returned addresses are served
    /// straight away — no readiness poll, and a failure in the test that
    /// follows is a real failure rather than a startup race. Every startup
    /// failure — an unloadable key, an unusable address, a port that is
    /// genuinely taken — comes back as `Err` here rather than reaching a
    /// test as a connection failure further down.
    async fn test_relay_server_with(
        configure: impl FnOnce(&mut super::RelayArgs),
    ) -> Result<TestRelay, super::CliError> {
        let dir = tempfile::tempdir().unwrap();
        let mut args = relay_args(dir.path());
        configure(&mut args);

        let config: pluto_relay_server::config::Config = args.try_into()?;
        let key = super::load_or_create_key(&config)?;

        let ct = CancellationToken::new();
        let bound = pluto_relay_server::p2p::bind_relay(&config, key, ct.child_token()).await?;

        // Read the addresses off the bound relay before serving consumes it.
        let http_addr = bound
            .http_addr()
            .expect("`relay_args` configures an http address");
        let monitoring_addr = bound.monitoring_addr();
        let p2p_addrs = bound.p2p_addrs().await;

        let handle =
            tokio::spawn(async move { bound.serve().await.map(|_| ()).map_err(Into::into) });

        Ok(TestRelay {
            http_addr,
            monitoring_addr,
            p2p_addrs,
            ct,
            handle,
            _dir: dir,
        })
    }

    impl TestRelay {
        /// URL for `path` on the relay's HTTP server.
        fn url(&self, path: &str) -> String {
            format!("http://{}{path}", self.http_addr)
        }

        /// Port of the relay's libp2p listen address selected by `port_of`,
        /// e.g. [`pluto_p2p::utils::tcp_port`].
        fn p2p_port(&self, port_of: impl Fn(&libp2p::Multiaddr) -> Option<u16>) -> u16 {
            self.p2p_addrs
                .iter()
                .find_map(port_of)
                .expect("`relay_args` configures both transports")
        }

        /// Fetches `path` until it answers 2xx *and* `ready` accepts the body,
        /// returning that body.
        ///
        /// This is not race tolerance — the relay is fully bound and serving
        /// before a test gets hold of it, so a request can never be refused and
        /// a transport error panics instead of being retried. The one thing it
        /// waits out is DNS: `--p2p-external-hostname` is resolved on a tick by
        /// a background task, so the ENR reflects it only after the first
        /// lookup answers. Charon waits the same way (`assert.Eventually`,
        /// `cmd/relay/relay_internal_test.go:208`).
        async fn get_until(&self, path: &str, ready: impl Fn(&str) -> bool) -> String {
            let started = Instant::now();

            loop {
                let response = CLIENT
                    .get(self.url(path))
                    .timeout(REQUEST_TIMEOUT)
                    .send()
                    .await
                    .unwrap_or_else(|err| {
                        panic!(
                            "GET {path} failed: {err} (relay exited: {})",
                            self.handle.is_finished()
                        )
                    });

                let status = response.status();
                let body = response.text().await.unwrap();

                if status.is_success() && ready(&body) {
                    return body;
                }

                // The relay is the only thing serving this address, so if it is
                // gone nothing will ever satisfy the poll.
                assert!(
                    !self.handle.is_finished(),
                    "relay exited while waiting for {path} to serve"
                );
                assert!(
                    started.elapsed() < SERVING_TIMEOUT,
                    "{path} not ready {SERVING_TIMEOUT:?} into startup; last status {status}: {body}"
                );

                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        /// Cancels the relay, waits for it to stop, and returns its exit
        /// status.
        ///
        /// Only needed by tests that assert on what stopping released; dropping
        /// the value is enough everywhere else.
        async fn stop(&mut self) -> Result<(), super::CliError> {
            self.ct.cancel();

            match tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut self.handle).await {
                Ok(Ok(exit)) => exit,
                Ok(Err(err)) => panic!("relay task did not join: {err}"),
                Err(_) => panic!("relay did not shut down within {SHUTDOWN_TIMEOUT:?}"),
            }
        }
    }

    impl Drop for TestRelay {
        /// Best-effort: a `Drop` cannot await the task, which is why
        /// [`TestRelay::stop`] exists for tests that need it fully stopped.
        fn drop(&mut self) {
            self.ct.cancel();
        }
    }

    /// Parses an ENR response body.
    fn parse_enr(body: &str) -> pluto_eth2util::enr::Record {
        pluto_eth2util::enr::Record::try_from(body).unwrap()
    }

    /// Single-shot GET, failing on a non-2xx status.
    ///
    /// Single-shot on purpose: the relay is serving before a test gets hold of
    /// it, so a failure here is a real failure rather than a startup race.
    async fn http_get(url: &str) -> Result<reqwest::Response, reqwest::Error> {
        CLIENT
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .and_then(|response| response.error_for_status())
    }

    /// Binds a loopback port and holds it, so anything else binding the
    /// returned address fails with `AddrInUse`.
    async fn squat_tcp_addr() -> (net::TcpListener, String) {
        let listener = net::TcpListener::bind(ANY_ADDR).await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        (listener, addr)
    }
}
