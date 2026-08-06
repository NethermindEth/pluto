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

    bind_relay(config, ct)
        .await?
        .run()
        .await
        .map_err(Into::into)
}

/// Loads the p2p key and binds every relay listener.
///
/// Everything that can fail before the relay serves happens here, so the caller
/// gets a startup error instead of a relay that is running but unreachable.
async fn bind_relay(
    config: &pluto_relay_server::config::Config,
    ct: CancellationToken,
) -> Result<pluto_relay_server::RelayServer, CliError> {
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

    Ok(pluto_relay_server::RelayServer::bind(config, key, ct).await?)
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, str::FromStr, time::Duration};
    use tokio::net;
    use tokio_util::sync::{CancellationToken, DropGuard};

    /// Listen address that lets the kernel assign the port, so no two tests can
    /// race for one and no address has to be guessed up front.
    const ANY_ADDR: &str = "127.0.0.1:0";

    /// A relay server, running for as long as this value is alive.
    #[derive(Debug)]
    struct TestRelay {
        /// Address the ENR / multiaddr HTTP server is bound to.
        http_addr: Option<SocketAddr>,
        /// Address the Prometheus monitoring server is bound to.
        monitoring_addr: Option<SocketAddr>,
        /// Addresses libp2p is listening on.
        p2p_addrs: Vec<libp2p::Multiaddr>,
        /// Data dir of this relay, removed with it.
        _dir: tempfile::TempDir,
        /// Stops the relay when dropped.
        _ct: DropGuard,
    }

    /// Starts a relay server, configured through [`super::RelayArgs`] by
    /// `configure`.
    ///
    /// Returns once every listener is bound, so requests against the returned
    /// addresses are served without waiting: a failure in the test that follows
    /// is a real failure, not a startup race. Startup errors are returned
    /// instead of showing up as connection failures later.
    async fn test_relay_server(
        configure: impl FnOnce(&mut super::RelayArgs),
    ) -> Result<TestRelay, super::CliError> {
        let dir = tempfile::tempdir().unwrap();

        let mut args = test_relay_args(dir.path().to_path_buf());
        configure(&mut args);

        let config: pluto_relay_server::config::Config = args.try_into()?;
        let ct = CancellationToken::new();
        let server = super::bind_relay(&config, ct.child_token()).await?;

        let relay = TestRelay {
            http_addr: server.http_addr(),
            monitoring_addr: server.monitoring_addr(),
            p2p_addrs: server.p2p_addrs(),
            _dir: dir,
            _ct: ct.drop_guard(),
        };

        tokio::spawn(server.run());

        Ok(relay)
    }

    /// Relay arguments every test starts from: a fresh data dir, an
    /// auto-generated p2p key, and kernel-assigned ports for every listener.
    fn test_relay_args(data_dir: std::path::PathBuf) -> super::RelayArgs {
        super::RelayArgs {
            data_dir: super::RelayDataDirArgs { data_dir },
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

    #[tokio::test]
    async fn run_bootnode() {
        let _relay = test_relay_server(|args| {
            args.relay.auto_p2p_key = false;
            pluto_p2p::k1::new_saved_priv_key(&args.data_dir.data_dir).unwrap();
        })
        .await
        .expect("relay must start with an existing p2p key");
    }

    #[tokio::test]
    async fn run_bootnode_auto_p2p() {
        let missing_key = test_relay_server(|args| args.relay.auto_p2p_key = false).await;
        assert!(matches!(
            missing_key,
            Err(super::CliError::RelayP2PError(
                pluto_relay_server::RelayP2PError::FailedToLoadPrivateKey(..)
            ))
        ));

        let _relay = test_relay_server(|_| {})
            .await
            .expect("relay must start with an auto-generated p2p key");
    }

    #[tokio::test]
    async fn serve_addr_multiaddrs() {
        let relay = test_relay_server(|_| {}).await.unwrap();

        let response = relay_get(&relay, "/").await.unwrap();
        let body = response.text().await.unwrap();
        let addresses: Vec<String> = serde_json::from_str(&body).unwrap();

        assert!(
            !addresses.is_empty(),
            "Expected at least one multiaddr in response"
        );

        for addr in addresses {
            libp2p::Multiaddr::from_str(&addr)
                .unwrap_or_else(|err| panic!("Failed to parse multiaddr '{addr}': {err}"));
        }
    }

    #[tokio::test]
    async fn serve_addr_enr() {
        let relay = test_relay_server(|_| {}).await.unwrap();

        let enr = get_enr(&relay).await;

        assert_eq!(enr.ip(), Some(std::net::Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(
            enr.tcp(),
            Some(p2p_port(&relay, pluto_p2p::utils::tcp_port))
        );
        assert_eq!(
            enr.udp(),
            Some(p2p_port(&relay, pluto_p2p::utils::udp_port))
        );
    }

    #[tokio::test]
    async fn serve_addr_enr_ext_ip() {
        let relay = test_relay_server(|args| args.p2p.external_ip = Some("222.222.222.222".into()))
            .await
            .unwrap();

        let enr = get_enr(&relay).await;

        assert_eq!(enr.ip(), Some(std::net::Ipv4Addr::new(222, 222, 222, 222)));
        // The external IP is advertised on the ports libp2p bound, not on the
        // port 0 that was asked for.
        assert_eq!(
            enr.tcp(),
            Some(p2p_port(&relay, pluto_p2p::utils::tcp_port))
        );
        assert_eq!(
            enr.udp(),
            Some(p2p_port(&relay, pluto_p2p::utils::udp_port))
        );
    }

    #[tokio::test]
    async fn serve_addr_enr_ext_host() {
        let relay =
            test_relay_server(|args| args.p2p.external_host = Some("www.google.com".into()))
                .await
                .unwrap();

        // Resolution is asynchronous and depends on a DNS server answering, so
        // this is the one thing the relay cannot report as ready. Wait for the
        // ENR to reflect a non-loopback IP (as the Go test does with
        // `assert.Eventually`).
        tokio::time::timeout(Duration::from_secs(10), async {
            while get_enr(&relay).await.ip().unwrap().is_loopback() {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("external host never resolved to non-loopback ip");
    }

    #[tokio::test]
    async fn serve_addr_metrics() {
        let relay = test_relay_server(|args| {
            args.debug_monitoring.monitor_addr = Some(ANY_ADDR.into());
        })
        .await
        .unwrap();

        let monitoring_addr = relay.monitoring_addr.unwrap();
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
        let taken = net::TcpListener::bind(ANY_ADDR).await.unwrap();
        let addr = taken.local_addr().unwrap().to_string();

        let err = test_relay_server(|args| args.relay.http_address = addr)
            .await
            .expect_err("relay must not start while its http port is taken");

        assert!(
            matches!(
                err,
                super::CliError::RelayP2PError(
                    pluto_relay_server::RelayP2PError::FailedToBindHttpListener { .. }
                )
            ),
            "expected the bind error to be surfaced, got: {err}"
        );
    }

    #[tokio::test]
    async fn taken_monitoring_port_fails_the_relay() {
        let taken = net::TcpListener::bind(ANY_ADDR).await.unwrap();
        let addr = taken.local_addr().unwrap().to_string();

        let err = test_relay_server(|args| args.debug_monitoring.monitor_addr = Some(addr))
            .await
            .expect_err("relay must not start while its monitoring port is taken");

        assert!(
            matches!(
                err,
                super::CliError::RelayP2PError(
                    pluto_relay_server::RelayP2PError::FailedToBindMonitoringListener { .. }
                )
            ),
            "expected the monitoring bind error to be surfaced, got: {err}"
        );
    }

    #[tokio::test]
    async fn unusable_monitoring_addr_fails_the_relay() {
        let err = test_relay_server(|args| {
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
            "expected the startup error to be surfaced, got: {err}"
        );
    }

    /// Returns the port of the relay's libp2p listen address selected by
    /// `port_of`, e.g. [`pluto_p2p::utils::tcp_port`].
    fn p2p_port(relay: &TestRelay, port_of: impl Fn(&libp2p::Multiaddr) -> Option<u16>) -> u16 {
        relay
            .p2p_addrs
            .iter()
            .find_map(port_of)
            .expect("relay listens on the requested transports")
    }

    async fn get_enr(relay: &TestRelay) -> pluto_eth2util::enr::Record {
        let response = relay_get(relay, "/enr").await.unwrap();
        let body = response.text().await.unwrap();

        pluto_eth2util::enr::Record::try_from(body.as_str()).unwrap()
    }

    /// Makes an HTTP GET request against the relay's ENR server.
    ///
    /// Single-shot on purpose: [`test_relay_server`] returns only once the
    /// listener is bound, so a failure here is a real failure.
    async fn relay_get(relay: &TestRelay, path: &str) -> Result<reqwest::Response, reqwest::Error> {
        let http_addr = relay.http_addr.expect("relay serves an http address");
        http_get(&format!("http://{http_addr}{path}")).await
    }

    async fn http_get(url: &str) -> Result<reqwest::Response, reqwest::Error> {
        reqwest::get(url)
            .await
            .and_then(|response| response.error_for_status())
    }
}
