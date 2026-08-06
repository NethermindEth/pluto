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

    pluto_relay_server::p2p::run_relay_p2p_node(config, key, ct)
        .await
        .map(|_| ())
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        io,
        str::FromStr,
        time::{Duration, Instant},
    };
    use tokio::{net, task::JoinHandle};
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn run_bootnode() {
        with_relay_server(
            |args, _| {
                args.relay.auto_p2p_key = false;
                pluto_p2p::k1::new_saved_priv_key(&args.data_dir.data_dir).unwrap();
            },
            async |_| { /* Relay server starts with existing p2p key */ },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn run_bootnode_auto_p2p() {
        let first_run = with_relay_server(
            |args, _| {
                args.relay.auto_p2p_key = false;
            },
            async |_| { /* Relay server does not start due to missing p2p key */ },
        )
        .await;
        assert!(matches!(
            first_run,
            Err(super::CliError::RelayP2PError(
                pluto_relay_server::RelayP2PError::FailedToLoadPrivateKey(..)
            ))
        ));

        let second_run = with_relay_server(
            |_, _| {},
            async |_| { /* Relay server starts with auto-generated p2p key */ },
        )
        .await;
        assert!(matches!(second_run, Ok(())));
    }

    #[tokio::test]
    async fn serve_addr_multiaddrs() {
        with_relay_server(
            |_, _| {},
            async |cfg| {
                let response = relay_server_get(cfg, "/").await.unwrap();
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
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn serve_addr_enr() {
        with_relay_server(
            |_, _| {},
            async |cfg| {
                let response = relay_server_get(cfg, "/enr").await.unwrap();
                let body = response.text().await.unwrap();
                let enr = pluto_eth2util::enr::Record::try_from(body.as_str()).unwrap();

                assert_eq!(enr.ip(), Some(std::net::Ipv4Addr::new(127, 0, 0, 1)));
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn serve_addr_enr_ext_ip() {
        with_relay_server(
            |args, _| args.p2p.external_ip = Some("222.222.222.222".into()),
            async |cfg| {
                let response = relay_server_get(cfg, "/enr").await.unwrap();
                let body = response.text().await.unwrap();
                let enr = pluto_eth2util::enr::Record::try_from(body.as_str()).unwrap();

                assert_eq!(enr.ip(), Some(std::net::Ipv4Addr::new(222, 222, 222, 222)));
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn serve_addr_enr_ext_host() {
        with_relay_server(
            |args, _| args.p2p.external_host = Some("www.google.com".into()),
            async |cfg| {
                // Resolution happens asynchronously on a tick, so poll until the
                // ENR reflects a non-loopback IP (mirrors the Go test using
                // `assert.Eventually`).
                tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        let response = relay_server_get(cfg.clone(), "/enr").await.unwrap();
                        let body = response.text().await.unwrap();
                        let enr = pluto_eth2util::enr::Record::try_from(body.as_str()).unwrap();
                        let ip = enr.ip().unwrap();

                        if !ip.is_loopback() {
                            break;
                        }

                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                })
                .await
                .expect("external host never resolved to non-loopback ip");
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn serve_addr_metrics() {
        with_relay_server(
            |args, monitoring_addr| {
                args.debug_monitoring.monitor_addr = Some(monitoring_addr.into());
            },
            async |cfg| {
                let monitoring_addr = cfg.monitoring_addr.unwrap();
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
            },
        )
        .await
        .unwrap();
    }

    /// Number of complete relay startup attempts — each with a fresh data dir
    /// and freshly allocated HTTP ports — before the fixture gives up on a bind
    /// race and surfaces the error.
    const MAX_STARTUP_ATTEMPTS: usize = 5;

    /// Per-attempt budget for the relay's HTTP servers to start serving. Sized
    /// for a heavily loaded CI machine: the relay either serves or exits with
    /// an error long before this, so exceeding it means it hung.
    const SERVING_TIMEOUT: Duration = Duration::from_secs(30);

    /// Budget for the relay to stop once the test function has returned.
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

    /// libp2p listen address for the fixture: port 0 lets the kernel assign the
    /// port inside libp2p's own `bind`, so no other process can claim it in
    /// between.
    ///
    /// The HTTP listeners can't do that: their addresses are inbound config the
    /// relay never reports back (as in Charon, whose relay test passes
    /// `HTTPAddr` in), so the fixture allocates them up front and retries the
    /// race instead. A p2p race could not be retried anyway — libp2p buries the
    /// `AddrInUse` inside `io::Error::other(Transport(..))`, out of reach of
    /// `Error::source` and therefore of [`is_addr_in_use`].
    ///
    /// The cost is that external multiaddrs derived from these listen ports
    /// carry port 0; no test asserts on them (Charon's assert only on the ENR's
    /// IP), and the listen-port-to-advertised-port mapping is covered
    /// separately by `external_multiaddrs_keep_the_listen_ports` in
    /// `pluto_p2p::utils`.
    const P2P_LISTEN_ADDR: &str = "127.0.0.1:0";

    /// Allocates a loopback address by binding port 0, reading back the
    /// assigned port and dropping the socket.
    ///
    /// The relay rebinds that port moments later, so another process can claim
    /// it in between; [`with_relay_server`] retries the whole startup with a
    /// new address when that happens.
    async fn free_tcp_addr() -> String {
        squat_tcp_addr().await.1
    }

    /// A relay that has been observed serving every HTTP endpoint it was
    /// configured with.
    struct ServingRelay {
        /// Config the relay was started with.
        cfg: pluto_relay_server::config::Config,
        /// Cancels the relay.
        ct: CancellationToken,
        /// Relay task, resolving with the relay's exit status.
        handle: JoinHandle<Result<(), crate::error::CliError>>,
        /// Data dir of this attempt, kept alive while the relay runs.
        dir: tempfile::TempDir,
    }

    /// Run a function in the context of a running relay server.
    ///
    /// The server can be configured before initialization through
    /// [`super::RelayArgs`]; the closure also receives a loopback address
    /// allocated for the attempt, for tests that opt into the monitoring
    /// server. It is invoked once per startup attempt, so it must not assume it
    /// runs only once.
    ///
    /// The test function runs only once the relay serves every HTTP endpoint it
    /// was configured with, and receives the config the relay was started with.
    /// Startup and shutdown errors are returned to the caller instead of
    /// showing up as connection failures inside the test function.
    async fn with_relay_server<FArgs, FTest, Fut>(
        mut config_fn: FArgs,
        test_fn: FTest,
    ) -> Result<(), crate::error::CliError>
    where
        FArgs: FnMut(&mut super::RelayArgs, &str),
        FTest: FnOnce(pluto_relay_server::config::Config) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let mut attempts: usize = 0;

        let ServingRelay {
            cfg,
            ct,
            handle,
            dir,
        } = loop {
            attempts = attempts.saturating_add(1);

            match start_relay(&mut config_fn).await {
                Ok(relay) => break relay,
                // Another process claimed one of the freshly allocated ports
                // before the relay could bind it. The relay task is gone for
                // good — request retries in the test function could never
                // recover — so start over with new ports, boundedly.
                Err(err) if is_addr_in_use(&err) && attempts < MAX_STARTUP_ATTEMPTS => {
                    tracing::debug!("relay lost the race for a port, retrying: {err}");
                }
                Err(err) => return Err(err),
            }
        };

        test_fn(cfg).await;

        ct.cancel();
        let exit = match tokio::time::timeout(SHUTDOWN_TIMEOUT, handle).await {
            Ok(Ok(exit)) => exit,
            Ok(Err(err)) => resume_relay_panic(err),
            Err(_) => panic!("relay did not shut down within {SHUTDOWN_TIMEOUT:?}"),
        };

        // The relay has stopped, so nothing reads the data dir anymore.
        drop(dir);

        exit
    }

    /// Starts one relay with freshly allocated addresses and waits until it
    /// either serves or exits.
    async fn start_relay(
        config_fn: &mut impl FnMut(&mut super::RelayArgs, &str),
    ) -> Result<ServingRelay, crate::error::CliError> {
        let dir = tempfile::tempdir().unwrap();
        // Only bound when a test opts into the monitoring server by setting
        // `super::RelayDebugMonitoringArgs::monitor_addr` to it.
        let monitoring_addr = free_tcp_addr().await;

        let mut args = super::RelayArgs {
            data_dir: super::RelayDataDirArgs {
                data_dir: dir.path().to_path_buf(),
            },
            relay: super::RelayRelayArgs {
                http_address: free_tcp_addr().await,
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
                tcp_addrs: vec![P2P_LISTEN_ADDR.into()],
                udp_addrs: vec![P2P_LISTEN_ADDR.into()],
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
        };
        config_fn(&mut args, &monitoring_addr);

        let cfg: pluto_relay_server::config::Config = args.try_into().unwrap();
        let ct = CancellationToken::new();
        let mut handle = tokio::spawn(super::run(cfg.clone(), ct.child_token()));

        // Wait for the relay to serve, or to exit trying. A failed listener
        // bind takes the relay down permanently, and awaiting the relay only
        // after the test function would let a request `unwrap()` mask it as
        // `ConnectionRefused`.
        let serving = tokio::select! {
            joined = &mut handle => {
                // The relay is gone; cancel so nothing it spawned outlives it
                // and keeps a listener bound into the next attempt.
                ct.cancel();

                return match joined {
                    Ok(Ok(())) => panic!("relay exited before serving {:?}", cfg.http_addr),
                    Ok(Err(err)) => Err(err),
                    Err(err) => resume_relay_panic(err),
                };
            },
            serving = wait_until_serving(&cfg) => serving,
        };

        if let Err(err) = serving {
            // The relay is alive but never served: not a bind race. Take it
            // down so the failure isn't followed by a leaked relay.
            ct.cancel();
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, handle).await;
            panic!("{err}");
        }

        Ok(ServingRelay {
            cfg,
            ct,
            handle,
            dir,
        })
    }

    /// Polls every HTTP endpoint the relay is configured to serve until each
    /// one answers, returning a description of whichever never came up within
    /// [`SERVING_TIMEOUT`].
    ///
    /// `/enr` stands in for the ENR server as a whole: it shares a listener
    /// with `/` and only succeeds once libp2p has reported its listen
    /// addresses, so test functions can request either without racing startup.
    async fn wait_until_serving(cfg: &pluto_relay_server::config::Config) -> Result<(), String> {
        let client = reqwest::Client::new();
        let started = Instant::now();

        let urls = [
            cfg.http_addr
                .as_ref()
                .map(|addr| format!("http://{addr}/enr")),
            cfg.monitoring_addr
                .as_ref()
                .map(|addr| format!("http://{addr}/metrics")),
        ]
        .into_iter()
        .flatten();

        for url in urls {
            while let Err(err) = client
                .get(&url)
                .timeout(Duration::from_secs(1))
                .send()
                .await
                .and_then(|response| response.error_for_status())
            {
                if started.elapsed() >= SERVING_TIMEOUT {
                    return Err(format!(
                        "{url} still not serving {SERVING_TIMEOUT:?} into startup: {err}"
                    ));
                }

                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        Ok(())
    }

    /// Reports whether `err`'s source chain contains an
    /// [`io::ErrorKind::AddrInUse`] error, i.e. whether a listener lost the
    /// race for a port that had just been allocated.
    ///
    /// Walks the chain instead of matching error strings so the typed
    /// `io::ErrorKind` decides: both relay bind errors
    /// ([`pluto_relay_server::RelayP2PError::FailedToBindHttpListener`] and its
    /// monitoring counterpart) keep the original `io::Error`.
    ///
    /// Those two are the only bind races this fixture can hit; the p2p
    /// listeners use port 0 instead — see [`P2P_LISTEN_ADDR`].
    fn is_addr_in_use(err: &(dyn std::error::Error + 'static)) -> bool {
        let mut next = Some(err);

        while let Some(err) = next {
            if let Some(io_err) = err.downcast_ref::<io::Error>()
                && io_err.kind() == io::ErrorKind::AddrInUse
            {
                return true;
            }

            next = err.source();
        }

        false
    }

    /// Re-raises a panic from the relay task in the test thread, so the
    /// original panic message is what the test reports.
    fn resume_relay_panic(err: tokio::task::JoinError) -> ! {
        if err.is_panic() {
            std::panic::resume_unwind(err.into_panic());
        }

        panic!("relay task was cancelled: {err}");
    }

    /// Binds a loopback port and holds it, so anything else binding the
    /// returned address fails with [`io::ErrorKind::AddrInUse`] — the failure a
    /// concurrently started process causes by claiming a port between
    /// [`free_tcp_addr`] and the relay's own bind.
    async fn squat_tcp_addr() -> (net::TcpListener, String) {
        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        (listener, addr)
    }

    #[tokio::test]
    async fn fixture_recovers_from_transient_bind_race() {
        let (squatter, squatted) = squat_tcp_addr().await;
        // Released at the start of the second attempt, so exactly one bind
        // loses the race — the transient failure seen when tests run
        // concurrently.
        let mut squatter = Some(squatter);
        let attempts = Cell::new(0usize);

        with_relay_server(
            |args, _| {
                attempts.set(attempts.get().saturating_add(1));
                if attempts.get() > 1 {
                    squatter.take();
                }
                args.relay.http_address = squatted.clone();
            },
            async |cfg| {
                let response = relay_server_get(cfg, "/enr").await.unwrap();

                assert!(response.status().is_success(), "{}", response.status());
            },
        )
        .await
        .unwrap();

        assert_eq!(
            attempts.get(),
            2,
            "the relay should have started on the second attempt"
        );
    }

    /// Runs the fixture with `configure` pointing one of the relay's listeners
    /// at a port held for the whole run, so every attempt loses the race for it
    /// as if a concurrent process had claimed it.
    ///
    /// Asserts that the fixture retried boundedly and gave up with an
    /// `AddrInUse` error, and returns that error so the caller can check which
    /// listener reported it.
    async fn exhaust_retries_on_taken_port(
        configure: impl Fn(&mut super::RelayArgs, String),
    ) -> super::CliError {
        let (_squatter, squatted) = squat_tcp_addr().await;
        let attempts = Cell::new(0usize);

        let result = with_relay_server(
            |args, _| {
                attempts.set(attempts.get().saturating_add(1));
                configure(args, squatted.clone());
            },
            async |_| panic!("test function must not run when a listener cannot bind"),
        )
        .await;

        let err = result.expect_err("relay must not serve while one of its ports is taken");
        assert!(
            is_addr_in_use(&err),
            "expected an AddrInUse error, got: {err}"
        );
        assert_eq!(
            attempts.get(),
            MAX_STARTUP_ATTEMPTS,
            "bind races must be retried, but boundedly"
        );

        err
    }

    #[tokio::test]
    async fn fixture_retries_bind_races_boundedly() {
        let err = exhaust_retries_on_taken_port(|args, addr| args.relay.http_address = addr).await;
        assert!(
            matches!(
                err,
                super::CliError::RelayP2PError(
                    pluto_relay_server::RelayP2PError::FailedToBindHttpListener { .. }
                )
            ),
            "expected the bind error to be surfaced, got: {err}"
        );

        // The monitoring listener behaves the same way. It used to be only
        // `warn!`-ed, which left the relay running and the port unserved — the
        // most frequent pre-fix failure in the stress runs.
        let err = exhaust_retries_on_taken_port(|args, addr| {
            args.debug_monitoring.monitor_addr = Some(addr);
        })
        .await;
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
    async fn fixture_leaves_no_listener_bound_when_startup_fails() {
        let http_addr = Cell::new(None);
        let attempts = Cell::new(0usize);

        let result = with_relay_server(
            |args, _| {
                attempts.set(attempts.get().saturating_add(1));
                http_addr.set(Some(args.relay.http_address.clone()));
                // Rejected while starting up, after the HTTP address has been
                // configured: the relay must fail without leaving its HTTP
                // listener bound behind.
                args.debug_monitoring.monitor_addr = Some("not-an-address".into());
            },
            async |_| panic!("test function must not run when startup fails"),
        )
        .await;

        let err = result.expect_err("an unusable monitoring address must fail the relay");
        assert!(
            matches!(
                err,
                super::CliError::RelayP2PError(
                    pluto_relay_server::RelayP2PError::FailedToParseMonitoringAddr(..)
                )
            ),
            "expected the startup error to be surfaced, got: {err}"
        );
        assert_eq!(attempts.get(), 1, "this failure is not retryable");

        let http_addr = http_addr.take().expect("the fixture configured the relay");
        net::TcpListener::bind(&http_addr)
            .await
            .unwrap_or_else(|err| panic!("failed relay left {http_addr} bound: {err}"));
    }

    #[tokio::test]
    async fn fixture_stops_relay_and_releases_http_port() {
        let http_addr = Cell::new(None);

        with_relay_server(
            |_, _| {},
            async |cfg| {
                http_addr.set(cfg.http_addr.clone());
            },
        )
        .await
        .unwrap();

        // The fixture returned, so the relay task has joined — and with it, its
        // listener must be gone.
        let http_addr = http_addr.take().expect("relay served an http address");
        net::TcpListener::bind(&http_addr)
            .await
            .unwrap_or_else(|err| panic!("relay did not release {http_addr}: {err}"));
    }

    #[test]
    fn is_addr_in_use_detects_bind_races_through_error_chain() {
        let http_bind = super::CliError::RelayP2PError(
            pluto_relay_server::RelayP2PError::FailedToBindHttpListener {
                addr: "127.0.0.1:1".into(),
                source: io::Error::from(io::ErrorKind::AddrInUse),
            },
        );
        assert!(is_addr_in_use(&http_bind));

        let monitoring_bind = super::CliError::RelayP2PError(
            pluto_relay_server::RelayP2PError::FailedToBindMonitoringListener {
                addr: "127.0.0.1:1".parse().unwrap(),
                source: io::Error::from(io::ErrorKind::AddrInUse),
            },
        );
        assert!(is_addr_in_use(&monitoring_bind));

        let unrelated =
            super::CliError::RelayP2PError(pluto_relay_server::RelayP2PError::FailedToServeHTTP(
                io::Error::from(io::ErrorKind::ConnectionReset),
            ));
        assert!(!is_addr_in_use(&unrelated));
    }

    /// Make an HTTP GET request to the relay server.
    ///
    /// Single-shot on purpose: [`with_relay_server`] runs the test function
    /// only once the relay serves, so a failure here is a real failure
    /// rather than a startup race that retries would paper over.
    async fn relay_server_get(
        cfg: pluto_relay_server::config::Config,
        path: &str,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let http_address = cfg.http_addr.unwrap();
        http_get(&format!("http://{http_address}{path}")).await
    }

    async fn http_get(url: &str) -> Result<reqwest::Response, reqwest::Error> {
        reqwest::get(url)
            .await
            .and_then(|response| response.error_for_status())
    }
}
