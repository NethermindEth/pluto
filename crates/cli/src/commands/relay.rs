use crate::error::CliError;
use libp2p::multiaddr::{self, Protocol};
use pluto_p2p::k1;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

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
                let multiaddr = multiaddr::from_url(relay)?;

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

        let log_config = {
            let mut builder = pluto_tracing::TracingConfig::builder();

            builder = builder.with_default_console();
            builder = match self.log.color {
                ConsoleColor::Auto => builder.console_with_ansi(std::env::var("NO_COLOR").is_err()),
                ConsoleColor::Force => builder.console_with_ansi(true),
                ConsoleColor::Disable => builder.console_with_ansi(false),
            };
            builder = builder.override_env_filter(self.log.level);

            // TODO: Handle loki config

            // TODO: Handle log output path

            builder.build()
        };

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
            .monitoring_addr(self.debug_monitoring.monitor_addr)
            .debug_addr(self.debug_monitoring.debug_addr)
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
        default_value = "127.0.0.1:3640",
        help = "Listening address (ip and port) for the relay http server serving runtime ENR."
    )]
    pub http_address: String,

    #[arg(
        long = "auto-p2p-key",
        default_value_t = true,
        help = "Automatically generate and persist a p2p key if one does not exist."
    )]
    pub auto_p2p_key: bool,

    #[arg(
        long = "p2p-relay-loglevel",
        default_value = "",
        help = "Libp2p circuit relay log level. E.g., debug, info, warn, error."
    )]
    pub p2p_relay_log_level: String,

    // TODO: Check if https://github.com/libp2p/go-libp2p/issues/1713 is releveant for the Rust libp2p implementation
    // If so, decrease defaults after this has been addressed
    #[arg(
        long = "p2p-max-reservations",
        default_value_t = 512,
        help = "Updates max circuit reservations per peer (each valid for 30min)"
    )]
    pub max_res_per_peer: usize,

    #[arg(
        long = "p2p-max-connections",
        default_value_t = 16384,
        help = "Libp2p maximum number of peers that can connect to this relay."
    )]
    pub max_conns: usize,

    #[arg(
        long = "p2p-advertise-private-addresses",
        help = "Enable advertising of libp2p auto-detected private addresses. This doesn't affect manually provided p2p-external-ip/hostname."
    )]
    pub advertise_priv: bool,
}

#[derive(clap::Args, Clone)]
pub struct RelayDebugMonitoringArgs {
    #[arg(
        long = "monitoring-address",
        default_value = "",
        help = "Listening address (ip and port) for the monitoring API (prometheus)."
    )]
    pub monitor_addr: String,

    #[arg(
        long = "debug-address",
        default_value = "",
        help = "Listening address (ip and port) for the pprof and QBFT debug API. It is not enabled by default."
    )]
    pub debug_addr: String,
}

#[derive(clap::Args, Clone)]
pub struct RelayP2PArgs {
    #[arg(
        long = "p2p-relays",
        value_delimiter = ',',
        default_values_t = ["https://0.relay.obol.tech".to_string(), "https://2.relay.obol.dev".to_string(), "https://1.relay.obol.tech".to_string()],
        help = "Comma-separated list of libp2p relay URLs or multiaddrs."
    )]
    pub relays: Vec<String>,

    #[arg(
        long = "p2p-external-ip",
        help = "The IP address advertised by libp2p. This may be used to advertise an external IP."
    )]
    pub external_ip: Option<String>,

    #[arg(
        long = "p2p-external-hostname",
        help = "The DNS hostname advertised by libp2p. This may be used to advertise an external DNS."
    )]
    pub external_host: Option<String>,

    #[arg(
        long = "p2p-tcp-address",
        value_delimiter = ',',
        help = "Comma-separated list of listening TCP addresses (ip and port) for libP2P traffic. Empty default doesn't bind to local port therefore only supports outgoing connections."
    )]
    pub tcp_addrs: Vec<String>,

    #[arg(
        long = "p2p-udp-address",
        value_delimiter = ',',
        help = "Comma-separated list of listening UDP addresses (ip and port) for libP2P traffic. Empty default doesn't bind to local port therefore only supports outgoing connections."
    )]
    pub udp_addrs: Vec<String>,

    #[arg(
        long = "p2p-disable-reuseport",
        default_value_t = false,
        help = "Disables TCP port reuse for outgoing libp2p connections."
    )]
    pub disable_reuseport: bool,
}

#[derive(clap::Args, Clone)]
pub struct RelayLogFlags {
    #[arg(
        long = "log-format",
        default_value = "console",
        help = "Log format; console, logfmt or json"
    )]
    pub format: String,

    #[arg(
        long = "log-level",
        default_value = "info",
        help = "Log level; debug, info, warn or error"
    )]
    pub level: String,

    #[arg(long = "log-color", default_value = "auto", help = "Log color")]
    pub color: ConsoleColor,

    #[arg(
        long = "log-output-path",
        default_value = "",
        help = "Path in which to write on-disk logs."
    )]
    pub log_output_path: String,
}

#[derive(clap::ValueEnum, Clone, Default)]
pub enum ConsoleColor {
    #[default]
    Auto,
    Force,
    Disable,
}

#[derive(clap::Args, Clone)]
pub struct RelayLokiArgs {
    #[arg(
        long = "loki-addresses",
        value_delimiter = ',',
        help = "Enables sending of logfmt structured logs to these Loki log aggregation server addresses. This is in addition to normal stderr logs."
    )]
    pub loki_addresses: Vec<String>,

    #[arg(
        long = "loki-service",
        default_value = "charon",
        help = "Service label sent with logs to Loki."
    )]
    pub loki_service: String,
}

pub async fn run(args: RelayArgs, ct: CancellationToken) -> Result<(), CliError> {
    let config: pluto_relay_server::config::Config = args.try_into()?;

    let log_config = config
        .log_config
        .as_ref()
        .expect("Log config is always configured");
    pluto_tracing::init(log_config).expect("Failed to initialize tracing");

    run_with_config(config, ct).await
}

async fn run_with_config(
    config: pluto_relay_server::config::Config,
    ct: CancellationToken,
) -> Result<(), CliError> {
    info!(concat!(
        "This software is licensed under the Maria DB Business Source License 1.1; ",
        "you may not use this software except in compliance with this license. You may obtain a ",
        "copy of this license at https://github.com/ObolNetwork/charon/blob/main/LICENSE"
    ));

    info!(config = ?config);

    let key = match pluto_p2p::k1::load_priv_key(&config.data_dir) {
        Ok(key) => Ok(key),
        Err(
            e @ pluto_p2p::k1::K1Error::K1UtilError(pluto_k1util::K1UtilError::FailedToReadFile(_)),
        ) => {
            if !config.auto_p2p_key {
                error!(
                    "charon-enr-private-key not found in data dir (run with --auto-p2pkey to auto generate)."
                );
                return Err(pluto_relay_server::RelayP2PError::FailedToLoadPrivateKey(e).into());
            }

            let path = k1::key_path(&config.data_dir);
            info!(path = ?path, "Automatically creating charon-enr-private-key");

            k1::new_saved_priv_key(&config.data_dir)
        }
        e => e,
    }?;

    pluto_relay_server::p2p::run_relay_p2p_node(&config, key, ct)
        .await
        .map(|_| ())
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use backon::{BackoffBuilder, Retryable};
    use std::time;
    use tokio::net;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn run_bootnode() {
        let dir = tempfile::tempdir().unwrap();

        // NOTE: Do not refactor this code into a helper function that returns the
        // String address. This is because we need to ensure that the sockets
        // remain bound and are not dropped before the relay is run, which would cause
        // the ports to be freed and potentially reused by other processes, leading to
        // test flakiness.
        let tcp_addr = net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();

        let udp_addr = net::UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();

        let http_addr = net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();

        let args = {
            let mut args = test_relay_args();
            args.data_dir.data_dir = dir.path().to_path_buf();
            args.p2p.tcp_addrs = vec![tcp_addr];
            args.p2p.udp_addrs = vec![udp_addr];
            args.relay.http_address = http_addr;
            args
        };
        let cfg = args.try_into().unwrap();

        pluto_p2p::k1::new_saved_priv_key(dir.path()).unwrap();

        let ct = CancellationToken::new();
        let relay = super::run_with_config(cfg, ct.child_token());
        ct.cancel();
        relay.await.unwrap();
    }

    #[tokio::test]
    async fn run_bootnode_auto_p2p() {
        let dir = tempfile::tempdir().unwrap();

        let tcp_addr = net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();

        let udp_addr = net::UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();

        let http_addr = net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();

        let mut args = test_relay_args();
        args.data_dir.data_dir = dir.path().to_path_buf();
        args.p2p.tcp_addrs = vec![tcp_addr];
        args.p2p.udp_addrs = vec![udp_addr];
        args.relay.http_address = http_addr;

        let first_run = {
            let ct = CancellationToken::new();
            let cfg = args.clone().try_into().unwrap();
            let relay = super::run_with_config(cfg, ct.child_token());
            ct.cancel();
            relay.await
        };
        assert!(matches!(
            first_run,
            Err(super::CliError::RelayP2PError(
                pluto_relay_server::RelayP2PError::FailedToLoadPrivateKey(..)
            ))
        ));

        args.relay.auto_p2p_key = true;
        let second_run = {
            let ct = CancellationToken::new();
            let cfg = args.clone().try_into().unwrap();
            let relay = super::run_with_config(cfg, ct.child_token());
            ct.cancel();
            relay.await
        };
        assert!(matches!(second_run, Ok(())));
    }

    #[tokio::test]
    async fn serve_addr_enr() {
        with_relay_server(
            |_| {},
            async |cfg| {
                let response = relay_server_get(cfg, "/enr").await.unwrap();
                let body = response.text().await.unwrap();
                let enr = pluto_eth2util::enr::Record::try_from(body.as_str()).unwrap();

                assert_eq!(enr.ip(), Some(std::net::Ipv4Addr::new(127, 0, 0, 1)));
            },
        )
        .await;
    }

    /// Run a function in the context of a running relay server.
    ///
    /// The server can be configured before initialization through
    /// [`super::RelayArgs`], while the test function receives a function to
    /// make HTTP requests to the running relay server.
    async fn with_relay_server<FArgs, FTest, Fut>(config_fn: FArgs, test_fn: FTest)
    where
        FArgs: FnOnce(&mut super::RelayArgs),
        FTest: FnOnce(pluto_relay_server::config::Config) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let dir = tempfile::tempdir().unwrap();

        let tcp_addr = net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();

        let udp_addr = net::UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();

        let http_addr = net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();

        let mut args = test_relay_args();
        args.data_dir.data_dir = dir.path().to_path_buf();
        args.p2p.tcp_addrs = vec![tcp_addr];
        args.p2p.udp_addrs = vec![udp_addr];
        args.relay.http_address = http_addr;
        args.relay.auto_p2p_key = true;
        config_fn(&mut args);

        let cfg: pluto_relay_server::config::Config = args.clone().try_into().unwrap();
        let ct = CancellationToken::new();

        let relay = tokio::spawn(super::run_with_config(cfg.clone(), ct.child_token()));

        test_fn(cfg.clone()).await;

        ct.cancel();
        relay.await.unwrap().unwrap();
    }

    async fn relay_server_get(
        cfg: pluto_relay_server::config::Config,
        path: &str,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let http_address = cfg.http_addr.unwrap();
        let request = || reqwest::get(format!("http://{}{}", http_address, path));

        let mut backoff = backon::ExponentialBuilder::default()
            .with_min_delay(time::Duration::from_millis(200))
            .with_max_delay(time::Duration::from_secs(2))
            .with_factor(1.0)
            .with_max_times(8)
            .build();
        request.retry(&mut backoff).await
    }

    // Default [`RelayArgs`] used for testing.
    // Values are overridden in tests as needed.
    fn test_relay_args() -> super::RelayArgs {
        super::RelayArgs {
            data_dir: super::RelayDataDirArgs {
                data_dir: "".into(),
            },
            relay: super::RelayRelayArgs {
                http_address: "".into(),
                auto_p2p_key: false,
                p2p_relay_log_level: "info".into(),
                max_res_per_peer: 0,
                max_conns: 0,
                advertise_priv: false,
            },
            debug_monitoring: super::RelayDebugMonitoringArgs {
                monitor_addr: "".into(),
                debug_addr: "".into(),
            },
            p2p: super::RelayP2PArgs {
                relays: vec![],
                external_ip: None,
                external_host: None,
                tcp_addrs: vec![],
                udp_addrs: vec![],
                disable_reuseport: false,
            },
            log: super::RelayLogFlags {
                format: "console".into(),
                level: "error".into(),
                color: super::ConsoleColor::Disable,
                log_output_path: "".into(),
            },
            loki: super::RelayLokiArgs {
                loki_addresses: vec![],
                loki_service: "".into(),
            },
        }
    }
}
