//! Shared helpers for CLI commands.

use std::{collections::HashMap, path::PathBuf};

use pluto_p2p::config::RelayAddr;
use tracing::warn;

use crate::error::CliError;

/// Shared license notice shown by long-running commands.
pub const LICENSE: &str = concat!(
    "This software is licensed under the Maria DB Business Source License 1.1; ",
    "you may not use this software except in compliance with this license. You may obtain a ",
    "copy of this license at https://github.com/NethermindEth/pluto/blob/main/LICENSE"
);

/// Console color selection for terminal logging.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default)]
pub enum ConsoleColor {
    /// Automatically decide whether to use ANSI colors.
    #[default]
    Auto,
    /// Always use ANSI colors.
    Force,
    /// Never use ANSI colors.
    Disable,
}

/// Console log verbosity, matching the levels Charon accepts.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LogLevel {
    /// Everything, including per-duty detail.
    Debug,
    /// Normal operational events.
    #[default]
    Info,
    /// Only recoverable problems.
    Warn,
    /// Only failures.
    Error,
}

impl LogLevel {
    /// The `EnvFilter` directive this level maps to.
    fn as_directive(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Logging and Loki flags, accepted by every subcommand.
///
/// These are `global`, so they parse identically before or after the
/// subcommand and are readable from the root [`crate::cli::Cli`] before any
/// command-specific config conversion runs. That ordering is what lets
/// `main` install the subscriber before validation starts.
// TODO: wire `log-output-path` (file output) and `log-format` (logfmt/json)
// into the tracing layers. `pluto_tracing` supports console + Loki only, so
// these flags are accepted but not yet applied.
#[derive(clap::Args, Clone, Debug)]
#[command(next_help_heading = "Logging")]
pub struct TracingArgs {
    #[arg(
        long = "log-format",
        env = "CHARON_LOG_FORMAT",
        default_value = "console",
        global = true,
        display_order = 1000,
        help = "Log format; console, logfmt or json"
    )]
    pub log_format: String,

    #[arg(
        long = "log-level",
        env = "CHARON_LOG_LEVEL",
        default_value = "info",
        global = true,
        ignore_case = true,
        display_order = 1001,
        help = "Log level; debug, info, warn or error"
    )]
    pub log_level: LogLevel,

    #[arg(
        long = "log-color",
        env = "CHARON_LOG_COLOR",
        default_value = "auto",
        global = true,
        ignore_case = true,
        display_order = 1002,
        help = "Log color; auto, force, disable."
    )]
    pub log_color: ConsoleColor,

    #[arg(
        long = "log-output-path",
        env = "CHARON_LOG_OUTPUT_PATH",
        global = true,
        display_order = 1003,
        help = "Path in which to write on-disk logs."
    )]
    pub log_output_path: Option<PathBuf>,

    #[arg(
        long = "loki-addresses",
        env = "CHARON_LOKI_ADDRESSES",
        value_delimiter = ',',
        global = true,
        display_order = 1004,
        help = "Enables sending of logfmt structured logs to these Loki log aggregation server addresses. This is in addition to normal stderr logs."
    )]
    pub loki_addresses: Vec<String>,

    #[arg(
        long = "loki-service",
        env = "CHARON_LOKI_SERVICE",
        default_value = "pluto",
        global = true,
        display_order = 1005,
        help = "Service label sent with logs to Loki."
    )]
    pub loki_service: String,
}

impl TracingArgs {
    /// Builds the subscriber configuration.
    ///
    /// Emits nothing: this runs before the subscriber exists, so any diagnostic
    /// it produced would be dropped. Deferred warnings live in
    /// [`TracingArgs::warn_unused`].
    pub fn tracing_config(&self) -> pluto_tracing::TracingConfig {
        let ansi = match self.log_color {
            ConsoleColor::Auto => std::env::var_os("NO_COLOR").is_none(),
            ConsoleColor::Force => true,
            ConsoleColor::Disable => false,
        };

        let mut builder = pluto_tracing::TracingConfig::builder()
            .with_default_console()
            .console_with_ansi(ansi)
            .override_env_filter(self.log_level.as_directive());

        // Only the first address is used; see `warn_unused`.
        if let Some(loki_url) = self.loki_addresses.first() {
            builder = builder.loki(pluto_tracing::LokiConfig {
                loki_url: loki_url.clone(),
                labels: HashMap::from([("service".to_string(), self.loki_service.clone())]),
                extra_fields: HashMap::new(),
            });
        }

        builder.build()
    }

    /// Reports flag values that were accepted but not applied.
    ///
    /// Call once the subscriber is installed.
    pub fn warn_unused(&self) {
        // Charon fans logs out to every entry in `loki-addresses`, but
        // `pluto_tracing::TracingConfig` supports a single Loki layer today.
        let ignored = self.loki_addresses.len().saturating_sub(1);
        if ignored > 0 {
            warn!(
                ignored,
                "Additional --loki-addresses ignored; only the first is used"
            );
        }
    }
}

/// Parses the configured relay addresses, warning about insecure ones.
///
/// Exactly one empty value (`--p2p-relays=""`) means "no relays". That is the
/// only accepted empty form: every other empty is an error, including interior
/// ones (`a,,b`, `,`) and an empty value repeated or mixed with real addresses
/// (`--p2p-relays="" --p2p-relays=https://x`, which flattens to the same list
/// as `--p2p-relays=,https://x` and so cannot be told apart from it). Each of
/// those is a field that was meant to hold an address; dropping them would
/// silently leave fewer relays configured than requested.
pub fn parse_relay_addrs(relays: &[String]) -> std::result::Result<Vec<RelayAddr>, CliError> {
    if let [only] = relays
        && only.is_empty()
    {
        return Ok(Vec::new());
    }

    let mut parsed = Vec::with_capacity(relays.len());

    for relay in relays {
        let addr: RelayAddr = relay.parse().map_err(|source| CliError::InvalidRelayAddr {
            addr: relay.clone(),
            source,
        })?;

        // Warn once per plain-http relay while validating flags, before the P2P
        // stack starts resolving them.
        if addr.is_insecure_url() {
            warn!(address = %relay, "Insecure relay address provided, not HTTPS");
        }

        parsed.push(addr);
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;

    #[test]
    fn log_flags_accept_any_casing() {
        // Charon takes these from env as often as from the command line, where
        // `CHARON_LOG_LEVEL=INFO` is idiomatic.
        for level in ["debug", "DEBUG", "Debug"] {
            let cli = <Cli as clap::Parser>::try_parse_from([
                "pluto",
                "enr",
                &format!("--log-level={level}"),
            ])
            .unwrap_or_else(|err| panic!("--log-level={level} should parse: {err}"));

            assert_eq!(
                cli.tracing.tracing_config().override_env_filter.as_deref(),
                Some("debug")
            );
        }

        for color in ["disable", "DISABLE", "Disable"] {
            let cli = <Cli as clap::Parser>::try_parse_from([
                "pluto",
                "enr",
                &format!("--log-color={color}"),
            ])
            .unwrap_or_else(|err| panic!("--log-color={color} should parse: {err}"));

            assert!(
                !cli.tracing
                    .tracing_config()
                    .console
                    .expect("console")
                    .with_ansi
            );
        }
    }

    #[test]
    fn log_level_still_rejects_values_charon_does_not_accept() {
        // A free-form level would parse as an `EnvFilter` target directive and
        // silently disable all logging.
        let err =
            match <Cli as clap::Parser>::try_parse_from(["pluto", "enr", "--log-level=nonsense"]) {
                Ok(_) => panic!("bogus level should be rejected"),
                Err(err) => err,
            };

        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
    }

    // Per-address parsing is covered by `RelayAddr`'s own tests; what is left
    // to check here is the empty-value contract and the error wrapping.

    #[test]
    fn treats_a_lone_empty_value_as_no_relays() {
        // `--p2p-relays=""` is how relaying is turned off.
        assert!(
            parse_relay_addrs(&["".to_string()])
                .expect("relays")
                .is_empty()
        );
        assert!(parse_relay_addrs(&[]).expect("relays").is_empty());
    }

    #[test]
    fn rejects_interior_empty_values() {
        // `a,,b` splits to ["a", "", "b"] and `,` to ["", ""]. Dropping those
        // empties would silently turn a typo'd flag into fewer relays, or none
        // at all.
        for relays in [
            vec!["https://relay.one".to_string(), String::new()],
            vec![
                "https://relay.one".to_string(),
                String::new(),
                "https://relay.two".to_string(),
            ],
            vec![String::new(), String::new()],
        ] {
            let err = parse_relay_addrs(&relays).expect_err("empty entry should be rejected");

            assert!(
                err.to_string().contains("empty relay address"),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn rejects_invalid_relays() {
        let err = parse_relay_addrs(&["not-an-address".to_string()])
            .expect_err("invalid relay should be rejected");

        // The offending address must be named; the old error was just
        // "Invalid multiaddr: invalid multiaddr".
        assert!(
            err.to_string().contains("not-an-address"),
            "unexpected error: {err}"
        );
    }
}
