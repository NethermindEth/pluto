//! Shared helpers for CLI commands.

use std::fmt;

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

/// The log levels `tracing_subscriber`'s `EnvFilter` understands.
///
/// `Display` renders the directive spelling, so these compose into a filter
/// string that always parses.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        })
    }
}

/// Builds a tracing configuration for CLI commands, optionally enabling Loki.
///
/// `loki` is `Some` when the caller wants events forwarded to a Loki endpoint
/// (e.g. via `--loki-addresses`), and `None` for commands that only need
/// console output.
// TODO: wire `log-output-path` (file output) and `log-format` (logfmt/json)
// into the tracing layers. `pluto_tracing` supports console + Loki only, so
// `run`/`dkg`/`relay` accept these flags but do not yet apply them.
pub fn build_console_tracing_config(
    level: impl Into<String>,
    color: &ConsoleColor,
    loki: Option<pluto_tracing::LokiConfig>,
) -> pluto_tracing::TracingConfig {
    let mut builder = pluto_tracing::TracingConfig::builder().with_default_console();

    builder = match color {
        ConsoleColor::Auto => builder.console_with_ansi(std::env::var("NO_COLOR").is_err()),
        ConsoleColor::Force => builder.console_with_ansi(true),
        ConsoleColor::Disable => builder.console_with_ansi(false),
    };

    if let Some(loki) = loki {
        builder = builder.loki(loki);
    }

    builder.override_env_filter(level.into()).build()
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
