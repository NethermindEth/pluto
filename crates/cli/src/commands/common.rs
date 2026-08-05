//! Shared helpers for CLI commands.

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
/// A single empty value (`--p2p-relays=""`) means "no relays", and that is the
/// only empty form accepted. Interior empties (`a,,b`, `,`) are CSV fields that
/// were meant to hold an address, so they are rejected rather than dropped —
/// dropping them would silently leave fewer relays configured than requested.
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

    fn parse_one(relay: &str) -> RelayAddr {
        let parsed = parse_relay_addrs(&[relay.to_string()]).expect("relay should parse");

        assert_eq!(parsed.len(), 1);

        parsed.into_iter().next().expect("one relay")
    }

    #[test]
    fn parses_relay_url_forms() {
        // The reported regression: a relay URL with a path is accepted and the
        // path survives.
        assert_eq!(
            parse_one("http://relay:3640/enr"),
            RelayAddr::Url("http://relay:3640/enr".parse().expect("url"))
        );
        assert_eq!(
            parse_one("http://relay:3640"),
            RelayAddr::Url("http://relay:3640".parse().expect("url"))
        );
        assert_eq!(
            parse_one("https://relay.example.org/enr"),
            RelayAddr::Url("https://relay.example.org/enr".parse().expect("url"))
        );
    }

    #[test]
    fn parses_raw_multiaddr() {
        let relay =
            "/ip4/127.0.0.1/tcp/3610/p2p/16Uiu2HAm7ULrTMdiEmQCJ2N9nsuGvfUDvfDGgHXJ4vNjrCwCzGDs";

        assert_eq!(
            parse_one(relay),
            RelayAddr::Multiaddr(relay.parse().expect("multiaddr"))
        );
    }

    #[test]
    fn flags_only_plain_http_relays_as_insecure() {
        assert!(parse_one("http://relay:3640/enr").is_insecure_url());
        assert!(!parse_one("https://relay.example.org/enr").is_insecure_url());
    }

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
