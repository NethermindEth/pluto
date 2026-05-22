//! Shared helpers for CLI commands.

use std::str::FromStr;

use libp2p::{Multiaddr, multiaddr};

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
// TODO: wire `log-output-path` (Charon's `LogOutputPath`) into the file layer.
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

/// Parses a relay string as either a relay URL or a raw multiaddr.
pub fn parse_relay_addr(relay: &str) -> std::result::Result<Multiaddr, libp2p::multiaddr::Error> {
    multiaddr::from_url(relay).or_else(|_| Multiaddr::from_str(relay))
}
