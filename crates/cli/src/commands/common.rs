//! Shared helpers for CLI commands.

use std::str::FromStr;

use libp2p::{Multiaddr, multiaddr};

/// Shared license notice shown by long-running commands.
pub const LICENSE: &str = concat!(
    "This software is licensed under the Maria DB Business Source License 1.1; ",
    "you may not use this software except in compliance with this license. You may obtain a ",
    "copy of this license at https://github.com/NethermindEth/pluto/blob/main/LICENSE"
);

/// Shared default relay endpoints used by Charon-compatible commands.
pub const DEFAULT_RELAYS: [&str; 3] = [
    "https://0.relay.obol.tech",
    "https://2.relay.obol.dev",
    "https://1.relay.obol.tech",
];

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

/// Builds a console tracing configuration for CLI commands.
pub fn build_console_tracing_config(
    level: impl Into<String>,
    color: &ConsoleColor,
) -> pluto_tracing::TracingConfig {
    let mut builder = pluto_tracing::TracingConfig::builder().with_default_console();

    builder = match color {
        ConsoleColor::Auto => builder.console_with_ansi(std::env::var("NO_COLOR").is_err()),
        ConsoleColor::Force => builder.console_with_ansi(true),
        ConsoleColor::Disable => builder.console_with_ansi(false),
    };

    builder.override_env_filter(level.into()).build()
}

/// Parses a relay string as either a relay URL or a raw multiaddr.
pub fn parse_relay_addr(relay: &str) -> std::result::Result<Multiaddr, libp2p::multiaddr::Error> {
    multiaddr::from_url(relay).or_else(|_| Multiaddr::from_str(relay))
}
