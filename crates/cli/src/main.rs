//! # Pluto CLI
//!
//! Command-line interface for the Pluto distributed validator node.
//! This crate provides the CLI tools and commands for managing and operating
//! Pluto validator nodes.

use clap::Parser;

mod cli;
mod commands;
mod error;

use cli::{Cli, Commands, CreateCommands};
use error::ExitResult;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> ExitResult {
    let cli = Cli::parse();

    // Top level cancellation token for graceful shutdown on Ctrl+C
    let ct = CancellationToken::new();
    tokio::spawn({
        let ct = ct.clone();
        async move {
            let _ = tokio::signal::ctrl_c().await;
            ct.cancel();
        }
    });

    let result = match cli.command {
        Commands::Create(args) => match args.command {
            CreateCommands::Enr(args) => commands::create_enr::run(args),
        },
        Commands::Enr(args) => commands::enr::run(args),
        Commands::Version(args) => commands::version::run(args),
        Commands::Relay(args) => commands::relay::run(args, ct.child_token()).await,
    };

    ExitResult(result)
}
