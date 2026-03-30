//! # Pluto CLI
//!
//! Command-line interface for the Pluto distributed validator node.
//! This crate provides the CLI tools and commands for managing and operating
//! Pluto validator nodes.

use clap::{CommandFactory, FromArgMatches};

mod ascii;
mod cli;
mod commands;
mod duration;
mod error;

use cli::{AlphaCommands, Cli, Commands, CreateCommands, TestCommands};

use crate::error::ExitResult;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> ExitResult {
    let mut builder = pluto_tracing::TracingConfig::builder();
    builder = builder.with_default_console();
    builder.build();

    let cmd = commands::test::update_test_cases_help(Cli::command());
    let matches = cmd.get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => return ExitResult(Err(error::CliError::Other(e.to_string()))),
    };

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
        Commands::Relay(args) => commands::relay::run(*args, ct.child_token()).await,
        Commands::Alpha(args) => match args.command {
            AlphaCommands::Test(args) => {
                let mut stdout = std::io::stdout();
                match args.command {
                    TestCommands::Peers(args) => commands::test::peers::run(args, &mut stdout)
                        .await
                        .map(|_| ()),
                    TestCommands::Beacon(args) => {
                        commands::test::beacon::run(args, &mut stdout, ct.child_token())
                            .await
                            .map(|_| ())
                    }
                    TestCommands::Validator(args) => {
                        commands::test::validator::run(args, &mut stdout)
                            .await
                            .map(|_| ())
                    }
                    TestCommands::Mev(args) => commands::test::mev::run(args, &mut stdout)
                        .await
                        .map(|_| ()),
                    TestCommands::Infra(args) => commands::test::infra::run(args, &mut stdout)
                        .await
                        .map(|_| ()),
                    TestCommands::All(args) => commands::test::all::run(*args, &mut stdout).await,
                }
            }
        },
    };

    ExitResult(result)
}
