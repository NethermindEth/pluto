//! # Pluto CLI
//!
//! Command-line interface for the Pluto distributed validator node.
//! This crate provides the CLI tools and commands for managing and operating
//! Pluto validator nodes.

use crate::error::CliError;
use clap::{CommandFactory, FromArgMatches};
use cli::{AlphaCommands, Cli, Commands, CreateCommands, TestCommands};
use std::process::ExitCode;
use tokio_util::sync::CancellationToken;

mod ascii;
mod cli;
mod commands;
mod duration;
mod error;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {}", err);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> std::result::Result<(), CliError> {
    let cmd = commands::test::update_test_cases_help(Cli::command());
    let matches = cmd.get_matches();
    let cli = Cli::from_arg_matches(&matches)?;

    // Top level cancellation token for graceful shutdown on Ctrl+C
    let ct = CancellationToken::new();
    tokio::spawn({
        let ct = ct.clone();
        async move {
            let _ = tokio::signal::ctrl_c().await;
            ct.cancel();
        }
    });

    match cli.command {
        Commands::Create(args) => match args.command {
            CreateCommands::Enr(args) => commands::create_enr::run(args),
            CreateCommands::Cluster(args) => {
                let mut stdout = std::io::stdout();
                commands::create_cluster::run(&mut stdout, *args).await
            }
        },
        Commands::Enr(args) => commands::enr::run(args),
        Commands::Version(args) => commands::version::run(args),
        Commands::Relay(args) => {
            let config: pluto_relay_server::config::Config = (*args).clone().try_into()?;
            pluto_tracing::init(&config.log_config).expect("Failed to initialize tracing");
            commands::relay::run(config, ct.clone()).await
        }
        Commands::Alpha(args) => match args.command {
            AlphaCommands::Test(args) => {
                let mut stdout = std::io::stdout();
                match args.command {
                    TestCommands::Peers(args) => commands::test::peers::run(args, &mut stdout)
                        .await
                        .map(|_| ()),
                    TestCommands::Beacon(args) => {
                        pluto_tracing::init(&pluto_tracing::TracingConfig::default())
                            .expect("Failed to initialize tracing");
                        commands::test::beacon::run(args, &mut stdout, ct.clone())
                            .await
                            .map(|_| ())
                    }
                    TestCommands::Validator(args) => {
                        commands::test::validator::run(args, &mut stdout)
                            .await
                            .map(|_| ())
                    }
                    TestCommands::Mev(args) => commands::test::mev::run(args, &mut stdout, &ct)
                        .await
                        .map(|_| ()),
                    TestCommands::Infra(args) => commands::test::infra::run(args, &mut stdout)
                        .await
                        .map(|_| ()),
                    TestCommands::All(args) => commands::test::all::run(*args, &mut stdout).await,
                }
            }
        },
    }
}
