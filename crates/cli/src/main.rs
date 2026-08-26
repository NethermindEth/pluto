//! # Pluto CLI
//!
//! Command-line interface for the Pluto distributed validator node.
//! This crate provides the CLI tools and commands for managing and operating
//! Pluto validator nodes.

use crate::error::CliError;
use clap::FromArgMatches;
use cli::{AlphaCommands, Cli, Commands, CreateCommands, TestCommands, UnsafeCommands};
use std::process::ExitCode;
use tokio_util::sync::CancellationToken;
use tracing::error;

mod ascii;
mod cli;
mod commands;
mod duration;
mod error;

#[tokio::main]
async fn main() -> ExitCode {
    let matches = cli::build_command().get_matches();

    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };

    let loki = match pluto_tracing::init(&cli.tracing.tracing_config()) {
        Ok(loki) => loki,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };

    let result = run(cli.command).await;

    let exit = match &result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!(error = %err, "command exited with error");
            ExitCode::FAILURE
        }
    };

    if let Some(loki) = loki {
        loki.shutdown().await;
    }

    exit
}

async fn run(command: Commands) -> std::result::Result<(), CliError> {
    // Top level cancellation token for graceful shutdown on Ctrl+C / SIGTERM.
    let ct = CancellationToken::new();
    tokio::spawn({
        let ct = ct.clone();
        async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigterm = match signal(SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = tokio::signal::ctrl_c().await;
                        ct.cancel();
                        return;
                    }
                };
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            ct.cancel();
        }
    });

    let mut stdout = std::io::stdout();
    match command {
        Commands::Create(args) => match args.command {
            CreateCommands::Dkg(args) => commands::create_dkg::run(*args).await,
            CreateCommands::Enr(args) => commands::create_enr::run(args),
            CreateCommands::Cluster(args) => {
                commands::create_cluster::run(&mut stdout, *args).await
            }
        },
        Commands::Enr(args) => commands::enr::run(args),
        Commands::Version(args) => commands::version::run(args),
        Commands::Dkg(args) => {
            let config: pluto_dkg::dkg::Config = (*args).try_into()?;
            commands::dkg::run(config, ct).await
        }
        Commands::Relay(args) => {
            let config: pluto_relay_server::config::Config = (*args).clone().try_into()?;
            commands::relay::run(config, ct).await
        }
        Commands::Run(args) => {
            let config: commands::run::RunConfig = (*args).try_into()?;
            commands::run::run(config, ct).await
        }
        Commands::Unsafe(args) => match args.command {
            UnsafeCommands::Run(args) => {
                let config: commands::run::RunConfig = (*args).try_into()?;
                commands::run::run(config, ct).await
            }
        },
        Commands::Alpha(args) => match args.command {
            AlphaCommands::Test(args) => match args.command {
                TestCommands::Peers(args) => commands::test::peers::run(args, &mut stdout, ct)
                    .await
                    .map(|_| ()),
                TestCommands::Beacon(args) => commands::test::beacon::run(args, &mut stdout, ct)
                    .await
                    .map(|_| ()),
                TestCommands::Validator(args) => {
                    commands::test::validator::run(args, &mut stdout, ct)
                        .await
                        .map(|_| ())
                }
                TestCommands::Mev(args) => commands::test::mev::run(args, &mut stdout, ct)
                    .await
                    .map(|_| ()),
                TestCommands::Infra(args) => commands::test::infra::run(args, &mut stdout, ct)
                    .await
                    .map(|_| ()),
                TestCommands::All(args) => commands::test::all::run(*args, &mut stdout).await,
            },
        },
    }
}
