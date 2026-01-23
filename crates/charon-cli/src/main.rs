//! # Pluto CLI
//!
//! Command-line interface for the Pluto distributed validator node.
//! This crate provides the CLI tools and commands for managing and operating
//! Pluto validator nodes.

use clap::Parser;

mod ascii;
mod cli;
mod commands;
mod error;

use cli::{Cli, Commands, CreateCommands, TestCommands};
use error::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Create(args) => match args.command {
            CreateCommands::Enr(args) => commands::create_enr::run(args),
        },
        Commands::Enr(args) => commands::enr::run(args),
        Commands::Version(args) => commands::version::run(args),
        Commands::Test(args) => {
            let mut stdout = std::io::stdout();
            match args.command {
                TestCommands::Peers(args) => {
                    commands::test::peers::run(args, &mut stdout).await?;
                    Ok(())
                }
                TestCommands::Beacon(args) => {
                    commands::test::beacon::run(args, &mut stdout).await?;
                    Ok(())
                }
                TestCommands::Validator(args) => {
                    commands::test::validator::run(args, &mut stdout).await?;
                    Ok(())
                }
                TestCommands::Mev(args) => {
                    commands::test::mev::run(args, &mut stdout).await?;
                    Ok(())
                }
                TestCommands::Infra(args) => {
                    commands::test::infra::run(args, &mut stdout).await?;
                    Ok(())
                }
                TestCommands::All(args) => commands::test::all::run(args, &mut stdout).await,
            }
        }
    }
}
