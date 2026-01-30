//! # Pluto CLI
//!
//! Command-line interface for the Pluto distributed validator node.
//! This crate provides the CLI tools and commands for managing and operating
//! Pluto validator nodes.

use std::process::{ExitCode, Termination};

use clap::Parser;

mod cli;
mod commands;
mod error;

use cli::{Cli, Commands, CreateCommands};
use error::Result;

fn main() -> ExitResult {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Create(args) => match args.command {
            CreateCommands::Enr(args) => commands::create_enr::run(args),
        },
        Commands::Enr(args) => commands::enr::run(args),
        Commands::Version(args) => commands::version::run(args),
    };

    ExitResult(result)
}

struct ExitResult(Result<()>);

impl Termination for ExitResult {
    fn report(self) -> ExitCode {
        match self.0 {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("Error: {}", err);
                ExitCode::FAILURE
            }
        }
    }
}
