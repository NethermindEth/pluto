//! CLI structure and argument definitions.

use clap::{Parser, Subcommand};

use crate::commands::{enr::EnrArgs, version::VersionArgs};

/// Pluto - Proof of Stake Ethereum Distributed Validator Client
#[derive(Parser)]
#[command(
    name = "pluto",
    version,
    about = "Pluto - Proof of Stake Ethereum Distributed Validator Client",
    long_about = "Pluto enables the operation of Ethereum validators in a fault tolerant manner by splitting the validating keys across a group of trusted parties using threshold cryptography."
)]
pub struct Cli {
    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Available commands.
#[derive(Subcommand)]
pub enum Commands {
    #[command(
        about = "Print the ENR that identifies this client",
        long_about = "Prints an Ethereum Node Record (ENR) from this client's charon-enr-private-key. This serves as a public key that identifies this client to its peers."
    )]
    Enr(EnrArgs),

    #[command(about = "Print version and exit", long_about = "Output version info")]
    Version(VersionArgs),
    // Future commands will be added here:
    // Run(RunArgs),
    // Create(CreateArgs),
}
