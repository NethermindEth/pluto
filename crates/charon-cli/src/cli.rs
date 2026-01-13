//! CLI structure and argument definitions.

use clap::{Parser, Subcommand};

use crate::commands::{create_enr::CreateEnrArgs, enr::EnrArgs, version::VersionArgs};

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

    #[command(
        about = "Create artifacts for a distributed validator cluster",
        long_about = "Create artifacts for a distributed validator cluster. These commands can be used to facilitate the creation of a distributed validator cluster between a group of operators by performing a distributed key generation ceremony, or they can be used to create a local cluster for single operator use cases."
    )]
    Create(CreateArgs),

    #[command(about = "Print version and exit", long_about = "Output version info")]
    Version(VersionArgs),
    // Future commands will be added here:
    // Run(RunArgs),
}

/// Arguments for the create command
#[derive(clap::Args)]
pub struct CreateArgs {
    #[command(subcommand)]
    pub command: CreateCommands,
}

/// Create subcommands
#[derive(Subcommand)]
pub enum CreateCommands {
    /// Create an Ethereum Node Record (ENR) private key to identify this charon
    /// client
    Enr(CreateEnrArgs),
}
