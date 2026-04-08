//! CLI structure and argument definitions.

use clap::{Parser, Subcommand};

use crate::commands::{
    create_cluster::CreateClusterArgs,
    create_dkg::CreateDkgArgs,
    create_enr::CreateEnrArgs,
    enr::EnrArgs,
    relay::RelayArgs,
    test::{
        all::TestAllArgs, beacon::TestBeaconArgs, infra::TestInfraArgs, mev::TestMevArgs,
        peers::TestPeersArgs, validator::TestValidatorArgs,
    },
    version::VersionArgs,
};

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
        long_about = "Prints an Ethereum Node Record (ENR) from this client's pluto-enr-private-key. This serves as a public key that identifies this client to its peers."
    )]
    Enr(EnrArgs),

    #[command(
        about = "Create artifacts for a distributed validator cluster",
        long_about = "Create artifacts for a distributed validator cluster. These commands can be used to facilitate the creation of a distributed validator cluster between a group of operators by performing a distributed key generation ceremony, or they can be used to create a local cluster for single operator use cases."
    )]
    Create(Box<CreateArgs>),

    #[command(about = "Print version and exit", long_about = "Output version info")]
    Version(VersionArgs),

    #[command(
        about = "Start a libp2p relay server",
        long_about = "Starts a libp2p circuit relay that charon clients can use to discover and connect to their peers."
    )]
    Relay(Box<RelayArgs>),

    #[command(
        about = "Alpha subcommands provide early access to in-development features",
        long_about = "Alpha subcommands represent features that are currently under development. They're not yet released for general use, but offer a glimpse into future functionalities planned for the distributed cluster system."
    )]
    Alpha(AlphaArgs),
}

/// Arguments for the alpha command
#[derive(clap::Args)]
pub struct AlphaArgs {
    #[command(subcommand)]
    pub command: AlphaCommands,
}

/// Alpha subcommands
#[derive(clap::Subcommand)]
pub enum AlphaCommands {
    #[command(
        about = "Test subcommands provide test suite to evaluate current cluster setup",
        long_about = "Test subcommands provide test suite to evaluate current cluster setup. The full validator stack can be tested - charon peers, consensus layer, validator client, MEV. Current machine's infra can be examined as well."
    )]
    Test(Box<TestArgs>),
}

/// Arguments for the test command
#[derive(clap::Args)]
pub struct TestArgs {
    #[command(subcommand)]
    pub command: TestCommands,
}

/// Test subcommands
#[derive(clap::Subcommand)]
pub enum TestCommands {
    #[command(
        about = "Run multiple tests towards peer nodes",
        long_about = "Run multiple tests towards peer nodes. Verify that Charon can efficiently interact with Validator Client."
    )]
    Peers(TestPeersArgs),

    #[command(
        about = "Run multiple tests towards beacon nodes",
        long_about = "Run multiple tests towards beacon nodes. Verify that Charon can efficiently interact with Beacon Node(s)."
    )]
    Beacon(TestBeaconArgs),

    #[command(
        about = "Run multiple tests towards validator client",
        long_about = "Run multiple tests towards validator client. Verify that Charon can efficiently interact with its validator client."
    )]
    Validator(TestValidatorArgs),

    #[command(
        about = "Run multiple tests towards MEV relays",
        long_about = "Run multiple tests towards MEV relays. Verify that Charon can efficiently interact with MEV relay(s)."
    )]
    Mev(TestMevArgs),

    #[command(
        about = "Run multiple hardware and internet connectivity tests",
        long_about = "Run multiple hardware and internet connectivity tests. Verify that Charon is running on host with sufficient capabilities."
    )]
    Infra(TestInfraArgs),

    #[command(
        about = "Run tests towards peer nodes, beacon nodes, validator client, MEV relays, own hardware and internet connectivity.",
        long_about = "Run tests towards peer nodes, beacon nodes, validator client, MEV relays, own hardware and internet connectivity. Verify that Pluto can efficiently do its duties on the tested setup."
    )]
    All(Box<TestAllArgs>),
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
    /// Create a cluster definition file for a new Distributed Key Generation
    /// ceremony
    Dkg(Box<CreateDkgArgs>),

    /// Create an Ethereum Node Record (ENR) private key to identify this charon
    /// client
    Enr(CreateEnrArgs),

    #[command(
        about = "Create private keys and configuration files needed to run a distributed validator cluster locally",
        long_about = "Creates a local charon cluster configuration including validator keys, charon p2p keys, cluster-lock.json and deposit-data.json file(s). See flags for supported features."
    )]
    Cluster(Box<CreateClusterArgs>),
}
