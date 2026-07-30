//! CLI structure and argument definitions.

use clap::{Parser, Subcommand};

use crate::commands::{
    create_cluster::CreateClusterArgs,
    create_dkg::CreateDkgArgs,
    create_enr::CreateEnrArgs,
    dkg::DkgArgs,
    enr::EnrArgs,
    relay::RelayArgs,
    run::{RunArgs, RunUnsafeArgs},
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
        about = "Participate in a Distributed Key Generation ceremony",
        long_about = "Participate in a distributed key generation ceremony for a specific cluster definition that creates distributed validator key shares and a final cluster lock configuration. Note that all other cluster operators should run this command at the same time."
    )]
    Dkg(Box<DkgArgs>),

    #[command(
        about = "Alpha subcommands provide early access to in-development features",
        long_about = "Alpha subcommands represent features that are currently under development. They're not yet released for general use, but offer a glimpse into future functionalities planned for the distributed cluster system."
    )]
    Alpha(AlphaArgs),

    #[command(
        about = "Run the pluto middleware client",
        long_about = "Starts the long-running Pluto middleware process to perform distributed validator duties."
    )]
    Run(Box<RunArgs>),

    #[command(
        hide = true,
        about = "Unsafe subcommands provides regular pluto commands for testing purposes",
        long_about = "Unsafe subcommands is a group of subcommands that includes both normal and test flags. It is intended for internal testing of the Pluto client and should be used with caution."
    )]
    Unsafe(UnsafeArgs),
}

/// Arguments for the hidden unsafe command.
#[derive(clap::Args)]
pub struct UnsafeArgs {
    #[command(subcommand)]
    pub command: UnsafeCommands,
}

/// Unsafe subcommands (hidden; for internal testing).
#[derive(Subcommand)]
pub enum UnsafeCommands {
    #[command(
        about = "Run the pluto middleware client",
        long_about = "Starts the long-running Pluto middleware process to perform distributed validator duties."
    )]
    Run(Box<RunUnsafeArgs>),
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

/// Builds the fully-configured root command.
///
/// Use this instead of [`Cli::command`] anywhere the command is rendered or
/// parsed, so every entrypoint gets the same hardening.
pub fn build_command() -> clap::Command {
    build_command_with(&|name| std::env::var_os(name))
}

/// [`build_command`] with an injectable environment lookup.
///
/// Tests build through this so they exercise the real assembly pipeline —
/// including the empty-env handling and help hardening — rather than calling a
/// single transform in isolation, which would still pass if a transform were
/// dropped from the pipeline.
fn build_command_with(
    lookup: &impl Fn(&std::ffi::OsStr) -> Option<std::ffi::OsString>,
) -> clap::Command {
    let cmd =
        crate::commands::test::update_test_cases_help(<Cli as clap::CommandFactory>::command());

    hide_env_values(ignore_empty_env_with(cmd, lookup))
}

/// Treats a `CHARON_*` variable that is set but empty as unset, for every flag
/// in the tree.
///
/// Charon's CLI resolves env vars through Viper, whose `getEnv` returns
/// "not found" for an empty value unless `AllowEmptyEnv` is set — which charon
/// does not set. clap instead treats `VAR=` as the literal value `""`, which
/// diverges in three ways an operator hits with common empty placeholders
/// (`CHARON_X=` in a compose file or CI matrix):
///   - numeric flags fail parsing outright ("cannot parse integer from empty
///     string") where charon falls back to the default;
///   - comma-delimited list flags become a single empty element rather than an
///     empty list;
///   - string flags silently take `""` instead of their default, which can
///     select a different code path.
///
/// Resolved centrally here so it holds for every command and every value type,
/// rather than per-flag at each use site.
fn ignore_empty_env_with(
    cmd: clap::Command,
    lookup: &impl Fn(&std::ffi::OsStr) -> Option<std::ffi::OsString>,
) -> clap::Command {
    cmd.mut_args(|arg| {
        let is_empty = arg
            .get_env()
            .is_some_and(|name| lookup(name).is_some_and(|value| value.is_empty()));

        if is_empty {
            arg.env(clap::builder::Resettable::Reset)
        } else {
            arg
        }
    })
    .mut_subcommands(|sub| ignore_empty_env_with(sub, lookup))
}

/// Suppresses environment variable *values* in `--help`, recursively for every
/// subcommand.
///
/// clap renders `[env: VAR=value]` by default, which prints the caller's actual
/// value — including secrets like `CHARON_KEYMANAGER_AUTH_TOKEN(S)` — into
/// terminals, CI logs and support captures. With this applied help shows only
/// `[env: VAR]`. Charon does not expose env values in its help either (its
/// viper env binding is invisible to cobra's help renderer), so this is also
/// the parity behaviour.
fn hide_env_values(cmd: clap::Command) -> clap::Command {
    cmd.mut_args(|arg| arg.hide_env_values(true))
        .mut_subcommands(hide_env_values)
}

#[cfg(test)]
mod tests {
    use super::build_command;

    /// Recursively visits every command in the tree.
    fn for_each_command(cmd: &clap::Command, path: &str, f: &mut impl FnMut(&clap::Command, &str)) {
        f(cmd, path);
        for sub in cmd.get_subcommands() {
            let child = format!("{path} {}", sub.get_name());
            for_each_command(sub, &child, f);
        }
    }

    /// `--help` must never print the VALUE of an env var: clap's default
    /// `[env: VAR=value]` rendering would leak secrets (e.g. the keymanager
    /// bearer tokens) into terminals, CI logs and support captures.
    ///
    /// Asserted structurally over the whole command tree — rather than by
    /// setting a sentinel env var, which this crate cannot do (`unsafe_code`
    /// is forbidden, and `std::env::set_var` is unsafe since Rust 2024) — so a
    /// new subcommand or flag cannot reintroduce the leak.
    #[test]
    fn every_env_bound_flag_hides_its_env_value() {
        let root = build_command();
        let mut checked = 0usize;

        for_each_command(&root, "pluto", &mut |cmd, path| {
            for arg in cmd.get_arguments() {
                if arg.get_env().is_none() {
                    continue;
                }

                checked += 1;
                assert!(
                    arg.is_hide_env_values_set(),
                    "`{path}` flag --{} renders its env value in help",
                    arg.get_long().unwrap_or("<positional>"),
                );
            }
        });

        assert!(checked > 0, "expected env-bound flags; the walk is broken");
    }
    /// An empty `CHARON_*` value must be stripped from the arg's env binding by
    /// the assembly pipeline, so clap never sees `""` as a provided value.
    ///
    /// This is the fast structural half of the check; the behavioural half
    /// (numeric/bool/list/string actually parsing to their defaults) lives in
    /// `tests/empty_env.rs`, which spawns the binary so a real environment
    /// reaches clap. Both are needed: this one catches the transform being
    /// dropped from the pipeline, that one catches it not working.
    #[test]
    fn empty_env_strips_bindings_across_the_whole_tree() {
        let empty_env = |_: &std::ffi::OsStr| Some(std::ffi::OsString::new());
        let root = super::build_command_with(&empty_env);
        let mut checked = 0usize;

        for_each_command(&root, "pluto", &mut |cmd, path| {
            for arg in cmd.get_arguments() {
                checked += 1;
                assert!(
                    arg.get_env().is_none(),
                    "`{path}` flag --{} kept its env binding for an empty value",
                    arg.get_long().unwrap_or("<positional>"),
                );
            }
        });

        assert!(checked > 0, "expected flags; the walk is broken");
    }

    /// A non-empty env value must keep its binding, so the empty-value handling
    /// does not disable env support altogether.
    #[test]
    fn non_empty_env_binding_is_retained() {
        let set_env = |_: &std::ffi::OsStr| Some(std::ffi::OsString::from("value"));
        let cmd = super::build_command_with(&set_env);
        let cluster = cmd
            .find_subcommand("create")
            .expect("create")
            .find_subcommand("cluster")
            .expect("cluster")
            .clone();

        let bound = cluster
            .get_arguments()
            .filter(|a| a.get_env().is_some())
            .count();
        assert!(bound > 0, "non-empty env values must keep their bindings");
    }

    /// Hiding values must not hide which env var configures a flag: the names
    /// stay in help output.
    #[test]
    fn help_still_documents_env_var_names() {
        let create = build_command()
            .find_subcommand("create")
            .expect("create subcommand")
            .clone();
        let help = create
            .find_subcommand("cluster")
            .expect("create cluster subcommand")
            .clone()
            .render_long_help()
            .to_string();

        assert!(
            help.contains("[env: CHARON_KEYMANAGER_AUTH_TOKENS]"),
            "{help}"
        );
        assert!(help.contains("[env: CHARON_CLUSTER_DIR]"), "{help}");
    }
}
