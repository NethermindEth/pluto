//! `pluto exit` command implementations.
//!
//! Ports Charon's `cmd/exit.go` (the parent command and its shared flag set)
//! and `cmd/exit_delete.go` (the `delete` subcommand).

use std::{path::PathBuf, time::Duration};

use pluto_app::obolapi::{Client, ClientOptions, ObolApiError};
use tracing::{info, warn};

use crate::error::{CliError, Result};

/// Arguments for `pluto exit delete`.
///
/// Mirrors the flag subset Charon's `newDeleteExitCmd` binds through
/// `bindExitFlags`, in the same order.
#[derive(clap::Args, Clone, Debug)]
pub struct ExitDeleteArgs {
    #[arg(
        long = "publish-address",
        env = "CHARON_PUBLISH_ADDRESS",
        default_value = "https://api.obol.tech/v1",
        help = "The URL of the remote API."
    )]
    pub publish_address: String,

    #[arg(
        long = "private-key-file",
        env = "CHARON_PRIVATE_KEY_FILE",
        default_value = ".charon/charon-enr-private-key",
        help = "The path to the charon enr private key file. "
    )]
    pub private_key_file: PathBuf,

    #[arg(
        long = "lock-file",
        env = "CHARON_LOCK_FILE",
        default_value = ".charon/cluster-lock.json",
        help = "The path to the cluster lock file defining the distributed validator cluster."
    )]
    pub lock_file: PathBuf,

    /// `None` means the flag was not provided, which is what Charon's
    /// `Flags().Lookup(...).Changed` check distinguishes.
    #[arg(
        long = "validator-public-key",
        env = "CHARON_VALIDATOR_PUBLIC_KEY",
        help = "Public key of the validator to exit, must be present in the cluster lock manifest. If --validator-index is also provided, validator liveliness won't be checked on the beacon chain."
    )]
    pub validator_public_key: Option<String>,

    #[arg(
        long = "all",
        env = "CHARON_ALL",
        help = "Exit all currently active validators in the cluster."
    )]
    pub all: bool,

    #[arg(
        long = "publish-timeout",
        env = "CHARON_PUBLISH_TIMEOUT",
        default_value = "5m",
        value_parser = crate::duration::parse_go_duration,
        help = "Timeout for publishing a signed exit to the publish-address API."
    )]
    pub publish_timeout: Duration,

    #[arg(
        long = "testnet-name",
        env = "CHARON_TESTNET_NAME",
        default_value = "",
        help = "Name of the custom test network."
    )]
    pub testnet_name: String,

    #[arg(
        long = "testnet-fork-version",
        env = "CHARON_TESTNET_FORK_VERSION",
        default_value = "",
        help = "Genesis fork version of the custom test network (in hex)."
    )]
    pub testnet_fork_version: String,

    #[arg(
        long = "testnet-chain-id",
        env = "CHARON_TESTNET_CHAIN_ID",
        default_value_t = 0,
        help = "Chain ID of the custom test network."
    )]
    pub testnet_chain_id: u64,

    #[arg(
        long = "testnet-genesis-timestamp",
        env = "CHARON_TESTNET_GENESIS_TIMESTAMP",
        default_value_t = 0,
        help = "Genesis timestamp of the custom test network."
    )]
    pub testnet_genesis_timestamp: u64,

    #[arg(
        long = "testnet-capella-hard-fork",
        env = "CHARON_TESTNET_CAPELLA_HARD_FORK",
        default_value = "",
        help = "Capella hard fork version of the custom test network."
    )]
    pub testnet_capella_hard_fork: String,
}

impl ExitDeleteArgs {
    /// Rejects flag combinations Charon refuses in `newDeleteExitCmd`'s
    /// `wrapPreRunE`, verbatim messages included.
    pub fn validate(&self) -> Result<()> {
        if self.validator_public_key.is_none() && !self.all {
            return Err(CliError::ValidatorPubkeyRequired);
        }

        if self.all && self.validator_public_key.is_some() {
            return Err(CliError::ValidatorPubkeyWithAll);
        }

        Ok(())
    }

    /// Returns the fully-specified custom testnet, or `None`.
    ///
    /// Charon silently ignores partially-specified testnet flags
    /// (`eth2util.Network.IsNonZero` excludes the capella hard fork), so the
    /// same fields are checked here before leaking the strings needed for
    /// registration.
    fn testnet_network(&self) -> Option<pluto_eth2util::network::Network> {
        if self.testnet_name.is_empty()
            || self.testnet_fork_version.is_empty()
            || self.testnet_chain_id == 0
            || self.testnet_genesis_timestamp == 0
        {
            return None;
        }

        Some(pluto_eth2util::network::Network {
            chain_id: self.testnet_chain_id,
            name: self.testnet_name.clone().leak(),
            genesis_fork_version_hex: self.testnet_fork_version.clone().leak(),
            genesis_timestamp: self.testnet_genesis_timestamp,
            capella_hard_fork: self.testnet_capella_hard_fork.clone().leak(),
        })
    }
}

/// Deletes the partially signed exit message(s) of this operator from the
/// remote Obol API.
///
/// Ports Charon's `runDeleteExit`.
pub async fn run_delete(args: ExitDeleteArgs) -> Result<()> {
    args.validate()?;

    // A fully-specified custom testnet must be registered before the cluster
    // lock is loaded, so the lock's genesis fork version resolves.
    if let Some(network) = args.testnet_network() {
        pluto_eth2util::network::add_test_network(network)?;
    }

    let identity_key = pluto_k1util::load(&args.private_key_file)?;

    let lock = pluto_cluster::load::load_cluster_lock_and_verify(&args.lock_file)
        .await
        .map_err(|source| CliError::LoadClusterLock {
            path: args.lock_file.clone(),
            source,
        })?;

    let client = Client::new(
        &args.publish_address,
        ClientOptions::builder()
            .timeout(args.publish_timeout)
            .build(),
    )?;

    // Charon derives the operator's share index from the cluster lock and the
    // loaded identity key (`keystore.ShareIdxForCluster`).
    let peer_id = pluto_p2p::peer::peer_id_from_key(identity_key.public_key())?;
    let share_idx = lock.node_idx(&peer_id)?.share_idx;

    if args.all {
        for validator in &lock.distributed_validators {
            let validator_pubkey = validator.public_key_hex()?;

            info!(validator = %validator_pubkey, "Deleting partial exit message");

            match client
                .delete_partial_exit(&validator_pubkey, &lock.lock_hash, share_idx, &identity_key)
                .await
            {
                Ok(()) => {}
                // An operator that never submitted a partial exit for this
                // validator is not an error when deleting all of them.
                Err(ObolApiError::NoExit) => {
                    warn!(
                        "partial exit data from Obol API for validator {validator_pubkey} not available (exit may not have been submitted)"
                    );
                }
                Err(source) => return Err(source.into()),
            }
        }
    } else {
        let validator_pubkey = args.validator_public_key.unwrap_or_default();

        // Reject a malformed public key before hitting the API, mirroring
        // Charon's `core.PubKey(...).Bytes()` pre-check.
        pluto_core::types::PubKey::try_from(validator_pubkey.as_str()).map_err(|source| {
            CliError::InvalidValidatorPubKey {
                pubkey: validator_pubkey.clone(),
                source,
            }
        })?;

        info!(validator = %validator_pubkey, "Deleting partial exit message");

        client
            .delete_partial_exit(&validator_pubkey, &lock.lock_hash, share_idx, &identity_key)
            .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path_regex},
    };

    use super::*;
    use crate::cli::{Cli, Commands, ExitCommands};

    /// Parses `pluto exit delete <flags>` and returns the subcommand args.
    fn parse(flags: &[&str]) -> std::result::Result<ExitDeleteArgs, clap::Error> {
        let argv = ["pluto", "exit", "delete"]
            .into_iter()
            .chain(flags.iter().copied());

        let cli = <Cli as clap::Parser>::try_parse_from(argv)?;

        match cli.command {
            Commands::Exit(args) => match args.command {
                ExitCommands::Delete(args) => Ok(*args),
            },
            _ => panic!("expected the exit delete subcommand"),
        }
    }

    /// Ports Charon's `TestExitDeleteCLI`: the pre-run flag checks and their
    /// verbatim messages.
    ///
    /// Charon spells the boolean as `--all=false`/`--all=true`; the Pluto CLI
    /// uses clap's presence-only booleans throughout, so absence is `false`.
    #[test]
    fn rejects_invalid_flag_combinations() {
        let base = [
            "--publish-address=test",
            "--private-key-file=test",
            "--lock-file=test",
            "--publish-timeout=1ms",
            "--testnet-name=test",
            "--testnet-fork-version=test",
            "--testnet-chain-id=1",
            "--testnet-genesis-timestamp=1",
            "--testnet-capella-hard-fork=test",
        ];

        // No validator public key and not all.
        let args = parse(&base).expect("flags should parse");
        let err = args.validate().expect_err("missing pubkey should fail");
        assert_eq!(
            err.to_string(),
            "validator-public-key must be specified when exiting single validator."
        );

        // Validator public key and all.
        let mut flags = base.to_vec();
        flags.push("--validator-public-key=test");
        flags.push("--all");

        let args = parse(&flags).expect("flags should parse");
        let err = args.validate().expect_err("pubkey with --all should fail");
        assert_eq!(
            err.to_string(),
            "validator-public-key should not be specified when all is, as it is obsolete and misleading."
        );

        // Either one on its own is accepted.
        let mut single = base.to_vec();
        single.push("--validator-public-key=test");
        parse(&single)
            .expect("flags should parse")
            .validate()
            .expect("a single validator public key is valid");

        let mut all = base.to_vec();
        all.push("--all");
        parse(&all)
            .expect("flags should parse")
            .validate()
            .expect("--all is valid on its own");
    }

    /// Charon's `bindExitFlags` defaults, which the help output documents.
    #[test]
    fn flag_defaults_match_charon() {
        let args = parse(&["--all"]).expect("flags should parse");

        assert_eq!(args.publish_address, "https://api.obol.tech/v1");
        assert_eq!(
            args.private_key_file,
            PathBuf::from(".charon/charon-enr-private-key")
        );
        assert_eq!(args.lock_file, PathBuf::from(".charon/cluster-lock.json"));
        assert_eq!(args.publish_timeout, Duration::from_secs(5 * 60));
        assert_eq!(args.validator_public_key, None);
        assert_eq!(args.testnet_name, "");
        assert_eq!(args.testnet_fork_version, "");
        assert_eq!(args.testnet_chain_id, 0);
        assert_eq!(args.testnet_genesis_timestamp, 0);
        assert_eq!(args.testnet_capella_hard_fork, "");
    }

    /// A partially-specified custom testnet is ignored, as in Charon.
    #[test]
    fn testnet_network_requires_every_identifying_field() {
        let args = parse(&["--all", "--testnet-name=devnet"]).expect("flags should parse");
        assert!(args.testnet_network().is_none());

        let args = parse(&[
            "--all",
            "--testnet-name=devnet",
            "--testnet-fork-version=0x00000000",
            "--testnet-chain-id=1234",
            "--testnet-genesis-timestamp=42",
        ])
        .expect("flags should parse");

        let network = args.testnet_network().expect("fully-specified testnet");
        assert_eq!(network.name, "devnet");
        assert_eq!(network.chain_id, 1234);
        assert_eq!(network.genesis_timestamp, 42);
    }

    /// Cluster fixture: a verified lock on disk plus one operator's identity
    /// key, as `runDeleteExit` expects to find them.
    struct Fixture {
        _dir: tempfile::TempDir,
        lock: pluto_cluster::lock::Lock,
        lock_file: PathBuf,
        private_key_file: PathBuf,
    }

    /// The fixture cluster holds this many distributed validators.
    const FIXTURE_VALIDATORS: usize = 2;

    fn fixture() -> Fixture {
        let (lock, p2p_keys, _) =
            pluto_cluster::test_cluster::new_for_test(FIXTURE_VALIDATORS, 3, 4, 1);

        let dir = tempfile::tempdir().expect("create temp dir");

        let lock_file = dir.path().join("cluster-lock.json");
        let mut file = std::fs::File::create(&lock_file).expect("create lock file");
        file.write_all(
            serde_json::to_string(&lock)
                .expect("serialize lock")
                .as_bytes(),
        )
        .expect("write lock file");

        // Operator 1 of 4, so a non-trivial share index is exercised.
        let private_key_file = dir.path().join("charon-enr-private-key");
        pluto_k1util::save(&p2p_keys[1], &private_key_file).expect("save identity key");

        Fixture {
            _dir: dir,
            lock,
            lock_file,
            private_key_file,
        }
    }

    fn args_for(fixture: &Fixture, publish_address: &str) -> ExitDeleteArgs {
        ExitDeleteArgs {
            publish_address: publish_address.to_string(),
            private_key_file: fixture.private_key_file.clone(),
            lock_file: fixture.lock_file.clone(),
            validator_public_key: None,
            all: false,
            publish_timeout: Duration::from_secs(10),
            testnet_name: String::new(),
            testnet_fork_version: String::new(),
            testnet_chain_id: 0,
            testnet_genesis_timestamp: 0,
            testnet_capella_hard_fork: String::new(),
        }
    }

    /// Ports Charon's `testRunDeleteExitFullFlow` for a single validator: the
    /// exit is deleted at the share index the lock assigns this identity key.
    #[tokio::test]
    async fn deletes_a_single_partial_exit() {
        let fixture = fixture();
        let server = MockServer::start().await;

        let validator = fixture.lock.distributed_validators[0]
            .public_key_hex()
            .expect("validator pubkey");
        let lock_hash = format!("0x{}", hex::encode(&fixture.lock.lock_hash));

        Mock::given(method("DELETE"))
            .and(path_regex(format!(
                "^/exp/partial_exits/{lock_hash}/2/{validator}$"
            )))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let mut args = args_for(&fixture, &server.uri());
        args.validator_public_key = Some(validator);

        run_delete(args).await.expect("delete partial exit");
    }

    /// Ports Charon's `testRunDeleteExitFullFlow` with `all`: every validator
    /// in the lock is deleted, and a missing exit is warned about rather than
    /// aborting the loop.
    #[tokio::test]
    async fn deletes_every_partial_exit_with_all() {
        let fixture = fixture();
        let server = MockServer::start().await;

        let first = fixture.lock.distributed_validators[0]
            .public_key_hex()
            .expect("validator pubkey");

        assert_eq!(
            fixture.lock.distributed_validators.len(),
            FIXTURE_VALIDATORS
        );

        // The first validator has no stored exit (404 -> warn and continue),
        // the remaining one is deleted.
        Mock::given(method("DELETE"))
            .and(path_regex(format!("/{first}$")))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let mut args = args_for(&fixture, &server.uri());
        args.all = true;

        run_delete(args).await.expect("delete all partial exits");
    }

    /// A validator public key that is not 48 hex-encoded bytes is rejected
    /// before any request is made.
    #[tokio::test]
    async fn rejects_a_malformed_validator_public_key() {
        let fixture = fixture();
        let server = MockServer::start().await;

        let mut args = args_for(&fixture, &server.uri());
        args.validator_public_key = Some("0xdeadbeef".to_string());

        let err = run_delete(args)
            .await
            .expect_err("malformed pubkey should fail");

        assert!(
            err.to_string().contains("0xdeadbeef"),
            "unexpected error: {err}"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty()
        );
    }

    /// An identity key that is not one of the cluster's operators has no share
    /// index, which Charon reports as a missing node index.
    #[tokio::test]
    async fn rejects_an_identity_key_outside_the_cluster() {
        let fixture = fixture();
        let server = MockServer::start().await;

        // An identity key from an unrelated cluster. `new_for_test` derives
        // operator keys from `seed + operator index`, so the seeds must be far
        // enough apart that the two operator sets do not overlap.
        let (_, other_keys, _) =
            pluto_cluster::test_cluster::new_for_test(FIXTURE_VALIDATORS, 3, 4, 100);
        let stranger = fixture._dir.path().join("stranger-key");
        pluto_k1util::save(&other_keys[0], &stranger).expect("save stranger key");

        let mut args = args_for(&fixture, &server.uri());
        args.private_key_file = stranger;
        args.all = true;

        run_delete(args)
            .await
            .expect_err("an unknown identity key should fail");

        // The share index is resolved before any request is made.
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty()
        );
    }
}
