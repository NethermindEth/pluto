//! Create DKG command implementation.
//!
//! This module implements the `pluto create dkg` command, which creates the
//! configuration for a new Distributed Key Generation ceremony.

use std::path::PathBuf;

use k256::{SecretKey, elliptic_curve::rand_core::OsRng};
use pluto_app::obolapi::{Client, ClientOptions};
use pluto_cluster::{
    definition::{Creator, Definition},
    eip712sigs::{sign_cluster_definition_hash, sign_terms_and_conditions},
    operator::Operator,
};
use pluto_core::consensus::protocols::is_supported_protocol_name;
use pluto_eth2util::{
    deposit::{eths_to_gweis, verify_deposit_amounts},
    enr::Record,
    helpers::{checksum_address, public_key_to_address},
    network::{
        GNOSIS, GOERLI, HOLESKY, HOODI, MAINNET, PRATER, SEPOLIA, network_to_fork_version,
        valid_network,
    },
};
use tracing::{info, warn};

use crate::error::{CliError, Result};

const DEFAULT_NETWORK: &str = "mainnet";
const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
const MIN_NODES: usize = 3;
const MIN_THRESHOLD: u64 = 2;

/// Arguments for the `pluto create dkg` command.
#[derive(clap::Args)]
#[command(
    about = "Create the configuration for a new Distributed Key Generation ceremony using pluto dkg",
    long_about = "Create a cluster definition file that will be used by all participants of a DKG."
)]
pub struct CreateDkgArgs {
    /// The folder to write the output cluster-definition.json file to.
    #[arg(long, default_value = ".charon")]
    pub output_dir: PathBuf,

    /// Optional cosmetic cluster name.
    #[arg(long, default_value = "")]
    pub name: String,

    /// The number of distributed validators the cluster will manage (32ETH+
    /// staked for each).
    #[arg(long, default_value_t = 1)]
    pub num_validators: u64,

    /// Optional override of threshold required for signature reconstruction.
    /// Defaults to ceil(n*2/3) if zero. Warning, non-default values
    /// decrease security.
    #[arg(long, short = 't', default_value_t = 0)]
    pub threshold: u64,

    /// Comma separated list of Ethereum addresses of the fee recipient for each
    /// validator. Either provide a single fee recipient address or one per
    /// validator.
    #[arg(long, value_delimiter = ',')]
    pub fee_recipient_addresses: Vec<String>,

    /// Comma separated list of Ethereum addresses to receive the returned stake
    /// and accrued rewards for each validator. Either provide a single
    /// withdrawal address or one per validator.
    #[arg(long, value_delimiter = ',')]
    pub withdrawal_addresses: Vec<String>,

    /// Ethereum network to create validators for.
    /// Options: mainnet, goerli, sepolia, hoodi, holesky, gnosis, chiado.
    #[arg(long, default_value = DEFAULT_NETWORK)]
    pub network: String,

    /// DKG algorithm to use; default, frost.
    #[arg(long = "dkg-algorithm", default_value = "default")]
    pub dkg_algo: String,

    /// List of partial deposit amounts (integers) in ETH. Values must sum up to
    /// at least 32ETH.
    #[arg(long, value_delimiter = ',')]
    pub deposit_amounts: Vec<u64>,

    /// Comma-separated list of each operator's Charon ENR address.
    #[arg(long, value_delimiter = ',')]
    pub operator_enrs: Vec<String>,

    /// Preferred consensus protocol name for the cluster. Selected
    /// automatically when not specified.
    #[arg(long, default_value = "")]
    pub consensus_protocol: String,

    /// Preferred target gas limit for transactions.
    #[arg(long, default_value_t = 60_000_000)]
    pub target_gas_limit: u64,

    /// Enable compounding rewards for validators by using 0x02 withdrawal
    /// credentials.
    #[arg(long, default_value_t = false)]
    pub compounding: bool,

    /// The address of the execution engine JSON-RPC API.
    #[arg(long = "execution-client-rpc-endpoint", default_value = "")]
    pub execution_engine_addr: String,

    /// Creates an invitation to the DKG ceremony on the DV Launchpad.
    /// Terms and conditions apply.
    #[arg(long, default_value_t = false)]
    pub publish: bool,

    /// The URL to publish the cluster to.
    #[arg(long, default_value = "https://api.obol.tech/v1")]
    pub publish_address: String,

    /// Comma-separated list of each operator's Ethereum address.
    #[arg(long, value_delimiter = ',')]
    pub operator_addresses: Vec<String>,
}

/// Runs the create dkg command.
pub async fn run(args: CreateDkgArgs) -> Result<()> {
    run_create_dkg(parse_args(args)?).await
}

fn parse_args(args: CreateDkgArgs) -> Result<CreateDkgArgs> {
    if args.threshold != 0 {
        if args.threshold < MIN_THRESHOLD {
            return Err(CliError::Other(
                "threshold must be greater than 1".to_string(),
            ));
        }
        let num_enrs = u64::try_from(args.operator_enrs.len())
            .map_err(|_| CliError::Other("operator count overflow".to_string()))?;
        if args.threshold > num_enrs {
            return Err(CliError::Other(
                "threshold cannot be greater than number of operators".to_string(),
            ));
        }
    }

    if !args.operator_enrs.is_empty() && !args.operator_addresses.is_empty() {
        return Err(CliError::Other(
            "cannot provide both --operator-enrs and --operator-addresses".to_string(),
        ));
    }

    if args.publish {
        if args.operator_enrs.is_empty() && args.operator_addresses.is_empty() {
            return Err(CliError::Other(
                r#"required flag(s) "operator-enrs" or "operator-addresses" not set"#.to_string(),
            ));
        }
    } else if args.operator_enrs.is_empty() {
        return Err(CliError::Other(
            r#"required flag(s) "operator-enrs" not set"#.to_string(),
        ));
    }

    Ok(args)
}

async fn run_create_dkg(mut args: CreateDkgArgs) -> Result<()> {
    // Map prater to goerli to ensure backwards compatibility with older cluster
    // definitions.
    if args.network == PRATER {
        args.network = GOERLI.name.to_string();
    }

    let operators_len = if args.operator_enrs.is_empty() {
        args.operator_addresses.len()
    } else {
        args.operator_enrs.len()
    };

    validate_dkg_config(
        operators_len,
        &args.network,
        &args.deposit_amounts,
        &args.consensus_protocol,
        args.compounding,
    )?;

    let (fee_recipient_addrs, withdrawal_addrs) = validate_addresses(
        args.num_validators,
        args.fee_recipient_addresses.clone(),
        args.withdrawal_addresses.clone(),
    )?;

    validate_withdrawal_addrs(&withdrawal_addrs, &args.network)?;

    info!("Pluto create DKG starting");

    let def_path = args.output_dir.join("cluster-definition.json");
    if def_path.exists() {
        return Err(CliError::Other(
            "existing cluster-definition.json found. Try again after deleting it".to_string(),
        ));
    }

    let mut operators: Vec<Operator> = Vec::new();

    for (i, enr_str) in args.operator_enrs.iter().enumerate() {
        Record::try_from(enr_str.as_str())
            .map_err(|e| CliError::Other(format!("invalid ENR (operator {i}): {e}")))?;

        operators.push(Operator {
            enr: enr_str.clone(),
            ..Default::default()
        });
    }

    for (i, addr) in args.operator_addresses.iter().enumerate() {
        let checksum_addr = checksum_address(addr).map_err(|e| {
            CliError::Other(format!("invalid operator address: {e} (operator {i})"))
        })?;
        operators.push(Operator {
            address: checksum_addr,
            ..Default::default()
        });
    }

    let num_operators = u64::try_from(operators.len())
        .map_err(|_| CliError::Other("operator count overflow".to_string()))?;
    let safe_thresh = safe_threshold(num_operators)?;
    let threshold = if args.threshold == 0 {
        safe_thresh
    } else {
        warn!(
            threshold = args.threshold,
            safe_threshold = safe_thresh,
            "Non standard `--threshold` flag provided, this will affect cluster safety"
        );
        args.threshold
    };

    let fork_version_hex = network_to_fork_version(&args.network)?;

    let (priv_key, creator) = if args.publish {
        // Temporary creator address
        let key = SecretKey::random(&mut OsRng);
        let addr = public_key_to_address(&key.public_key());
        (
            Some(key),
            Creator {
                address: addr,
                ..Default::default()
            },
        )
    } else {
        (None, Creator::default())
    };

    let deposit_amounts_gwei: Vec<u64> = eths_to_gweis(&args.deposit_amounts);

    let mut def = Definition::new(
        args.name.clone(),
        args.num_validators,
        threshold,
        fee_recipient_addrs,
        withdrawal_addrs,
        fork_version_hex,
        creator,
        operators,
        deposit_amounts_gwei,
        args.consensus_protocol.clone(),
        args.target_gas_limit,
        args.compounding,
        vec![],
    )?;

    def.dkg_algorithm = args.dkg_algo.clone();
    def.set_definition_hashes()?;

    if let Some(key) = &priv_key {
        def.creator.config_signature = sign_cluster_definition_hash(key, &def)?;
    }

    // Verify signatures when an ETH1 endpoint is available. Skipped when the
    // endpoint is empty because the client cannot connect — safe for DKG create
    // since operators have no signatures at this stage.
    if !args.publish && !args.execution_engine_addr.is_empty() {
        let eth1 = pluto_eth1wrap::EthClient::new(&args.execution_engine_addr).await?;
        def.verify_signatures(&eth1).await?;
    }

    if args.publish {
        let key = priv_key.expect("publish requires a private key");
        return publish_partial_definition(args, key, def).await;
    }

    let json = serde_json::to_string_pretty(&def)?;

    tokio::fs::create_dir_all(&args.output_dir).await?;
    tokio::fs::write(&def_path, json.as_bytes()).await?;

    // Set file to read-only (best-effort).
    let mut perms = tokio::fs::metadata(&def_path).await?.permissions();
    perms.set_readonly(true);
    let _ = tokio::fs::set_permissions(&def_path, perms).await;

    info!("Cluster definition created: {}", def_path.display());

    Ok(())
}

fn validate_dkg_config(
    num_operators: usize,
    network: &str,
    deposit_amounts: &[u64],
    consensus_protocol: &str,
    compounding: bool,
) -> Result<()> {
    if num_operators < MIN_NODES {
        return Err(CliError::Other(format!(
            "number of operators is below minimum: got {num_operators}, need at least {MIN_NODES} via --operator-enrs or --operator-addresses",
        )));
    }

    if !valid_network(network) {
        return Err(CliError::Other("unsupported network".to_string()));
    }

    if !deposit_amounts.is_empty() {
        let gweis = eths_to_gweis(deposit_amounts);
        verify_deposit_amounts(&gweis, compounding)?;
    }

    if !consensus_protocol.is_empty() && !is_supported_protocol_name(consensus_protocol) {
        return Err(CliError::Other(
            "unsupported consensus protocol".to_string(),
        ));
    }

    Ok(())
}

fn validate_addresses(
    num_validators: u64,
    fee_recipient_addrs: Vec<String>,
    withdrawal_addrs: Vec<String>,
) -> Result<(Vec<String>, Vec<String>)> {
    let num_vals = num_validators;
    let num_fee = u64::try_from(fee_recipient_addrs.len())
        .map_err(|_| CliError::Other("address count overflow".to_string()))?;
    let num_wa = u64::try_from(withdrawal_addrs.len())
        .map_err(|_| CliError::Other("address count overflow".to_string()))?;

    if num_fee != num_vals && num_fee != 1 {
        return Err(CliError::Other(
            "mismatching --num-validators and --fee-recipient-addresses".to_string(),
        ));
    }

    if num_wa != num_vals && num_wa != 1 {
        return Err(CliError::Other(
            "mismatching --num-validators and --withdrawal-addresses".to_string(),
        ));
    }

    let num_validators = usize::try_from(num_validators)
        .map_err(|_| CliError::Other("num_validators is greater than usize::MAX".to_string()))?;
    let expand = |addrs: Vec<String>| -> Vec<String> {
        if addrs.len() == 1 {
            vec![addrs[0].clone(); num_validators]
        } else {
            addrs
        }
    };

    Ok((expand(fee_recipient_addrs), expand(withdrawal_addrs)))
}

fn validate_withdrawal_addrs(addrs: &[String], network: &str) -> Result<()> {
    for addr in addrs {
        let checksum = checksum_address(addr)
            .map_err(|e| CliError::Other(format!("invalid withdrawal address: {e}")))?;

        if checksum != *addr {
            return Err(CliError::Other(format!(
                "invalid checksummed address: {addr}"
            )));
        }

        if is_main_or_gnosis(network) && addr == ZERO_ADDRESS {
            return Err(CliError::Other(format!(
                "zero address forbidden on this network: {network}"
            )));
        }
    }

    Ok(())
}

fn is_main_or_gnosis(network: &str) -> bool {
    network == MAINNET.name || network == GNOSIS.name
}

fn safe_threshold(num_operators: u64) -> Result<u64> {
    let two_n = num_operators
        .checked_mul(2)
        .ok_or_else(|| CliError::Other("threshold overflow".to_string()))?;
    Ok(two_n
        .checked_add(2)
        .ok_or_else(|| CliError::Other("threshold overflow".to_string()))?
        / 3)
}

fn generate_launchpad_link(config_hash: &[u8], network: &str) -> String {
    let network_prefix =
        if network == HOLESKY.name || network == HOODI.name || network == SEPOLIA.name {
            format!("{network}.")
        } else {
            String::new()
        };
    format!(
        "https://{}launchpad.obol.org/dv#0x{}",
        network_prefix,
        hex::encode(config_hash)
    )
}

fn generate_api_link(config_hash: &[u8]) -> String {
    format!(
        "https://api.obol.tech/v1/definition/0x{}",
        hex::encode(config_hash)
    )
}

async fn publish_partial_definition(
    args: CreateDkgArgs,
    priv_key: SecretKey,
    def: Definition,
) -> Result<()> {
    let api_client = Client::new(
        &args.publish_address,
        ClientOptions::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build(),
    )?;

    let sig = sign_terms_and_conditions(&priv_key, &def)?;

    api_client
        .sign_terms_and_conditions(&def.creator.address, &def.fork_version, &sig)
        .await?;

    info!("Creator successfully signed Obol's terms and conditions");

    api_client
        .publish_definition(def.clone(), &def.creator.config_signature)
        .await?;

    info!("Cluster Invitation Prepared");

    if args.operator_enrs.is_empty() {
        info!(
            "Direct the Node Operators to: {} to review the cluster configuration and begin the distributed key generation ceremony.",
            generate_launchpad_link(&def.config_hash, &args.network)
        );
    } else {
        let api_link = generate_api_link(&def.config_hash);
        info!(
            "Distributed Key Generation configuration created. Run one of the following commands from the directories where the associated .charon/charon-enr-private-key(s) that match these ENRs are: \
             (Without docker): `pluto dkg --definition-file={api_link}` \
             (With docker): `docker run --rm -v \"$(pwd)/.charon:/opt/charon/.charon\" obolnetwork/charon:latest dkg --definition-file={api_link}`"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use test_case::test_case;

    use super::*;

    const VALID_ETH_ADDR: &str = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";

    const VALID_ENRS: &[&str] = &[
        "enr:-JG4QFI0llFYxSoTAHm24OrbgoVx77dL6Ehl1Ydys39JYoWcBhiHrRhtGXDTaygWNsEWFb1cL7a1Bk0klIdaNuXplKWGAYGv0Gt7gmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQL6bcis0tFXnbqG4KuywxT5BLhtmijPFApKCDJNl3mXFYN0Y3CCDhqDdWRwgg4u",
        "enr:-JG4QPnqHa7FU3PBqGxpV5L0hjJrTUqv8Wl6_UTHt-rELeICWjvCfcVfwmax8xI_eJ0ntI3ly9fgxAsmABud6-yBQiuGAYGv0iYPgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMLLCMZ5Oqi_sdnBfdyhmysZMfFm78PgF7Y9jitTJPSroN0Y3CCPoODdWRwgj6E",
        "enr:-JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u",
        "enr:-JG4QKu734_MXQklKrNHe9beXIsIV5bqv58OOmsjWmp6CF5vJSHNinYReykn7-IIkc5-YsoF8Hva1Q3pl7_gUj5P9cOGAYGv0jBLgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMM3AvPhXGCUIzBl9VFOw7VQ6_m8dGifVfJ1YXrvZsaZoN0Y3CCDhqDdWRwgg4u",
    ];

    fn temp_dir() -> TempDir {
        tempfile::tempdir().expect("create temp dir")
    }

    #[tokio::test]
    async fn test_create_dkg_valid() {
        let dir = temp_dir();
        let args = CreateDkgArgs {
            output_dir: dir.path().to_path_buf(),
            name: String::new(),
            num_validators: 1,
            threshold: 3,
            fee_recipient_addresses: vec![VALID_ETH_ADDR.to_string()],
            withdrawal_addresses: vec![VALID_ETH_ADDR.to_string()],
            network: DEFAULT_NETWORK.to_string(),
            dkg_algo: "default".to_string(),
            deposit_amounts: vec![8, 16, 4, 4],
            operator_enrs: VALID_ENRS.iter().map(|s| s.to_string()).collect(),
            consensus_protocol: "qbft".to_string(),
            target_gas_limit: 30_000_000,
            compounding: false,
            execution_engine_addr: String::new(),
            publish: false,
            publish_address: "https://api.obol.tech/v1".to_string(),
            operator_addresses: vec![],
        };

        run_create_dkg(args).await.unwrap();
        assert!(dir.path().join("cluster-definition.json").exists());
    }

    #[test_case(
        CreateDkgArgs {
            operator_enrs: {
                let mut v = vec!["-JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u".to_string()];
                v.extend(VALID_ENRS.iter().map(|s| s.to_string()));
                v
            },
            threshold: 3, network: DEFAULT_NETWORK.to_string(),
            ..default_args()
        },
        "invalid ENR (operator 0): The format of the record is invalid: Record does not start with 'enr:'" ;
        "missing_enr_prefix_dash"
    )]
    #[test_case(
        CreateDkgArgs {
            operator_enrs: {
                let mut v = vec!["enr:JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u".to_string()];
                v.extend(VALID_ENRS.iter().map(|s| s.to_string()));
                v
            },
            threshold: 3, network: DEFAULT_NETWORK.to_string(),
            ..default_args()
        },
        "invalid ENR (operator 0): Failed to decode the base64 encoded data: Invalid last symbol 117, offset 194." ;
        "enr_colon_no_dash"
    )]
    #[test_case(
        CreateDkgArgs {
            operator_enrs: {
                let mut v = vec!["enrJG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u".to_string()];
                v.extend(VALID_ENRS.iter().map(|s| s.to_string()));
                v
            },
            threshold: 3, network: DEFAULT_NETWORK.to_string(),
            ..default_args()
        },
        "invalid ENR (operator 0): The format of the record is invalid: Record does not start with 'enr:'" ;
        "enr_no_colon"
    )]
    #[test_case(
        CreateDkgArgs {
            operator_enrs: {
                let mut v = vec!["JG4QDKNYm_JK-w6NuRcUFKvJAlq2L4CwkECelzyCVrMWji4YnVRn8AqQEL5fTQotPL2MKxiKNmn2k6XEINtq-6O3Z2GAYGvzr_LgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKlO7fSaBa3h48CdM-qb_Xb2_hSrJOy6nNjR0mapAqMboN0Y3CCDhqDdWRwgg4u".to_string()];
                v.extend(VALID_ENRS.iter().map(|s| s.to_string()));
                v
            },
            threshold: 3, network: DEFAULT_NETWORK.to_string(),
            ..default_args()
        },
        "invalid ENR (operator 0): The format of the record is invalid: Record does not start with 'enr:'" ;
        "no_enr_prefix"
    )]
    #[test_case(
        CreateDkgArgs { operator_enrs: vec!["".to_string()], ..default_args() },
        "number of operators is below minimum: got 1, need at least 3 via --operator-enrs or --operator-addresses" ;
        "single_empty_enr"
    )]
    #[test_case(
        CreateDkgArgs { ..default_args() },
        "number of operators is below minimum: got 0, need at least 3 via --operator-enrs or --operator-addresses" ;
        "no_operators"
    )]
    #[test_case(
        CreateDkgArgs {
            operator_enrs: VALID_ENRS[..3].iter().map(|s| s.to_string()).collect(),
            threshold: 3, network: DEFAULT_NETWORK.to_string(),
            consensus_protocol: "unreal".to_string(),
            ..default_args()
        },
        "unsupported consensus protocol" ;
        "unsupported_consensus"
    )]
    #[tokio::test]
    async fn test_create_dkg_invalid(args: CreateDkgArgs, expected_err: &str) {
        let err = run_create_dkg(args).await.unwrap_err();
        assert_eq!(err.to_string(), expected_err);
    }

    #[test]
    fn test_require_operator_enr_flag_no_enrs() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(run(CreateDkgArgs {
                operator_enrs: vec![],
                operator_addresses: vec![],
                publish: false,
                ..default_args()
            }))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"required flag(s) "operator-enrs" not set"#
        );
    }

    #[tokio::test]
    async fn test_require_operator_enr_flag_below_minimum() {
        let err = run(CreateDkgArgs {
            operator_enrs: vec!["enr:-JG4QG472ZVvl8ySSnUK9uNVDrP_hjkUrUqIxUC75aayzmDVQedXkjbqc7QKyOOS71VmlqnYzri_taV8ZesFYaoQSIOGAYHtv1WsgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKwwq_CAld6oVKOrixE-JzMtvvNgb9yyI-_rwq4NFtajIN0Y3CCDhqDdWRwgg4u".to_string()],
            fee_recipient_addresses: vec!["0xa6430105220d0b29688b734b8ea0f3ca9936e846".to_string()],
            withdrawal_addresses: vec!["0xa6430105220d0b29688b734b8ea0f3ca9936e846".to_string()],
            ..default_args()
        }).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "number of operators is below minimum: got 1, need at least 3 via --operator-enrs or --operator-addresses"
        );
    }

    #[tokio::test]
    async fn test_existing_cluster_definition() {
        let dir = temp_dir();
        tokio::fs::write(
            dir.path().join("cluster-definition.json"),
            b"sample definition",
        )
        .await
        .unwrap();

        let enr = "enr:-JG4QG472ZVvl8ySSnUK9uNVDrP_hjkUrUqIxUC75aayzmDVQedXkjbqc7QKyOOS71VmlqnYzri_taV8ZesFYaoQSIOGAYHtv1WsgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKwwq_CAld6oVKOrixE-JzMtvvNgb9yyI-_rwq4NFtajIN0Y3CCDhqDdWRwgg4u";
        let enrs: Vec<String> = (0..MIN_NODES).map(|_| enr.to_string()).collect();

        let err = run_create_dkg(CreateDkgArgs {
            output_dir: dir.path().to_path_buf(),
            operator_enrs: enrs,
            fee_recipient_addresses: vec![VALID_ETH_ADDR.to_string()],
            withdrawal_addresses: vec![VALID_ETH_ADDR.to_string()],
            threshold: 2,
            ..default_args()
        })
        .await
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "existing cluster-definition.json found. Try again after deleting it"
        );
    }

    #[test]
    fn test_validate_withdrawal_addr_ok() {
        validate_withdrawal_addrs(&[VALID_ETH_ADDR.to_string()], "goerli").unwrap();
    }

    #[test]
    fn test_validate_withdrawal_addr_invalid_network() {
        let err = validate_withdrawal_addrs(&[ZERO_ADDRESS.to_string()], "mainnet").unwrap_err();
        assert!(
            err.to_string()
                .contains("zero address forbidden on this network")
        );
    }

    #[test]
    fn test_validate_withdrawal_addr_invalid_address() {
        let err =
            validate_withdrawal_addrs(&["0xBAD000BAD000BAD".to_string()], "gnosis").unwrap_err();
        assert!(err.to_string().contains("invalid withdrawal address"));
    }

    #[test]
    fn test_validate_withdrawal_addr_invalid_checksum() {
        let err = validate_withdrawal_addrs(
            &["0x000BAD0000000BAD0000000BAD0000000BAD0000".to_string()],
            "gnosis",
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid checksummed address"));
    }

    #[test]
    fn test_validate_dkg_config_insufficient_operators() {
        let err = validate_dkg_config(2, "", &[], "", false).unwrap_err();
        assert!(
            err.to_string()
                .contains("number of operators is below minimum")
        );
    }

    #[test]
    fn test_validate_dkg_config_invalid_network() {
        let err = validate_dkg_config(4, "cosmos", &[], "", false).unwrap_err();
        assert!(err.to_string().contains("unsupported network"));
    }

    #[test]
    fn test_validate_dkg_config_wrong_deposit_amounts() {
        let err = validate_dkg_config(4, "goerli", &[8, 16], "", false).unwrap_err();
        assert!(err.to_string().contains(
            "Sum of partial deposit amounts must be at least 32ETH, repetition is allowed"
        ));
    }

    #[test]
    fn test_validate_dkg_config_unsupported_consensus() {
        let err = validate_dkg_config(4, "goerli", &[], "unreal", false).unwrap_err();
        assert!(err.to_string().contains("unsupported consensus protocol"));
    }

    #[tokio::test]
    async fn test_dkg_cli_threshold_below_minimum() {
        let enr = "enr:-JG4QG472ZVvl8ySSnUK9uNVDrP_hjkUrUqIxUC75aayzmDVQedXkjbqc7QKyOOS71VmlqnYzri_taV8ZesFYaoQSIOGAYHtv1WsgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKwwq_CAld6oVKOrixE-JzMtvvNgb9yyI-_rwq4NFtajIN0Y3CCDhqDdWRwgg4u";
        let enrs: Vec<String> = (0..MIN_NODES).map(|_| enr.to_string()).collect();

        let err = run(CreateDkgArgs {
            operator_enrs: enrs,
            fee_recipient_addresses: vec![VALID_ETH_ADDR.to_string()],
            withdrawal_addresses: vec![VALID_ETH_ADDR.to_string()],
            threshold: 1,
            ..default_args()
        })
        .await
        .unwrap_err();

        assert!(err.to_string().contains("threshold must be greater than 1"));
    }

    #[tokio::test]
    async fn test_dkg_cli_threshold_above_maximum() {
        let enr = "enr:-JG4QG472ZVvl8ySSnUK9uNVDrP_hjkUrUqIxUC75aayzmDVQedXkjbqc7QKyOOS71VmlqnYzri_taV8ZesFYaoQSIOGAYHtv1WsgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKwwq_CAld6oVKOrixE-JzMtvvNgb9yyI-_rwq4NFtajIN0Y3CCDhqDdWRwgg4u";
        let enrs: Vec<String> = (0..MIN_NODES).map(|_| enr.to_string()).collect();

        let err = run(CreateDkgArgs {
            operator_enrs: enrs,
            fee_recipient_addresses: vec![VALID_ETH_ADDR.to_string()],
            withdrawal_addresses: vec![VALID_ETH_ADDR.to_string()],
            threshold: 4,
            ..default_args()
        })
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("threshold cannot be greater than number of operators")
        );
    }

    #[tokio::test]
    async fn test_dkg_cli_no_threshold() {
        let dir = temp_dir();
        let enr = "enr:-JG4QG472ZVvl8ySSnUK9uNVDrP_hjkUrUqIxUC75aayzmDVQedXkjbqc7QKyOOS71VmlqnYzri_taV8ZesFYaoQSIOGAYHtv1WsgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKwwq_CAld6oVKOrixE-JzMtvvNgb9yyI-_rwq4NFtajIN0Y3CCDhqDdWRwgg4u";
        let enrs: Vec<String> = (0..MIN_NODES).map(|_| enr.to_string()).collect();

        run(CreateDkgArgs {
            output_dir: dir.path().to_path_buf(),
            operator_enrs: enrs,
            fee_recipient_addresses: vec![VALID_ETH_ADDR.to_string()],
            withdrawal_addresses: vec![VALID_ETH_ADDR.to_string()],
            num_validators: 1,
            threshold: 0,
            ..default_args()
        })
        .await
        .unwrap();

        assert!(dir.path().join("cluster-definition.json").exists());
    }

    #[test_case("mainnet", b"123abc", "https://launchpad.obol.org/dv#0x313233616263" ; "mainnet")]
    #[test_case("holesky", b"123abc", "https://holesky.launchpad.obol.org/dv#0x313233616263" ; "holesky")]
    #[test_case("hoodi",   b"123abc", "https://hoodi.launchpad.obol.org/dv#0x313233616263"   ; "hoodi")]
    #[test_case("sepolia", b"123abc", "https://sepolia.launchpad.obol.org/dv#0x313233616263" ; "sepolia")]
    #[test_case("testnet-1", b"123abc", "https://launchpad.obol.org/dv#0x313233616263"       ; "unknown_network")]
    fn test_launchpad_link(network: &str, config_hash: &[u8], expected: &str) {
        assert_eq!(generate_launchpad_link(config_hash, network), expected);
    }

    fn default_args() -> CreateDkgArgs {
        CreateDkgArgs {
            output_dir: PathBuf::from(".charon"),
            name: String::new(),
            num_validators: 0,
            threshold: 0,
            fee_recipient_addresses: vec![],
            withdrawal_addresses: vec![],
            network: DEFAULT_NETWORK.to_string(),
            dkg_algo: "default".to_string(),
            deposit_amounts: vec![],
            operator_enrs: vec![],
            consensus_protocol: String::new(),
            target_gas_limit: 60_000_000,
            compounding: false,
            execution_engine_addr: String::new(),
            publish: false,
            publish_address: "https://api.obol.tech/v1".to_string(),
            operator_addresses: vec![],
        }
    }
}
