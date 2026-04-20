//! Create DKG command implementation.
//!
//! This module implements the `pluto create dkg` command, which creates the
//! configuration for a new Distributed Key Generation ceremony.

use std::path::PathBuf;

use k256::{SecretKey, elliptic_curve::rand_core::OsRng};
use pluto_app::obolapi::{Client, ClientOptions};
use pluto_cluster::{
    definition::{Creator, Definition},
    operator::Operator,
};
use pluto_core::consensus::protocols::is_supported_protocol_name;
use pluto_eth2util::{
    deposit::{eths_to_gweis, verify_deposit_amounts},
    enr::Record,
    helpers::{checksum_address, public_key_to_address},
    network::{
        GNOSIS, GOERLI, HOODI, MAINNET, PRATER, SEPOLIA, network_to_fork_version, valid_network,
    },
};
use thiserror::Error;
use tracing::{info, warn};

use super::constants::{DEFAULT_NETWORK, MIN_NODES, MIN_THRESHOLD, ZERO_ADDRESS};

/// Arguments for the `pluto create dkg` command.
#[derive(clap::Args)]
#[command(
    about = "Create the configuration for a new Distributed Key Generation ceremony using pluto dkg",
    long_about = "Create a cluster definition file that will be used by all participants of a DKG."
)]
pub struct CreateDkgArgs {
    #[arg(
        long,
        default_value = ".charon",
        help = "The folder to write the output cluster-definition.json file to."
    )]
    pub output_dir: PathBuf,

    #[arg(long, default_value = "", help = "Optional cosmetic cluster name")]
    pub name: String,

    #[arg(
        long,
        default_value_t = 1,
        help = "The number of distributed validators the cluster will manage (32ETH+ staked for each)."
    )]
    pub num_validators: u64,

    #[arg(
        long,
        short = 't',
        default_value_t = 0,
        help = "Optional override of threshold required for signature reconstruction. Defaults to ceil(n*2/3) if zero. Warning, non-default values decrease security."
    )]
    pub threshold: u64,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma separated list of Ethereum addresses of the fee recipient for each validator. Either provide a single fee recipient address or fee recipient addresses for each validator."
    )]
    pub fee_recipient_addresses: Vec<String>,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma separated list of Ethereum addresses to receive the returned stake and accrued rewards for each validator. Either provide a single withdrawal address or withdrawal addresses for each validator."
    )]
    pub withdrawal_addresses: Vec<String>,

    #[arg(long, default_value = DEFAULT_NETWORK, help = "Ethereum network to create validators for. Options: mainnet, goerli, sepolia, hoodi, gnosis, chiado.")]
    pub network: String,

    #[arg(
        long = "dkg-algorithm",
        default_value = "default",
        help = "DKG algorithm to use; default, frost"
    )]
    pub dkg_algo: String,

    #[arg(
        long,
        value_delimiter = ',',
        help = "List of partial deposit amounts (integers) in ETH. Values must sum up to at least 32ETH."
    )]
    pub deposit_amounts: Vec<u64>,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma-separated list of each operator's Charon ENR address."
    )]
    pub operator_enrs: Vec<String>,

    #[arg(
        long,
        default_value = "",
        help = "Preferred consensus protocol name for the cluster. Selected automatically when not specified."
    )]
    pub consensus_protocol: String,

    #[arg(
        long,
        default_value_t = 60_000_000,
        help = "Preferred target gas limit for transactions."
    )]
    pub target_gas_limit: u64,

    #[arg(
        long,
        default_value_t = false,
        help = "Enable compounding rewards for validators by using 0x02 withdrawal credentials."
    )]
    pub compounding: bool,

    #[arg(
        long = "execution-client-rpc-endpoint",
        default_value = "",
        help = "The address of the execution engine JSON-RPC API."
    )]
    pub execution_engine_addr: String,

    #[arg(
        long,
        default_value_t = false,
        help = "Creates an invitation to the DKG ceremony on the DV Launchpad. Terms and conditions apply."
    )]
    pub publish: bool,

    #[arg(
        long,
        default_value = "https://api.obol.tech/v1",
        help = "The URL to publish the cluster to."
    )]
    pub publish_address: String,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma-separated list of each operator's Ethereum address."
    )]
    pub operator_addresses: Vec<String>,
}

#[derive(Error, Debug)]
pub enum CreateDkgError {
    #[error("existing cluster-definition.json found. Try again after deleting it")]
    DefinitionAlreadyExists,

    #[error("invalid ENR (operator {index}): {source}")]
    InvalidEnr {
        index: usize,
        #[source]
        source: pluto_eth2util::enr::RecordError,
    },

    #[error("invalid operator address: {source} (operator {index})")]
    InvalidOperatorAddress {
        index: usize,
        #[source]
        source: pluto_eth2util::helpers::HelperError,
    },

    #[error(
        "number of operators is below minimum: got {num_operators}, need at least {MIN_NODES} via --operator-enrs or --operator-addresses"
    )]
    TooFewOperators { num_operators: usize },

    #[error("unsupported network")]
    UnsupportedNetwork,

    #[error("unsupported consensus protocol")]
    UnsupportedConsensusProtocol,

    #[error(transparent)]
    AddressValidation(#[from] super::address_validation::AddressValidationError),

    #[error("threshold must be greater than 1 (threshold={threshold}, min={min})")]
    ThresholdTooLow { threshold: u64, min: u64 },

    #[error("threshold ({threshold}) cannot be greater than number of operators ({num_enrs})")]
    ThresholdTooHigh { threshold: u64, num_enrs: u64 },

    #[error("cannot provide both --operator-enrs and --operator-addresses")]
    MutuallyExclusiveOperatorFlags,

    #[error(r#"required flag(s) "operator-enrs" or "operator-addresses" not set"#)]
    MissingOperatorEnrsOrAddresses,

    #[error(r#"required flag(s) "operator-enrs" not set"#)]
    MissingOperatorEnrs,

    #[error(transparent)]
    WithdrawalValidation(#[from] WithdrawalValidationError),

    #[error(transparent)]
    Network(#[from] pluto_eth2util::network::NetworkError),

    #[error(transparent)]
    Definition(#[from] pluto_cluster::definition::DefinitionError),

    #[error(transparent)]
    Eip712(#[from] pluto_cluster::eip712sigs::EIP712Error),

    #[error(transparent)]
    Eth1wrap(#[from] pluto_eth1wrap::EthClientError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Deposit(#[from] pluto_eth2util::deposit::DepositError),

    #[error(transparent)]
    ObolApi(#[from] pluto_app::obolapi::ObolApiError),
}

/// Runs the create dkg command.
pub async fn run(args: CreateDkgArgs) -> crate::error::Result<()> {
    Ok(run_create_dkg(parse_args(args)?).await?)
}

fn parse_args(args: CreateDkgArgs) -> Result<CreateDkgArgs, CreateDkgError> {
    if args.threshold != 0 {
        if args.threshold < MIN_THRESHOLD {
            return Err(CreateDkgError::ThresholdTooLow {
                threshold: args.threshold,
                min: MIN_THRESHOLD,
            });
        }
        let num_enrs = args.operator_enrs.len() as u64;
        if args.threshold > num_enrs {
            return Err(CreateDkgError::ThresholdTooHigh {
                threshold: args.threshold,
                num_enrs,
            });
        }
    }

    if !args.operator_enrs.is_empty() && !args.operator_addresses.is_empty() {
        return Err(CreateDkgError::MutuallyExclusiveOperatorFlags);
    }

    if args.publish {
        if args.operator_enrs.is_empty() && args.operator_addresses.is_empty() {
            return Err(CreateDkgError::MissingOperatorEnrsOrAddresses);
        }
    } else if args.operator_enrs.is_empty() {
        return Err(CreateDkgError::MissingOperatorEnrs);
    }

    Ok(args)
}

async fn run_create_dkg(mut args: CreateDkgArgs) -> Result<(), CreateDkgError> {
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

    let (fee_recipient_addrs, withdrawal_addrs) = super::address_validation::validate_addresses(
        args.num_validators,
        &args.fee_recipient_addresses,
        &args.withdrawal_addresses,
    )?;

    validate_withdrawal_addrs(&withdrawal_addrs, &args.network)?;

    pluto_core::version::log_info("Pluto create DKG starting");

    let def_path = args.output_dir.join("cluster-definition.json");
    if def_path.exists() {
        return Err(CreateDkgError::DefinitionAlreadyExists);
    }

    let mut operators: Vec<Operator> = Vec::new();

    for (i, enr_str) in args.operator_enrs.iter().enumerate() {
        Record::try_from(enr_str.as_str())
            .map_err(|source| CreateDkgError::InvalidEnr { index: i, source })?;

        operators.push(Operator {
            enr: enr_str.clone(),
            ..Default::default()
        });
    }

    for (i, addr) in args.operator_addresses.iter().enumerate() {
        let checksum_addr = checksum_address(addr)
            .map_err(|source| CreateDkgError::InvalidOperatorAddress { index: i, source })?;
        operators.push(Operator {
            address: checksum_addr,
            ..Default::default()
        });
    }

    // Taking total number of operators, operator_enrs and operator_addresses are
    // mutually exclusive so no if statement is needed.
    let num_operators = operators.len() as u64;
    let safe_threshold = pluto_cluster::helpers::threshold(num_operators);
    let threshold = if args.threshold == 0 {
        safe_threshold
    } else {
        warn!(
            threshold = args.threshold,
            safe_threshold = safe_threshold,
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
        def.creator.config_signature =
            pluto_cluster::eip712sigs::sign_cluster_definition_hash(key, &def)?;
    }

    if !args.publish {
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
) -> Result<(), CreateDkgError> {
    if (num_operators as u64) < MIN_NODES {
        return Err(CreateDkgError::TooFewOperators { num_operators });
    }

    if !valid_network(network) {
        return Err(CreateDkgError::UnsupportedNetwork);
    }

    if !deposit_amounts.is_empty() {
        let gweis = eths_to_gweis(deposit_amounts);
        verify_deposit_amounts(&gweis, compounding)?;
    }

    if !consensus_protocol.is_empty() && !is_supported_protocol_name(consensus_protocol) {
        return Err(CreateDkgError::UnsupportedConsensusProtocol);
    }

    Ok(())
}

/// Errors that can occur during withdrawal address validation.
#[derive(Error, Debug)]
pub enum WithdrawalValidationError {
    /// Invalid withdrawal address.
    #[error("invalid withdrawal address: {address}: {reason}")]
    InvalidWithdrawalAddress {
        /// The invalid address.
        address: String,
        /// The reason for the invalid address.
        reason: String,
    },

    /// Invalid checksummed address.
    #[error("invalid checksummed address: {address}")]
    InvalidChecksummedAddress {
        /// The address with invalid checksum.
        address: String,
    },

    /// Zero address forbidden on mainnet/gnosis.
    #[error("zero address forbidden on this network: {network}")]
    ZeroAddressForbiddenOnNetwork {
        /// The network name.
        network: String,
    },

    /// Eth2util helpers error.
    #[error("Eth2util helpers error: {0}")]
    Eth2utilHelperError(#[from] pluto_eth2util::helpers::HelperError),
}

/// Validates withdrawal addresses for the given network.
///
/// Returns an error if any of the provided withdrawal addresses is invalid.
pub fn validate_withdrawal_addrs(
    addrs: &[String],
    network: &str,
) -> Result<(), WithdrawalValidationError> {
    for addr in addrs {
        let checksum_addr = checksum_address(addr).map_err(|e| {
            WithdrawalValidationError::InvalidWithdrawalAddress {
                address: addr.clone(),
                reason: e.to_string(),
            }
        })?;

        if checksum_addr != *addr {
            return Err(WithdrawalValidationError::InvalidChecksummedAddress {
                address: addr.clone(),
            });
        }

        // We cannot allow a zero withdrawal address on mainnet or gnosis.
        if is_main_or_gnosis(network) && addr == ZERO_ADDRESS {
            return Err(WithdrawalValidationError::ZeroAddressForbiddenOnNetwork {
                network: network.to_string(),
            });
        }
    }

    Ok(())
}

fn is_main_or_gnosis(network: &str) -> bool {
    network == MAINNET.name || network == GNOSIS.name
}

fn generate_launchpad_link(config_hash: &[u8], network: &str) -> String {
    let network_prefix = if network == HOODI.name || network == SEPOLIA.name {
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
) -> Result<(), CreateDkgError> {
    let api_client = Client::new(
        &args.publish_address,
        ClientOptions::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build(),
    )?;

    let sig = pluto_cluster::eip712sigs::sign_terms_and_conditions(&priv_key, &def)?;

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
        CreateDkgArgs {
            operator_enrs: VALID_ENRS[..3].iter().map(|s| s.to_string()).collect(),
            threshold: 3, network: DEFAULT_NETWORK.to_string(),
            consensus_protocol: "unreal".to_string(),
            ..default_args()
        },
        "unsupported consensus protocol" ;
        "unsupported_consensus"
    )]
    #[test_case(
        CreateDkgArgs { ..default_args() },
        "number of operators is below minimum: got 0, need at least 3 via --operator-enrs or --operator-addresses" ;
        "no_operators"
    )]
    #[test_case(
        CreateDkgArgs { operator_enrs: vec!["enr:-JG4QG472ZVvl8ySSnUK9uNVDrP_hjkUrUqIxUC75aayzmDVQedXkjbqc7QKyOOS71VmlqnYzri_taV8ZesFYaoQSIOGAYHtv1WsgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKwwq_CAld6oVKOrixE-JzMtvvNgb9yyI-_rwq4NFtajIN0Y3CCDhqDdWRwgg4u".to_string()], ..default_args() },
        "number of operators is below minimum: got 1, need at least 3 via --operator-enrs or --operator-addresses" ;
        "below_minimum"
    )]
    #[tokio::test]
    async fn test_create_dkg_invalid(args: CreateDkgArgs, expected_err: &str) {
        let err = run_create_dkg(args).await.unwrap_err();
        assert_eq!(err.to_string(), expected_err);
    }

    #[test_case(
        CreateDkgArgs { operator_enrs: vec![], operator_addresses: vec![], publish: false, ..default_args() },
        r#"Create DKG error: required flag(s) "operator-enrs" not set"# ;
        "no_enrs"
    )]
    #[test_case(
        CreateDkgArgs { threshold: 1, ..default_args() },
        "Create DKG error: threshold must be greater than 1 (threshold=1, min=2)" ;
        "threshold_below_minimum"
    )]
    #[test_case(
        CreateDkgArgs { operator_enrs: VALID_ENRS[..3].iter().map(|s| s.to_string()).collect(), threshold: 4, ..default_args() },
        "Create DKG error: threshold (4) cannot be greater than number of operators (3)" ;
        "threshold_above_maximum"
    )]
    #[tokio::test]
    async fn test_run_invalid(args: CreateDkgArgs, expected_err: &str) {
        let err = run(args).await.unwrap_err();
        assert_eq!(err.to_string(), expected_err);
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

    #[test_case(VALID_ETH_ADDR, "goerli", None; "ok")]
    #[test_case(ZERO_ADDRESS, "mainnet", Some("zero address forbidden on this network"); "invalid_network")]
    #[test_case("0xBAD000BAD000BAD", "gnosis", Some("invalid withdrawal address"); "invalid_address")]
    #[test_case("0x000BAD0000000BAD0000000BAD0000000BAD0000", "gnosis", Some("invalid checksummed address"); "invalid_checksum")]
    fn test_validate_withdrawal_addr(addr: &str, network: &str, expected_err: Option<&str>) {
        let result = validate_withdrawal_addrs(&[addr.to_string()], network);
        match expected_err {
            None => result.unwrap(),
            Some(msg) => assert!(result.unwrap_err().to_string().contains(msg)),
        }
    }

    #[test_case(2, "", &[], "", false, "number of operators is below minimum"; "insufficient_operators")]
    #[test_case(4, "cosmos", &[], "", false, "unsupported network"; "invalid_network")]
    #[test_case(4, "goerli", &[8, 16], "", false, "Sum of partial deposit amounts must be at least 32ETH, repetition is allowed"; "wrong_deposit_amounts")]
    #[test_case(4, "goerli", &[], "unreal", false, "unsupported consensus protocol"; "unsupported_consensus")]
    fn test_validate_dkg_config(
        num_operators: usize,
        network: &str,
        deposit_amounts: &[u64],
        consensus_protocol: &str,
        compounding: bool,
        expected_err: &str,
    ) {
        let err = validate_dkg_config(
            num_operators,
            network,
            deposit_amounts,
            consensus_protocol,
            compounding,
        )
        .unwrap_err();
        assert!(err.to_string().contains(expected_err));
    }

    #[test_case("mainnet", b"123abc", "https://launchpad.obol.org/dv#0x313233616263" ; "mainnet")]
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
