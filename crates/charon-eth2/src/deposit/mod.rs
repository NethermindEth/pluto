mod constants;
mod errors;
mod types;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

pub use constants::*;
pub use errors::DepositError;
pub use types::*;

use crate::network;
use charon_crypto::{
    blst_impl::BlstImpl,
    tbls::Tbls,
    types::{PUBLIC_KEY_LENGTH, PublicKey, SIGNATURE_LENGTH, Signature},
};
use tree_hash::TreeHash;

/// Creates a new deposit message with the given parameters.
pub fn new_message(
    pubkey: PublicKey,
    withdrawal_addr: &str,
    amount: Gwei,
    compounding: bool,
) -> Result<DepositMessage, DepositError> {
    // Get withdrawal credentials
    let withdrawal_credentials = withdrawal_creds_from_addr(withdrawal_addr, compounding)?;

    // Validate amount
    if amount < MIN_DEPOSIT_AMOUNT {
        return Err(DepositError::MinimumAmountNotMet(amount));
    }

    let max_amount = max_deposit_amount(compounding);
    if amount > max_amount {
        return Err(DepositError::MaximumAmountExceeded {
            amount,
            max: max_amount,
        });
    }

    Ok(DepositMessage {
        pub_key: pubkey,
        withdrawal_credentials,
        amount,
    })
}

/// Returns the maximum deposit amount based on compounding flag.
pub fn max_deposit_amount(compounding: bool) -> Gwei {
    if compounding {
        MAX_COMPOUNDING_DEPOSIT_AMOUNT
    } else {
        MAX_STANDARD_DEPOSIT_AMOUNT
    }
}

/// Serializes a list of deposit data into a single file.
pub fn marshal_deposit_data(
    deposit_datas: &[DepositData],
    network: &str,
) -> Result<Vec<u8>, DepositError> {
    let fork_version = crate::network::network_to_fork_version(network)?;

    let mut dd_list = Vec::new();

    // Get fork version for the network
    let fork_version_hex_without_0x = fork_version.strip_prefix("0x").unwrap_or(&fork_version);

    for deposit_data in deposit_datas {
        // Create deposit message
        let msg = DepositMessage::from(deposit_data);

        // Compute deposit message root
        let msg_root = msg.tree_hash_root();

        // Verify signature
        let sig_data = get_message_signing_root(&msg, network)?;

        BlstImpl
            .verify(&deposit_data.pub_key, &sig_data, &deposit_data.signature)
            .map_err(|e| DepositError::InvalidSignature(e.to_string()))?;

        // Compute deposit data root
        let data_root = deposit_data.tree_hash_root();

        // Create JSON entry
        dd_list.push(DepositDataJson {
            pubkey: hex::encode(deposit_data.pub_key),
            withdrawal_credentials: hex::encode(deposit_data.withdrawal_credentials),
            amount: deposit_data.amount,
            signature: hex::encode(deposit_data.signature),
            deposit_message_root: hex::encode(msg_root.0),
            deposit_data_root: hex::encode(data_root.0),
            fork_version: fork_version_hex_without_0x.to_string(),
            network_name: network.to_string(),
            deposit_cli_version: DEPOSIT_CLI_VERSION.to_string(),
        });
    }

    // Sort by pubkey
    dd_list.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));

    let bytes = {
        use serde::Serialize;
        let mut buf = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b" "); // Single space
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
        dd_list.serialize(&mut ser)?;
        buf
    };

    Ok(bytes)
}

/// Returns the deposit signature domain.
fn get_deposit_domain(fork_version: Version) -> Domain {
    let fork_data = ForkData {
        current_version: fork_version,
        genesis_validators_root: Root::default(),
    };

    let fork_data_root = fork_data.tree_hash_root();

    let mut domain = Domain::default();
    domain[0..4].copy_from_slice(&DEPOSIT_DOMAIN_TYPE);
    domain[4..32].copy_from_slice(&fork_data_root.0[0..28]);

    domain
}

/// Returns the deposit message signing root created by the provided parameters.
pub fn get_message_signing_root(msg: &DepositMessage, network: &str) -> Result<Root, DepositError> {
    // Get message root
    let msg_root = msg.tree_hash_root();

    // Get fork version for network
    let fork_version_bytes = network::network_to_fork_version_bytes(network)?;

    let fork_version: Version = fork_version_bytes.as_slice().try_into().map_err(|_| {
        DepositError::NetworkError(network::NetworkError::InvalidForkVersion {
            fork_version: hex::encode(&fork_version_bytes),
        })
    })?;

    // Get deposit domain
    let domain = get_deposit_domain(fork_version);

    // Create signing data
    let signing_data = SigningData {
        object_root: msg_root.0,
        domain,
    };

    // Return signing root
    let signing_root = signing_data.tree_hash_root();
    Ok(signing_root.0)
}

/// Converts an Ethereum address to withdrawal credentials.
fn withdrawal_creds_from_addr(addr: &str, compounding: bool) -> Result<[u8; 32], DepositError> {
    crate::helpers::checksum_address(addr)?;

    // Decode address bytes (we already validated format, so this should succeed)
    let addr_bytes = hex::decode(&addr[2..])?;

    let mut creds = [0u8; 32];

    // Set withdrawal prefix based on compounding flag
    if compounding {
        creds[0] = EIP7251_ADDRESS_WITHDRAWAL_PREFIX;
    } else {
        creds[0] = ETH1_ADDRESS_WITHDRAWAL_PREFIX;
    }

    // Copy address bytes to positions 12-31 (last 20 bytes)
    if addr_bytes.len() != 20 {
        return Err(DepositError::InvalidAddress(format!(
            "Address must be 20 bytes, got {}",
            addr_bytes.len()
        )));
    }
    creds[12..32].copy_from_slice(&addr_bytes);

    Ok(creds)
}

/// Verifies various conditions about partial deposit amounts.
pub fn verify_deposit_amounts(amounts: &[Gwei], compounding: bool) -> Result<(), DepositError> {
    if amounts.is_empty() {
        // If no partial amounts specified, the implementation shall default to 32ETH
        return Ok(());
    }

    let max_amount = max_deposit_amount(compounding);
    let mut sum: u64 = 0;

    for &amount in amounts {
        if amount < MIN_DEPOSIT_AMOUNT {
            return Err(DepositError::AmountBelowMinimum(amount));
        }

        if amount > max_amount {
            return Err(DepositError::AmountExceedsMaximum {
                amount,
                max: max_amount,
            });
        }

        sum = sum.saturating_add(amount);
    }

    if sum < DEFAULT_DEPOSIT_AMOUNT {
        return Err(DepositError::AmountSumBelowDefault(sum));
    }

    Ok(())
}

/// Converts amounts from ETH (as integers) to Gwei.
pub fn eths_to_gweis(eth_amounts: &[u64]) -> Vec<Gwei> {
    eth_amounts
        .iter()
        .map(|&eth| ONE_ETH_IN_GWEI.saturating_mul(eth))
        .collect()
}

/// Deduplicates and sorts amounts in ascending order.
pub fn dedup_amounts(amounts: &[Gwei]) -> Vec<Gwei> {
    let mut result: Vec<Gwei> = amounts.to_vec();
    result.sort_unstable();
    result.dedup();
    result
}

/// Returns the default deposit amounts based on compounding flag.
pub fn default_deposit_amounts(compounding: bool) -> Vec<Gwei> {
    if compounding {
        vec![
            MIN_DEPOSIT_AMOUNT,
            ONE_ETH_IN_GWEI * 8,
            ONE_ETH_IN_GWEI * 32,
            ONE_ETH_IN_GWEI * 256,
        ]
    } else {
        vec![MIN_DEPOSIT_AMOUNT, DEFAULT_DEPOSIT_AMOUNT]
    }
}

/// Writes deposit-data-*eth.json files for each distinct amount.
pub fn write_cluster_deposit_data_files(
    deposit_datas: &[&[DepositData]],
    network: &str,
    cluster_dir: &Path,
    num_nodes: usize,
) -> Result<(), DepositError> {
    for deposit_data_set in deposit_datas {
        for n in 0..num_nodes {
            let node_dir = cluster_dir.join(format!("node{}", n));
            write_deposit_data_file(deposit_data_set, network, &node_dir)?;
        }
    }

    Ok(())
}

/// Writes deposit-data-*eth.json file for the provided depositDatas.
// The amount will be reflected in the filename in ETH.
// All depositDatas amounts shall have equal values.
pub fn write_deposit_data_file(
    deposit_datas: &[DepositData],
    network: &str,
    data_dir: &Path,
) -> Result<(), DepositError> {
    if deposit_datas.is_empty() {
        return Err(DepositError::EmptyDepositData);
    }

    // Verify all amounts are equal
    let first_amount = deposit_datas[0].amount;
    for (i, dd) in deposit_datas.iter().enumerate() {
        if dd.amount != first_amount {
            return Err(DepositError::UnequalAmounts(i));
        }
    }

    // Marshal to JSON
    let bytes =
        marshal_deposit_data(deposit_datas, network).map_err(|e| DepositError::InvalidData {
            field: "deposit_data".to_string(),
            message: e.to_string(),
        })?;

    // Get file path
    let file_path = get_deposit_file_path(data_dir, first_amount);

    // Write file with read-only permissions (0o444)
    std::fs::write(&file_path, bytes)?;

    // Set permissions to read-only
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&file_path)?.permissions();
        perms.set_mode(0o444);
        std::fs::set_permissions(&file_path, perms)?;
    }

    Ok(())
}

/// Constructs the file path for a deposit data file based on amount.d
pub fn get_deposit_file_path(data_dir: &Path, amount: Gwei) -> PathBuf {
    let filename = if amount == DEFAULT_DEPOSIT_AMOUNT {
        // For backward compatibility, use the old filename for 32 ETH
        "deposit-data.json".to_string()
    } else {
        // Convert Gwei to ETH and format
        #[allow(clippy::cast_precision_loss)]
        let eth = amount as f64 / ONE_ETH_IN_GWEI as f64;
        format!("deposit-data-{}eth.json", eth)
    };

    data_dir.join(filename)
}

/// Reads all deposit data files from a cluster directory.d
pub fn read_deposit_data_files(cluster_dir: &Path) -> Result<Vec<Vec<DepositData>>, DepositError> {
    // Find all deposit-data*.json files
    let pattern = cluster_dir.join("deposit-data*.json");
    let pattern_str = pattern.to_str().ok_or_else(|| DepositError::InvalidData {
        field: "path".to_string(),
        message: "Invalid UTF-8 in path".to_string(),
    })?;

    let files: Vec<PathBuf> = glob::glob(pattern_str)
        .map_err(|e| DepositError::InvalidData {
            field: "glob_pattern".to_string(),
            message: e.to_string(),
        })?
        .filter_map(Result::ok)
        .collect();

    if files.is_empty() {
        return Err(DepositError::NoFilesFound(
            cluster_dir.display().to_string(),
        ));
    }

    let mut deposit_datas_list = Vec::new();

    for file in files {
        // Read file
        let bytes = std::fs::read(&file)?;

        // Parse JSON
        let dd_list: Vec<DepositDataJson> = serde_json::from_slice(&bytes)?;

        // Convert to DepositData
        let mut deposit_datas = Vec::new();
        for d in dd_list {
            // Decode pubkey
            let pubkey_bytes = hex::decode(&d.pubkey)?;
            let pub_key: PublicKey =
                pubkey_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| DepositError::InvalidData {
                        field: "pubkey".to_string(),
                        message: format!(
                            "Expected {} bytes, got {}",
                            PUBLIC_KEY_LENGTH,
                            pubkey_bytes.len()
                        ),
                    })?;

            // Decode withdrawal credentials
            let wc_bytes = hex::decode(&d.withdrawal_credentials)?;
            let withdrawal_credentials: [u8; 32] =
                wc_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| DepositError::InvalidData {
                        field: "withdrawal_credentials".to_string(),
                        message: format!("Expected 32 bytes, got {}", wc_bytes.len()),
                    })?;

            // Decode signature
            let sig_bytes = hex::decode(&d.signature)?;
            let signature: Signature =
                sig_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| DepositError::InvalidData {
                        field: "signature".to_string(),
                        message: format!(
                            "Expected {} bytes, got {}",
                            SIGNATURE_LENGTH,
                            sig_bytes.len()
                        ),
                    })?;

            deposit_datas.push(DepositData {
                pub_key,
                withdrawal_credentials,
                amount: d.amount,
                signature,
            });
        }

        deposit_datas_list.push(deposit_datas);
    }

    Ok(deposit_datas_list)
}

/// Merges two sets of deposit data files.
pub fn merge_deposit_data_sets(
    a: Vec<Vec<DepositData>>,
    b: Vec<Vec<DepositData>>,
) -> Vec<Vec<DepositData>> {
    if a.is_empty() {
        return b;
    }

    if b.is_empty() {
        return a;
    }

    // Create map by amount
    let mut ddm: HashMap<Gwei, Vec<DepositData>> = HashMap::new();

    // Add all from a
    for deposit_set in a {
        for dd in deposit_set {
            ddm.entry(dd.amount).or_default().push(dd);
        }
    }

    // Add all from b
    for deposit_set in b {
        for dd in deposit_set {
            ddm.entry(dd.amount).or_default().push(dd);
        }
    }

    // Convert back to Vec<Vec<DepositData>>
    ddm.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_message() {
        let pubkey = [0u8; 48];
        let addr = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";
        let amount = DEFAULT_DEPOSIT_AMOUNT;

        let msg = new_message(pubkey, addr, amount, false).unwrap();

        assert_eq!(msg.pub_key, pubkey);
        assert_eq!(msg.amount, amount);
        assert_eq!(
            msg.withdrawal_credentials[0],
            ETH1_ADDRESS_WITHDRAWAL_PREFIX
        );
    }

    #[test]
    fn test_new_message_below_minimum() {
        let pubkey = [0u8; 48];
        let addr = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";
        let amount = MIN_DEPOSIT_AMOUNT - 1;

        let err = new_message(pubkey, addr, amount, false).unwrap_err();
        assert!(matches!(err, DepositError::MinimumAmountNotMet(_)));
    }

    #[test]
    fn test_new_message_above_maximum() {
        let pubkey = [0u8; 48];
        let addr = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";

        // Non-compounding: max is 32 ETH
        let amount = MAX_STANDARD_DEPOSIT_AMOUNT + 1;
        let err = new_message(pubkey, addr, amount, false).unwrap_err();
        assert!(matches!(err, DepositError::MaximumAmountExceeded { .. }));

        // Should work with compounding
        assert!(new_message(pubkey, addr, amount, true).is_ok());
    }

    #[test]
    fn test_max_deposit_amount() {
        assert_eq!(max_deposit_amount(false), MAX_STANDARD_DEPOSIT_AMOUNT);
        assert_eq!(max_deposit_amount(true), MAX_COMPOUNDING_DEPOSIT_AMOUNT);
    }

    #[test]
    fn test_verify_deposit_amounts_valid() {
        let amounts = vec![16_000_000_000, 16_000_000_000]; // 16 ETH + 16 ETH = 32 ETH
        assert!(verify_deposit_amounts(&amounts, false).is_ok());
    }

    #[test]
    fn test_verify_deposit_amounts_below_minimum() {
        let amounts = vec![500_000_000, 31_500_000_000]; // 0.5 ETH + 31.5 ETH
        let err = verify_deposit_amounts(&amounts, false).unwrap_err();
        assert!(matches!(err, DepositError::AmountBelowMinimum(_)));
    }

    #[test]
    fn test_verify_deposit_amounts_sum_below_default() {
        let amounts = vec![8_000_000_000, 16_000_000_000]; // 8 ETH + 16 ETH = 24 ETH
        let err = verify_deposit_amounts(&amounts, false).unwrap_err();
        assert!(matches!(err, DepositError::AmountSumBelowDefault(_)));
    }

    #[test]
    fn test_eths_to_gweis() {
        assert_eq!(eths_to_gweis(&[]), Vec::<Gwei>::new());
        assert_eq!(eths_to_gweis(&[1, 5]), vec![1_000_000_000, 5_000_000_000]);
    }

    #[test]
    fn test_dedup_amounts() {
        let amounts = vec![100, 500, 100, 0, 0, 300];
        assert_eq!(dedup_amounts(&amounts), vec![0, 100, 300, 500]);
    }

    #[test]
    fn test_default_deposit_amounts() {
        assert_eq!(
            default_deposit_amounts(false),
            vec![MIN_DEPOSIT_AMOUNT, DEFAULT_DEPOSIT_AMOUNT]
        );

        assert_eq!(
            default_deposit_amounts(true),
            vec![
                MIN_DEPOSIT_AMOUNT,
                8 * ONE_ETH_IN_GWEI,
                32 * ONE_ETH_IN_GWEI,
                256 * ONE_ETH_IN_GWEI
            ]
        );
    }

    #[test]
    fn test_withdrawal_creds_from_addr() {
        let addr = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";

        // Test non-compounding (0x01 prefix)
        let creds = withdrawal_creds_from_addr(addr, false).unwrap();
        assert_eq!(creds[0], ETH1_ADDRESS_WITHDRAWAL_PREFIX);
        assert_eq!(
            &creds[12..32],
            &hex::decode("321dcb529f3945bc94fecea9d3bc5caf35253b94").unwrap()[..]
        );

        // Test compounding (0x02 prefix)
        let creds = withdrawal_creds_from_addr(addr, true).unwrap();
        assert_eq!(creds[0], EIP7251_ADDRESS_WITHDRAWAL_PREFIX);
        assert_eq!(
            &creds[12..32],
            &hex::decode("321dcb529f3945bc94fecea9d3bc5caf35253b94").unwrap()[..]
        );
    }

    #[test]
    fn test_withdrawal_creds_without_prefix() {
        // Address without 0x prefix should fail (matching Go's behavior)
        let addr = "321dcb529f3945bc94fecea9d3bc5caf35253b94";
        let err = withdrawal_creds_from_addr(addr, false).unwrap_err();
        // Error is HelperError wrapped in DepositError
        assert!(matches!(err, DepositError::AddressValidationError(_)));
    }

    #[test]
    fn test_invalid_address_length() {
        let addr = "0x321dcb5"; // Too short
        let err = withdrawal_creds_from_addr(addr, false).unwrap_err();
        // Error is HelperError wrapped in DepositError
        assert!(matches!(err, DepositError::AddressValidationError(_)));
    }

    #[test]
    fn test_marshal_deposit_data_matches_fixture() {
        let pub_key = hex::decode(
            "80d0436ccacd2b263f5e9e7ebaa14015fe5c80d3e57dc7c37bcbda783895e3491019d3ed694ecbb49c8c80a0480c0392",
        )
        .unwrap();
        let withdrawal_credentials =
            hex::decode("02000000000000000000000005f9f73f74c205f2b9267c04296e3069767531fb")
                .unwrap();
        let signature = hex::decode(
            "aed3c99949ab93622f2d1baaeb047d30cb33e744e1a8464eebe1a2a634f0f23529ce753c54035968e9f3f683bca02f6704c933ca9ff2b181897de4eb27b0b2568721fe625084d5cc9030be55ceb1bc573df61a8a67bad87d94187ee4d28fc36f",
        )
        .unwrap();

        let deposit_data = DepositData {
            pub_key: pub_key.as_slice().try_into().unwrap(),
            withdrawal_credentials: withdrawal_credentials.as_slice().try_into().unwrap(),
            amount: DEFAULT_DEPOSIT_AMOUNT,
            signature: signature.as_slice().try_into().unwrap(),
        };

        let bytes = marshal_deposit_data(&[deposit_data], "goerli").unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let expected = serde_json::json!([
            {
                "pubkey": "80d0436ccacd2b263f5e9e7ebaa14015fe5c80d3e57dc7c37bcbda783895e3491019d3ed694ecbb49c8c80a0480c0392",
                "withdrawal_credentials": "02000000000000000000000005f9f73f74c205f2b9267c04296e3069767531fb",
                "amount": 32000000000u64,
                "signature": "aed3c99949ab93622f2d1baaeb047d30cb33e744e1a8464eebe1a2a634f0f23529ce753c54035968e9f3f683bca02f6704c933ca9ff2b181897de4eb27b0b2568721fe625084d5cc9030be55ceb1bc573df61a8a67bad87d94187ee4d28fc36f",
                "deposit_message_root": "0ed9775278db27ab7ef0efeea0861750d1f0e917deecfe68398321468201f2f8",
                "deposit_data_root": "10e0a77c03f4420198571cf957ce3cd7cc85ae310664c77ff9556eba18ec8689",
                "fork_version": "00001020",
                "network_name": "goerli",
                "deposit_cli_version": DEPOSIT_CLI_VERSION,
            }
        ]);

        assert_eq!(value, expected);
    }

    #[test]
    fn test_address_parsing_valid_checksum() {
        // Valid EIP-55 checksummed address should pass
        let addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        assert!(crate::helpers::checksum_address(addr).is_ok());
        assert!(withdrawal_creds_from_addr(addr, false).is_ok());
    }

    #[test]
    fn test_address_parsing_invalid_checksum_accepted() {
        // Mixed case with WRONG checksum is ACCEPTED
        let addr_wrong = "0x5aAeb6053f3E94C9b9A09f33669435E7Ef1BeAed";
        assert!(crate::helpers::checksum_address(addr_wrong).is_ok());
        assert!(withdrawal_creds_from_addr(addr_wrong, false).is_ok());
    }

    #[test]
    fn test_address_requires_prefix() {
        // Address without 0x prefix should fail
        let addr = "321dcb529f3945bc94fecea9d3bc5caf35253b94";
        assert!(withdrawal_creds_from_addr(addr, false).is_err());

        // With prefix should work
        let addr_with_prefix = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";
        assert!(withdrawal_creds_from_addr(addr_with_prefix, false).is_ok());
    }

    #[test]
    fn test_get_deposit_file_path() {
        let dir = Path::new("/tmp/test");

        // Default amount (32 ETH) should use old filename
        let path = get_deposit_file_path(dir, DEFAULT_DEPOSIT_AMOUNT);
        assert_eq!(path, dir.join("deposit-data.json"));

        // 1 ETH
        let path = get_deposit_file_path(dir, MIN_DEPOSIT_AMOUNT);
        assert_eq!(path, dir.join("deposit-data-1eth.json"));

        // 31.999999999 ETH (DEFAULT - 1 Gwei)
        let path = get_deposit_file_path(dir, DEFAULT_DEPOSIT_AMOUNT - 1);
        assert!(
            path.to_str()
                .unwrap()
                .contains("deposit-data-31.999999999eth.json")
        );

        // 16 ETH
        let path = get_deposit_file_path(dir, 16 * ONE_ETH_IN_GWEI);
        assert_eq!(path, dir.join("deposit-data-16eth.json"));
    }

    #[test]
    fn test_merge_deposit_data_sets_empty() {
        let a: Vec<Vec<DepositData>> = vec![];
        let b = vec![vec![DepositData {
            pub_key: [1u8; 48],
            withdrawal_credentials: [0u8; 32],
            amount: DEFAULT_DEPOSIT_AMOUNT,
            signature: [0u8; 96],
        }]];

        let merged = merge_deposit_data_sets(a.clone(), b.clone());
        assert_eq!(merged.len(), 1);

        let merged = merge_deposit_data_sets(b, a);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn test_merge_deposit_data_sets() {
        let dd1 = DepositData {
            pub_key: [1u8; 48],
            withdrawal_credentials: [0u8; 32],
            amount: DEFAULT_DEPOSIT_AMOUNT,
            signature: [0u8; 96],
        };

        let dd2 = DepositData {
            pub_key: [2u8; 48],
            withdrawal_credentials: [0u8; 32],
            amount: DEFAULT_DEPOSIT_AMOUNT / 2,
            signature: [0u8; 96],
        };

        let a = vec![vec![dd1.clone()], vec![dd2.clone()]];
        let b = vec![vec![dd1.clone()], vec![dd2.clone()]];

        let merged = merge_deposit_data_sets(a, b);

        // Should have 2 distinct amounts
        assert_eq!(merged.len(), 2);

        // Each amount should have 2 entries (from a and b)
        for deposit_set in merged {
            assert_eq!(deposit_set.len(), 2);
        }
    }
}
