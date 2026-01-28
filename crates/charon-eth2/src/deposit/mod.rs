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

use errors::Result;

use crate::network;
use charon_crypto::{
    blst_impl::BlstImpl,
    tbls::Tbls,
    types::{PUBLIC_KEY_LENGTH, PublicKey, SIGNATURE_LENGTH, Signature},
};
use tree_hash::TreeHash;

/// Returns the maximum deposit amount based on compounding flag.
pub fn max_deposit_amount(compounding: bool) -> Gwei {
    if compounding {
        MAX_COMPOUNDING_DEPOSIT_AMOUNT
    } else {
        MAX_STANDARD_DEPOSIT_AMOUNT
    }
}

/// Serializes a list of deposit data into a single file.
pub fn marshal_deposit_data(deposit_datas: &[DepositData], network: &str) -> Result<Vec<u8>> {
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
        let sig_data = msg.get_message_signing_root(network)?;

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
pub(crate) fn get_deposit_domain(fork_version: Version) -> Domain {
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

/// Converts an Ethereum address to withdrawal credentials.
pub(crate) fn withdrawal_creds_from_addr(
    addr: &str,
    compounding: bool,
) -> Result<WithdrawalCredentials> {
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
pub fn verify_deposit_amounts(amounts: &[Gwei], compounding: bool) -> Result<()> {
    if amounts.is_empty() {
        // If no partial amounts specified, the implementation shall default to 32ETH
        return Ok(());
    }

    let max_amount = max_deposit_amount(compounding);
    let mut sum: Gwei = 0;

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
pub async fn write_cluster_deposit_data_files(
    deposit_datas: &[&[DepositData]],
    network: &str,
    cluster_dir: &Path,
    num_nodes: usize,
) -> Result<()> {
    for deposit_data_set in deposit_datas {
        for n in 0..num_nodes {
            let node_dir = cluster_dir.join(format!("node{}", n));
            write_deposit_data_file(deposit_data_set, network, &node_dir).await?;
        }
    }

    Ok(())
}

/// Writes deposit-data-*eth.json file for the provided depositDatas.
// The amount will be reflected in the filename in ETH.
// All depositDatas amounts shall have equal values.
pub async fn write_deposit_data_file(
    deposit_datas: &[DepositData],
    network: &str,
    data_dir: &Path,
) -> Result<()> {
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

    let bytes = marshal_deposit_data(deposit_datas, network)?;

    let file_path = get_deposit_file_path(data_dir, first_amount);

    tokio::fs::write(&file_path, bytes).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o444);
        tokio::fs::set_permissions(&file_path, perms).await?;
    }
    #[cfg(not(unix))]
    {
        let mut perms = tokio::fs::metadata(&file_path).await?.permissions();
        perms.set_readonly(true);
        tokio::fs::set_permissions(&file_path, perms).await?;
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
pub fn read_deposit_data_files(cluster_dir: &Path) -> Result<Vec<Vec<DepositData>>> {
    // Find all deposit-data*.json files
    let pattern = cluster_dir.join("deposit-data*.json");
    let pattern_str = pattern
        .to_str()
        .ok_or_else(|| DepositError::InvalidData {
            field: "path".into(),
            message: "Invalid UTF-8 in path".into(),
        })?;

    let mut files: Vec<PathBuf> = glob::glob(pattern_str)
        .map_err(|e| DepositError::InvalidData {
            field: "glob_pattern".into(),
            message: e.to_string(),
        })?
        .filter_map(|r| r.ok())
        .collect();

    if files.is_empty() {
        return Err(DepositError::NoFilesFound(
            cluster_dir.display().to_string(),
        ));
    }

    files.sort_unstable();

    let mut deposit_datas_list = Vec::new();

    for file in files {
        let bytes = std::fs::read(&file)?;

        let dd_list: Vec<DepositDataJson> = serde_json::from_slice(&bytes)?;

        let mut deposit_datas = Vec::new();
        for d in dd_list {
            let pubkey_bytes = hex::decode(&d.pubkey)?;
            let pub_key: PublicKey = pubkey_bytes.as_slice().try_into().map_err(|_| {
                DepositError::InvalidDataLength {
                    field: "pubkey".into(),
                    expected: PUBLIC_KEY_LENGTH,
                    actual: pubkey_bytes.len(),
                }
            })?;

            let wc_bytes = hex::decode(&d.withdrawal_credentials)?;
            let withdrawal_credentials: WithdrawalCredentials =
                wc_bytes.as_slice().try_into().map_err(|_| {
                    DepositError::InvalidDataLength {
                        field: "withdrawal_credentials".into(),
                        expected: WITHDRAWAL_CREDENTIALS_LENGTH,
                        actual: wc_bytes.len(),
                    }
                })?;

            let sig_bytes = hex::decode(&d.signature)?;
            let signature: Signature = sig_bytes.as_slice().try_into().map_err(|_| {
                DepositError::InvalidDataLength {
                    field: "signature".into(),
                    expected: SIGNATURE_LENGTH,
                    actual: sig_bytes.len(),
                }
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

    let mut ddm: HashMap<Gwei, Vec<DepositData>> = HashMap::new();

    for deposit_set in a {
        for dd in deposit_set {
            ddm.entry(dd.amount).or_default().push(dd);
        }
    }

    for deposit_set in b {
        for dd in deposit_set {
            ddm.entry(dd.amount).or_default().push(dd);
        }
    }

    ddm.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use tempfile::tempdir;

    type Result<T> = std::result::Result<T, String>;

    /// Get the private and public keys from a hex-encoded private key.
    fn get_keys(priv_key_hex: &str) -> Result<(charon_crypto::types::PrivateKey, PublicKey)> {
        let priv_key_bytes = hex::decode(priv_key_hex).map_err(|e| e.to_string())?;
        let priv_key: charon_crypto::types::PrivateKey = priv_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "private key is 32 bytes".to_string())?;

        let tbls = BlstImpl;
        let pub_key = tbls
            .secret_to_public_key(&priv_key)
            .map_err(|e| format!("{e:?}"))?;

        Ok((priv_key, pub_key))
    }

    /// Generate properly signed deposit data for testing.
    fn generate_deposit_datas(amount: Gwei) -> Result<Vec<DepositData>> {
        const NETWORK: &str = "goerli";
        let priv_keys = [
            "01477d4bfbbcebe1fef8d4d6f624ecbb6e3178558bb1b0d6286c816c66842a6d",
            "5b77c0f0ef7c4ddc123d55b8bd93daeefbd7116764a941c0061a496649e145b5",
            "1dabcbfc9258f0f28606bf9e3b1c9f06d15a6e4eb0fbc28a43835eaaed7623fc",
            "002ff4fd29d3deb6de9f5d115182a49c618c97acaa365ad66a0b240bd825c4ff",
        ];
        let withdrawal_addrs = [
            "0x321dcb529f3945bc94fecea9d3bc5caf35253b94",
            "0x08ef6a66a4f315aa250d2e748de0bfe5a6121096",
            "0x05f9f73f74c205f2b9267c04296e3069767531fb",
            "0x67f5df029ae8d3f941abef0bec6462a6b4e4b522",
        ];

        let tbls = BlstImpl;
        let mut datas = Vec::new();

        for i in 0..priv_keys.len() {
            let (priv_key, pub_key) = get_keys(priv_keys[i])?;

            let msg = DepositMessage::new(pub_key, withdrawal_addrs[i], amount, true)
                .map_err(|e| e.to_string())?;

            let sig_root = msg
                .get_message_signing_root(NETWORK)
                .map_err(|e| e.to_string())?;

            let signature = tbls
                .sign(&priv_key, &sig_root)
                .map_err(|e| format!("{e:?}"))?;

            datas.push(DepositData {
                pub_key: msg.pub_key,
                withdrawal_credentials: msg.withdrawal_credentials,
                amount: msg.amount,
                signature,
            });
        }

        Ok(datas)
    }

    #[test]
    fn test_new_message() -> Result<()> {
        const PRIV_KEY: &str = "01477d4bfbbcebe1fef8d4d6f624ecbb6e3178558bb1b0d6286c816c66842a6d";
        const ADDR: &str = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";

        let amount = DEFAULT_DEPOSIT_AMOUNT;
        let (_priv_key, pub_key) = get_keys(PRIV_KEY)?;

        let msg = DepositMessage::new(pub_key, ADDR, amount, false).map_err(|e| e.to_string())?;

        assert_eq!(msg.pub_key, pub_key);
        assert_eq!(msg.amount, amount);
        assert_eq!(
            msg.withdrawal_credentials[0],
            ETH1_ADDRESS_WITHDRAWAL_PREFIX
        );
        Ok(())
    }

    #[test]
    fn test_new_message_below_minimum() -> Result<()> {
        const PRIV_KEY: &str = "01477d4bfbbcebe1fef8d4d6f624ecbb6e3178558bb1b0d6286c816c66842a6d";
        const ADDR: &str = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";

        let (_priv_key, pub_key) = get_keys(PRIV_KEY)?;
        let amount = MIN_DEPOSIT_AMOUNT - 1;

        match DepositMessage::new(pub_key, ADDR, amount, false) {
            Err(DepositError::MinimumAmountNotMet(_)) => Ok(()),
            other => Err(format!("expected MinimumAmountNotMet, got {other:?}")),
        }
    }

    #[test]
    fn test_new_message_above_maximum() -> Result<()> {
        const PRIV_KEY: &str = "01477d4bfbbcebe1fef8d4d6f624ecbb6e3178558bb1b0d6286c816c66842a6d";
        const ADDR: &str = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";

        let (_priv_key, pub_key) = get_keys(PRIV_KEY)?;

        // Non-compounding: max is 32 ETH
        let amount = MAX_STANDARD_DEPOSIT_AMOUNT + 1;
        match DepositMessage::new(pub_key, ADDR, amount, false) {
            Err(DepositError::MaximumAmountExceeded { .. }) => {}
            other => return Err(format!("expected MaximumAmountExceeded, got {other:?}")),
        }

        // Should work with compounding
        DepositMessage::new(pub_key, ADDR, amount, true).map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn test_max_deposit_amount() -> Result<()> {
        assert_eq!(max_deposit_amount(false), MAX_STANDARD_DEPOSIT_AMOUNT);
        assert_eq!(max_deposit_amount(true), MAX_COMPOUNDING_DEPOSIT_AMOUNT);
        Ok(())
    }

    #[test]
    fn test_verify_deposit_amounts_empty_slice_ok() -> Result<()> {
        verify_deposit_amounts(&[], false).map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn test_verify_deposit_amounts_valid() -> Result<()> {
        let amounts = vec![16_000_000_000, 16_000_000_000]; // 16 ETH + 16 ETH = 32 ETH
        verify_deposit_amounts(&amounts, false).map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn test_verify_deposit_amounts_below_minimum() -> Result<()> {
        let amounts = vec![500_000_000, 31_500_000_000]; // 0.5 ETH + 31.5 ETH
        match verify_deposit_amounts(&amounts, false) {
            Err(DepositError::AmountBelowMinimum(_)) => Ok(()),
            other => Err(format!("expected AmountBelowMinimum, got {other:?}")),
        }
    }

    #[test]
    fn test_verify_deposit_amounts_exceeds_max_unless_compounding() -> Result<()> {
        let amounts = vec![
            MIN_DEPOSIT_AMOUNT,
            DEFAULT_DEPOSIT_AMOUNT + MIN_DEPOSIT_AMOUNT,
        ]; // 1 ETH + 33 ETH
        match verify_deposit_amounts(&amounts, false) {
            Err(DepositError::AmountExceedsMaximum { .. }) => {}
            other => return Err(format!("expected AmountExceedsMaximum, got {other:?}")),
        }

        verify_deposit_amounts(&amounts, true).map_err(|e| e.to_string())?;

        let too_large = MAX_COMPOUNDING_DEPOSIT_AMOUNT
            .checked_add(MIN_DEPOSIT_AMOUNT)
            .ok_or_else(|| "overflow".to_string())?;
        let amounts = vec![MIN_DEPOSIT_AMOUNT, too_large];
        match verify_deposit_amounts(&amounts, true) {
            Err(DepositError::AmountExceedsMaximum { .. }) => Ok(()),
            other => Err(format!("expected AmountExceedsMaximum, got {other:?}")),
        }
    }

    #[test]
    fn test_verify_deposit_amounts_sum_below_default() -> Result<()> {
        let amounts = vec![8_000_000_000, 16_000_000_000]; // 8 ETH + 16 ETH = 24 ETH
        match verify_deposit_amounts(&amounts, false) {
            Err(DepositError::AmountSumBelowDefault(_)) => Ok(()),
            other => Err(format!("expected AmountSumBelowDefault, got {other:?}")),
        }
    }

    #[test]
    fn test_eths_to_gweis() -> Result<()> {
        assert_eq!(eths_to_gweis(&[]), Vec::<Gwei>::new());
        assert_eq!(eths_to_gweis(&[1, 5]), vec![1_000_000_000, 5_000_000_000]);
        Ok(())
    }

    #[test]
    fn test_dedup_amounts() -> Result<()> {
        let amounts = vec![100, 500, 100, 0, 0, 300];
        assert_eq!(dedup_amounts(&amounts), vec![0, 100, 300, 500]);
        Ok(())
    }

    #[test]
    fn test_default_deposit_amounts() -> Result<()> {
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
        Ok(())
    }

    #[test]
    fn test_withdrawal_creds_from_addr() -> Result<()> {
        let addr = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";

        // Test non-compounding (0x01 prefix)
        let creds = withdrawal_creds_from_addr(addr, false).map_err(|e| e.to_string())?;
        assert_eq!(creds[0], ETH1_ADDRESS_WITHDRAWAL_PREFIX);
        assert_eq!(
            &creds[12..32],
            &hex::decode("321dcb529f3945bc94fecea9d3bc5caf35253b94").map_err(|e| e.to_string())?[..]
        );

        // Test compounding (0x02 prefix)
        let creds = withdrawal_creds_from_addr(addr, true).map_err(|e| e.to_string())?;
        assert_eq!(creds[0], EIP7251_ADDRESS_WITHDRAWAL_PREFIX);
        assert_eq!(
            &creds[12..32],
            &hex::decode("321dcb529f3945bc94fecea9d3bc5caf35253b94").map_err(|e| e.to_string())?[..]
        );
        Ok(())
    }

    #[test]
    fn test_withdrawal_creds_without_prefix() -> Result<()> {
        // Address without 0x prefix should fail (matching Go's behavior)
        let addr = "321dcb529f3945bc94fecea9d3bc5caf35253b94";
        match withdrawal_creds_from_addr(addr, false) {
            Err(DepositError::AddressValidationError(_)) => Ok(()),
            other => Err(format!("expected AddressValidationError, got {other:?}")),
        }
    }

    #[test]
    fn test_invalid_address_length() -> Result<()> {
        let addr = "0x321dcb5"; // Too short
        match withdrawal_creds_from_addr(addr, false) {
            Err(DepositError::AddressValidationError(_)) => Ok(()),
            other => Err(format!("expected AddressValidationError, got {other:?}")),
        }
    }

    #[test]
    fn test_marshal_deposit_data_matches() -> Result<()> {
        let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT)?;
        let bytes = marshal_deposit_data(&datas, "goerli").map_err(|e| e.to_string())?;
        let actual = String::from_utf8(bytes).map_err(|e| e.to_string())?;

        let expected_raw = include_str!("testdata/TestMarshalDepositData.golden");
        let expected = expected_raw.strip_suffix('\n').unwrap_or(expected_raw);
        if actual != expected {
            let mut i = 0usize;
            let mut a_it = actual.bytes();
            let mut e_it = expected.bytes();
            loop {
                match (a_it.next(), e_it.next()) {
                    (Some(a), Some(e)) if a == e => {
                        i = i.saturating_add(1);
                        continue;
                    }
                    (None, None) => break,
                    _ => {
                        let start = i.saturating_sub(20);
                        let end = (i.saturating_add(20)).min(actual.len()).min(expected.len());
                        let a_snip = actual.get(start..end).unwrap_or("");
                        let e_snip = expected.get(start..end).unwrap_or("");
                        return Err(format!(
                            "marshal_deposit_data output didn't match golden file (first mismatch at byte {i}).\nactual:   {a_snip:?}\nexpected: {e_snip:?}"
                        ));
                    }
                }
            }

            return Err("marshal_deposit_data output didn't match golden file".to_string());
        }

        Ok(())
    }

    #[test]
    fn test_address_parsing_valid_checksum() -> Result<()> {
        // Valid EIP-55 checksummed address should pass
        let addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        crate::helpers::checksum_address(addr).map_err(|e| e.to_string())?;
        withdrawal_creds_from_addr(addr, false).map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn test_address_parsing_invalid_checksum_accepted() -> Result<()> {
        // Mixed case with WRONG checksum is ACCEPTED
        let addr_wrong = "0x5aAeb6053f3E94C9b9A09f33669435E7Ef1BeAed";
        crate::helpers::checksum_address(addr_wrong).map_err(|e| e.to_string())?;
        withdrawal_creds_from_addr(addr_wrong, false).map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn test_address_requires_prefix() -> Result<()> {
        // Address without 0x prefix should fail
        let addr = "321dcb529f3945bc94fecea9d3bc5caf35253b94";
        assert!(withdrawal_creds_from_addr(addr, false).is_err());

        // With prefix should work
        let addr_with_prefix = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";
        withdrawal_creds_from_addr(addr_with_prefix, false).map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn test_get_deposit_file_path() -> Result<()> {
        let dir = Path::new("/tmp/test");

        // Default amount (32 ETH) should use old filename
        let path = get_deposit_file_path(dir, DEFAULT_DEPOSIT_AMOUNT);
        assert_eq!(path, dir.join("deposit-data.json"));

        // 1 ETH
        let path = get_deposit_file_path(dir, MIN_DEPOSIT_AMOUNT);
        assert_eq!(path, dir.join("deposit-data-1eth.json"));

        // 31.999999999 ETH (DEFAULT - 1 Gwei)
        let path = get_deposit_file_path(dir, DEFAULT_DEPOSIT_AMOUNT - 1);
        assert_eq!(path, dir.join("deposit-data-31.999999999eth.json"));

        // 16 ETH
        let path = get_deposit_file_path(dir, 16 * ONE_ETH_IN_GWEI);
        assert_eq!(path, dir.join("deposit-data-16eth.json"));
        Ok(())
    }

    #[test]
    fn test_merge_deposit_data_sets_empty() -> Result<()> {
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
        Ok(())
    }

    #[test]
    fn test_merge_deposit_data_sets() -> Result<()> {
        let deposit_datas1 = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT)?;
        let half = DEFAULT_DEPOSIT_AMOUNT
            .checked_div(2)
            .ok_or_else(|| "overflow".to_string())?;
        let deposit_datas2 = generate_deposit_datas(half)?;

        let set1 = vec![deposit_datas1[0..2].to_vec(), deposit_datas2[0..2].to_vec()];
        let set2 = vec![deposit_datas1[2..4].to_vec(), deposit_datas2[2..4].to_vec()];

        let mut merged = merge_deposit_data_sets(set1, set2);

        // Two distinct amounts.
        assert_eq!(merged.len(), 2);

        // Deterministic validation regardless of hashmap order.
        merged.sort_by_key(|s| s.first().map(|d| d.amount).unwrap_or(0));

        for dd in &merged {
            assert_eq!(dd.len(), 4);
            let a0 = dd[0].amount;
            assert_eq!(a0, dd[1].amount);
            assert_eq!(a0, dd[2].amount);
            assert_eq!(a0, dd[3].amount);
        }

        assert_ne!(merged[0][0].amount, merged[1][0].amount);
        Ok(())
    }

    #[tokio::test]
    async fn test_write_deposit_data_file() -> Result<()> {
        let dir = tempdir().map_err(|e| e.to_string())?;
        let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT)?;

        write_deposit_data_file(&datas, "goerli", dir.path())
            .await
            .map_err(|e| e.to_string())?;

        let expected = marshal_deposit_data(&datas, "goerli").map_err(|e| e.to_string())?;
        let file_path = get_deposit_file_path(dir.path(), DEFAULT_DEPOSIT_AMOUNT);
        let actual = tokio::fs::read(&file_path)
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(expected, actual);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = tokio::fs::metadata(&file_path)
                .await
                .map_err(|e| e.to_string())?
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o444);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_write_deposit_data_file_errors() -> Result<()> {
        let dir = tempdir().map_err(|e| e.to_string())?;

        // empty deposit datas
        let err = write_deposit_data_file(&[], "goerli", dir.path())
            .await
            .err()
            .ok_or_else(|| "expected error".to_string())?;
        match err {
            DepositError::EmptyDepositData => {}
            other => return Err(format!("expected EmptyDepositData, got {other:?}")),
        }

        // not equal amounts
        let mut datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT)?;
        let half = datas[1]
            .amount
            .checked_div(2)
            .ok_or_else(|| "overflow".to_string())?;
        datas[1].amount = half;
        let err = write_deposit_data_file(&datas, "goerli", dir.path())
            .await
            .err()
            .ok_or_else(|| "expected error".to_string())?;
        match err {
            DepositError::UnequalAmounts(_) => {}
            other => return Err(format!("expected UnequalAmounts, got {other:?}")),
        }

        Ok(())
    }

    #[test]
    fn test_read_deposit_data_files_errors() -> Result<()> {
        // no files found
        let dir = tempdir().map_err(|e| e.to_string())?;
        let err = read_deposit_data_files(dir.path())
            .err()
            .ok_or_else(|| "expected error".to_string())?;
        match err {
            DepositError::NoFilesFound(_) => {}
            other => return Err(format!("expected NoFilesFound, got {other:?}")),
        }

        // invalid json in file
        let file = dir.path().join("deposit-data.json");
        std::fs::write(&file, b"{invalid json").map_err(|e| e.to_string())?;
        let err = read_deposit_data_files(dir.path())
            .err()
            .ok_or_else(|| "expected error".to_string())?;
        match err {
            DepositError::SerializationError(_) => {}
            other => return Err(format!("expected SerializationError, got {other:?}")),
        }

        Ok(())
    }

    #[test]
    fn test_read_deposit_data_files_decode_and_length_errors() -> Result<()> {
        // Use a fresh dir per case (files are made read-only).
        fn mk_dir() -> Result<tempfile::TempDir> {
            tempdir().map_err(|e| e.to_string())
        }

        // helper: write a valid deposit file, then rewrite it with a modified JSON
        // payload
        fn rewrite_file(path: &Path, bytes: Vec<u8>) -> Result<()> {
            if path.exists() {
                std::fs::remove_file(path).map_err(|e| e.to_string())?;
            }
            std::fs::write(path, bytes).map_err(|e| e.to_string())?;
            Ok(())
        }

        // invalid pubkey hex
        {
            let dir = mk_dir()?;
            let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT)?;
            let bytes = marshal_deposit_data(&datas, "goerli").map_err(|e| e.to_string())?;
            let file = get_deposit_file_path(dir.path(), DEFAULT_DEPOSIT_AMOUNT);
            std::fs::write(&file, &bytes).map_err(|e| e.to_string())?;

            let mut v: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            v[0]["pubkey"] = serde_json::Value::String("zzzz".to_string());
            let corrupt = serde_json::to_vec(&v).map_err(|e| e.to_string())?;
            rewrite_file(&file, corrupt)?;

            let err = read_deposit_data_files(dir.path())
                .err()
                .ok_or_else(|| "expected error".to_string())?;
            match err {
                DepositError::HexError(_) => {}
                other => return Err(format!("expected HexError, got {other:?}")),
            }
        }

        // invalid pubkey length
        {
            let dir = mk_dir()?;
            let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT)?;
            let bytes = marshal_deposit_data(&datas, "goerli").map_err(|e| e.to_string())?;
            let file = get_deposit_file_path(dir.path(), DEFAULT_DEPOSIT_AMOUNT);
            std::fs::write(&file, &bytes).map_err(|e| e.to_string())?;

            let mut v: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            v[0]["pubkey"] = serde_json::Value::String("abcd".to_string()); // too short
            let corrupt = serde_json::to_vec(&v).map_err(|e| e.to_string())?;
            rewrite_file(&file, corrupt)?;

            let err = read_deposit_data_files(dir.path())
                .err()
                .ok_or_else(|| "expected error".to_string())?;
            match err {
                DepositError::InvalidDataLength { .. } => {}
                other => return Err(format!("expected InvalidDataLength, got {other:?}")),
            }
        }

        // invalid withdrawal credentials hex
        {
            let dir = mk_dir()?;
            let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT)?;
            let bytes = marshal_deposit_data(&datas, "goerli").map_err(|e| e.to_string())?;
            let file = get_deposit_file_path(dir.path(), DEFAULT_DEPOSIT_AMOUNT);
            std::fs::write(&file, &bytes).map_err(|e| e.to_string())?;

            let mut v: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            v[0]["withdrawal_credentials"] = serde_json::Value::String("badhex".to_string());
            let corrupt = serde_json::to_vec(&v).map_err(|e| e.to_string())?;
            rewrite_file(&file, corrupt)?;

            let err = read_deposit_data_files(dir.path())
                .err()
                .ok_or_else(|| "expected error".to_string())?;
            match err {
                DepositError::HexError(_) => {}
                other => return Err(format!("expected HexError, got {other:?}")),
            }
        }

        // invalid signature hex
        {
            let dir = mk_dir()?;
            let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT)?;
            let bytes = marshal_deposit_data(&datas, "goerli").map_err(|e| e.to_string())?;
            let file = get_deposit_file_path(dir.path(), DEFAULT_DEPOSIT_AMOUNT);
            std::fs::write(&file, &bytes).map_err(|e| e.to_string())?;

            let mut v: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            v[0]["signature"] = serde_json::Value::String("badhex".to_string());
            let corrupt = serde_json::to_vec(&v).map_err(|e| e.to_string())?;
            rewrite_file(&file, corrupt)?;

            let err = read_deposit_data_files(dir.path())
                .err()
                .ok_or_else(|| "expected error".to_string())?;
            match err {
                DepositError::HexError(_) => {}
                other => return Err(format!("expected HexError, got {other:?}")),
            }
        }

        // invalid signature length
        {
            let dir = mk_dir()?;
            let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT)?;
            let bytes = marshal_deposit_data(&datas, "goerli").map_err(|e| e.to_string())?;
            let file = get_deposit_file_path(dir.path(), DEFAULT_DEPOSIT_AMOUNT);
            std::fs::write(&file, &bytes).map_err(|e| e.to_string())?;

            let mut v: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            v[0]["signature"] = serde_json::Value::String("abcd".to_string()); // too short
            let corrupt = serde_json::to_vec(&v).map_err(|e| e.to_string())?;
            rewrite_file(&file, corrupt)?;

            let err = read_deposit_data_files(dir.path())
                .err()
                .ok_or_else(|| "expected error".to_string())?;
            match err {
                DepositError::InvalidDataLength { .. } => {}
                other => return Err(format!("expected InvalidDataLength, got {other:?}")),
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_write_cluster_deposit_data_files() -> Result<()> {
        const NUM_NODES: usize = 4;
        let dir = tempdir().map_err(|e| e.to_string())?;

        for n in 0..NUM_NODES {
            std::fs::create_dir_all(dir.path().join(format!("node{n}")))
                .map_err(|e| e.to_string())?;
        }

        let half = DEFAULT_DEPOSIT_AMOUNT
            .checked_div(2)
            .ok_or_else(|| "overflow".to_string())?;
        let quarter = DEFAULT_DEPOSIT_AMOUNT
            .checked_div(4)
            .ok_or_else(|| "overflow".to_string())?;
        let datas1 = generate_deposit_datas(half)?;
        let datas2 = generate_deposit_datas(quarter)?;
        let deposit_sets: Vec<&[DepositData]> = vec![&datas1, &datas2];

        write_cluster_deposit_data_files(&deposit_sets, "goerli", dir.path(), NUM_NODES)
            .await
            .map_err(|e| e.to_string())?;

        for set in [&datas1, &datas2] {
            let expected = marshal_deposit_data(set, "goerli").map_err(|e| e.to_string())?;
            for n in 0..NUM_NODES {
                let node_dir = dir.path().join(format!("node{n}"));
                let file_path = get_deposit_file_path(&node_dir, set[0].amount);
                let actual = tokio::fs::read(&file_path)
                    .await
                    .map_err(|e| e.to_string())?;
                assert_eq!(expected, actual);
            }
        }

        Ok(())
    }
}
