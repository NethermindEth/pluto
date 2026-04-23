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

use pluto_crypto::{
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
pub fn marshal_deposit_data(
    deposit_datas: &[DepositData],
    network: impl AsRef<str>,
) -> Result<Vec<u8>> {
    let network = network.as_ref();
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
            .verify(&deposit_data.pubkey, &sig_data, &deposit_data.signature)
            .map_err(|e| DepositError::InvalidSignature(e.to_string()))?;

        // Compute deposit data root
        let data_root = deposit_data.tree_hash_root();

        // Create JSON entry
        dd_list.push(DepositDataJson {
            pubkey: hex::encode(deposit_data.pubkey),
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

/// Converts an Ethereum address to withdrawal credentials.
pub(crate) fn withdrawal_creds_from_addr(
    addr: impl AsRef<str>,
    compounding: bool,
) -> Result<WithdrawalCredentials> {
    let addr = crate::helpers::verify_address(addr.as_ref())?;
    let mut creds = [0u8; 32];
    // Set withdrawal prefix based on compounding flag
    if compounding {
        creds[0] = EIP7251_ADDRESS_WITHDRAWAL_PREFIX;
    } else {
        creds[0] = ETH1_ADDRESS_WITHDRAWAL_PREFIX;
    }
    creds[12..32].copy_from_slice(addr.as_slice());
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
pub async fn write_cluster_deposit_data_files<D: AsRef<[DepositData]>>(
    deposit_datas: &[D],
    network: impl AsRef<str>,
    cluster_dir: impl AsRef<Path>,
    num_nodes: usize,
) -> Result<()> {
    let network = network.as_ref();
    let cluster_dir = cluster_dir.as_ref();
    for deposit_data_set in deposit_datas {
        for n in 0..num_nodes {
            let node_dir = cluster_dir.join(format!("node{}", n));
            write_deposit_data_file(deposit_data_set.as_ref(), network, &node_dir).await?;
        }
    }

    Ok(())
}

/// Writes deposit-data-*eth.json file for the provided `deposit_datas``.
// The amount will be reflected in the filename in ETH.
// All `deposit_datas` amounts shall have equal values.
pub async fn write_deposit_data_file(
    deposit_datas: &[DepositData],
    network: impl AsRef<str>,
    data_dir: impl AsRef<Path>,
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

    // TODO: The write and set permissions may not atomic, which the file has write
    // permission between write and set perm actions.
    let mut perms = tokio::fs::metadata(&file_path).await?.permissions();
    perms.set_readonly(true);
    tokio::fs::set_permissions(&file_path, perms).await?;

    Ok(())
}

/// Constructs the file path for a deposit data file based on amount.d
pub fn get_deposit_file_path(data_dir: impl AsRef<Path>, amount: Gwei) -> PathBuf {
    let filename = if amount == DEFAULT_DEPOSIT_AMOUNT {
        // For backward compatibility, use the old filename for 32 ETH
        "deposit-data.json".to_string()
    } else {
        // Convert Gwei to ETH and format
        #[allow(clippy::cast_precision_loss)]
        let eth = amount as f64 / ONE_ETH_IN_GWEI as f64;
        format!("deposit-data-{}eth.json", eth)
    };

    data_dir.as_ref().join(filename)
}

/// Reads all deposit data files from a cluster directory.
pub async fn read_deposit_data_files(
    cluster_dir: impl AsRef<Path>,
) -> Result<Vec<Vec<DepositData>>> {
    let cluster_dir = cluster_dir.as_ref();
    let mut files = Vec::new();
    let mut entries = tokio::fs::read_dir(cluster_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("deposit-data") && name_str.ends_with(".json") {
            files.push(entry.path());
        }
    }

    if files.is_empty() {
        return Err(DepositError::NoFilesFound(
            cluster_dir.display().to_string(),
        ));
    }

    let mut deposit_datas_list = Vec::new();

    // TODO: could run multiple files concurrently.
    for file in files {
        let bytes = tokio::fs::read(&file).await?;

        let dd_list: Vec<DepositDataJson> = serde_json::from_slice(&bytes)?;

        let mut deposit_datas = Vec::new();
        for d in dd_list {
            let pubkey_bytes = hex::decode(&d.pubkey)?;
            let pubkey: PublicKey = pubkey_bytes.as_slice().try_into().map_err(|_| {
                DepositError::InvalidDataLength {
                    field: "pubkey".into(),
                    expected: PUBLIC_KEY_LENGTH,
                    actual: pubkey_bytes.len(),
                }
            })?;

            let wc_bytes = hex::decode(&d.withdrawal_credentials)?;
            let withdrawal_credentials: WithdrawalCredentials = wc_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DepositError::InvalidDataLength {
                    field: "withdrawal_credentials".into(),
                    expected: WITHDRAWAL_CREDENTIALS_LENGTH,
                    actual: wc_bytes.len(),
                })?;

            let sig_bytes = hex::decode(&d.signature)?;
            let signature: Signature =
                sig_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| DepositError::InvalidDataLength {
                        field: "signature".into(),
                        expected: SIGNATURE_LENGTH,
                        actual: sig_bytes.len(),
                    })?;

            deposit_datas.push(DepositData {
                pubkey,
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

    /// Get the private and public keys from a hex-encoded private key.
    fn get_keys(priv_key_hex: &str) -> (pluto_crypto::types::PrivateKey, PublicKey) {
        let priv_key_bytes = hex::decode(priv_key_hex).unwrap();
        let priv_key: pluto_crypto::types::PrivateKey =
            priv_key_bytes.as_slice().try_into().unwrap();

        let tbls = BlstImpl;
        let pub_key = tbls.secret_to_public_key(&priv_key).unwrap();

        (priv_key, pub_key)
    }

    /// Generate properly signed deposit data for testing.
    fn generate_deposit_datas(amount: Gwei) -> Vec<DepositData> {
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
            let (priv_key, pub_key) = get_keys(priv_keys[i]);

            let msg = super::new_message(pub_key, withdrawal_addrs[i], amount, true).unwrap();

            let sig_root = super::get_message_signing_root(&msg, NETWORK).unwrap();

            let signature = tbls.sign(&priv_key, &sig_root).unwrap();

            datas.push(DepositData {
                pubkey: msg.pubkey,
                withdrawal_credentials: msg.withdrawal_credentials,
                amount: msg.amount,
                signature,
            });
        }

        datas
    }

    #[test]
    fn new_message_valid() {
        const PRIV_KEY: &str = "01477d4bfbbcebe1fef8d4d6f624ecbb6e3178558bb1b0d6286c816c66842a6d";
        const ADDR: &str = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";

        let amount = DEFAULT_DEPOSIT_AMOUNT;
        let (_priv_key, pub_key) = get_keys(PRIV_KEY);

        let msg = super::new_message(pub_key, ADDR, amount, false).unwrap();

        assert_eq!(msg.pubkey, pub_key);
        assert_eq!(msg.amount, amount);
        assert_eq!(
            msg.withdrawal_credentials[0],
            ETH1_ADDRESS_WITHDRAWAL_PREFIX
        );
    }

    #[test]
    fn new_message_below_minimum() {
        const PRIV_KEY: &str = "01477d4bfbbcebe1fef8d4d6f624ecbb6e3178558bb1b0d6286c816c66842a6d";
        const ADDR: &str = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";

        let (_priv_key, pub_key) = get_keys(PRIV_KEY);
        let amount = MIN_DEPOSIT_AMOUNT - 1;

        let err = super::new_message(pub_key, ADDR, amount, false).unwrap_err();
        assert!(matches!(err, DepositError::MinimumAmountNotMet(_)));
    }

    #[test]
    fn new_message_above_maximum() {
        const PRIV_KEY: &str = "01477d4bfbbcebe1fef8d4d6f624ecbb6e3178558bb1b0d6286c816c66842a6d";
        const ADDR: &str = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";

        let (_priv_key, pub_key) = get_keys(PRIV_KEY);

        // Non-compounding: max is 32 ETH
        let amount = MAX_STANDARD_DEPOSIT_AMOUNT + 1;
        let err = super::new_message(pub_key, ADDR, amount, false).unwrap_err();
        assert!(matches!(err, DepositError::MaximumAmountExceeded { .. }));

        // Should work with compounding
        super::new_message(pub_key, ADDR, amount, true).unwrap();
    }

    #[test]
    fn max_deposit_amount_by_compounding() {
        assert_eq!(max_deposit_amount(false), MAX_STANDARD_DEPOSIT_AMOUNT);
        assert_eq!(max_deposit_amount(true), MAX_COMPOUNDING_DEPOSIT_AMOUNT);
    }

    #[test]
    fn verify_deposit_amounts_empty_slice_ok() {
        verify_deposit_amounts(&[], false).unwrap();
    }

    #[test]
    fn verify_deposit_amounts_valid() {
        let amounts = vec![16_000_000_000, 16_000_000_000]; // 16 ETH + 16 ETH = 32 ETH
        verify_deposit_amounts(&amounts, false).unwrap();
    }

    #[test]
    fn verify_deposit_amounts_each_amount_is_greater_than_1eth() {
        let amounts = vec![500_000_000, 31_500_000_000]; // 0.5 ETH + 31.5 ETH
        let err = verify_deposit_amounts(&amounts, false).unwrap_err();
        assert!(matches!(err, DepositError::AmountBelowMinimum(_)));
    }

    #[test]
    fn verify_deposit_amounts_exceeds_standard_max() {
        let amounts = vec![
            MIN_DEPOSIT_AMOUNT,
            DEFAULT_DEPOSIT_AMOUNT + MIN_DEPOSIT_AMOUNT,
        ]; // 1 ETH + 33 ETH
        let err = verify_deposit_amounts(&amounts, false).unwrap_err();
        assert!(matches!(err, DepositError::AmountExceedsMaximum { .. }));
    }

    #[test]
    fn verify_deposit_amounts_exceeds_standard_max_compounding() {
        let amounts = vec![
            MIN_DEPOSIT_AMOUNT,
            DEFAULT_DEPOSIT_AMOUNT + MIN_DEPOSIT_AMOUNT,
        ]; // 1 ETH + 33 ETH
        verify_deposit_amounts(&amounts, true).unwrap();
    }

    #[test]
    fn verify_deposit_amounts_exceeds_compounding_max() {
        let too_large = MAX_COMPOUNDING_DEPOSIT_AMOUNT + MIN_DEPOSIT_AMOUNT;
        let amounts = vec![MIN_DEPOSIT_AMOUNT, too_large];
        let err = verify_deposit_amounts(&amounts, true).unwrap_err();
        assert!(matches!(err, DepositError::AmountExceedsMaximum { .. }));
    }

    #[test]
    fn verify_deposit_amounts_sum_below_default() {
        let amounts = vec![8_000_000_000, 16_000_000_000]; // 8 ETH + 16 ETH = 24 ETH
        let err = verify_deposit_amounts(&amounts, false).unwrap_err();
        assert!(matches!(err, DepositError::AmountSumBelowDefault(_)));
    }

    #[test]
    fn eths_to_gweis_conversion() {
        assert_eq!(eths_to_gweis(&[]), Vec::<Gwei>::new());
        assert_eq!(eths_to_gweis(&[1, 5]), vec![1_000_000_000, 5_000_000_000]);
    }

    #[test]
    fn dedup_amounts_sorts_and_deduplicates() {
        let amounts = vec![100, 500, 100, 0, 0, 300];
        assert_eq!(dedup_amounts(&amounts), vec![0, 100, 300, 500]);
    }

    #[test]
    fn default_deposit_amounts_by_compounding() {
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
    fn withdrawal_creds_from_addr_sets_prefix() {
        let addr = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";
        let expected = hex::decode("321dcb529f3945bc94fecea9d3bc5caf35253b94").unwrap();

        // Test standard (0x01 prefix)
        let creds = withdrawal_creds_from_addr(addr, false).unwrap();
        assert_eq!(creds[0], ETH1_ADDRESS_WITHDRAWAL_PREFIX);
        assert_eq!(&creds[1..12], &[0u8; 11]);
        assert_eq!(&creds[12..32], &expected[..]);

        // Test compounding (0x02 prefix)
        let creds = withdrawal_creds_from_addr(addr, true).unwrap();
        assert_eq!(creds[0], EIP7251_ADDRESS_WITHDRAWAL_PREFIX);
        assert_eq!(&creds[1..12], &[0u8; 11]);
        assert_eq!(&creds[12..32], &expected[..]);
    }

    #[test]
    fn withdrawal_creds_without_prefix() {
        // Address without 0x prefix should fail (matching Go's behavior)
        let addr = "321dcb529f3945bc94fecea9d3bc5caf35253b94";
        let err = withdrawal_creds_from_addr(addr, false).unwrap_err();
        assert!(matches!(err, DepositError::AddressValidationError(_)));
    }

    #[test]
    fn invalid_address_length() {
        let addr = "0x321dcb5"; // Too short
        let err = withdrawal_creds_from_addr(addr, false).unwrap_err();
        assert!(matches!(err, DepositError::AddressValidationError(_)));
    }

    #[test]
    fn marshal_deposit_data_matches() {
        let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT);
        let bytes = marshal_deposit_data(&datas, "goerli").unwrap();
        let actual: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let expected_raw = include_str!("testdata/TestMarshalDepositData.golden");
        let expected: serde_json::Value = serde_json::from_str(expected_raw).unwrap();

        assert_json_diff::assert_json_eq!(actual, expected);
    }

    #[test]
    fn get_deposit_file_path_formats_by_amount() {
        let dir = Path::new("/tmp/test");

        // Default amount (32 ETH) should use old filename
        assert_eq!(
            get_deposit_file_path(dir, DEFAULT_DEPOSIT_AMOUNT),
            dir.join("deposit-data.json")
        );

        // 1 ETH
        assert_eq!(
            get_deposit_file_path(dir, MIN_DEPOSIT_AMOUNT),
            dir.join("deposit-data-1eth.json")
        );

        // 31.999999999 ETH (DEFAULT - 1 Gwei)
        assert_eq!(
            get_deposit_file_path(dir, DEFAULT_DEPOSIT_AMOUNT - 1),
            dir.join("deposit-data-31.999999999eth.json")
        );

        // 16 ETH
        assert_eq!(
            get_deposit_file_path(dir, 16 * ONE_ETH_IN_GWEI),
            dir.join("deposit-data-16eth.json")
        );
    }

    #[test]
    fn merge_deposit_data_sets_empty() {
        let a: Vec<Vec<DepositData>> = vec![];
        let b = vec![vec![DepositData {
            pubkey: [1u8; 48],
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
    fn merge_deposit_data_sets_combines_by_amount() {
        let deposit_datas1 = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT);
        let half = DEFAULT_DEPOSIT_AMOUNT / 2;
        let deposit_datas2 = generate_deposit_datas(half);

        let set1 = vec![deposit_datas1[0..2].to_vec(), deposit_datas2[0..2].to_vec()];
        let set2 = vec![deposit_datas1[2..4].to_vec(), deposit_datas2[2..4].to_vec()];

        let merged = merge_deposit_data_sets(set1, set2);

        // Two distinct amounts.
        assert_eq!(merged.len(), 2);

        for dd in &merged {
            assert_eq!(dd.len(), 4);
            let a0 = dd[0].amount;
            assert_eq!(a0, dd[1].amount);
            assert_eq!(a0, dd[2].amount);
            assert_eq!(a0, dd[3].amount);
        }

        assert_ne!(merged[0][0].amount, merged[1][0].amount);
    }

    #[tokio::test]
    async fn write_deposit_data_file_creates_readonly() {
        let dir = tempdir().unwrap();
        let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT);

        write_deposit_data_file(&datas, "goerli", dir.path())
            .await
            .unwrap();

        let expected = marshal_deposit_data(&datas, "goerli").unwrap();
        let file_path = get_deposit_file_path(dir.path(), DEFAULT_DEPOSIT_AMOUNT);
        let actual = tokio::fs::read(&file_path).await.unwrap();
        assert_eq!(expected, actual);

        let is_readonly = tokio::fs::metadata(&file_path)
            .await
            .unwrap()
            .permissions()
            .readonly();
        assert!(is_readonly);
    }

    #[tokio::test]
    async fn write_deposit_data_file_errors() {
        let dir = tempdir().unwrap();

        // empty deposit datas
        let err = write_deposit_data_file(&[], "goerli", dir.path())
            .await
            .unwrap_err();
        assert!(matches!(err, DepositError::EmptyDepositData));

        // not equal amounts
        let mut datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT);
        let half = datas[1].amount.checked_div(2).unwrap();
        datas[1].amount = half;
        let err = write_deposit_data_file(&datas, "goerli", dir.path())
            .await
            .unwrap_err();
        assert!(matches!(err, DepositError::UnequalAmounts(_)));
    }

    #[tokio::test]
    async fn read_deposit_data_files_errors() {
        // no files found
        let dir = tempdir().unwrap();
        let err = read_deposit_data_files(dir.path()).await.unwrap_err();
        assert!(matches!(err, DepositError::NoFilesFound(_)));

        // invalid json in file
        let file = dir.path().join("deposit-data.json");
        tokio::fs::write(&file, b"{invalid json").await.unwrap();
        let err = read_deposit_data_files(dir.path()).await.unwrap_err();
        assert!(matches!(err, DepositError::SerializationError(_)));
    }

    #[tokio::test]
    async fn read_deposit_data_files_invalid_pubkey_hex() {
        let dir = tempdir().unwrap();
        let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT);
        let bytes = marshal_deposit_data(&datas, "goerli").unwrap();
        let file = get_deposit_file_path(dir.path(), DEFAULT_DEPOSIT_AMOUNT);
        tokio::fs::write(&file, &bytes).await.unwrap();

        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v[0]["pubkey"] = serde_json::Value::String("zzzz".to_string());
        tokio::fs::write(&file, serde_json::to_vec(&v).unwrap())
            .await
            .unwrap();

        let err = read_deposit_data_files(dir.path()).await.unwrap_err();
        assert!(matches!(err, DepositError::HexError(_)));
    }

    #[tokio::test]
    async fn read_deposit_data_files_invalid_pubkey_length() {
        let dir = tempdir().unwrap();
        let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT);
        let bytes = marshal_deposit_data(&datas, "goerli").unwrap();
        let file = get_deposit_file_path(dir.path(), DEFAULT_DEPOSIT_AMOUNT);
        tokio::fs::write(&file, &bytes).await.unwrap();

        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v[0]["pubkey"] = serde_json::Value::String("abcd".to_string()); // too short
        tokio::fs::write(&file, serde_json::to_vec(&v).unwrap())
            .await
            .unwrap();

        let err = read_deposit_data_files(dir.path()).await.unwrap_err();
        assert!(matches!(err, DepositError::InvalidDataLength { .. }));
    }

    #[tokio::test]
    async fn read_deposit_data_files_invalid_withdrawal_creds_hex() {
        let dir = tempdir().unwrap();
        let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT);
        let bytes = marshal_deposit_data(&datas, "goerli").unwrap();
        let file = get_deposit_file_path(dir.path(), DEFAULT_DEPOSIT_AMOUNT);
        tokio::fs::write(&file, &bytes).await.unwrap();

        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v[0]["withdrawal_credentials"] = serde_json::Value::String("badhex".to_string());
        tokio::fs::write(&file, serde_json::to_vec(&v).unwrap())
            .await
            .unwrap();

        let err = read_deposit_data_files(dir.path()).await.unwrap_err();
        assert!(matches!(err, DepositError::HexError(_)));
    }

    #[tokio::test]
    async fn read_deposit_data_files_invalid_signature_hex() {
        let dir = tempdir().unwrap();
        let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT);
        let bytes = marshal_deposit_data(&datas, "goerli").unwrap();
        let file = get_deposit_file_path(dir.path(), DEFAULT_DEPOSIT_AMOUNT);
        tokio::fs::write(&file, &bytes).await.unwrap();

        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v[0]["signature"] = serde_json::Value::String("badhex".to_string());
        tokio::fs::write(&file, serde_json::to_vec(&v).unwrap())
            .await
            .unwrap();

        let err = read_deposit_data_files(dir.path()).await.unwrap_err();
        assert!(matches!(err, DepositError::HexError(_)));
    }

    #[tokio::test]
    async fn read_deposit_data_files_invalid_signature_length() {
        let dir = tempdir().unwrap();
        let datas = generate_deposit_datas(DEFAULT_DEPOSIT_AMOUNT);
        let bytes = marshal_deposit_data(&datas, "goerli").unwrap();
        let file = get_deposit_file_path(dir.path(), DEFAULT_DEPOSIT_AMOUNT);
        tokio::fs::write(&file, &bytes).await.unwrap();

        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v[0]["signature"] = serde_json::Value::String("abcd".to_string()); // too short
        tokio::fs::write(&file, serde_json::to_vec(&v).unwrap())
            .await
            .unwrap();

        let err = read_deposit_data_files(dir.path()).await.unwrap_err();
        assert!(matches!(err, DepositError::InvalidDataLength { .. }));
    }

    #[tokio::test]
    async fn write_cluster_deposit_data_files_per_node() {
        const NUM_NODES: usize = 4;
        let dir = tempdir().unwrap();

        for n in 0..NUM_NODES {
            std::fs::create_dir_all(dir.path().join(format!("node{n}"))).unwrap();
        }

        let half = DEFAULT_DEPOSIT_AMOUNT.checked_div(2).unwrap();
        let quarter = DEFAULT_DEPOSIT_AMOUNT.checked_div(4).unwrap();
        let datas1 = generate_deposit_datas(half);
        let datas2 = generate_deposit_datas(quarter);
        let deposit_sets: Vec<&[DepositData]> = vec![&datas1, &datas2];

        write_cluster_deposit_data_files(&deposit_sets, "goerli", dir.path(), NUM_NODES)
            .await
            .unwrap();

        for set in [&datas1, &datas2] {
            let expected = marshal_deposit_data(set, "goerli").unwrap();
            for n in 0..NUM_NODES {
                let node_dir = dir.path().join(format!("node{n}"));
                let file_path = get_deposit_file_path(&node_dir, set[0].amount);
                let actual = tokio::fs::read(&file_path).await.unwrap();
                assert_eq!(expected, actual);
            }
        }
    }
}
