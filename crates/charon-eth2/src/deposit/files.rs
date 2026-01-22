use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use charon_crypto::types::{PUBLIC_KEY_LENGTH, PublicKey, SIGNATURE_LENGTH, Signature};

use super::{
    constants::{Gwei, *},
    types::{DepositData, DepositDataJson},
};

/// Error type for file operations
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// JSON error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Hex decoding error
    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),

    /// Invalid data
    #[error("Invalid {field}: {message}")]
    InvalidData {
        /// Field name
        field: String,
        /// Error message
        message: String,
    },

    /// Empty deposit data
    #[error("Empty deposit data")]
    EmptyDepositData,

    /// Deposit amounts not equal
    #[error("Deposit datas have different amounts at index {0}")]
    UnequalAmounts(usize),

    /// No deposit files found
    #[error("No deposit-data*.json files found in {0}")]
    NoFilesFound(String),
}

/// Constructs the file path for a deposit data file based on amount.
///
/// # Arguments
/// * `data_dir` - Directory where deposit file should be stored
/// * `amount` - Deposit amount in Gwei
///
/// # Returns
/// Path to the deposit data file:
/// - For 32 ETH: "deposit-data.json" (backwards compatibility)
/// - For other amounts: "deposit-data-{eth}eth.json"
/// NOTE: DOUBLE CHECK THE FORMAT OF THE FILENAME
/// format!("deposit-data-{}eth.json", eth.to_string())
pub fn get_deposit_file_path(data_dir: &Path, amount: Gwei) -> PathBuf {
    let filename = if amount == DEFAULT_DEPOSIT_AMOUNT {
        // For backward compatibility, use the old filename for 32 ETH
        "deposit-data.json".to_string()
    } else {
        // Convert Gwei to ETH and format
        let eth = amount.as_u64() as f64 / ONE_ETH_IN_GWEI.as_u64() as f64;
        format!("deposit-data-{}eth.json", eth)
    };

    data_dir.join(filename)
}

/// Writes a single deposit data file for the provided deposit datas.
///
/// All deposit datas must have the same amount value.
///
/// # Arguments
/// * `deposit_datas` - Slice of deposit data (all must have same amount)
/// * `network` - Network name (e.g., "mainnet", "goerli")
/// * `data_dir` - Directory where file should be written
///
/// # Errors
/// Returns error if:
/// - Deposit datas is empty
/// - Deposit datas have different amounts
/// - Marshaling fails
/// - File write fails
/// NOTE: DONE
pub fn write_deposit_data_file(
    deposit_datas: &[DepositData],
    network: &str,
    data_dir: &Path,
) -> Result<(), FileError> {
    if deposit_datas.is_empty() {
        return Err(FileError::EmptyDepositData);
    }

    // Verify all amounts are equal
    let first_amount = deposit_datas[0].amount;
    for (i, dd) in deposit_datas.iter().enumerate() {
        if dd.amount != first_amount {
            return Err(FileError::UnequalAmounts(i));
        }
    }

    // Marshal to JSON
    let bytes = super::marshal_deposit_data(deposit_datas, network).map_err(|e| {
        FileError::InvalidData {
            field: "deposit_data".to_string(),
            message: e.to_string(),
        }
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

/// Writes deposit data files for a cluster across all node directories.
///
/// # Arguments
/// * `deposit_datas` - Vector of deposit data sets (one per amount)
/// * `network` - Network name
/// * `cluster_dir` - Root cluster directory
/// * `num_nodes` - Number of nodes in the cluster
///
/// # Errors
/// Returns error if file writing fails for any node
/// NOTE: DONE
pub fn write_cluster_deposit_data_files(
    deposit_datas: &[&[DepositData]],
    network: &str,
    cluster_dir: &Path,
    num_nodes: usize,
) -> Result<(), FileError> {
    for deposit_data_set in deposit_datas {
        for n in 0..num_nodes {
            let node_dir = cluster_dir.join(format!("node{}", n));
            write_deposit_data_file(deposit_data_set, network, &node_dir)?;
        }
    }

    Ok(())
}

/// Reads all deposit data files from a cluster directory.
///
/// # Arguments
/// * `cluster_dir` - Cluster directory containing deposit-data*.json files
///
/// # Returns
/// Vector of deposit data sets, ordered by amount
///
/// # Errors
/// Returns error if:
/// - No deposit files found
/// - File read fails
/// - JSON parsing fails
/// - Data validation fails
/// NOTE: DONE
pub fn read_deposit_data_files(cluster_dir: &Path) -> Result<Vec<Vec<DepositData>>, FileError> {
    // Find all deposit-data*.json files
    let pattern = cluster_dir.join("deposit-data*.json");
    let pattern_str = pattern.to_str().ok_or_else(|| FileError::InvalidData {
        field: "path".to_string(),
        message: "Invalid UTF-8 in path".to_string(),
    })?;

    let files: Vec<PathBuf> = glob::glob(pattern_str)
        .map_err(|e| FileError::InvalidData {
            field: "glob_pattern".to_string(),
            message: e.to_string(),
        })?
        .filter_map(Result::ok)
        .collect();

    if files.is_empty() {
        return Err(FileError::NoFilesFound(cluster_dir.display().to_string()));
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
                    .map_err(|_| FileError::InvalidData {
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
                    .map_err(|_| FileError::InvalidData {
                        field: "withdrawal_credentials".to_string(),
                        message: format!("Expected 32 bytes, got {}", wc_bytes.len()),
                    })?;

            // Decode signature
            let sig_bytes = hex::decode(&d.signature)?;
            let signature: Signature =
                sig_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| FileError::InvalidData {
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
                amount: Gwei(d.amount),
                signature,
            });
        }

        deposit_datas_list.push(deposit_datas);
    }

    Ok(deposit_datas_list)
}

/// Merges two sets of deposit data files.
///
/// Combines deposit data by amount, removing duplicates.
///
/// # Arguments
/// * `a` - First set of deposit data
/// * `b` - Second set of deposit data
///
/// # Returns
/// Merged deposit data sets
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
    fn test_get_deposit_file_path() {
        let dir = Path::new("/tmp/test");

        // Default amount (32 ETH) should use old filename
        let path = get_deposit_file_path(dir, DEFAULT_DEPOSIT_AMOUNT);
        assert_eq!(path, dir.join("deposit-data.json"));

        // 1 ETH
        let path = get_deposit_file_path(dir, MIN_DEPOSIT_AMOUNT);
        assert_eq!(path, dir.join("deposit-data-1eth.json"));

        // 31.999999999 ETH (DEFAULT - 1 Gwei)
        let path = get_deposit_file_path(dir, DEFAULT_DEPOSIT_AMOUNT - Gwei(1));
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

    /// Comprehensive test for deposit file path formatting to match Go's strconv.FormatFloat(eth, 'f', -1, 64).
    ///
    /// Verifies that Rust's format!("{}", f64) produces identical output to Go for:
    /// - Whole numbers (no ".0" suffix)
    /// - Decimals (no trailing zeros)
    /// - Small numbers (fixed-point, not scientific notation)
    /// - Large numbers (no scientific notation)
    /// - Problematic floats (0.3, 0.7)
    ///
    /// If this test fails, implement explicit Go-compatible formatting.
    #[test]
    fn test_deposit_file_path_go_formatting_compatibility() {
        use std::path::Path;

        let data_dir = Path::new("/tmp/deposits");

        struct TestCase {
            gwei: u64,
            expected_filename: &'static str,
            description: &'static str,
        }

        let test_cases = vec![
            // Legacy filename for default amount
            TestCase {
                gwei: 32_000_000_000,
                expected_filename: "deposit-data.json",
                description: "32 ETH - legacy filename",
            },
            // Whole numbers - no decimal point or trailing zeros
            TestCase {
                gwei: 1_000_000_000,
                expected_filename: "deposit-data-1eth.json",
                description: "1 ETH - no trailing .0",
            },
            TestCase {
                gwei: 16_000_000_000,
                expected_filename: "deposit-data-16eth.json",
                description: "16 ETH - no trailing .0",
            },
            TestCase {
                gwei: 100_000_000_000,
                expected_filename: "deposit-data-100eth.json",
                description: "100 ETH - no trailing .0",
            },
            TestCase {
                gwei: 1_000_000_000_000_000,
                expected_filename: "deposit-data-1000000eth.json",
                description: "1M ETH - large number, no scientific notation",
            },
            // Decimals - no trailing zeros
            TestCase {
                gwei: 100_000_000,
                expected_filename: "deposit-data-0.1eth.json",
                description: "0.1 ETH - one decimal",
            },
            TestCase {
                gwei: 500_000_000,
                expected_filename: "deposit-data-0.5eth.json",
                description: "0.5 ETH - one decimal",
            },
            TestCase {
                gwei: 1_500_000_000,
                expected_filename: "deposit-data-1.5eth.json",
                description: "1.5 ETH - one decimal",
            },
            TestCase {
                gwei: 1_250_000_000,
                expected_filename: "deposit-data-1.25eth.json",
                description: "1.25 ETH - two decimals",
            },
            TestCase {
                gwei: 125_000_000,
                expected_filename: "deposit-data-0.125eth.json",
                description: "0.125 ETH - three decimals",
            },
            TestCase {
                gwei: 62_500_000,
                expected_filename: "deposit-data-0.0625eth.json",
                description: "0.0625 ETH - four decimals",
            },
            TestCase {
                gwei: 24_500_000_000,
                expected_filename: "deposit-data-24.5eth.json",
                description: "24.5 ETH - non-standard amount",
            },
            TestCase {
                gwei: 32_100_000_000,
                expected_filename: "deposit-data-32.1eth.json",
                description: "32.1 ETH - slightly more than default",
            },
            TestCase {
                gwei: 10_100_000_000,
                expected_filename: "deposit-data-10.1eth.json",
                description: "10.1 ETH - decimal precision",
            },
            // Problematic floats (binary representation issues)
            TestCase {
                gwei: 300_000_000,
                expected_filename: "deposit-data-0.3eth.json",
                description: "0.3 ETH - known problematic float",
            },
            TestCase {
                gwei: 700_000_000,
                expected_filename: "deposit-data-0.7eth.json",
                description: "0.7 ETH - known problematic float",
            },
            // Very small amounts - must use fixed-point notation, not scientific
            TestCase {
                gwei: 1_000,
                expected_filename: "deposit-data-0.000001eth.json",
                description: "0.000001 ETH - 6 decimals, no scientific notation",
            },
            TestCase {
                gwei: 10,
                expected_filename: "deposit-data-0.00000001eth.json",
                description: "10 Gwei - 8 decimals, no scientific notation",
            },
            TestCase {
                gwei: 1,
                expected_filename: "deposit-data-0.000000001eth.json",
                description: "1 Gwei - 9 decimals, no scientific notation",
            },
        ];

        for test_case in test_cases {
            let amount = Gwei::new(test_case.gwei);
            let path = get_deposit_file_path(data_dir, amount);
            let actual_filename = path.file_name().unwrap().to_str().unwrap();

            // Check exact filename match
            assert_eq!(
                actual_filename, test_case.expected_filename,
                "Failed for {}: expected '{}', got '{}'",
                test_case.description, test_case.expected_filename, actual_filename
            );

            // For non-legacy filenames, verify no scientific notation in the number part
            if test_case.gwei != 32_000_000_000 {
                let number_part = actual_filename
                    .strip_prefix("deposit-data-")
                    .and_then(|s| s.strip_suffix("eth.json"))
                    .expect("filename should have correct prefix/suffix");
                
                assert!(
                    !number_part.contains('e') && !number_part.contains('E'),
                    "Number part '{}' should not use scientific notation for {}",
                    number_part, test_case.description
                );
            }
        }
    }
}
