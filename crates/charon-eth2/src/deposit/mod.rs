mod amounts;
mod constants;
mod domain;
mod files;
mod types;

// Re-export public API
pub use amounts::{
    AmountError, dedup_amounts, default_deposit_amounts, eths_to_gweis, max_deposit_amount,
    verify_deposit_amounts,
};
pub use constants::{Domain, Gwei, Root, Version, *};
pub use domain::{DomainError, get_message_signing_root};
pub use files::{
    FileError, get_deposit_file_path, merge_deposit_data_sets, read_deposit_data_files,
    write_cluster_deposit_data_files, write_deposit_data_file,
};
pub use types::{DepositData, DepositDataJson, DepositMessage};

// Re-export crypto types for convenience
pub use charon_crypto::types::{PublicKey, Signature};

use tree_hash::TreeHash;

/// Error type for deposit operations
#[derive(Debug, thiserror::Error)]
pub enum DepositError {
    /// Amount error
    #[error("Amount error: {0}")]
    AmountError(#[from] AmountError),

    /// Domain error
    #[error("Domain error: {0}")]
    DomainError(#[from] DomainError),

    /// Deposit message minimum amount not met
    #[error("Deposit message minimum amount must be >= 1ETH, got {0} Gwei")]
    MinimumAmountNotMet(Gwei),

    /// Deposit message maximum amount exceeded
    #[error("Deposit message maximum amount exceeded: {amount} Gwei (max: {max} Gwei)")]
    MaximumAmountExceeded {
        /// Actual amount
        amount: Gwei,
        /// Maximum allowed
        max: Gwei,
    },

    /// BLS signature verification failed
    #[error("Invalid deposit data signature: {0}")]
    InvalidSignature(String),

    /// Hash tree root computation error
    #[error("Hash tree root error: {0}")]
    HashTreeRootError(String),

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(#[from] crate::network::NetworkError),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Crypto error
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

/// Creates a new deposit message with the given parameters.
///
/// # Arguments
/// * `pubkey` - Validator's BLS public key (48 bytes)
/// * `withdrawal_addr` - Ethereum withdrawal address
/// * `amount` - Deposit amount in Gwei
/// * `compounding` - Whether to use EIP-7251 compounding withdrawal credentials
///
/// # Returns
/// A new DepositMessage
///
/// # Errors
/// Returns error if:
/// - Amount is below minimum (1 ETH)
/// - Amount exceeds maximum for the given compounding mode
/// - Withdrawal address is invalid
/// NOTE: DONE
pub fn new_message(
    pubkey: PublicKey,
    withdrawal_addr: &str,
    amount: Gwei,
    compounding: bool,
) -> Result<DepositMessage, DepositError> {
    // Get withdrawal credentials
    let withdrawal_credentials = domain::withdrawal_creds_from_addr(withdrawal_addr, compounding)?;

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

/// Serializes a list of deposit data into JSON format compatible with the
/// Ethereum deposit CLI.
///
/// This function:
/// 1. Verifies each deposit data signature
/// 2. Computes deposit message root and deposit data root
/// 3. Sorts by public key
/// 4. Serializes to JSON
///
/// # Arguments
/// * `deposit_datas` - Slice of deposit data to serialize
/// * `network` - Network name (e.g., "mainnet", "goerli")
///
/// # Returns
/// JSON-encoded deposit data as bytes
///
/// # Errors
/// Returns error if:
/// - Any signature is invalid
/// - Hash tree root computation fails
/// - Network is invalid
/// - JSON serialization fails
/// NOTE: DONE
pub fn marshal_deposit_data(
    deposit_datas: &[DepositData],
    network: &str,
) -> Result<Vec<u8>, DepositError> {
    // NOTE: move to top
    use charon_crypto::{blst_impl::BlstImpl, tbls::Tbls};

    let fork_version = crate::network::network_to_fork_version(network)?;

    // NOTE : no need
    let tbls = BlstImpl;
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

        tbls.verify(&deposit_data.pub_key, &sig_data, &deposit_data.signature)
            .map_err(|e| DepositError::InvalidSignature(e.to_string()))?;

        // Compute deposit data root
        let data_root = deposit_data.tree_hash_root();

        // Create JSON entry
        dd_list.push(DepositDataJson {
            pubkey: hex::encode(deposit_data.pub_key),
            withdrawal_credentials: hex::encode(deposit_data.withdrawal_credentials),
            amount: deposit_data.amount.as_u64(),
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

    // Serialize to JSON with pretty printing
    let bytes = serde_json::to_vec_pretty(&dd_list)?;

    Ok(bytes)
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
        let amount = MIN_DEPOSIT_AMOUNT - Gwei(1);

        let err = new_message(pubkey, addr, amount, false).unwrap_err();
        assert!(matches!(err, DepositError::MinimumAmountNotMet(_)));
    }

    #[test]
    fn test_new_message_above_maximum() {
        let pubkey = [0u8; 48];
        let addr = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";

        // Non-compounding: max is 32 ETH
        let amount = MAX_STANDARD_DEPOSIT_AMOUNT + Gwei(1);
        let err = new_message(pubkey, addr, amount, false).unwrap_err();
        assert!(matches!(err, DepositError::MaximumAmountExceeded { .. }));

        // Should work with compounding
        assert!(new_message(pubkey, addr, amount, true).is_ok());
    }

    #[test]
    fn test_new_message_compounding_flag() {
        let pubkey = [0u8; 48];
        let addr = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";
        let amount = DEFAULT_DEPOSIT_AMOUNT;

        // Non-compounding
        let msg = new_message(pubkey, addr, amount, false).unwrap();
        assert_eq!(
            msg.withdrawal_credentials[0],
            ETH1_ADDRESS_WITHDRAWAL_PREFIX
        );

        // Compounding
        let msg = new_message(pubkey, addr, amount, true).unwrap();
        assert_eq!(
            msg.withdrawal_credentials[0],
            EIP7251_ADDRESS_WITHDRAWAL_PREFIX
        );
    }
}
