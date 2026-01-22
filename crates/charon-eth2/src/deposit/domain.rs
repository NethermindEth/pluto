// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business
// Source License 1.1

//! Deposit domain and signing root computation

use tree_hash::TreeHash;

use super::{
    constants::*,
    types::{DepositMessage, ForkData, SigningData},
};
use crate::{helpers, network};

use super::constants::{Domain, Root, Version};

/// Error type for domain operations
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    /// Invalid Ethereum address
    #[error("Invalid withdrawal address: {0}")]
    InvalidAddress(String),

    /// Hex decoding error
    #[error("Failed to decode hex: {0}")]
    HexError(#[from] hex::FromHexError),

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(#[from] network::NetworkError),

    /// Helper error
    #[error("Address validation error: {0}")]
    HelperError(#[from] helpers::HelperError),
}

/// Converts an Ethereum address to withdrawal credentials.
///
/// # Arguments
/// * `addr` - Ethereum address with 0x prefix (format validation only, checksum not enforced)
/// * `compounding` - Whether to use EIP-7251 compounding withdrawal credentials
///
/// # Returns
/// 32-byte withdrawal credentials
///
/// # Errors
/// Returns error if address format is invalid
/// NOTE: Done - Uses helpers::checksum_address to match Go's eth2util.ChecksumAddress behavior
/// Go's ChecksumAddress accepts any valid hex without validating existing EIP-55 checksums
pub(crate) fn withdrawal_creds_from_addr(
    addr: &str,
    compounding: bool,
) -> Result<[u8; 32], DomainError> {
    // Validate address format and get checksummed version
    // This matches Go's eth2util.ChecksumAddress: validates format but doesn't validate checksums
    helpers::checksum_address(addr)?;

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
        return Err(DomainError::InvalidAddress(format!(
            "Address must be 20 bytes, got {}",
            addr_bytes.len()
        )));
    }
    creds[12..32].copy_from_slice(&addr_bytes);

    Ok(creds)
}


/// Returns the deposit domain for the given fork version.
///
/// # Arguments
/// * `fork_version` - Fork version
///
/// # Returns
/// Deposit domain
/// NOTE: DONE
pub(crate) fn get_deposit_domain(fork_version: Version) -> Domain {
    // Create ForkData with genesis validators root set to zero (per deposit spec)
    let fork_data = ForkData {
        current_version: fork_version,
        genesis_validators_root: Root::default(),
    };

    // Compute fork data root
    let fork_data_root = fork_data.tree_hash_root();

    // Construct domain: first 4 bytes are domain type, last 28 bytes are from fork
    // data root
    let mut domain = Domain::default();
    domain[0..4].copy_from_slice(&DEPOSIT_DOMAIN_TYPE);
    domain[4..32].copy_from_slice(&fork_data_root.0[0..28]);

    domain
}

/// Returns the deposit message signing root for the given message and network.
///
/// # Arguments
/// * `msg` - Deposit message to sign
/// * `network` - Network name (e.g., "mainnet", "goerli")
///
/// # Returns
/// Signing root
///
/// # Errors
/// Returns error if network is invalid or fork version cannot be determined
/// NOTE: DONE
pub fn get_message_signing_root(msg: &DepositMessage, network: &str) -> Result<Root, DomainError> {
    // Get message root
    let msg_root = msg.tree_hash_root();

    // Get fork version for network
    let fork_version_bytes = network::network_to_fork_version_bytes(network)?;

    let fork_version: Version = fork_version_bytes.as_slice().try_into().map_err(|_| {
        DomainError::NetworkError(network::NetworkError::InvalidForkVersion {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        // Error is HelperError wrapped in DomainError
        assert!(matches!(err, DomainError::HelperError(_)));
    }

    #[test]
    fn test_invalid_address_length() {
        let addr = "0x321dcb5"; // Too short
        let err = withdrawal_creds_from_addr(addr, false).unwrap_err();
        // Error is HelperError wrapped in DomainError
        assert!(matches!(err, DomainError::HelperError(_)));
    }

    #[test]
    fn test_address_parsing_all_lowercase() {
        // All lowercase with 0x prefix should pass (matching Go's lenient behavior)
        let addr = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";
        assert!(helpers::checksum_address(addr).is_ok());
        assert!(withdrawal_creds_from_addr(addr, false).is_ok());
    }

    #[test]
    fn test_address_parsing_all_uppercase() {
        // All uppercase with 0x prefix should pass (matching Go's lenient behavior)
        let addr = "0x321DCB529F3945BC94FECEA9D3BC5CAF35253B94";
        assert!(helpers::checksum_address(addr).is_ok());
        assert!(withdrawal_creds_from_addr(addr, false).is_ok());
    }

    #[test]
    fn test_address_parsing_valid_checksum() {
        // Valid EIP-55 checksummed address should pass
        let addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        assert!(helpers::checksum_address(addr).is_ok());
        assert!(withdrawal_creds_from_addr(addr, false).is_ok());
    }

    #[test]
    fn test_address_parsing_invalid_checksum_accepted() {
        // Mixed case with WRONG checksum is ACCEPTED (matching Go's lenient behavior)
        // Go doesn't validate checksums, just accepts valid hex
        let addr_wrong = "0x5aAeb6053f3E94C9b9A09f33669435E7Ef1BeAed";
        assert!(helpers::checksum_address(addr_wrong).is_ok());
        assert!(withdrawal_creds_from_addr(addr_wrong, false).is_ok());
    }

    #[test]
    fn test_address_requires_prefix() {
        // Address without 0x prefix should fail (matching Go's behavior)
        let addr = "321dcb529f3945bc94fecea9d3bc5caf35253b94";
        assert!(withdrawal_creds_from_addr(addr, false).is_err());

        // With prefix should work
        let addr_with_prefix = "0x321dcb529f3945bc94fecea9d3bc5caf35253b94";
        assert!(withdrawal_creds_from_addr(addr_with_prefix, false).is_ok());
    }

}
