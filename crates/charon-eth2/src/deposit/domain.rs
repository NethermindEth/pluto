// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business
// Source License 1.1

//! Deposit domain and signing root computation

use tree_hash::TreeHash;

use super::{
    constants::*,
    types::{DepositMessage, ForkData, SigningData},
};
use crate::network;

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

    /// Invalid address checksum
    #[error("Invalid address checksum: {0}")]
    InvalidChecksum(String),
}

/// Converts an Ethereum address to withdrawal credentials.
///
/// # Arguments
/// * `addr` - Ethereum address (with or without 0x prefix)
/// * `compounding` - Whether to use EIP-7251 compounding withdrawal credentials
///
/// # Returns
/// 32-byte withdrawal credentials
///
/// # Errors
/// Returns error if address is invalid or checksum fails
/// NOTE: Done
pub(crate) fn withdrawal_creds_from_addr(
    addr: &str,
    compounding: bool,
) -> Result<[u8; 32], DomainError> {
    // Validate checksum
    validate_checksum(addr)?;

    // Remove 0x prefix if present
    let addr_hex = addr.strip_prefix("0x").unwrap_or(addr);

    // Decode address bytes
    let addr_bytes = hex::decode(addr_hex)?;

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

/// Validates Ethereum address checksum using EIP-55.
///
/// # Arguments
/// * `addr` - Ethereum address to validate
///
/// # Errors
/// Returns error if checksum validation fails
/// NOTE: Consider to use alloy-primitive
/// NOTE: or create eth2util/helper
fn validate_checksum(addr: &str) -> Result<(), DomainError> {
    let addr_no_prefix = addr.strip_prefix("0x").unwrap_or(addr);

    // Check length
    if addr_no_prefix.len() != 40 {
        return Err(DomainError::InvalidAddress(format!(
            "Address must be 40 hex characters, got {}",
            addr_no_prefix.len()
        )));
    }

    // If all lowercase or all uppercase, skip checksum validation
    let has_uppercase = addr_no_prefix.chars().any(|c| c.is_uppercase());
    let has_lowercase = addr_no_prefix.chars().any(|c| c.is_lowercase());

    if !has_uppercase || !has_lowercase {
        // Mixed case not present, skip validation
        return Ok(());
    }

    // Compute checksum using Keccak256
    use sha3::{Digest, Keccak256};
    let hash = Keccak256::digest(addr_no_prefix.to_lowercase().as_bytes());

    for (i, ch) in addr_no_prefix.chars().enumerate() {
        if ch.is_alphabetic() {
            let hash_byte = hash[i / 2];
            let hash_nibble = if i % 2 == 0 {
                hash_byte >> 4
            } else {
                hash_byte & 0x0f
            };

            let should_be_uppercase = hash_nibble >= 8;

            if ch.is_uppercase() != should_be_uppercase {
                return Err(DomainError::InvalidChecksum(addr.to_string()));
            }
        }
    }

    Ok(())
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
        let addr = "321dcb529f3945bc94fecea9d3bc5caf35253b94";
        let creds = withdrawal_creds_from_addr(addr, false).unwrap();
        assert_eq!(creds[0], ETH1_ADDRESS_WITHDRAWAL_PREFIX);
    }

    #[test]
    fn test_invalid_address_length() {
        let addr = "0x321dcb5"; // Too short
        let err = withdrawal_creds_from_addr(addr, false).unwrap_err();
        assert!(matches!(err, DomainError::InvalidAddress(_)));
    }

    #[test]
    fn test_validate_checksum_all_lowercase() {
        // All lowercase should pass
        assert!(validate_checksum("0x321dcb529f3945bc94fecea9d3bc5caf35253b94").is_ok());
    }

    #[test]
    fn test_validate_checksum_all_uppercase() {
        // All uppercase should pass
        assert!(validate_checksum("0x321DCB529F3945BC94FECEA9D3BC5CAF35253B94").is_ok());
    }

    #[test]
    fn test_validate_checksum_valid_mixed_case() {
        // Valid EIP-55 checksummed address
        let addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        assert!(validate_checksum(addr).is_ok());
    }

    #[test]
    fn test_validate_checksum_invalid() {
        // Invalid checksum (wrong case for some letters)
        let addr = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"; // Should have some uppercase
        // This is all lowercase, so it passes (no checksum validation)
        assert!(validate_checksum(addr).is_ok());

        // But this should fail (mixed case but wrong checksum)
        let addr_wrong = "0x5aAeb6053f3E94C9b9A09f33669435E7Ef1BeAed"; // Wrong case
        assert!(validate_checksum(addr_wrong).is_err());
    }
}
