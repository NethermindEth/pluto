//! Create DKG command utilities.
//!
//! This module provides utilities for the `pluto create dkg` command,
//! including validation functions for withdrawal addresses.

use pluto_eth2util::{self as eth2util};
use thiserror::Error;

use crate::commands::create_cluster::{ZERO_ADDRESS, is_main_or_gnosis};

/// Errors that can occur during withdrawal address validation.
#[derive(Error, Debug)]
pub enum WithdrawalValidationError {
    /// Invalid withdrawal address.
    #[error("Invalid withdrawal address: {address}")]
    InvalidWithdrawalAddress {
        /// The invalid address.
        address: String,
    },

    /// Invalid checksummed address.
    #[error("Invalid checksummed address: {address}")]
    InvalidChecksummedAddress {
        /// The address with invalid checksum.
        address: String,
    },

    /// Zero address forbidden on mainnet/gnosis.
    #[error("Zero address forbidden on this network: {network}")]
    ZeroAddressForbiddenOnNetwork {
        /// The network name.
        network: String,
    },

    /// Eth2util helpers error.
    #[error("Eth2util helpers error: {0}")]
    Eth2utilHelperError(#[from] eth2util::helpers::HelperError),
}

/// Validates withdrawal addresses for the given network.
///
/// Returns an error if any of the provided withdrawal addresses is invalid.
pub fn validate_withdrawal_addrs(
    addrs: &[String],
    network: &str,
) -> std::result::Result<(), WithdrawalValidationError> {
    for addr in addrs {
        let checksum_addr = eth2util::helpers::checksum_address(addr).map_err(|_| {
            WithdrawalValidationError::InvalidWithdrawalAddress {
                address: addr.clone(),
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
