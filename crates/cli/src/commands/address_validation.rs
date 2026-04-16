#[derive(thiserror::Error, Debug)]
pub enum AddressValidationError {
    /// Value exceeds usize::MAX.
    #[error("Value {value} exceeds usize::MAX")]
    ValueExceedsUsize {
        /// The value that exceeds usize::MAX.
        value: u64,
    },

    /// Mismatching number of fee recipient addresses.
    #[error(
        "mismatching --num-validators and --fee-recipient-addresses: num_validators={num_validators}, addresses={addresses}"
    )]
    MismatchingFeeRecipientAddresses {
        /// Number of validators.
        num_validators: u64,
        /// Number of addresses.
        addresses: usize,
    },

    /// Mismatching number of withdrawal addresses.
    #[error(
        "mismatching --num-validators and --withdrawal-addresses: num_validators={num_validators}, addresses={addresses}"
    )]
    MismatchingWithdrawalAddresses {
        /// Number of validators.
        num_validators: u64,
        /// Number of addresses.
        addresses: usize,
    },
}

type Result<T> = std::result::Result<T, AddressValidationError>;

/// Validates that addresses match the number of validators.
/// If only one address is provided, it fills the slice to match num_validators.
///
/// Returns an error if the number of addresses doesn't match and isn't exactly
/// 1.
pub(crate) fn validate_addresses(
    num_validators: u64,
    fee_recipient_addrs: &[String],
    withdrawal_addrs: &[String],
) -> Result<(Vec<String>, Vec<String>)> {
    let num_validators_usize =
        usize::try_from(num_validators).map_err(|_| AddressValidationError::ValueExceedsUsize {
            value: num_validators,
        })?;

    if fee_recipient_addrs.len() != num_validators_usize && fee_recipient_addrs.len() != 1 {
        return Err(AddressValidationError::MismatchingFeeRecipientAddresses {
            num_validators,
            addresses: fee_recipient_addrs.len(),
        });
    }

    if withdrawal_addrs.len() != num_validators_usize && withdrawal_addrs.len() != 1 {
        return Err(AddressValidationError::MismatchingWithdrawalAddresses {
            num_validators,
            addresses: withdrawal_addrs.len(),
        });
    }

    let mut fee_addrs = fee_recipient_addrs.to_vec();
    let mut withdraw_addrs = withdrawal_addrs.to_vec();

    if fee_addrs.len() == 1 {
        let addr = fee_addrs[0].clone();
        fee_addrs = vec![addr; num_validators_usize];
    }

    if withdraw_addrs.len() == 1 {
        let addr = withdraw_addrs[0].clone();
        withdraw_addrs = vec![addr; num_validators_usize];
    }

    Ok((fee_addrs, withdraw_addrs))
}
