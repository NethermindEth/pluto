use super::constants::{Gwei, *};

/// Error type for deposit amount operations
#[derive(Debug, thiserror::Error)]
pub enum AmountError {
    /// Amount is below minimum
    #[error("Each partial deposit amount must be greater than 1ETH, got {0} Gwei")]
    BelowMinimum(Gwei),

    /// Amount exceeds maximum
    #[error(
        "Single partial deposit amount is too large unless --compounding validators are used: {amount} Gwei (max: {max} Gwei)"
    )]
    ExceedsMaximum {
        /// Actual amount
        amount: Gwei,
        /// Maximum allowed
        max: Gwei,
    },

    /// Sum of amounts is below default
    #[error(
        "Sum of partial deposit amounts must be at least 32ETH, repetition is allowed: {0} Gwei"
    )]
    SumBelowDefault(Gwei),
}

/// Returns the maximum deposit amount based on compounding flag.
///
/// # Arguments
/// * `compounding` - Whether compounding is enabled (EIP-7251)
///
/// # Returns
/// Maximum deposit amount in Gwei (2048 ETH if compounding, 32 ETH otherwise)
/// NOTE: DONE
pub fn max_deposit_amount(compounding: bool) -> Gwei {
    if compounding {
        MAX_COMPOUNDING_DEPOSIT_AMOUNT
    } else {
        MAX_STANDARD_DEPOSIT_AMOUNT
    }
}

/// Verifies various conditions about partial deposit amounts.
///
/// # Arguments
/// * `amounts` - Slice of deposit amounts in Gwei
/// * `compounding` - Whether compounding is enabled
///
/// # Errors
/// Returns error if:
/// - Any amount is less than 1 ETH
/// - Any amount exceeds the maximum for the given compounding mode
/// - Sum of amounts is less than 32 ETH
///
/// # Returns
/// Ok(()) if all validation passes, empty slice is allowed (defaults to 32 ETH)
/// NOTE: DONE
pub fn verify_deposit_amounts(amounts: &[Gwei], compounding: bool) -> Result<(), AmountError> {
    if amounts.is_empty() {
        // If no partial amounts specified, the implementation shall default to 32ETH
        return Ok(());
    }

    let max_amount = max_deposit_amount(compounding);
    let mut sum = Gwei(0);

    for &amount in amounts {
        if amount < MIN_DEPOSIT_AMOUNT {
            return Err(AmountError::BelowMinimum(amount));
        }

        if amount > max_amount {
            return Err(AmountError::ExceedsMaximum {
                amount,
                max: max_amount,
            });
        }

        sum = sum + amount;
    }

    if sum < DEFAULT_DEPOSIT_AMOUNT {
        return Err(AmountError::SumBelowDefault(sum));
    }

    Ok(())
}

/// Converts amounts from ETH (as integers) to Gwei.
///
/// # Arguments
/// * `eth_amounts` - Slice of amounts in ETH
///
/// # Returns
/// Vector of amounts in Gwei, or empty vector if input is empty
/// NOTE: Should we check if eth_amounts is negative
pub fn eths_to_gweis(eth_amounts: &[i32]) -> Vec<Gwei> {
    eth_amounts
        .iter()
        .map(|&eth| ONE_ETH_IN_GWEI * (eth as u64))
        .collect()
}

/// Deduplicates and sorts amounts in ascending order.
///
/// # Arguments
/// * `amounts` - Slice of deposit amounts in Gwei
///
/// # Returns
/// Deduplicated and sorted vector of amounts
/// NOTE: DONE
pub fn dedup_amounts(amounts: &[Gwei]) -> Vec<Gwei> {
    let mut result: Vec<Gwei> = amounts
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    result.sort_unstable();
    result
}

/// Returns the default deposit amounts based on compounding flag.
///
/// # Arguments
/// * `compounding` - Whether compounding is enabled
///
/// # Returns
/// - If compounding=false: [1, 32] ETH
/// - If compounding=true: [1, 8, 32, 256] ETH
/// NOTE: DONE
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_deposit_amount() {
        assert_eq!(max_deposit_amount(false), MAX_STANDARD_DEPOSIT_AMOUNT);
        assert_eq!(max_deposit_amount(true), MAX_COMPOUNDING_DEPOSIT_AMOUNT);
    }

    #[test]
    fn test_verify_deposit_amounts_empty() {
        assert!(verify_deposit_amounts(&[], false).is_ok());
        assert!(verify_deposit_amounts(&[], true).is_ok());
    }

    #[test]
    fn test_verify_deposit_amounts_valid() {
        let amounts = vec![Gwei(16_000_000_000), Gwei(16_000_000_000)]; // 16 ETH + 16 ETH = 32 ETH
        assert!(verify_deposit_amounts(&amounts, false).is_ok());
    }

    #[test]
    fn test_verify_deposit_amounts_below_minimum() {
        let amounts = vec![Gwei(500_000_000), Gwei(31_500_000_000)]; // 0.5 ETH + 31.5 ETH
        let err = verify_deposit_amounts(&amounts, false).unwrap_err();
        assert!(matches!(err, AmountError::BelowMinimum(_)));
    }

    #[test]
    fn test_verify_deposit_amounts_exceeds_max() {
        let amounts = vec![MIN_DEPOSIT_AMOUNT, Gwei(33_000_000_000)]; // 1 ETH + 33 ETH
        let err = verify_deposit_amounts(&amounts, false).unwrap_err();
        assert!(matches!(err, AmountError::ExceedsMaximum { .. }));

        // But should work with compounding
        assert!(verify_deposit_amounts(&amounts, true).is_ok());
    }

    #[test]
    fn test_verify_deposit_amounts_sum_below_default() {
        let amounts = vec![Gwei(8_000_000_000), Gwei(16_000_000_000)]; // 8 ETH + 16 ETH = 24 ETH
        let err = verify_deposit_amounts(&amounts, false).unwrap_err();
        assert!(matches!(err, AmountError::SumBelowDefault(_)));
    }

    #[test]
    fn test_eths_to_gweis() {
        assert_eq!(eths_to_gweis(&[]), Vec::<Gwei>::new());
        assert_eq!(
            eths_to_gweis(&[1, 5]),
            vec![Gwei(1_000_000_000), Gwei(5_000_000_000)]
        );
    }

    #[test]
    fn test_dedup_amounts() {
        let amounts = vec![Gwei(100), Gwei(500), Gwei(100), Gwei(0), Gwei(0), Gwei(300)];
        assert_eq!(
            dedup_amounts(&amounts),
            vec![Gwei(0), Gwei(100), Gwei(300), Gwei(500)]
        );
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
}
