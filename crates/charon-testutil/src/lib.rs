//! # Charon Test Utilities
//!
//! Testing utilities and mock implementations for the Charon distributed
//! validator node. This crate provides test helpers, mock objects, and testing
//! utilities for unit tests, integration tests, and development.

/// Adds two numbers together.
///
/// # Arguments
///
/// * `left` - The first number to add
/// * `right` - The second number to add
///
/// # Returns
///
/// The sum of the two numbers
///
/// # Examples
///
/// ```
/// use charon_testutil::add;
///
/// let result = add(2, 2);
/// assert_eq!(result, 4);
/// ```
pub fn add(left: u64, right: u64) -> u64 {
    left.wrapping_add(right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
