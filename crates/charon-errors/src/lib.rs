//! # Charon Errors
//!
//! Error types and error handling utilities for the Charon distributed
//! validator node. This crate defines the error types, error codes, and error
//! handling mechanisms used throughout the Charon system.

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
/// use charon_errors::add;
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
