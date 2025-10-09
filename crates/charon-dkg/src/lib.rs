//! # Charon DKG
//!
//! Distributed Key Generation (DKG) protocols for Charon distributed validator
//! nodes. This crate implements the cryptographic protocols required for
//! generating, distributing, and managing validator keys across the distributed
//! network.

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
/// use charon_dkg::add;
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
