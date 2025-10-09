//! # Charon P2P
//!
//! Peer-to-peer networking and communication for the Charon distributed
//! validator node. This crate provides networking protocols, peer discovery,
//! and communication mechanisms for validator nodes to coordinate and exchange
//! information.

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
/// use charon_p2p::add;
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
