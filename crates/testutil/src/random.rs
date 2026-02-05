//! # Random Utilities
//!
//! Random utilities for testing.

use k256::{
    SecretKey,
    elliptic_curve::rand_core::{CryptoRng, Error, RngCore},
};
use rand::{Rng, SeedableRng, rngs::StdRng};

/// A deterministic RNG that always returns the same byte value.
/// This counter-acts the library's attempt at making ECDSA signatures
/// non-deterministic.
#[derive(Debug, Clone, Copy)]
struct ConstReader(u8);

impl RngCore for ConstReader {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([self.0; 4])
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([self.0; 8])
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(self.0);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// Mark as CryptoRng even though it's not cryptographically secure
// This is needed for the k256 API but is safe since we only use this for
// testing
impl CryptoRng for ConstReader {}

/// Generates a deterministic insecure secp256k1 private key using the provided
/// seed.
pub fn generate_insecure_k1_key(seed: u8) -> SecretKey {
    // Add 1 to seed to avoid passing 0, which could cause issues
    let mut rng = ConstReader(seed.wrapping_add(1));
    SecretKey::random(&mut rng)
}

/// Generates a deterministic 32-byte hash for testing using a seed.
pub fn random_bytes32_seed(seed: u8) -> Vec<u8> {
    let seed_bytes = [seed; 32];
    let mut rng = StdRng::from_seed(seed_bytes);

    let mut bytes = vec![0u8; 32];
    rng.fill(&mut bytes[..]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::PublicKey;

    #[test]
    fn test_deterministic_generation() {
        let key1 = generate_insecure_k1_key(42);
        let key2 = generate_insecure_k1_key(42);

        assert_eq!(
            key1.to_bytes(),
            key2.to_bytes(),
            "Keys with same seed should be identical"
        );
    }

    #[test]
    fn test_different_seeds_produce_different_keys() {
        let key1 = generate_insecure_k1_key(1);
        let key2 = generate_insecure_k1_key(2);

        assert_ne!(
            key1.to_bytes(),
            key2.to_bytes(),
            "Different seeds should produce different keys"
        );
    }

    #[test]
    fn test_zero_seed_is_handled() {
        // Should not panic or loop infinitely
        let key = generate_insecure_k1_key(0);

        // Verify it's a valid key by deriving public key
        let _pubkey: PublicKey = key.public_key();
    }

    #[test]
    fn random_bytes32_deterministic() {
        let bytes1 = random_bytes32_seed(42);
        let bytes2 = random_bytes32_seed(42);

        assert_eq!(bytes1, bytes2, "Same seed should produce identical bytes");
        assert_eq!(bytes1.len(), 32);
    }

    #[test]
    fn random_bytes32_different_seeds() {
        let bytes1 = random_bytes32_seed(1);
        let bytes2 = random_bytes32_seed(2);

        assert_ne!(
            bytes1, bytes2,
            "Different seeds should produce different bytes"
        );
    }
}
