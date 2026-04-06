//! Test utilities for the Charon core.

use rand::Rng;

use crate::types::PubKey;

/// Returns a random core workflow pubkey.
pub fn random_core_pub_key() -> PubKey {
    random_core_pub_key_seed(rand::thread_rng())
}

/// Returns a random core workflow pubkey using a provided random source.
pub fn random_core_pub_key_seed<R: Rng>(mut rng: R) -> PubKey {
    let mut key = [0u8; 48];
    rng.fill_bytes(&mut key);
    PubKey::from(key)
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn test_random_core_pub_key_generates_valid_keys() {
        let pk1 = random_core_pub_key();
        let pk2 = random_core_pub_key();

        // Keys should be different
        assert_ne!(pk1, pk2);

        // Keys should have the correct length when serialized
        assert_eq!(pk1.to_string().len(), 98); // 0x + 96 hex chars
        assert_eq!(pk2.to_string().len(), 98);
    }

    #[test]
    fn test_random_core_pub_key_seed_is_deterministic() {
        let seed = 12345u64;
        let rng1 = rand::rngs::StdRng::seed_from_u64(seed);
        let rng2 = rand::rngs::StdRng::seed_from_u64(seed);

        let pk1 = random_core_pub_key_seed(rng1);
        let pk2 = random_core_pub_key_seed(rng2);

        // Same seed should produce same key
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_random_core_pub_key_seed_different_rngs() {
        let rng1 = rand::rngs::StdRng::seed_from_u64(1);
        let rng2 = rand::rngs::StdRng::seed_from_u64(2);

        let pk1 = random_core_pub_key_seed(rng1);
        let pk2 = random_core_pub_key_seed(rng2);

        // Different seeds should produce different keys
        assert_ne!(pk1, pk2);
    }
}
