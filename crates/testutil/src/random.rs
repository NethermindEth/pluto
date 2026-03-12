//! # Random Utilities
//!
//! Random utilities for testing.

use k256::{
    SecretKey,
    elliptic_curve::rand_core::{CryptoRng, Error, RngCore},
};
use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls, types::PrivateKey};
use pluto_eth2api::types::{
    AltairBeaconStateCurrentJustifiedCheckpoint, ConsensusVersion, Data,
    GetAggregatedAttestationV2ResponseResponse, GetAggregatedAttestationV2ResponseResponseData,
    GetBlockAttestationsV2ResponseResponseDataArray2,
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

/// Generates a deterministic BLS private key for testing.
pub fn generate_test_bls_key(seed: u64) -> PrivateKey {
    let tbls = BlstImpl;
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let rng = StdRng::from_seed(seed_bytes);
    tbls.generate_secret_key(rng)
        .expect("deterministic key generation should not fail")
}

/// Generates a random BLS signature as a hex string for testing.
///
/// Returns a 96-byte (192 hex characters) BLS signature encoded as a hex string
/// with "0x" prefix.
pub fn random_eth2_signature() -> String {
    let mut bytes = [0u8; 96];
    let mut rng = rand::thread_rng();
    for byte in &mut bytes {
        *byte = rng.r#gen();
    }
    format!("0x{}", hex::encode(bytes))
}

/// Generates a random 32-byte root as a hex string for testing.
///
/// Returns a 32-byte (64 hex characters) root encoded as a hex string with "0x" prefix.
pub fn random_root() -> String {
    let mut bytes = [0u8; 32];
    let mut rng = rand::thread_rng();
    for byte in &mut bytes {
        *byte = rng.r#gen();
    }
    format!("0x{}", hex::encode(bytes))
}

/// Generates a random bitlist as a hex string for testing.
///
/// # Arguments
///
/// * `length` - The number of bits to set in the bitlist
///
/// Returns a hex-encoded bitlist string with "0x" prefix.
pub fn random_bit_list(length: usize) -> String {
    // Create a byte array large enough to hold the bits
    // For simplicity, use 32 bytes (256 bits)
    let mut bytes = [0u8; 32];
    let mut rng = rand::thread_rng();

    // Set 'length' random bits
    for _ in 0..length {
        let bit_idx = rng.r#gen::<usize>() % 256;
        let byte_idx = bit_idx / 8;
        let bit_offset = bit_idx % 8;
        bytes[byte_idx] |= 1 << bit_offset;
    }

    format!("0x{}", hex::encode(bytes))
}

/// Generates a random checkpoint for testing.
fn random_checkpoint() -> AltairBeaconStateCurrentJustifiedCheckpoint {
    let mut rng = rand::thread_rng();
    AltairBeaconStateCurrentJustifiedCheckpoint {
        epoch: rng.r#gen::<u64>().to_string(),
        root: random_root(),
    }
}

/// Generates random attestation data for Phase 0.
fn random_attestation_data_phase0() -> Data {
    let mut rng = rand::thread_rng();
    Data {
        slot: rng.r#gen::<u64>().to_string(),
        index: rng.r#gen::<u64>().to_string(),
        beacon_block_root: random_root(),
        source: random_checkpoint(),
        target: random_checkpoint(),
    }
}

/// Generates a random Phase 0 attestation.
///
/// Returns an attestation with random aggregation bits, attestation data, and signature.
pub fn random_phase0_attestation() -> GetBlockAttestationsV2ResponseResponseDataArray2 {
    GetBlockAttestationsV2ResponseResponseDataArray2 {
        aggregation_bits: random_bit_list(1),
        data: random_attestation_data_phase0(),
        signature: random_eth2_signature(),
    }
}

/// Generates a random Deneb versioned attestation.
///
/// Returns a versioned attestation containing a Phase 0 attestation with the Deneb version tag.
/// This matches the Go implementation:
///
/// ```go
/// func RandomDenebVersionedAttestation() *eth2spec.VersionedAttestation {
///     return &eth2spec.VersionedAttestation{
///         Version: eth2spec.DataVersionDeneb,
///         Deneb:   RandomPhase0Attestation(),
///     }
/// }
/// ```
pub fn random_deneb_versioned_attestation() -> GetAggregatedAttestationV2ResponseResponse {
    GetAggregatedAttestationV2ResponseResponse {
        version: ConsensusVersion::Deneb,
        data: GetAggregatedAttestationV2ResponseResponseData::Object2(random_phase0_attestation()),
    }
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

    #[test]
    fn test_bls_key_deterministic() {
        let key1 = generate_test_bls_key(42);
        let key2 = generate_test_bls_key(42);

        assert_eq!(key1, key2, "Same seed should produce identical BLS keys");
    }

    #[test]
    fn test_bls_key_different_seeds() {
        let key1 = generate_test_bls_key(1);
        let key2 = generate_test_bls_key(2);

        assert_ne!(
            key1, key2,
            "Different seeds should produce different BLS keys"
        );
    }

    #[test]
    fn test_random_eth2_signature() {
        let sig1 = random_eth2_signature();
        let sig2 = random_eth2_signature();

        // Check format
        assert!(sig1.starts_with("0x"));
        // 96 bytes = 192 hex chars + "0x" prefix = 194 total
        assert_eq!(sig1.len(), 194);

        // Different calls should produce different signatures
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_random_root() {
        let root1 = random_root();
        let root2 = random_root();

        // Check format
        assert!(root1.starts_with("0x"));
        // 32 bytes = 64 hex chars + "0x" prefix = 66 total
        assert_eq!(root1.len(), 66);

        // Different calls should produce different roots
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_random_bit_list() {
        let bitlist = random_bit_list(5);

        // Check format
        assert!(bitlist.starts_with("0x"));
        // 32 bytes = 64 hex chars + "0x" prefix = 66 total
        assert_eq!(bitlist.len(), 66);
    }

    #[test]
    fn test_random_phase0_attestation() {
        let att = random_phase0_attestation();

        // Check that all fields are populated
        assert!(att.aggregation_bits.starts_with("0x"));
        assert!(att.signature.starts_with("0x"));
        assert!(att.data.beacon_block_root.starts_with("0x"));
        assert!(!att.data.slot.is_empty());
        assert!(!att.data.index.is_empty());
    }

    #[test]
    fn test_random_deneb_versioned_attestation() {
        let versioned_att = random_deneb_versioned_attestation();

        // Check version is Deneb
        assert!(matches!(versioned_att.version, ConsensusVersion::Deneb));

        // Check that data is populated
        match versioned_att.data {
            GetAggregatedAttestationV2ResponseResponseData::Object2(att) => {
                assert!(att.aggregation_bits.starts_with("0x"));
                assert!(att.signature.starts_with("0x"));
            }
            _ => panic!("Expected Object2 variant"),
        }
    }

    #[test]
    fn test_random_deneb_versioned_attestation_different() {
        let att1 = random_deneb_versioned_attestation();
        let att2 = random_deneb_versioned_attestation();

        // Different calls should produce different attestations
        // Check signatures are different
        let sig1 = match &att1.data {
            GetAggregatedAttestationV2ResponseResponseData::Object2(a) => &a.signature,
            _ => panic!("Expected Object2"),
        };
        let sig2 = match &att2.data {
            GetAggregatedAttestationV2ResponseResponseData::Object2(a) => &a.signature,
            _ => panic!("Expected Object2"),
        };

        assert_ne!(sig1, sig2);
    }
}
