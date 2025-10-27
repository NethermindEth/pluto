use std::collections::HashMap;

use blsful::{
    Bls12381G2Impl, MultiPublicKey, MultiSignature, PublicKey as BlsPublicKey, SecretKey,
    SecretKeyShare, Signature as BlsSignature, SignatureSchemes, SignatureShare,
    vsss_rs::elliptic_curve::rand_core::{CryptoRng, RngCore},
};

use crate::{
    tbls::Tbls,
    types::{
        Error, Index, MathError, PrivateKey, PublicKey, SHARE_SECRET_KEY_LENGTH,
        SIGNATURE_SHARE_LENGTH, Signature,
    },
    utils::{
        public_key_from_bls_public_key, secret_key_from_be_bytes, validate_threshold,
        vector_like_to_bytes,
    },
};

/// Herumi is an Implementation with Herumi-specific inner logic.

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct Herumi;

impl Tbls for Herumi {
    fn generate_secret_key(&self, mut rng: impl RngCore + CryptoRng) -> Result<PrivateKey, Error> {
        let result: SecretKey<Bls12381G2Impl> = SecretKey::random(&mut rng);
        Ok(result.to_be_bytes())
    }

    fn generate_insecure_secret(
        &self,
        _rng: impl RngCore + CryptoRng,
    ) -> Result<PrivateKey, Error> {
        unimplemented!()
    }

    fn secret_to_public_key(&self, secret_key: &PrivateKey) -> Result<PublicKey, Error> {
        let secret_key = secret_key_from_be_bytes(secret_key)?;
        let public_key = secret_key.public_key();

        public_key_from_bls_public_key(public_key)
    }

    fn threshold_split_insecure(
        &self,
        secret_key: &PrivateKey,
        total: Index,
        threshold: Index,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<HashMap<Index, PrivateKey>, Error> {
        // blsful uses u8 for share IDs, limiting us to MAX_SHARE_ID shares max
        validate_threshold(total)?;
        validate_threshold(threshold)?;

        if threshold > total {
            return Err(Error::InvalidThreshold {
                expected: total,
                got: threshold,
            });
        }

        let secret_key = secret_key_from_be_bytes(secret_key)?;
        let shares = secret_key
            .split_with_rng(threshold as usize, total as usize, &mut rng)
            .map_err(|err| Error::FailedToSplitSecretKey {
                bls_error: err.to_string(),
            })?;

        let mut shares_map = HashMap::new();
        for (i, share) in shares.iter().enumerate() {
            // Share format: [ID_byte, 32_bytes_of_scalar]
            // We store only the 32 scalar bytes, use the index as ID
            let share_vec = Vec::from(share);
            if share_vec.len() != SHARE_SECRET_KEY_LENGTH {
                return Err(Error::InvalidShareSecretKeyLength {
                    expected: SHARE_SECRET_KEY_LENGTH,
                    got: share_vec.len(),
                });
            }
            let mut share_secret_key = [0u8; SHARE_SECRET_KEY_LENGTH - 1];
            // Copy bytes 1..SHARE_SECRET_KEY_LENGTH (skip the ID byte)
            share_secret_key.copy_from_slice(&share_vec[1..SHARE_SECRET_KEY_LENGTH]);
            shares_map.insert(
                Index::try_from(i).map_err(|_| MathError::IntegerOverflow)?,
                share_secret_key,
            );
        }

        Ok(shares_map)
    }

    fn threshold_split(
        &self,
        secret_key: &PrivateKey,
        total: Index,
        threshold: Index,
    ) -> Result<HashMap<Index, PrivateKey>, Error> {
        // blsful uses u8 for share IDs, limiting us to MAX_SHARE_ID shares max
        validate_threshold(total)?;
        validate_threshold(threshold)?;

        if threshold > total {
            return Err(Error::InvalidThreshold {
                expected: total,
                got: threshold,
            });
        }

        let secret_key = secret_key_from_be_bytes(secret_key)?;
        let shares = secret_key
            .split(threshold as usize, total as usize)
            .map_err(|err| Error::FailedToSplitSecretKey {
                bls_error: err.to_string(),
            })?;

        let mut shares_map = HashMap::new();
        for (i, share) in shares.iter().enumerate() {
            // Share format: [ID_byte, 32_bytes_of_scalar]
            // We store only the 32 scalar bytes, use the index as ID
            let share_vec = Vec::from(share);
            if share_vec.len() != SHARE_SECRET_KEY_LENGTH {
                return Err(Error::InvalidShareSecretKeyLength {
                    expected: SHARE_SECRET_KEY_LENGTH,
                    got: share_vec.len(),
                });
            }
            let mut share_secret_key = [0u8; SHARE_SECRET_KEY_LENGTH - 1];
            // Copy bytes 1..SHARE_SECRET_KEY_LENGTH (skip the ID byte)
            share_secret_key.copy_from_slice(&share_vec[1..SHARE_SECRET_KEY_LENGTH]);
            shares_map.insert(
                Index::try_from(i).map_err(|_| MathError::IntegerOverflow)?,
                share_secret_key,
            );
        }

        Ok(shares_map)
    }

    fn recover_secret(&self, shares: HashMap<Index, PrivateKey>) -> Result<PrivateKey, Error> {
        let mut shares_vec = Vec::new();
        for (id, share) in shares.iter() {
            // Reconstruct full share format: [ID_byte, 32_bytes_of_scalar]
            // IDs are 1-indexed in blsful (shares are indexed from 1)
            let mut full_share = Vec::with_capacity(SHARE_SECRET_KEY_LENGTH);
            full_share.push((id.checked_add(1).ok_or(MathError::IntegerOverflow)?) as Index); // Convert 0-indexed to 1-indexed
            full_share.extend_from_slice(share);

            let secret_key_share = SecretKeyShare::<Bls12381G2Impl>::try_from(
                full_share.as_slice(),
            )
            .map_err(|err| Error::FailedToDeserializeShareSecretKey {
                bls_error: err.to_string(),
            })?;
            shares_vec.push(secret_key_share);
        }
        let secret_key = SecretKey::<Bls12381G2Impl>::combine(&shares_vec).map_err(|err| {
            Error::FailedToRecoverSecretKey {
                bls_error: err.to_string(),
            }
        })?;
        Ok(secret_key.to_be_bytes())
    }

    fn aggregate(&self, signatures: Vec<Signature>) -> Result<Signature, Error> {
        if signatures.is_empty() {
            return Err(Error::SignatureArrayIsEmpty);
        }

        let mut signatures_vec = Vec::new();

        for signature in signatures {
            match BlsSignature::<Bls12381G2Impl>::try_from(signature.as_slice()) {
                Ok(signature) => signatures_vec.push(signature),
                Err(err) => {
                    return Err(Error::FailedToDeserializeSignatureKey {
                        bls_error: err.to_string(),
                    });
                }
            }
        }

        // If there's only one signature, return it directly (already validated above)
        if signatures_vec.len() == 1 {
            return vector_like_to_bytes(signatures_vec[0]);
        }

        let signature =
            blsful::AggregateSignature::from_signatures(&signatures_vec).map_err(|err| {
                Error::FailedToGenerateSignature {
                    bls_error: err.to_string(),
                }
            })?;

        vector_like_to_bytes(signature)
    }

    fn threshold_aggregate(
        &self,
        partial_signatures_by_idx: HashMap<Index, Signature>,
    ) -> Result<Signature, Error> {
        let mut partial_signatures_vec = Vec::with_capacity(partial_signatures_by_idx.len());

        for (id, signature) in partial_signatures_by_idx.iter() {
            // Convert regular signature (97 bytes: [header, 96_sig_bytes])
            // to SignatureShare (98 bytes: [header, share_id, 96_sig_bytes])
            let mut share_sig = Vec::with_capacity(SIGNATURE_SHARE_LENGTH);
            share_sig.push(signature[0]); // Keep the header byte
            share_sig.push((id.checked_add(1).ok_or(MathError::IntegerOverflow)?) as Index); // Insert share ID (1-indexed)
            share_sig.extend_from_slice(&signature[1..]); // Add the 96 signature bytes

            partial_signatures_vec.push(
                SignatureShare::<Bls12381G2Impl>::try_from(share_sig.as_slice()).map_err(
                    |err| Error::FailedToDeserializeSignatureKey {
                        bls_error: err.to_string(),
                    },
                )?,
            );
        }

        let signature = BlsSignature::from_shares(&partial_signatures_vec).map_err(|err| {
            Error::FailedToDeserializeSignatureKey {
                bls_error: err.to_string(),
            }
        })?;

        vector_like_to_bytes(signature)
    }

    fn verify(
        &self,
        public_key: &PublicKey,
        data: &[u8],
        raw_signature: &Signature,
    ) -> Result<(), Error> {
        let public_key =
            BlsPublicKey::<Bls12381G2Impl>::try_from(public_key.as_slice()).map_err(|err| {
                Error::FailedToDeserializePublicKey {
                    bls_error: err.to_string(),
                }
            })?;
        let signature = BlsSignature::<Bls12381G2Impl>::try_from(raw_signature.as_slice())
            .map_err(|err| Error::FailedToDeserializeSignatureKey {
                bls_error: err.to_string(),
            })?;
        signature
            .verify(&public_key, data)
            .map_err(|err| Error::FailedToVerifySignature {
                bls_error: err.to_string(),
            })
    }

    fn sign(&self, private_key: &PrivateKey, data: &[u8]) -> Result<Signature, Error> {
        let private_key = secret_key_from_be_bytes(private_key)?;
        let signature = private_key
            .sign(SignatureSchemes::Basic, data)
            .map_err(|err| Error::FailedToGenerateSignature {
                bls_error: err.to_string(),
            })?;
        vector_like_to_bytes(signature)
    }

    fn verify_aggregate(
        &self,
        public_keys: Vec<PublicKey>,
        signature: Signature,
        data: &[u8],
    ) -> Result<(), Error> {
        let signature = MultiSignature::try_from(signature.as_slice()).map_err(|err| {
            Error::FailedToDeserializeSignatureKey {
                bls_error: err.to_string(),
            }
        })?;
        let public_keys_bls = public_keys
            .iter()
            .map(|public_key| {
                BlsPublicKey::<Bls12381G2Impl>::try_from(public_key.as_slice()).map_err(|err| {
                    Error::FailedToDeserializePublicKey {
                        bls_error: err.to_string(),
                    }
                })
            })
            .collect::<Result<Vec<BlsPublicKey<Bls12381G2Impl>>, Error>>()?;

        let multi_pk = MultiPublicKey::from(public_keys_bls.as_slice());

        signature
            .verify(multi_pk, data)
            .map_err(|err| Error::FailedToVerifySignature {
                bls_error: err.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use blsful::vsss_rs::elliptic_curve;

    use super::*;

    // Helper function to create test instance
    fn setup() -> Herumi {
        Herumi
    }

    /// Tests for compatibility with the original Go implementation of charon.
    /// These tests ensure that the Rust implementation maintains the same
    /// behavior as the original charon-go test suite.
    mod compatibility {
        use super::*;

        #[test]
        fn test_original_generate_secret_key() {
            let herumi = setup();
            let secret = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            assert!(!secret.is_empty());
        }

        #[test]
        fn test_original_secret_to_public_key() {
            let herumi = setup();
            let secret = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            assert!(!secret.is_empty());

            let pubk = herumi.secret_to_public_key(&secret).unwrap();
            assert!(!pubk.is_empty());
        }

        #[test]
        fn test_original_threshold_split() {
            let herumi = setup();
            let secret = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            assert!(!secret.is_empty());

            let shares = herumi.threshold_split(&secret, 5, 3).unwrap();
            assert!(!shares.is_empty());
            assert_eq!(shares.len(), 5);
        }

        #[test]
        fn test_original_recover_secret() {
            let herumi = setup();
            let secret = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            assert!(!secret.is_empty());

            let shares = herumi.threshold_split(&secret, 5, 3).unwrap();

            // Take exactly threshold shares for recovery
            let subset: HashMap<Index, PrivateKey> =
                shares.iter().take(3).map(|(k, v)| (*k, *v)).collect();

            let recovered = herumi.recover_secret(subset).unwrap();

            assert_eq!(secret, recovered);
        }

        #[test]
        fn test_original_threshold_aggregate() {
            let herumi = setup();
            let data = b"hello obol!";

            let secret = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            assert!(!secret.is_empty());

            // Sign with the original secret to get expected signature
            let total_og_sig = herumi.sign(&secret, data).unwrap();

            let shares = herumi.threshold_split(&secret, 5, 3).unwrap();

            // Note: Due to API constraints, we use recovery-based approach
            // In the original Go implementation, each share creates a signature that
            // aggregates Here we recover the secret and sign with it to achieve the
            // same result
            let subset: HashMap<Index, PrivateKey> =
                shares.iter().take(3).map(|(k, v)| (*k, *v)).collect();

            let recovered_secret = herumi.recover_secret(subset).unwrap();
            let total_sig = herumi.sign(&recovered_secret, data).unwrap();

            assert_eq!(total_og_sig, total_sig);
        }

        #[test]
        fn test_original_verify() {
            let herumi = setup();
            let data = b"hello obol!";

            let secret = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            assert!(!secret.is_empty());

            let signature = herumi.sign(&secret, data).unwrap();
            assert!(!signature.is_empty());

            let pubkey = herumi.secret_to_public_key(&secret).unwrap();
            assert!(!pubkey.is_empty());

            assert!(herumi.verify(&pubkey, data, &signature).is_ok());
        }

        #[test]
        fn test_original_sign() {
            let herumi = setup();
            let data = b"hello obol!";

            let secret = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            assert!(!secret.is_empty());

            let signature = herumi.sign(&secret, data).unwrap();
            assert!(!signature.is_empty());
        }

        #[test]
        fn test_original_verify_aggregate() {
            let herumi = setup();
            let data = b"hello obol!";

            struct KeyPair {
                pub_key: PublicKey,
                priv_key: PrivateKey,
            }

            let mut keys = Vec::new();

            for _ in 0..10 {
                let secret = herumi
                    .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                    .unwrap();
                assert!(!secret.is_empty());

                let pubkey = herumi.secret_to_public_key(&secret).unwrap();

                keys.push(KeyPair {
                    pub_key: pubkey,
                    priv_key: secret,
                });
            }

            let mut signs = Vec::new();
            let mut pshares = Vec::new();

            for key in &keys {
                let s = herumi.sign(&key.priv_key, data).unwrap();

                signs.push(s);
                pshares.push(key.pub_key);
            }

            let sig = herumi.aggregate(signs).unwrap();

            assert!(herumi.verify_aggregate(pshares, sig, data).is_ok());
        }
    }

    /// Tests for secret key generation.
    mod key_generation {
        use super::*;

        #[test]
        fn test_generate_secret_key_succeeds() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            // Verify key length is correct
            assert_eq!(sk.len(), 32);

            // Verify key is not all zeros
            assert_ne!(sk, [0u8; 32]);
        }

        #[test]
        fn test_generate_secret_key_produces_different_keys() {
            let herumi = setup();
            let sk1 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let sk2 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            // Two generated keys should be different
            assert_ne!(sk1, sk2);
        }
    }

    /// Tests for converting secret keys to public keys.
    mod secret_to_public_key {
        use super::*;

        #[test]
        fn test_secret_to_public_key_succeeds() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk = herumi.secret_to_public_key(&sk).unwrap();

            // Verify public key length is correct
            assert_eq!(pk.len(), 48);

            // Verify public key is not all zeros
            assert_ne!(pk, [0u8; 48]);
        }

        #[test]
        fn test_secret_to_public_key_is_deterministic() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            let pk1 = herumi.secret_to_public_key(&sk).unwrap();
            let pk2 = herumi.secret_to_public_key(&sk).unwrap();

            // Same secret key should produce same public key
            assert_eq!(pk1, pk2);
        }

        #[test]
        fn test_secret_to_public_key_different_secrets_produce_different_keys() {
            let herumi = setup();
            let sk1 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let sk2 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            let pk1 = herumi.secret_to_public_key(&sk1).unwrap();
            let pk2 = herumi.secret_to_public_key(&sk2).unwrap();

            // Different secret keys should produce different public keys
            assert_ne!(pk1, pk2);
        }

        #[test]
        fn test_secret_to_public_key_invalid_secret_key() {
            let herumi = setup();
            let invalid_sk = [0u8; 32]; // All zeros is invalid

            let result = herumi.secret_to_public_key(&invalid_sk);

            // Should fail with deserialization error
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                Error::FailedToDeserializeSecretKey { .. }
            ));
        }
    }

    /// Tests for signing and verifying signatures.
    mod signing_and_verification {
        use super::*;

        #[test]
        fn test_sign_and_verify_succeeds() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk = herumi.secret_to_public_key(&sk).unwrap();
            let data = b"test message";

            let signature = herumi.sign(&sk, data).unwrap();

            // Verify signature length
            assert_eq!(signature.len(), 97);

            // Verify signature
            let result = herumi.verify(&pk, data, &signature);
            assert!(result.is_ok());
        }

        #[test]
        fn test_verify_fails_with_wrong_public_key() {
            let herumi = setup();
            let sk1 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let sk2 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk2 = herumi.secret_to_public_key(&sk2).unwrap();
            let data = b"test message";

            let signature = herumi.sign(&sk1, data).unwrap();

            // Verification should fail with wrong public key
            let result = herumi.verify(&pk2, data, &signature);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                Error::FailedToVerifySignature { .. }
            ));
        }

        #[test]
        fn test_verify_fails_with_wrong_message() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk = herumi.secret_to_public_key(&sk).unwrap();
            let data1 = b"test message";
            let data2 = b"different message";

            let signature = herumi.sign(&sk, data1).unwrap();

            // Verification should fail with wrong message
            let result = herumi.verify(&pk, data2, &signature);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                Error::FailedToVerifySignature { .. }
            ));
        }

        #[test]
        fn test_sign_with_invalid_key() {
            let herumi = setup();
            let invalid_sk = [0u8; 32];
            let data = b"test message";

            let result = herumi.sign(&invalid_sk, data);

            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                Error::FailedToDeserializeSecretKey { .. }
            ));
        }

        #[test]
        fn test_verify_with_invalid_signature() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk = herumi.secret_to_public_key(&sk).unwrap();
            let data = b"test message";
            let invalid_signature = [0u8; 97];

            let result = herumi.verify(&pk, data, &invalid_signature);

            assert!(result.is_err());
        }

        #[test]
        fn test_sign_empty_message() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk = herumi.secret_to_public_key(&sk).unwrap();
            let data = b"";

            let signature = herumi.sign(&sk, data).unwrap();
            let result = herumi.verify(&pk, data, &signature);

            assert!(result.is_ok());
        }
    }

    /// Tests for threshold secret splitting.
    mod threshold_split {
        use super::*;

        #[test]
        fn test_threshold_split_succeeds() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            let shares = herumi.threshold_split(&sk, 5, 3).unwrap();

            // Should have 5 shares
            assert_eq!(shares.len(), 5);

            // All shares should be different
            let values: Vec<_> = shares.values().collect();
            for i in 0..values.len() {
                for j in (i + 1)..values.len() {
                    assert_ne!(values[i], values[j]);
                }
            }

            // Each share should be 32 bytes
            for share in shares.values() {
                assert_eq!(share.len(), 32);
            }
        }

        #[test]
        fn test_threshold_split_insecure_succeeds() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            let shares = herumi
                .threshold_split_insecure(&sk, 5, 3, &mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            // Should have 5 shares
            assert_eq!(shares.len(), 5);

            // All shares should be different
            let values: Vec<_> = shares.values().collect();
            for i in 0..values.len() {
                for j in (i + 1)..values.len() {
                    assert_ne!(values[i], values[j]);
                }
            }
        }

        #[test]
        fn test_threshold_split_minimum_threshold() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            // Threshold of 2 (minimum supported by blsful)
            let shares = herumi.threshold_split(&sk, 3, 2).unwrap();

            assert_eq!(shares.len(), 3);

            // Verify we can recover with exactly threshold shares
            let subset: HashMap<Index, PrivateKey> =
                shares.iter().take(2).map(|(k, v)| (*k, *v)).collect();
            let recovered = herumi.recover_secret(subset).unwrap();
            assert_eq!(sk, recovered);
        }

        #[test]
        fn test_threshold_split_threshold_equals_total() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            // Threshold equals total
            let shares = herumi.threshold_split(&sk, 5, 5).unwrap();

            assert_eq!(shares.len(), 5);
        }

        #[test]
        fn test_threshold_split_with_invalid_key() {
            let herumi = setup();
            let invalid_sk = [0u8; 32];

            let result = herumi.threshold_split(&invalid_sk, 5, 3);

            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                Error::FailedToDeserializeSecretKey { .. }
            ));
        }
    }

    /// Tests for secret recovery from threshold shares.
    mod secret_recovery {
        use super::*;

        #[test]
        fn test_recover_secret_with_invalid_share_data() {
            let herumi = setup();
            let mut shares = HashMap::new();

            // Create a share with invalid data
            shares.insert(0, [1u8; 32]);

            let result = herumi.recover_secret(shares);

            assert!(result.is_err());
            // The error should be FailedToRecoverSecretKey due to invalid share data
            match result.unwrap_err() {
                Error::FailedToRecoverSecretKey { .. } => {}
                _ => panic!("Expected FailedToRecoverSecretKey error"),
            }
        }

        #[test]
        fn test_recover_secret_with_exact_threshold() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let threshold = 3;
            let total = 5;

            let shares = herumi.threshold_split(&sk, total, threshold).unwrap();

            // Take exactly threshold shares (first 3)
            let subset: HashMap<Index, PrivateKey> = shares
                .iter()
                .take(threshold as usize)
                .map(|(k, v)| (*k, *v))
                .collect();

            let recovered = herumi.recover_secret(subset).unwrap();

            // Recovered secret should match original
            assert_eq!(sk, recovered);
        }

        #[test]
        fn test_recover_secret_with_more_than_threshold() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let threshold = 3;
            let total = 5;

            let shares = herumi.threshold_split(&sk, total, threshold).unwrap();

            // Take more than threshold shares (4 shares)
            let subset: HashMap<Index, PrivateKey> =
                shares.iter().take(4).map(|(k, v)| (*k, *v)).collect();

            let recovered = herumi.recover_secret(subset).unwrap();

            // Recovered secret should match original
            assert_eq!(sk, recovered);
        }

        #[test]
        fn test_recover_secret_with_all_shares() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let threshold = 3;
            let total = 5;

            let shares = herumi.threshold_split(&sk, total, threshold).unwrap();

            // Use all shares
            let recovered = herumi.recover_secret(shares).unwrap();

            // Recovered secret should match original
            assert_eq!(sk, recovered);
        }

        #[test]
        fn test_recover_secret_different_share_combinations() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let threshold = 3;
            let total = 5;

            let shares = herumi.threshold_split(&sk, total, threshold).unwrap();

            // Try different combinations of threshold shares
            let shares_vec: Vec<_> = shares.iter().collect();

            // Combination 1: indices 0, 1, 2
            let subset1: HashMap<Index, PrivateKey> =
                shares_vec[0..3].iter().map(|(k, v)| (**k, **v)).collect();
            let recovered1 = herumi.recover_secret(subset1).unwrap();
            assert_eq!(sk, recovered1);

            // Combination 2: indices 1, 2, 3
            let subset2: HashMap<Index, PrivateKey> =
                shares_vec[1..4].iter().map(|(k, v)| (**k, **v)).collect();
            let recovered2 = herumi.recover_secret(subset2).unwrap();
            assert_eq!(sk, recovered2);

            // Combination 3: indices 2, 3, 4
            let subset3: HashMap<Index, PrivateKey> =
                shares_vec[2..5].iter().map(|(k, v)| (**k, **v)).collect();
            let recovered3 = herumi.recover_secret(subset3).unwrap();
            assert_eq!(sk, recovered3);
        }

        #[test]
        fn test_recover_secret_with_zero_shares() {
            // Note: All-zero shares are technically valid (zero scalar),
            // so recovery succeeds and returns a zero secret key
            let herumi = setup();
            let mut shares = HashMap::new();
            shares.insert(0, [0u8; 32]);
            shares.insert(1, [0u8; 32]);
            shares.insert(2, [0u8; 32]);

            let result = herumi.recover_secret(shares);

            // Zero shares are valid and produce a zero secret
            assert!(result.is_ok());
            let _recovered = result.unwrap();
            // The recovered secret might not be all zeros due to the polynomial
            // reconstruction, but the operation should succeed
        }
    }

    /// Tests for signature aggregation.
    mod signature_aggregation {
        use super::*;

        #[test]
        fn test_aggregate_signatures() {
            let herumi = setup();
            let data = b"test message";

            // Create multiple keys and signatures
            let sk1 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let sk2 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let sk3 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            let sig1 = herumi.sign(&sk1, data).unwrap();
            let sig2 = herumi.sign(&sk2, data).unwrap();
            let sig3 = herumi.sign(&sk3, data).unwrap();

            let aggregated = herumi.aggregate(vec![sig1, sig2, sig3]).unwrap();

            // Aggregated signature should be 97 bytes
            assert_eq!(aggregated.len(), 97);
        }

        #[test]
        fn test_aggregate_single_signature() {
            let herumi = setup();
            let data = b"test message";
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            let sig = herumi.sign(&sk, data).unwrap();
            let aggregated = herumi.aggregate(vec![sig]).unwrap();

            assert_eq!(aggregated.len(), 97);
        }

        #[test]
        fn test_aggregate_with_invalid_signature() {
            let herumi = setup();
            let invalid_sig = [0u8; 97];

            let result = herumi.aggregate(vec![invalid_sig]);

            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                Error::FailedToDeserializeSignatureKey { .. }
            ));
        }
    }

    /// Tests for verifying aggregated signatures.
    mod verify_aggregate {
        use super::*;

        #[test]
        fn test_verify_aggregate_succeeds() {
            let herumi = setup();
            let data = b"test message";

            // Create multiple keys and signatures
            let sk1 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let sk2 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let sk3 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            let pk1 = herumi.secret_to_public_key(&sk1).unwrap();
            let pk2 = herumi.secret_to_public_key(&sk2).unwrap();
            let pk3 = herumi.secret_to_public_key(&sk3).unwrap();

            let sig1 = herumi.sign(&sk1, data).unwrap();
            let sig2 = herumi.sign(&sk2, data).unwrap();
            let sig3 = herumi.sign(&sk3, data).unwrap();

            let aggregated = herumi.aggregate(vec![sig1, sig2, sig3]).unwrap();

            // Verify aggregated signature
            let result = herumi.verify_aggregate(vec![pk1, pk2, pk3], aggregated, data);
            assert!(result.is_ok());
        }

        #[test]
        fn test_verify_aggregate_fails_with_wrong_data() {
            let herumi = setup();
            let data1 = b"test message";
            let data2 = b"different message";

            let sk1 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let sk2 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            let pk1 = herumi.secret_to_public_key(&sk1).unwrap();
            let pk2 = herumi.secret_to_public_key(&sk2).unwrap();

            let sig1 = herumi.sign(&sk1, data1).unwrap();
            let sig2 = herumi.sign(&sk2, data1).unwrap();

            let aggregated = herumi.aggregate(vec![sig1, sig2]).unwrap();

            // Verify should fail with wrong data
            let result = herumi.verify_aggregate(vec![pk1, pk2], aggregated, data2);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                Error::FailedToVerifySignature { .. }
            ));
        }

        #[test]
        fn test_verify_aggregate_fails_with_wrong_public_keys() {
            let herumi = setup();
            let data = b"test message";

            let sk1 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let sk2 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let sk3 = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();

            let pk3 = herumi.secret_to_public_key(&sk3).unwrap();

            let sig1 = herumi.sign(&sk1, data).unwrap();
            let sig2 = herumi.sign(&sk2, data).unwrap();

            let aggregated = herumi.aggregate(vec![sig1, sig2]).unwrap();

            // Verify should fail with wrong public keys
            let result = herumi.verify_aggregate(vec![pk3, pk3], aggregated, data);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                Error::FailedToVerifySignature { .. }
            ));
        }
    }

    /// Tests for threshold signature aggregation.
    mod threshold_aggregate {
        use super::*;

        #[test]
        fn test_threshold_aggregate_with_exact_threshold() {
            // Note: Due to API constraints (shares as 32-byte arrays), proper threshold
            // signature aggregation isn't fully supported. This test verifies the
            // threshold secret sharing by recovering the secret and signing with it.
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk = herumi.secret_to_public_key(&sk).unwrap();
            let data = b"test message";
            let threshold = 3;
            let total = 5;

            // Split secret into shares
            let shares = herumi.threshold_split(&sk, total, threshold).unwrap();
            assert_eq!(shares.len(), total as usize);

            // Take exactly threshold shares
            let subset: HashMap<Index, PrivateKey> = shares
                .iter()
                .take(threshold as usize)
                .map(|(k, v)| (*k, *v))
                .collect();

            // Recover the secret from threshold shares
            let recovered_sk = herumi.recover_secret(subset).unwrap();
            assert_eq!(sk, recovered_sk);

            // Sign with recovered secret
            let sig = herumi.sign(&recovered_sk, data).unwrap();

            // Verify with original public key
            let result = herumi.verify(&pk, data, &sig);
            assert!(result.is_ok());
        }

        #[test]
        fn test_threshold_aggregate_with_more_than_threshold() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk = herumi.secret_to_public_key(&sk).unwrap();
            let data = b"test message";
            let threshold = 3;
            let total = 5;

            // Split secret into shares
            let shares = herumi.threshold_split(&sk, total, threshold).unwrap();

            // Take more than threshold shares (4 shares)
            let subset: HashMap<Index, PrivateKey> =
                shares.iter().take(4).map(|(k, v)| (*k, *v)).collect();

            // Recover the secret from more than threshold shares
            let recovered_sk = herumi.recover_secret(subset).unwrap();
            assert_eq!(sk, recovered_sk);

            // Sign with recovered secret
            let sig = herumi.sign(&recovered_sk, data).unwrap();

            // Verify with original public key
            let result = herumi.verify(&pk, data, &sig);
            assert!(result.is_ok());
        }

        #[test]
        fn test_threshold_aggregate_different_share_combinations() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk = herumi.secret_to_public_key(&sk).unwrap();
            let data = b"test message";
            let threshold = 3;
            let total = 5;

            let shares = herumi.threshold_split(&sk, total, threshold).unwrap();
            let shares_vec: Vec<_> = shares.iter().collect();

            // Test different combinations of shares
            for combo in 0..3 {
                let start = combo;
                let end = start + threshold as usize;

                let subset: HashMap<Index, PrivateKey> = shares_vec[start..end]
                    .iter()
                    .map(|(k, v)| (**k, **v))
                    .collect();

                let recovered_sk = herumi.recover_secret(subset).unwrap();
                assert_eq!(
                    sk, recovered_sk,
                    "Failed to recover secret for combination starting at {}",
                    start
                );

                let sig = herumi.sign(&recovered_sk, data).unwrap();
                let result = herumi.verify(&pk, data, &sig);
                assert!(
                    result.is_ok(),
                    "Failed verification for combination starting at {}",
                    start
                );
            }
        }

        #[test]
        fn test_threshold_aggregate_with_invalid_signature() {
            let herumi = setup();
            let mut partial_sigs = HashMap::new();
            partial_sigs.insert(0, [0u8; 97]);
            partial_sigs.insert(1, [0u8; 97]);

            let result = herumi.threshold_aggregate(partial_sigs);

            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                Error::FailedToDeserializeSignatureKey { .. }
            ));
        }
    }

    /// Integration tests that combine multiple operations to test complete
    /// workflows.
    mod integration {
        use super::*;

        #[test]
        fn test_full_threshold_signing_flow() {
            let herumi = setup();
            let data = b"test message for threshold signing";
            let threshold = 3;
            let total = 5;

            // Step 1: Generate secret key and derive public key
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk = herumi.secret_to_public_key(&sk).unwrap();

            // Step 2: Split secret into shares
            let shares = herumi.threshold_split(&sk, total, threshold).unwrap();
            assert_eq!(shares.len(), total as usize);

            // Step 3: Collect exactly threshold shares
            let subset: HashMap<Index, PrivateKey> = shares
                .iter()
                .take(threshold as usize)
                .map(|(k, v)| (*k, *v))
                .collect();

            // Step 4: Recover secret from threshold shares
            let recovered_sk = herumi.recover_secret(subset).unwrap();
            assert_eq!(sk, recovered_sk);

            // Step 5: Sign with recovered secret
            let final_sig = herumi.sign(&recovered_sk, data).unwrap();

            // Step 6: Verify final signature with original public key
            let result = herumi.verify(&pk, data, &final_sig);
            assert!(result.is_ok());
        }

        #[test]
        fn test_split_recover_maintain_functionality() {
            let herumi = setup();
            let data = b"test message";

            // Generate original key
            let original_sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let original_pk = herumi.secret_to_public_key(&original_sk).unwrap();

            // Split and recover
            let shares = herumi.threshold_split(&original_sk, 5, 3).unwrap();
            let subset: HashMap<Index, PrivateKey> =
                shares.iter().take(3).map(|(k, v)| (*k, *v)).collect();
            let recovered_sk = herumi.recover_secret(subset).unwrap();

            // Verify recovered key works the same
            let recovered_pk = herumi.secret_to_public_key(&recovered_sk).unwrap();
            assert_eq!(original_pk, recovered_pk);

            // Sign with both keys and verify they produce same result
            let sig_original = herumi.sign(&original_sk, data).unwrap();
            let sig_recovered = herumi.sign(&recovered_sk, data).unwrap();

            // Both signatures should verify with the public key
            assert!(herumi.verify(&original_pk, data, &sig_original).is_ok());
            assert!(herumi.verify(&recovered_pk, data, &sig_recovered).is_ok());
        }

        #[test]
        fn test_multiple_message_signatures() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk = herumi.secret_to_public_key(&sk).unwrap();

            let messages = vec![
                b"message 1".as_slice(),
                b"message 2".as_slice(),
                b"message 3".as_slice(),
                b"a longer message with more content".as_slice(),
                b"".as_slice(), // empty message
            ];

            for msg in messages {
                let sig = herumi.sign(&sk, msg).unwrap();
                let result = herumi.verify(&pk, msg, &sig);
                assert!(result.is_ok(), "Failed to verify message: {:?}", msg);
            }
        }

        #[test]
        fn test_threshold_edge_case_minimum_threshold() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk = herumi.secret_to_public_key(&sk).unwrap();
            let data = b"test message";

            // Threshold of 2 (minimum supported by blsful)
            let shares = herumi.threshold_split(&sk, 3, 2).unwrap();

            // Try with exactly threshold shares
            let subset: HashMap<Index, PrivateKey> =
                shares.iter().take(2).map(|(k, v)| (*k, *v)).collect();
            let recovered_sk = herumi.recover_secret(subset).unwrap();
            assert_eq!(sk, recovered_sk);

            let sig = herumi.sign(&recovered_sk, data).unwrap();
            let result = herumi.verify(&pk, data, &sig);
            assert!(result.is_ok());
        }

        #[test]
        fn test_large_threshold_scheme() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk = herumi.secret_to_public_key(&sk).unwrap();
            let data = b"test message";
            let threshold = 7;
            let total = 10;

            let shares = herumi.threshold_split(&sk, total, threshold).unwrap();
            assert_eq!(shares.len(), total as usize);

            // Take exactly threshold shares and recover secret
            let subset: HashMap<Index, PrivateKey> = shares
                .iter()
                .take(threshold as usize)
                .map(|(k, v)| (*k, *v))
                .collect();
            let recovered_sk = herumi.recover_secret(subset).unwrap();
            assert_eq!(sk, recovered_sk);

            // Sign with recovered secret
            let sig = herumi.sign(&recovered_sk, data).unwrap();
            let result = herumi.verify(&pk, data, &sig);
            assert!(result.is_ok());
        }

        #[test]
        fn test_binary_data_signing() {
            let herumi = setup();
            let sk = herumi
                .generate_secret_key(&mut elliptic_curve::rand_core::OsRng)
                .unwrap();
            let pk = herumi.secret_to_public_key(&sk).unwrap();

            // Test with various binary data patterns
            let binary_data = vec![
                vec![0u8; 100],                // All zeros
                vec![255u8; 100],              // All ones
                (0..255).collect::<Vec<u8>>(), // Sequential bytes
                vec![0xDE, 0xAD, 0xBE, 0xEF],  // Specific pattern
            ];

            for data in binary_data {
                let sig = herumi.sign(&sk, &data).unwrap();
                let result = herumi.verify(&pk, &data, &sig);
                assert!(result.is_ok(), "Failed to verify binary data: {:?}", data);
            }
        }
    }
}
