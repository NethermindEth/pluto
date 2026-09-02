//! # tbls
//!
//! Threshold BLS signatures over the blst library, compatible with the Herumi
//! BLS library used in the Go implementation of Charon.

use std::collections::HashMap;

use blst::{
    BLST_ERROR,
    min_pk::{PublicKey as BlstPublicKey, SecretKey as BlstSecretKey, Signature as BlstSignature},
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::types::{BlsError, Error, Index, PrivateKey, PublicKey, SIGNATURE_LENGTH, Signature};

mod math;

/// Domain Separation Tag for Ethereum 2.0 BLS signatures
const ETH2_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Serialized BLS12-381 G2 compressed point at infinity (the identity
/// signature). This is the value Charon's Herumi `Aggregate` returns for an
/// empty input slice: `sig.Serialize()` of a zero `bls.Sign`. The high byte
/// sets the compression bit (`0x80`) and the infinity bit (`0x40`); all other
/// bytes are zero.
const IDENTITY_SIGNATURE: Signature = {
    let mut s = [0u8; SIGNATURE_LENGTH];
    s[0] = 0xc0;
    s
};

/// Generates a secret key and returns its compressed
/// serialized representation.
pub fn generate_secret_key(mut rng: impl RngCore + CryptoRng) -> Result<PrivateKey, Error> {
    // `ikm` is secret input key material; wipe it on drop. (`BlstSecretKey`
    // itself is `#[zeroize(drop)]`, so the derived `sk` is wiped too.)
    let mut ikm = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(ikm.as_mut());

    let sk = BlstSecretKey::key_gen(ikm.as_ref(), &[])
        .map_err(|_| Error::InvalidSecretKey(BlsError::KeyGeneration))?;

    Ok(sk.to_bytes())
}

/// Generates a secret that is not cryptographically
/// secure using the provided random number generator. This is useful
/// for testing.
pub fn generate_insecure_secret(mut rng: impl RngCore + CryptoRng) -> Result<PrivateKey, Error> {
    for _ in 0..100 {
        // Wipe the candidate buffer on every iteration; on success its value
        // is copied into the returned key first.
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(bytes.as_mut());

        if BlstSecretKey::from_bytes(bytes.as_ref()).is_ok() {
            return Ok(*bytes);
        }
    }
    Err(Error::InvalidSecretKey(BlsError::KeyGeneration))
}

/// Extracts the public key associated with the secret
/// passed in input, and returns its compressed serialized
/// representation.
pub fn secret_to_public_key(secret_key: &PrivateKey) -> Result<PublicKey, Error> {
    let sk =
        BlstSecretKey::from_bytes(secret_key).map_err(|e| Error::InvalidSecretKey(e.into()))?;
    let pk = sk.sk_to_pk();
    Ok(pk.to_bytes())
}

/// Splits a compressed secret into total units of
/// secret keys, with the given threshold. It returns a map that
/// associates each private, compressed private key to its ID.
///
/// **Important:** Share IDs are 1-indexed (1, 2, 3, ..., n), matching
/// the Go implementation and TBLS polynomial evaluation points.
///
/// # Limitations
///
/// Maximum of 255 shares (total <= 255) due to underlying BLS library
/// constraints.
///
/// # Errors
///
/// Returns [`Error::InvalidThreshold`] if `threshold < 2` or
/// `threshold > total`. (Charon only enforces `threshold > 1`; Pluto
/// additionally rejects `threshold > total` as an unrecoverable, always-bug
/// configuration.) Returns [`Error::InvalidSecretKey`] if `secret_key` is
/// not a valid BLS scalar, and [`Error::ThresholdOverflow`] if `threshold`
/// does not fit in `usize` on this platform.
pub fn threshold_split_insecure(
    secret_key: &PrivateKey,
    total: Index,
    threshold: Index,
    mut rng: impl RngCore + CryptoRng,
) -> Result<HashMap<Index, PrivateKey>, Error> {
    // Charon's Herumi backend only rejects `threshold <= 1`
    // (see charon/tbls/herumi.go ThresholdSplit @ v1.7.1). We additionally
    // reject `threshold > total`: such a (t, n) scheme is unrecoverable and
    // is always a programming error. No Charon call site passes t > n, so
    // this hardening never rejects an otherwise-valid split.
    if threshold <= 1 || threshold > total {
        return Err(Error::InvalidThreshold { threshold, total });
    }

    // `threshold` is bounded above by `total` here; the conversion is
    // infallible on 64-bit targets and only fails on 32-bit targets for an
    // implausibly large `total`. Map that to a dedicated overflow error
    // rather than re-using InvalidThreshold (the value is in range).
    let threshold_usize =
        usize::try_from(threshold).map_err(|_| Error::ThresholdOverflow { threshold })?;

    let sk =
        BlstSecretKey::from_bytes(secret_key).map_err(|e| Error::InvalidSecretKey(e.into()))?;

    // Create polynomial coefficients: a_0 = secret, a_1..a_{t-1} = random.
    // `poly` holds `BlstSecretKey`s, each `#[zeroize(drop)]`, so the secret
    // coefficients are wiped when `poly` is dropped.
    let mut poly = Vec::with_capacity(threshold_usize);
    poly.push(sk);

    for _ in 1..threshold {
        let mut ikm = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(ikm.as_mut());
        let coeff = BlstSecretKey::key_gen(ikm.as_ref(), &[])
            .map_err(|_| Error::InvalidSecretKey(BlsError::KeyGeneration))?;
        poly.push(coeff);
    }

    // Evaluate polynomial at points 1..total to create shares
    let mut shares = HashMap::new();
    for i in 1..=total {
        let share = math::evaluate_polynomial(&poly, i)?;
        shares.insert(i, share.to_bytes());
    }

    Ok(shares)
}

/// ThresholdSplit splits a compressed secret into total units of secret
/// keys, with the given threshold. It returns a map that associates
/// each private, compressed private key to its ID.
///
/// **Important:** Share IDs are 1-indexed (1, 2, 3, ..., n), matching
/// the Go implementation and TBLS polynomial evaluation points.
///
/// # Limitations
///
/// Maximum of 255 shares (total <= 255) due to underlying BLS library
/// constraints.
///
/// # Errors
///
/// Returns [`Error::InvalidThreshold`] if `threshold < 2` or
/// `threshold > total`. (Charon only enforces `threshold > 1`; Pluto
/// additionally rejects `threshold > total` as an unrecoverable, always-bug
/// configuration.) Returns [`Error::InvalidSecretKey`] if `secret_key` is
/// not a valid BLS scalar, and [`Error::ThresholdOverflow`] if `threshold`
/// does not fit in `usize` on this platform.
pub fn threshold_split(
    secret_key: &PrivateKey,
    total: Index,
    threshold: Index,
) -> Result<HashMap<Index, PrivateKey>, Error> {
    // Use OsRng for secure random number generation
    threshold_split_insecure(secret_key, total, threshold, rand::rngs::OsRng)
}

/// Recovers a secret from a set of shares
///
/// **Important:** Share IDs in the input HashMap must be 1-indexed
/// (1, 2, 3, ..., n), matching the IDs returned by threshold_split.
///
/// # Limitations
///
/// Share IDs must be < 255 due to underlying BLS library constraints.
pub fn recover_secret(shares: &HashMap<Index, PrivateKey>) -> Result<PrivateKey, Error> {
    if shares.is_empty() {
        return Err(Error::SharesAreEmpty);
    }

    // Share indices are already 1-indexed (matching their polynomial evaluation
    // points)
    let share_points: Vec<Index> = shares.keys().copied().collect();

    // The reconstructed master secret and the parsed share scalars are all
    // `BlstSecretKey`s (`#[zeroize(drop)]`), so they are wiped on drop.
    let share_secrets: Vec<BlstSecretKey> = shares
        .values()
        .map(|bytes| {
            BlstSecretKey::from_bytes(bytes).map_err(|e| Error::InvalidSecretKey(e.into()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Lagrange interpolation at x=0
    let recovered = math::lagrange_interpolate_secret(&share_points, &share_secrets)?;
    Ok(recovered.to_bytes())
}

/// Aggregates a set of signatures into a single signature
pub fn aggregate(signatures: &[Signature]) -> Result<Signature, Error> {
    // Parity with Charon Herumi `Aggregate` (tbls/herumi.go:227): an empty
    // input is NOT an error. Herumi aggregates into a zero `bls.Sign` and
    // returns its serialized form, i.e. the G2 compressed point at infinity.
    if signatures.is_empty() {
        return Ok(IDENTITY_SIGNATURE);
    }

    // Deserialize every input signature (matches the Herumi loop, which
    // errors if any element fails to deserialize). Note: aggregation
    // canonicalizes the output even for a single input (Herumi returns
    // `sig.Serialize()`, never the input bytes verbatim).
    let parsed_sigs: Vec<BlstSignature> = signatures
        .iter()
        .map(|sig_bytes| {
            BlstSignature::from_bytes(sig_bytes).map_err(|e| Error::InvalidSignature(e.into()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let sigs: Vec<&BlstSignature> = parsed_sigs.iter().collect();

    let agg = blst::min_pk::AggregateSignature::aggregate(&sigs[..], true)
        .map_err(|e| Error::AggregationFailed(e.into()))?;

    Ok(agg.to_signature().to_bytes())
}

/// Aggregates a set of partial signatures into a single
/// signature
///
/// **Important:** Share IDs in the input HashMap must be 1-indexed
/// (1, 2, 3, ..., n), matching the share IDs used for key splitting.
///
/// # Limitations
///
/// Share IDs must be < 255 due to underlying BLS library constraints.
pub fn threshold_aggregate(
    partial_signatures_by_idx: &HashMap<Index, Signature>,
) -> Result<Signature, Error> {
    if partial_signatures_by_idx.is_empty() {
        return Err(Error::EmptySignatureArray);
    }

    // Signature indices are already 1-indexed (matching share evaluation
    // points)
    let indices: Vec<Index> = partial_signatures_by_idx.keys().copied().collect();

    let signatures: Vec<BlstSignature> = partial_signatures_by_idx
        .values()
        .map(|sig_bytes| {
            BlstSignature::from_bytes(sig_bytes).map_err(|e| Error::InvalidSignature(e.into()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Perform Lagrange interpolation on signatures at x=0
    let recovered_sig = math::lagrange_interpolate_signature(&indices, &signatures)?;
    Ok(recovered_sig.to_bytes())
}

/// Verify verifies a signature
pub fn verify(public_key: &PublicKey, data: &[u8], raw_signature: &Signature) -> Result<(), Error> {
    let pk =
        BlstPublicKey::from_bytes(public_key).map_err(|e| Error::InvalidPublicKey(e.into()))?;

    let sig =
        BlstSignature::from_bytes(raw_signature).map_err(|e| Error::InvalidSignature(e.into()))?;

    let result = sig.verify(true, data, ETH2_DST, &[], &pk, true);

    if result == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(Error::VerificationFailed(result.into()))
    }
}

/// Signs a message with a private key
pub fn sign(private_key: &PrivateKey, data: &[u8]) -> Result<Signature, Error> {
    let sk =
        BlstSecretKey::from_bytes(private_key).map_err(|e| Error::InvalidSecretKey(e.into()))?;
    let sig = sk.sign(data, ETH2_DST, &[]);
    Ok(sig.to_bytes())
}

/// Verifies an aggregate signature against the sum of `public_keys`.
///
/// Each key is validated individually — infinity and G1 subgroup checks —
/// before the keys are summed: a point and its negation cancel to infinity, so
/// checking only the sum lets invalid keys through. This is the IETF BLS
/// `FastAggregateVerify` precondition that `KeyValidate` succeeded for every
/// input key.
pub fn verify_aggregate(
    public_keys: &[PublicKey],
    signature: Signature,
    data: &[u8],
) -> Result<(), Error> {
    if public_keys.is_empty() {
        return Err(Error::EmptyPublicKeyArray);
    }

    let pks: Vec<BlstPublicKey> = public_keys
        .iter()
        .map(|pk_bytes| {
            BlstPublicKey::key_validate(pk_bytes).map_err(|e| Error::InvalidPublicKey(e.into()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let sig =
        BlstSignature::from_bytes(&signature).map_err(|e| Error::InvalidSignature(e.into()))?;

    // Aggregate public keys using blst point addition
    let agg_pk = math::aggregate_public_keys(&pks)?;

    let result = sig.verify(true, data, ETH2_DST, &[], &agg_pk, true);

    if result == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(Error::VerificationFailed(result.into()))
    }
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::StdRng};
    use test_case::test_case;

    use super::*;
    use crate::types::PUBLIC_KEY_LENGTH;

    #[test]
    fn generate_insecure_secret() {
        let sk = super::generate_insecure_secret(rand::rngs::OsRng).unwrap();
        assert_eq!(sk.len(), 32);
    }

    #[test]
    fn verify_aggregate_from_data() {
        let data = b"hello obol!";

        // Decode the secret key from hex
        let secret_bytes =
            hex::decode("7356c7dab0220088158a8bba45894b164c04cf7de83149e2c4fab381e765ff38")
                .unwrap();
        assert_eq!(secret_bytes.len(), 32);

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);
        assert!(!secret.is_empty());

        // Split the secret into shares (total=5, threshold=3)
        let shares = threshold_split(&secret, 5, 3).unwrap();
        assert_eq!(shares.len(), 5);

        // Create signatures for each share
        let mut signatures = HashMap::new();
        for (idx, key) in shares.iter() {
            let signature = sign(key, data).unwrap();
            signatures.insert(*idx, signature);
        }

        // Aggregate the threshold signatures
        let total_sig = threshold_aggregate(&signatures).unwrap();

        // Expected signature from the Go implementation
        let expected_sig = hex::decode("b46736c3a1fb5d7977acc6abf3cb3a10fd1a5aed301437022f28cf616326186654d747fda7cd530c2bf18c640e4c024b01d7ba38d90e4abe0cc5356ef63b8e20f717ef0a1f68c3292bd62b4f891345ecafa89a8604f8f6c3ce193dc239215adf").unwrap();

        // Compare the aggregated signature with the expected one
        assert_eq!(
            expected_sig,
            &total_sig[..],
            "Aggregated signature does not match expected signature from Go implementation"
        );
    }

    #[test]
    fn generate_and_derive_key() {
        use rand::rngs::OsRng;

        let sk = generate_secret_key(OsRng).unwrap();
        assert_eq!(sk.len(), 32);

        let pk = secret_to_public_key(&sk).unwrap();
        assert_eq!(pk.len(), 48);
    }

    #[test]
    fn sign_and_verify() {
        use rand::rngs::OsRng;

        let sk = generate_secret_key(OsRng).unwrap();
        let pk = secret_to_public_key(&sk).unwrap();
        let data = b"test message";

        let sig = sign(&sk, data).unwrap();
        assert_eq!(sig.len(), 96);

        let result = verify(&pk, data, &sig);
        assert!(result.is_ok());
    }

    #[test]
    fn threshold_split_and_recover() {
        use rand::rngs::OsRng;

        let sk = generate_secret_key(OsRng).unwrap();
        let threshold = 3;
        let total = 5;

        let shares = threshold_split(&sk, total, threshold).unwrap();
        assert_eq!(shares.len(), usize::try_from(total).unwrap());

        // Take exactly threshold shares
        let subset: HashMap<Index, PrivateKey> = shares
            .iter()
            .take(usize::try_from(threshold).unwrap())
            .map(|(k, v)| (*k, *v))
            .collect();

        let recovered_sk = recover_secret(&subset).unwrap();
        assert_eq!(sk, recovered_sk);
    }

    #[test]
    fn recover_secret_with_all_shares() {
        use rand::rngs::OsRng;

        let secret = generate_secret_key(OsRng).unwrap();
        let threshold = 3;
        let total = 5;

        let shares = threshold_split(&secret, total, threshold).unwrap();
        assert_eq!(shares.len(), usize::try_from(total).unwrap());

        // Recover using all shares
        let recovered = recover_secret(&shares).unwrap();
        assert_eq!(
            secret, recovered,
            "Secret recovered from all shares should match original"
        );
    }

    #[test]
    fn threshold_aggregate_matches_direct_sign() {
        use rand::rngs::OsRng;

        let data = b"hello obol!";

        let secret = generate_secret_key(OsRng).unwrap();

        // Sign directly with the secret
        let direct_sig = sign(&secret, data).unwrap();

        // Split into shares and sign with each
        let shares = threshold_split(&secret, 5, 3).unwrap();
        let mut signatures = HashMap::new();
        for (idx, key) in shares.iter() {
            let signature = sign(key, data).unwrap();
            signatures.insert(*idx, signature);
        }

        // Aggregate threshold signatures
        let aggregated_sig = threshold_aggregate(&signatures).unwrap();

        // Both signatures should be identical
        assert_eq!(
            direct_sig, aggregated_sig,
            "Threshold aggregated signature should match direct signature"
        );
    }

    #[test]
    fn verify_with_correct_signature() {
        use rand::rngs::OsRng;

        let data = b"hello obol!";

        let secret = generate_secret_key(OsRng).unwrap();
        let pubkey = secret_to_public_key(&secret).unwrap();
        let signature = sign(&secret, data).unwrap();

        let result = verify(&pubkey, data, &signature);
        assert!(
            result.is_ok(),
            "Verification should succeed with correct signature"
        );
    }

    #[test]
    fn verify_fails_with_wrong_message() {
        use rand::rngs::OsRng;

        let data1 = b"hello obol!";
        let data2 = b"goodbye obol!";

        let secret = generate_secret_key(OsRng).unwrap();
        let pubkey = secret_to_public_key(&secret).unwrap();
        let signature = sign(&secret, data1).unwrap();

        let result = verify(&pubkey, data2, &signature);
        assert!(
            result.is_err(),
            "Verification should fail with wrong message"
        );
    }

    #[test]
    fn verify_fails_with_wrong_public_key() {
        use rand::rngs::OsRng;

        let data = b"hello obol!";

        let secret1 = generate_secret_key(OsRng).unwrap();
        let secret2 = generate_secret_key(OsRng).unwrap();
        let pubkey2 = secret_to_public_key(&secret2).unwrap();
        let signature1 = sign(&secret1, data).unwrap();

        let result = verify(&pubkey2, data, &signature1);
        assert!(
            result.is_err(),
            "Verification should fail with wrong public key"
        );
    }

    #[test]
    fn verify_aggregate_success() {
        use rand::rngs::OsRng;

        let data = b"hello obol!";

        // Generate 10 key pairs
        let mut keys = Vec::new();
        for _ in 0..10 {
            let secret = generate_secret_key(OsRng).unwrap();
            let pubkey = secret_to_public_key(&secret).unwrap();
            keys.push((secret, pubkey));
        }

        // Sign with each key
        let mut signatures = Vec::new();
        let mut public_keys = Vec::new();
        for (secret, pubkey) in &keys {
            let sig = sign(secret, data).unwrap();
            signatures.push(sig);
            public_keys.push(*pubkey);
        }

        // Aggregate signatures
        let aggregated_sig = aggregate(&signatures).unwrap();

        // Verify aggregate
        let result = verify_aggregate(&public_keys, aggregated_sig, data);
        assert!(result.is_ok(), "Aggregate verification should succeed");
    }

    #[test]
    fn verify_aggregate_fails_with_wrong_data() {
        use rand::rngs::OsRng;

        let data1 = b"hello obol!";
        let data2 = b"goodbye obol!";

        // Generate 5 key pairs
        let mut keys = Vec::new();
        for _ in 0..5 {
            let secret = generate_secret_key(OsRng).unwrap();
            let pubkey = secret_to_public_key(&secret).unwrap();
            keys.push((secret, pubkey));
        }

        // Sign with each key using data1
        let mut signatures = Vec::new();
        let mut public_keys = Vec::new();
        for (secret, pubkey) in &keys {
            let sig = sign(secret, data1).unwrap();
            signatures.push(sig);
            public_keys.push(*pubkey);
        }

        // Aggregate signatures
        let aggregated_sig = aggregate(&signatures).unwrap();

        // Verify with data2 (wrong data)
        let result = verify_aggregate(&public_keys, aggregated_sig, data2);
        assert!(
            result.is_err(),
            "Aggregate verification should fail with wrong data"
        );
    }

    #[test]
    fn aggregate_single_signature_is_canonical() {
        use rand::rngs::OsRng;

        let data = b"test message";

        let sk = generate_secret_key(OsRng).unwrap();
        let sig = sign(&sk, data).unwrap();

        // Charon Herumi Aggregate deserializes+re-serializes even for one
        // element, so the output is the canonical encoding of the
        // parsed point (not the input bytes verbatim). For a signature
        // produced by `sign` these coincide.
        let aggregated = aggregate(&[sig]).unwrap();
        assert_eq!(sig, aggregated);

        // Canonical round-trip: re-serializing the parsed aggregate is
        // idempotent.
        let reparsed = BlstSignature::from_bytes(&aggregated).unwrap();
        assert_eq!(aggregated, reparsed.to_bytes());
    }

    #[test]
    fn aggregate_single_malformed_signature_errors() {
        // All-zero 96 bytes is not a valid compressed signature; Herumi's
        // Deserialize fails, so Aggregate returns an error.
        let bad = [0u8; 96];
        assert!(aggregate(&[bad]).is_err());
    }

    #[test]
    fn aggregate_multiple_signatures() {
        use rand::rngs::OsRng;

        let data = b"test message";

        // Generate 3 signatures
        let mut signatures = Vec::new();
        for _ in 0..3 {
            let sk = generate_secret_key(OsRng).unwrap();
            let sig = sign(&sk, data).unwrap();
            signatures.push(sig);
        }

        let aggregated = aggregate(&signatures).unwrap();
        assert_eq!(
            aggregated.len(),
            96,
            "Aggregated signature should be 96 bytes"
        );
    }

    #[test]
    fn threshold_split_minimum_threshold() {
        use rand::rngs::OsRng;

        let sk = generate_secret_key(OsRng).unwrap();

        // Minimum valid threshold is 2
        let shares = threshold_split(&sk, 3, 2).unwrap();
        assert_eq!(shares.len(), 3);

        // Recover with exactly 2 shares
        let subset: HashMap<Index, PrivateKey> =
            shares.iter().take(2).map(|(k, v)| (*k, *v)).collect();

        let recovered = recover_secret(&subset).unwrap();
        assert_eq!(sk, recovered);
    }

    #[test]
    fn threshold_split_invalid_threshold() {
        use rand::rngs::OsRng;

        let sk = generate_secret_key(OsRng).unwrap();

        // Threshold of 1 is invalid
        let err = threshold_split(&sk, 5, 1).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidThreshold {
                threshold: 1,
                total: 5
            }
        ));

        // Threshold greater than total is invalid
        let err = threshold_split(&sk, 3, 5).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidThreshold {
                threshold: 5,
                total: 3
            }
        ));

        // threshold == 0 is also rejected (<= 1)
        let err = threshold_split(&sk, 5, 0).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidThreshold {
                threshold: 0,
                total: 5
            }
        ));
    }

    #[test]
    fn threshold_equal_total_is_valid() {
        let sk = generate_secret_key(rand::rngs::OsRng).unwrap();
        // threshold == total is a valid (n, n) scheme.
        let shares = threshold_split(&sk, 4, 4).unwrap();
        assert_eq!(shares.len(), 4);
        let recovered = recover_secret(&shares).unwrap();
        assert_eq!(sk, recovered);
    }

    #[test]
    fn invalid_secret_key_error_is_consistent() {
        // All-0xff bytes are >= the scalar field order => from_bytes fails.
        let bad: PrivateKey = [0xff; 32];

        assert!(matches!(
            secret_to_public_key(&bad),
            Err(Error::InvalidSecretKey(_))
        ));
        assert!(matches!(
            sign(&bad, b"data"),
            Err(Error::InvalidSecretKey(_))
        ));
        assert!(matches!(
            threshold_split(&bad, 5, 3),
            Err(Error::InvalidSecretKey(_))
        ));

        let mut shares = HashMap::new();
        shares.insert(1u64, bad);
        shares.insert(2u64, bad);
        assert!(matches!(
            recover_secret(&shares),
            Err(Error::InvalidSecretKey(_))
        ));
    }

    #[test]
    fn different_keys_produce_different_signatures() {
        use rand::rngs::OsRng;

        let data = b"test message";

        let sk1 = generate_secret_key(OsRng).unwrap();
        let sk2 = generate_secret_key(OsRng).unwrap();

        let sig1 = sign(&sk1, data).unwrap();
        let sig2 = sign(&sk2, data).unwrap();

        assert_ne!(
            sig1, sig2,
            "Different keys should produce different signatures"
        );
    }

    #[test]
    fn same_key_produces_same_signature() {
        use rand::rngs::OsRng;

        let data = b"test message";

        let sk = generate_secret_key(OsRng).unwrap();

        let sig1 = sign(&sk, data).unwrap();
        let sig2 = sign(&sk, data).unwrap();

        assert_eq!(
            sig1, sig2,
            "Same key should produce same signature for same data"
        );
    }

    #[test]
    fn aggregate_empty_returns_identity_signature() {
        // Parity with Charon Herumi Aggregate: empty input is NOT an error; it
        // returns the serialized G2 point at infinity. Fixture: `0xc0` followed
        // by 95 zero bytes (Herumi `sig.Serialize()` of a zero
        // `bls.Sign`).
        let agg = aggregate(&[]).expect("empty aggregate must not error (Herumi parity)");

        let mut expected = [0u8; 96];
        expected[0] = 0xc0;
        assert_eq!(
            agg, expected,
            "empty aggregate must equal the serialized identity signature"
        );
    }

    #[test]
    fn identity_signature_matches_go_fixture() {
        // Hex of Herumi `bls.Sign{}.Serialize()` for the BLS12-381 G2
        // compressed point at infinity (eth2/ZCash compressed
        // encoding): `c0` followed by 190 hex zeros (96 bytes total).
        let go_fixture_hex = format!("c0{}", "0".repeat(190));
        let go_fixture = hex::decode(go_fixture_hex).unwrap();
        assert_eq!(go_fixture.len(), 96);
        assert_eq!(&IDENTITY_SIGNATURE[..], &go_fixture[..]);
    }

    #[test]
    fn public_key_is_deterministic() {
        use rand::rngs::OsRng;

        let sk = generate_secret_key(OsRng).unwrap();

        let pk1 = secret_to_public_key(&sk).unwrap();
        let pk2 = secret_to_public_key(&sk).unwrap();

        assert_eq!(pk1, pk2, "Public key derivation should be deterministic");
    }

    #[test]
    fn different_secrets_produce_different_public_keys() {
        use rand::rngs::OsRng;

        let sk1 = generate_secret_key(OsRng).unwrap();
        let sk2 = generate_secret_key(OsRng).unwrap();

        let pk1 = secret_to_public_key(&sk1).unwrap();
        let pk2 = secret_to_public_key(&sk2).unwrap();

        assert_ne!(
            pk1, pk2,
            "Different secrets should produce different public keys"
        );
    }

    #[test]
    fn threshold_split_returns_1_indexed_keys() {
        use rand::rngs::OsRng;

        let sk = generate_secret_key(OsRng).unwrap();

        // Split into 5 shares
        let shares = threshold_split(&sk, 5, 3).unwrap();
        assert_eq!(shares.len(), 5);

        // Verify keys are 1-indexed (1, 2, 3, 4, 5)
        assert!(shares.contains_key(&1), "Should contain key 1");
        assert!(shares.contains_key(&2), "Should contain key 2");
        assert!(shares.contains_key(&3), "Should contain key 3");
        assert!(shares.contains_key(&4), "Should contain key 4");
        assert!(shares.contains_key(&5), "Should contain key 5");

        // Verify no 0-indexed key exists
        assert!(!shares.contains_key(&0), "Should not contain key 0");
    }

    /// Compressed `x = 4`: on the curve, outside the order-`r` subgroup G1.
    /// `0x80` is the compression flag, sign bit clear.
    const OFF_SUBGROUP_G1_POINT: PublicKey = {
        let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
        bytes[0] = 0x80;
        bytes[PUBLIC_KEY_LENGTH - 1] = 4;
        bytes
    };

    /// Same `x` with the sign bit set: the negation, so the pair sums to
    /// infinity.
    const NEGATED_OFF_SUBGROUP_G1_POINT: PublicKey = {
        let mut bytes = OFF_SUBGROUP_G1_POINT;
        bytes[0] = 0xa0;
        bytes
    };

    /// Compressed G1 point at infinity: compression bit plus infinity bit.
    const INFINITY_G1_POINT: PublicKey = {
        let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
        bytes[0] = 0xc0;
        bytes
    };

    /// Position must not matter, so all three orderings are checked.
    #[test]
    fn verify_aggregate_rejects_off_subgroup_cancelling_keys() {
        let data = b"test message";
        let sk = generate_secret_key(rand::rngs::OsRng).unwrap();
        let pk = secret_to_public_key(&sk).unwrap();
        let sig = sign(&sk, data).unwrap();

        assert!(verify_aggregate(&[pk], sig, data).is_ok());

        for keys in [
            [pk, OFF_SUBGROUP_G1_POINT, NEGATED_OFF_SUBGROUP_G1_POINT],
            [OFF_SUBGROUP_G1_POINT, NEGATED_OFF_SUBGROUP_G1_POINT, pk],
            [OFF_SUBGROUP_G1_POINT, pk, NEGATED_OFF_SUBGROUP_G1_POINT],
        ] {
            assert!(
                matches!(
                    verify_aggregate(&keys, sig, data),
                    Err(Error::InvalidPublicKey(BlsError::PointNotInGroup))
                ),
                "cancelling keys must be rejected, not summed away"
            );
        }
    }

    /// The degenerate case: infinity contributes nothing to the sum either.
    #[test]
    fn verify_aggregate_rejects_infinity_key() {
        let data = b"test message";
        let sk = generate_secret_key(rand::rngs::OsRng).unwrap();
        let pk = secret_to_public_key(&sk).unwrap();
        let sig = sign(&sk, data).unwrap();

        for keys in [[pk, INFINITY_G1_POINT], [INFINITY_G1_POINT, pk]] {
            assert!(matches!(
                verify_aggregate(&keys, sig, data),
                Err(Error::InvalidPublicKey(BlsError::InvalidPublicKey))
            ));
        }
    }

    /// A lone off-subgroup key was rejected before this fix too, but as
    /// `VerificationFailed` from the check on the summed key.
    #[test]
    fn verify_aggregate_reports_a_bad_key_as_a_key_error_not_a_verify_failure() {
        let data = b"test message";
        let sk = generate_secret_key(rand::rngs::OsRng).unwrap();
        let sig = sign(&sk, data).unwrap();

        assert!(matches!(
            verify_aggregate(&[OFF_SUBGROUP_G1_POINT], sig, data),
            Err(Error::InvalidPublicKey(BlsError::PointNotInGroup))
        ));

        assert!(matches!(
            verify_aggregate(&[[0xff; PUBLIC_KEY_LENGTH]], sig, data),
            Err(Error::InvalidPublicKey(BlsError::BadEncoding))
        ));
    }

    /// An RNG that yields one byte value forever, so these assertions do not
    /// depend on a particular `rand` version's stream.
    struct ConstantRng(u8);

    impl RngCore for ConstantRng {
        fn next_u32(&mut self) -> u32 {
            u32::from_le_bytes([self.0; 4])
        }

        fn next_u64(&mut self) -> u64 {
            u64::from_le_bytes([self.0; 8])
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(self.0);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for ConstantRng {}

    /// Below the scalar-field order (which begins `0x73`) and non-zero, so it
    /// is accepted on the first draw.
    const VALID_DRAW: PrivateKey = [0x01; 32];

    /// Above the scalar-field order, so it is always rejected.
    const INVALID_DRAW: u8 = 0xff;

    #[test]
    fn generate_insecure_secret_is_reproducible_from_its_seed() {
        let first = super::generate_insecure_secret(StdRng::from_seed([1u8; 32])).unwrap();
        let again = super::generate_insecure_secret(StdRng::from_seed([1u8; 32])).unwrap();
        let other = super::generate_insecure_secret(StdRng::from_seed([2u8; 32])).unwrap();

        assert_eq!(first, again, "the same seed must give the same secret");
        assert_ne!(first, other, "different seeds must give different secrets");
    }

    // Unlike `generate_secret_key`, this performs no key derivation: it hands
    // back the draw verbatim. That is why it is documented as insecure.
    #[test]
    fn generate_insecure_secret_returns_the_raw_rng_draw() {
        // Asserted, so this cannot quietly become a test of the retry loop.
        assert!(
            BlstSecretKey::from_bytes(&VALID_DRAW).is_ok(),
            "the fixture draw must already be a valid scalar"
        );

        let secret = super::generate_insecure_secret(ConstantRng(VALID_DRAW[0])).unwrap();

        assert_eq!(
            secret, VALID_DRAW,
            "the returned secret must be the RNG draw itself"
        );
    }

    // The retry loop is bounded at 100 attempts, so an RNG that can never
    // produce a valid scalar must terminate rather than spin.
    #[test]
    fn generate_insecure_secret_gives_up_after_its_retry_budget() {
        let result = super::generate_insecure_secret(ConstantRng(INVALID_DRAW));

        assert!(
            matches!(
                result,
                Err(Error::InvalidSecretKey(BlsError::KeyGeneration))
            ),
            "expected InvalidSecretKey(KeyGeneration), got {result:?}"
        );
    }

    // `generate_secret_key` runs EIP-2333 `key_gen` over the RNG output, so
    // the returned key is *not* the draw.
    #[test]
    fn generate_secret_key_derives_rather_than_returning_the_rng_draw() {
        let derived = generate_secret_key(ConstantRng(VALID_DRAW[0])).unwrap();

        // `VALID_DRAW` is itself a usable scalar, so returning it verbatim
        // would have looked correct.
        assert_ne!(
            derived, VALID_DRAW,
            "the key must be derived from the IKM, not equal to it"
        );
        assert_eq!(
            derived,
            generate_secret_key(ConstantRng(VALID_DRAW[0])).unwrap(),
            "derivation must be deterministic for fixed input key material"
        );
    }

    // Three empty inputs, three different errors, all raised by this layer
    // before it delegates. `tbls::math` reports `IndicesSharesMismatch` for the
    // empty case — a different guard, a different variant.
    #[test]
    fn empty_inputs_are_rejected_with_their_own_errors() {
        assert!(matches!(
            recover_secret(&HashMap::new()),
            Err(Error::SharesAreEmpty)
        ));
        assert!(matches!(
            threshold_aggregate(&HashMap::new()),
            Err(Error::EmptySignatureArray)
        ));
        assert!(matches!(
            verify_aggregate(&[], IDENTITY_SIGNATURE, b"data"),
            Err(Error::EmptyPublicKeyArray)
        ));
    }

    // Aggregating fewer than `threshold` partials returns `Ok` with a
    // well-formed 96-byte signature; only verification reveals it signs
    // nothing. (`math.rs` pins the secret-side twin.)
    #[test]
    fn threshold_aggregate_below_threshold_returns_a_signature_that_does_not_verify() {
        const MSG: &[u8] = b"sub-threshold aggregate";

        let secret = generate_secret_key(rand::rngs::OsRng).unwrap();
        let public_key = secret_to_public_key(&secret).unwrap();
        let shares = threshold_split(&secret, 5, 3).unwrap();

        // Fixed explicitly: `HashMap` order is not stable, so "the first two"
        // would be flaky.
        let mut partials = HashMap::new();
        for idx in [1u64, 2] {
            let share = shares.get(&idx).expect("shares are 1-indexed over 1..=5");
            partials.insert(idx, sign(share, MSG).unwrap());
        }

        let aggregated = threshold_aggregate(&partials)
            .expect("sub-threshold aggregation succeeds — that is the hazard");

        assert_eq!(
            aggregated.len(),
            SIGNATURE_LENGTH,
            "the result is indistinguishable from a real signature by shape"
        );
        assert!(
            matches!(
                verify(&public_key, MSG, &aggregated),
                Err(Error::VerificationFailed(_))
            ),
            "only verification reveals that 2 of 3 was not enough"
        );
    }

    // A *key* error, never a verification failure: the two lead a caller to
    // opposite conclusions — "my input is broken" vs "this signer is lying".
    #[test_case([0u8; PUBLIC_KEY_LENGTH] ; "all zero")]
    #[test_case([0xff; PUBLIC_KEY_LENGTH] ; "all ones")]
    fn verify_rejects_a_malformed_public_key(public_key: PublicKey) {
        let result = verify(&public_key, b"data", &IDENTITY_SIGNATURE);

        assert!(
            matches!(result, Err(Error::InvalidPublicKey(BlsError::BadEncoding))),
            "expected InvalidPublicKey(BadEncoding), got {result:?}"
        );
    }

    // Four functions parse signatures independently; only `aggregate` had
    // coverage. Each remaining call site maps its own error, so a missing or
    // mis-mapped `?` is otherwise invisible.
    #[test]
    fn every_entry_point_that_parses_a_signature_rejects_a_malformed_one() {
        const MSG: &[u8] = b"malformed signature";
        const BAD: Signature = [0u8; SIGNATURE_LENGTH];

        let secret = generate_secret_key(rand::rngs::OsRng).unwrap();
        let public_key = secret_to_public_key(&secret).unwrap();

        let threshold = threshold_aggregate(&HashMap::from([(1u64, BAD)]));
        assert!(
            matches!(threshold, Err(Error::InvalidSignature(_))),
            "threshold_aggregate: expected InvalidSignature, got {threshold:?}"
        );

        let verified = verify(&public_key, MSG, &BAD);
        assert!(
            matches!(verified, Err(Error::InvalidSignature(_))),
            "verify: expected InvalidSignature, got {verified:?}"
        );

        let verified_aggregate = verify_aggregate(&[public_key], BAD, MSG);
        assert!(
            matches!(verified_aggregate, Err(Error::InvalidSignature(_))),
            "verify_aggregate: expected InvalidSignature, got {verified_aggregate:?}"
        );
    }

    // `aggregate(&[])` hands back the identity signature, which must fail
    // rather than verify against anything.
    #[test]
    fn verify_rejects_the_identity_signature() {
        let secret = generate_secret_key(rand::rngs::OsRng).unwrap();
        let public_key = secret_to_public_key(&secret).unwrap();

        let result = verify(&public_key, b"data", &IDENTITY_SIGNATURE);

        assert!(
            matches!(result, Err(Error::VerificationFailed(_))),
            "the identity signature must not verify, got {result:?}"
        );
    }

    // Through `verify`, an off-subgroup key is indistinguishable from a bad
    // signature: blst 0.3.17's `aggregate_verify` collapses every per-key
    // failure into one flag and returns a flat `BLST_VERIFY_FAIL`.
    // `verify_aggregate` calls `key_validate` first and reports
    // `InvalidPublicKey`. Asserted together so the contrast cannot drift.
    #[test]
    fn verify_cannot_distinguish_an_off_subgroup_key_from_a_bad_signature() {
        const MSG: &[u8] = b"off subgroup key";

        // Genuine, so the outcome is attributable to the key alone.
        let secret = generate_secret_key(rand::rngs::OsRng).unwrap();
        let signature = sign(&secret, MSG).unwrap();

        let result = verify(&OFF_SUBGROUP_G1_POINT, MSG, &signature);
        assert!(
            matches!(
                result,
                Err(Error::VerificationFailed(BlsError::VerifyFailed))
            ),
            "expected VerificationFailed(VerifyFailed), got {result:?}"
        );

        // The same 48 bytes, reported far more precisely one function over.
        let aggregate_result = verify_aggregate(&[OFF_SUBGROUP_G1_POINT], signature, MSG);
        assert!(
            matches!(
                aggregate_result,
                Err(Error::InvalidPublicKey(BlsError::PointNotInGroup))
            ),
            "verify_aggregate must name the real cause, got {aggregate_result:?}"
        );
    }
}
