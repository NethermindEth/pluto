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

/// Verifies an aggregate signature
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
            BlstPublicKey::from_bytes(pk_bytes).map_err(|e| Error::InvalidPublicKey(e.into()))
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
    use super::*;

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

    /// All size-`k` combinations of `items`, order-independent.
    fn combinations<T: Copy>(items: &[T], k: usize) -> Vec<Vec<T>> {
        if k == 0 {
            return vec![vec![]];
        }
        // No combinations exist once `k` exceeds the remaining items.
        let Some(max_start) = items.len().checked_sub(k) else {
            return vec![];
        };
        let mut out = Vec::new();
        for i in 0..=max_start {
            let rest = &items[i.saturating_add(1)..];
            for mut tail in combinations(rest, k.saturating_sub(1)) {
                let mut combo = vec![items[i]];
                combo.append(&mut tail);
                out.push(combo);
            }
        }
        out
    }

    /// Lagrange interpolation of the secret must recover the original from
    /// *every* threshold-sized subset of shares, not just the first `threshold`
    /// or the full set — exercising `lagrange_interpolate_secret` across many
    /// distinct (and non-contiguous) index sets.
    #[test]
    fn recover_secret_from_every_threshold_subset() {
        use rand::rngs::OsRng;

        for (total, threshold) in [(4u64, 2u64), (5, 3), (6, 4), (7, 4)] {
            let secret = generate_secret_key(OsRng).unwrap();
            let shares = threshold_split(&secret, total, threshold).unwrap();
            let indices: Vec<Index> = {
                let mut ks: Vec<Index> = shares.keys().copied().collect();
                ks.sort_unstable();
                ks
            };

            for subset in combinations(&indices, usize::try_from(threshold).unwrap()) {
                let picked: HashMap<Index, PrivateKey> =
                    subset.iter().map(|idx| (*idx, shares[idx])).collect();
                let recovered = recover_secret(&picked).unwrap();
                assert_eq!(
                    secret, recovered,
                    "recovery from subset {subset:?} of (t={threshold}, n={total}) must match",
                );
            }
        }
    }

    /// Lagrange interpolation of signatures (the Pippenger MSM path) must
    /// reconstruct the group signature from *every* threshold-sized subset of
    /// partial signatures, and it must equal the signature produced directly by
    /// the master secret.
    #[test]
    fn threshold_aggregate_from_every_threshold_subset() {
        use rand::rngs::OsRng;

        let data = b"hello obol!";
        for (total, threshold) in [(4u64, 2u64), (5, 3), (6, 4), (7, 4)] {
            let secret = generate_secret_key(OsRng).unwrap();
            let direct_sig = sign(&secret, data).unwrap();

            let shares = threshold_split(&secret, total, threshold).unwrap();
            let partials: HashMap<Index, Signature> = shares
                .iter()
                .map(|(idx, key)| (*idx, sign(key, data).unwrap()))
                .collect();
            let indices: Vec<Index> = {
                let mut ks: Vec<Index> = partials.keys().copied().collect();
                ks.sort_unstable();
                ks
            };

            for subset in combinations(&indices, usize::try_from(threshold).unwrap()) {
                let picked: HashMap<Index, Signature> =
                    subset.iter().map(|idx| (*idx, partials[idx])).collect();
                let aggregated = threshold_aggregate(&picked).unwrap();
                assert_eq!(
                    direct_sig, aggregated,
                    "aggregate from subset {subset:?} of (t={threshold}, n={total}) must match direct sign",
                );
            }
        }
    }
}
