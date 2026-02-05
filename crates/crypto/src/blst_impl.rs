//! # BLST implementation
//!
//! Implementation of threshold BLS signatures using the blst library.
//! This implementation is compatible with the Herumi BLS library used in the Go
//! implementation.
#![allow(unsafe_code)]

use std::collections::{HashMap, HashSet};

use blst::{
    BLST_ERROR,
    min_pk::{PublicKey as BlstPublicKey, SecretKey as BlstSecretKey, Signature as BlstSignature},
};
use rand_core::{CryptoRng, RngCore};

use crate::{
    tbls::Tbls,
    types::{BlsError, Error, Index, MathError, PrivateKey, PublicKey, Signature},
};

/// Domain Separation Tag for Ethereum 2.0 BLS signatures
const ETH2_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// BLST implementation of threshold BLS signatures.
///
/// This implementation is compatible with the Herumi BLS library used in
/// the Go implementation of Charon.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct BlstImpl;

impl Tbls for BlstImpl {
    fn generate_secret_key(&self, mut rng: impl RngCore + CryptoRng) -> Result<PrivateKey, Error> {
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        let sk = BlstSecretKey::key_gen(&ikm, &[])
            .map_err(|_| Error::InvalidSecretKey(BlsError::KeyGeneration))?;

        Ok(sk.to_bytes())
    }

    fn generate_insecure_secret(
        &self,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<PrivateKey, Error> {
        for _ in 0..100 {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);

            if BlstSecretKey::from_bytes(&bytes).is_ok() {
                return Ok(bytes);
            }
        }
        Err(Error::InvalidSecretKey(BlsError::KeyGeneration))
    }

    fn secret_to_public_key(&self, secret_key: &PrivateKey) -> Result<PublicKey, Error> {
        let sk = BlstSecretKey::from_bytes(secret_key)?;
        let pk = sk.sk_to_pk();
        Ok(pk.to_bytes())
    }

    fn threshold_split_insecure(
        &self,
        secret_key: &PrivateKey,
        total: Index,
        threshold: Index,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<HashMap<Index, PrivateKey>, Error> {
        if threshold <= 1 || threshold > total {
            return Err(Error::InvalidThreshold { threshold, total });
        }

        let sk = BlstSecretKey::from_bytes(secret_key)?;

        // Create polynomial coefficients: a_0 = secret, a_1..a_{t-1} = random
        let mut poly = Vec::with_capacity(threshold as usize);
        poly.push(sk);

        for _ in 1..threshold {
            let mut ikm = [0u8; 32];
            rng.fill_bytes(&mut ikm);
            let coeff = BlstSecretKey::key_gen(&ikm, &[])
                .map_err(|_| Error::InvalidSecretKey(BlsError::KeyGeneration))?;
            poly.push(coeff);
        }

        // Evaluate polynomial at points 1..total to create shares
        let mut shares = HashMap::new();
        for i in 1..=total {
            let share = evaluate_polynomial(&poly, i)?;
            shares.insert(i.saturating_sub(1), share.to_bytes());
        }

        Ok(shares)
    }

    fn threshold_split(
        &self,
        secret_key: &PrivateKey,
        total: Index,
        threshold: Index,
    ) -> Result<HashMap<Index, PrivateKey>, Error> {
        // Use OsRng for secure random number generation
        self.threshold_split_insecure(secret_key, total, threshold, rand::rngs::OsRng)
    }

    fn recover_secret(&self, shares: &HashMap<Index, PrivateKey>) -> Result<PrivateKey, Error> {
        if shares.is_empty() {
            return Err(Error::SharesAreEmpty);
        }

        // Convert share indices to 1-indexed (shares are stored 0-indexed, but
        // evaluated at 1-indexed points)
        let share_points: Vec<Index> = shares
            .keys()
            .map(|&k| k.checked_add(1).ok_or(MathError::IntegerOverflow))
            .collect::<Result<Vec<_>, _>>()?;

        let share_secrets: Vec<BlstSecretKey> = shares
            .values()
            .map(|bytes| {
                BlstSecretKey::from_bytes(bytes).map_err(|e| Error::InvalidSecretKey(e.into()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Lagrange interpolation at x=0
        let recovered = lagrange_interpolate_secret(&share_points, &share_secrets)?;
        Ok(recovered.to_bytes())
    }

    fn aggregate(&self, signatures: Vec<Signature>) -> Result<Signature, Error> {
        if signatures.is_empty() {
            return Err(Error::EmptySignatureArray);
        }

        if signatures.len() == 1 {
            return Ok(signatures[0]);
        }

        // Use blst's aggregation
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

    fn threshold_aggregate(
        &self,
        partial_signatures_by_idx: &HashMap<Index, Signature>,
    ) -> Result<Signature, Error> {
        if partial_signatures_by_idx.is_empty() {
            return Err(Error::EmptySignatureArray);
        }

        // Convert indices to 1-indexed points (shares are 0-indexed, evaluated at
        // 1-indexed points)
        let indices: Vec<Index> = partial_signatures_by_idx
            .keys()
            .map(|&k| k.checked_add(1).ok_or(MathError::IntegerOverflow))
            .collect::<Result<Vec<_>, _>>()?;

        let signatures: Vec<BlstSignature> = partial_signatures_by_idx
            .values()
            .map(|sig_bytes| {
                BlstSignature::from_bytes(sig_bytes).map_err(|e| Error::InvalidSignature(e.into()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Perform Lagrange interpolation on signatures at x=0
        let recovered_sig = lagrange_interpolate_signature(&indices, &signatures)?;
        Ok(recovered_sig.to_bytes())
    }

    fn verify(
        &self,
        public_key: &PublicKey,
        data: &[u8],
        raw_signature: &Signature,
    ) -> Result<(), Error> {
        let pk =
            BlstPublicKey::from_bytes(public_key).map_err(|e| Error::InvalidPublicKey(e.into()))?;

        let sig = BlstSignature::from_bytes(raw_signature)
            .map_err(|e| Error::InvalidSignature(e.into()))?;

        let result = sig.verify(true, data, ETH2_DST, &[], &pk, true);

        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(Error::VerificationFailed(result.into()))
        }
    }

    fn sign(&self, private_key: &PrivateKey, data: &[u8]) -> Result<Signature, Error> {
        let sk = BlstSecretKey::from_bytes(private_key)?;
        let sig = sk.sign(data, ETH2_DST, &[]);
        Ok(sig.to_bytes())
    }

    fn verify_aggregate(
        &self,
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
        let agg_pk = aggregate_public_keys(&pks)?;

        let result = sig.verify(true, data, ETH2_DST, &[], &agg_pk, true);

        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(Error::VerificationFailed(result.into()))
        }
    }
}

/// Aggregate public keys
fn aggregate_public_keys(pks: &[BlstPublicKey]) -> Result<BlstPublicKey, Error> {
    if pks.is_empty() {
        return Err(Error::EmptyPublicKeyArray);
    }

    let mut agg = blst::blst_p1::default();

    unsafe {
        // Convert first key to projective form
        let first_affine: &blst::blst_p1_affine = (&pks[0]).into();
        blst::blst_p1_from_affine(&raw mut agg, first_affine);

        for pk in pks.iter().skip(1) {
            let pk_affine: &blst::blst_p1_affine = pk.into();
            blst::blst_p1_add_or_double_affine(&raw mut agg, &raw const agg, pk_affine);
        }

        // Convert back to affine
        let mut agg_affine = blst::blst_p1_affine::default();
        blst::blst_p1_to_affine(&raw mut agg_affine, &raw const agg);
        Ok(BlstPublicKey::from(agg_affine))
    }
}

/// Evaluate polynomial at point x
/// poly(x) = `a_0` + `a_1`*x + `a_2`*x^2 + ... + `a_n`*x^n
fn evaluate_polynomial(poly: &[BlstSecretKey], x: Index) -> Result<BlstSecretKey, Error> {
    if poly.is_empty() {
        return Err(Error::PolynomialIsEmpty);
    }

    // Start with the constant term
    let mut result = poly[0].clone();

    // Compute powers of x and accumulate
    let mut x_power = scalar_from_u64(u64::from(x));

    for coeff in poly.iter().skip(1) {
        // result += coeff * x_power
        let term = scalar_mult_secret(coeff, &x_power)?;
        result = scalar_add_secret(&result, &term)?;

        // x_power *= x for next iteration
        if poly.len() > 2 {
            let x_scalar = scalar_from_u64(u64::from(x));
            x_power = scalar_mult_scalars(&x_power, &x_scalar)?;
        }
    }

    Ok(result)
}

/// Lagrange interpolation of secret keys at x=0
/// Recovers f(0) from points (`x_i`, `y_i`) where `y_i` are secret keys
fn lagrange_interpolate_secret(
    indices: &[Index],
    shares: &[BlstSecretKey],
) -> Result<BlstSecretKey, Error> {
    if indices.len() != shares.len() || indices.is_empty() {
        return Err(Error::IndicesSharesMismatch);
    }

    // Compute Lagrange coefficients and interpolate
    let coeffs = compute_lagrange_coefficients(indices)?;

    let mut result = BlstSecretKey::default();

    for i in 0..shares.len() {
        let term = scalar_mult_secret(&shares[i], &coeffs[i])?;
        result = scalar_add_secret(&result, &term)?;
    }

    Ok(result)
}

/// Lagrange interpolation of signatures at x=0
/// Recovers f(0) from points (`x_i`, `σ_i`) where `σ_i` are signatures
fn lagrange_interpolate_signature(
    indices: &[Index],
    signatures: &[BlstSignature],
) -> Result<BlstSignature, Error> {
    if indices.len() != signatures.len() || indices.is_empty() {
        return Err(Error::EmptySignatureArray);
    }

    // Compute Lagrange coefficients
    let coeffs = compute_lagrange_coefficients(indices)?;

    // Multiply each signature by its Lagrange coefficient and aggregate
    let first_sig_scaled = signature_mult(&signatures[0], &coeffs[0])?;
    let mut result_p2 = blst::blst_p2::default();

    unsafe {
        // Convert first scaled signature to projective
        let first_affine: &blst::blst_p2_affine = (&first_sig_scaled).into();
        blst::blst_p2_from_affine(&raw mut result_p2, first_affine);

        for i in 1..signatures.len() {
            let sig_scaled = signature_mult(&signatures[i], &coeffs[i])?;
            let sig_affine: &blst::blst_p2_affine = (&sig_scaled).into();
            blst::blst_p2_add_or_double_affine(
                &raw mut result_p2,
                &raw const result_p2,
                sig_affine,
            );
        }

        // Convert back to affine
        let mut result_affine = blst::blst_p2_affine::default();
        blst::blst_p2_to_affine(&raw mut result_affine, &raw const result_p2);
        Ok(BlstSignature::from(result_affine))
    }
}

/// Compute Lagrange coefficients for interpolation at x=0
/// `λ_i` = ∏_{j≠i} (0 - `x_j`) / (`x_i` - `x_j`) = ∏_{j≠i} `x_j` / (`x_j` -
/// `x_i`)
fn compute_lagrange_coefficients(indices: &[Index]) -> Result<Vec<blst::blst_scalar>, Error> {
    // Check if indices are unique
    if indices.len() != indices.iter().collect::<HashSet<_>>().len() {
        return Err(Error::IndicesNotUnique);
    }

    let mut coeffs = Vec::with_capacity(indices.len());

    for (i, &x_i) in indices.iter().enumerate() {
        let mut numerator = scalar_from_u64(1);
        let mut denominator = scalar_from_u64(1);

        for (j, &x_j) in indices.iter().enumerate() {
            if i == j {
                continue;
            }

            // numerator *= x_j
            let x_j_scalar = scalar_from_u64(u64::from(x_j));
            numerator = scalar_mult_scalars(&numerator, &x_j_scalar)?;

            // denominator *= (x_j - x_i)
            let diff = if x_j > x_i {
                let diff_val = x_j.abs_diff(x_i);
                scalar_from_u64(u64::from(diff_val))
            } else {
                // For negative differences, we need to work in the scalar field
                // x_j - x_i (mod r) where r is the curve order
                let diff_val = x_i.abs_diff(x_j);
                scalar_negate(&scalar_from_u64(u64::from(diff_val)))?
            };

            denominator = scalar_mult_scalars(&denominator, &diff)?;
        }

        // Compute numerator / denominator = numerator * denominator^{-1}
        let coeff = scalar_div(&numerator, &denominator)?;
        coeffs.push(coeff);
    }

    Ok(coeffs)
}

/// Convert u64 to blst scalar
fn scalar_from_u64(val: u64) -> blst::blst_scalar {
    let mut scalar = blst::blst_scalar::default();
    unsafe {
        blst::blst_scalar_from_uint64(&raw mut scalar, &raw const val);
    }
    scalar
}

/// Multiply secret key by scalar
fn scalar_mult_secret(
    sk: &BlstSecretKey,
    scalar: &blst::blst_scalar,
) -> Result<BlstSecretKey, Error> {
    let sk_scalar = sk.into();
    let result_scalar = scalar_mult_scalars(sk_scalar, scalar)?;
    let sk: &BlstSecretKey = (&result_scalar)
        .try_into()
        .map_err(|_| Error::FailedToConvertSkToBlstScalar)?;
    Ok(sk.clone())
}

/// Add two secret keys
fn scalar_add_secret(sk1: &BlstSecretKey, sk2: &BlstSecretKey) -> Result<BlstSecretKey, Error> {
    let result = scalar_add(sk1.into(), sk2.into())?;
    let sk: &BlstSecretKey = (&result)
        .try_into()
        .map_err(|_| Error::FailedToConvertScalarToSecretKey)?;
    Ok(sk.clone())
}

/// Multiply signature by scalar
fn signature_mult(sig: &BlstSignature, scalar: &blst::blst_scalar) -> Result<BlstSignature, Error> {
    let mut sig_proj = blst::blst_p2::default();
    let mut result_p2 = blst::blst_p2::default();
    let mut result_affine = blst::blst_p2_affine::default();

    unsafe {
        // Convert affine to projective
        let sig_affine: &blst::blst_p2_affine = sig.into();
        blst::blst_p2_from_affine(&raw mut sig_proj, sig_affine);
        // Multiply
        blst::blst_p2_mult(
            &raw mut result_p2,
            &raw const sig_proj,
            scalar.b.as_ptr(),
            255,
        );
        // Convert back to affine
        blst::blst_p2_to_affine(&raw mut result_affine, &raw const result_p2);
    }

    Ok(BlstSignature::from(result_affine))
}

/// Add two scalars
fn scalar_add(a: &blst::blst_scalar, b: &blst::blst_scalar) -> Result<blst::blst_scalar, Error> {
    let mut result = blst::blst_scalar::default();
    unsafe {
        if blst::blst_sk_add_n_check(&raw mut result, a, b) {
            Ok(result)
        } else {
            Err(Error::FailedToAddScalars)
        }
    }
}

/// Multiply two scalars
fn scalar_mult_scalars(
    a: &blst::blst_scalar,
    b: &blst::blst_scalar,
) -> Result<blst::blst_scalar, Error> {
    let mut result = blst::blst_scalar::default();
    unsafe {
        if blst::blst_sk_mul_n_check(&raw mut result, a, b) {
            Ok(result)
        } else {
            Err(Error::FailedToMultiplyScalars)
        }
    }
}

/// Negate a scalar
fn scalar_negate(a: &blst::blst_scalar) -> Result<blst::blst_scalar, Error> {
    // To negate in the field, we compute (r - a) where r is the curve order
    // But blst doesn't expose this directly, so we use: -a ≡ r - a
    // We can compute this as: 0 - a
    let zero = scalar_from_u64(0);
    let mut result_scalar = blst::blst_scalar::default();

    unsafe {
        // Convert scalars to fr for arithmetic
        let mut a_fr = blst::blst_fr::default();
        let mut zero_fr = blst::blst_fr::default();

        blst::blst_fr_from_scalar(&raw mut a_fr, a);
        blst::blst_fr_from_scalar(&raw mut zero_fr, &raw const zero);

        let mut result_fr = blst::blst_fr::default();
        blst::blst_fr_sub(&raw mut result_fr, &raw const zero_fr, &raw const a_fr);

        blst::blst_scalar_from_fr(&raw mut result_scalar, &raw const result_fr);
    }

    Ok(result_scalar)
}

/// Divide two scalars (multiply by inverse)
fn scalar_div(
    numerator: &blst::blst_scalar,
    denominator: &blst::blst_scalar,
) -> Result<blst::blst_scalar, Error> {
    let zero = blst::blst_scalar::default();
    if *denominator == zero {
        return Err(Error::MathError(MathError::DivisionByZero));
    }

    let mut inv_scalar = blst::blst_scalar::default();

    unsafe {
        blst::blst_sk_inverse(&raw mut inv_scalar, denominator);
    }

    scalar_mult_scalars(numerator, &inv_scalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> BlstImpl {
        BlstImpl
    }

    #[test]
    fn test_generate_insecure_secret() {
        let blst = setup();
        let sk = blst.generate_insecure_secret(rand::rngs::OsRng).unwrap();
        assert_eq!(sk.len(), 32);
    }

    #[test]
    fn test_verify_aggregate_from_data() {
        let blst = setup();
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
        let shares = blst.threshold_split(&secret, 5, 3).unwrap();
        assert_eq!(shares.len(), 5);

        // Create signatures for each share
        let mut signatures = HashMap::new();
        for (idx, key) in &shares {
            let signature = blst.sign(key, data).unwrap();
            signatures.insert(*idx, signature);
        }

        // Aggregate the threshold signatures
        let total_sig = blst.threshold_aggregate(&signatures).unwrap();

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
    fn test_generate_and_derive_key() {
        use rand::rngs::OsRng;

        let blst = setup();
        let sk = blst.generate_secret_key(OsRng).unwrap();
        assert_eq!(sk.len(), 32);

        let pk = blst.secret_to_public_key(&sk).unwrap();
        assert_eq!(pk.len(), 48);
    }

    #[test]
    fn test_sign_and_verify() {
        use rand::rngs::OsRng;

        let blst = setup();
        let sk = blst.generate_secret_key(OsRng).unwrap();
        let pk = blst.secret_to_public_key(&sk).unwrap();
        let data = b"test message";

        let sig = blst.sign(&sk, data).unwrap();
        assert_eq!(sig.len(), 96);

        let result = blst.verify(&pk, data, &sig);
        assert!(result.is_ok());
    }

    #[test]
    fn test_threshold_split_and_recover() {
        use rand::rngs::OsRng;

        let blst = setup();
        let sk = blst.generate_secret_key(OsRng).unwrap();
        let threshold = 3;
        let total = 5;

        let shares = blst.threshold_split(&sk, total, threshold).unwrap();
        assert_eq!(shares.len(), total as usize);

        // Take exactly threshold shares
        let subset: HashMap<Index, PrivateKey> = shares
            .iter()
            .take(threshold as usize)
            .map(|(k, v)| (*k, *v))
            .collect();

        let recovered_sk = blst.recover_secret(&subset).unwrap();
        assert_eq!(sk, recovered_sk);
    }

    #[test]
    fn test_recover_secret_with_all_shares() {
        use rand::rngs::OsRng;

        let blst = setup();
        let secret = blst.generate_secret_key(OsRng).unwrap();
        let threshold = 3;
        let total = 5;

        let shares = blst.threshold_split(&secret, total, threshold).unwrap();
        assert_eq!(shares.len(), total as usize);

        // Recover using all shares
        let recovered = blst.recover_secret(&shares).unwrap();
        assert_eq!(
            secret, recovered,
            "Secret recovered from all shares should match original"
        );
    }

    #[test]
    fn test_threshold_aggregate_matches_direct_sign() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"hello obol!";

        let secret = blst.generate_secret_key(OsRng).unwrap();

        // Sign directly with the secret
        let direct_sig = blst.sign(&secret, data).unwrap();

        // Split into shares and sign with each
        let shares = blst.threshold_split(&secret, 5, 3).unwrap();
        let mut signatures = HashMap::new();
        for (idx, key) in &shares {
            let signature = blst.sign(key, data).unwrap();
            signatures.insert(*idx, signature);
        }

        // Aggregate threshold signatures
        let aggregated_sig = blst.threshold_aggregate(&signatures).unwrap();

        // Both signatures should be identical
        assert_eq!(
            direct_sig, aggregated_sig,
            "Threshold aggregated signature should match direct signature"
        );
    }

    #[test]
    fn test_verify_with_correct_signature() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"hello obol!";

        let secret = blst.generate_secret_key(OsRng).unwrap();
        let pubkey = blst.secret_to_public_key(&secret).unwrap();
        let signature = blst.sign(&secret, data).unwrap();

        let result = blst.verify(&pubkey, data, &signature);
        assert!(
            result.is_ok(),
            "Verification should succeed with correct signature"
        );
    }

    #[test]
    fn test_verify_fails_with_wrong_message() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data1 = b"hello obol!";
        let data2 = b"goodbye obol!";

        let secret = blst.generate_secret_key(OsRng).unwrap();
        let pubkey = blst.secret_to_public_key(&secret).unwrap();
        let signature = blst.sign(&secret, data1).unwrap();

        let result = blst.verify(&pubkey, data2, &signature);
        assert!(
            result.is_err(),
            "Verification should fail with wrong message"
        );
    }

    #[test]
    fn test_verify_fails_with_wrong_public_key() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"hello obol!";

        let secret1 = blst.generate_secret_key(OsRng).unwrap();
        let secret2 = blst.generate_secret_key(OsRng).unwrap();
        let pubkey2 = blst.secret_to_public_key(&secret2).unwrap();
        let signature1 = blst.sign(&secret1, data).unwrap();

        let result = blst.verify(&pubkey2, data, &signature1);
        assert!(
            result.is_err(),
            "Verification should fail with wrong public key"
        );
    }

    #[test]
    fn test_verify_aggregate_success() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"hello obol!";

        // Generate 10 key pairs
        let mut keys = Vec::new();
        for _ in 0..10 {
            let secret = blst.generate_secret_key(OsRng).unwrap();
            let pubkey = blst.secret_to_public_key(&secret).unwrap();
            keys.push((secret, pubkey));
        }

        // Sign with each key
        let mut signatures = Vec::new();
        let mut public_keys = Vec::new();
        for (secret, pubkey) in &keys {
            let sig = blst.sign(secret, data).unwrap();
            signatures.push(sig);
            public_keys.push(*pubkey);
        }

        // Aggregate signatures
        let aggregated_sig = blst.aggregate(signatures).unwrap();

        // Verify aggregate
        let result = blst.verify_aggregate(&public_keys, aggregated_sig, data);
        assert!(result.is_ok(), "Aggregate verification should succeed");
    }

    #[test]
    fn test_verify_aggregate_fails_with_wrong_data() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data1 = b"hello obol!";
        let data2 = b"goodbye obol!";

        // Generate 5 key pairs
        let mut keys = Vec::new();
        for _ in 0..5 {
            let secret = blst.generate_secret_key(OsRng).unwrap();
            let pubkey = blst.secret_to_public_key(&secret).unwrap();
            keys.push((secret, pubkey));
        }

        // Sign with each key using data1
        let mut signatures = Vec::new();
        let mut public_keys = Vec::new();
        for (secret, pubkey) in &keys {
            let sig = blst.sign(secret, data1).unwrap();
            signatures.push(sig);
            public_keys.push(*pubkey);
        }

        // Aggregate signatures
        let aggregated_sig = blst.aggregate(signatures).unwrap();

        // Verify with data2 (wrong data)
        let result = blst.verify_aggregate(&public_keys, aggregated_sig, data2);
        assert!(
            result.is_err(),
            "Aggregate verification should fail with wrong data"
        );
    }

    #[test]
    fn test_aggregate_single_signature() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"test message";

        let sk = blst.generate_secret_key(OsRng).unwrap();
        let sig = blst.sign(&sk, data).unwrap();

        let aggregated = blst.aggregate(vec![sig]).unwrap();
        assert_eq!(
            sig, aggregated,
            "Aggregating single signature should return the same signature"
        );
    }

    #[test]
    fn test_aggregate_multiple_signatures() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"test message";

        // Generate 3 signatures
        let mut signatures = Vec::new();
        for _ in 0..3 {
            let sk = blst.generate_secret_key(OsRng).unwrap();
            let sig = blst.sign(&sk, data).unwrap();
            signatures.push(sig);
        }

        let aggregated = blst.aggregate(signatures).unwrap();
        assert_eq!(
            aggregated.len(),
            96,
            "Aggregated signature should be 96 bytes"
        );
    }

    #[test]
    fn test_threshold_split_minimum_threshold() {
        use rand::rngs::OsRng;

        let blst = setup();
        let sk = blst.generate_secret_key(OsRng).unwrap();

        // Minimum valid threshold is 2
        let shares = blst.threshold_split(&sk, 3, 2).unwrap();
        assert_eq!(shares.len(), 3);

        // Recover with exactly 2 shares
        let subset: HashMap<Index, PrivateKey> =
            shares.iter().take(2).map(|(k, v)| (*k, *v)).collect();

        let recovered = blst.recover_secret(&subset).unwrap();
        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_threshold_split_invalid_threshold() {
        use rand::rngs::OsRng;

        let blst = setup();
        let sk = blst.generate_secret_key(OsRng).unwrap();

        // Threshold of 1 is invalid
        let result = blst.threshold_split(&sk, 5, 1);
        assert!(result.is_err(), "Threshold of 1 should be rejected");

        // Threshold greater than total is invalid
        let result = blst.threshold_split(&sk, 3, 5);
        assert!(result.is_err(), "Threshold > total should be rejected");
    }

    #[test]
    fn test_different_keys_produce_different_signatures() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"test message";

        let sk1 = blst.generate_secret_key(OsRng).unwrap();
        let sk2 = blst.generate_secret_key(OsRng).unwrap();

        let sig1 = blst.sign(&sk1, data).unwrap();
        let sig2 = blst.sign(&sk2, data).unwrap();

        assert_ne!(
            sig1, sig2,
            "Different keys should produce different signatures"
        );
    }

    #[test]
    fn test_same_key_produces_same_signature() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"test message";

        let sk = blst.generate_secret_key(OsRng).unwrap();

        let sig1 = blst.sign(&sk, data).unwrap();
        let sig2 = blst.sign(&sk, data).unwrap();

        assert_eq!(
            sig1, sig2,
            "Same key should produce same signature for same data"
        );
    }

    #[test]
    fn test_empty_aggregate_fails() {
        let blst = setup();

        let result = blst.aggregate(vec![]);
        assert!(
            result.is_err(),
            "Aggregating empty signature list should fail"
        );
    }

    #[test]
    fn test_public_key_is_deterministic() {
        use rand::rngs::OsRng;

        let blst = setup();
        let sk = blst.generate_secret_key(OsRng).unwrap();

        let pk1 = blst.secret_to_public_key(&sk).unwrap();
        let pk2 = blst.secret_to_public_key(&sk).unwrap();

        assert_eq!(pk1, pk2, "Public key derivation should be deterministic");
    }

    #[test]
    fn test_different_secrets_produce_different_public_keys() {
        use rand::rngs::OsRng;

        let blst = setup();

        let sk1 = blst.generate_secret_key(OsRng).unwrap();
        let sk2 = blst.generate_secret_key(OsRng).unwrap();

        let pk1 = blst.secret_to_public_key(&sk1).unwrap();
        let pk2 = blst.secret_to_public_key(&sk2).unwrap();

        assert_ne!(
            pk1, pk2,
            "Different secrets should produce different public keys"
        );
    }
}
