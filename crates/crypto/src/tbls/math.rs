//! Scalar-field and curve-point arithmetic over the blst FFI.
//!
//! Every `unsafe` block in this crate lives here.
#![allow(unsafe_code)]

use std::collections::HashSet;

use blst::{
    MultiPoint,
    min_pk::{PublicKey as BlstPublicKey, SecretKey as BlstSecretKey, Signature as BlstSignature},
};
use zeroize::Zeroize;

use crate::types::{Error, Index, SCALAR_LENGTH};

/// Bit width of BLS12-381 scalars as consumed by blst multi-scalar
/// multiplication.
const SCALAR_BITS: usize = 255;

/// Aggregate public keys
pub(super) fn aggregate_public_keys(pks: &[BlstPublicKey]) -> Result<BlstPublicKey, Error> {
    if pks.is_empty() {
        return Err(Error::EmptyPublicKeyArray);
    }

    let mut agg = blst::blst_p1::default();

    unsafe {
        // Convert first key to projective form
        let first_affine: &blst::blst_p1_affine = (&pks[0]).into();
        blst::blst_p1_from_affine(&mut agg, first_affine);

        for pk in pks.iter().skip(1) {
            let pk_affine: &blst::blst_p1_affine = pk.into();
            blst::blst_p1_add_or_double_affine(&mut agg, &agg, pk_affine);
        }

        // Convert back to affine
        let mut agg_affine = blst::blst_p1_affine::default();
        blst::blst_p1_to_affine(&mut agg_affine, &agg);
        Ok(BlstPublicKey::from(agg_affine))
    }
}

/// Evaluate polynomial at point x
/// poly(x) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n
pub(super) fn evaluate_polynomial(
    poly: &[BlstSecretKey],
    x: Index,
) -> Result<BlstSecretKey, Error> {
    // The fr-domain copy of the secret coefficients is wiped on drop; the
    // evaluation result is wiped explicitly once converted back to a key.
    let poly_fr = SecretFrVec::from_secrets(poly);
    let mut acc = evaluate_polynomial_fr(&poly_fr.0, x)?;
    let result = secret_from_fr(&acc);
    wipe_fr(std::slice::from_mut(&mut acc));
    result
}

/// Evaluate polynomial at point x using Horner's method in the fr domain:
/// poly(x) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n
fn evaluate_polynomial_fr(poly: &[blst::blst_fr], x: Index) -> Result<blst::blst_fr, Error> {
    let Some(highest) = poly.last() else {
        return Err(Error::PolynomialIsEmpty);
    };

    let x_fr = fr_from_scalar(&scalar_from_u64(x));
    let mut acc = *highest;

    unsafe {
        for coeff in poly.iter().rev().skip(1) {
            blst::blst_fr_mul(&mut acc, &acc, &x_fr);
            blst::blst_fr_add(&mut acc, &acc, coeff);
        }
    }

    Ok(acc)
}

/// Lagrange interpolation of secret keys at x=0
/// Recovers f(0) from points (x_i, y_i) where y_i are secret keys
pub(super) fn lagrange_interpolate_secret(
    indices: &[Index],
    shares: &[BlstSecretKey],
) -> Result<BlstSecretKey, Error> {
    if indices.len() != shares.len() || indices.is_empty() {
        return Err(Error::IndicesSharesMismatch);
    }

    let coeffs = compute_lagrange_coefficients(indices)?;

    // The fr-domain copies of the shares and the accumulator hold secret
    // material; both are wiped before returning.
    let shares_fr = SecretFrVec::from_secrets(shares);
    let mut acc = blst::blst_fr::default();

    unsafe {
        for (share, coeff) in shares_fr.0.iter().zip(&coeffs) {
            // `term = share_i·λ_i` is recoverable secret material and `blst_fr`
            // is `Copy` with no zeroizing `Drop`, so wipe it each iteration.
            let mut term = blst::blst_fr::default();
            blst::blst_fr_mul(&mut term, share, coeff);
            blst::blst_fr_add(&mut acc, &acc, &term);
            wipe_fr(std::slice::from_mut(&mut term));
        }
    }

    let result = secret_from_fr(&acc);
    wipe_fr(std::slice::from_mut(&mut acc));

    result
}

/// Lagrange interpolation of signatures at x=0
/// Recovers f(0) from points (x_i, σ_i) where σ_i are signatures
pub(super) fn lagrange_interpolate_signature(
    indices: &[Index],
    signatures: &[BlstSignature],
) -> Result<BlstSignature, Error> {
    if indices.len() != signatures.len() || indices.is_empty() {
        return Err(Error::EmptySignatureArray);
    }

    // Compute Lagrange coefficients
    let coeffs = compute_lagrange_coefficients(indices)?;

    let mut scalar_bytes = Vec::with_capacity(SCALAR_LENGTH.saturating_mul(coeffs.len()));
    for coeff in &coeffs {
        scalar_bytes.extend_from_slice(&scalar_from_fr(coeff).b);
    }

    // Multi-scalar multiplication (Pippenger) of all signatures by their
    // Lagrange coefficients in one pass, with a single final affine
    // conversion (each affine conversion costs a field inversion). `blst`'s
    // `MultiPoint for [Signature]` transmutes to the affine slice and runs the
    // same MSM, so this matches the hand-rolled version without the manual
    // affine extraction and conversion.
    Ok(signatures.mult(&scalar_bytes, SCALAR_BITS).to_signature())
}

/// Compute Lagrange coefficients for interpolation at x=0, in the fr domain:
/// λ_i = ∏_{j≠i} (0 - x_j) / (x_i - x_j) = ∏_{j≠i} x_j / (x_j - x_i)
fn compute_lagrange_coefficients(indices: &[Index]) -> Result<Vec<blst::blst_fr>, Error> {
    // Check if indices are unique
    if indices.len() != indices.iter().collect::<HashSet<_>>().len() {
        return Err(Error::IndicesNotUnique);
    }

    let indices_fr: Vec<blst::blst_fr> = indices
        .iter()
        .map(|&x| fr_from_scalar(&scalar_from_u64(x)))
        .collect();
    let one = fr_from_scalar(&scalar_from_u64(1));

    let mut coeffs = Vec::with_capacity(indices.len());

    unsafe {
        for (i, x_i) in indices_fr.iter().enumerate() {
            let mut numerator = one;
            let mut denominator = one;

            for (j, x_j) in indices_fr.iter().enumerate() {
                if i == j {
                    continue;
                }

                // numerator *= x_j
                blst::blst_fr_mul(&mut numerator, &numerator, x_j);

                // denominator *= (x_j - x_i), computed modulo the field order.
                let mut diff = blst::blst_fr::default();
                blst::blst_fr_sub(&mut diff, x_j, x_i);
                blst::blst_fr_mul(&mut denominator, &denominator, &diff);
            }

            // `blst_fr_eucl_inverse` below is variable-time, which is fine
            // here: it only ever operates on public share indices.
            // Unreachable with unique indices, but guard division regardless.
            if scalar_from_fr(&denominator) == blst::blst_scalar::default() {
                return Err(Error::DivisionByZero);
            }

            // coeff = numerator / denominator
            let mut inverse = blst::blst_fr::default();
            blst::blst_fr_eucl_inverse(&mut inverse, &denominator);

            let mut coeff = blst::blst_fr::default();
            blst::blst_fr_mul(&mut coeff, &numerator, &inverse);
            coeffs.push(coeff);
        }
    }

    Ok(coeffs)
}

/// Converts a scalar to the fr (Montgomery) domain.
fn fr_from_scalar(scalar: &blst::blst_scalar) -> blst::blst_fr {
    let mut fr = blst::blst_fr::default();
    unsafe { blst::blst_fr_from_scalar(&mut fr, scalar) };
    fr
}

/// Converts an fr (Montgomery) value back to a scalar.
fn scalar_from_fr(fr: &blst::blst_fr) -> blst::blst_scalar {
    let mut scalar = blst::blst_scalar::default();
    unsafe { blst::blst_scalar_from_fr(&mut scalar, fr) };
    scalar
}

/// Converts an fr value to a secret key, validating it (nonzero, below the
/// group order) exactly like the previous scalar-domain conversion did.
fn secret_from_fr(fr: &blst::blst_fr) -> Result<BlstSecretKey, Error> {
    let mut scalar = scalar_from_fr(fr);
    let result = <&BlstSecretKey>::try_from(&scalar)
        .cloned()
        .map_err(|_| Error::FailedToConvertScalarToSecretKey);
    scalar.zeroize();
    result
}

/// Best-effort volatile wipe of fr values holding secret material.
fn wipe_fr(values: &mut [blst::blst_fr]) {
    for value in values.iter_mut() {
        // SAFETY: `value` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(value, blst::blst_fr::default()) };
    }
}

/// Fr-domain copies of secret keys, wiped on drop.
struct SecretFrVec(Vec<blst::blst_fr>);

impl SecretFrVec {
    fn from_secrets(secrets: &[BlstSecretKey]) -> Self {
        Self(
            secrets
                .iter()
                .map(|sk| {
                    let scalar: &blst::blst_scalar = sk.into();
                    fr_from_scalar(scalar)
                })
                .collect(),
        )
    }
}

impl Drop for SecretFrVec {
    fn drop(&mut self) {
        wipe_fr(&mut self.0);
    }
}

/// Convert u64 to blst scalar
fn scalar_from_u64(val: u64) -> blst::blst_scalar {
    let mut scalar = blst::blst_scalar::default();
    let limbs: [u64; 4] = [val, 0, 0, 0];
    unsafe {
        blst::blst_scalar_from_uint64(&mut scalar, limbs.as_ptr());
    }
    scalar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_from_u64_upper_limbs_are_zero() {
        // blst_scalar_from_uint64 reads 4 consecutive u64s (4 × 8 = 32 bytes);
        // passing &val instead of &[val, 0, 0, 0] reads 3 extra u64s from the
        // stack. The scalar is stored little-endian: the value occupies the
        // first u64 (bytes 0–7) and the remaining three limbs (bytes
        // 8–31) must be zero.
        for val in [0u64, 1, 2, 3, 4, 255, u64::from(u32::MAX)] {
            let scalar = scalar_from_u64(val);
            let expected = val.to_le_bytes();
            assert_eq!(
                &scalar.b[..8],
                &expected,
                "lower 8 bytes should encode {val}"
            );
            assert!(
                scalar.b[8..].iter().all(|&b| b == 0),
                "upper 24 bytes must be zero for val={val}"
            );
        }
    }
}
