//! Scalar-field and curve-point arithmetic over the blst FFI.
//!
//! Every `unsafe` block in this crate lives here.
#![allow(unsafe_code)]

use std::collections::HashSet;

use blst::min_pk::{
    PublicKey as BlstPublicKey, SecretKey as BlstSecretKey, Signature as BlstSignature,
};

use crate::types::{Error, Index};

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
    if poly.is_empty() {
        return Err(Error::PolynomialIsEmpty);
    }

    // Start with the constant term
    let mut result = poly[0].clone();

    // Horner-free evaluation: `x_power` holds x^i entering iteration i.
    let x_scalar = scalar_from_u64(x);
    let mut x_power = x_scalar.clone();

    for coeff in poly.iter().skip(1) {
        // result += coeff * x_power
        let term = scalar_mult_secret(coeff, &x_power)?;
        result = scalar_add_secret(&result, &term)?;

        x_power = scalar_mult_scalars(&x_power, &x_scalar)?;
    }

    Ok(result)
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

    // Multiply each signature by its Lagrange coefficient and aggregate
    let first_sig_scaled = signature_mult(&signatures[0], &coeffs[0])?;
    let mut result_p2 = blst::blst_p2::default();

    unsafe {
        // Convert first scaled signature to projective
        let first_affine: &blst::blst_p2_affine = (&first_sig_scaled).into();
        blst::blst_p2_from_affine(&mut result_p2, first_affine);

        for i in 1..signatures.len() {
            let sig_scaled = signature_mult(&signatures[i], &coeffs[i])?;
            let sig_affine: &blst::blst_p2_affine = (&sig_scaled).into();
            blst::blst_p2_add_or_double_affine(&mut result_p2, &result_p2, sig_affine);
        }

        // Convert back to affine
        let mut result_affine = blst::blst_p2_affine::default();
        blst::blst_p2_to_affine(&mut result_affine, &result_p2);
        Ok(BlstSignature::from(result_affine))
    }
}

/// Compute Lagrange coefficients for interpolation at x=0
/// λ_i = ∏_{j≠i} (0 - x_j) / (x_i - x_j) = ∏_{j≠i} x_j / (x_j - x_i)
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
            let x_j_scalar = scalar_from_u64(x_j);
            numerator = scalar_mult_scalars(&numerator, &x_j_scalar)?;

            // denominator *= (x_j - x_i)
            let diff = if x_j > x_i {
                scalar_from_u64(x_j.abs_diff(x_i))
            } else {
                // For negative differences, we need to work in the scalar field
                // x_j - x_i (mod r) where r is the curve order
                scalar_negate(&scalar_from_u64(x_i.abs_diff(x_j)))?
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
    let limbs: [u64; 4] = [val, 0, 0, 0];
    unsafe {
        blst::blst_scalar_from_uint64(&mut scalar, limbs.as_ptr());
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
        blst::blst_p2_from_affine(&mut sig_proj, sig_affine);
        // Multiply
        blst::blst_p2_mult(&mut result_p2, &sig_proj, scalar.b.as_ptr(), 255);
        // Convert back to affine
        blst::blst_p2_to_affine(&mut result_affine, &result_p2);
    }

    Ok(BlstSignature::from(result_affine))
}

/// Add two scalars
fn scalar_add(a: &blst::blst_scalar, b: &blst::blst_scalar) -> Result<blst::blst_scalar, Error> {
    let mut result = blst::blst_scalar::default();
    unsafe {
        if blst::blst_sk_add_n_check(&mut result, a, b) {
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
        if blst::blst_sk_mul_n_check(&mut result, a, b) {
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

        blst::blst_fr_from_scalar(&mut a_fr, a);
        blst::blst_fr_from_scalar(&mut zero_fr, &zero);

        let mut result_fr = blst::blst_fr::default();
        blst::blst_fr_sub(&mut result_fr, &zero_fr, &a_fr);

        blst::blst_scalar_from_fr(&mut result_scalar, &result_fr);
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
        return Err(Error::DivisionByZero);
    }

    let mut inv_scalar = blst::blst_scalar::default();

    unsafe {
        blst::blst_sk_inverse(&mut inv_scalar, denominator);
    }

    scalar_mult_scalars(numerator, &inv_scalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_from_u64_upper_limbs_are_zero() {
        // blst_scalar_from_uint64 reads 4 consecutive u64s (4 × 8 = 32 bytes);
        // passing &val instead of &[val, 0, 0, 0] reads 3 extra u64s from the
        // stack. The scalar is stored little-endian: the value occupies the first
        // u64 (bytes 0–7) and the remaining three limbs (bytes 8–31) must be zero.
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
