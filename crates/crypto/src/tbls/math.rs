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
    use test_case::test_case;

    use super::{super::ETH2_DST, *};

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

    /// The BLS12-381 scalar-field order minus 19, big-endian. Written from the
    /// published curve order, not read off this implementation.
    const R_MINUS_19: [u8; 32] = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff,
        0xff, 0xee,
    ];

    /// A secret key holding the non-zero field element `v`.
    fn sk(v: u64) -> BlstSecretKey {
        let scalar = scalar_from_u64(v);
        let sk: &BlstSecretKey = (&scalar)
            .try_into()
            .expect("a small non-zero value is a valid BLS scalar");
        sk.clone()
    }

    /// The big-endian encoding of a small field element.
    fn be_bytes(v: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&v.to_be_bytes());
        out
    }

    /// f(x) = 7 + 11x + 13x², so f(0) = 7 is the secret.
    fn poly_7_11_13() -> Vec<BlstSecretKey> {
        vec![sk(7), sk(11), sk(13)]
    }

    fn shares_at(indices: &[Index]) -> Vec<BlstSecretKey> {
        indices
            .iter()
            .map(|&i| evaluate_polynomial(&poly_7_11_13(), i).expect("the polynomial is not empty"))
            .collect()
    }

    #[test]
    fn evaluate_polynomial_rejects_empty_polynomial() {
        assert!(matches!(
            evaluate_polynomial(&[], 1),
            Err(Error::PolynomialIsEmpty)
        ));
    }

    // Evaluated by hand, so the expectations do not come from the code under
    // test: 7+11+13 = 31, 7+22+52 = 81, 7+55+325 = 387.
    #[test_case(1, 31 ; "x = 1 sums the coefficients")]
    #[test_case(2, 81 ; "x = 2")]
    #[test_case(5, 387 ; "x = 5, where the squared term dominates")]
    fn evaluate_polynomial_matches_hand_computed_values(x: Index, expected: u64) {
        let value = evaluate_polynomial(&poly_7_11_13(), x).unwrap();

        assert_eq!(
            value.to_bytes(),
            be_bytes(expected),
            "f({x}) should be {expected}"
        );
    }

    // The `skip(1)` loop never runs, so x must not reach the result.
    #[test]
    fn evaluate_polynomial_degree_zero_ignores_x() {
        let poly = vec![sk(7)];

        for x in [1u64, 2, 1_000] {
            assert_eq!(
                evaluate_polynomial(&poly, x).unwrap().to_bytes(),
                be_bytes(7),
                "a constant polynomial must evaluate to 7 at x = {x}"
            );
        }
    }

    // The descending set is the row that matters:
    // `compute_lagrange_coefficients` negates in the scalar field when
    // x_j < x_i instead of subtracting in the integers.
    #[test_case(&[1, 2, 3] ; "contiguous ascending")]
    #[test_case(&[2, 4, 5] ; "non-contiguous")]
    #[test_case(&[5, 4, 2] ; "descending, driving the scalar_negate branch")]
    fn lagrange_interpolate_secret_recovers_constant_term(indices: &[Index]) {
        let recovered = lagrange_interpolate_secret(indices, &shares_at(indices)).unwrap();

        assert_eq!(
            recovered.to_bytes(),
            be_bytes(7),
            "f(0) = 7 must be recovered from {indices:?}"
        );
    }

    // The negative property: too few shares do not fail, they silently
    // interpolate a different field element. The line through f(1) and f(2)
    // gives 2·f(1) − f(2) = 62 − 81 = −19, i.e. exactly r − 19.
    #[test]
    fn lagrange_interpolate_secret_below_threshold_yields_wrong_scalar() {
        let recovered = lagrange_interpolate_secret(&[1, 2], &shares_at(&[1, 2]))
            .expect("sub-threshold interpolation succeeds — that is the hazard");

        assert_ne!(
            recovered.to_bytes(),
            be_bytes(7),
            "two shares must not recover a 3-of-n secret"
        );
        assert_eq!(
            recovered.to_bytes(),
            R_MINUS_19,
            "sub-threshold recovery yields 2·f(1) − f(2) = −19 mod r"
        );
    }

    #[test]
    fn lagrange_interpolate_secret_rejects_duplicate_indices() {
        let indices = [1, 2, 2];

        assert!(matches!(
            lagrange_interpolate_secret(&indices, &shares_at(&indices)),
            Err(Error::IndicesNotUnique)
        ));
    }

    // Not `SharesAreEmpty`: that comes from `tbls::recover_secret`, which
    // guards the empty map before this layer. Different guards, different
    // errors.
    #[test_case(&[], &[] ; "empty")]
    #[test_case(&[1, 2, 3], &[1, 2] ; "more indices than shares")]
    fn lagrange_interpolate_secret_rejects_length_mismatch(
        indices: &[Index],
        share_points: &[Index],
    ) {
        let result = lagrange_interpolate_secret(indices, &shares_at(share_points));

        assert!(
            matches!(result, Err(Error::IndicesSharesMismatch)),
            "expected IndicesSharesMismatch, got {:?}",
            result.map(|_| "Ok")
        );
    }

    // BLS signing is deterministic, so the interpolated signature must be
    // byte-identical to the one the recovered secret produces. Descending
    // indices again, for the negated-denominator branch.
    #[test]
    fn lagrange_interpolate_signature_recovers_group_signature() {
        const MSG: &[u8] = b"lagrange interpolate signature";

        let indices: [Index; 3] = [5, 4, 2];
        let partials: Vec<BlstSignature> = shares_at(&indices)
            .iter()
            .map(|share| share.sign(MSG, ETH2_DST, &[]))
            .collect();

        let interpolated = lagrange_interpolate_signature(&indices, &partials).unwrap();

        assert_eq!(
            interpolated.to_bytes(),
            sk(7).sign(MSG, ETH2_DST, &[]).to_bytes(),
            "the interpolated signature must equal the group signature"
        );
    }

    // Same shape of guard as the secret path, but a *different* variant:
    // `EmptySignatureArray`, not `IndicesSharesMismatch`.
    #[test_case(&[], &[] ; "empty")]
    #[test_case(&[1, 2, 3], &[1, 2] ; "more indices than signatures")]
    fn lagrange_interpolate_signature_rejects_length_mismatch(
        indices: &[Index],
        sig_points: &[Index],
    ) {
        let partials: Vec<BlstSignature> = shares_at(sig_points)
            .iter()
            .map(|share| share.sign(b"mismatch", ETH2_DST, &[]))
            .collect();

        let result = lagrange_interpolate_signature(indices, &partials);

        assert!(
            matches!(result, Err(Error::EmptySignatureArray)),
            "expected EmptySignatureArray, got {:?}",
            result.map(|_| "Ok")
        );
    }

    // pk(7) + pk(11) = pk(18). A fold that dropped or double-counted a term
    // would still return a well-formed point.
    #[test]
    fn aggregate_public_keys_is_additively_homomorphic() {
        let agg = aggregate_public_keys(&[sk(7).sk_to_pk(), sk(11).sk_to_pk()]).unwrap();

        assert_eq!(
            agg.to_bytes(),
            sk(18).sk_to_pk().to_bytes(),
            "pk(7) + pk(11) must equal pk(18)"
        );
    }

    // n = 1 is the `skip(1)` boundary: the loop body never runs, so an
    // off-by-one in the accumulator shows up only here.
    #[test]
    fn aggregate_public_keys_of_single_key_is_that_key() {
        let agg = aggregate_public_keys(&[sk(7).sk_to_pk()]).unwrap();

        assert_eq!(agg.to_bytes(), sk(7).sk_to_pk().to_bytes());
    }

    #[test]
    fn scalar_div_rejects_zero_denominator() {
        assert!(matches!(
            scalar_div(&scalar_from_u64(42), &scalar_from_u64(0)),
            Err(Error::DivisionByZero)
        ));
    }

    #[test]
    fn scalar_div_multiplies_by_modular_inverse() {
        let quotient = scalar_div(&scalar_from_u64(42), &scalar_from_u64(6)).unwrap();

        assert_eq!(
            quotient.b,
            scalar_from_u64(7).b,
            "42 / 6 = 7 in the scalar field"
        );
    }

    // Negating zero, −19 == r − 19, and involution.
    #[test]
    fn scalar_negate_computes_additive_inverse() {
        assert_eq!(
            scalar_negate(&scalar_from_u64(0)).unwrap().b,
            scalar_from_u64(0).b,
            "the additive inverse of zero is zero"
        );

        let negative_19 = scalar_negate(&scalar_from_u64(19)).unwrap();

        // `blst_scalar` is little-endian; `R_MINUS_19` is written big-endian.
        let mut expected = R_MINUS_19;
        expected.reverse();
        assert_eq!(negative_19.b, expected, "−19 must be r − 19");

        assert_eq!(
            scalar_negate(&negative_19).unwrap().b,
            scalar_from_u64(19).b,
            "negation must be an involution"
        );
    }
}
