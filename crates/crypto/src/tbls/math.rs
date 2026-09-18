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
    // `compute_lagrange_coefficients` subtracts modulo the field order, so
    // x_j < x_i wraps rather than underflowing.
    #[test_case(&[1, 2, 3] ; "contiguous ascending")]
    #[test_case(&[2, 4, 5] ; "non-contiguous")]
    #[test_case(&[5, 4, 2] ; "descending, driving the negative-difference branch")]
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
            "expected IndicesSharesMismatch"
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
            "expected EmptySignatureArray"
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

    /// The BLS12-381 scalar-field order minus 3, big-endian. Written from the
    /// published curve order, not read off this implementation.
    const R_MINUS_3: [u8; 32] = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff,
        0xff, 0xfe,
    ];

    /// The big-endian bytes of an fr value.
    fn fr_be_bytes(fr: &blst::blst_fr) -> [u8; 32] {
        let mut bytes = scalar_from_fr(fr).b;
        // `blst_scalar` is little-endian; the expectations are big-endian.
        bytes.reverse();
        bytes
    }

    // The coefficients themselves, by hand, so the two arithmetic steps the
    // fr domain took over from the old `scalar_negate`/`scalar_div` helpers
    // are pinned directly: λ₁ = (2/1)·(3/2) = 3, λ₂ = (1/−1)·(3/1) = −3,
    // λ₃ = (1/−2)·(2/−1) = 1. The negative denominators exercise the
    // subtraction modulo r, and the halves exercise the modular inverse.
    #[test]
    fn compute_lagrange_coefficients_matches_hand_computed_values() {
        let coeffs = compute_lagrange_coefficients(&[1, 2, 3]).unwrap();

        assert_eq!(coeffs.len(), 3);
        assert_eq!(fr_be_bytes(&coeffs[0]), be_bytes(3), "λ₁ = 3");
        assert_eq!(fr_be_bytes(&coeffs[1]), R_MINUS_3, "λ₂ = −3 = r − 3");
        assert_eq!(fr_be_bytes(&coeffs[2]), be_bytes(1), "λ₃ = 1");
    }

    #[test]
    fn compute_lagrange_coefficients_rejects_duplicate_indices() {
        assert!(matches!(
            compute_lagrange_coefficients(&[1, 2, 2]),
            Err(Error::IndicesNotUnique)
        ));
    }
}
