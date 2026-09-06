//! Thin wrappers around [`blst`] types for the BLS12-381 scalar field and G1
//! curve group.
//!
//! Provides [`Scalar`], [`G1Projective`], and [`G1Affine`] with arithmetic
//! operator overloads, serialization, and safe constructors that enforce
//! subgroup membership.

use std::{
    fmt,
    ops::{Add, Mul, Sub},
};

use blst::*;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// BLS12-381 scalar field element. Wrapper around `blst_fr` in Montgomery form.
///
/// # Secret material & zeroization
///
/// `Scalar` is used to hold secret key material (DKG polynomial coefficients,
/// signing shares). It implements [`Zeroize`] but intentionally **retains
/// `Copy`** rather than deriving `Drop`/`ZeroizeOnDrop`:
///
/// - `Drop`/`ZeroizeOnDrop` are mutually exclusive with `Copy`, and `Scalar` is
///   consumed by value throughout this crate (the arithmetic operators take
///   `self`, `to_scalar()` returns by value). Removing `Copy` would ripple
///   across every call site for no real guarantee, because the inner `blst_fr`
///   is itself a `Copy` C struct — moves bit-copy it regardless.
/// - Secret-holding wrapper types ([`crate::SigningShare`],
///   [`crate::KeyPackage`], [`crate::kryptology::ShamirShare`]) derive
///   `ZeroizeOnDrop`, which wipes their inner `Scalar`/bytes via this `Zeroize`
///   impl on drop.
/// - Bare secret `Scalar` locals (the DKG nonce and reconstructed key in
///   `kryptology::round1`/`round2`) are wiped explicitly with
///   [`Zeroize::zeroize`].
///
/// Zeroization here is best-effort defense-in-depth, not an absolute guarantee.
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct Scalar(pub(crate) blst_fr);

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Scalar").field(&self.to_bytes()).finish()
    }
}

impl Scalar {
    /// Multiplicative identity.
    pub const ONE: Self = {
        // Montgomery form of 1 for BLS12-381 scalar field.
        // R mod r where R = 2^256 and r is the scalar field order.
        // Computed from: blst_scalar_from_uint64([1,0,0,0]) ->
        // blst_fr_from_scalar Pre-computed constant:
        Scalar(blst_fr {
            l: [
                0x0000_0001_ffff_fffe,
                0x5884_b7fa_0003_4802,
                0x998c_4fef_ecbc_4ff5,
                0x1824_b159_acc5_056f,
            ],
        })
    };
    /// Additive identity.
    pub const ZERO: Self = Scalar(blst_fr { l: [0; 4] });

    /// Serialize to 32 little-endian bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut scalar = blst_scalar::default();
        let mut out = [0u8; 32];
        unsafe {
            blst_scalar_from_fr(&mut scalar, &self.0);
            blst_lendian_from_scalar(out.as_mut_ptr(), &scalar);
        }
        out
    }

    /// Deserialize from 32 little-endian bytes. Returns `None` if invalid.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut scalar = blst_scalar::default();
        unsafe {
            blst_scalar_from_lendian(&mut scalar, bytes.as_ptr());
            if !blst_scalar_fr_check(&scalar) {
                return None;
            }
            let mut fr = blst_fr::default();
            blst_fr_from_scalar(&mut fr, &scalar);
            Some(Scalar(fr))
        }
    }

    /// Reduce 64 little-endian bytes modulo the scalar field order.
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
        let mut scalar = blst_scalar::default();
        let mut fr = blst_fr::default();
        unsafe {
            blst_scalar_from_le_bytes(&mut scalar, bytes.as_ptr(), 64);
            blst_fr_from_scalar(&mut fr, &scalar);
        }
        Scalar(fr)
    }

    /// Reduce big-endian bytes modulo the scalar field order.
    pub(crate) fn from_be_bytes_wide(bytes: &[u8]) -> Self {
        let mut scalar = blst_scalar::default();
        let mut fr = blst_fr::default();
        unsafe {
            blst_scalar_from_be_bytes(&mut scalar, bytes.as_ptr(), bytes.len());
            blst_fr_from_scalar(&mut fr, &scalar);
        }
        Scalar(fr)
    }

    /// Generate a uniformly random scalar.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        Self::from_bytes_wide(&wide)
    }

    /// Compute the multiplicative inverse. Returns `None` for zero.
    pub fn invert(&self) -> Option<Self> {
        if *self == Self::ZERO {
            return None;
        }
        let mut out = blst_fr::default();
        unsafe { blst_fr_eucl_inverse(&mut out, &self.0) };
        Some(Scalar(out))
    }

    /// Compare scalar limbs without early-exit equality.
    pub(crate) fn constant_time_eq(&self, other: &Self) -> bool {
        self.0.l.ct_eq(&other.0.l).into()
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.l.zeroize();
    }
}

impl From<u64> for Scalar {
    fn from(val: u64) -> Self {
        let mut fr = blst_fr::default();
        let limbs: [u64; 4] = [val, 0, 0, 0];
        unsafe { blst_fr_from_uint64(&mut fr, limbs.as_ptr()) };
        Scalar(fr)
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let mut out = blst_fr::default();
        unsafe { blst_fr_add(&mut out, &self.0, &rhs.0) };
        Scalar(out)
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        let mut out = blst_fr::default();
        unsafe { blst_fr_sub(&mut out, &self.0, &rhs.0) };
        Scalar(out)
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let mut out = blst_fr::default();
        unsafe { blst_fr_mul(&mut out, &self.0, &rhs.0) };
        Scalar(out)
    }
}

/// BLS12-381 G1 point in projective (Jacobian) coordinates. Wrapper around
/// `blst_p1`.
#[derive(Copy, Clone, Default, Eq)]
pub struct G1Projective(pub(crate) blst_p1);

impl PartialEq for G1Projective {
    fn eq(&self, other: &Self) -> bool {
        unsafe { blst_p1_is_equal(&self.0, &other.0) }
    }
}

impl fmt::Debug for G1Projective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("G1Projective")
            .field(&G1Affine::from(*self).to_compressed())
            .finish()
    }
}

impl G1Projective {
    /// The fixed generator of G1.
    pub fn generator() -> Self {
        unsafe { G1Projective(*blst_p1_generator()) }
    }

    /// The identity (point at infinity).
    pub fn identity() -> Self {
        Self::default()
    }

    /// Check whether this is the identity element.
    pub fn is_identity(&self) -> bool {
        unsafe { blst_p1_is_inf(&self.0) }
    }

    /// Deserialize from 48-byte compressed form.
    /// Returns `None` on invalid encoding or point not in G1, or the identity
    /// (point at infinity).
    pub fn from_compressed(bytes: &[u8; 48]) -> Option<Self> {
        let affine = G1Affine::from_compressed(bytes)?;
        if affine.is_identity() {
            return None;
        }
        Some(G1Projective::from(affine))
    }
}

impl Add for G1Projective {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let mut out = blst_p1::default();
        unsafe { blst_p1_add_or_double(&mut out, &self.0, &rhs.0) };
        G1Projective(out)
    }
}

impl Sub for G1Projective {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        let mut neg = rhs.0;
        let mut out = blst_p1::default();
        unsafe {
            blst_p1_cneg(&mut neg, true);
            blst_p1_add_or_double(&mut out, &self.0, &neg);
        }
        G1Projective(out)
    }
}

impl Mul<Scalar> for G1Projective {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self {
        let mut scalar = blst_scalar::default();
        let mut out = blst_p1::default();
        unsafe {
            blst_scalar_from_fr(&mut scalar, &rhs.0);
            // BLS12-381 scalar field order has 255 significant bits.
            blst_p1_mult(&mut out, &self.0, scalar.b.as_ptr(), 255);
        }
        G1Projective(out)
    }
}

/// BLS12-381 G1 point in affine coordinates (for serialization). Wrapper around
/// `blst_p1_affine`.
#[derive(Copy, Clone, Default)]
pub struct G1Affine(pub(crate) blst_p1_affine);

impl G1Affine {
    /// Serialize to 48-byte compressed form.
    pub fn to_compressed(&self) -> [u8; 48] {
        unsafe {
            let mut out = [0u8; 48];
            blst_p1_affine_compress(out.as_mut_ptr(), &self.0);
            out
        }
    }

    /// Deserialize from 48-byte compressed form.
    /// Returns `None` on invalid encoding or point not in G1.
    pub fn from_compressed(bytes: &[u8; 48]) -> Option<Self> {
        let mut affine = blst_p1_affine::default();
        unsafe {
            if blst_p1_uncompress(&mut affine, bytes.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                return None;
            }
            if !blst_p1_affine_in_g1(&affine) {
                return None;
            }
        }
        Some(G1Affine(affine))
    }

    /// Check whether this is the identity (point at infinity).
    pub fn is_identity(&self) -> bool {
        unsafe { blst_p1_affine_is_inf(&self.0) }
    }
}

impl From<G1Projective> for G1Affine {
    fn from(p: G1Projective) -> Self {
        let mut affine = blst_p1_affine::default();
        unsafe { blst_p1_to_affine(&mut affine, &p.0) };
        G1Affine(affine)
    }
}

impl From<&G1Projective> for G1Affine {
    fn from(p: &G1Projective) -> Self {
        G1Affine::from(*p)
    }
}

impl From<G1Affine> for G1Projective {
    fn from(a: G1Affine) -> Self {
        let mut p = blst_p1::default();
        unsafe { blst_p1_from_affine(&mut p, &a.0) };
        G1Projective(p)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn scalar_one_matches_blst_conversion() {
        assert_eq!(Scalar::ONE, Scalar::from(1u64));
    }

    #[test]
    fn scalar_round_trips_little_endian_bytes() {
        let scalar = Scalar::from(42);
        let bytes = scalar.to_bytes();

        assert_eq!(Scalar::from_bytes(&bytes), Some(scalar));
    }

    #[test]
    fn scalar_rejects_out_of_range_bytes() {
        assert_eq!(Scalar::from_bytes(&[0xff; 32]), None);
    }

    #[test]
    fn scalar_from_be_bytes_wide_matches_reversed_le_wide() {
        let be = [7u8; 48];
        let from_be = Scalar::from_be_bytes_wide(&be);

        let mut reversed = be;
        reversed.reverse();
        let mut wide = [0u8; 64];
        wide[..48].copy_from_slice(&reversed);

        assert_eq!(from_be, Scalar::from_bytes_wide(&wide));
    }

    #[test]
    fn scalar_constant_time_eq_matches_equality() {
        let a = Scalar::from(42);
        let b = Scalar::from(42);
        let c = Scalar::from(43);

        assert!(a.constant_time_eq(&b));
        assert!(!a.constant_time_eq(&c));
    }

    #[test]
    fn scalar_zeroize_clears_limbs() {
        let mut scalar = Scalar::from(42);

        scalar.zeroize();

        assert_eq!(scalar, Scalar::ZERO);
    }

    #[test]
    fn scalar_invert_returns_none_for_zero() {
        assert_eq!(Scalar::ZERO.invert(), None);
    }

    #[test]
    fn scalar_invert_returns_multiplicative_inverse() {
        let scalar = Scalar::from(42);
        let inverse = scalar.invert().expect("non-zero scalar should invert");

        assert_eq!(scalar * inverse, Scalar::ONE);
    }

    #[test]
    fn g1_projective_identity_reports_identity() {
        assert!(G1Projective::identity().is_identity());
        assert!(!G1Projective::generator().is_identity());
    }

    #[test]
    fn g1_projective_rejects_identity_compressed_point() {
        let identity = G1Affine::from(G1Projective::identity()).to_compressed();

        assert_eq!(G1Projective::from_compressed(&identity), None);
    }

    #[test]
    fn g1_affine_round_trips_generator_compressed_point() {
        let generator = G1Projective::generator();
        let compressed = G1Affine::from(generator).to_compressed();
        let affine = G1Affine::from_compressed(&compressed).expect("generator should deserialize");

        assert_eq!(G1Projective::from(affine), generator);
    }

    /// The BLS12-381 scalar-field order `r`, little-endian as `from_bytes`
    /// takes it. Written from the published curve parameter.
    const R_LE: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd,
        0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7,
        0xed, 0x73,
    ];

    /// `r - 1`, the largest representable scalar.
    const R_MINUS_1_LE: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd,
        0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7,
        0xed, 0x73,
    ];

    /// `(2^512 - 1) mod r`, computed independently of this crate.
    const MAX_WIDE_REDUCED_LE: [u8; 32] = [
        0x6c, 0x9c, 0xf2, 0xf3, 0x90, 0xe9, 0x99, 0xc9, 0x23, 0x5c, 0x92, 0x87, 0xcb, 0xed, 0x6c,
        0x2b, 0x8f, 0x39, 0x54, 0x72, 0x96, 0x14, 0xd3, 0x05, 0x11, 0xff, 0x59, 0x9f, 0xd9, 0xd9,
        0x48, 0x07,
    ];

    /// Compressed `x = 4`: a well-formed encoding of a point on the curve but
    /// outside the order-`r` subgroup. `0x80` is the compression flag with the
    /// sign bit clear. Shared with `frost_core`'s tests.
    pub(crate) const OFF_SUBGROUP_G1_POINT: [u8; 48] = {
        let mut bytes = [0u8; 48];
        bytes[0] = 0x80;
        bytes[47] = 4;
        bytes
    };

    /// Widen little-endian bytes to the 64 `from_bytes_wide` expects.
    fn widen(bytes: &[u8; 32]) -> [u8; 64] {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(bytes);
        wide
    }

    // Computed by hand rather than read off the operators. The existing tests
    // only assert relationships (`scalar * inverse == ONE`), which any
    // consistently wrong pair of operations also satisfies.
    #[test]
    fn scalar_arithmetic_matches_hand_computed_values() {
        assert_eq!(
            Scalar::from(7u64) + Scalar::from(11u64),
            Scalar::from(18u64)
        );
        assert_eq!(Scalar::from(11u64) - Scalar::from(7u64), Scalar::from(4u64));
        assert_eq!(
            Scalar::from(7u64) * Scalar::from(11u64),
            Scalar::from(77u64)
        );
    }

    // Wrap-around at the two ends of the field, where a missing reduction
    // produces something that is not a field element at all.
    #[test]
    fn scalar_arithmetic_wraps_at_field_edges() {
        let max = Scalar::from_bytes(&R_MINUS_1_LE).expect("r - 1 is in range");

        assert_eq!(
            max + Scalar::from(1u64),
            Scalar::ZERO,
            "(r - 1) + 1 must wrap to zero"
        );
        assert_eq!(
            Scalar::ZERO - Scalar::from(1u64),
            max,
            "0 - 1 must wrap to r - 1"
        );
    }

    // The two deserializers disagree on `r` by design: `from_bytes` is
    // range-checked and rejects it, `from_bytes_wide` reduces it. Each
    // assertion alone reads like an accident.
    #[test]
    fn scalar_from_bytes_rejects_field_order_but_wide_reduces_it() {
        assert_eq!(
            Scalar::from_bytes(&R_LE),
            None,
            "r is not a representable scalar"
        );
        assert_eq!(
            Scalar::from_bytes_wide(&widen(&R_LE)),
            Scalar::ZERO,
            "r must reduce to zero"
        );
    }

    // r + 5 ≡ 5. A reduction that subtracted the modulus the wrong number of
    // times still lands on *a* field element, so the value is stated.
    #[test]
    fn scalar_from_bytes_wide_reduces_modulo_field_order() {
        let mut r_plus_5 = widen(&R_LE);
        r_plus_5[0] = 0x06;

        assert_eq!(Scalar::from_bytes_wide(&r_plus_5), Scalar::from(5u64));
    }

    // The largest possible input. The round trip proves the result is a
    // canonical in-range scalar and not merely some 32 bytes.
    #[test]
    fn scalar_from_bytes_wide_reduces_largest_input() {
        let reduced = Scalar::from_bytes_wide(&[0xff; 64]);

        assert_eq!(reduced.to_bytes(), MAX_WIDE_REDUCED_LE, "(2^512 - 1) mod r");
        assert_eq!(
            Scalar::from_bytes(&MAX_WIDE_REDUCED_LE),
            Some(reduced),
            "the reduced value must pass the range check"
        );
    }

    /// Compressed `2G`, `3G` and `5G`, computed outside this crate by modular
    /// arithmetic over `y^2 = x^3 + 4 (mod p)`. Comparing `G + G` against
    /// `G * 2` would only show that `Add` and `Mul` agree with each other.
    const TWO_G: &str = "a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e";
    const THREE_G: &str = "89ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224";
    const FIVE_G: &str = "b0e7791fb972fe014159aa33a98622da3cdc98ff707965e536d8636b5fcc5ac7a91a8c46e59a00dca575af0f18fb13dc";

    fn compressed(point: G1Projective) -> String {
        hex::encode(G1Affine::from(point).to_compressed())
    }

    // `blst_p1_add_or_double` branches on whether its operands are equal, so
    // doubling is a distinct code path from ordinary addition.
    #[test]
    fn g1_arithmetic_matches_independently_computed_points() {
        let g = G1Projective::generator();

        assert_eq!(compressed(g + g), TWO_G, "doubling");
        assert_eq!(
            compressed(g * Scalar::from(3u64)),
            THREE_G,
            "scalar multiplication"
        );
        assert_eq!(
            compressed(g + g + g + g + g),
            FIVE_G,
            "repeated addition of unequal operands"
        );
        assert_eq!(
            compressed(g * Scalar::from(5u64) - g * Scalar::from(2u64)),
            THREE_G,
            "subtraction"
        );
    }

    // `G - G == identity` also covers `Sub`, which negates and re-adds rather
    // than calling blst directly.
    #[test]
    fn g1_group_laws_hold_for_identity() {
        let g = G1Projective::generator();
        let identity = G1Projective::identity();

        assert_eq!(g + identity, g, "the identity is neutral for addition");
        assert!(
            (g - g).is_identity(),
            "a point minus itself is the identity"
        );
        assert!(
            (g * Scalar::ZERO).is_identity(),
            "multiplying by zero gives the identity"
        );
        assert_eq!(g * Scalar::ONE, g, "multiplying by one is a no-op");
    }

    // The point is on the curve, so uncompression succeeds and only
    // `blst_p1_affine_in_g1` stands between it and acceptance. Both
    // constructors are checked because the projective one delegates.
    #[test]
    fn g1_from_compressed_rejects_off_subgroup_point() {
        assert!(
            G1Affine::from_compressed(&OFF_SUBGROUP_G1_POINT).is_none(),
            "an off-subgroup point must not deserialize"
        );
        assert_eq!(
            G1Projective::from_compressed(&OFF_SUBGROUP_G1_POINT),
            None,
            "the projective constructor must reject it too"
        );
    }

    // Both rejected before any curve arithmetic happens.
    #[test]
    fn g1_from_compressed_rejects_malformed_encodings() {
        // Compression flag clear: not a compressed point at all.
        assert!(G1Affine::from_compressed(&[0x00; 48]).is_none());

        // Compression flag set, but x is larger than the base field modulus.
        let mut x_out_of_range = [0xffu8; 48];
        x_out_of_range[0] = 0x9f;
        assert!(G1Affine::from_compressed(&x_out_of_range).is_none());
    }

    // The identity *is* a G1 element, so the affine constructor accepts it and
    // only the projective one rejects it. That asymmetry matters because
    // `from_commitments` goes through the projective constructor.
    #[test]
    fn g1_affine_accepts_identity_that_projective_rejects() {
        let identity = G1Affine::from(G1Projective::identity()).to_compressed();

        assert!(
            G1Affine::from_compressed(&identity).is_some_and(|affine| affine.is_identity()),
            "the affine constructor accepts the identity"
        );
        assert_eq!(G1Projective::from_compressed(&identity), None);
    }
}
