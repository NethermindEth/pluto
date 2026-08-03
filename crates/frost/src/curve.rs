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
        // Computed from: blst_scalar_from_uint64([1,0,0,0]) -> blst_fr_from_scalar
        // Pre-computed constant:
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
mod tests {
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
}
