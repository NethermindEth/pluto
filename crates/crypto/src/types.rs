//! # pluto-crypto types
//!
//! The BLS key and signature types, together with the conversions between them,
//! their raw byte encodings, and their eth2 counterparts.
//!
//! Conversions for core types are intentionally excluded here to avoid a
//! `core -> eth2util -> crypto -> core` crate dependency cycle.

use blst::BLST_ERROR;
use pluto_eth2api::spec::phase0;

/// Public key length
pub const PUBLIC_KEY_LENGTH: usize = 48;
/// Private key length
pub const PRIVATE_KEY_LENGTH: usize = 32;
/// Signature length (BLS12-381 G2 compressed)
pub const SIGNATURE_LENGTH: usize = 96;
/// BLS12-381 G1 compressed point length.
pub const G1_COMPRESSED_LENGTH: usize = 48;
/// BLS12-381 scalar length.
pub const SCALAR_LENGTH: usize = 32;

/// Public key type
pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];
/// Private key type
pub type PrivateKey = [u8; PRIVATE_KEY_LENGTH];
/// Signature type (BLS12-381 G2 compressed)
pub type Signature = [u8; SIGNATURE_LENGTH];
/// Index type & total shares / threshold
pub type Index = u64;

/// Converts a [`Signature`] into an eth2 phase0 [`phase0::BLSSignature`].
pub fn sig_to_eth2(sig: Signature) -> phase0::BLSSignature {
    sig
}

/// Converts a [`PublicKey`] into an eth2 phase0 [`phase0::BLSPubKey`].
pub fn pubkey_to_eth2(pk: PublicKey) -> phase0::BLSPubKey {
    pk
}

/// Returns a [`PrivateKey`] from the given byte slice.
///
/// Returns an error if the data isn't exactly [`PRIVATE_KEY_LENGTH`] bytes.
pub fn privkey_from_bytes(data: &[u8]) -> Result<PrivateKey, ConvError> {
    let key: [u8; PRIVATE_KEY_LENGTH] = data.try_into().map_err(|_| ConvError::InvalidLength {
        expected: PRIVATE_KEY_LENGTH,
        got: data.len(),
    })?;
    Ok(key)
}

/// Returns a [`PublicKey`] from the given byte slice.
///
/// Returns an error if the data isn't exactly [`PUBLIC_KEY_LENGTH`] bytes.
pub fn pubkey_from_bytes(data: &[u8]) -> Result<PublicKey, ConvError> {
    let key: [u8; PUBLIC_KEY_LENGTH] = data.try_into().map_err(|_| ConvError::InvalidLength {
        expected: PUBLIC_KEY_LENGTH,
        got: data.len(),
    })?;
    Ok(key)
}

/// Returns a [`Signature`] from the given byte slice.
///
/// Returns an error if the data isn't exactly [`SIGNATURE_LENGTH`] bytes.
pub fn signature_from_bytes(data: &[u8]) -> Result<Signature, ConvError> {
    let sig: [u8; SIGNATURE_LENGTH] = data.try_into().map_err(|_| ConvError::InvalidLength {
        expected: SIGNATURE_LENGTH,
        got: data.len(),
    })?;
    Ok(sig)
}

/// Error type for charon-crypto operations.
///
/// This enum represents all possible errors that can occur during cryptographic
/// operations in the charon-crypto library, including key management, signature
/// operations, and threshold cryptography.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to deserialize a secret key from bytes.
    ///
    /// This error occurs when the provided bytes don't represent a valid
    /// BLS secret key (e.g., out of valid scalar field range).
    #[error("Failed to deserialize secret key: {0}")]
    InvalidSecretKey(#[from] BlsError),

    /// BLST error.
    #[error("BLST error: {0}")]
    BlsError(BlsError),

    /// Failed to deserialize a public key from bytes.
    #[error("Failed to deserialize public key: {0}")]
    InvalidPublicKey(BlsError),

    /// Failed to deserialize a signature from bytes.
    #[error("Failed to deserialize signature: {0}")]
    InvalidSignature(BlsError),

    /// The threshold value provided for threshold cryptography is invalid.
    ///
    /// In threshold cryptography, the threshold must be at least 2 and at most
    /// equal to the total number of shares.
    #[error(
        "Invalid threshold. Must be >= 2 and <= total. Got threshold={threshold}, total={total}"
    )]
    InvalidThreshold {
        /// The threshold value provided.
        threshold: Index,
        /// The total number of shares.
        total: Index,
    },

    /// The threshold value does not fit into the platform `usize`.
    ///
    /// `Index` is a `u64`; on 32-bit targets a sufficiently large threshold
    /// cannot be used as a `Vec` capacity. This is a platform/overflow
    /// condition, distinct from a caller-supplied out-of-range threshold
    /// (`InvalidThreshold`).
    #[error("Threshold {threshold} does not fit into usize on this platform")]
    ThresholdOverflow {
        /// The threshold value that failed to convert.
        threshold: Index,
    },

    /// Failed to verify a BLS signature.
    ///
    /// This error occurs when signature verification fails, indicating either
    /// an invalid signature or a mismatch between the signature, message, and
    /// public key.
    #[error("Signature verification failed: {0}")]
    VerificationFailed(BlsError),

    /// Failed to aggregate signatures.
    ///
    /// This error can occur during the signature aggregation process.
    #[error("Signature aggregation failed: {0}")]
    AggregationFailed(BlsError),

    /// The signature array is empty.
    ///
    /// This error occurs when the provided signature array is empty.
    #[error("Signature array is empty")]
    EmptySignatureArray,

    /// Division by zero.
    #[error("Division by zero")]
    DivisionByZero,

    /// Failed to convert secret key to blst scalar.
    #[error("Failed to convert secret key to blst scalar")]
    FailedToConvertSkToBlstScalar,

    /// Failed to add scalars.
    #[error("Failed to add scalars")]
    FailedToAddScalars,

    /// Failed to multiply scalars.
    #[error("Failed to multiply scalars")]
    FailedToMultiplyScalars,

    /// Indices are not unique.
    #[error("Indices are not unique")]
    IndicesNotUnique,

    /// Shares are empty.
    #[error("Shares are empty")]
    SharesAreEmpty,

    /// Failed to convert scalar to secret key.
    #[error("Failed to convert scalar to secret key")]
    FailedToConvertScalarToSecretKey,

    /// Indices and shares mismatch.
    #[error("Indices and shares mismatch")]
    IndicesSharesMismatch,

    /// Polynomial is empty.
    #[error("Polynomial is empty")]
    PolynomialIsEmpty,

    /// Public key array is empty.
    #[error("Public key array is empty")]
    EmptyPublicKeyArray,
}

/// BLST-specific error wrapper.
///
/// Wraps BLST_ERROR enum to provide idiomatic Rust error handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlsError {
    /// Generic BLS error during key generation.
    #[error("Key generation failed")]
    KeyGeneration,

    /// Invalid encoding or compression.
    #[error("Bad encoding")]
    BadEncoding,

    /// Point not in correct subgroup.
    #[error("Point not in group")]
    PointNotInGroup,

    /// Point not on curve.
    #[error("Point not on curve")]
    PointNotOnCurve,

    /// Aggregate verification failed.
    #[error("Aggregate mismatch")]
    AggregateMismatch,

    /// Generic verification failure.
    #[error("Verification failed")]
    VerifyFailed,

    /// Invalid public key.
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid secret key.
    #[error("Invalid secret key")]
    InvalidSecretKey,

    /// Invalid signature.
    #[error("Invalid signature")]
    InvalidSignature,

    /// Invalid scalar.
    #[error("Invalid scalar")]
    InvalidScalar,

    /// Unknown BLST error.
    #[error("Unknown error")]
    Unknown,
}

/// Conversion error.
#[derive(Debug, thiserror::Error)]
pub enum ConvError {
    /// Data is not of the expected length.
    #[error("data is not of the correct length: expected {expected}, got {got}")]
    InvalidLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
}

impl From<BLST_ERROR> for BlsError {
    fn from(err: BLST_ERROR) -> Self {
        match err {
            BLST_ERROR::BLST_BAD_ENCODING => Self::BadEncoding,
            BLST_ERROR::BLST_POINT_NOT_ON_CURVE => Self::PointNotOnCurve,
            BLST_ERROR::BLST_POINT_NOT_IN_GROUP => Self::PointNotInGroup,
            BLST_ERROR::BLST_AGGR_TYPE_MISMATCH => Self::AggregateMismatch,
            BLST_ERROR::BLST_VERIFY_FAIL => Self::VerifyFailed,
            BLST_ERROR::BLST_PK_IS_INFINITY => Self::InvalidPublicKey,
            BLST_ERROR::BLST_BAD_SCALAR => Self::InvalidScalar,
            _ => Self::Unknown,
        }
    }
}

impl From<BLST_ERROR> for Error {
    fn from(err: BLST_ERROR) -> Self {
        Error::BlsError(BlsError::from(err))
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test_case(&[], PRIVATE_KEY_LENGTH, 0 ; "empty input")]
    #[test_case(&[42u8; PRIVATE_KEY_LENGTH + 1], PRIVATE_KEY_LENGTH, PRIVATE_KEY_LENGTH + 1 ; "more data than expected")]
    #[test_case(&[42u8; PRIVATE_KEY_LENGTH - 1], PRIVATE_KEY_LENGTH, PRIVATE_KEY_LENGTH - 1 ; "less data than expected")]
    fn privkey_from_bytes_invalid(data: &[u8], expected: usize, got: usize) {
        assert!(matches!(
            privkey_from_bytes(data),
            Err(ConvError::InvalidLength { expected: e, got: g }) if e == expected && g == got
        ));
    }

    #[test]
    fn privkey_from_bytes_valid() {
        let data = vec![42u8; PRIVATE_KEY_LENGTH];
        let key = privkey_from_bytes(&data).unwrap();
        assert_eq!(key, [42u8; PRIVATE_KEY_LENGTH]);
    }

    #[test_case(&[], PUBLIC_KEY_LENGTH, 0 ; "empty input")]
    #[test_case(&[42u8; PUBLIC_KEY_LENGTH + 1], PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH + 1 ; "more data than expected")]
    #[test_case(&[42u8; PUBLIC_KEY_LENGTH - 1], PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH - 1 ; "less data than expected")]
    fn pubkey_from_bytes_invalid(data: &[u8], expected: usize, got: usize) {
        assert!(matches!(
            pubkey_from_bytes(data),
            Err(ConvError::InvalidLength { expected: e, got: g }) if e == expected && g == got
        ));
    }

    #[test]
    fn pubkey_from_bytes_valid() {
        let data = vec![42u8; PUBLIC_KEY_LENGTH];
        let key = pubkey_from_bytes(&data).expect("should succeed");
        assert_eq!(key, [42u8; PUBLIC_KEY_LENGTH]);
    }

    #[test]
    fn pubkey_to_eth2_roundtrip() {
        let data = vec![42u8; PUBLIC_KEY_LENGTH];
        let pubkey = pubkey_from_bytes(&data).expect("should succeed");
        let res = pubkey_to_eth2(pubkey);
        assert_eq!(pubkey[..], res[..]);
    }

    #[test_case(&[], SIGNATURE_LENGTH, 0 ; "empty input")]
    #[test_case(&[42u8; SIGNATURE_LENGTH + 1], SIGNATURE_LENGTH, SIGNATURE_LENGTH + 1 ; "more data than expected")]
    #[test_case(&[42u8; SIGNATURE_LENGTH - 1], SIGNATURE_LENGTH, SIGNATURE_LENGTH - 1 ; "less data than expected")]
    fn signature_from_bytes_invalid(data: &[u8], expected: usize, got: usize) {
        assert!(matches!(
            signature_from_bytes(data),
            Err(ConvError::InvalidLength { expected: e, got: g }) if e == expected && g == got
        ));
    }

    #[test]
    fn signature_from_bytes_valid() {
        let data = vec![42u8; SIGNATURE_LENGTH];
        let sig = signature_from_bytes(&data).expect("should succeed");
        assert_eq!(sig, [42u8; SIGNATURE_LENGTH]);
    }

    #[test]
    fn sig_to_eth2_roundtrip() {
        let data = vec![42u8; SIGNATURE_LENGTH];
        let sig = signature_from_bytes(&data).expect("should succeed");
        let eth2_sig = sig_to_eth2(sig);
        assert_eq!(sig[..], eth2_sig[..]);
    }
}
