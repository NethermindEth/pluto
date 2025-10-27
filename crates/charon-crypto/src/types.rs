//! # charon-crypto types

/// Maximum share ID.
pub const MAX_SHARE_ID: Index = 255;
/// Share secret key length
pub const SHARE_SECRET_KEY_LENGTH: usize = 33;
/// Signature share length
pub const SIGNATURE_SHARE_LENGTH: usize = 98;
/// Public key length
pub const PUBLIC_KEY_LENGTH: usize = 48;
/// Private key length
pub const PRIVATE_KEY_LENGTH: usize = 32;
/// Signature length
pub const SIGNATURE_LENGTH: usize = 97;

/// Public key type
pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];
/// Private key type
pub type PrivateKey = [u8; PRIVATE_KEY_LENGTH];
/// Signature type (BLS12-381 G2 compressed with header)
pub type Signature = [u8; SIGNATURE_LENGTH];
/// Index type & total shares / threshold
pub type Index = u8;

/// Error type for charon-crypto operations.
///
/// This enum represents all possible errors that can occur during cryptographic
/// operations in the charon-crypto library, including key management, signature
/// operations, and threshold cryptography.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The provided secret key bytes have an invalid length.
    ///
    /// Secret keys must be exactly 32 bytes in the BLS signature scheme.
    #[error("Invalid secret key length. Expected {expected}, got {got}")]
    InvalidSecretKeyLength {
        /// The expected number of bytes for a valid secret key.
        expected: usize,
        /// The actual number of bytes provided.
        got: usize,
    },

    /// The provided public key bytes have an invalid length.
    #[error("Invalid public key length. Expected {expected}, got {got}")]
    InvalidPublicKeyLength {
        /// The expected number of bytes for a valid public key.
        expected: usize,
        /// The actual number of bytes provided.
        got: usize,
    },

    /// The provided signature bytes have an invalid length.
    #[error("Invalid signature length. Expected {expected}, got {got}")]
    InvalidSignatureLength {
        /// The expected number of bytes for a valid signature.
        expected: usize,
        /// The actual number of bytes provided.
        got: usize,
    },

    /// Generic error for invalid byte array length.
    ///
    /// Used when converting between different byte representations where the
    /// length doesn't match the expected size.
    #[error("Invalid bytes length. Expected {expected}, got {got}")]
    InvalidBytesLength {
        /// The expected number of bytes.
        expected: usize,
        /// The actual number of bytes provided.
        got: usize,
    },

    /// The provided share secret key bytes have an invalid length.
    ///
    /// Share secret keys are used in threshold cryptography and must match
    /// the expected format for Shamir's Secret Sharing.
    #[error("Invalid share secret key length. Expected {expected}, got {got}")]
    InvalidShareSecretKeyLength {
        /// The expected number of bytes for a valid share secret key.
        expected: usize,
        /// The actual number of bytes provided.
        got: usize,
    },

    /// Failed to deserialize a share secret key from bytes.
    ///
    /// This error occurs when the bytes represent an invalid share secret key
    /// according to the BLS signature scheme rules.
    #[error("Failed to deserialize share secret key. Bls error: {bls_error}")]
    FailedToDeserializeShareSecretKey {
        /// The underlying BLS error message.
        /// We use String as BlsError does not implement PartialEq.
        bls_error: String,
    },

    /// Failed to deserialize a secret key from bytes.
    ///
    /// This error occurs when the provided bytes don't represent a valid
    /// BLS secret key (e.g., out of valid scalar field range).
    #[error("Failed to deserialize secret key.")]
    FailedToDeserializeSecretKey {
        /// The underlying BLS error message.
        /// We use String as BlsError does not implement PartialEq.
        bls_error: String,
    },

    /// Failed to deserialize a public key from bytes.
    #[error("Failed to deserialize public key.")]
    FailedToDeserializePublicKey {
        /// The underlying BLS error message.
        /// We use String as BlsError does not implement PartialEq.
        bls_error: String,
    },

    /// Failed to split a secret key into shares using Shamir's Secret Sharing.
    ///
    /// This error can occur due to invalid parameters such as threshold being
    /// greater than the number of shares.
    #[error("Failed to split secret key. Bls error: {bls_error}")]
    FailedToSplitSecretKey {
        /// The underlying BLS error message.
        /// We use String as BlsError does not implement PartialEq.
        bls_error: String,
    },

    /// Failed to recover a secret key from shares using Shamir's Secret
    /// Sharing.
    ///
    /// This error can occur when the provided shares are invalid, corrupted,
    /// or insufficient to reconstruct the original secret.
    #[error("Failed to recover secret key. Bls error: {bls_error}")]
    FailedToRecoverSecretKey {
        /// The underlying BLS error message.
        /// We use String as BlsError does not implement PartialEq.
        bls_error: String,
    },

    /// The threshold value provided for threshold cryptography is invalid.
    ///
    /// In threshold cryptography, the threshold must be at least 1 and at most
    /// equal to the total number of shares.
    #[error("Invalid threshold. Expected {expected}, got {got}")]
    InvalidThreshold {
        /// The expected threshold value or range.
        expected: Index,
        /// The actual threshold value provided.
        got: Index,
    },

    /// Failed to deserialize a signature from bytes.
    #[error("Failed to deserialize signature key.")]
    FailedToDeserializeSignatureKey {
        /// The underlying BLS error message.
        /// We use String as BlsError does not implement PartialEq.
        bls_error: String,
    },

    /// Failed to verify a BLS signature.
    ///
    /// This error occurs when signature verification fails, indicating either
    /// an invalid signature or a mismatch between the signature, message, and
    /// public key.
    #[error("Failed to verify signature.")]
    FailedToVerifySignature {
        /// The underlying BLS error message.
        /// We use String as BlsError does not implement PartialEq.
        bls_error: String,
    },

    /// Failed to generate a BLS signature.
    ///
    /// This error can occur during the signing process, typically due to
    /// invalid input data or internal cryptographic failures.
    #[error("Failed to generate signature.")]
    FailedToGenerateSignature {
        /// The underlying BLS error message.
        /// We use String as BlsError does not implement PartialEq.
        bls_error: String,
    },

    /// The signature array is empty.
    ///
    /// This error occurs when the provided signature array is empty.
    #[error("Signature array is empty.")]
    SignatureArrayIsEmpty,

    /// Math error.
    #[error("Math error: {0}")]
    MathError(#[from] MathError),
}

/// Math error type.
///
/// This enum represents all possible math errors that can occur during
/// arithmetic operations in the charon-crypto library.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MathError {
    /// Integer overflow.
    #[error("Share ID overflow.")]
    IntegerOverflow,

    /// Integer underflow.
    #[error("Integer underflow.")]
    IntegerUnderflow,

    /// Division by zero.
    #[error("Division by zero.")]
    DivisionByZero,

    /// Modulo by zero.
    #[error("Modulo by zero.")]
    ModuloByZero,
}
