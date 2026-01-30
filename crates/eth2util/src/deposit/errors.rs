use super::{constants::MIN_DEPOSIT_AMOUNT, types::Gwei};
use crate::{helpers, network};

/// Error type for deposit operations
#[derive(Debug, thiserror::Error)]
pub enum DepositError {
    // Domain/Address errors
    /// Invalid Ethereum address
    #[error("Invalid withdrawal address: {0}")]
    InvalidAddress(String),

    /// Address validation error
    #[error("Address validation error: {0}")]
    AddressValidationError(#[from] helpers::HelperError),

    // Amount validation errors
    /// Amount is below minimum
    #[error("Each partial deposit amount must be greater than 1ETH, got {0} Gwei")]
    AmountBelowMinimum(Gwei),

    /// Amount exceeds maximum
    #[error(
        "Single partial deposit amount is too large unless --compounding validators are used: {amount} Gwei (max: {max} Gwei)"
    )]
    AmountExceedsMaximum {
        /// Actual amount
        amount: Gwei,
        /// Maximum allowed
        max: Gwei,
    },

    /// Sum of amounts is below default
    #[error(
        "Sum of partial deposit amounts must be at least 32ETH, repetition is allowed: {0} Gwei"
    )]
    AmountSumBelowDefault(Gwei),

    /// Deposit message minimum amount not met
    #[error("Deposit message minimum amount must be >= {MIN_DEPOSIT_AMOUNT} ETH, got {0} Gwei")]
    MinimumAmountNotMet(Gwei),

    /// Deposit message maximum amount exceeded
    #[error("Deposit message maximum amount exceeded: {amount} Gwei (max: {max} Gwei)")]
    MaximumAmountExceeded {
        /// Actual amount
        amount: Gwei,
        /// Maximum allowed
        max: Gwei,
    },

    // Signature/Crypto errors
    /// BLS signature verification failed
    #[error("Invalid deposit data signature: {0}")]
    InvalidSignature(String),

    /// Crypto error
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Hash tree root computation error
    #[error("Hash tree root error: {0}")]
    HashTreeRootError(String),

    // File operations errors
    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Invalid data
    #[error("Invalid {field}: {message}")]
    InvalidData {
        /// Field name
        field: String,
        /// Error message
        message: String,
    },

    /// Invalid data length
    #[error("Invalid {field}: Expected {expected} bytes, got {actual}")]
    InvalidDataLength {
        /// Field name
        field: String,
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },

    /// Empty deposit data
    #[error("Empty deposit data")]
    EmptyDepositData,

    /// Deposit amounts not equal
    #[error("Deposit datas have different amounts at index {0}")]
    UnequalAmounts(usize),

    /// No deposit files found
    #[error("No deposit-data*.json files found in {0}")]
    NoFilesFound(String),

    // Network/Serialization errors
    /// Network error
    #[error("Network error: {0}")]
    NetworkError(#[from] network::NetworkError),

    /// Hex decoding error
    #[error("Failed to decode hex: {0}")]
    HexError(#[from] hex::FromHexError),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

pub(crate) type Result<T> = std::result::Result<T, DepositError>;
