use thiserror::Error;

/// Manifest module error type.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// Invalid cluster.
    #[error("invalid cluster")]
    InvalidCluster,

    /// Cluster contains duplicate peer ENRs.
    #[error("cluster contains duplicate peer enrs: {enr}")]
    DuplicatePeerENR {
        /// ENR string.
        enr: String,
    },

    /// Peer not in definition.
    #[error("peer not in definition")]
    PeerNotInDefinition,

    /// Invalid hex length.
    #[error("invalid hex length (expect: {expect}, actual: {actual})")]
    InvalidHexLength {
        /// Expected length.
        expect: usize,
        /// Actual length.
        actual: usize,
    },

    /// ENR parsing error.
    #[error("enr parsing error: {0}")]
    EnrParse(String),

    /// P2P error.
    #[error("p2p error: {0}")]
    P2p(String),

    /// Crypto error.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Public key share from provided private key share not found in provided
    /// lock.
    #[error("public key share from provided private key share not found in provided lock")]
    PubShareNotFound,

    /// Amount of key shares don't match amount of validator public keys.
    #[error("amount of key shares don't match amount of validator public keys")]
    KeyShareCountMismatch,

    /// Node index for loaded ENR not found in cluster lock.
    #[error("node index for loaded enr not found in cluster lock")]
    NodeIdxNotFound,
}

/// Result type alias for manifest operations.
pub type Result<T> = std::result::Result<T, ManifestError>;
