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
}

/// Result type alias for manifest operations.
pub type Result<T> = std::result::Result<T, ManifestError>;
