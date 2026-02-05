use thiserror::Error;

/// Manifest module error type.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// Empty or nil DAG.
    #[error("empty raw DAG")]
    EmptyDAG,

    /// No files found.
    #[error("no file found (lock-file: {lock_file}, manifest-file: {manifest_file})")]
    NoFileFound {
        /// Lock file path.
        lock_file: String,
        /// Manifest file path.
        manifest_file: String,
    },

    /// Manifest and legacy cluster hashes don't match.
    #[error(
        "manifest and legacy cluster hashes don't match (manifest_hash: {manifest_hash}, legacy_hash: {legacy_hash})"
    )]
    ClusterHashMismatch {
        /// Manifest hash hex string.
        manifest_hash: String,
        /// Legacy hash hex string.
        legacy_hash: String,
    },

    /// Mutation is nil.
    #[error("mutation is nil")]
    InvalidSignedMutation,

    /// Invalid mutation.
    #[error("invalid mutation: {0}")]
    InvalidMutation(String),

    /// Non-empty signature or signer.
    #[error("{0}")]
    NonEmptyField(String),

    /// Invalid mutation signature.
    #[error("invalid mutation signature")]
    InvalidSignature,

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

    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Protobuf decode error.
    #[error("protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),

    /// JSON error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Hex decode error.
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// K1 key error.
    #[error("k1 key error: {0}")]
    K1Key(String),

    /// Crypto error.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// ENR parsing error.
    #[error("enr parsing error: {0}")]
    EnrParse(String),

    /// P2P error.
    #[error("p2p error: {0}")]
    P2p(String),

    /// BLS conversion error.
    #[error("bls conversion error: {0}")]
    BlsConversion(String),

    /// Builder registration error.
    #[error("builder registration error: {0}")]
    BuilderRegistration(String),

    /// Invalid lock hash.
    #[error("invalid lock hash")]
    InvalidLockHash,

    /// Invalid mutation type.
    #[error("invalid mutation type: {0}")]
    InvalidMutationType(String),
}

/// Result type alias for manifest operations.
pub type Result<T> = std::result::Result<T, ManifestError>;
