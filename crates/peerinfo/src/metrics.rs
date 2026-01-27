//! Metrics for the peerinfo protocol.

use vise::*;

/// Metrics for the peerinfo protocol.
#[derive(Debug, Metrics)]
#[metrics(prefix = "app_peerinfo")]
pub struct PeerInfoMetrics {
    /// Peer clock offset in seconds.
    #[metrics(labels = ["peer"])]
    pub clock_offset_seconds: LabeledFamily<String, Gauge<i64>>,

    /// Constant gauge with version label set to peer's charon version.
    pub version: Family<PeerVersionLabels, Gauge>,

    /// Constant gauge with git_hash label set to peer's git commit hash.
    pub git_commit: Family<PeerGitHashLabels, Gauge>,

    /// Constant gauge set to the peer start time of the binary in unix seconds.
    #[metrics(labels = ["peer"])]
    pub start_time_secs: LabeledFamily<String, Gauge<i64>>,

    /// Constant gauge set to the peer index in the cluster definition.
    #[metrics(labels = ["peer"])]
    pub index: LabeledFamily<String, Gauge<usize>>,

    /// Set to 1 if the peer's version is supported by (compatible with) the
    /// current version, else 0 if unsupported.
    #[metrics(labels = ["peer"])]
    pub version_support: LabeledFamily<String, Gauge>,

    /// Set to 1 if builder API is enabled on this peer, else 0 if disabled.
    #[metrics(labels = ["peer"])]
    pub builder_api_enabled: LabeledFamily<String, Gauge>,

    /// Constant gauge with nickname label set to peer's charon nickname.
    pub nickname: Family<PeerNicknameLabels, Gauge>,
}

/// Labels for peer version metric.
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct PeerVersionLabels {
    peer: String,
    version: String,
}

impl PeerVersionLabels {
    /// Creates new peer version labels.
    pub fn new(peer: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            peer: peer.into(),
            version: version.into(),
        }
    }
}

/// Labels for peer git hash metric.
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct PeerGitHashLabels {
    peer: String,
    git_hash: String,
}

impl PeerGitHashLabels {
    /// Creates new peer git hash labels.
    pub fn new(peer: impl Into<String>, git_hash: impl Into<String>) -> Self {
        Self {
            peer: peer.into(),
            git_hash: git_hash.into(),
        }
    }
}

/// Labels for peer nickname metric.
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct PeerNicknameLabels {
    peer: String,
    peer_nickname: String,
}

impl PeerNicknameLabels {
    /// Creates new peer nickname labels.
    pub fn new(peer: impl Into<String>, peer_nickname: impl Into<String>) -> Self {
        Self {
            peer: peer.into(),
            peer_nickname: peer_nickname.into(),
        }
    }
}

/// Global metrics for the peerinfo protocol.
#[vise::register]
pub static PEERINFO_METRICS: Global<PeerInfoMetrics> = Global::new();
