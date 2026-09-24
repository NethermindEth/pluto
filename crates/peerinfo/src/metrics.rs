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

impl PeerInfoMetrics {
    /// Sets `peer`'s nickname series to 1, zeroing every other nickname series
    /// for that peer.
    ///
    /// Charon's `peerNickname` is a `ResetGaugeVec` and calls
    /// `peerNickname.Reset(peerName)` before each set, which *deletes* every
    /// series for that peer and so guarantees exactly one series per peer.
    /// `vise` families cannot delete series, so we zero the stale ones
    /// instead; the invariant dashboards rely on — at most one series reads 1
    /// per peer — holds either way.
    pub fn set_peer_nickname(&self, peer: &str, nickname: &str) {
        let labels = PeerNicknameLabels::new(peer, nickname);
        for (previous, gauge) in self.nickname.to_entries() {
            if previous.peer == peer && previous != labels {
                gauge.set(0);
            }
        }
        self.nickname[&labels].set(1);
    }

    /// Sets `peer`'s version series to 1, zeroing every other version series
    /// for that peer. See [`Self::set_peer_nickname`] for why stale series are
    /// zeroed rather than deleted; Charon resets `peerVersion` the same way.
    pub fn set_peer_version(&self, peer: &str, version: &str) {
        let labels = PeerVersionLabels::new(peer, version);
        for (previous, gauge) in self.version.to_entries() {
            if previous.peer == peer && previous != labels {
                gauge.set(0);
            }
        }
        self.version[&labels].set(1);
    }

    /// Sets `peer`'s git-commit series to 1, zeroing every other git-commit
    /// series for that peer. See [`Self::set_peer_nickname`] for why stale
    /// series are zeroed rather than deleted; Charon resets `peerGitHash` the
    /// same way.
    pub fn set_peer_git_commit(&self, peer: &str, git_hash: &str) {
        let labels = PeerGitHashLabels::new(peer, git_hash);
        for (previous, gauge) in self.git_commit.to_entries() {
            if previous.peer == peer && previous != labels {
                gauge.set(0);
            }
        }
        self.git_commit[&labels].set(1);
    }
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

    /// Returns the peer name label.
    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// Returns the peer nickname label.
    pub fn peer_nickname(&self) -> &str {
        &self.peer_nickname
    }
}

/// Global metrics for the peerinfo protocol.
#[vise::register]
pub static PEERINFO_METRICS: Global<PeerInfoMetrics> = Global::new();

#[cfg(test)]
mod tests {
    use super::*;

    /// The global registry is process-wide, so every test uses peer names of
    /// its own to stay independent of the others.
    fn nickname_gauges(metrics: &PeerInfoMetrics, peer: &str) -> Vec<(String, i64)> {
        let mut out: Vec<_> = metrics
            .nickname
            .to_entries()
            .filter(|(labels, _)| labels.peer == peer)
            .map(|(labels, gauge)| (labels.peer_nickname, gauge.get()))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn set_peer_nickname_leaves_one_series_at_one() {
        let metrics = PeerInfoMetrics::default();

        metrics.set_peer_nickname("perfect-water", "bravo");
        assert_eq!(
            nickname_gauges(&metrics, "perfect-water"),
            vec![("bravo".to_owned(), 1)]
        );

        // The peer restarts under a new nickname with the same key: Charon's
        // `Reset` would drop the old series entirely, we zero it.
        metrics.set_peer_nickname("perfect-water", "charlie");
        assert_eq!(
            nickname_gauges(&metrics, "perfect-water"),
            vec![("bravo".to_owned(), 0), ("charlie".to_owned(), 1)]
        );

        // Exactly one series reads 1 — what a `peer -> peer_nickname` join
        // needs.
        assert_eq!(
            nickname_gauges(&metrics, "perfect-water")
                .iter()
                .filter(|(_, v)| *v == 1)
                .count(),
            1
        );
    }

    #[test]
    fn set_peer_nickname_does_not_touch_other_peers() {
        let metrics = PeerInfoMetrics::default();

        metrics.set_peer_nickname("still-mountain", "alpha");
        metrics.set_peer_nickname("quiet-river", "bravo");
        metrics.set_peer_nickname("quiet-river", "charlie");

        // The local node's own series must survive a peer's nickname change.
        assert_eq!(
            nickname_gauges(&metrics, "still-mountain"),
            vec![("alpha".to_owned(), 1)]
        );
    }

    #[test]
    fn set_peer_nickname_repeat_is_idempotent() {
        let metrics = PeerInfoMetrics::default();

        metrics.set_peer_nickname("brave-cloud", "alpha");
        metrics.set_peer_nickname("brave-cloud", "alpha");

        assert_eq!(
            nickname_gauges(&metrics, "brave-cloud"),
            vec![("alpha".to_owned(), 1)]
        );
    }

    #[test]
    fn set_peer_version_and_git_commit_clear_stale_series() {
        let metrics = PeerInfoMetrics::default();

        // A binary upgrade: the pre-upgrade series must stop reading 1.
        metrics.set_peer_version("lucky-forest", "v1.7.1");
        metrics.set_peer_version("lucky-forest", "v1.8.0");
        metrics.set_peer_git_commit("lucky-forest", "abc1234");
        metrics.set_peer_git_commit("lucky-forest", "def5678");

        let versions: Vec<_> = metrics
            .version
            .to_entries()
            .filter(|(labels, _)| labels.peer == "lucky-forest")
            .map(|(labels, gauge)| (labels.version, gauge.get()))
            .collect();
        assert_eq!(versions.len(), 2);
        assert_eq!(
            versions
                .iter()
                .filter(|(v, g)| *g == 1 && v == "v1.8.0")
                .count(),
            1
        );
        assert_eq!(versions.iter().filter(|(_, g)| *g == 1).count(), 1);

        let hashes: Vec<_> = metrics
            .git_commit
            .to_entries()
            .filter(|(labels, _)| labels.peer == "lucky-forest")
            .map(|(labels, gauge)| (labels.git_hash, gauge.get()))
            .collect();
        assert_eq!(hashes.len(), 2);
        assert_eq!(
            hashes
                .iter()
                .filter(|(h, g)| *g == 1 && h == "def5678")
                .count(),
            1
        );
        assert_eq!(hashes.iter().filter(|(_, g)| *g == 1).count(), 1);
    }
}
