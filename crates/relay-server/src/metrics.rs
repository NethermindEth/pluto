use vise::*;

use pluto_p2p::metrics::BUCKETS;

/// Metrics for the relay P2P layer.
#[derive(Debug, Metrics)]
#[metrics(prefix = "relay_p2p")]
pub struct RelayMetrics {
    /// Total number of new connections by peer and cluster.
    pub connection_total: Family<PeerWithPeerClusterLabels, Counter>,

    /// Current number of active connections by peer and cluster.
    pub active_connections: Family<PeerWithPeerClusterLabels, Gauge>,

    /// Total number of network bytes sent to the peer and cluster.
    pub network_sent_bytes_total: Family<PeerWithPeerClusterLabels, Counter>,

    /// Total number of network bytes received from the peer and cluster.
    pub network_received_bytes_total: Family<PeerWithPeerClusterLabels, Counter>,

    /// Ping latency by peer and cluster.
    #[metrics(buckets = &BUCKETS)]
    pub ping_latency: Family<PeerWithPeerClusterLabels, Histogram>,
}

/// Labels for peer with peer cluster.
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct PeerWithPeerClusterLabels {
    /// Peer name.
    pub peer: String,
    /// Peer cluster identifier (empty when unknown).
    pub peer_cluster: String,
}

impl PeerWithPeerClusterLabels {
    /// Creates a new label set with the given peer name and cluster.
    pub fn new(peer: impl Into<String>, peer_cluster: impl Into<String>) -> Self {
        Self {
            peer: peer.into(),
            peer_cluster: peer_cluster.into(),
        }
    }
}

/// Global metrics for the relay P2P layer.
#[vise::register]
pub static RELAY_METRICS: Global<RelayMetrics> = Global::new();
