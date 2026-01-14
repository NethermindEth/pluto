use vise::*;

use charon_p2p::metrics::BUCKETS;

/// Metrics for the relay P2P layer.
#[derive(Debug, Metrics)]
#[metrics(prefix = "relay_p2p")]
pub struct RelayMetrics {
    /// Total number of new connections by peer and cluster.
    connection_total: Family<PeerWithPeerClusterLabels, Counter>,

    /// Current number of active connections by peer and cluster.
    active_connections: Family<PeerWithPeerClusterLabels, Gauge>,

    /// Total number of network bytes sent to the peer and cluster.
    network_sent_bytes_total: Family<PeerWithPeerClusterLabels, Counter>,

    /// Total number of network bytes received from the peer and cluster.
    network_received_bytes_total: Family<PeerWithPeerClusterLabels, Counter>,

    /// Ping latency by peer and cluster.
    #[metrics(buckets = &BUCKETS)]
    ping_latency: Family<PeerWithPeerClusterLabels, Histogram>,
}

/// Labels for peer with peer cluster.
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct PeerWithPeerClusterLabels {
    peer: String,
    peer_cluster: String,
}

/// Global metrics for the relay P2P layer.
#[vise::register]
pub static RELAY_METRICS: Global<RelayMetrics> = Global::new();
