use vise::*;

/// Buckets for the ping latency histogram.
pub const BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Metrics for the P2P layer.
#[derive(Debug, Metrics)]
#[metrics(prefix = "p2p")]
pub struct P2PMetrics {
    /// Ping latencies in seconds per peer
    #[metrics(buckets = &BUCKETS, labels = ["peer"])]
    pub ping_latency_secs: LabeledFamily<String, Histogram>,

    /// Total number of ping errors per peer
    #[metrics(labels = ["peer"])]
    pub ping_error_total: LabeledFamily<String, Counter>,

    /// Whether the last ping was successful (1) or not (0). Can be used as
    /// proxy for connected peers
    #[metrics(labels = ["peer"])]
    pub ping_success: LabeledFamily<String, Gauge>,

    /// Current libp2p reachability status of this node as detected by autonat:
    /// unknown(0), public(1) or private(2).
    pub reachability_status: Gauge,

    /// Connected relays by name
    #[metrics(labels = ["peer"])]
    pub relay_connections: LabeledFamily<String, Gauge>,

    /// Current number of libp2p connections by peer, type (`direct` or
    /// `relay`), and protocol (`tcp`, `quic`). Note that peers may have
    /// multiple connections.
    pub peer_connection_types: Family<PeerConnectionLabels, Gauge>,

    /// Current number of libp2p connections by relay, type (`direct` or
    /// `relay`), and protocol (`tcp`, `quic`). Note that peers may have
    /// multiple connections.
    pub relay_connection_types: Family<RelayConnectionLabels, Gauge>,

    /// Current number of libp2p streams by peer, direction ('inbound' or
    /// 'outbound' or 'unknown') and protocol.
    pub peer_streams: Family<PeerStreamLabels, Gauge>,

    /// Total number of libp2p connections per peer.
    #[metrics(labels = ["peer"])]
    pub peer_connection_total: LabeledFamily<String, Counter>,

    /// Total number of network bytes received from the peer by protocol.
    pub peer_network_receive_bytes_total: Family<PeerNetworkLabels, Counter>,

    /// Total number of network bytes sent to the peer by protocol.
    pub peer_network_sent_bytes_total: Family<PeerNetworkLabels, Counter>,
}

/// The type of connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelValue)]
#[metrics(rename_all = "snake_case")]
pub enum ConnectionType {
    /// A direct connection to a peer.
    Direct,
    /// A connection to a relay.
    Relay,
}

/// The direction of a connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelValue)]
#[metrics(rename_all = "snake_case")]
pub enum Direction {
    /// An inbound connection.
    Inbound,
    /// An outbound connection.
    Outbound,
    /// An unknown connection.
    Unknown,
}

/// The protocol of a connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelValue)]
#[metrics(rename_all = "snake_case")]
pub enum Protocol {
    /// A TCP connection.
    Tcp,
    /// A QUIC connection.
    Quic,
}

/// Labels for peer connections.
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct PeerConnectionLabels {
    peer: String,
    r#type: ConnectionType,
    protocol: Protocol,
}

impl PeerConnectionLabels {
    /// Creates a new peer connection labels.
    pub fn new(peer: &str, r#type: ConnectionType, protocol: Protocol) -> Self {
        Self {
            peer: peer.to_string(),
            r#type,
            protocol,
        }
    }
}

/// Relay connection labels
pub type RelayConnectionLabels = PeerConnectionLabels;

/// Labels for peer streams.
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct PeerStreamLabels {
    peer: String,
    direction: Direction,
    protocol: Protocol,
}

impl PeerStreamLabels {
    /// Creates a new peer stream labels.
    pub fn new(peer: &str, direction: Direction, protocol: Protocol) -> Self {
        Self {
            peer: peer.to_string(),
            direction,
            protocol,
        }
    }
}

/// Labels for peer network.
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct PeerNetworkLabels {
    peer: String,
    protocol: Protocol,
}

impl PeerNetworkLabels {
    /// Creates a new peer network labels.
    pub fn new(peer: &str, protocol: Protocol) -> Self {
        Self {
            peer: peer.to_string(),
            protocol,
        }
    }
}

/// Global metrics for the P2P layer.
#[vise::register]
pub static P2P_METRICS: Global<P2PMetrics> = Global::new();
