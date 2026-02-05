//! Configuration for the peerinfo protocol.

use std::time::Duration;

use libp2p::PeerId;
use prost_types::Timestamp;

use crate::peerinfopb::v1::peerinfo::PeerInfo;

/// Default interval between peer info exchanges.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);

/// Default timeout for peer info requests.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// The configuration for the peerinfo protocol.
#[derive(Debug, Clone)]
pub struct Config {
    /// The timeout for peer info requests.
    timeout: Duration,
    /// The interval between peer info exchanges.
    interval: Duration,
    /// Local peer info to send to other peers.
    local_info: LocalPeerInfo,
    /// Known peers.
    peers: Vec<PeerId>,
}

/// Local peer information to be shared with other peers.
#[derive(Debug, Clone, Default)]
pub struct LocalPeerInfo {
    /// Charon version string (e.g., "v1.0.0").
    pub pluto_version: String,
    /// Lock hash identifying the cluster.
    pub lock_hash: Vec<u8>,
    /// Git commit hash (7 characters).
    pub git_hash: String,
    /// Whether the builder API is enabled.
    pub builder_api_enabled: bool,
    /// Human-readable nickname for this peer.
    pub nickname: String,
    /// Time when the node started.
    pub started_at: Option<Timestamp>,
}

impl LocalPeerInfo {
    /// Creates a new `LocalPeerInfo` with the given parameters.
    pub fn new(
        pluto_version: impl Into<String>,
        lock_hash: impl Into<Vec<u8>>,
        git_hash: impl Into<String>,
        builder_api_enabled: bool,
        nickname: impl Into<String>,
    ) -> Self {
        Self {
            pluto_version: pluto_version.into(),
            lock_hash: lock_hash.into(),
            git_hash: git_hash.into(),
            builder_api_enabled,
            nickname: nickname.into(),
            started_at: Some(Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
        }
    }

    /// Converts to a protobuf `PeerInfo` message with the current timestamp.
    pub(crate) fn to_proto(&self) -> PeerInfo {
        let now = chrono::Utc::now();
        PeerInfo {
            pluto_version: self.pluto_version.clone(),
            lock_hash: self.lock_hash.clone().into(),
            git_hash: self.git_hash.clone(),
            sent_at: Some(Timestamp {
                seconds: now.timestamp(),
                nanos: i32::try_from(now.timestamp_subsec_nanos()).unwrap_or(0),
            }),
            started_at: self.started_at,
            builder_api_enabled: self.builder_api_enabled,
            nickname: self.nickname.clone(),
        }
    }
}

impl Config {
    /// Creates a new [`Config`] with the following default settings:
    ///
    /// * [`Config::with_interval`] 60s
    /// * [`Config::with_timeout`] 20s
    ///
    /// These settings have the following effect:
    ///
    /// * A peer info request is sent every 60 seconds on a healthy connection.
    /// * Every request must yield a response within 20 seconds to be
    ///   successful.
    #[must_use]
    pub fn new(local_info: LocalPeerInfo) -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            interval: DEFAULT_INTERVAL,
            local_info,
            peers: Vec::new(),
        }
    }

    /// Sets the peer info request timeout.
    #[must_use]
    pub fn with_timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    /// Sets the peer info exchange interval.
    #[must_use]
    pub fn with_interval(mut self, d: Duration) -> Self {
        self.interval = d;
        self
    }

    /// Sets the local peer info.
    #[must_use]
    pub fn with_local_info(mut self, info: LocalPeerInfo) -> Self {
        self.local_info = info;
        self
    }

    /// Sets the known peers.
    #[must_use]
    pub fn with_peers(mut self, peers: Vec<PeerId>) -> Self {
        self.peers = peers;
        self
    }

    /// Returns the local peer info.
    #[must_use]
    pub fn local_info(&self) -> &LocalPeerInfo {
        &self.local_info
    }

    /// Returns the timeout.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the interval.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Returns the known peers.
    #[must_use]
    pub fn peers(&self) -> &[PeerId] {
        &self.peers
    }
}
