use std::net::SocketAddr;

use libp2p::multiaddr;

use pluto_p2p::p2p::P2PError;

/// Relay P2P error.
#[derive(Debug, thiserror::Error)]
pub enum RelayP2PError {
    /// Failed to load private key.
    #[error("Failed to load private key")]
    FailedToLoadPrivateKey(#[from] pluto_p2p::k1::K1Error),

    /// P2P error.
    #[error("P2P error: {0}")]
    P2PError(#[from] P2PError),

    /// P2P Config error.
    #[error("P2P Config error: {0}")]
    P2PConfigError(#[from] pluto_p2p::config::P2PConfigError),

    /// Failed to bind HTTP listener.
    #[error("Failed to bind HTTP listener {addr}: {source}")]
    FailedToBindHttpListener {
        /// Address the listener could not be bound to.
        addr: String,
        /// Underlying bind error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to serve HTTP.
    #[error("Failed to serve HTTP: {0}")]
    FailedToServeHTTP(#[source] std::io::Error),

    /// A libp2p listener closed before reporting the address it bound.
    #[error("libp2p listener closed during startup: {reason}")]
    ListenerClosedDuringStartup {
        /// Why the listener closed.
        reason: String,
    },

    /// One of the HTTP server tasks ended without returning.
    #[error("Relay HTTP server task failed: {0}")]
    ServerTaskFailed(#[source] tokio::task::JoinError),

    /// Failed to bind the monitoring listener.
    #[error("Failed to bind monitoring listener {addr}: {source}")]
    FailedToBindMonitoringListener {
        /// Address the monitoring listener could not be bound to.
        addr: SocketAddr,
        /// Underlying bind error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to serve the monitoring API.
    #[error("Failed to serve monitoring API: {0}")]
    FailedToServeMonitoring(#[source] std::io::Error),

    /// Failed to parse multiaddress.
    #[error("Failed to parse multiaddress: {0}")]
    FailedToParseMultiaddr(#[from] multiaddr::Error),

    /// Failed to parse monitoring address.
    #[error("Failed to parse monitoring address: {0}")]
    FailedToParseMonitoringAddr(String),
}

/// Relay P2P result.
pub(crate) type Result<T> = std::result::Result<T, RelayP2PError>;
