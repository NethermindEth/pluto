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
    #[error("Failed to bind HTTP listener: {0}")]
    FailedToBindHttpListener(String),

    /// Failed to serve HTTP.
    #[error("Failed to serve HTTP: {0}")]
    FailedToServeHTTP(std::io::Error),

    /// Failed to parse multiaddress.
    #[error("Failed to parse multiaddress: {0}")]
    FailedToParseMultiaddr(#[from] multiaddr::Error),
}

/// Relay P2P result.
pub(crate) type Result<T> = std::result::Result<T, RelayP2PError>;
