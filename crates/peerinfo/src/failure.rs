//! Failure types for the peerinfo protocol.

use std::sync::Arc;

/// A peer info exchange failure.
/// The difference between original `ping` implementation is that it's
/// cloneable.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Failure {
    /// The peer info request timed out, i.e., no response was received within
    /// the configured timeout.
    #[error("PeerInfo request timeout")]
    Timeout,
    /// The peer does not support the peerinfo protocol.
    #[error("PeerInfo protocol not supported")]
    Unsupported,
    /// The peer info response was invalid (e.g., missing required fields).
    #[error("Invalid PeerInfo response: {reason}")]
    InvalidResponse {
        /// Description of the validation error.
        reason: String,
    },
    /// The peer info exchange failed for reasons other than a timeout.
    #[error("PeerInfo error: {error}")]
    Other {
        /// The underlying error (wrapped in Arc for Clone).
        #[source]
        error: Arc<dyn std::error::Error + Send + Sync + 'static>,
    },
}

impl Failure {
    /// Creates a new `Failure::Other` from any error type.
    pub fn other(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Other { error: Arc::new(e) }
    }

    /// Creates a new `Failure::InvalidResponse` with the given reason.
    pub fn invalid_response(reason: impl Into<String>) -> Self {
        Self::InvalidResponse {
            reason: reason.into(),
        }
    }
}
