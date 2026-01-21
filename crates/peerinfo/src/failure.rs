//! Failure types for the peerinfo protocol.

use std::{error::Error, fmt, sync::Arc};

/// A peer info exchange failure.
/// The difference between original `ping` implementation is that it's
/// cloneable.
#[derive(Debug, Clone)]
pub enum Failure {
    /// The peer info request timed out, i.e., no response was received within
    /// the configured timeout.
    Timeout,
    /// The peer does not support the peerinfo protocol.
    Unsupported,
    /// The peer info response was invalid (e.g., missing required fields).
    InvalidResponse {
        /// Description of the validation error.
        reason: String,
    },
    /// The peer info exchange failed for reasons other than a timeout.
    Other {
        /// The underlying error (wrapped in Arc for Clone).
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

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Timeout => f.write_str("PeerInfo request timeout"),
            Failure::Unsupported => f.write_str("PeerInfo protocol not supported"),
            Failure::InvalidResponse { reason } => {
                write!(f, "Invalid PeerInfo response: {reason}")
            }
            Failure::Other { error } => write!(f, "PeerInfo error: {error}"),
        }
    }
}

impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Failure::Timeout => None,
            Failure::Unsupported => None,
            Failure::InvalidResponse { .. } => None,
            Failure::Other { error } => Some(&**error),
        }
    }
}
