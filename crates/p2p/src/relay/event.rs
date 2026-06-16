//! Public event and error types emitted by [`RelayManager`].
//!
//! [`RelayManager`]: super::RelayManager

use libp2p::{PeerId, swarm::DialError};

/// Events emitted by [`RelayManager`] to the swarm.
///
/// Mirrors the relay lifecycle (`Dialing → Established → Reserved`) plus the
/// outcomes of routing known cluster peers through reserved circuits. Consumers
/// can observe the full progression of a reservation, or pick out just the
/// events they care about (e.g. `RelayReserved` for "circuits are usable now").
///
/// [`RelayManager`]: super::RelayManager
#[derive(Debug)]
pub enum RelayManagerEvent {
    /// Transport connection to a relay is up. A circuit listener has been
    /// requested but the reservation is not yet confirmed.
    RelayConnected(PeerId),
    /// Relay accepted the reservation; circuits through this relay are now
    /// usable for routing cluster peers.
    RelayReserved(PeerId),
    /// Circuit listener for this relay expired; the relay has been demoted to
    /// `Established`. libp2p's circuit client typically refreshes the
    /// reservation shortly, which will re-emit `RelayReserved`.
    RelayReservationLost(PeerId),
    /// Last transport connection to the relay closed. A re-dial campaign with
    /// exponential backoff has been queued.
    RelayDisconnected(PeerId),
    /// A cluster peer has been reached through one of the reserved relay
    /// circuits. From here libp2p owns the connection; this event exists for
    /// telemetry only.
    PeerRoutedConnected(PeerId),
    /// A dial attempt failed. The underlying `RelayDialState` self-rearms
    /// with exponential backoff, so consumers don't need to take any action.
    DialFailed {
        /// Target peer id (a relay server, or a routed cluster peer).
        peer_id: PeerId,
        /// Whether this dial was targeting a relay or a routed peer.
        target: RelayDialType,
        /// Number of attempts so far (including this one).
        retry_count: u32,
        /// Categorised dial error.
        error: RelayDialError,
    },
}

/// Categorised dial error surfaced via [`RelayManagerEvent::DialFailed`].
///
/// Translated from libp2p's [`DialError`] so consumers can match on variants
/// without depending on libp2p's swarm types directly. Free-form details are
/// preserved as strings on the variants where they carry diagnostic value.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RelayDialError {
    /// Attempted to dial our own peer id.
    #[error("local peer id")]
    LocalPeerId,
    /// No transport addresses were available for the target.
    #[error("no addresses")]
    NoAddresses,
    /// Dial was skipped because of a peer condition (already
    /// connected/dialing).
    #[error("dial skipped: peer condition not met")]
    Skipped,
    /// Pending connection attempt was aborted (e.g. swarm shutdown, or a newer
    /// dial superseded it).
    #[error("aborted")]
    Aborted,
    /// Connected, but the remote reported a peer id different from the
    /// expected one.
    #[error("wrong peer id")]
    WrongPeerId,
    /// Connection was denied by a behaviour or upgrade step.
    #[error("denied: {0}")]
    Denied(String),
    /// All transport attempts failed; details preserved as `addr: err`,
    /// joined by `; `.
    #[error("transport: {0}")]
    Transport(String),
}

impl From<&DialError> for RelayDialError {
    fn from(err: &DialError) -> Self {
        match err {
            DialError::LocalPeerId { .. } => Self::LocalPeerId,
            DialError::NoAddresses => Self::NoAddresses,
            DialError::DialPeerConditionFalse(_) => Self::Skipped,
            DialError::Aborted => Self::Aborted,
            DialError::WrongPeerId { .. } => Self::WrongPeerId,
            DialError::Denied { cause } => Self::Denied(cause.to_string()),
            DialError::Transport(errors) => Self::Transport(
                errors
                    .iter()
                    .map(|(addr, e)| format!("{addr}: {e}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
        }
    }
}

/// Whether a `RelayDialState` is targeting a relay server or a cluster peer
/// reached through reserved relay circuits.
#[derive(Debug, Clone, Copy)]
pub enum RelayDialType {
    /// Dial a known cluster peer via reserved relay circuits.
    ClusterPeer,
    /// Dial a relay server directly.
    RelayServer,
}
