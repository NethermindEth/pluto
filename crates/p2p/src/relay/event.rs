//! Public event and error types emitted by [`RelayManager`].
//!
//! [`RelayManager`]: super::RelayManager

use libp2p::{
    PeerId,
    relay::outbound::hop::{ConnectError, ReserveError},
    swarm::DialError,
};

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
    /// The relay refused the circuit (or the reservation) because one of its
    /// resource limits was exceeded — its circuit/reservation quota or one of
    /// its rate limiters.
    ///
    /// Unlike the other variants this is *the relay throttling us*, so the
    /// caller must slow down rather than retry on the normal ladder; see
    /// `RelayDialState::throttle_denied`.
    #[error("relay resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),
    /// All transport attempts failed; details preserved as `addr: err`,
    /// joined by `; `.
    #[error("transport: {0}")]
    Transport(String),
}

impl RelayDialError {
    /// Whether the relay denied us for exceeding one of its resource limits.
    pub fn is_resource_limit_exceeded(&self) -> bool {
        matches!(self, Self::ResourceLimitExceeded(_))
    }
}

/// Renders an error together with its `source()` chain as `a: b: c`.
///
/// A relay circuit failure reaches the swarm as
/// `TransportError::Other(io::Error)` wrapping several layers of transport
/// adapters, and every layer's `Display` drops its source — the top-level
/// message is a useless `"Failed to connect to destination."`. Walking the
/// chain is what makes the actual denial readable in logs.
fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = Vec::new();
    let mut current = Some(err);
    while let Some(e) = current {
        let msg = e.to_string();
        if !msg.is_empty() {
            parts.push(msg);
        }
        current = e.source();
    }

    parts.join(": ")
}

/// Whether `err` or any error in its `source()` chain is a relay
/// resource-limit denial (`RESOURCE_LIMIT_EXCEEDED` in the HOP response).
fn is_resource_limit_exceeded(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(err);
    while let Some(e) = current {
        if matches!(
            e.downcast_ref::<ConnectError>(),
            Some(ConnectError::ResourceLimitExceeded)
        ) || matches!(
            e.downcast_ref::<ReserveError>(),
            Some(ReserveError::ResourceLimitExceeded)
        ) {
            return true;
        }
        current = e.source();
    }

    false
}

impl From<&DialError> for RelayDialError {
    fn from(err: &DialError) -> Self {
        match err {
            DialError::LocalPeerId { .. } => Self::LocalPeerId,
            DialError::NoAddresses => Self::NoAddresses,
            DialError::DialPeerConditionFalse(_) => Self::Skipped,
            DialError::Aborted => Self::Aborted,
            DialError::WrongPeerId { .. } => Self::WrongPeerId,
            DialError::Denied { cause } => {
                if is_resource_limit_exceeded(cause) {
                    Self::ResourceLimitExceeded(error_chain(cause))
                } else {
                    Self::Denied(cause.to_string())
                }
            }
            DialError::Transport(errors) => {
                let detail = errors
                    .iter()
                    .map(|(addr, e)| format!("{addr}: {}", error_chain(e)))
                    .collect::<Vec<_>>()
                    .join("; ");
                if errors.iter().any(|(_, e)| is_resource_limit_exceeded(e)) {
                    Self::ResourceLimitExceeded(detail)
                } else {
                    Self::Transport(detail)
                }
            }
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

#[cfg(test)]
mod tests {
    use libp2p::core::transport::TransportError;

    use super::*;

    /// The transport error a relay circuit denial actually produces: the
    /// `ConnectError` sits several `source()` levels below the boxed
    /// `io::Error` the swarm surfaces, and every intermediate `Display` drops
    /// its source.
    fn boxed_relay_error(inner: libp2p::relay::client::transport::Error) -> DialError {
        DialError::Transport(vec![(
            "/ip4/10.0.0.1/tcp/9000".parse().expect("valid multiaddr"),
            TransportError::Other(std::io::Error::other(inner)),
        )])
    }

    #[test]
    fn transport_resource_limit_denial_is_classified_and_detailed() {
        let err = RelayDialError::from(&boxed_relay_error(
            libp2p::relay::client::transport::Error::Connect(ConnectError::ResourceLimitExceeded),
        ));

        assert!(err.is_resource_limit_exceeded());
        assert!(
            err.to_string().contains("resource limit exceeded"),
            "the denial must survive into the message, got {err}"
        );
    }

    #[test]
    fn transport_reservation_resource_limit_denial_is_classified() {
        let err = RelayDialError::from(&boxed_relay_error(
            libp2p::relay::client::transport::Error::Reservation(
                ReserveError::ResourceLimitExceeded,
            ),
        ));

        assert!(err.is_resource_limit_exceeded());
    }

    #[test]
    fn other_transport_failures_are_not_classified_as_denials() {
        let err = RelayDialError::from(&boxed_relay_error(
            libp2p::relay::client::transport::Error::Connect(ConnectError::NoReservation),
        ));

        assert!(!err.is_resource_limit_exceeded());
        assert!(matches!(err, RelayDialError::Transport(_)));
        // The chain walk is also what keeps the real cause visible: the
        // outermost Display is a bare "Failed to connect to destination.".
        assert!(
            err.to_string().contains("Relay has no reservation"),
            "source chain must be rendered, got {err}"
        );
    }

    #[test]
    fn non_transport_dial_errors_are_unchanged() {
        assert!(matches!(
            RelayDialError::from(&DialError::NoAddresses),
            RelayDialError::NoAddresses
        ));
        assert!(matches!(
            RelayDialError::from(&DialError::Aborted),
            RelayDialError::Aborted
        ));
    }
}
