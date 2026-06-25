//! Readiness state and error reasons for the monitoring API.

use tokio::sync::watch;

/// Result returned by a readiness checker.
pub type ReadyResult = Result<(), ReadinessError>;

/// Source of readiness state for the `/readyz` endpoint.
pub trait ReadinessCheck: Send + Sync + 'static {
    /// Returns `Ok(())` when the node is ready, or a concrete reason when it is
    /// not ready.
    fn check_ready(&self) -> ReadyResult;
}

impl<F> ReadinessCheck for F
where
    F: Fn() -> ReadyResult + Send + Sync + 'static,
{
    fn check_ready(&self) -> ReadyResult {
        self()
    }
}

/// Readiness failure reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadinessError {
    /// Ready checks have not produced a first result yet.
    #[error("ready check uninitialised")]
    Uninitialised,

    /// The node is not connected to enough peers for quorum.
    #[error("quorum peers not connected")]
    InsufficientPeers,

    /// The beacon node API is unavailable.
    #[error("beacon node down")]
    BeaconNodeDown,

    /// The beacon node is too far behind the head slot.
    #[error("beacon node far behind")]
    BeaconNodeFarBehind,

    /// The beacon node reports that it is syncing.
    #[error("beacon node not synced")]
    BeaconNodeSyncing,

    /// The beacon node has no connected peers.
    #[error("beacon node has zero peers")]
    BeaconNodeZeroPeers,

    /// No validator client calls were observed in the last readiness window.
    #[error("vc not connected")]
    ValidatorClientNotConnected,

    /// Validator client calls were observed, but not for every expected
    /// validator.
    #[error("vc missing validators")]
    ValidatorClientMissingValidators,

    /// Custom readiness failure reason supplied by future wiring.
    #[error("{0}")]
    Custom(String),
}

impl ReadinessError {
    /// Charon-compatible `/readyz` metric code for this failure reason. A ready
    /// node is reported separately as `1`; these codes must stay stable.
    pub(crate) fn readyz_code(&self) -> i64 {
        match self {
            Self::Uninitialised | Self::BeaconNodeDown | Self::Custom(_) => 2,
            Self::BeaconNodeSyncing => 3,
            Self::InsufficientPeers => 4,
            Self::ValidatorClientNotConnected => 5,
            Self::ValidatorClientMissingValidators => 6,
            Self::BeaconNodeZeroPeers => 7,
            Self::BeaconNodeFarBehind => 8,
        }
    }
}

/// Mutable readiness state suitable for sharing between background checks and
/// the monitoring API.
#[derive(Clone, Debug)]
pub struct ReadyState {
    sender: watch::Sender<ReadyResult>,
}

impl ReadyState {
    /// Creates a readiness state that starts as uninitialised.
    pub fn new() -> Self {
        let (sender, _receiver) = watch::channel(Err(ReadinessError::Uninitialised));
        Self { sender }
    }

    /// Creates a readiness state that starts ready.
    pub fn ready() -> Self {
        let state = Self::new();
        state.set_ready();
        state
    }

    /// Marks the node ready.
    pub fn set_ready(&self) {
        self.set(Ok(()));
    }

    /// Marks the node not ready with `error`.
    pub fn set_error(&self, error: ReadinessError) {
        self.set(Err(error));
    }

    /// Returns the current readiness result.
    pub fn status(&self) -> ReadyResult {
        self.sender.borrow().clone()
    }

    fn set(&self, status: ReadyResult) {
        let _previous = self.sender.send_replace(status);
    }
}

impl Default for ReadyState {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadinessCheck for ReadyState {
    fn check_ready(&self) -> ReadyResult {
        self.status()
    }
}

#[cfg(test)]
mod tests {
    use super::{ReadinessCheck, ReadinessError, ReadyState};

    #[test]
    fn ready_state_starts_uninitialised() {
        let state = ReadyState::new();

        assert_eq!(
            state.check_ready(),
            Err(ReadinessError::Uninitialised),
            "new readiness state should match the Go default readiness error"
        );
    }

    #[test]
    fn ready_state_can_transition_between_ready_and_error() {
        let state = ReadyState::new();

        state.set_ready();
        assert_eq!(state.check_ready(), Ok(()));

        state.set_error(ReadinessError::BeaconNodeSyncing);
        assert_eq!(state.check_ready(), Err(ReadinessError::BeaconNodeSyncing));
    }

    #[test]
    fn closure_can_provide_readiness() {
        let check = || Err(ReadinessError::InsufficientPeers);

        assert_eq!(check.check_ready(), Err(ReadinessError::InsufficientPeers));
    }
}
