//! Consensus seam for the priority protocol.
//!
//! The prioritiser proposes each deterministically-computed [`PriorityResult`]
//! through cluster QBFT consensus and subscribes to the decided result. This
//! module defines the [`Consensus`] trait abstracting that interaction so the
//! prioritiser can be unit-tested against a mock, and implements it for the
//! QBFT component.

use std::error::Error as StdError;

use async_trait::async_trait;
use pluto_consensus::qbft::{self, SubscriberResult};
use pluto_core::{corepb::v1::priority::PriorityResult, types::Duty};
use tokio_util::sync::CancellationToken;

/// Subscriber callback invoked with each decided priority consensus result.
pub type PrioritySubscriber =
    Box<dyn Fn(Duty, PriorityResult) -> SubscriberResult + Send + Sync + 'static>;

/// Boxed error returned by [`Consensus::propose_priority`].
pub type ConsensusError = Box<dyn StdError + Send + Sync + 'static>;

/// Cluster consensus over priority results.
///
/// Implementors run a consensus instance per duty and notify subscribers when
/// agreement is reached.
#[async_trait]
pub trait Consensus: Send + Sync {
    /// Proposes a priority result for the duty's consensus instance.
    ///
    /// `ct` is the instance's cancellation token, tied to the duty deadline, so
    /// cancellation reaches the underlying consensus run.
    async fn propose_priority(
        &self,
        duty: Duty,
        result: PriorityResult,
        ct: &CancellationToken,
    ) -> Result<(), ConsensusError>;

    /// Registers a callback invoked with each decided priority result.
    fn subscribe_priority(&self, callback: PrioritySubscriber);
}

#[async_trait]
impl Consensus for qbft::Consensus {
    async fn propose_priority(
        &self,
        duty: Duty,
        result: PriorityResult,
        ct: &CancellationToken,
    ) -> Result<(), ConsensusError> {
        qbft::Consensus::propose_priority(self, duty, result, ct)
            .await
            .map_err(|e| Box::new(e) as ConsensusError)
    }

    fn subscribe_priority(&self, callback: PrioritySubscriber) {
        qbft::Consensus::subscribe_priority(self, callback);
    }
}
