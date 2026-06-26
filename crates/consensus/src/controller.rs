//! Consensus protocol controller.

use std::sync::Arc;

use k256::SecretKey;
use pluto_core::{deadline::DeadlinerHandle, gater::DutyGaterFn, types::Duty};
use pluto_featureset::FeatureSet;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    debugger::Debugger,
    qbft,
    timer::RoundTimerFunc,
    wrapper::{Consensus, ConsensusWrapper},
};

/// Consensus controller result.
pub type Result<T> = std::result::Result<T, Error>;

/// Consensus controller error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to construct the default QBFT consensus implementation.
    #[error("{0}")]
    Qbft(#[from] qbft::Error),
    /// Protocol ID is not supported by this controller.
    #[error("unsupported protocol id")]
    UnsupportedProtocolId,
}

/// Consensus controller constructor config.
pub struct Config {
    /// Consensus peers in process-index order.
    pub peers: Vec<qbft::Peer>,
    /// Local zero-based process index.
    pub local_peer_idx: i64,
    /// Local secp256k1 private key.
    pub privkey: SecretKey,
    /// Duty deadline scheduler. Name it `"consensus.qbft"` to match Go's
    /// internally-built deadliner for log parity.
    pub deadliner: DeadlinerHandle,
    /// Expired-duty receiver paired with `deadliner`.
    pub expired_rx: mpsc::Receiver<Duty>,
    /// Duty admission gate.
    pub duty_gater: DutyGaterFn,
    /// External message broadcaster.
    pub broadcaster: qbft::Broadcaster,
    /// Consensus debugger.
    pub debugger: Debugger,
    /// Enables attestation value comparison.
    pub compare_attestations: bool,
    /// Round timer factory.
    pub timer_func: RoundTimerFunc,
    /// Injected feature set, resolved once at construction.
    pub feature_set: Arc<FeatureSet>,
}

/// Controls the active consensus protocol implementation.
pub struct ConsensusController {
    default_consensus: Arc<dyn Consensus>,
    wrapped_consensus: ConsensusWrapper,
}

impl ConsensusController {
    /// Creates a new consensus controller with QBFT as the default protocol.
    pub fn new(config: Config) -> Result<Self> {
        let qbft = Arc::new(qbft::Consensus::new(qbft::Config {
            peers: config.peers,
            local_peer_idx: config.local_peer_idx,
            privkey: config.privkey,
            deadliner: config.deadliner,
            expired_rx: config.expired_rx,
            duty_gater: config.duty_gater,
            broadcaster: config.broadcaster,
            sniffer: config.debugger.sniffer(),
            compare_attestations: config.compare_attestations,
            timer_func: config.timer_func,
            feature_set: config.feature_set,
        })?);
        let default_consensus: Arc<dyn Consensus> = qbft;

        Ok(Self {
            wrapped_consensus: ConsensusWrapper::new(default_consensus.clone()),
            default_consensus,
        })
    }

    /// Starts the default consensus implementation.
    pub fn start(&self, ct: CancellationToken) {
        self.default_consensus.start(ct);
    }

    /// Returns the default consensus implementation.
    pub fn default_consensus(&self) -> Arc<dyn Consensus> {
        Arc::clone(&self.default_consensus)
    }

    /// Returns the current consensus wrapper.
    pub fn current_consensus(&self) -> &ConsensusWrapper {
        &self.wrapped_consensus
    }

    /// Sets the current consensus implementation for `protocol`.
    pub fn set_current_consensus_for_protocol(&self, protocol: &str) -> Result<()> {
        if self.wrapped_consensus.protocol_id() == protocol {
            return Ok(());
        }

        if self.default_consensus.protocol_id() == protocol {
            self.wrapped_consensus
                .set_impl(Arc::clone(&self.default_consensus));
            return Ok(());
        }

        // TODO: When introducing non-default consensus protocols, mirror Go's
        // deferred wrapped-context cancellation here: cancel the previous
        // non-default impl, build a `"consensus.<proto>"` deadliner, set the
        // new impl, and start it under a fresh cancellation token.
        Err(Error::UnsupportedProtocolId)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use k256::SecretKey;
    use pluto_core::{
        deadline::{DeadlinerTask, NeverExpiringCalculator},
        types::DutyType,
    };

    use crate::{debugger::Debugger, protocols::QBFT_V2_PROTOCOL_ID, timer::get_round_timer_func};

    use super::*;

    #[tokio::test]
    async fn consensus_controller_uses_qbft_as_default_and_current() {
        let controller = ConsensusController::new(config()).expect("controller should construct");
        let ct = CancellationToken::new();

        controller.start(ct.clone());

        let default_consensus = controller.default_consensus();
        assert_eq!(default_consensus.protocol_id(), QBFT_V2_PROTOCOL_ID);
        assert_eq!(
            controller.current_consensus().protocol_id(),
            QBFT_V2_PROTOCOL_ID
        );

        controller
            .set_current_consensus_for_protocol(QBFT_V2_PROTOCOL_ID)
            .expect("default protocol is supported");
        let err = controller
            .set_current_consensus_for_protocol("boo")
            .expect_err("unknown protocol should fail");
        assert!(matches!(err, Error::UnsupportedProtocolId));

        ct.cancel();
    }

    fn config() -> Config {
        let ct = CancellationToken::new();
        let (deadliner, expired_rx) =
            DeadlinerTask::start(ct, "controller-test", NeverExpiringCalculator);

        let fs = Arc::new(FeatureSet::new());
        Config {
            peers: peers(),
            local_peer_idx: 0,
            privkey: secret_key(1),
            deadliner,
            expired_rx,
            duty_gater: Arc::new(|duty| duty.duty_type == DutyType::Attester),
            broadcaster: Arc::new(|_, _| Box::pin(async { Ok(()) })),
            debugger: Debugger::new(),
            compare_attestations: false,
            timer_func: get_round_timer_func(fs.clone()),
            feature_set: fs,
        }
    }

    fn peers() -> Vec<qbft::Peer> {
        vec![
            qbft::Peer {
                index: 0,
                name: "node-0".to_string(),
                public_key: secret_key(1).public_key(),
            },
            qbft::Peer {
                index: 1,
                name: "node-1".to_string(),
                public_key: secret_key(2).public_key(),
            },
        ]
    }

    fn secret_key(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).expect("test secret key is valid")
    }
}
