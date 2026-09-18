//! Swappable consensus implementation wrapper.

use std::{
    error::Error as StdError,
    sync::{Arc, PoisonError, RwLock},
};

use async_trait::async_trait;
use pluto_core::{corepb::v1::core as pbcore, types::Duty};
use tokio_util::sync::CancellationToken;

use crate::qbft;

/// Consensus wrapper result.
pub type Result<T> = std::result::Result<T, Error>;

/// Consensus implementation error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// QBFT consensus failed.
    #[error(transparent)]
    Qbft(#[from] qbft::RunnerError),
}

/// Subscriber callback result.
pub type SubscriberResult = std::result::Result<(), Box<dyn StdError + Send + Sync + 'static>>;

/// Subscriber callback for decided unsigned duty data.
pub type Subscriber =
    Box<dyn Fn(Duty, pbcore::UnsignedDataSet) -> SubscriberResult + Send + Sync + 'static>;

/// Consensus implementation interface.
#[async_trait]
pub trait Consensus: Send + Sync {
    /// Returns the consensus protocol ID.
    fn protocol_id(&self) -> String;

    /// Starts the consensus implementation.
    fn start(&self, ct: CancellationToken);

    /// Starts participating in a consensus instance.
    async fn participate(&self, ct: CancellationToken, duty: Duty) -> Result<()>;

    /// Proposes unsigned duty data for a consensus instance.
    async fn propose(
        &self,
        ct: CancellationToken,
        duty: Duty,
        value: pbcore::UnsignedDataSet,
    ) -> Result<()>;

    /// Registers a callback for decided unsigned duty data.
    fn subscribe(&self, subscriber: Subscriber);
}

/// Wrapper that forwards calls to the current consensus implementation.
pub struct ConsensusWrapper {
    implementation: RwLock<Arc<dyn Consensus>>,
}

impl ConsensusWrapper {
    /// Wraps a consensus implementation.
    pub fn new(implementation: Arc<dyn Consensus>) -> Self {
        Self {
            implementation: RwLock::new(implementation),
        }
    }

    /// Sets the current consensus implementation.
    pub fn set_impl(&self, implementation: Arc<dyn Consensus>) {
        *self
            .implementation
            .write()
            .unwrap_or_else(PoisonError::into_inner) = implementation;
    }

    /// Returns the current consensus protocol ID.
    pub fn protocol_id(&self) -> String {
        self.current().protocol_id()
    }

    /// Starts the current consensus implementation.
    pub fn start(&self, ct: CancellationToken) {
        self.current().start(ct);
    }

    /// Starts participating in a consensus instance.
    pub async fn participate(&self, ct: CancellationToken, duty: Duty) -> Result<()> {
        self.current().participate(ct, duty).await
    }

    /// Proposes unsigned duty data for a consensus instance.
    pub async fn propose(
        &self,
        ct: CancellationToken,
        duty: Duty,
        value: pbcore::UnsignedDataSet,
    ) -> Result<()> {
        self.current().propose(ct, duty, value).await
    }

    /// Registers a callback for decided unsigned duty data.
    pub fn subscribe(&self, subscriber: Subscriber) {
        self.current().subscribe(subscriber);
    }

    fn current(&self) -> Arc<dyn Consensus> {
        self.implementation
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use pluto_core::{
        corepb::v1::core as pbcore,
        types::{Duty, SlotNumber},
    };

    use crate::protocols::QBFT_V2_PROTOCOL_ID;

    use super::*;

    #[tokio::test]
    async fn new_consensus_wrapper_forwards_to_current_impl() {
        let ct = CancellationToken::new();
        let duty = Duty::new_randao_duty(SlotNumber::new(123));
        let value = pbcore::UnsignedDataSet::default();
        let first = Arc::new(TestConsensus::new(QBFT_V2_PROTOCOL_ID));
        let wrapper = ConsensusWrapper::new(first.clone());

        assert_eq!(wrapper.protocol_id(), QBFT_V2_PROTOCOL_ID);

        wrapper
            .participate(ct.clone(), duty.clone())
            .await
            .expect("participate forwards");
        wrapper
            .propose(ct.clone(), duty.clone(), value)
            .await
            .expect("propose forwards");

        let subscribed = Arc::new(Mutex::new(Vec::new()));
        let subscribed_clone = Arc::clone(&subscribed);
        wrapper.subscribe(Box::new(move |duty, _| {
            subscribed_clone
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(duty);
            Ok(())
        }));

        wrapper.start(ct);

        assert_eq!(
            first.calls(),
            vec!["participate", "propose", "subscribe", "start"]
        );
        assert_eq!(
            subscribed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_slice(),
            &[duty]
        );

        let second = Arc::new(TestConsensus::new("foobar"));
        wrapper.set_impl(second);

        assert_eq!(wrapper.protocol_id(), "foobar");
    }

    struct TestConsensus {
        protocol_id: String,
        calls: Mutex<Vec<&'static str>>,
    }

    impl TestConsensus {
        fn new(protocol_id: &str) -> Self {
            Self {
                protocol_id: protocol_id.to_string(),
                calls: Mutex::default(),
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        fn record(&self, call: &'static str) {
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(call);
        }
    }

    #[async_trait]
    impl Consensus for TestConsensus {
        fn protocol_id(&self) -> String {
            self.protocol_id.clone()
        }

        fn start(&self, _ct: CancellationToken) {
            self.record("start");
        }

        async fn participate(&self, _ct: CancellationToken, _duty: Duty) -> Result<()> {
            self.record("participate");
            Ok(())
        }

        async fn propose(
            &self,
            _ct: CancellationToken,
            _duty: Duty,
            _value: pbcore::UnsignedDataSet,
        ) -> Result<()> {
            self.record("propose");
            Ok(())
        }

        fn subscribe(&self, subscriber: Subscriber) {
            self.record("subscribe");
            subscriber(
                Duty::new_randao_duty(SlotNumber::new(123)),
                pbcore::UnsignedDataSet::default(),
            )
            .expect("test subscriber succeeds");
        }
    }
}
