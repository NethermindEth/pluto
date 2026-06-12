//! QBFT consensus wrapper.

mod component;
pub(crate) mod definition;
pub(crate) mod runner;

pub use component::{
    BroadcastResult, Broadcaster, Config, Consensus, DutyGater, Error, Peer, Result, SnifferSink,
    SubscriberResult,
};
pub use runner::{Error as RunnerError, Result as RunnerResult};

/// QBFT protobuf message wrapper.
pub mod msg;

/// Concrete libp2p adapter for QBFT consensus messages.
pub mod p2p;

pub(crate) mod sniffer;
pub(crate) mod transport;

#[cfg(test)]
// QBFT tests override pluto_featureset::GLOBAL_STATE to exercise feature-gated
// paths. Since that state is process-global, those tests must serialize their
// mutations until the feature set is threaded as an explicit dependency.
pub(crate) static FEATURESET_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod qbft_run_test;
#[cfg(test)]
mod strategy_sim_test;
