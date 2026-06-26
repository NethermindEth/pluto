//! QBFT consensus wrapper.

mod component;
pub(crate) mod definition;
pub(crate) mod runner;

pub use component::{
    BroadcastResult, Broadcaster, Config, Consensus, Error, Peer, Result, SnifferSink,
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
mod qbft_run_test;
#[cfg(test)]
mod strategy_sim_test;
