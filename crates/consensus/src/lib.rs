//! # Charon Consensus
//!
//! Consensus-related functionality for the Charon distributed validator node.
//! This crate implements the consensus algorithms and protocols required for
//! coordinating validator operations across the distributed network.

/// Consensus protocol controller.
pub mod controller;

/// Consensus debug message buffer.
pub mod debugger;

/// Consensus protocols.
pub mod protocols;

/// Consensus instance I/O channels.
pub mod instance;
/// Consensus metrics.
pub mod metrics;
/// QBFT consensus wrapper.
pub mod qbft;

/// Consensus round timers.
pub mod timer;

/// Swappable consensus implementation wrapper.
pub mod wrapper;
