//! # Charon Consensus
//!
//! Consensus-related functionality for the Charon distributed validator node.
//! This crate implements the consensus algorithms and protocols required for
//! coordinating validator operations across the distributed network.

/// Consensus protocols.
pub mod protocols;

/// Consensus instance I/O channels.
pub mod instance;
/// QBFT consensus wrapper.
pub mod qbft;

/// Consensus round timers.
pub mod timer;
