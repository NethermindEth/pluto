//! # Charon
//!
//! The main Charon library providing distributed validator key management and
//! coordination for Ethereum 2.0 validators. This crate serves as the primary
//! entry point for the Charon distributed validator node implementation.

/// Peerinfo.
pub mod peerinfo;

/// Log
pub mod log;

/// Retry
pub mod retry;

/// Deadline
pub mod deadline;

/// Ethereum EL RPC client management
pub mod eth1wrap;
