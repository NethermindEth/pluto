//! # Charon
//!
//! The main Charon library providing distributed validator key management and
//! coordination for Ethereum 2.0 validators. This crate serves as the primary
//! entry point for the Charon distributed validator node implementation.

/// Peerinfo.
pub mod peerinfo;

/// Log
pub mod log;

/// Provides a generic async function [`do_async`] executor with retries for
/// robustness against network failures. Functions are linked to a deadline,
/// executed asynchronously and network errors are retried with backoff
/// until the deadline has elapsed.
pub mod retry;

/// Deadline
pub mod deadline;

/// Ethereum EL RPC client management
pub mod eth1wrap;
