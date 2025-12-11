//! # Charon ETH2
//!
//! Ethereum 2.0 integration and utilities for the Charon distributed validator
//! node. This crate provides interfaces, types, and utilities for interacting
//! with Ethereum 2.0 networks and validator operations.

/// Ethereum 2.0 ENR utilities.
pub mod enr;

/// RLP utilities.
pub mod rlp;

/// EIP712 utilities.
pub mod eip712;

/// Network utilities.
pub mod network;

/// Utilities.
pub(crate) mod utils;
