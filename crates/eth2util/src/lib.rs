//! # Pluto ETH2
//!
//! Ethereum 2.0 integration and utilities for the Pluto distributed validator
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

/// Deposit data creation and management.
pub mod deposit;

/// Ethereum address helpers.
pub mod helpers;

/// EIP-2335 keystore management.
pub mod keystore;
/// Validator registration for builder API.
pub mod registration;

/// Shared eth2 signing helpers.
pub mod signing;

/// ETH2 Keymanager API client.
pub mod keymanager;

/// Go-parity type/version conversion helpers.
pub mod types;

/// Utilities.
pub(crate) mod utils;
