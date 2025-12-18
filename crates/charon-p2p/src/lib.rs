//! # Charon P2P
//!
//! Peer-to-peer networking and communication for the Charon distributed
//! validator node. This crate provides networking protocols, peer discovery,
//! and communication mechanisms for validator nodes to coordinate and exchange
//! information.

/// Peer-related types and utilities.
pub mod peer;

/// Name-related types and utilities.
pub mod name;

/// P2P configuration.
pub mod config;

/// Metrics.
pub mod metrics;

/// P2P.
pub mod p2p;

/// Gater
pub mod gater;
