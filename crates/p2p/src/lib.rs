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

/// Behaviours.
pub mod behaviours;

/// K1 utilities.
pub mod k1;

/// Multiaddr network utilities (manet).
pub mod manet;

/// Utilities.
pub mod utils;

/// Connection logger.
pub mod conn_logger;

/// Global context.
pub mod p2p_context;

/// QUIC connection upgrade behaviour.
pub mod quic_upgrade;

/// Force direct connection behaviour.
pub mod force_direct;
