//! # Charon DKG
//!
//! Distributed Key Generation (DKG) protocols for Charon distributed validator
//! nodes. This crate implements the cryptographic protocols required for
//! generating, distributing, and managing validator keys across the distributed
//! network.

/// Protobuf definitions.
pub mod dkgpb;

/// Reliable broadcast protocol for DKG messages.
pub mod bcast;

/// General DKG IO operations.
pub mod disk;

/// Main DKG protocol implementation.
pub mod dkg;

/// Node signature exchange over the lock hash.
pub mod nodesigs;

/// Shares distributed to each node in the cluster.
pub mod share;
