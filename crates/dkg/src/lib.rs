//! # Charon DKG
//!
//! Distributed Key Generation (DKG) protocols for Charon distributed validator
//! nodes. This crate implements the cryptographic protocols required for
//! generating, distributing, and managing validator keys across the distributed
//! network.

/// Protobuf definitions.
pub mod dkgpb;

/// General DKG IO operations.
pub mod disk;

/// Main DKG protocol implementation.
pub mod dkg;

/// Shares distributed to each node in the cluster.
pub mod share;
