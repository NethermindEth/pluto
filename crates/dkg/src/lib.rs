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

/// Partial-signature verification and aggregation helpers.
mod aggregate;

/// General DKG IO operations.
pub mod disk;

/// Main DKG protocol implementation.
pub mod dkg;

/// Partial-signature exchanger for DKG.
pub mod exchanger;

/// Node signature exchange over the lock hash.
pub mod nodesigs;

/// Lock publishing helpers.
mod publish;

/// Shares distributed to each node in the cluster.
pub mod share;

/// Step synchronization protocol for DKG peers.
pub mod sync;

/// FROST round-1 direct P2P stream behaviour.
pub mod frostp2p;

/// Compound DKG libp2p node setup.
pub mod node;

/// FROST DKG orchestration and P2P transport.
pub mod frost;

/// Post-DKG signing and aggregation.
pub mod signing;

/// Registration conversion and distributed-validator assembly helpers.
mod validators;
