//! # Charon Cluster
//!
//! Cluster management and coordination for Charon distributed validator nodes.
//! This crate handles the formation, management, and coordination of validator
//! clusters in the Charon network.

/// Cluster definition management and coordination.
pub mod definition;
/// Cluster deposit management and coordination.
pub mod deposit;
/// Cluster distributed validator management and coordination.
pub mod distvalidator;
/// Cluster EIP-712 signatures management and coordination.
pub mod eip712sigs;
/// Cluster helpers management and coordination.
pub mod helpers;
/// Cluster lock management and coordination.
pub mod lock;
/// Manifest
pub mod manifest;
/// Manifest protocol buffers.
pub mod manifestpb;
/// Cluster operator management and coordination.
pub mod operator;
/// Cluster registration management and coordination.
pub mod registration;
/// Cluster SSZ management and coordination.
pub mod ssz;
/// Cluster SSZ hashing management and coordination.
pub mod ssz_hasher;
/// Cluster test cluster management and coordination.
#[cfg(test)]
pub mod test_cluster;
/// Cluster version management and coordination.
pub mod version;
