//! # Charon Cluster
//!
//! Cluster management and coordination for Charon distributed validator nodes.
//! This crate handles the formation, management, and coordination of validator
//! clusters in the Charon network.

/// `Definition` type representing the intended cluster configuration
/// (operators, validators, fork version) with EIP-712 hashing and verification.
pub mod definition;
/// `DepositData` type for activating validators.
pub mod deposit;
/// `DistValidator` type representing a distributed validator with its group
/// public key, per-node public shares, and deposit data.
pub mod distvalidator;
/// EIP-712 typed data construction and signing for cluster definition config
/// hashes and operator ENR signatures.
pub mod eip712sigs;
/// General helper utilities.
pub mod helpers;
/// `Lock` type representing the finalized cluster configuration, including
/// distributed validators and node signatures.
pub mod lock;
/// Cluster manifest types, loading, mutation, and materialization.
pub mod manifest;
/// Generated protobuf types for the cluster manifest (v1).
pub mod manifestpb;
/// `Operator` type representing a charon node operator with Ethereum address,
/// ENR, and config/ENR signatures.
pub mod operator;
/// `BuilderRegistration` and `Registration` types for pre-generated signed
/// validator registrations sent to the builder network.
pub mod registration;
/// SSZ serialization for various cluster types.
pub mod ssz;
/// Core SSZ utilities.
pub mod ssz_hasher;
/// Factory for constructing deterministic or random cluster locks for use in
/// tests.
#[cfg(any(test, feature = "test-cluster"))]
pub mod test_cluster;
/// Supported cluster definition version constants and feature-flag helpers.
pub mod version;
