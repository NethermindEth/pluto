//! # Charon Core
//!
//! Core functionality and utilities for the Charon distributed validator node.
//! This crate provides the fundamental building blocks, data structures, and
//! core algorithms used throughout the Charon system.

pub mod qbft;
/// Types for the Charon core.
pub mod types;

/// Signed data wrappers and helpers.
pub mod signeddata;

/// Consensus-related functionality.
pub mod consensus;

/// Protobuf definitions.
pub mod corepb;

/// Semver version parsing utilities.
pub mod version;

/// Duty deadline tracking and notification.
pub mod deadline;

/// parsigdb
pub mod parsigdb;

mod parsigex_codec;
// SSZ codec operates on compile-time-constant byte sizes and offsets.
// Arithmetic is bounded and casts from `usize` to `u32` are safe because all
// sizes are well below `u32::MAX`.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
pub(crate) mod ssz_codec;

pub use parsigex_codec::ParSigExCodecError;

/// Test utilities.
#[cfg(test)]
pub mod testutils;
