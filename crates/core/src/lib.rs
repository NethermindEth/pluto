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

/// Clock abstraction over the current time.
pub mod clock;

/// parsigdb
pub mod parsigdb;

/// DutyDB — in-memory store for unsigned duty data.
pub mod dutydb;

/// ValidatorAPI — HTTP router that serves the validator-facing beacon API
/// subset related to distributed validation and proxies the rest upstream.
pub mod validatorapi;

/// SigAgg — threshold BLS signature aggregation.
pub mod sigagg;

/// Implementations of AggSigDB.
pub mod aggsigdb;

mod parsigex_codec;

// SSZ codec operates on compile-time-constant byte sizes and offsets.
// Arithmetic is bounded and casts from `usize` to `u32` are safe because all
// sizes are well below `u32::MAX`.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
pub(crate) mod ssz_codec;

pub use parsigex_codec::ParSigExCodecError;

/// Duty lifecycle tracker — monitors workflow steps and reports failures and
/// participation.
pub mod tracker;

/// Test utilities.
#[cfg(test)]
pub mod testutils;
