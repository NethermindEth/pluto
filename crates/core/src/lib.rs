//! # Charon Core
//!
//! Core functionality and utilities for the Charon distributed validator node.
//! This crate provides the fundamental building blocks, data structures, and
//! core algorithms used throughout the Charon system.

pub mod qbft;
/// Types for the Charon core.
pub mod types;

/// Unsigned duty data decoding.
pub mod unsigneddata;

/// Signed data wrappers and helpers.
pub mod signeddata;

/// Protobuf definitions.
pub mod corepb;

/// Semver version parsing utilities.
pub mod version;

/// Duty deadline tracking and notification.
pub mod deadline;

/// Clock abstraction over the current time.
pub mod clock;

/// Duty gater — rejects duties whose type is invalid or that are too far in the
/// future.
pub mod gater;

/// parsigdb
pub mod parsigdb;

/// DutyDB — in-memory store for unsigned duty data.
pub mod dutydb;

/// ValidatorAPI — HTTP router that serves the validator-facing beacon API
/// subset related to distributed validation and proxies the rest upstream.
pub mod validatorapi;

/// SigAgg — threshold BLS signature aggregation.
pub mod sigagg;

/// Resolves beacon-chain duties per epoch, ticks the slot clock, and fans
/// duties out to downstream components.
pub mod scheduler;

/// Implementations of AggSigDB.
pub mod aggsigdb;

/// Broadcaster for aggregate signed duty data.
pub mod bcast;

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
