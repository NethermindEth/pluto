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

/// parasigdb
pub mod parasigdb;

/// Test utilities.
#[cfg(test)]
pub mod testutils;
