//! # Charon Test Utilities
//!
//! Testing utilities and mock implementations for the Charon distributed
//! validator node. This crate provides test helpers, mock objects, and testing
//! utilities for unit tests, integration tests, and development.

/// Random utilities.
pub mod random;

pub use random::{
    random_deneb_versioned_attestation, random_eth2_signature, random_eth2_signature_bytes,
    random_root, random_root_bytes, random_slot, random_v_idx,
};
