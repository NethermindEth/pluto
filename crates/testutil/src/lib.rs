//! # Charon Test Utilities
//!
//! Testing utilities and mock implementations for the Charon distributed
//! validator node. This crate provides test helpers, mock objects, and testing
//! utilities for unit tests, integration tests, and development.

// Raised so the large `json!` literals in `beaconmock::defaults::default_spec`
// expand without hitting the default macro recursion limit.
#![recursion_limit = "256"]

/// Random utilities.
pub mod random;

/// Beacon node API mock utilities.
pub mod beaconmock;

/// Validator mock — drives validator-side duties against a [`BeaconMock`].
pub mod validatormock;

pub use beaconmock::{BeaconMock, MockState, Validator, ValidatorSet};
pub use random::{
    random_deneb_versioned_attestation, random_eth2_signature, random_eth2_signature_bytes,
    random_root, random_root_bytes, random_slot, random_v_idx,
};
pub use validatormock::{
    ActiveValidators, EndpointMatch, Error as ValidatorMockError, MetaEpoch, MetaSlot,
    Result as ValidatorMockResult, Sign, SignError, SignFunc, Signer, SpecMeta, SubmissionCapture,
    active_validators,
};
