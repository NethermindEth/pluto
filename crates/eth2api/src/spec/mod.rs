//! Ethereum 2.0 consensus layer specification types.
//! These types are maintained in parity with `go-eth2-client` spec structures.

/// Shared serde helpers for spec-compatible JSON.
pub mod serde_utils;

/// Spec-level version enums.
pub mod version;
pub use version::{
    BuilderVersion, DataVersion, VersionError, serde_legacy_builder_version,
    serde_legacy_data_version,
};

/// Phase 0 consensus types from the Ethereum beacon chain specification.
pub mod phase0;

/// Altair consensus types from the Ethereum beacon chain specification.
pub mod altair;

/// Bellatrix consensus types from the Ethereum beacon chain specification.
pub mod bellatrix;

/// Capella consensus types from the Ethereum beacon chain specification.
pub mod capella;

/// Deneb consensus types from the Ethereum beacon chain specification.
pub mod deneb;

/// Electra consensus types from the Ethereum beacon chain specification.
pub mod electra;

/// Fulu consensus types from the Ethereum beacon chain specification.
pub mod fulu;
