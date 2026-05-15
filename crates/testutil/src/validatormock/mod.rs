//! Validator mock — Rust port of `charon/testutil/validatormock`.
//!
//! Drives validator-side duties (block proposal, attestation, aggregation,
//! sync-committee messages and contributions) against a [`crate::BeaconMock`].
//! Ported file-per-concern to match the Go layout; mirror functional behavior
//! while using idiomatic Rust async primitives.

pub mod attest;
pub mod capture;
pub mod error;
pub mod meta;
pub mod sign;
pub mod validators;

pub use attest::{AttesterDuty, BeaconCommitteeSelection, SlotAttester};
pub use capture::{EndpointMatch, SubmissionCapture};
pub use error::{Error, Result, SignError};
pub use meta::{MetaEpoch, MetaSlot, SpecMeta};
pub use sign::{Sign, SignFunc, Signer};
pub use validators::{ActiveValidators, active_validators};
