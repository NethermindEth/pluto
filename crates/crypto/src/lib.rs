//! # Charon Crypto
//!
//! Cryptographic primitives and utilities for the Charon distributed validator
//! node. This crate provides cryptographic functions, key management, and
//! security operations required for distributed validator operations.
//!
//! This crate implements threshold BLS signatures compatible with the Herumi
//! BLS library used in the Go implementation, using the BLST library which
//! provides high-performance BLS12-381 cryptography.

/// BLST implementation of TBLS (Herumi-compatible)
pub mod blst_impl;

/// TBLS trait definition
pub mod tbls;

/// Error types and constants
pub mod types;
