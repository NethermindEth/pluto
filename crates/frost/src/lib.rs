//! Kryptology-compatible FROST DKG and BLS threshold signing over BLS12-381 G1.
//! This crate implements a distributed key generation protocol compatible with
//! Go's Coinbase Kryptology FROST DKG, and BLS threshold signing (Ethereum 2.0
//! compatible).

#![allow(non_snake_case)]
#![doc = include_str!("../dkg.md")]

extern crate alloc;

pub mod curve;
pub mod frost_core;
pub mod kryptology;

pub use curve::*;
pub use frost_core::*;
pub use rand_core;

#[cfg(test)]
mod tests;
