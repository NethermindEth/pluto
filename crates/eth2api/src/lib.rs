//! # Eth2Api
//!
//! Abstraction to multiple Ethereum 2 beacon nodes. Its external API follows
//! the official [Ethereum beacon APIs specification](https://ethereum.github.io/beacon-APIs/).

#[allow(missing_docs)]
#[allow(clippy::all)]
#[rustfmt::skip]
pub mod client;

#[allow(missing_docs)]
#[allow(clippy::all)]
#[rustfmt::skip]
pub mod types;

pub use client::*;
pub use types::*;

/// Additional data types and functions to reduce the boilerplate when
/// interacting with `eth2api`.
pub mod extensions;

pub use extensions::*;

/// Ethereum 2.0 consensus layer specification types.
pub mod spec;

/// API v1 types from the Ethereum beacon chain and builder API specifications.
pub mod v1;

#[cfg(test)]
#[cfg(feature = "integration")]
mod integration;
