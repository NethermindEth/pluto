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

#[cfg(test)]
#[cfg(feature = "integration")]
mod integration;
