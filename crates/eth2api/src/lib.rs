//! # Eth2Api
//!
//! Abstraction to multiple Ethereum 2 beacon nodes. Its external API follows
//! the official [Ethereum beacon APIs specification](https://ethereum.github.io/beacon-APIs/).

#[allow(missing_docs)]
pub mod client;

#[allow(missing_docs)]
pub mod types;

pub use client::*;
pub use types::*;

#[cfg(test)]
#[cfg(feature = "integration")]
mod integration;
