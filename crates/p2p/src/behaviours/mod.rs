//! Network behaviours for Charon P2P nodes.
//!
//! This module provides pre-configured network behaviours that combine multiple
//! libp2p protocols for use in Charon nodes.
//!
//! # Available Behaviours
//!
//! - [`PlutoBehaviour`](pluto::PlutoBehaviour): Core behaviour with relay,
//!   identify, ping, and AutoNAT
//! - [`PlutoMdnsBehaviour`](pluto_mdns::PlutoMdnsBehaviour): Extends
//!   `PlutoBehaviour` with mDNS discovery (requires `mdns` feature)

#![allow(missing_docs)] // we need to allow missing docs for the derive macro

/// Pluto behaviour.
pub mod pluto;

#[cfg(feature = "mdns")]
/// Pluto Mdns behaviour.
pub mod pluto_mdns;

/// Optional behaviour wrapper.
pub mod optional;

// Re-export autonat types for convenience
pub use libp2p::autonat;
