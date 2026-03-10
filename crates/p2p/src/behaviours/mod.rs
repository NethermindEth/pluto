//! Network behaviours for Charon P2P nodes.
//!
//! This module provides pre-configured network behaviours that combine multiple
//! libp2p protocols for use in Charon nodes.

#![allow(missing_docs)] // we need to allow missing docs for the derive macro

/// Pluto behaviour.
pub mod pluto;

/// Optional behaviour wrapper.
pub mod optional;

// Re-export autonat types for convenience
pub use libp2p::autonat;
