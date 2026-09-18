//! Network behaviours for Charon P2P nodes.
//!
//! This module provides pre-configured network behaviours that combine multiple
//! libp2p protocols for use in Charon nodes.

#![expect(
    missing_docs,
    reason = "the NetworkBehaviour derive macro generates undocumented items"
)]

/// Pluto behaviour.
pub mod pluto;

/// Optional behaviour wrapper.
pub mod optional;

// Re-export autonat types for convenience
pub use libp2p::autonat;
