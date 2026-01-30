//! Behaviours.
#![allow(missing_docs)] // we need to allow missing docs for the derive macro

/// Pluto behaviour.
pub mod pluto;

#[cfg(feature = "mdns")]
/// Pluto Mdns behaviour.
pub mod pluto_mdns;
