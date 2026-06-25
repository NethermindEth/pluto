//! Distributed-validator node wiring.
//!
//! This module is the Rust analog of Charon's `app/app.go`: it constructs every
//! core duty-workflow component, connects them together (the analog of Charon's
//! `core.Wire`), composes the P2P behaviours, and runs the node until cancelled.

pub mod config;

pub use config::AppConfig;
