//! # Charon Observability
//!
//! Observability and monitoring utilities for the Charon distributed validator
//! node. This crate provides logging, metrics, tracing, and monitoring
//! capabilities for tracking and debugging validator operations.

/// Configuration for the tracing.
pub mod config;

/// Initialization for the tracing.
pub mod init;

/// Layers for the tracing.
pub mod layers;

/// Metrics for the tracing.
pub mod metrics;

pub use config::{ConsoleConfig, LokiConfig, TracingConfig, TracingConfigBuilder};

pub use init::init;
