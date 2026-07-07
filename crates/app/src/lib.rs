//! # Charon
//!
//! The main Charon library providing distributed validator key management and
//! coordination for Ethereum 2.0 validators. This crate serves as the primary
//! entry point for the Charon distributed validator node implementation.

/// Log
pub mod log;

/// Provides a generic async function [`retry::do_async`] executor with retries
/// for robustness against network failures. Functions are linked to a deadline,
/// executed asynchronously and network errors are retried with backoff
/// until the deadline has elapsed.
pub mod retry;

/// Obol API client for interacting with the Obol network API.
pub mod obolapi;

/// Monitoring API endpoints for process liveness and readiness.
pub mod monitoringapi;

/// Ethereum CL RPC client management.
pub mod eth2wrap;

/// Private key locking service.
pub mod privkeylock;

/// Validator-stack process sniper: periodically scans a `/proc`-like
/// filesystem for running Ethereum validator stack processes and reports the
/// detected component names and CLI parameters through a callback.
pub mod stacksnipe;

/// Listen for SSE from Beacon Node
pub mod sse;

/// Utility helpers for archiving, extracting, and comparing files/directories.
pub mod utils;

/// Application health checks: periodically scrapes process metrics, evaluates a
/// fixed set of checks over a rolling window, and publishes per-check pass/fail
/// state as the `app_health_checks` gauge.
pub mod health;
