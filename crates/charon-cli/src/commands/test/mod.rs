//! Test command module for cluster evaluation.
//!
//! This module provides a comprehensive test suite to evaluate the current
//! cluster setup, including tests for peers, beacon nodes, validator clients,
//! MEV relays, and infrastructure.

pub mod all;
pub mod beacon;
pub mod config;
pub mod infra;
pub mod mev;
pub mod output;
pub mod peers;
pub mod scoring;
pub mod types;
pub mod validator;

// Re-export main types
pub use config::TestConfigArgs;
pub use types::{
    CategoryScore, Duration, TestCategoryResult, TestResult, TestResultError, TestVerdict,
};
