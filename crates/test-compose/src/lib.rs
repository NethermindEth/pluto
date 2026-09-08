//! Docker-compose cluster generator for smoke testing pluto and charon nodes.
//!
//! A cluster is produced in steps; each reads `config.json` from the compose
//! directory, advances its `step` and rewrites `docker-compose.yml`:
//!
//! 1. `define` writes the key-generation compose file, the static monitoring
//!    configs and the Prometheus scrape and alert-rule files.
//! 2. `lock` writes the cluster-lock compose file (`create cluster` or `dkg`).
//! 3. `run` writes the compose file that runs nodes, validator clients, relay
//!    and monitoring.
//!
//! [`auto`] chains the steps against a docker daemon and watches Prometheus
//! for alerts; [`smoke`] holds the scenario matrix.

// Test infrastructure: item names and error strings carry the meaning.
#![allow(missing_docs)]

mod alert;
mod auto;
mod config;
mod define;
mod duration;
mod error;
mod fsutil;
mod lock;
mod process;
mod run;
pub mod smoke;
mod static_files;
mod template;

#[cfg(test)]
mod golden_tests;

pub use auto::{AutoConfig, auto};
pub use config::{Config, PLUTO_REPO_ENV, write_config};
pub use error::{ComposeError, Result};
pub use fsutil::env_non_empty;
