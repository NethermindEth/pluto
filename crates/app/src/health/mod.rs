//! Application health checks.
//!
//! A background service that, every 30s, scrapes all process metrics, keeps a
//! rolling window of the last 10 scrapes, runs a fixed set of health checks
//! over that window (query a metric by name → select series by label → reduce
//! the time series to one number → compare to a threshold), and publishes the
//! per-check pass/fail state as the `app_health_checks{severity,name}` gauge
//! (1 = failing, 0 = ok). It also detects high-cardinality metrics and
//! publishes `app_health_metrics_high_cardinality{name}`.
//!
//! The module is split into `checker.rs`, `checks.rs` (with the check tests
//! inline), `select.rs`, `reducers.rs`, and `metrics.rs`. `model.rs`,
//! `error.rs`, and `gatherer.rs` provide the metric model, the error type, and
//! the registry-to-model bridge.

mod checker;
mod checks;
mod error;
mod gatherer;
mod metrics;
mod model;
mod reducers;
mod select;

pub use checker::Checker;
pub use checks::Metadata;
pub use error::{Error, Result};
pub use gatherer::{GatherError, Gatherer, ViseGatherer};
pub use metrics::{HEALTH_METRICS, HealthMetrics};
pub use model::{LabelPair, Metric, MetricFamily, MetricType};
