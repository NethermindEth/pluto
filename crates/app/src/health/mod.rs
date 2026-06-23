//! Application health checks.
//!
//! A background service that, every [`SCRAPE_PERIOD`], scrapes all process
//! metrics, keeps a rolling window of the last [`MAX_SCRAPES`] scrapes, runs a
//! fixed set of health checks over that window (query a metric by name → select
//! series by label → reduce the time series to one number → compare to a
//! threshold), and publishes the per-check pass/fail state as the
//! `app_health_checks{severity,name}` gauge (1 = failing, 0 = ok). It also
//! detects high-cardinality metrics and publishes
//! `app_health_metrics_high_cardinality{name}`.

mod checker;
mod checks;
mod error;
mod gatherer;
mod metrics;
mod model;
mod reducers;
mod select;

pub use checker::Checker;
pub use error::{Error, Result};
pub use gatherer::{GatherError, Gatherer, ViseGatherer};
pub use metrics::{HEALTH_METRICS, HealthMetrics};
pub use model::{LabelPair, Metric, MetricFamily, MetricType};

use std::time::Duration;

/// Period between metric scrapes.
const SCRAPE_PERIOD: Duration = Duration::from_secs(30);

/// Maximum number of scrapes retained in the rolling window.
const MAX_SCRAPES: usize = 10;

/// High-cardinality threshold for a single validator; for `n` validators the
/// effective threshold is `LABELS_CARDINALITY_THRESHOLD * n`.
const LABELS_CARDINALITY_THRESHOLD: usize = 100;

/// Severity of a health check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Severity {
    /// Critical: the node is likely not performing its duties.
    Critical,
    /// Warning: something needs attention.
    Warning,
    /// Info: informational only.
    Info,
}

impl Severity {
    /// Returns the lowercase string used as the `severity` label value.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }
}

/// Metadata about the cluster, used by the health checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct Metadata {
    /// Number of validators in the cluster.
    pub num_validators: i64,
    /// Number of peers in the cluster.
    pub num_peers: i64,
    /// Number of peers required for quorum.
    pub quorum_peers: i64,
}
