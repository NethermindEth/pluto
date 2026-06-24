//! Prometheus metrics published by the health checker.

use vise::{Gauge, Global, LabeledFamily, Metrics};

/// Health metrics published by the checker.
///
/// Emitted (after vise's `_total`-strip / Prometheus naming) as
/// `app_health_checks{severity,name}` and
/// `app_health_metrics_high_cardinality{name}`.
#[derive(Debug, Metrics)]
#[metrics(prefix = "app_health")]
pub struct HealthMetrics {
    /// Application health checks by name and severity. Set to 1 for failing, 0
    /// for ok
    #[metrics(labels = ["severity", "name"])]
    pub checks: LabeledFamily<(String, String), Gauge, 2>,

    /// Metrics with high cardinality by name
    #[metrics(labels = ["name"])]
    pub metrics_high_cardinality: LabeledFamily<String, Gauge>,
}

/// Global health metrics.
#[vise::register]
pub static HEALTH_METRICS: Global<HealthMetrics> = Global::new();
