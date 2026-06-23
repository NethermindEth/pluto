use vise::{Counter, LabeledFamily, Metrics};

/// Metrics for the tracing.
///
/// Emitted as `app_log_error_total{topic}` / `app_log_warn_total{topic}`,
/// matching Charon's `app/log` metrics (name, `_total` suffix, and `topic`
/// label), so Charon's Grafana dashboards and the health checker pick them up
/// by their Charon names.
#[derive(Debug, Metrics)]
#[metrics(prefix = "app_log")]
pub struct TracingMetrics {
    /// Total count of logged errors by topic
    #[metrics(labels = ["topic"])]
    pub error_total: LabeledFamily<String, Counter>,

    /// Total count of logged warnings by topic
    #[metrics(labels = ["topic"])]
    pub warn_total: LabeledFamily<String, Counter>,
}

/// Global metrics for the tracing.
#[vise::register]
pub static TRACING_METRICS: vise::Global<TracingMetrics> = vise::Global::new();
