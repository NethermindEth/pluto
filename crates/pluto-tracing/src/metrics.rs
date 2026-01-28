use vise::{Counter, Metrics};

/// Metrics for the tracing.
#[derive(Debug, Metrics)]
pub struct TracingMetrics {
    /// Error count.
    pub error_count: Counter,

    /// Warn count.
    pub warn_count: Counter,
}

/// Global metrics for the tracing.
#[vise::register]
pub static TRACING_METRICS: vise::Global<TracingMetrics> = vise::Global::new();
