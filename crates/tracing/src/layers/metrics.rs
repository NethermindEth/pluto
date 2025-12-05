use crate::metrics::TRACING_METRICS;

/// Metrics layer.
pub struct MetricsLayer;

fn inc_error_count() {
    TRACING_METRICS.error_count.inc();
}

fn inc_warn_count() {
    TRACING_METRICS.warn_count.inc();
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for MetricsLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // check level
        match event.metadata().level() {
            &tracing::Level::ERROR => {
                inc_error_count();
            }
            &tracing::Level::WARN => {
                inc_warn_count();
            }
            _ => {
                // do nothing
            }
        }
    }
}
