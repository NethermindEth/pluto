//! Regression for topic labels with the production tracing subscriber.

use pluto_tracing::{TracingConfig, init, metrics::TRACING_METRICS};

#[test]
fn default_info_filter_keeps_debug_topic_for_warn_metric() {
    // Use the production initializer, not a custom subscriber stack.
    let config = TracingConfig {
        override_env_filter: Some("info".into()),
        ..Default::default()
    };
    init(&config).expect("initialize the default tracing layers");

    let topic = String::from("init_info_filter_topic");
    let before = TRACING_METRICS.warn_total[&topic].get();
    let span = tracing::debug_span!("health", topic = "init_info_filter_topic");
    {
        let _guard = span.enter();
        tracing::warn!("warning from a debug-level topic span");
    }

    assert_eq!(
        TRACING_METRICS.warn_total[&topic].get(),
        before.saturating_add(1),
        "topic span disabled by the info console filter: {}",
        span.is_disabled()
    );
}
