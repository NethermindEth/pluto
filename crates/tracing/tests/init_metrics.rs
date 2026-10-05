//! Regression for topic labels with the production tracing subscriber.

use pluto_tracing::{TracingConfig, init, metrics::TRACING_METRICS};

#[test]
fn default_info_filter_keeps_debug_topic_for_log_metrics() {
    // Use the production initializer, not a custom subscriber stack.
    let config = TracingConfig {
        override_env_filter: Some("info".into()),
        ..Default::default()
    };
    // Global subscriber is initialized here so this binary can only hold this
    // test.
    init(&config).expect("initialize the default tracing layers");
    assert!(
        !tracing::enabled!(tracing::Level::DEBUG),
        "metrics filter must not enable DEBUG callsites at info"
    );
    assert!(
        tracing::debug_span!("no_topic").is_disabled(),
        "metrics filter must not enable spans without a topic"
    );
    assert!(
        !tracing::trace_span!("trace_topic", topic = "init_trace_topic").is_disabled(),
        "metrics filter must enable topic spans at any level"
    );

    let topic = String::from("init_info_filter_topic");
    let warns_before = TRACING_METRICS.warn_total[&topic].get();
    let errors_before = TRACING_METRICS.error_total[&topic].get();
    let span = tracing::debug_span!("health", topic = "init_info_filter_topic");
    {
        let _guard = span.enter();
        tracing::warn!("warning from a debug-level topic span");
        tracing::error!("error from a debug-level topic span");
    }

    assert_eq!(
        TRACING_METRICS.warn_total[&topic].get(),
        warns_before.saturating_add(1),
        "topic span disabled by the info console filter: {}",
        span.is_disabled()
    );
    assert_eq!(
        TRACING_METRICS.error_total[&topic].get(),
        errors_before.saturating_add(1),
        "topic span disabled by the info console filter: {}",
        span.is_disabled()
    );
}
