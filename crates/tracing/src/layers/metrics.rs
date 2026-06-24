use std::fmt;

use tracing::{
    field::{Field, Visit},
    span::{Attributes, Id},
};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

use crate::metrics::TRACING_METRICS;

/// Metrics layer: counts error/warn log events, labelled by `topic`, into
/// `app_log_{error,warn}_total{topic}`.
pub struct MetricsLayer;

/// The `topic` field value recorded for a span.
struct SpanTopic(String);

/// Records the `topic` span field, if present.
struct TopicVisitor(Option<String>);

impl Visit for TopicVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "topic" {
            self.0 = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "topic" && self.0.is_none() {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

/// Returns the `topic` of the nearest enclosing span, or empty when none is
/// set.
fn event_topic<S>(ctx: &Context<'_, S>, event: &tracing::Event<'_>) -> String
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    for span in ctx.event_scope(event).into_iter().flatten() {
        if let Some(topic) = span.extensions().get::<SpanTopic>() {
            return topic.0.clone();
        }
    }
    String::new()
}

impl<S> Layer<S> for MetricsLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut visitor = TopicVisitor(None);
        attrs.record(&mut visitor);
        if let Some(topic) = visitor.0
            && let Some(span) = ctx.span(id)
        {
            span.extensions_mut().insert(SpanTopic(topic));
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let level = *event.metadata().level();
        if level != tracing::Level::ERROR && level != tracing::Level::WARN {
            return;
        }

        let topic = event_topic(&ctx, event);
        match level {
            tracing::Level::ERROR => {
                TRACING_METRICS.error_total[&topic].inc();
            }
            tracing::Level::WARN => {
                TRACING_METRICS.warn_total[&topic].inc();
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt as _;

    #[test]
    fn counts_errors_and_warns_by_topic() {
        // Unique topic so the global counter is touched only by this test.
        let topic = "metrics_layer_test_topic";
        let subscriber = tracing_subscriber::registry().with(MetricsLayer);

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("test", topic);
            let _guard = span.enter();
            tracing::error!("an error");
            tracing::warn!("a warning");
            tracing::info!("ignored");
        });

        assert_eq!(TRACING_METRICS.error_total[&topic.to_owned()].get(), 1);
        assert_eq!(TRACING_METRICS.warn_total[&topic.to_owned()].get(), 1);
    }

    #[test]
    fn events_without_topic_use_empty_label() {
        let subscriber = tracing_subscriber::registry().with(MetricsLayer);

        let before = TRACING_METRICS.error_total[&String::new()].get();
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!("no topic");
        });
        let after = TRACING_METRICS.error_total[&String::new()].get();

        assert!(after > before);
    }
}
