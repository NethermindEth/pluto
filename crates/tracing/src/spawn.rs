//! Span-propagating task spawning.
//!
//! [`tokio::spawn`] does **not** carry the current [`tracing`] span into the
//! spawned future: the new task starts with an empty span stack. That breaks
//! the `topic` label used by [`crate::layers::metrics::MetricsLayer`], because
//! a `warn!`/`error!` emitted from a bare spawn lands on `topic=""` even when
//! the spawning code is inside a component's `topic` span.
//!
//! Charon derives the same label from `context.Context`, which *is* propagated
//! into goroutines. To restore context-like propagation here, wrap the spawned
//! future with [`tracing::Instrument`] and attach [`tracing::Span::current`].
//!
//! Prefer [`spawn`] over [`tokio::spawn`] in long-running components so that
//! the component's root `topic` span is inherited by its subtasks by default.

use std::future::Future;

use tokio::task::JoinHandle;
use tracing::Instrument as _;

/// Like [`tokio::spawn`], but attaches the current [`tracing::Span`] to the
/// spawned future so span context (and therefore the metrics `topic` label) is
/// propagated across the task boundary.
///
/// Use this instead of [`tokio::spawn`] when the calling code runs inside a
/// component's `topic` span and the spawned work should be attributed to the
/// same topic.
pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future.instrument(tracing::Span::current()))
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::layer::SubscriberExt as _;

    use crate::{layers::metrics::MetricsLayer, metrics::TRACING_METRICS};

    #[tokio::test]
    async fn spawn_propagates_topic_across_task_boundary() {
        let topic = "spawn_helper_propagation_test";
        let subscriber = tracing_subscriber::registry().with(MetricsLayer);

        let before = TRACING_METRICS.error_total[&topic.to_owned()].get();

        // `Instrument` captures both the span and the dispatcher at spawn time,
        // so the default subscriber set below applies to the spawned task.
        let guard = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("component", topic);
        let handle = {
            let _enter = span.enter();
            super::spawn(async {
                tracing::error!("boom from spawned task");
            })
        };
        handle.await.unwrap();

        drop(guard);

        let after = TRACING_METRICS.error_total[&topic.to_owned()].get();
        assert_eq!(
            after,
            before.saturating_add(1),
            "spawned task should inherit topic"
        );
    }

    #[tokio::test]
    async fn bare_tokio_spawn_loses_topic() {
        // Documents the behaviour the helper fixes: a bare spawn drops the
        // topic and is counted under the empty label.
        let topic = "spawn_helper_bare_test";
        let subscriber = tracing_subscriber::registry().with(MetricsLayer);

        let before = TRACING_METRICS.error_total[&topic.to_owned()].get();

        let guard = tracing::subscriber::set_default(subscriber);
        let span = tracing::info_span!("component", topic);
        let handle = {
            let _enter = span.enter();
            tokio::spawn(async {
                tracing::error!("boom from bare spawned task");
            })
        };
        handle.await.unwrap();
        drop(guard);

        let after = TRACING_METRICS.error_total[&topic.to_owned()].get();
        assert_eq!(after, before, "bare spawn must not inherit topic");
    }
}
