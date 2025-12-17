use backon::{BackoffBuilder, Retryable};
use std::{sync::Arc, time::Duration};

/// TODO
#[derive(Clone)]
pub struct AsyncOptions<T> {
    backoff_builder: backon::ExponentialBuilder,
    deadline_fn: Arc<dyn Fn(T) -> Option<chrono::DateTime<chrono::Utc>> + Send + Sync>,
    time_fn: Arc<dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync>,
}

impl<T> AsyncOptions<T> {
    /// TODO
    pub fn with_backoff(mut self, backoff_builder: backon::ExponentialBuilder) -> Self {
        self.backoff_builder = backoff_builder;
        self
    }

    /// TODO
    pub fn with_deadline(
        mut self,
        deadline_fn: impl Fn(T) -> Option<chrono::DateTime<chrono::Utc>> + Send + Sync + 'static,
    ) -> Self {
        self.deadline_fn = Arc::new(deadline_fn);
        self
    }

    /// TODO
    pub fn with_time(
        mut self,
        time_fn: impl Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync + 'static,
    ) -> Self {
        self.time_fn = Arc::new(time_fn);
        self
    }
}

impl<T> Default for AsyncOptions<T> {
    fn default() -> Self {
        Self {
            backoff_builder: backon::ExponentialBuilder::default()
                .with_min_delay(Duration::from_millis(250))
                .with_max_delay(Duration::from_secs(12))
                .with_factor(1.6)
                .without_max_times()
                .with_jitter(),
            deadline_fn: Arc::new(|_| None),
            time_fn: Arc::new(|| chrono::Utc::now()),
        }
    }
}

/// Execute a provided function with retries and a maximum timeout according to
/// the provided options.
///
/// Intended to be used withing a `tokio` task:
/// ```ignore
/// tokio::spawn(retry::do_async(...))
/// ```
pub async fn do_async<T, E, A, Fut: Future<Output = Result<A, E>>, FutureFn: FnMut() -> Fut>(
    options: AsyncOptions<T>,
    t: T,
    topic: &'static str,
    name: &'static str,
    future: FutureFn,
) {
    let deadline = (options.deadline_fn)(t);
    let now = (options.time_fn)();

    let total_delay = deadline.and_then(|deadline| (deadline - now).to_std().ok());

    let mut backoff = options
        .backoff_builder
        .clone()
        .with_total_delay(total_delay)
        .build();

    let _result = future
        .retry(&mut backoff)
        // TODO: Use correct when (check errors, check cancellation, etc.)
        .when(|_| true)
        // TODO: Trace/Log retry attempts
        .notify(|_, _| println!("Retrying: {}/{}", topic, name))
        .await;
}
