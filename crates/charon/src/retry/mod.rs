use backon::{BackoffBuilder, Retryable};
use std::{
    sync::Arc,
    time::{self, Duration},
};

/// TODO
#[derive(Clone)]
pub struct AsyncOptions<T> {
    backoff_builder: backon::ExponentialBuilder,
    timeout_builder: Arc<dyn Fn(T) -> Option<time::Duration> + Send + Sync>,
}

impl<T> AsyncOptions<T> {
    /// TODO
    pub fn new(timeout_fn: impl Fn(T) -> Option<time::Duration> + Send + Sync + 'static) -> Self {
        Self {
            backoff_builder: backon::ExponentialBuilder::default()
                .with_min_delay(Duration::from_millis(250))
                .with_max_delay(Duration::from_secs(12))
                .with_factor(1.6)
                .without_max_times()
                .with_jitter(),
            timeout_builder: Arc::new(timeout_fn),
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
    let timeout = (options.timeout_builder)(t);
    let mut backoff = options
        .backoff_builder
        .clone()
        .with_total_delay(timeout)
        .build();

    let _result = future
        .retry(&mut backoff)
        // TODO: Use correct when (check errors, check cancellation, etc.)
        .when(|_| true)
        // TODO: Trace/Log retry attempts
        .notify(|_, _| println!("Retrying: {}/{}", topic, name))
        .await;
}

#[cfg(test)]
mod tests {
    use backon::{BackoffBuilder, ExponentialBuilder, Retryable};

    async fn request() -> std::result::Result<(), Box<dyn std::error::Error>> {
        Err("error".into())
    }

    #[tokio::test]
    async fn it_works() {
        let mut eb: backon::ExponentialBackoff = ExponentialBuilder::default()
            .with_min_delay(std::time::Duration::from_millis(100))
            .without_max_times()
            .with_max_delay(std::time::Duration::from_secs(3))
            .build();

        let _ = request
            .retry(&mut eb)
            .notify(|err, d| println!("Retrying: {err:?} - {d:?}"))
            .await;
    }
}
