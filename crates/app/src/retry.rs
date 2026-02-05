use backon::{BackoffBuilder, Retryable};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, warn};

/// Options for the asynchronous retry executor.
#[derive(Clone)]
pub struct AsyncOptions<T> {
    backoff_builder: backon::ExponentialBuilder,
    deadline_fn: Arc<dyn Fn(T) -> Option<chrono::DateTime<chrono::Utc>> + Send + Sync>,
    time_fn: Arc<dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync>,
    cancellation_token: Option<CancellationToken>,
}

impl<T> AsyncOptions<T> {
    /// Set the backoff strategy.
    #[must_use]
    pub fn with_backoff(mut self, backoff_builder: backon::ExponentialBuilder) -> Self {
        self.backoff_builder = backoff_builder;
        self
    }

    /// Set the deadline function.
    #[must_use]
    pub fn with_deadline(
        mut self,
        deadline_fn: impl Fn(T) -> Option<chrono::DateTime<chrono::Utc>> + Send + Sync + 'static,
    ) -> Self {
        self.deadline_fn = Arc::new(deadline_fn);
        self
    }

    /// Set the time provider function. This function should return the "current
    /// time", which will be compared with the deadline computed by the
    /// `deadline_fn`.
    #[must_use]
    pub fn with_time(
        mut self,
        time_fn: impl Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync + 'static,
    ) -> Self {
        self.time_fn = Arc::new(time_fn);
        self
    }

    /// Set the [`CancellationToken`] if any. By default, no token is used.
    #[must_use]
    pub fn with_cancellation_token(mut self, cancellation_token: CancellationToken) -> Self {
        self.cancellation_token = Some(cancellation_token);
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
            time_fn: Arc::new(chrono::Utc::now),
            cancellation_token: None,
        }
    }
}

/// A wrapper over an iterator that tracks when it has been exhausted.
///
/// The inner iterator is assumed to be exhausted once it returns the first
/// [`None`].
struct ExhaustedIterator<I: Iterator> {
    inner: I,
    is_exhausted: bool,
}

impl<I: Iterator> From<I> for ExhaustedIterator<I> {
    fn from(value: I) -> Self {
        Self {
            inner: value,
            is_exhausted: false,
        }
    }
}

impl<I: Iterator> Iterator for ExhaustedIterator<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.inner.next() {
            Some(item)
        } else {
            self.is_exhausted = true;
            None
        }
    }
}

/// Errors that can occur during the execution of the async function with
/// retries.
#[derive(Debug, thiserror::Error)]
pub enum DoAsyncError {
    /// An error that can be retried.
    #[error("Retryable error")]
    RetryableError,

    /// An error that cannot be retried.
    #[error("Non-retryable error")]
    NonRetryableError,
}
// TODO: Implement `From` for various error types (ex. Alloy RPC errors)

/// Execute a provided function with retries and a maximum timeout according to
/// the provided options.
///
/// Intended to be used within a `tokio` task:
/// ```ignore
/// tokio::spawn(retry::do_async(...))
/// ```
pub async fn do_async<
    T,
    A,
    Fut: Future<Output = Result<A, DoAsyncError>>,
    FutureFn: FnMut() -> Fut,
>(
    options: AsyncOptions<T>,
    t: T,
    topic: &'static str,
    name: &'static str,
    mut future: FutureFn,
) {
    let deadline = (options.deadline_fn)(t);
    let now = (options.time_fn)();

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "chrono to std conversion is safe for negative values"
    )]
    let total_delay = deadline.and_then(|deadline| (deadline - now).to_std().ok());

    let mut backoff = ExhaustedIterator::from(
        options
            .backoff_builder
            .with_total_delay(total_delay)
            .build(),
    );

    let span = tracing::debug_span!("retry::do_async", topic, name);
    async move {
        let cancelled = || {
            options
                .cancellation_token
                .as_ref()
                .is_some_and(tokio_util::sync::CancellationToken::is_cancelled)
        };

        let mut attempt = 0u64;
        let future = || {
            debug!(attempt);
            attempt = attempt.saturating_add(1);
            future()
        };

        let result = future
            .retry(&mut backoff)
            .when(|e| {
                if cancelled() {
                    return false;
                }

                match e {
                    DoAsyncError::RetryableError => true,
                    DoAsyncError::NonRetryableError => false,
                }
            })
            .notify(|error, _| {
                warn!(?error, "retryable error");
            })
            .await;

        match result {
            Ok(_) => info!(status = "success"),
            Err(error) => {
                let status = if cancelled() {
                    "cancelled"
                } else if backoff.is_exhausted {
                    "timeout"
                } else {
                    "error"
                };
                error!(status, ?error);
            }
        }
    }
    .instrument(span)
    .await;
}

#[cfg(test)]
mod tests {
    use tokio_util::sync::CancellationToken;

    use crate::retry::{self, DoAsyncError};
    use core::time;
    use std::sync::{Arc, Mutex};

    struct TestCase {
        options: retry::AsyncOptions<()>,
        func: Arc<dyn Fn(usize) -> Result<(), DoAsyncError> + Send + Sync>,
        expected_attempts: usize,
    }

    fn test_backoff() -> backon::ExponentialBuilder {
        backon::ExponentialBuilder::default()
            .with_min_delay(time::Duration::from_millis(1))
            .with_max_delay(time::Duration::from_millis(1))
            .with_factor(2.0)
            .without_max_times()
    }

    #[tokio::test]
    async fn no_retries() {
        run_test(TestCase {
            options: retry::AsyncOptions::default().with_backoff(test_backoff()),
            func: Arc::new(|_: usize| Ok(())),
            expected_attempts: 1,
        })
        .await;
    }

    #[tokio::test]
    async fn one_retry() {
        run_test(TestCase {
            options: retry::AsyncOptions::default().with_backoff(test_backoff()),
            func: Arc::new(|attempts: usize| {
                if attempts < 2 {
                    Err(DoAsyncError::RetryableError)
                } else {
                    Ok(())
                }
            }),
            expected_attempts: 2,
        })
        .await;
    }

    #[tokio::test]
    async fn multiple_retries() {
        run_test(TestCase {
            options: retry::AsyncOptions::default().with_backoff(test_backoff()),
            func: Arc::new(|attempts: usize| {
                if attempts < 5 {
                    Err(DoAsyncError::RetryableError)
                } else {
                    Ok(())
                }
            }),
            expected_attempts: 5,
        })
        .await;
    }

    #[tokio::test]
    async fn non_retryable_error() {
        run_test(TestCase {
            options: retry::AsyncOptions::default().with_backoff(test_backoff()),
            func: Arc::new(|_| Err(DoAsyncError::NonRetryableError)),
            expected_attempts: 1,
        })
        .await;
    }

    #[tokio::test]
    async fn one_attempt_on_cancellation() {
        let cancellation_token = CancellationToken::new();
        cancellation_token.cancel();

        run_test(TestCase {
            options: retry::AsyncOptions::default()
                .with_backoff(test_backoff())
                .with_cancellation_token(cancellation_token),
            func: Arc::new(|_| Err(DoAsyncError::RetryableError)),
            expected_attempts: 1,
        })
        .await;
    }

    #[tokio::test]
    async fn one_attempt_timeout() {
        let now = chrono::Utc::now();

        run_test(TestCase {
            options: retry::AsyncOptions::default()
                .with_backoff(test_backoff())
                .with_time(move || now)
                .with_deadline(move |()| Some(now)),
            func: Arc::new(|_| Err(DoAsyncError::RetryableError)),
            expected_attempts: 1,
        })
        .await;
    }

    async fn run_test(tc: TestCase) {
        let TestCase {
            options,
            func,
            expected_attempts,
        } = tc;

        let attempts = Arc::new(Mutex::new(0usize));

        retry::do_async(options, (), "test", "test", {
            let attempts = attempts.clone();
            move || {
                let attempts = attempts.clone();
                let func = func.clone();
                async move {
                    let mut inner = attempts.lock().unwrap();
                    *inner = (*inner).saturating_add(1);

                    func(*inner)
                }
            }
        })
        .await;

        assert_eq!(*attempts.lock().unwrap(), expected_attempts);
    }
}
