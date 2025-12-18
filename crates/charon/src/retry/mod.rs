use backon::{BackoffBuilder, Retryable};
use charon_core::types::{Duty, DutyDefinitionSet, DutyType};
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

async fn fetcher_fetch(
    _duty: Duty,
    _set: DutyDefinitionSet<DutyType>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

async fn consensus_participate(_duty: Duty) -> std::result::Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

/// TODO
pub fn with_async_retry(options: AsyncOptions<Duty>) {
    let fetcher_fetch = |duty: Duty, set: DutyDefinitionSet<DutyType>| {
        tokio::spawn(do_async(
            options.clone(),
            duty.clone(),
            "fetcher",
            "fetch",
            move || fetcher_fetch(duty.clone(), set.clone()),
        ));
    };
    let consensus_participate = |duty: Duty| {
        tokio::spawn(do_async(
            options.clone(),
            duty.clone(),
            "consensus",
            "participate",
            move || consensus_participate(duty.clone()),
        ));
    };
    // ... other funcs
}

#[cfg(test)]
mod tests {
    use crate::{deadline, retry};
    use core::time;
    use std::sync::{Arc, Mutex};

    struct TestCase {
        options: retry::AsyncOptions<()>,
        func: Arc<dyn Fn(usize) -> Result<(), ()> + Send + Sync>,
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
            func: Arc::new(|_: usize| {
                let result: Result<(), ()> = Ok(());
                result
            }),
            expected_attempts: 1,
        })
        .await;
    }

    #[tokio::test]
    async fn one_retry() {
        run_test(TestCase {
            options: retry::AsyncOptions::default().with_backoff(test_backoff()),
            func: Arc::new(
                |attempts: usize| {
                    if attempts < 2 { Err(()) } else { Ok(()) }
                },
            ),
            expected_attempts: 2,
        })
        .await;
    }

    #[tokio::test]
    async fn multiple_retries() {
        run_test(TestCase {
            options: retry::AsyncOptions::default().with_backoff(test_backoff()),
            func: Arc::new(
                |attempts: usize| {
                    if attempts < 5 { Err(()) } else { Ok(()) }
                },
            ),
            expected_attempts: 5,
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "not implemented"]
    async fn non_retryable_error() {
        run_test(TestCase {
            options: retry::AsyncOptions::default().with_backoff(test_backoff()),
            func: Arc::new(|_| todo!("Return non-retryable error")),
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

        let attempts = Arc::new(Mutex::new(0));

        retry::do_async(options, (), "test", "test", {
            let attempts = attempts.clone();
            move || {
                let attempts = attempts.clone();
                let func = func.clone();
                async move {
                    let mut inner = attempts.lock().unwrap();
                    *inner += 1;

                    func(*inner)
                }
            }
        })
        .await;

        assert_eq!(*attempts.lock().unwrap(), expected_attempts);
    }

    #[test]
    #[ignore = "compile check"]
    fn it_compiles() {
        let duty_deadline: deadline::DeadlineFunc = deadline::new_duty_deadline_func().unwrap();
        let opts = retry::AsyncOptions::default().with_deadline(duty_deadline);
        super::with_async_retry(opts);
    }
}
