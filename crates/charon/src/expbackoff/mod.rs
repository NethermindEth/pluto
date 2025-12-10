use std::time;
use tower::{
    retry::backoff::Backoff,
    util::rng::{HasherRng, Rng},
};

/// A jittered [exponential backoff] strategy.
///
/// The backoff duration will increase exponentially for every subsequent
/// backoff, up to a maximum duration. A small amount of [random jitter] is
/// added to each backoff duration, in order to avoid retry spikes.
///
/// [exponential backoff]: https://en.wikipedia.org/wiki/Exponential_backoff
/// [random jitter]: https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
pub struct ExponentialBackoff<R = HasherRng> {
    base_delay: time::Duration,
    multiplier: f64,
    jitter: f64,
    max_delay: time::Duration,
    rng: R,
    retries: u32,
}

impl<R> ExponentialBackoff<R>
where
    R: Rng,
{
    /// Compute the amount of time to wait before the next retry.
    pub fn backoff(&mut self) -> time::Duration {
        if self.retries == 0 {
            return self.base_delay;
        }

        let mut backoff = self.base_delay;
        let mut retries = self.retries;

        while backoff < self.max_delay && retries > 0 {
            backoff = backoff.mul_f64(self.multiplier);
            retries -= 1;
        }

        backoff = backoff.min(self.max_delay);

        // Randomize backoff delays so that if a cluster of requests start at
        // the same time, they won't operate in lockstep.
        backoff = backoff.mul_f64(1.0 + (self.jitter * self.rng.next_f64() * 2.0 - 1.0));

        backoff
    }

    /// Resets the backoff duration to the base delay.
    pub fn reset(&mut self) {
        self.retries = 0;
    }
}

impl<R> Backoff for ExponentialBackoff<R>
where
    R: Rng,
{
    type Future = tokio::time::Sleep;

    fn next_backoff(&mut self) -> Self::Future {
        self.retries += 1;

        let duration = self.backoff();
        tokio::time::sleep(duration)
    }
}

/// Builder pattern to create an [`ExponentialBackoff`] instance.
pub struct ExponentialBackoffBuilder {
    /// Amount of time to backoff after the first failure.
    pub base_delay: time::Duration,
    /// Factor with which to multiply backoffs after a failed retry. Should
    /// ideally be greater than 1.
    pub multiplier: f64,
    /// Factor with which backoffs are randomized.
    pub jitter: f64,
    /// Upper bound of backoff delay.
    pub max_delay: time::Duration,
}

type Result<T> = std::result::Result<T, InvalidBackoff>;

/// Error indicating an invalid backoff configuration.
#[derive(Debug, thiserror::Error)]
#[error("Invalid backoff configuration: {0}")]
pub struct InvalidBackoff(&'static str);

impl Default for ExponentialBackoffBuilder {
    /// Backoff configuration with the default values specified at https://github.com/grpc/grpc/blob/master/doc/connection-backoff.md.
    ///
    /// This should be useful for callers who want to configure backoff with
    /// non-default values only for a subset of the options.
    ///
    /// Copied from [google.golang.org/grpc@v1.48.0/backoff/backoff.go]
    fn default() -> Self {
        Self {
            base_delay: time::Duration::from_millis(100),
            multiplier: 1.6,
            jitter: 0.2,
            max_delay: time::Duration::from_secs(5),
        }
    }
}

impl ExponentialBackoffBuilder {
    /// Common configuration for fast backoff.
    pub fn fast_config() -> Self {
        Self {
            base_delay: time::Duration::from_millis(100),
            multiplier: 1.6,
            jitter: 0.2,
            max_delay: time::Duration::from_secs(5),
        }
    }

    /// Construct a new [`ExponentialBackoff`] instance from the builder.
    pub fn build(self) -> Result<ExponentialBackoff> {
        if self.base_delay > self.max_delay {
            return Err(InvalidBackoff("maximum must not be less than base"));
        }
        if self.max_delay == time::Duration::from_millis(0) {
            return Err(InvalidBackoff("maximum must be non-zero"));
        }
        if self.jitter < 0.0 {
            return Err(InvalidBackoff("jitter must not be negative"));
        }
        if self.jitter > 100.0 {
            return Err(InvalidBackoff("jitter must not be greater than 100"));
        }
        if !self.jitter.is_finite() {
            return Err(InvalidBackoff("jitter must be finite"));
        }
        if self.multiplier < 0.0 {
            return Err(InvalidBackoff("multiplier must not be negative"));
        }

        Ok(ExponentialBackoff {
            base_delay: self.base_delay,
            jitter: self.jitter,
            multiplier: self.multiplier,
            max_delay: self.max_delay,
            rng: HasherRng::default(),
            retries: 0,
        })
    }
}
