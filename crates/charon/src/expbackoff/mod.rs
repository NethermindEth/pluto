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
pub struct ExponentialBackoff<R> {
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
        backoff = backoff.mul_f64(1.0 + (self.jitter * (self.rng.next_f64() * 2.0 - 1.0)));

        backoff
    }

    /// Assume a retry has occurred.
    pub fn tried(&mut self) {
        self.retries += 1;
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
        let duration = self.backoff();
        self.tried();

        tokio::time::sleep(duration)
    }
}

/// Builder pattern to create an [`ExponentialBackoff`] instance.
pub struct ExponentialBackoffBuilder<R> {
    base_delay: time::Duration,
    multiplier: f64,
    jitter: f64,
    max_delay: time::Duration,
    rng: R,
}

type Result<T> = std::result::Result<T, InvalidBackoff>;

/// Error indicating an invalid backoff configuration.
#[derive(Debug, thiserror::Error)]
#[error("Invalid backoff configuration: {0}")]
pub struct InvalidBackoff(&'static str);

impl<R> ExponentialBackoffBuilder<R> {
    /// Backoff configuration with the default values specified at https://github.com/grpc/grpc/blob/master/doc/connection-backoff.md.
    ///
    /// This should be useful for callers who want to configure backoff with
    /// non-default values only for a subset of the options.
    ///
    /// Copied from [google.golang.org/grpc@v1.48.0/backoff/backoff.go]
    pub fn default() -> ExponentialBackoffBuilder<HasherRng> {
        ExponentialBackoffBuilder {
            base_delay: time::Duration::from_secs(1),
            multiplier: 1.6,
            jitter: 0.2,
            max_delay: time::Duration::from_secs(120),
            rng: HasherRng::default(),
        }
    }

    /// Common configuration for fast backoff.
    pub fn fast_config() -> ExponentialBackoffBuilder<HasherRng> {
        ExponentialBackoffBuilder {
            base_delay: time::Duration::from_millis(100),
            multiplier: 1.6,
            jitter: 0.2,
            max_delay: time::Duration::from_secs(5),
            rng: HasherRng::default(),
        }
    }

    /// Set the amount of time to backoff after the first failure.
    pub fn with_base_delay(mut self, delay: time::Duration) -> Self {
        self.base_delay = delay;
        self
    }

    /// Set the factor with which to multiply backoffs after a failed retry.
    /// Should ideally be greater than 1.
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }

    /// Set the factor with which backoffs are randomized.
    pub fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter;
        self
    }

    /// Set the upper bound of backoff delay.
    pub fn with_max_delay(mut self, delay: time::Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Set the random number generator to use for jittering.
    pub fn with_rng<T>(self, rng: T) -> ExponentialBackoffBuilder<T> {
        ExponentialBackoffBuilder {
            base_delay: self.base_delay,
            multiplier: self.multiplier,
            jitter: self.jitter,
            max_delay: self.max_delay,
            rng,
        }
    }

    /// Construct a new [`ExponentialBackoff`] instance from the builder.
    pub fn build(self) -> Result<ExponentialBackoff<R>> {
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
            rng: self.rng,
            retries: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::expbackoff::{ExponentialBackoff, ExponentialBackoffBuilder};
    use core::time::Duration;
    use tower::util::rng::Rng;

    struct Const(f64);

    impl Rng for Const {
        fn next_f64(&mut self) -> f64 {
            self.0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }
    }

    #[test]
    fn default_config() {
        let backoffs: Vec<Duration> = vec![
            Duration::from_secs(1),
            Duration::from_secs(1) + Duration::from_millis(600),
            Duration::from_secs(2) + Duration::from_millis(560),
            Duration::from_secs(4) + Duration::from_millis(090),
            Duration::from_secs(6) + Duration::from_millis(550),
            Duration::from_secs(10) + Duration::from_millis(480),
            Duration::from_secs(16) + Duration::from_millis(770),
            Duration::from_secs(26) + Duration::from_millis(840),
            Duration::from_secs(42) + Duration::from_millis(940),
            Duration::from_mins(1) + Duration::from_millis(8710),
            Duration::from_mins(1) + Duration::from_millis(49950),
            Duration::from_mins(2),
            Duration::from_mins(2),
        ];

        let mut backoff = ExponentialBackoffBuilder::<Const>::default()
            .with_rng(Const(0.5))
            .build()
            .unwrap();

        for expected in backoffs {
            let duration = backoff.backoff();
            backoff.tried();

            assert!(duration - expected <= Duration::from_millis(10));
        }
    }

    #[test]
    fn default_config_max_jitter() {
        let backoffs: Vec<Duration> = vec![
            Duration::from_secs(1),
            Duration::from_secs(1) + Duration::from_millis(920),
            Duration::from_secs(3) + Duration::from_millis(70),
            Duration::from_secs(4) + Duration::from_millis(910),
            Duration::from_secs(7) + Duration::from_millis(860),
            Duration::from_secs(12) + Duration::from_millis(580),
            Duration::from_secs(20) + Duration::from_millis(130),
            Duration::from_secs(32) + Duration::from_millis(210),
            Duration::from_secs(51) + Duration::from_millis(530),
            Duration::from_mins(1) + Duration::from_secs(22) + Duration::from_millis(460),
            Duration::from_mins(2) + Duration::from_secs(11) + Duration::from_millis(940),
            Duration::from_mins(2) + Duration::from_secs(24),
            Duration::from_mins(2) + Duration::from_secs(24),
        ];

        let mut backoff: ExponentialBackoff<Const> = ExponentialBackoffBuilder::<Const>::default()
            .with_rng(Const(1.0))
            .build()
            .unwrap();

        for expected in backoffs {
            let duration = backoff.backoff();
            backoff.tried();

            assert!(duration - expected <= Duration::from_millis(10));
        }
    }
}
