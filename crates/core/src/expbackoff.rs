//! Exponential backoff builders mirroring Charon's `app/expbackoff` package.
//!
//! Charon defines two shared configurations (`app/expbackoff/expbackoff.go`):
//! `FastConfig` (100ms base, 5s max) for quick retries, and `DefaultConfig`
//! (1s base, 120s max) for slower loops. Both use a 1.6 multiplier and 0.2
//! jitter and retry until the surrounding context is cancelled.
//!
//! Note on jitter: Charon applies a `±20%` multiplicative jitter, whereas
//! `backon`'s [`ExponentialBuilder::with_jitter`] adds a randomized delay in
//! `(0, base)`. This is an approximation, but it matches every existing
//! Pluto backoff call site, so consolidating here introduces no behavioral
//! change.

use std::time::Duration;

use backon::ExponentialBuilder;

/// Backoff matching Charon's `expbackoff.FastConfig`: base=100ms, max=5s,
/// multiplier=1.6, jitter≈0.2. Retries until the surrounding cancellation
/// stops it (`without_max_times`), mirroring Go's "back off until the context
/// is cancelled" loops.
pub fn fast() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(100))
        .with_max_delay(Duration::from_secs(5))
        .with_factor(1.6)
        .without_max_times()
        .with_jitter()
}

/// Backoff matching Charon's `expbackoff.DefaultConfig`: base=1s, max=120s,
/// multiplier=1.6, jitter≈0.2. Retries until the surrounding cancellation
/// stops it (`without_max_times`).
pub fn default() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(1))
        .with_max_delay(Duration::from_secs(120))
        .with_factor(1.6)
        .without_max_times()
        .with_jitter()
}
