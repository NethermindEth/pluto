//! Injectable clock for the validator-mock scheduler.
//!
//! Replaces Go's `clockwork.FakeClock` from `propose_test.go`. The scheduler
//! always calls into [`Clock`], so tests can substitute [`FakeClock`] to drive
//! time-based duties deterministically without `tokio::time::pause()`, which
//! interacts poorly with `wiremock::MockServer`.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use tokio::sync::oneshot;

/// Abstract wall-clock used by [`crate::validatormock::Component`].
#[async_trait]
pub trait Clock: Send + Sync + std::fmt::Debug + 'static {
    /// Returns the current time.
    fn now(&self) -> SystemTime;

    /// Sleeps until `wake_at`. Returns immediately if `wake_at` has already
    /// passed.
    async fn sleep_until(&self, wake_at: SystemTime);
}

/// Real-time clock backed by `SystemTime::now` and `tokio::time::sleep`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

#[async_trait]
impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    async fn sleep_until(&self, wake_at: SystemTime) {
        let now = SystemTime::now();
        let duration = wake_at.duration_since(now).unwrap_or(Duration::ZERO);
        if duration.is_zero() {
            return;
        }
        tokio::time::sleep(duration).await;
    }
}

/// Test clock: advances only via [`FakeClock::advance`] /
/// [`FakeClock::advance_to`].
///
/// Pending [`Clock::sleep_until`] futures register a oneshot sender; advancing
/// past the wake time fires every sender at or before the new time.
#[derive(Debug, Default, Clone)]
pub struct FakeClock(Arc<Mutex<FakeClockInner>>);

#[derive(Debug)]
struct FakeClockInner {
    now: SystemTime,
    pending: Vec<(SystemTime, oneshot::Sender<()>)>,
}

impl Default for FakeClockInner {
    fn default() -> Self {
        Self {
            now: SystemTime::UNIX_EPOCH,
            pending: Vec::new(),
        }
    }
}

impl FakeClock {
    /// Builds a clock pinned at `now`.
    #[must_use]
    pub fn new(now: SystemTime) -> Self {
        Self(Arc::new(Mutex::new(FakeClockInner {
            now,
            pending: Vec::new(),
        })))
    }

    /// Advances by `delta` and wakes pending sleepers whose deadline has
    /// passed.
    pub fn advance(&self, delta: Duration) {
        let new_now = {
            let guard = self.0.lock().expect("FakeClock mutex poisoned");
            guard.now.checked_add(delta).unwrap_or(guard.now)
        };
        self.advance_to(new_now);
    }

    /// Advances the clock to `target` (no-op if already past) and wakes
    /// pending sleepers whose deadline has passed.
    pub fn advance_to(&self, target: SystemTime) {
        let drained: Vec<oneshot::Sender<()>> = {
            let mut guard = self.0.lock().expect("FakeClock mutex poisoned");
            if target > guard.now {
                guard.now = target;
            }
            let now = guard.now;
            let mut keep = Vec::with_capacity(guard.pending.len());
            let mut fire = Vec::new();
            for (wake_at, tx) in guard.pending.drain(..) {
                if wake_at <= now {
                    fire.push(tx);
                } else {
                    keep.push((wake_at, tx));
                }
            }
            guard.pending = keep;
            fire
        };
        for tx in drained {
            let _ = tx.send(());
        }
    }
}

#[async_trait]
impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        self.0.lock().expect("FakeClock mutex poisoned").now
    }

    async fn sleep_until(&self, wake_at: SystemTime) {
        let rx = {
            let mut guard = self.0.lock().expect("FakeClock mutex poisoned");
            if wake_at <= guard.now {
                return;
            }
            let (tx, rx) = oneshot::channel();
            guard.pending.push((wake_at, tx));
            rx
        };
        let _ = rx.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn system_clock_now_advances() {
        let c = SystemClock;
        let a = c.now();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let b = c.now();
        assert!(b > a);
    }

    #[tokio::test]
    async fn fake_clock_sleep_resolves_after_advance() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let clock = FakeClock::new(start);
        let clock_for_task = clock.clone();
        let wake = start + Duration::from_secs(10);

        let handle = tokio::spawn(async move {
            clock_for_task.sleep_until(wake).await;
        });

        // Give the task a chance to enqueue.
        tokio::task::yield_now().await;
        clock.advance(Duration::from_secs(10));

        handle.await.expect("sleeper completes");
    }

    #[tokio::test]
    async fn fake_clock_sleep_already_passed_returns_immediately() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let clock = FakeClock::new(start);
        clock.sleep_until(start - Duration::from_secs(1)).await; // no panic, returns
    }

    #[tokio::test]
    async fn fake_clock_multiple_sleepers() {
        let start = SystemTime::UNIX_EPOCH;
        let clock = FakeClock::new(start);

        let a = tokio::spawn({
            let c = clock.clone();
            async move { c.sleep_until(start + Duration::from_secs(1)).await }
        });
        let b = tokio::spawn({
            let c = clock.clone();
            async move { c.sleep_until(start + Duration::from_secs(2)).await }
        });
        tokio::task::yield_now().await;

        clock.advance(Duration::from_secs(1));
        a.await.expect("a wakes");
        // b should still be pending; advance more.
        clock.advance(Duration::from_secs(1));
        b.await.expect("b wakes");
    }
}
