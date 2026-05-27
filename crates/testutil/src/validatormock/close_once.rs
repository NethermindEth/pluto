//! One-shot async signal shared by attest / synccomm drivers.
//!
//! Models Go's `chan struct{}` + `close(ch)` idiom: any number of awaiters park
//! in [`CloseOnce::wait`], and a single [`CloseOnce::close`] wakes every
//! pending and future awaiter. Both calls are wait-free in the
//! already-closed case.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

/// One-shot async signal mirroring Go's `chan struct{}` + `close(ch)` idiom.
///
/// [`Self::close`] is idempotent (Go panics on the second `close`; we prefer
/// silent re-close). [`Self::wait`] returns immediately once closed, otherwise
/// blocks on a [`Notify`] until the next [`Self::close`] call. Using
/// `notify_waiters` (not `notify_one`) ensures every pending waiter is woken
/// when the signal fires.
///
/// Unlike `tokio::sync::OnceCell` + `get_or_init(pending)`, this primitive does
/// not park inside an initialiser that holds a per-cell semaphore permit. That
/// permit is what made the previous `wait_ready` implementation deadlock when
/// a waiter raced ahead of its producer: the waiter's pending future kept the
/// permit, and the producer's later `cell.set(())` returned
/// `SetError::InitializingError` without ever waking the waiter.
#[derive(Debug, Default)]
pub(super) struct CloseOnce {
    closed: AtomicBool,
    notify: Notify,
}

impl CloseOnce {
    /// Marks the signal closed and wakes every currently-registered waiter.
    /// Idempotent — calling twice is a no-op.
    pub(super) fn close(&self) {
        // Store first so a fresh waiter that arrives between the store and
        // notify sees `closed == true` on its first poll. `notify_waiters`
        // only wakes waiters already registered; the `wait` loop's re-check
        // of `closed` after registering interest is what closes the race.
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    /// Awaits until [`Self::close`] has been (or is) called. Returns
    /// immediately once closed.
    pub(super) async fn wait(&self) {
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return;
            }
            // Register interest before re-checking to avoid a missed wakeup.
            let notified = self.notify.notified();
            if self.closed.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::time::{Duration, timeout};

    use super::*;

    #[tokio::test]
    async fn wait_returns_immediately_after_close() {
        let signal = CloseOnce::default();
        signal.close();
        timeout(Duration::from_millis(100), signal.wait())
            .await
            .expect("wait must resolve once closed");
    }

    #[tokio::test]
    async fn close_wakes_pending_waiters() {
        let signal = Arc::new(CloseOnce::default());
        let waiter = {
            let signal = Arc::clone(&signal);
            tokio::spawn(async move { signal.wait().await })
        };

        // Give the waiter a chance to register its `Notify` interest.
        tokio::task::yield_now().await;
        signal.close();

        timeout(Duration::from_millis(100), waiter)
            .await
            .expect("waiter must finish before timeout")
            .expect("waiter join");
    }

    #[tokio::test]
    async fn double_close_is_noop() {
        let signal = CloseOnce::default();
        signal.close();
        signal.close();
        signal.wait().await;
    }

    /// Regression: waiter that races *ahead* of its producer must still
    /// wake when the producer eventually closes the signal — the deadlock
    /// the previous `OnceCell::get_or_init(pending)` design exhibited.
    #[tokio::test]
    async fn waiter_ahead_of_producer_still_wakes() {
        let signal = Arc::new(CloseOnce::default());

        // Spawn many waiters first, before any close.
        let waiters: Vec<_> = (0..8)
            .map(|_| {
                let signal = Arc::clone(&signal);
                tokio::spawn(async move { signal.wait().await })
            })
            .collect();

        // Let every waiter park on `notified`.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        signal.close();

        for w in waiters {
            timeout(Duration::from_millis(100), w)
                .await
                .expect("waiter must finish before timeout")
                .expect("waiter join");
        }
    }
}
