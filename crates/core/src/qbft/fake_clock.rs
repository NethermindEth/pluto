use crossbeam::channel as mpmc;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicIsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct FakeClock {
    inner: Arc<Mutex<FakeClockInner>>,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum TimerPriority {
    // Match the Go fake-clock harness at equal deadlines: delayed nodes start
    // before protocol timers, while delayed input values arrive after them.
    StartDelay,
    Protocol,
    InputValue,
}

struct FakeClockInner {
    start: Instant,
    now: Instant,
    last_id: usize,
    cancelled: bool,
    clients: BTreeMap<usize, (mpmc::Sender<Instant>, Instant, TimerPriority)>,
}

impl FakeClock {
    /// Create a fake clock pinned to an initial instant.
    pub fn new(now: Instant) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeClockInner {
                start: now,
                now,
                last_id: 1,
                cancelled: false,
                clients: Default::default(),
            })),
        }
    }

    /// Register a protocol timer with the default protocol priority.
    pub fn new_timer(
        &self,
        duration: Duration,
    ) -> (
        mpmc::Receiver<Instant>,
        Box<dyn Fn() + Send + Sync + 'static>,
    ) {
        self.new_timer_with_priority(duration, TimerPriority::Protocol)
    }

    /// Register a timer with explicit same-deadline ordering priority.
    pub fn new_timer_with_priority(
        &self,
        duration: Duration,
        priority: TimerPriority,
    ) -> (
        mpmc::Receiver<Instant>,
        Box<dyn Fn() + Send + Sync + 'static>,
    ) {
        // Synchronous expiry handoff: advancing fake time must wait until the
        // timer owner observes the tick, otherwise exact-round QBFT tests race
        // worker scheduling.
        let (tx, rx) = mpmc::bounded::<Instant>(0);

        let client_id = {
            let mut inner = self.inner.lock().unwrap();
            if inner.cancelled {
                return (rx, Box::new(|| {}));
            }

            let id = inner.last_id;
            let deadline = inner.now + duration;

            inner.last_id += 1;
            inner.clients.insert(id, (tx, deadline, priority));

            id
        };

        let inner = Arc::clone(&self.inner);
        let cancel = Box::new(move || {
            let mut inner = inner.lock().unwrap();
            inner.clients.remove(&client_id);
        });

        (rx, cancel)
    }

    /// Advance fake time and deliver all timers expired by the new time.
    pub fn advance(&self, duration: Duration) -> usize {
        self.advance_inner(duration, None)
    }

    /// Advance fake time and wait for each delivered timer action to complete.
    pub fn advance_and_wait(
        &self,
        duration: Duration,
        pending_timer_actions: &AtomicIsize,
    ) -> usize {
        self.advance_inner(duration, Some(pending_timer_actions))
    }

    /// Shared advance path; optionally synchronizes timer delivery with the
    /// test harness.
    fn advance_inner(
        &self,
        duration: Duration,
        pending_timer_actions: Option<&AtomicIsize>,
    ) -> usize {
        // Advance time and collect expired senders under lock, but perform sends
        // without holding lock.
        let mut expired = vec![];

        let now = {
            let mut inner = self.inner.lock().unwrap();
            inner.now += duration;
            let now = inner.now;

            for (&id, (ch, deadline, priority)) in &inner.clients {
                if *deadline <= now {
                    expired.push((id, *deadline, *priority, ch.clone()));
                }
            }

            for (id, ..) in expired.iter() {
                inner.clients.remove(id);
            }

            now
        };

        // Equal-deadline order is part of the test harness contract: these
        // tests assert exact rounds, and Go's fake-clock scheduling is stable.
        expired.sort_by_key(|(id, deadline, priority, _)| (*deadline, *priority, *id));

        let mut delivered = 0;
        for (_, _, _, ch) in expired {
            if let Some(pending_timer_actions) = pending_timer_actions {
                pending_timer_actions.fetch_add(1, Ordering::SeqCst);
            }

            if ch.send(now).is_ok() {
                delivered += 1;
                if let Some(pending_timer_actions) = pending_timer_actions {
                    while pending_timer_actions.load(Ordering::SeqCst) > 0 {
                        thread::yield_now();
                    }
                }
            } else if let Some(pending_timer_actions) = pending_timer_actions {
                pending_timer_actions.fetch_sub(1, Ordering::SeqCst);
            }
        }

        delivered
    }

    /// Return fake time elapsed since clock creation.
    pub fn elapsed(&self) -> Duration {
        let inner = self.inner.lock().unwrap();
        inner.now - inner.start
    }

    /// Return currently registered timers.
    pub fn timer_count(&self) -> usize {
        self.inner.lock().unwrap().clients.len()
    }

    /// Explicit terminal cleanup; do not reintroduce `Drop`, since dropping one
    /// clone must not cancel timers owned by other clones.
    pub fn cancel(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.cancelled = true;
        inner.clients.clear();
    }
}

#[test]
/// Timers registered by different threads fire after fake time passes
/// deadlines.
fn multiple_threads_timers() {
    let clock = FakeClock::new(Instant::now());
    let (done_tx, done_rx) = mpmc::bounded(2);

    thread::scope(|s| {
        let c1 = clock.clone();
        let (ch_1, _) = c1.new_timer(Duration::from_secs(5));
        let done_tx_1 = done_tx.clone();
        s.spawn(move || {
            done_tx_1.send(ch_1.recv().is_ok()).unwrap();
        });

        let c2 = clock.clone();
        let (ch_2, _) = c2.new_timer(Duration::from_secs(5));
        let done_tx_2 = done_tx.clone();
        s.spawn(move || {
            done_tx_2.send(ch_2.recv().is_ok()).unwrap();
        });

        clock.advance(Duration::from_secs(4));
        assert!(done_rx.try_recv().is_err());
        clock.advance(Duration::from_secs(6));
    });

    let done = done_rx.try_iter().collect::<Vec<_>>();
    assert_eq!(2, done.len());
    assert!(done.into_iter().all(|done| done));
    assert_eq!(Duration::from_secs(10), clock.elapsed());
}

#[test]
/// Cancelling the clock closes outstanding timers without advancing fake time.
fn multiple_threads_cancellation() {
    let clock = FakeClock::new(Instant::now());
    let (done_tx, done_rx) = mpmc::bounded(2);

    thread::scope(|s| {
        let c1 = clock.clone();
        let (ch_1, _) = c1.new_timer(Duration::from_secs(5));
        let done_tx_1 = done_tx.clone();
        s.spawn(move || {
            done_tx_1.send(ch_1.recv().is_err()).unwrap();
        });

        let c2 = clock.clone();
        let (ch_2, _) = c2.new_timer(Duration::from_secs(5));
        let done_tx_2 = done_tx.clone();
        s.spawn(move || {
            done_tx_2.send(ch_2.recv().is_err()).unwrap();
        });

        clock.cancel();
    });

    let done = done_rx.try_iter().collect::<Vec<_>>();
    assert_eq!(2, done.len());
    assert!(done.into_iter().all(|done| done));
    assert_eq!(Duration::ZERO, clock.elapsed());
}

#[test]
/// A timer created after clock cancellation is immediately closed.
fn timer_created_after_cancel_is_closed() {
    let clock = FakeClock::new(Instant::now());
    clock.cancel();

    let (ch, cancel) = clock.new_timer(Duration::from_secs(5));

    assert!(matches!(
        ch.try_recv(),
        Err(mpmc::TryRecvError::Disconnected)
    ));
    cancel();
}

#[test]
/// Cancelling one timer does not affect other timers with the same deadline.
fn cancel_one_timer_only() {
    let clock = FakeClock::new(Instant::now());
    let (ch_1, cancel_1) = clock.new_timer(Duration::from_secs(5));
    let (ch_2, _) = clock.new_timer(Duration::from_secs(5));
    let (done_tx, done_rx) = mpmc::bounded(1);

    cancel_1();
    thread::scope(|s| {
        s.spawn(move || {
            done_tx.send(ch_2.recv().is_ok()).unwrap();
        });

        clock.advance(Duration::from_secs(5));
    });

    assert!(ch_1.try_recv().is_err());
    assert_eq!(Ok(true), done_rx.try_recv());
}

#[test]
/// An expired timer is delivered once and removed from the clock.
fn expired_timer_delivers_once() {
    let clock = FakeClock::new(Instant::now());
    let (ch, _) = clock.new_timer(Duration::from_secs(5));
    let (done_tx, done_rx) = mpmc::bounded(1);

    thread::scope(|s| {
        s.spawn(move || {
            done_tx.send(ch.recv().is_ok()).unwrap();
        });

        clock.advance(Duration::from_secs(5));
    });

    assert_eq!(Ok(true), done_rx.try_recv());
    clock.advance(Duration::from_secs(5));
    assert!(done_rx.try_recv().is_err());
}
