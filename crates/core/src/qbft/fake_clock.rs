use crossbeam::channel as mpmc;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct FakeClock {
    inner: Arc<Mutex<FakeClockInner>>,
}

struct FakeClockInner {
    start: Instant,
    now: Instant,
    last_id: usize,
    clients: HashMap<usize, (mpmc::Sender<Instant>, Instant)>,
}

impl FakeClock {
    pub fn new(now: Instant) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeClockInner {
                start: now,
                now,
                last_id: 1,
                clients: Default::default(),
            })),
        }
    }

    pub fn new_timer(
        &self,
        duration: Duration,
    ) -> (
        mpmc::Receiver<Instant>,
        Box<dyn Fn() + Send + Sync + 'static>,
    ) {
        let (tx, rx) = mpmc::bounded::<Instant>(1);

        let client_id = {
            let mut inner = self.inner.lock().unwrap();
            let id = inner.last_id;
            let deadline = inner.now + duration;

            inner.last_id += 1;
            inner.clients.insert(id, (tx, deadline));

            id
        };

        let inner = Arc::clone(&self.inner);
        let cancel = Box::new(move || {
            let mut inner = inner.lock().unwrap();
            inner.clients.remove(&client_id);
        });

        (rx, cancel)
    }

    pub fn advance(&self, duration: Duration) {
        // Advance time and collect expired senders under lock, but perform sends
        // without holding lock.
        let mut expired = vec![];

        let now = {
            let mut inner = self.inner.lock().unwrap();
            inner.now += duration;
            let now = inner.now;

            for (&id, (ch, deadline)) in inner.clients.iter() {
                if *deadline <= now {
                    expired.push((id, ch.clone()));
                }
            }

            for (id, _) in expired.iter() {
                inner.clients.remove(id);
            }

            now
        };

        for (_, ch) in expired {
            let _ = ch.send(now);
        }
    }

    pub fn elapsed(&self) -> Duration {
        let inner = self.inner.lock().unwrap();
        inner.now - inner.start
    }

    pub fn cancel(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.clients.clear();
    }
}

#[test]
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
fn cancel_one_timer_only() {
    let clock = FakeClock::new(Instant::now());
    let (ch_1, cancel_1) = clock.new_timer(Duration::from_secs(5));
    let (ch_2, _) = clock.new_timer(Duration::from_secs(5));

    cancel_1();
    clock.advance(Duration::from_secs(5));

    assert!(ch_1.try_recv().is_err());
    assert!(ch_2.try_recv().is_ok());
}

#[test]
fn expired_timer_delivers_once() {
    let clock = FakeClock::new(Instant::now());
    let (ch, _) = clock.new_timer(Duration::from_secs(5));

    clock.advance(Duration::from_secs(5));
    assert!(ch.try_recv().is_ok());
    clock.advance(Duration::from_secs(5));
    assert!(ch.try_recv().is_err());
}
