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

impl Drop for FakeClock {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[test]
fn multiple_threads_timers() {
    let clock = FakeClock::new(Instant::now());

    let start = Instant::now();
    thread::scope(|s| {
        let c1 = clock.clone();
        let (ch_1, _) = c1.new_timer(Duration::from_secs(5));
        s.spawn(move || {
            let _ = ch_1.recv();
        });

        let c2 = clock.clone();
        let (ch_2, _) = c2.new_timer(Duration::from_secs(5));
        s.spawn(move || {
            let _ = ch_2.recv();
        });

        clock.advance(Duration::from_secs(6));
    });

    println!("start={:?}, clock={:?}", start.elapsed(), clock.elapsed());
}

#[test]
fn multiple_threads_cancellation() {
    let clock = FakeClock::new(Instant::now());

    let start = Instant::now();
    thread::scope(|s| {
        let c1 = clock.clone();
        let (ch_1, _) = c1.new_timer(Duration::from_secs(5));
        s.spawn(move || {
            let _ = ch_1.recv();
        });

        let c2 = clock.clone();
        let (ch_2, _) = c2.new_timer(Duration::from_secs(5));
        s.spawn(move || {
            let _ = ch_2.recv();
        });

        clock.cancel();
    });

    println!("start={:?}, clock={:?}", start.elapsed(), clock.elapsed());
}
