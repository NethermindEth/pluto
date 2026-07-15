//! Benchmarks a full in-memory QBFT consensus instance: N processes on OS
//! threads wired with crossbeam channels, happy path, measured from spawn to
//! all processes deciding.
//!
//! Benchmark ids follow the cross-language pair naming used by
//! `perf/pairs.json`; the Go counterpart lives in
//! `perf/go-bench/qbft_bench_test.go` and uses the same topology (i64 values,
//! never-firing round timers, blocking fan-out broadcast, value 42).
#![allow(missing_docs)]
// Bench-only arithmetic on small fixed node counts cannot overflow.
#![allow(clippy::arithmetic_side_effects)]

use std::{any::Any, sync::Arc, thread, time::Duration};

use cancellation::CancellationTokenSource;
use criterion::{Criterion, criterion_group, criterion_main};
use crossbeam::channel as mpmc;
use pluto_core::qbft::{
    self, BroadcastRequest, Definition, MessageType, Msg, QbftError, QbftLogger, QbftTypes,
    SomeMsg, Timer, Transport,
};

const INSTANCE: i64 = 1;
const VALUE: i64 = 42;
const FIFO_LIMIT: i64 = 100;

struct BenchQbft;

impl QbftTypes for BenchQbft {
    type Compare = i64;
    type Instance = i64;
    type Value = i64;
}

#[derive(Clone, Debug)]
struct BenchMsg {
    msg_type: MessageType,
    instance: i64,
    source: i64,
    round: i64,
    value: i64,
    prepared_round: i64,
    prepared_value: i64,
    justify: Vec<Msg<BenchQbft>>,
}

impl SomeMsg<BenchQbft> for BenchMsg {
    fn type_(&self) -> MessageType {
        self.msg_type
    }

    fn instance(&self) -> i64 {
        self.instance
    }

    fn source(&self) -> i64 {
        self.source
    }

    fn round(&self) -> i64 {
        self.round
    }

    fn value(&self) -> i64 {
        self.value
    }

    fn value_source(&self) -> Result<i64, QbftError> {
        Ok(self.value)
    }

    fn prepared_round(&self) -> i64 {
        self.prepared_round
    }

    fn prepared_value(&self) -> i64 {
        self.prepared_value
    }

    fn justification(&self) -> Vec<Msg<BenchQbft>> {
        self.justify.clone()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Runs one happy-path consensus instance with `nodes` processes and returns
/// the elapsed time from spawn to every process deciding. Teardown (cancel +
/// join, dominated by the 50ms cancellation poll interval) is excluded.
fn run_consensus(nodes: i64) -> Duration {
    let cts = CancellationTokenSource::new();
    let nodes_usize = usize::try_from(nodes).expect("node count fits usize");
    let (decided_tx, decided_rx) = mpmc::bounded::<i64>(nodes_usize);

    let mut senders = Vec::with_capacity(nodes_usize);
    let mut receivers = Vec::with_capacity(nodes_usize);
    for _ in 0..nodes {
        let (tx, rx) = mpmc::bounded::<Msg<BenchQbft>>(1024);
        senders.push(tx);
        receivers.push(rx);
    }
    let senders = Arc::new(senders);

    let definition = Arc::new(Definition::<BenchQbft> {
        is_leader: Box::new(move |req| {
            (*req.instance + req.round).rem_euclid(nodes) == req.process
        }),
        new_timer: Box::new(|_round| Timer {
            receive: mpmc::never(),
            stop: Box::new(|| {}),
        }),
        compare: Arc::new(|req| {
            req.return_err
                .send(Ok(()))
                .expect("compare status channel open");
        }),
        decide: {
            let decided_tx = decided_tx.clone();
            Box::new(move |req| {
                let _ = decided_tx.send(*req.value);
            })
        },
        logger: QbftLogger {
            upon_rule: Box::new(|_| {}),
            round_change: Box::new(|_| {}),
            unjust: Box::new(|_| {}),
        },
        nodes,
        fifo_limit: FIFO_LIMIT,
    });

    let mut decide_elapsed = Duration::ZERO;
    let start = std::time::Instant::now();

    thread::scope(|s| {
        for process in 1..=nodes {
            let receiver = receivers[usize::try_from(process).expect("fits") - 1].clone();
            let senders = Arc::clone(&senders);
            let token = cts.token().clone();
            let definition = Arc::clone(&definition);

            let transport = Transport::<BenchQbft> {
                broadcast: Box::new(move |req: BroadcastRequest<'_, BenchQbft>| {
                    let msg: Msg<BenchQbft> = Arc::new(BenchMsg {
                        msg_type: req.type_,
                        instance: *req.instance,
                        source: req.source,
                        round: req.round,
                        value: *req.value,
                        prepared_round: req.prepared_round,
                        prepared_value: *req.prepared_value,
                        justify: req.justification.cloned().unwrap_or_default(),
                    });

                    for tx in senders.iter() {
                        // Best effort: receivers may be gone after decide.
                        let _ = tx.send(Arc::clone(&msg));
                    }

                    Ok(())
                }),
                receive: receiver,
            };

            let (value_tx, value_rx) = mpmc::bounded::<i64>(1);
            value_tx.send(VALUE).expect("populate input value");
            let (source_tx, source_rx) = mpmc::bounded::<i64>(1);
            source_tx.send(VALUE).expect("populate input value source");

            s.spawn(move || {
                // Returns ContextCanceled after the bench cancels below.
                let _ = qbft::run(
                    &token,
                    &definition,
                    &transport,
                    &INSTANCE,
                    process,
                    value_rx,
                    source_rx,
                );
            });
        }

        for _ in 0..nodes {
            decided_rx
                .recv_timeout(Duration::from_secs(30))
                .expect("all processes decide");
        }

        decide_elapsed = start.elapsed();
        cts.cancel();
    });

    decide_elapsed
}

fn bench_decide(c: &mut Criterion) {
    for (name, nodes) in [("4of4", 4i64), ("7of10", 10)] {
        c.bench_function(&format!("tier2/qbft/decide_{name}"), |b| {
            b.iter_custom(|iters| (0..iters).map(|_| run_consensus(nodes)).sum())
        });
    }
}

fn config() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .measurement_time(Duration::from_secs(5))
}

criterion_group! {
    name = benches;
    config = config();
    targets = bench_decide,
}
criterion_main!(benches);
