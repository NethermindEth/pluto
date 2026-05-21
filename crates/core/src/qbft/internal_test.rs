#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::collapsible_if
)]

use crate::qbft::{
    self,
    fake_clock::{FakeClock, TimerPriority},
    *,
};
use cancellation::CancellationTokenSource;
use crossbeam::channel as mpmc;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fmt::Write as _,
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc, Mutex,
        atomic::{AtomicIsize, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use test_case::test_case;

const WRITE_CHAN_ERR: &str = "Failed to write to channel";
const READ_CHAN_ERR: &str = "Failed to read from channel";
const TEST_SEED_LABEL: &str = "qbft-test";
const CHAIN_SPLIT_SEED_LABEL: &str = "chain-split";
const TEST_STREAM_DROP: u64 = 1;
const TEST_STREAM_DUPLICATE: u64 = 2;
const TEST_STREAM_JITTER: u64 = 3;
const TEST_STREAM_DELAY_ORDER: u64 = 4;
const TEST_STREAM_MSG_TYPE: u64 = 10;
const TEST_STREAM_MSG_ROUND: u64 = 11;
const TEST_STREAM_MSG_VALUE: u64 = 12;
const TEST_STREAM_MSG_PREPARED_ROUND: u64 = 13;
const TEST_STREAM_MSG_PREPARED_VALUE: u64 = 14;
const TRACE_DUMP_LIMIT: usize = 200;
const TEST_WAIT_TIMEOUT: Duration = Duration::from_secs(1);
// Wall-clock guard catches lack of harness progress. Fake time still controls
// protocol progress, so slow-but-progressing parallel runs should not fail.
const TEST_STALL_TIMEOUT: Duration = Duration::from_secs(20);

type RunOutcome = std::thread::Result<Result<()>>;
type TestMsgRef = Msg<TestQbft>;

struct TestQbft;

impl QbftTypes for TestQbft {
    type Compare = i64;
    type Instance = i64;
    type Value = i64;
}

struct PendingCompareGuard {
    pending_compares: Arc<AtomicUsize>,
}

impl Drop for PendingCompareGuard {
    fn drop(&mut self) {
        self.pending_compares.fetch_sub(1, Ordering::SeqCst);
    }
}

fn complete_timer_action(pending_timer_actions: &AtomicIsize) {
    pending_timer_actions.fetch_sub(1, Ordering::SeqCst);
}

struct PendingBroadcast {
    deliver_at: Duration,
    key: u64,
    msg: TestMsgRef,
}

enum BroadcastEvent {
    Immediate(TestMsgRef),
    Delayed(PendingBroadcast),
}

#[derive(Default, Debug)]
struct Test {
    /// Consensus instance, only affects leader election.
    pub instance: i64,
    /// Results in 1s round timeout, otherwise exponential (1s,2s,4s...)
    pub const_period: bool,
    /// Delays start of certain processes
    pub start_delay: HashMap<i64, Duration>,
    /// Delays input value availability of certain processes
    pub value_delay: HashMap<i64, Duration>,
    /// [0..1] - probability of dropped messages per processes
    pub drop_prob: HashMap<i64, f64>,
    /// Add random delays to broadcast of messages.
    pub bcast_jitter_ms: i32,
    /// Only broadcast commits after this round.
    pub commits_after: i32,
    /// Deterministic consensus at specific round
    pub decide_round: i32,
    /// If prepared value decided, as opposed to leader's value.
    pub prepared_val: i32,
    /// Non-deterministic consensus at random round.
    pub random_round: bool,
    /// Enables fuzzing by node 1.
    pub fuzz: bool,
}

// Main QBFT simulation harness:
// 1. build one fake clock, four node transports, and QBFT callbacks;
// 2. spawn one thread per node running `qbft::run`;
// 3. route broadcasts through the in-memory network with optional
//    drop/jitter/fuzz;
// 4. advance fake time only after pending compare/timer work is drained;
// 5. collect all decisions and assert same value plus expected round/value.
fn test_qbft(test: Test) {
    const N: usize = 4;
    const MAX_ROUND: usize = 50;
    const FIFO_LIMIT: usize = 100;

    let seed = test_seed(&test);
    let trace = Trace::new();
    let start_time = time::Instant::now();
    let real_start = time::Instant::now();
    let clock = FakeClock::new(start_time);

    let cts = CancellationTokenSource::new();
    let pending_compares = Arc::new(AtomicUsize::new(0));
    let pending_timer_actions = Arc::new(AtomicIsize::new(0));
    // Keep peer iteration deterministic. These fake-clock tests assert exact
    // rounds, and broadcast fanout order affects which node observes quorums
    // first when tests run in parallel.
    let mut receives =
        BTreeMap::<i64, (mpmc::Sender<Msg<TestQbft>>, mpmc::Receiver<Msg<TestQbft>>)>::new();
    let (broadcast_tx, broadcast_rx) = mpmc::unbounded::<BroadcastEvent>();
    let (unjust_tx, unjust_rx) = mpmc::unbounded::<String>();
    let (result_chan_tx, result_chan_rx) = mpmc::bounded::<Vec<Msg<TestQbft>>>(N);
    let (run_chan_tx, run_chan_rx) = mpmc::bounded::<(i64, RunOutcome)>(N);
    let expected_initial_timers = N + test
        .value_delay
        .keys()
        .filter(|process| !test.start_delay.contains_key(process))
        .count();

    let is_leader = Box::new(make_is_leader(N as i64));

    let defs = Arc::new(Definition {
        is_leader: is_leader.clone(),
        new_timer: {
            let clock = clock.clone();

            Box::new(move |round| {
                let d: Duration = if test.const_period {
                    Duration::from_secs(1)
                } else {
                    // If not constant periods, then exponential.
                    Duration::from_secs(u64::pow(2, (round as u32) - 1))
                };

                let (receive, stop) = clock.new_timer(d);
                Timer { receive, stop }
            })
        },
        decide: {
            let result_chan_tx = result_chan_tx.clone();
            Box::new(move |req| {
                result_chan_tx
                    .send(req.qcommit.clone())
                    .expect(WRITE_CHAN_ERR);
            })
        },
        compare: {
            let pending_compares = pending_compares.clone();
            Arc::new(move |req| {
                let _guard = PendingCompareGuard {
                    pending_compares: pending_compares.clone(),
                };
                req.return_err.send(Ok(())).expect(WRITE_CHAN_ERR);
            })
        },
        nodes: N as i64,
        fifo_limit: FIFO_LIMIT as i64,
        logger: QbftLogger {
            round_change: {
                let clock = clock.clone();
                let trace = trace.clone();
                let pending_timer_actions = pending_timer_actions.clone();

                Box::new(move |req| {
                    if req.upon_rule == UPON_ROUND_TIMEOUT {
                        complete_timer_action(&pending_timer_actions);
                    }

                    trace.push(format!(
                        "{:?} - {}@{} change to {} ~= {}",
                        clock.elapsed(),
                        req.process,
                        req.round,
                        req.new_round,
                        req.upon_rule,
                    ));
                })
            },
            unjust: {
                let trace = trace.clone();
                let unjust_tx = unjust_tx.clone();
                let fuzz = test.fuzz;
                Box::new(move |req| {
                    let line = format!("Unjust: process={} msg={:?}", req.process, req.msg);
                    trace.push(line.clone());
                    if !fuzz {
                        unjust_tx.send(line).expect(WRITE_CHAN_ERR);
                    }
                })
            },
            upon_rule: {
                let clock = clock.clone();
                let trace = trace.clone();
                let pending_compares = pending_compares.clone();
                Box::new(move |req| {
                    if req.upon_rule == UPON_JUSTIFIED_PRE_PREPARE {
                        pending_compares.fetch_add(1, Ordering::SeqCst);
                    }

                    trace.push(format!(
                        "{:?} {} => {}@{} -> {}@{} ~= {}",
                        clock.elapsed(),
                        req.msg.source(),
                        req.msg.type_(),
                        req.msg.round(),
                        req.process,
                        req.round,
                        req.upon_rule,
                    ));
                })
            },
        },
    });

    thread::scope(|s| {
        for i in 1..=N as i64 {
            let (sender, receiver) = mpmc::bounded::<Msg<TestQbft>>(1000);
            let broadcast_tx = broadcast_tx.clone();
            receives.insert(i, (sender.clone(), receiver.clone()));

            let trans = Transport {
                broadcast: {
                    let clock = clock.clone();
                    let trace = trace.clone();

                    Box::new(move |req| {
                        if req.round > MAX_ROUND as i64 {
                            return Err(QbftError::MaxRoundReached);
                        }

                        if req.type_ == MSG_COMMIT && req.round <= test.commits_after.into() {
                            trace.push(format!(
                                "{:?} {} dropping commit for round {}",
                                clock.elapsed(),
                                req.source,
                                req.round
                            ));
                            return Ok(());
                        }

                        trace.push(format!(
                            "{:?} {} => {}@{}",
                            clock.elapsed(),
                            req.source,
                            req.type_,
                            req.round
                        ));

                        let msg = new_msg(
                            req.type_,
                            *req.instance,
                            req.source,
                            req.round,
                            *req.value,
                            *req.value,
                            req.prepared_round,
                            *req.prepared_value,
                            req.justification,
                        );
                        sender.send(msg.clone()).expect(WRITE_CHAN_ERR);

                        bcast(
                            broadcast_tx.clone(),
                            msg.clone(),
                            test.bcast_jitter_ms,
                            clock.clone(),
                            trace.clone(),
                            seed,
                        );

                        Ok(())
                    })
                },
                receive: receiver.clone(),
            };

            let token = cts.token().clone();
            let clock = clock.clone();
            let receiver = receiver.clone();
            let start_delay = test.start_delay.get(&i).copied();
            let value_delay = test.value_delay.get(&i).copied();
            let decide_round = test.decide_round;
            let run_chan_tx = run_chan_tx.clone();
            let defs = defs.clone();
            let is_leader = is_leader.clone();
            let pending_timer_actions = pending_timer_actions.clone();
            let trace = trace.clone();

            s.spawn(move || {
                let mut start_timer_fired = false;
                if let Some(delay) = start_delay {
                    trace.push(format!(
                        "{:?} Node {} start delay {:?}",
                        clock.elapsed(),
                        i,
                        delay
                    ));
                    let (delay_ch, _) =
                        clock.new_timer_with_priority(delay, TimerPriority::StartDelay);
                    if delay_ch.recv().is_ok() {
                        start_timer_fired = true;
                        trace.push(format!(
                            "{:?} Node {} starting {:?}",
                            clock.elapsed(),
                            i,
                            delay
                        ));
                    }
                }

                if start_delay.is_some() {
                    // Drain any buffered messages
                    while !receiver.is_empty() {
                        _ = receiver.recv().expect(READ_CHAN_ERR);
                    }
                }
                if start_timer_fired {
                    complete_timer_action(&pending_timer_actions);
                }

                let (v_chan_tx, v_chan_rx) = mpmc::bounded::<i64>(1);
                let (vs_chan_tx, vs_chan_rx) = mpmc::bounded::<i64>(1);
                let mut keep_value_sender = Some(v_chan_tx);
                let mut input_value_rx = v_chan_rx;

                if let Some(delay) = value_delay {
                    let v_chan_tx_send = keep_value_sender
                        .as_ref()
                        .expect("value sender kept until run returns")
                        .clone();
                    let pending_timer_actions = pending_timer_actions.clone();
                    let (delay_ch, cancel) =
                        clock.new_timer_with_priority(delay, TimerPriority::InputValue);
                    s.spawn(move || {
                        if delay_ch.recv().is_ok() {
                            _ = v_chan_tx_send.send(i);
                            complete_timer_action(&pending_timer_actions);
                        }

                        cancel();
                    });
                } else if decide_round != 1 {
                    let v_chan_tx_send = keep_value_sender
                        .as_ref()
                        .expect("value sender kept until run returns")
                        .clone();
                    s.spawn(move || {
                        _ = v_chan_tx_send.send(i);
                    });
                } else if is_leader(LeaderRequest {
                    instance: &test.instance,
                    round: 1,
                    process: i,
                }) {
                    let v_chan_tx_send = keep_value_sender
                        .as_ref()
                        .expect("value sender kept until run returns")
                        .clone();
                    s.spawn(move || {
                        _ = v_chan_tx_send.send(i);
                    });
                } else {
                    keep_value_sender = None;
                    input_value_rx = mpmc::never();
                }

                let keepalive = (keep_value_sender, vs_chan_tx);
                let run_result = panic::catch_unwind(AssertUnwindSafe(|| {
                    qbft::run(
                        &token,
                        &defs,
                        &trans,
                        &test.instance,
                        i,
                        input_value_rx,
                        vs_chan_rx,
                    )
                }));
                drop(keepalive);
                run_chan_tx.send((i, run_result)).expect(WRITE_CHAN_ERR);
            });
        }

        while clock.timer_count() < expected_initial_timers {
            thread::yield_now();
            if real_start.elapsed() > TEST_STALL_TIMEOUT {
                cts.cancel();
                clock.cancel();
                panic!(
                    "qbft test setup hang: timers={} expected={} seed={}\n{}",
                    clock.timer_count(),
                    expected_initial_timers,
                    seed,
                    trace.dump()
                );
            }
        }

        let mut results = BTreeMap::<i64, Msg<TestQbft>>::new();
        let mut count = 0;
        let mut decided = false;
        let mut done = 0;
        let mut broadcasts = 0usize;
        let mut pending = Vec::<PendingBroadcast>::new();
        let mut next_fuzz_at = test.fuzz.then_some(Duration::from_millis(100));
        let mut fuzz_counter = 0_u64;
        let mut last_progress = time::Instant::now();

        loop {
            let delivered = deliver_ready_broadcasts(
                &mut pending,
                &receives,
                &test.drop_prob,
                seed,
                &trace,
                &clock,
            );
            broadcasts += delivered;
            if delivered > 0 {
                last_progress = time::Instant::now();
            }

            if decided {
                next_fuzz_at = None;
            }

            while let Some(next) = next_fuzz_at {
                if clock.elapsed() < next {
                    break;
                }

                let msg = random_msg(test.instance, 1, seed, fuzz_counter);
                fuzz_counter = fuzz_counter.wrapping_add(1);
                trace.push(format!(
                    "{:?} fuzz {} => {}@{}",
                    clock.elapsed(),
                    msg.source(),
                    msg.type_(),
                    msg.round()
                ));
                broadcasts +=
                    fanout_broadcast(&receives, &test.drop_prob, seed, &trace, &clock, msg);
                last_progress = time::Instant::now();
                next_fuzz_at = Some(next + Duration::from_millis(100));
            }

            mpmc::select! {
                recv(broadcast_rx) -> event => {
                    match event.expect(READ_CHAN_ERR) {
                        BroadcastEvent::Immediate(msg) => {
                            broadcasts += fanout_broadcast(
                                &receives,
                                &test.drop_prob,
                                seed,
                                &trace,
                                &clock,
                                msg,
                            );
                        }
                        BroadcastEvent::Delayed(delayed) => pending.push(delayed),
                    }
                    last_progress = time::Instant::now();
                    if clock.elapsed() > Duration::from_secs(180) {
                        cts.cancel();
                        clock.cancel();
                        panic!(
                            "qbft test hang: decided={} done={} count={} elapsed={:?} real_elapsed={:?} broadcasts={} seed={}\n{}",
                            decided,
                            done,
                            count,
                            clock.elapsed(),
                            real_start.elapsed(),
                            broadcasts,
                            seed,
                            trace.dump()
                        );
                    }
                }

                recv(unjust_rx) -> unjust => {
                    let unjust = unjust.expect(READ_CHAN_ERR);
                    cts.cancel();
                    clock.cancel();
                    panic!("unjust message: {unjust} elapsed={:?} seed={}\n{}", clock.elapsed(), seed, trace.dump());
                }

                recv(result_chan_rx) -> res => {
                    let q_commit = res.expect(READ_CHAN_ERR);
                    last_progress = time::Instant::now();

                    for commit in q_commit.clone() {
                        for (_, previous) in results.iter() {
                            if previous.value() != commit.value() {
                                cts.cancel();
                                clock.cancel();
                                panic!(
                                    "commit values differ: previous={:?} commit={:?} elapsed={:?} seed={}\n{}",
                                    previous,
                                    commit,
                                    clock.elapsed(),
                                    seed,
                                    trace.dump()
                                );
                            }
                        }

                        if !test.random_round {
                            if i64::from(test.decide_round) != commit.round() {
                                cts.cancel();
                                clock.cancel();
                                panic!(
                                    "wrong decide round: want={} got={} commit={:?} elapsed={:?} seed={}\n{}",
                                    test.decide_round,
                                    commit.round(),
                                    commit,
                                    clock.elapsed(),
                                    seed,
                                    trace.dump()
                                );
                            }

                            if test.prepared_val != 0 { // Check prepared value if set
                                if i64::from(test.prepared_val) != commit.value() {
                                    cts.cancel();
                                    clock.cancel();
                                    panic!(
                                        "wrong prepared value: want={} got={} commit={:?} elapsed={:?} seed={}\n{}",
                                        test.prepared_val,
                                        commit.value(),
                                        commit,
                                        clock.elapsed(),
                                        seed,
                                        trace.dump()
                                    );
                                }
                            } else { // Otherwise check that leader value was used.
                                if !is_leader(LeaderRequest {
                                    instance: &test.instance,
                                    round: commit.round(),
                                    process: commit.value(),
                                }) {
                                    cts.cancel();
                                    clock.cancel();
                                    panic!(
                                        "not leader value: instance={} round={} value={} commit={:?} elapsed={:?} seed={}\n{}",
                                        test.instance,
                                        commit.round(),
                                        commit.value(),
                                        commit,
                                        clock.elapsed(),
                                        seed,
                                        trace.dump()
                                    );
                                }
                            }
                        }

                        results.insert(commit.source(), commit);
                    }

                    count += 1;
                    if count != N {
                        continue;
                    }

                    let round = q_commit[0].round();
                    trace.push(format!("Got all results in round {} after {:?}: {:?}", round, clock.elapsed(), results));

                    // Trigger shutdown
                    decided = true;
                    next_fuzz_at = None;

                    clock.cancel();
                    cts.cancel();
                }

                recv(run_chan_rx) -> res => {
                    let (node, outcome) = res.expect(READ_CHAN_ERR);
                    last_progress = time::Instant::now();

                    if !matches!(outcome, Ok(Ok(()))) {
                        if !decided {
                            cts.cancel();
                            clock.cancel();
                            panic!(
                                "unexpected run error: node={} outcome={} decided={} done={} count={} elapsed={:?} broadcasts={} seed={}\n{}",
                                node,
                                format_run_outcome(&outcome),
                                decided,
                                done,
                                count,
                                clock.elapsed(),
                                broadcasts,
                                seed,
                                trace.dump()
                            );
                        }
                    }

                    done += 1;
                    if done == N {
                        return;
                    }
                }

                default => {
                    if pending_compares.load(Ordering::SeqCst) != 0
                        || pending_timer_actions.load(Ordering::SeqCst) > 0
                    {
                        thread::yield_now();
                        if last_progress.elapsed() > TEST_STALL_TIMEOUT {
                            cts.cancel();
                            clock.cancel();
                            panic!(
                                "qbft test hang: pending_compares={} pending_timer_actions={} decided={} done={} count={} elapsed={:?} real_elapsed={:?} broadcasts={} seed={}\n{}",
                                pending_compares.load(Ordering::SeqCst),
                                pending_timer_actions.load(Ordering::SeqCst),
                                decided,
                                done,
                                count,
                                clock.elapsed(),
                                real_start.elapsed(),
                                broadcasts,
                                seed,
                                trace.dump()
                            );
                        }
                        continue;
                    }

                    // Matches the Go harness throttle; ordering correctness
                    // comes from the pending-work barriers, not this duration.
                    thread::sleep(Duration::from_micros(1));
                    clock.advance_and_wait(Duration::from_millis(1), &pending_timer_actions);
                    last_progress = time::Instant::now();
                    if clock.elapsed() > Duration::from_secs(180) {
                        cts.cancel();
                        clock.cancel();
                        panic!(
                            "qbft test hang: decided={} done={} count={} elapsed={:?} real_elapsed={:?} broadcasts={} seed={}\n{}",
                            decided,
                            done,
                            count,
                            clock.elapsed(),
                            real_start.elapsed(),
                            broadcasts,
                            seed,
                            trace.dump()
                        );
                    }
                }
            }
        }
    });
}

#[derive(Clone, Default)]
struct Trace(Arc<Mutex<VecDeque<String>>>);

impl Trace {
    fn new() -> Self {
        Self::default()
    }

    fn push(&self, line: String) {
        let mut lines = self.0.lock().unwrap();
        if lines.len() == TRACE_DUMP_LIMIT {
            lines.pop_front();
        }
        lines.push_back(line);
    }

    fn dump(&self) -> String {
        let lines = self.0.lock().unwrap();
        let mut out = String::new();
        for line in lines.iter() {
            let _ = writeln!(out, "{line}");
        }
        out
    }
}

fn format_run_outcome(outcome: &RunOutcome) -> String {
    match outcome {
        Ok(Ok(())) => "ok".to_string(),
        Ok(Err(err)) => format!("error {err:?}"),
        Err(payload) => {
            if let Some(msg) = payload.downcast_ref::<&str>() {
                format!("panic {msg}")
            } else if let Some(msg) = payload.downcast_ref::<String>() {
                format!("panic {msg}")
            } else {
                "panic <non-string payload>".to_string()
            }
        }
    }
}

fn outcome_is_error(outcome: &RunOutcome, expected: fn(&QbftError) -> bool) -> bool {
    matches!(outcome, Ok(Err(err)) if expected(err))
}

fn assert_upon_rule(expected: UponRule, actual: UponRule) {
    assert!(actual == expected, "want {expected}, got {actual}");
}

fn test_seed(test: &Test) -> u64 {
    let mut seed = seed_from_label(TEST_SEED_LABEL);
    seed ^= test.instance as u64;
    seed ^= u64::from(test.const_period) << 8;
    seed ^= (test.bcast_jitter_ms as u64) << 16;
    seed ^= (test.commits_after as u64) << 32;
    seed ^= (test.decide_round as u64) << 40;
    seed ^= (test.prepared_val as u64) << 48;
    seed ^= u64::from(test.random_round) << 56;
    seed ^= u64::from(test.fuzz) << 57;
    seed
}

fn seed_from_label(label: &str) -> u64 {
    // Small rolling-hash multiplier; only separates deterministic test labels,
    // not used for cryptographic randomness or protocol behavior.
    label.bytes().fold(0_u64, |seed, byte| {
        seed.wrapping_mul(131).wrapping_add(u64::from(byte))
    })
}

/// Construct a leader election function.
fn make_is_leader(n: i64) -> impl for<'a> Fn(LeaderRequest<'a, TestQbft>) -> bool + Clone {
    move |req| (*req.instance + req.round).rem_euclid(n) == req.process
}

/// Returns a new message to be broadcast.
#[allow(clippy::too_many_arguments)]
fn new_msg(
    type_: MessageType,
    instance: i64,
    source: i64,
    round: i64,
    value: i64,
    value_source: i64,
    pr: i64,
    pv: i64,
    justify: Option<&Vec<Msg<TestQbft>>>,
) -> Msg<TestQbft> {
    let msgs = match justify {
        None => vec![],
        Some(justify) => justify
            .iter()
            .map(|j| {
                let mut j = j
                    .as_any()
                    .downcast_ref::<TestMsg>()
                    .expect("Expected `TestMsg` instance")
                    .clone();
                j.justify = None;
                j
            })
            .collect(),
    };

    Arc::new(TestMsg {
        msg_type: type_,
        instance,
        peer_idx: source,
        round,
        value,
        value_source,
        pr,
        pv,
        justify: Some(msgs),
    })
}

fn new_prepare_quorum(round: i64, value: i64) -> Vec<TestMsgRef> {
    (1..=3)
        .map(|source| new_msg(MSG_PREPARE, 0, source, round, value, 0, 0, 0, None))
        .collect()
}

fn new_round_change(source: i64, round: i64, pr: i64, pv: i64) -> TestMsgRef {
    new_msg(MSG_ROUND_CHANGE, 0, source, round, 0, 0, pr, pv, None)
}

fn new_round_change_quorum(round: i64, pr: i64, pv: i64) -> Vec<TestMsgRef> {
    (1..=3)
        .map(|source| new_round_change(source, round, pr, pv))
        .collect()
}

// Delays the message broadcast by between 1x and 2x jitter_ms and drops
// messages.
fn bcast(
    broadcast: mpmc::Sender<BroadcastEvent>,
    msg: Msg<TestQbft>,
    jitter_ms: i32,
    clock: FakeClock,
    trace: Trace,
    seed: u64,
) {
    if jitter_ms == 0 {
        broadcast
            .send(BroadcastEvent::Immediate(msg.clone()))
            .expect(WRITE_CHAN_ERR);
        return;
    }

    let delta_ms =
        (f64::from(jitter_ms) * deterministic_unit(seed, &msg, 0, TEST_STREAM_JITTER)) as i32;
    let delay = Duration::from_millis((jitter_ms + delta_ms) as u64);
    trace.push(format!(
        "{:?} {} => {}@{} (bcast delay {:?})",
        clock.elapsed(),
        msg.source(),
        msg.type_(),
        msg.round(),
        delay
    ));
    let key = deterministic_msg_u64(seed, &msg, 0, TEST_STREAM_DELAY_ORDER);
    broadcast
        .send(BroadcastEvent::Delayed(PendingBroadcast {
            deliver_at: clock.elapsed() + delay,
            key,
            msg,
        }))
        .expect(WRITE_CHAN_ERR);
}

fn deliver_ready_broadcasts(
    pending: &mut Vec<PendingBroadcast>,
    receives: &BTreeMap<i64, (mpmc::Sender<TestMsgRef>, mpmc::Receiver<TestMsgRef>)>,
    drop_prob: &HashMap<i64, f64>,
    seed: u64,
    trace: &Trace,
    clock: &FakeClock,
) -> usize {
    pending.sort_by_key(|delayed| (delayed.deliver_at, delayed.key));
    let ready_count = pending
        .iter()
        .take_while(|delayed| delayed.deliver_at <= clock.elapsed())
        .count();

    pending
        .drain(..ready_count)
        .map(|delayed| fanout_broadcast(receives, drop_prob, seed, trace, clock, delayed.msg))
        .sum()
}

fn fanout_broadcast(
    receives: &BTreeMap<i64, (mpmc::Sender<TestMsgRef>, mpmc::Receiver<TestMsgRef>)>,
    drop_prob: &HashMap<i64, f64>,
    seed: u64,
    trace: &Trace,
    clock: &FakeClock,
    msg: TestMsgRef,
) -> usize {
    let mut broadcasts = 0;
    for (target, (out_tx, _)) in receives.iter() {
        if *target == msg.source() {
            continue; // Do not broadcast to self, we sent to self already.
        }

        if let Some(p) = drop_prob.get(&msg.source()) {
            if deterministic_unit(seed, &msg, *target, TEST_STREAM_DROP) < *p {
                trace.push(format!(
                    "{:?} {} => {}@{} => {} (dropped)",
                    clock.elapsed(),
                    msg.source(),
                    msg.type_(),
                    msg.round(),
                    target
                ));
                continue;
            }
        }

        out_tx.send(msg.clone()).expect(WRITE_CHAN_ERR);
        broadcasts += 1;

        if deterministic_unit(seed, &msg, *target, TEST_STREAM_DUPLICATE) < 0.1 {
            out_tx.send(msg.clone()).expect(WRITE_CHAN_ERR);
            broadcasts += 1;
            trace.push(format!(
                "{:?} {} => {}@{} => {} (duplicate)",
                clock.elapsed(),
                msg.source(),
                msg.type_(),
                msg.round(),
                target
            ));
        }
    }

    broadcasts
}

fn random_msg(instance: i64, peer_idx: i64, seed: u64, counter: u64) -> Msg<TestQbft> {
    let message_types = [
        MSG_PRE_PREPARE,
        MSG_PREPARE,
        MSG_COMMIT,
        MSG_ROUND_CHANGE,
        MSG_DECIDED,
    ];
    new_msg(
        message_types
            [deterministic_range(seed, counter, TEST_STREAM_MSG_TYPE, message_types.len())],
        instance,
        peer_idx,
        deterministic_i64(seed, counter, TEST_STREAM_MSG_ROUND, 10),
        deterministic_i64(seed, counter, TEST_STREAM_MSG_VALUE, 10),
        0,
        deterministic_i64(seed, counter, TEST_STREAM_MSG_PREPARED_ROUND, 10),
        deterministic_i64(seed, counter, TEST_STREAM_MSG_PREPARED_VALUE, 10),
        None,
    )
}

fn deterministic_unit(seed: u64, msg: &Msg<TestQbft>, target: i64, stream_id: u64) -> f64 {
    let value = deterministic_msg_u64(seed, msg, target, stream_id) >> 11;
    value as f64 / ((1_u64 << 53) as f64)
}

fn deterministic_msg_u64(seed: u64, msg: &Msg<TestQbft>, target: i64, stream_id: u64) -> u64 {
    let mut value = splitmix64(seed ^ stream_id);
    value = splitmix64(value ^ i64_to_u64(msg.type_().0));
    value = splitmix64(value ^ i64_to_u64(msg.instance()));
    value = splitmix64(value ^ i64_to_u64(msg.source()));
    value = splitmix64(value ^ i64_to_u64(msg.round()));
    value = splitmix64(value ^ i64_to_u64(msg.value()));
    value = splitmix64(value ^ i64_to_u64(msg.value_source().unwrap_or_default()));
    value = splitmix64(value ^ i64_to_u64(msg.prepared_round()));
    value = splitmix64(value ^ i64_to_u64(msg.prepared_value()));
    splitmix64(value ^ i64_to_u64(target))
}

fn deterministic_range(seed: u64, counter: u64, stream_id: u64, upper: usize) -> usize {
    let upper = u64::try_from(upper).expect("upper fits in u64");
    usize::try_from(splitmix64(seed ^ counter ^ stream_id) % upper).expect("range fits in usize")
}

fn deterministic_i64(seed: u64, counter: u64, stream_id: u64, upper: i64) -> i64 {
    let upper = u64::try_from(upper).expect("upper is positive");
    i64::try_from(splitmix64(seed ^ counter ^ stream_id) % upper).expect("range fits in i64")
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn i64_to_u64(value: i64) -> u64 {
    u64::from_le_bytes(value.to_le_bytes())
}

#[derive(Clone, Debug)]
struct TestMsg {
    msg_type: MessageType,
    instance: i64,
    peer_idx: i64,
    round: i64,
    value: i64,
    value_source: i64,
    pr: i64,
    pv: i64,
    justify: Option<Vec<TestMsg>>,
}

impl SomeMsg<TestQbft> for TestMsg {
    fn type_(&self) -> MessageType {
        self.msg_type
    }

    fn instance(&self) -> i64 {
        self.instance
    }

    fn source(&self) -> i64 {
        self.peer_idx
    }

    fn round(&self) -> i64 {
        self.round
    }

    fn value(&self) -> i64 {
        self.value
    }

    fn value_source(&self) -> Result<i64> {
        Ok(self.value_source)
    }

    fn prepared_round(&self) -> i64 {
        self.pr
    }

    fn prepared_value(&self) -> i64 {
        self.pv
    }

    fn justification(&self) -> Vec<Msg<TestQbft>> {
        match self.justify {
            None => vec![],
            Some(ref j) => j
                .iter()
                .map(|j| Arc::new(j.clone()) as Msg<TestQbft>)
                .collect(),
        }
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}

// Tests the normal-case path with an available round-1 leader.
// Expect all nodes to decide in round 1 on the leader value.
#[test_case(0 ; "happy_0")]
#[test_case(1 ; "happy_1")]
fn happy(instance: i64) {
    test_qbft(Test {
        instance,
        decide_round: 1,
        ..Default::default()
    });
}

// Tests prepared-value carryover when commits are suppressed in earlier rounds.
// Expect later rounds to decide the highest prepared value, not a new leader
// value.
#[test_case(1, None, 2, 1, false ; "prepare_round_1_decide_round_2")]
#[test_case(2, Some(2), 3, 2, true ; "prepare_round_2_decide_round_3")]
fn prepare_round(
    commits_after: i32,
    value_delay_secs: Option<u64>,
    decide_round: i32,
    prepared_val: i32,
    const_period: bool,
) {
    test_qbft(Test {
        instance: 0,
        commits_after,
        value_delay: value_delay_secs
            .map(|secs| HashMap::from([(1, Duration::from_secs(secs))]))
            .unwrap_or_default(),
        decide_round,
        prepared_val,
        const_period,
        ..Default::default()
    });
}

// Tests round change when the first leader starts late.
// Expect the next live leader to drive consensus in round 2.
#[test_case(false ; "leader_late_exp")]
#[test_case(true ; "leader_down_const")]
fn delayed_leader_start(const_period: bool) {
    test_qbft(Test {
        instance: 0,
        start_delay: HashMap::from([(1, Duration::from_secs(2))]),
        decide_round: 2,
        const_period,
        ..Default::default()
    });
}

// Tests recovery when two nodes, including early leaders, start much later.
// Expect consensus after enough round changes, with exact round only when
// deterministic.
#[test_case(3, false, 4, false ; "very_late_exp")]
#[test_case(1, true, 0, true ; "very_late_const")]
fn very_late_start(instance: i64, const_period: bool, decide_round: i32, random_round: bool) {
    test_qbft(Test {
        instance,
        start_delay: HashMap::from([(1, Duration::from_secs(5)), (2, Duration::from_secs(10))]),
        decide_round,
        const_period,
        random_round,
        ..Default::default()
    });
}

// Tests staggered node startup and message buffering/draining.
// Expect consensus once enough live nodes join, with round allowed to vary.
#[test_case(false ; "stagger_start_exp")]
#[test_case(true ; "stagger_start_const")]
fn stagger_start(const_period: bool) {
    test_qbft(Test {
        instance: 0,
        start_delay: HashMap::from([
            (1, Duration::from_secs(0)),
            (2, Duration::from_secs(1)),
            (3, Duration::from_secs(2)),
            (4, Duration::from_secs(3)),
        ]),
        const_period,
        random_round: true, // Takes 1 or 2 rounds.
        ..Default::default()
    });
}

// Tests late input values on nodes that otherwise participate in the protocol.
// Expect round changes until a valid leader value is available.
#[test_case(3, false, 4, false ; "very_delayed_value_exp")]
#[test_case(1, true, 0, true ; "very_delayed_value_const")]
fn very_delayed_value(instance: i64, const_period: bool, decide_round: i32, random_round: bool) {
    test_qbft(Test {
        instance,
        value_delay: HashMap::from([(1, Duration::from_secs(5)), (2, Duration::from_secs(10))]),
        const_period,
        decide_round,
        random_round,
        ..Default::default()
    });
}

// Tests input values arriving at different fake times for all nodes.
// Expect consensus once enough nodes can validate/propose values.
#[test_case(false ; "stagger_delayed_value_exp")]
#[test_case(true ; "stagger_delayed_value_const")]
fn stagger_delayed_value(const_period: bool) {
    test_qbft(Test {
        instance: 0,
        value_delay: HashMap::from([
            (1, Duration::from_secs(0)),
            (2, Duration::from_secs(1)),
            (3, Duration::from_secs(2)),
            (4, Duration::from_secs(3)),
        ]),
        const_period,
        random_round: true,
        ..Default::default()
    });
}

// Tests a round-1 leader without input and a round-2 leader that is offline.
// Expect consensus to skip both blocked leaders and decide in round 3.
#[test]
fn round1_leader_no_value_round2_leader_offline() {
    test_qbft(Test {
        instance: 0,
        value_delay: HashMap::from([(1, Duration::from_secs(1))]),
        start_delay: HashMap::from([(2, Duration::from_secs(2))]),
        const_period: true,
        decide_round: 3,
        ..Default::default()
    });
}

// Tests delayed broadcast delivery under fake network jitter.
// Expect safety and eventual consensus despite delayed messages.
#[test_case(500, false ; "jitter_500ms_exp")]
#[test_case(200, true ; "jitter_200ms_const")]
fn jitter(bcast_jitter_ms: i32, const_period: bool) {
    test_qbft(Test {
        instance: 3,
        bcast_jitter_ms,
        const_period,
        random_round: true,
        ..Default::default()
    });
}

// Tests deterministic message loss at 10% and 30%.
// Expect eventual consensus without conflicting decisions.
#[test_case(0.1 ; "drop_10_percent_const")]
#[test_case(0.3 ; "drop_30_percent_const")]
fn dropped_messages(drop_probability: f64) {
    test_qbft(Test {
        instance: 1,
        drop_prob: HashMap::from([
            (1, drop_probability),
            (2, drop_probability),
            (3, drop_probability),
            (4, drop_probability),
        ]),
        const_period: true,
        random_round: true,
        ..Default::default()
    });
}

// Tests bogus message injection during normal and delayed-leader scenarios.
// Expect unjust fuzz traffic to be ignored and honest nodes to still decide.
#[test_case(None, 1, false ; "fuzz")]
#[test_case(Some(2), 0, true ; "fuzz_with_late_leader")]
#[test_case(Some(10), 0, true ; "fuzz_with_very_late_leader")]
fn fuzzed(start_delay_secs: Option<u64>, decide_round: i32, random_round: bool) {
    test_qbft(Test {
        instance: 1,
        fuzz: true,
        start_delay: start_delay_secs
            .map(|secs| {
                HashMap::from([
                    (1, Duration::from_secs(secs)),
                    (2, Duration::from_secs(secs)),
                ])
            })
            .unwrap_or_default(),
        const_period: true,
        decide_round,
        random_round,
        ..Default::default()
    });
}

fn noop_definition() -> Definition<TestQbft> {
    Definition {
        is_leader: Box::new(|_| false),
        new_timer: Box::new(|_| Timer {
            receive: mpmc::never(),
            stop: Box::new(|| {}),
        }),
        decide: Box::new(|_| {}),
        compare: Arc::new(|_| {}),
        nodes: 0,
        fifo_limit: 0,
        logger: QbftLogger {
            round_change: Box::new(|_| {}),
            unjust: Box::new(|_| {}),
            upon_rule: Box::new(|_| {}),
        },
    }
}

fn noop_transport() -> Transport<TestQbft> {
    Transport {
        broadcast: Box::new(|_| Ok(())),
        receive: mpmc::never(),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BroadcastRecord {
    canceled: bool,
    type_: MessageType,
    instance: i64,
    source: i64,
    round: i64,
    value: i64,
    prepared_round: i64,
    prepared_value: i64,
    justification_len: usize,
}

#[test]
fn broadcast_request_maps_protocol_fields() {
    let (receive_tx, receive_rx) = mpmc::bounded::<Msg<TestQbft>>(4);
    receive_tx
        .send(new_msg(MSG_PRE_PREPARE, 0, 1, 1, 7, 7, 0, 0, None))
        .expect(WRITE_CHAN_ERR);
    for source in 1..=3 {
        receive_tx
            .send(new_msg(MSG_PREPARE, 0, source, 1, 7, 7, 0, 0, None))
            .expect(WRITE_CHAN_ERR);
    }

    let cts = CancellationTokenSource::new();
    let token = cts.token().clone();
    let (record_tx, record_rx) = mpmc::unbounded();
    let transport = Transport {
        broadcast: Box::new(move |req| {
            record_tx
                .send(BroadcastRecord {
                    canceled: req.ct.is_canceled(),
                    type_: req.type_,
                    instance: *req.instance,
                    source: req.source,
                    round: req.round,
                    value: *req.value,
                    prepared_round: req.prepared_round,
                    prepared_value: *req.prepared_value,
                    justification_len: req.justification.map_or(0, Vec::len),
                })
                .expect(WRITE_CHAN_ERR);
            if req.type_ == MSG_COMMIT {
                cts.cancel();
            }
            Ok(())
        }),
        receive: receive_rx,
    };
    let mut def = noop_definition();
    def.nodes = 4;
    def.fifo_limit = 100;
    def.is_leader = Box::new(|req| req.process == 1);
    def.compare = Arc::new(|req| req.return_err.send(Ok(())).expect(WRITE_CHAN_ERR));

    let (_input_tx, input_rx) = mpmc::bounded::<i64>(1);
    let (_source_tx, source_rx) = mpmc::bounded::<i64>(1);
    assert!(matches!(
        qbft::run(&token, &def, &transport, &0, 2, input_rx, source_rx),
        Err(QbftError::ContextCanceled)
    ));
    assert_eq!(
        record_rx.try_iter().collect::<Vec<_>>(),
        vec![
            BroadcastRecord {
                canceled: false,
                type_: MSG_PREPARE,
                instance: 0,
                source: 2,
                round: 1,
                value: 7,
                prepared_round: 0,
                prepared_value: 0,
                justification_len: 0,
            },
            BroadcastRecord {
                canceled: false,
                type_: MSG_COMMIT,
                instance: 0,
                source: 2,
                round: 1,
                value: 7,
                prepared_round: 0,
                prepared_value: 0,
                justification_len: 0,
            },
        ]
    );

    let (timer_tx, timer_rx) = mpmc::bounded(1);
    timer_tx.send(time::Instant::now()).expect(WRITE_CHAN_ERR);
    let cts = CancellationTokenSource::new();
    let token = cts.token().clone();
    let (record_tx, record_rx) = mpmc::unbounded();
    let transport = Transport {
        broadcast: Box::new(move |req| {
            record_tx
                .send(BroadcastRecord {
                    canceled: req.ct.is_canceled(),
                    type_: req.type_,
                    instance: *req.instance,
                    source: req.source,
                    round: req.round,
                    value: *req.value,
                    prepared_round: req.prepared_round,
                    prepared_value: *req.prepared_value,
                    justification_len: req.justification.map_or(0, Vec::len),
                })
                .expect(WRITE_CHAN_ERR);
            cts.cancel();
            Ok(())
        }),
        receive: mpmc::never(),
    };
    let mut def = noop_definition();
    def.nodes = 4;
    def.fifo_limit = 100;
    def.new_timer = Box::new(move |_| Timer {
        receive: timer_rx.clone(),
        stop: Box::new(|| {}),
    });

    let (_input_tx, input_rx) = mpmc::bounded::<i64>(1);
    let (_source_tx, source_rx) = mpmc::bounded::<i64>(1);
    assert!(matches!(
        qbft::run(&token, &def, &transport, &0, 2, input_rx, source_rx),
        Err(QbftError::ContextCanceled)
    ));
    assert_eq!(
        record_rx.try_iter().collect::<Vec<_>>(),
        vec![BroadcastRecord {
            canceled: false,
            type_: MSG_ROUND_CHANGE,
            instance: 0,
            source: 2,
            round: 2,
            value: 0,
            prepared_round: 0,
            prepared_value: 0,
            justification_len: 0,
        }]
    );
}

// Tests quorum/faulty formulas across node counts.
// Expect quorum and tolerated-fault counts to match the Charon formula.
#[test_case(1, 1, 0 ; "n1")]
#[test_case(2, 2, 0 ; "n2")]
#[test_case(3, 2, 0 ; "n3")]
#[test_case(4, 3, 1 ; "n4")]
#[test_case(5, 4, 1 ; "n5")]
#[test_case(6, 4, 1 ; "n6")]
#[test_case(7, 5, 2 ; "n7")]
#[test_case(8, 6, 2 ; "n8")]
#[test_case(9, 6, 2 ; "n9")]
#[test_case(10, 7, 3 ; "n10")]
#[test_case(11, 8, 3 ; "n11")]
#[test_case(12, 8, 3 ; "n12")]
#[test_case(13, 9, 4 ; "n13")]
#[test_case(14, 10, 4 ; "n14")]
#[test_case(15, 10, 4 ; "n15")]
#[test_case(16, 11, 5 ; "n16")]
#[test_case(17, 12, 5 ; "n17")]
#[test_case(18, 12, 5 ; "n18")]
#[test_case(19, 13, 6 ; "n19")]
#[test_case(20, 14, 6 ; "n20")]
#[test_case(21, 14, 6 ; "n21")]
#[test_case(22, 15, 7 ; "n22")]
fn formulas(n: i64, q: i64, f: i64) {
    let d = Definition::<TestQbft> {
        nodes: n,
        ..noop_definition()
    };
    assert_eq!(q, d.quorum(), "Quorum given N={n}");
    assert_eq!(f, d.faulty(), "Faulty given N={n}");
}

// Tests PRE-PREPARE justification with mixed ROUND_CHANGE and PREPARE evidence.
// Expect the proposal to be accepted when it carries a justified prepared
// value.
#[test]
fn is_justified_pre_prepare_mixed_round_change_prepare_fixture() {
    let preprepare = new_msg(
        MSG_PRE_PREPARE,
        1,
        3,
        6,
        2,
        0,
        0,
        0,
        Some(&vec![
            new_msg(MSG_ROUND_CHANGE, 1, 2, 6, 0, 0, 2, 3, None),
            new_msg(MSG_ROUND_CHANGE, 1, 3, 6, 0, 0, 2, 3, None),
            new_msg(MSG_ROUND_CHANGE, 1, 1, 6, 0, 0, 2, 2, None),
            new_msg(MSG_PREPARE, 1, 3, 2, 2, 0, 0, 0, None),
            new_msg(MSG_PREPARE, 1, 4, 2, 2, 0, 0, 0, None),
            new_msg(MSG_PREPARE, 1, 1, 2, 2, 0, 0, 0, None),
            new_msg(MSG_PREPARE, 1, 2, 2, 2, 0, 0, 0, None),
        ]),
    );
    let mut def = noop_definition();
    def.nodes = 4;
    def.is_leader = Box::new(make_is_leader(4));

    assert!(is_justified_pre_prepare(&def, &1, &preprepare, 0));
}

// Tests duplicate PRE-PREPARE rule handling after compare failure.
// Expect the next round proposal to trigger once and exit by cancellation.
#[test]
fn duplicate_pre_prepare_rules() {
    let cts = CancellationTokenSource::new();
    let ct = &cts.token().clone();

    const NO_LEADER: i64 = 1;
    const LEADER: i64 = 2;

    let new_preprepare = |round: i64| -> Msg<TestQbft> {
        new_msg(
            MSG_PRE_PREPARE,
            0,
            LEADER,
            round,
            0,
            0,
            0,
            0,
            // Round 2 is accepted after round 1 records a compare failure.
            None,
        )
    };

    let mut def = noop_definition();
    def.nodes = 4;
    def.fifo_limit = 100;
    def.is_leader = Box::new(|req| req.process == LEADER);
    def.logger.upon_rule = Box::new(move |req| {
        println!(
            "UponRule: rule={} round={} ",
            req.upon_rule,
            req.msg.round()
        );

        assert!(req.upon_rule == UPON_JUSTIFIED_PRE_PREPARE);

        if req.msg.round() == 1 {
            return;
        }

        if req.msg.round() == 2 {
            cts.cancel();
            return;
        }

        panic!("unexpected round {}", req.round);
    });
    def.compare = Arc::new(|req| {
        let result = if req.qcommit.round() == 1 {
            Err(QbftError::CompareError)
        } else {
            Ok(())
        };
        req.return_err.send(result).expect(WRITE_CHAN_ERR);
    });

    let (r_chan_tx, r_chan_rx) = mpmc::bounded::<Msg<TestQbft>>(2);
    r_chan_tx.send(new_preprepare(1)).expect(WRITE_CHAN_ERR);
    r_chan_tx.send(new_preprepare(2)).expect(WRITE_CHAN_ERR);

    let mut transport = noop_transport();
    transport.receive = r_chan_rx;

    let (ch, input_value_ch) = mpmc::bounded::<i64>(1);
    ch.send(1).expect(WRITE_CHAN_ERR);
    let (ch, input_value_source_ch) = mpmc::bounded::<i64>(1);
    ch.send(2).expect(WRITE_CHAN_ERR);

    let res = qbft::run(
        ct,
        &def,
        &transport,
        &0,
        NO_LEADER,
        input_value_ch,
        input_value_source_ch,
    );

    assert!(matches!(res, Err(QbftError::ContextCanceled)));
}

// Tests idle cancellation while no inputs, timers, or messages are available.
// Expect `run` to unblock and return `ContextCanceled`.
#[test]
fn idle_run_returns_when_cancelled() {
    let cts = CancellationTokenSource::new();
    let token = cts.token().clone();
    let mut def = noop_definition();
    def.nodes = 4;
    def.fifo_limit = 100;
    let transport = noop_transport();
    let (_input_tx, input_rx) = mpmc::bounded::<i64>(1);
    let (_source_tx, source_rx) = mpmc::bounded::<i64>(1);
    let (done_tx, done_rx) = mpmc::bounded(1);
    let (started_tx, started_rx) = mpmc::bounded(1);

    thread::spawn(move || {
        started_tx.send(()).expect(WRITE_CHAN_ERR);
        done_tx
            .send(qbft::run(
                &token, &def, &transport, &0, 1, input_rx, source_rx,
            ))
            .expect(WRITE_CHAN_ERR);
    });

    started_rx
        .recv_timeout(TEST_WAIT_TIMEOUT)
        .expect("run thread must start before cancellation");
    cts.cancel();

    assert!(matches!(
        done_rx
            .recv_timeout(TEST_WAIT_TIMEOUT)
            .expect("idle run must unblock on cancellation"),
        Err(QbftError::ContextCanceled)
    ));
}

fn run_with_definition(def: &Definition<TestQbft>) -> Result<()> {
    let cts = CancellationTokenSource::new();
    let transport = noop_transport();
    let (_input_tx, input_rx) = mpmc::bounded::<i64>(1);
    let (_source_tx, source_rx) = mpmc::bounded::<i64>(1);

    qbft::run(cts.token(), def, &transport, &0, 1, input_rx, source_rx)
}

// Tests definition validation at the `run` boundary.
// Expect invalid node count to return a typed error.
#[test]
fn invalid_nodes_rejected() {
    let mut def = noop_definition();
    def.nodes = 0;
    def.fifo_limit = 1;

    assert!(matches!(
        run_with_definition(&def),
        Err(QbftError::InvalidNodes { nodes: 0 })
    ));
}

// Tests definition validation at the `run` boundary.
// Expect invalid FIFO limit to return a typed error.
#[test]
fn invalid_fifo_limit_rejected() {
    let mut def = noop_definition();
    def.nodes = 4;
    def.fifo_limit = 0;

    assert!(matches!(
        run_with_definition(&def),
        Err(QbftError::InvalidFifoLimit { fifo_limit: 0 })
    ));
}

// Tests cancellation under a continuously hot receive channel.
// Expect cancellation to win even when incoming traffic is always ready.
#[test]
fn run_cancels_under_hot_receive_stream() {
    let cts = CancellationTokenSource::new();
    let token = cts.token().clone();
    let mut def = noop_definition();
    def.nodes = 4;
    def.fifo_limit = 100;

    let (receive_tx, receive_rx) = mpmc::bounded::<Msg<TestQbft>>(1024);
    let transport = Transport {
        receive: receive_rx,
        ..noop_transport()
    };
    let (_input_tx, input_rx) = mpmc::bounded::<i64>(1);
    let (_source_tx, source_rx) = mpmc::bounded::<i64>(1);
    let (done_tx, done_rx) = mpmc::bounded(1);
    let (started_tx, started_rx) = mpmc::bounded(1);

    let sender_cts = CancellationTokenSource::new();
    let sender_token = sender_cts.token().clone();
    let sender = thread::spawn(move || {
        let msg = new_msg(MSG_PREPARE, 0, 1, 2, 1, 0, 0, 0, None);
        while !sender_token.is_canceled() {
            match receive_tx.try_send(msg.clone()) {
                Ok(()) => {}
                Err(mpmc::TrySendError::Full(_)) => thread::yield_now(),
                Err(mpmc::TrySendError::Disconnected(_)) => break,
            }
        }
    });

    thread::spawn(move || {
        started_tx.send(()).expect(WRITE_CHAN_ERR);
        done_tx
            .send(qbft::run(
                &token, &def, &transport, &0, 1, input_rx, source_rx,
            ))
            .expect(WRITE_CHAN_ERR);
    });

    started_rx
        .recv_timeout(TEST_WAIT_TIMEOUT)
        .expect("run thread must start before cancellation");
    cts.cancel();

    assert!(matches!(
        done_rx
            .recv_timeout(TEST_WAIT_TIMEOUT)
            .expect("run must unblock on cancellation even with a hot receive stream"),
        Err(QbftError::ContextCanceled)
    ));

    sender_cts.cancel();
    sender.join().expect("sender thread must exit");
}

// Tests message classification into QBFT upon-rules.
// Expect each fixture to map to the rule required by the protocol transition.
#[test]
fn classify_rules() {
    let mut def = noop_definition();
    def.nodes = 4;
    def.is_leader = Box::new(make_is_leader(4));

    let preprepare = new_msg(MSG_PRE_PREPARE, 0, 1, 1, 1, 0, 0, 0, None);
    assert_upon_rule(
        UPON_JUSTIFIED_PRE_PREPARE,
        classify(&def, &0, 1, 2, &HashMap::new(), &preprepare).0,
    );

    let prepares = new_prepare_quorum(1, 2);
    let buffer = buffer_by_source(&prepares);
    assert_upon_rule(
        UPON_QUORUM_PREPARES,
        classify(&def, &0, 1, 2, &buffer, &prepares[2]).0,
    );

    let commits = vec![
        new_msg(MSG_COMMIT, 0, 1, 1, 2, 0, 0, 0, None),
        new_msg(MSG_COMMIT, 0, 2, 1, 2, 0, 0, 0, None),
        new_msg(MSG_COMMIT, 0, 3, 1, 2, 0, 0, 0, None),
    ];
    let buffer = buffer_by_source(&commits);
    assert_upon_rule(
        UPON_QUORUM_COMMITS,
        classify(&def, &0, 1, 2, &buffer, &commits[2]).0,
    );

    let future_round_changes = vec![
        new_msg(MSG_ROUND_CHANGE, 0, 1, 3, 0, 0, 0, 0, None),
        new_msg(MSG_ROUND_CHANGE, 0, 2, 3, 0, 0, 0, 0, None),
    ];
    let buffer = buffer_by_source(&future_round_changes);
    assert!(
        classify(&def, &0, 1, 2, &buffer, &future_round_changes[1]).0 == UPON_F_PLUS1_ROUND_CHANGES
    );

    let unjust_round_changes = new_round_change_quorum(1, 2, 9);
    let buffer = buffer_by_source(&unjust_round_changes);
    assert_upon_rule(
        UPON_UNJUST_QUORUM_ROUND_CHANGES,
        classify(&def, &0, 1, 2, &buffer, &unjust_round_changes[2]).0,
    );
}

// Tests ROUND_CHANGE quorum justification forms J1 and J2.
// Expect null-prepared and highest-prepared quorums to be accepted, invalid
// `pr` rejected.
#[test]
fn justified_qrc_j1_and_j2() {
    let mut def = noop_definition();
    def.nodes = 4;
    let j1 = new_round_change_quorum(2, 0, 0);
    assert_eq!(Some(0), contains_justified_qrc(&def, &j1, 2));
    assert_eq!(3, get_justified_qrc(&def, &j1, 2).unwrap().len());

    let mut j2 = vec![
        new_msg(MSG_ROUND_CHANGE, 0, 1, 2, 0, 0, 1, 7, None),
        new_msg(MSG_ROUND_CHANGE, 0, 2, 2, 0, 0, 1, 7, None),
        new_msg(MSG_ROUND_CHANGE, 0, 3, 2, 0, 0, 0, 0, None),
    ];
    j2.extend(new_prepare_quorum(1, 7));
    assert_eq!(Some(7), contains_justified_qrc(&def, &j2, 2));
    assert!(get_justified_qrc(&def, &j2, 2).unwrap().len() >= 6);

    let mut invalid_pr = new_round_change_quorum(2, 2, 7);
    invalid_pr.extend(new_prepare_quorum(2, 7));
    assert_eq!(None, contains_justified_qrc(&def, &invalid_pr, 2));
    assert!(get_justified_qrc(&def, &invalid_pr, 2).is_none());
}

// Tests ROUND_CHANGE prepared-round bounds.
// Expect only null prepared round or strictly previous prepared rounds to be
// valid.
#[test_case(2, -1, false ; "negative")]
#[test_case(1, 0, true ; "null_at_round_one")]
#[test_case(2, 1, true ; "previous_round")]
#[test_case(2, 2, false ; "current_round")]
#[test_case(2, 3, false ; "future_round")]
fn valid_round_change_prepared_round_boundaries(round: i64, prepared_round: i64, expected: bool) {
    let msg = new_msg(MSG_ROUND_CHANGE, 0, 1, round, 0, 0, prepared_round, 7, None);
    assert_eq!(expected, valid_round_change_prepared_round(&msg));
}

// Tests invalid prepared rounds at every justification call site.
// Expect invalid ROUND_CHANGE messages to be filtered while valid quorums
// survive.
#[test_case(-1 ; "negative")]
#[test_case(2 ; "current_round")]
#[test_case(3 ; "future_round")]
fn invalid_round_change_prepared_rounds_are_filtered_from_call_sites(invalid_pr: i64) {
    let mut def = noop_definition();
    def.nodes = 4;
    let target_round = 2;
    let valid_prepared_round = 1;
    let value = 7;
    let prepares = new_prepare_quorum(valid_prepared_round, value);
    let valid_round_changes = new_round_change_quorum(target_round, valid_prepared_round, value);

    let invalid_prepares = new_prepare_quorum(invalid_pr, value);
    let invalid_round_change = new_msg(
        MSG_ROUND_CHANGE,
        0,
        1,
        target_round,
        0,
        0,
        invalid_pr,
        value,
        Some(&invalid_prepares),
    );
    assert!(!is_justified_round_change(&def, &invalid_round_change));

    let mut only_invalid = new_round_change_quorum(target_round, invalid_pr, value);
    only_invalid.extend(invalid_prepares);
    assert_eq!(
        None,
        contains_justified_qrc(&def, &only_invalid, target_round)
    );
    assert!(get_justified_qrc(&def, &only_invalid, target_round).is_none());

    let mut with_invalid_extra = valid_round_changes.clone();
    with_invalid_extra.push(new_round_change(4, target_round, invalid_pr, value));
    with_invalid_extra.extend(prepares.clone());
    assert_eq!(
        Some(value),
        contains_justified_qrc(&def, &with_invalid_extra, target_round)
    );
    let qrc = get_justified_qrc(&def, &with_invalid_extra, target_round)
        .expect("valid quorum must remain after filtering invalid prepared_round");
    assert!(
        qrc.iter()
            .filter(|msg| msg.type_() == MSG_ROUND_CHANGE)
            .all(valid_round_change_prepared_round)
    );
}

// Tests null-prepared quorum filtering.
// Expect only `prepared_round = 0` and `prepared_value = 0` messages to form
// J1.
#[test_case(1, -1 ; "negative")]
#[test_case(1, 1 ; "current_round")]
#[test_case(1, 2 ; "future_round")]
fn quorum_null_prepared_requires_null_prepared_rounds(round: i64, invalid_pr: i64) {
    let mut def = noop_definition();
    def.nodes = 4;

    let valid = new_round_change_quorum(1, 0, 0);
    let (qrc, ok) = quorum_null_prepared(&def, &valid, 1);
    assert!(ok);
    assert_eq!(3, qrc.len());

    let invalid = new_round_change_quorum(round, invalid_pr, 0);
    let (qrc, ok) = quorum_null_prepared(&def, &invalid, round);
    assert!(!ok);
    assert!(qrc.is_empty());
}

// Tests duplicate sender handling in quorum filters.
// Expect at most one message per source to count toward a quorum.
#[test]
fn filter_msgs_keeps_one_per_source() {
    let msgs = vec![
        new_msg(MSG_PREPARE, 0, 1, 1, 7, 0, 0, 0, None),
        new_msg(MSG_PREPARE, 0, 1, 1, 7, 0, 0, 0, None),
        new_msg(MSG_PREPARE, 0, 2, 1, 7, 0, 0, 0, None),
    ];

    let filtered = filter_msgs(&msgs, MSG_PREPARE, 1, Some(&7), None, None);

    assert_eq!(2, filtered.len());
    assert_eq!(
        vec![1, 2],
        filtered.iter().map(|msg| msg.source()).collect::<Vec<_>>()
    );
}

// Tests compare outcomes: success, error, cached value source, and timeout.
// Expect cached value sources to be preserved and timer expiry to return
// `TimeoutError`.
#[test]
fn compare_success_error_cached_value_source_and_timeout() {
    let cts = CancellationTokenSource::new();
    let msg = new_msg(MSG_PRE_PREPARE, 0, 1, 1, 7, 11, 0, 0, None);
    let (_vs_tx, vs_rx) = mpmc::bounded::<i64>(1);
    let timer = mpmc::never();
    let mut def = noop_definition();
    def.compare = Arc::new(|req| {
        req.return_err.send(Ok(())).expect(WRITE_CHAN_ERR);
    });
    assert!(matches!(
        compare(cts.token(), &def, &msg, &vs_rx, 0, &timer),
        (0, Ok(()))
    ));

    let mut def = noop_definition();
    def.compare = Arc::new(|req| {
        let return_err = req.return_err.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            return_err.send(Ok(())).expect(WRITE_CHAN_ERR);
        });
    });
    assert!(matches!(
        compare(cts.token(), &def, &msg, &vs_rx, 41, &timer),
        (41, Ok(()))
    ));

    let mut def = noop_definition();
    def.compare = Arc::new(|req| {
        req.return_err
            .send(Err(QbftError::CompareError))
            .expect(WRITE_CHAN_ERR);
    });
    assert!(matches!(
        compare(cts.token(), &def, &msg, &vs_rx, 0, &timer),
        (0, Err(QbftError::CompareError))
    ));

    let (vs_tx, vs_rx) = mpmc::bounded::<i64>(1);
    vs_tx.send(42).expect(WRITE_CHAN_ERR);
    let mut def = noop_definition();
    def.compare = Arc::new(|req| {
        let cached = if *req.input_value_source == 0 {
            let value = req.input_value_source_ch.recv().expect(READ_CHAN_ERR);
            req.return_value.send(value).expect(WRITE_CHAN_ERR);
            value
        } else {
            *req.input_value_source
        };
        assert_eq!(42, cached);
        req.return_err.send(Ok(())).expect(WRITE_CHAN_ERR);
    });
    assert!(matches!(
        compare(cts.token(), &def, &msg, &vs_rx, 0, &timer),
        (42, Ok(()))
    ));

    let (vs_tx, vs_rx) = mpmc::bounded::<i64>(1);
    vs_tx.send(43).expect(WRITE_CHAN_ERR);
    let mut def = noop_definition();
    def.compare = Arc::new(|req| {
        let cached = if *req.input_value_source == 0 {
            let value = req.input_value_source_ch.recv().expect(READ_CHAN_ERR);
            req.return_value.send(value).expect(WRITE_CHAN_ERR);
            value
        } else {
            *req.input_value_source
        };
        assert_eq!(43, cached);
        req.return_err
            .send(Err(QbftError::CompareError))
            .expect(WRITE_CHAN_ERR);
    });
    assert!(matches!(
        compare(cts.token(), &def, &msg, &vs_rx, 0, &timer),
        (43, Err(QbftError::CompareError))
    ));

    let (timer_tx, timer_rx) = mpmc::bounded(1);
    timer_tx.send(time::Instant::now()).expect(WRITE_CHAN_ERR);
    let mut def = noop_definition();
    def.compare = Arc::new(|req| {
        thread::sleep(Duration::from_millis(20));
        let _ = req.return_err.send(Ok(()));
    });
    assert!(matches!(
        compare(cts.token(), &def, &msg, &vs_rx, 44, &timer_rx),
        (44, Err(QbftError::TimeoutError))
    ));
}

// Tests compare timeout with a cooperative but blocked callback.
// Expect `compare` to return timeout without joining the callback first.
#[test]
fn compare_timeout_does_not_wait_for_blocked_callback() {
    let cts = CancellationTokenSource::new();
    let msg = new_msg(MSG_PRE_PREPARE, 0, 1, 1, 7, 11, 0, 0, None);
    let (_vs_tx, vs_rx) = mpmc::bounded::<i64>(1);
    let (timer_tx, timer_rx) = mpmc::bounded(1);
    timer_tx.send(time::Instant::now()).expect(WRITE_CHAN_ERR);

    let mut def = noop_definition();
    def.compare = Arc::new(|req| {
        while !req.ct.is_canceled() {
            thread::sleep(Duration::from_millis(1));
        }
        let _ = req.return_err.send(Ok(()));
    });

    let (result_tx, result_rx) = mpmc::bounded(1);
    thread::spawn(move || {
        result_tx
            .send(compare(cts.token(), &def, &msg, &vs_rx, 0, &timer_rx))
            .expect(WRITE_CHAN_ERR);
    });

    assert!(matches!(
        result_rx
            .recv_timeout(TEST_WAIT_TIMEOUT)
            .expect("compare must return on timer without waiting for blocked callback"),
        (0, Err(QbftError::TimeoutError))
    ));
}

// Tests a compare callback that exits without sending status.
// Expect `compare` to wait for timer/cancel instead of treating disconnect as
// final.
#[test]
fn compare_callback_exit_without_status_waits_for_timer() {
    let cts = CancellationTokenSource::new();
    let msg = new_msg(MSG_PRE_PREPARE, 0, 1, 1, 7, 11, 0, 0, None);
    let (_vs_tx, vs_rx) = mpmc::bounded::<i64>(1);
    let (timer_tx, timer_rx) = mpmc::bounded(1);
    let (callback_done_tx, callback_done_rx) = mpmc::bounded(1);

    let mut def = noop_definition();
    def.compare = Arc::new(move |_| {
        callback_done_tx.send(()).expect(WRITE_CHAN_ERR);
    });

    let (result_tx, result_rx) = mpmc::bounded(1);
    thread::spawn(move || {
        result_tx
            .send(compare(cts.token(), &def, &msg, &vs_rx, 0, &timer_rx))
            .expect(WRITE_CHAN_ERR);
    });

    callback_done_rx
        .recv_timeout(TEST_WAIT_TIMEOUT)
        .expect("compare callback must exit");
    assert!(
        result_rx.try_recv().is_err(),
        "compare must wait for timer/cancel if callback exits without status"
    );

    timer_tx.send(time::Instant::now()).expect(WRITE_CHAN_ERR);
    assert!(matches!(
        result_rx
            .recv_timeout(TEST_WAIT_TIMEOUT)
            .expect("compare must return after timer fires"),
        (0, Err(QbftError::TimeoutError))
    ));
}

// Tests parent cancellation propagation into the compare callback token.
// Expect `compare` to return `ContextCanceled` and the callback token to be
// canceled.
#[test]
fn compare_parent_cancel_cancels_callback_token() {
    let cts = CancellationTokenSource::new();
    let token = cts.token().clone();
    let msg = new_msg(MSG_PRE_PREPARE, 0, 1, 1, 7, 11, 0, 0, None);
    let (_vs_tx, vs_rx) = mpmc::bounded::<i64>(1);
    let (timer_tx, timer_rx) = mpmc::bounded(1);
    let (compare_started_tx, compare_started_rx) = mpmc::bounded(1);
    let (token_cancelled_tx, token_cancelled_rx) = mpmc::bounded(1);

    let mut def = noop_definition();
    def.compare = Arc::new(move |req| {
        compare_started_tx.send(()).expect(WRITE_CHAN_ERR);
        while !req.ct.is_canceled() {
            thread::sleep(Duration::from_millis(1));
        }
        token_cancelled_tx.send(()).expect(WRITE_CHAN_ERR);
        let _ = req.return_err.send(Ok(()));
    });

    let (result_tx, result_rx) = mpmc::bounded(1);
    thread::spawn(move || {
        result_tx
            .send(compare(&token, &def, &msg, &vs_rx, 0, &timer_rx))
            .expect(WRITE_CHAN_ERR);
    });

    compare_started_rx
        .recv_timeout(TEST_WAIT_TIMEOUT)
        .expect("compare must start");
    cts.cancel();

    match result_rx.recv_timeout(TEST_WAIT_TIMEOUT) {
        Ok(result) => assert!(matches!(result, (0, Err(QbftError::ContextCanceled)))),
        Err(err) => {
            let _ = timer_tx.send(time::Instant::now());
            panic!("compare callback token must be canceled by parent token: {err}");
        }
    }
    token_cancelled_rx
        .recv_timeout(TEST_WAIT_TIMEOUT)
        .expect("callback token must be canceled by parent token");
}

// Tests parent cancellation while `run` is waiting inside compare.
// Expect `run` to return cancellation without broadcasting PREPARE.
#[test]
fn run_parent_cancel_during_compare_does_not_prepare() {
    const LEADER: i64 = 1;
    const PROCESS: i64 = 2;

    let cts = CancellationTokenSource::new();
    let token = cts.token().clone();
    let msg = new_msg(MSG_PRE_PREPARE, 0, LEADER, 1, 7, 11, 0, 0, None);
    let (receive_tx, receive_rx) = mpmc::bounded(1);
    receive_tx.send(msg).expect(WRITE_CHAN_ERR);

    let (compare_started_tx, compare_started_rx) = mpmc::bounded(1);
    let (compare_cancelled_tx, compare_cancelled_rx) = mpmc::bounded(1);
    let mut def = noop_definition();
    def.nodes = 4;
    def.fifo_limit = 100;
    def.is_leader = Box::new(|req| req.process == LEADER);
    def.compare = Arc::new(move |req| {
        compare_started_tx.send(()).expect(WRITE_CHAN_ERR);
        while !req.ct.is_canceled() {
            thread::sleep(Duration::from_millis(1));
        }
        compare_cancelled_tx.send(()).expect(WRITE_CHAN_ERR);
        let _ = req.return_err.send(Ok(()));
    });

    let (broadcast_tx, broadcast_rx) = mpmc::bounded(1);
    let transport = Transport {
        broadcast: Box::new(move |req| {
            broadcast_tx.send(req.type_).expect(WRITE_CHAN_ERR);
            Ok(())
        }),
        receive: receive_rx,
    };
    let (_input_tx, input_rx) = mpmc::bounded::<i64>(1);
    let (_source_tx, source_rx) = mpmc::bounded::<i64>(1);
    let (done_tx, done_rx) = mpmc::bounded(1);

    thread::spawn(move || {
        done_tx
            .send(qbft::run(
                &token, &def, &transport, &0, PROCESS, input_rx, source_rx,
            ))
            .expect(WRITE_CHAN_ERR);
    });

    compare_started_rx
        .recv_timeout(TEST_WAIT_TIMEOUT)
        .expect("compare must start");
    cts.cancel();

    assert!(matches!(
        done_rx
            .recv_timeout(TEST_WAIT_TIMEOUT)
            .expect("run must return parent cancellation from compare"),
        Err(QbftError::ContextCanceled)
    ));
    compare_cancelled_rx
        .recv_timeout(TEST_WAIT_TIMEOUT)
        .expect("compare callback token must be canceled");
    assert!(
        broadcast_rx.try_iter().all(|type_| type_ != MSG_PREPARE),
        "parent cancellation during compare must not broadcast PREPARE"
    );
}

fn buffer_by_source(msgs: &[Msg<TestQbft>]) -> HashMap<i64, Vec<Msg<TestQbft>>> {
    let mut buffer = HashMap::new();
    for msg in msgs {
        buffer
            .entry(msg.source())
            .or_insert_with(Vec::new)
            .push(msg.clone());
    }
    buffer
}

#[derive(Debug)]
struct ChainSplitTest {
    value_source: HashMap<i64, i64>,
    decide_round: i32,
    prepared_val: i32,
    should_halt: bool,
}

// Tests value-source disagreement across nodes.
// Expect agreement when a quorum can compare equal values, or halt when no
// quorum can.
#[test_case(1, 1, 1, 1, 1, 1, false ; "same_value")]
#[test_case(1, 3, 1, 1, 1, 1, false ; "non_leader_peer_has_different_value")]
#[test_case(3, 1, 1, 1, 2, 1, false ; "first_leader_has_different_value_second_leader_succeeds")]
#[test_case(1, 1, 3, 3, 0, 0, true ; "no_consensus_halt")]
fn chain_split(
    value_1: i64,
    value_2: i64,
    value_3: i64,
    value_4: i64,
    decide_round: i32,
    prepared_val: i32,
    should_halt: bool,
) {
    test_qbft_chain_split(ChainSplitTest {
        decide_round,
        value_source: HashMap::from([(1, value_1), (2, value_2), (3, value_3), (4, value_4)]),
        prepared_val,
        should_halt,
    });
}

fn test_qbft_chain_split(test: ChainSplitTest) {
    const N: usize = 4;
    const MAX_ROUND: i64 = 10;
    const FIFO_LIMIT: i64 = 100;

    let clock = FakeClock::new(time::Instant::now());
    let real_start = time::Instant::now();
    let cts = CancellationTokenSource::new();
    let trace = Trace::new();
    let pending_compares = Arc::new(AtomicUsize::new(0));
    let pending_timer_actions = Arc::new(AtomicIsize::new(0));
    // Keep peer iteration deterministic. These fake-clock tests assert exact
    // rounds, and broadcast fanout order affects which node observes quorums
    // first when tests run in parallel.
    let mut receives =
        BTreeMap::<i64, (mpmc::Sender<Msg<TestQbft>>, mpmc::Receiver<Msg<TestQbft>>)>::new();
    let (broadcast_tx, broadcast_rx) = mpmc::unbounded::<Msg<TestQbft>>();
    let (result_chan_tx, result_chan_rx) = mpmc::bounded::<Vec<Msg<TestQbft>>>(N);
    let (run_chan_tx, run_chan_rx) = mpmc::bounded::<(i64, RunOutcome)>(N);
    let instance = 0;

    let defs = Arc::new(Definition {
        is_leader: Box::new(make_is_leader(N as i64)),
        new_timer: {
            let clock = clock.clone();
            Box::new(move |round| {
                let (receive, stop) =
                    clock.new_timer(Duration::from_secs(u64::pow(2, (round as u32) - 1)));
                Timer { receive, stop }
            })
        },
        decide: {
            let result_chan_tx = result_chan_tx.clone();
            Box::new(move |req| {
                result_chan_tx
                    .send(req.qcommit.clone())
                    .expect(WRITE_CHAN_ERR);
            })
        },
        compare: {
            let pending_compares = pending_compares.clone();
            Arc::new(move |req| {
                let _guard = PendingCompareGuard {
                    pending_compares: pending_compares.clone(),
                };
                let leader_value_source = req.qcommit.value_source().expect("value source");
                let local = if *req.input_value_source == 0 {
                    let value = req.input_value_source_ch.recv().expect(READ_CHAN_ERR);
                    req.return_value.send(value).expect(WRITE_CHAN_ERR);
                    value
                } else {
                    *req.input_value_source
                };

                if leader_value_source != local {
                    req.return_err
                        .send(Err(QbftError::CompareError))
                        .expect(WRITE_CHAN_ERR);
                    return;
                }

                req.return_err.send(Ok(())).expect(WRITE_CHAN_ERR);
            })
        },
        nodes: N as i64,
        fifo_limit: FIFO_LIMIT,
        logger: QbftLogger {
            round_change: {
                let clock = clock.clone();
                let trace = trace.clone();
                let pending_timer_actions = pending_timer_actions.clone();
                Box::new(move |req| {
                    if req.upon_rule == UPON_ROUND_TIMEOUT {
                        complete_timer_action(&pending_timer_actions);
                    }

                    trace.push(format!(
                        "{:?} - {}@{} change to {} ~= {}",
                        clock.elapsed(),
                        req.process,
                        req.round,
                        req.new_round,
                        req.upon_rule
                    ));
                })
            },
            unjust: {
                let trace = trace.clone();
                Box::new(move |req| {
                    trace.push(format!("Unjust: process={} msg={:?}", req.process, req.msg))
                })
            },
            upon_rule: {
                let clock = clock.clone();
                let trace = trace.clone();
                let pending_compares = pending_compares.clone();
                Box::new(move |req| {
                    if req.upon_rule == UPON_JUSTIFIED_PRE_PREPARE {
                        pending_compares.fetch_add(1, Ordering::SeqCst);
                    }

                    trace.push(format!(
                        "{:?} {} => {}@{} -> {}@{} ~= {}",
                        clock.elapsed(),
                        req.msg.source(),
                        req.msg.type_(),
                        req.msg.round(),
                        req.process,
                        req.round,
                        req.upon_rule
                    ));
                })
            },
        },
    });

    thread::scope(|s| {
        for i in 1..=N as i64 {
            let (sender, receiver) = mpmc::bounded::<Msg<TestQbft>>(1000);
            receives.insert(i, (sender.clone(), receiver.clone()));
            let broadcast_tx = broadcast_tx.clone();
            let trace = trace.clone();
            let clock = clock.clone();

            let transport = Transport {
                broadcast: Box::new(move |req| {
                    if req.round > MAX_ROUND {
                        return Err(QbftError::MaxRoundReached);
                    }

                    trace.push(format!(
                        "{:?} {} => {}@{}",
                        clock.elapsed(),
                        req.source,
                        req.type_,
                        req.round
                    ));
                    let msg = new_msg(
                        req.type_,
                        *req.instance,
                        req.source,
                        req.round,
                        *req.value,
                        *req.value,
                        req.prepared_round,
                        *req.prepared_value,
                        req.justification,
                    );
                    sender.send(msg.clone()).expect(WRITE_CHAN_ERR);
                    broadcast_tx.send(msg).expect(WRITE_CHAN_ERR);
                    Ok(())
                }),
                receive: receiver,
            };

            let token = cts.token().clone();
            let defs = defs.clone();
            let run_chan_tx = run_chan_tx.clone();
            let value_source = test.value_source[&i];
            s.spawn(move || {
                let (v_tx, v_rx) = mpmc::bounded::<i64>(1);
                let (vs_tx, vs_rx) = mpmc::bounded::<i64>(1);
                v_tx.send(value_source).expect(WRITE_CHAN_ERR);
                vs_tx.send(value_source).expect(WRITE_CHAN_ERR);
                let run_result = panic::catch_unwind(AssertUnwindSafe(|| {
                    qbft::run(&token, &defs, &transport, &instance, i, v_rx, vs_rx)
                }));
                drop(v_tx);
                drop(vs_tx);
                run_chan_tx.send((i, run_result)).expect(WRITE_CHAN_ERR);
            });
        }

        while clock.timer_count() < N {
            thread::yield_now();
            if real_start.elapsed() > TEST_STALL_TIMEOUT {
                cts.cancel();
                clock.cancel();
                panic!(
                    "chain split setup hang: timers={} expected={} elapsed={:?}\n{}",
                    clock.timer_count(),
                    N,
                    clock.elapsed(),
                    trace.dump()
                );
            }
        }

        let mut results = BTreeMap::<i64, Msg<TestQbft>>::new();
        let mut count = 0;
        let mut decided = false;
        let mut done = 0;
        let mut last_progress = time::Instant::now();
        let chain_split_seed = seed_from_label(CHAIN_SPLIT_SEED_LABEL);
        // The no-consensus halt case must reach round 11; using Go's 1ms tick
        // here makes this Rust harness exceed its real-time guard, so only that
        // halt path fast-forwards fake time.
        let tick = if test.should_halt {
            Duration::from_millis(100)
        } else {
            Duration::from_millis(1)
        };
        let timeout_limit = if test.should_halt {
            let max_round = u32::try_from(MAX_ROUND).expect("MAX_ROUND fits u32");
            let seconds = 1_u64
                .checked_shl(
                    max_round
                        .checked_add(1)
                        .expect("MAX_ROUND permits timeout limit"),
                )
                .expect("MAX_ROUND permits timeout limit");
            Duration::from_secs(seconds)
        } else {
            Duration::from_secs(60)
        };

        loop {
            mpmc::select! {
            recv(broadcast_rx) -> msg => {
                let msg = msg.expect(READ_CHAN_ERR);
                last_progress = time::Instant::now();
                for (target, (out_tx, _)) in receives.iter() {
                    if *target == msg.source() {
                        continue;
                    }
                    out_tx.send(msg.clone()).expect(WRITE_CHAN_ERR);
                    if deterministic_unit(chain_split_seed, &msg, *target, TEST_STREAM_DUPLICATE) < 0.1 {
                        out_tx.send(msg.clone()).expect(WRITE_CHAN_ERR);
                    }
                }
            }
            recv(result_chan_rx) -> res => {
                let q_commit = res.expect(READ_CHAN_ERR);
                last_progress = time::Instant::now();
                if test.should_halt {
                    cts.cancel();
                    clock.cancel();
                    panic!(
                        "halt case unexpectedly decided: q_commit={:?} elapsed={:?}\n{}",
                        q_commit,
                        clock.elapsed(),
                        trace.dump()
                    );
                }

                for commit in &q_commit {
                    for previous in results.values() {
                        if previous.value() != commit.value() {
                            cts.cancel();
                            clock.cancel();
                            panic!(
                                "chain split commit values differ: previous={:?} commit={:?} elapsed={:?}\n{}",
                                previous,
                                commit,
                                clock.elapsed(),
                                trace.dump()
                            );
                        }
                    }
                    if i64::from(test.decide_round) != commit.round() {
                        cts.cancel();
                        clock.cancel();
                        panic!(
                            "chain split wrong decide round: want={} got={} commit={:?} elapsed={:?}\n{}",
                            test.decide_round,
                            commit.round(),
                            commit,
                            clock.elapsed(),
                            trace.dump()
                        );
                    }
                    if test.prepared_val != 0 {
                        if i64::from(test.prepared_val) != commit.value() {
                            cts.cancel();
                            clock.cancel();
                            panic!(
                                "chain split wrong prepared value: want={} got={} commit={:?} elapsed={:?}\n{}",
                                test.prepared_val,
                                commit.value(),
                                commit,
                                clock.elapsed(),
                                trace.dump()
                            );
                        }
                    }
                    results.insert(commit.source(), commit.clone());
                }
                count += 1;
                if count == N {
                    decided = true;
                    clock.cancel();
                    cts.cancel();
                }
            }
            recv(run_chan_rx) -> res => {
                let (node, outcome) = res.expect(READ_CHAN_ERR);
                last_progress = time::Instant::now();
                let expected_halt = test.should_halt
                    && outcome_is_error(&outcome, |err| matches!(err, QbftError::MaxRoundReached));
                if !(decided || expected_halt) {
                    cts.cancel();
                    clock.cancel();
                    panic!(
                        "unexpected chain split run error: node={} outcome={} decided={} done={} count={} elapsed={:?}\n{}",
                        node,
                        format_run_outcome(&outcome),
                        decided,
                        done,
                        count,
                        clock.elapsed(),
                        trace.dump()
                    );
                }
                done += 1;
                if done == N {
                    if test.should_halt {
                        assert!(!decided, "halt case unexpectedly decided");
                    }
                    return;
                }
            }
            default => {
                if pending_compares.load(Ordering::SeqCst) != 0
                    || pending_timer_actions.load(Ordering::SeqCst) > 0
                {
                    thread::yield_now();
                    if last_progress.elapsed() > TEST_STALL_TIMEOUT {
                        cts.cancel();
                        clock.cancel();
                        panic!(
                            "chain split hang: pending_compares={} pending_timer_actions={} decided={decided} done={done} count={count} elapsed={:?}\n{}",
                            pending_compares.load(Ordering::SeqCst),
                            pending_timer_actions.load(Ordering::SeqCst),
                            clock.elapsed(),
                            trace.dump()
                        );
                    }
                    continue;
                }

                // Matches the Go harness throttle; ordering correctness comes
                // from the pending-work barriers, not this duration.
                thread::sleep(Duration::from_micros(1));
                clock.advance_and_wait(tick, &pending_timer_actions);
                last_progress = time::Instant::now();
                if clock.elapsed() > timeout_limit {
                    cts.cancel();
                    clock.cancel();
                    panic!("chain split hang: decided={decided} done={done} count={count} elapsed={:?}\n{}", clock.elapsed(), trace.dump());
                }
            }
            }
        }
    });
}
