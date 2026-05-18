use crate::qbft::{self, fake_clock::FakeClock, *};
use cancellation::CancellationTokenSource;
use crossbeam::channel as mpmc;
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Write as _,
    panic::{self, AssertUnwindSafe},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

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

type RunOutcome = std::thread::Result<Result<()>>;
type TestMsgRef = Msg<i64, i64, i64>;

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
    // Keep peer iteration deterministic. These fake-clock tests assert exact
    // rounds, and broadcast fanout order affects which node observes quorums
    // first when tests run in parallel.
    let mut receives = BTreeMap::<
        i64,
        (
            mpmc::Sender<Msg<i64, i64, i64>>,
            mpmc::Receiver<Msg<i64, i64, i64>>,
        ),
    >::new();
    let (broadcast_tx, broadcast_rx) = mpmc::unbounded::<BroadcastEvent>();
    let (unjust_tx, unjust_rx) = mpmc::unbounded::<String>();
    let (result_chan_tx, result_chan_rx) = mpmc::bounded::<Vec<Msg<i64, i64, i64>>>(N);
    let (run_chan_tx, run_chan_rx) = mpmc::bounded::<(i64, RunOutcome)>(N);

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

                clock.new_timer(d)
            })
        },
        decide: {
            let result_chan_tx = result_chan_tx.clone();
            Box::new(move |_, _, _, q_commit| {
                result_chan_tx.send(q_commit.clone()).expect(WRITE_CHAN_ERR);
            })
        },
        compare: Arc::new(|_, _, _, _, return_err, _| {
            return_err.send(Ok(())).expect(WRITE_CHAN_ERR);
        }),
        nodes: N as i64,
        fifo_limit: FIFO_LIMIT as i64,
        log_round_change: {
            let clock = clock.clone();
            let trace = trace.clone();

            Box::new(move |_, process, round, new_round, upon_rule, _| {
                trace.push(format!(
                    "{:?} - {}@{} change to {} ~= {}",
                    clock.elapsed(),
                    process,
                    round,
                    new_round,
                    upon_rule,
                ));
            })
        },
        log_unjust: {
            let trace = trace.clone();
            let unjust_tx = unjust_tx.clone();
            let fuzz = test.fuzz;
            Box::new(move |_, process, msg| {
                let line = format!("Unjust: process={} msg={:?}", process, msg);
                trace.push(line.clone());
                if !fuzz {
                    unjust_tx.send(line).expect(WRITE_CHAN_ERR);
                }
            })
        },
        log_upon_rule: {
            let clock = clock.clone();
            let trace = trace.clone();
            Box::new(move |_, process, round, msg, upon_rule| {
                trace.push(format!(
                    "{:?} {} => {}@{} -> {}@{} ~= {}",
                    clock.elapsed(),
                    msg.source(),
                    msg.type_(),
                    msg.round(),
                    process,
                    round,
                    upon_rule,
                ));
            })
        },
    });

    thread::scope(|s| {
        for i in 1..=N as i64 {
            let (sender, receiver) = mpmc::bounded::<Msg<i64, i64, i64>>(1000);
            let broadcast_tx = broadcast_tx.clone();
            receives.insert(i, (sender.clone(), receiver.clone()));

            let trans = Transport {
                broadcast: {
                    let clock = clock.clone();
                    let trace = trace.clone();

                    Box::new(
                        move |_, type_, instance, source, round, value, pr, pv, justification| {
                            if round > MAX_ROUND as i64 {
                                return Err(QbftError::MaxRoundReached);
                            }

                            if type_ == MSG_COMMIT && round <= test.commits_after.into() {
                                trace.push(format!(
                                    "{:?} {} dropping commit for round {}",
                                    clock.elapsed(),
                                    source,
                                    round
                                ));
                                return Ok(());
                            }

                            trace.push(format!(
                                "{:?} {} => {}@{}",
                                clock.elapsed(),
                                source,
                                type_,
                                round
                            ));

                            let msg = new_msg(
                                type_,
                                *instance,
                                source,
                                round,
                                *value,
                                *value,
                                pr,
                                *pv,
                                justification,
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
                        },
                    )
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
            let trace = trace.clone();

            s.spawn(move || {
                if let Some(delay) = start_delay {
                    trace.push(format!(
                        "{:?} Node {} start delay {:?}",
                        clock.elapsed(),
                        i,
                        delay
                    ));
                    let (delay_ch, _) = clock.new_timer(delay);
                    _ = delay_ch.recv();
                    trace.push(format!(
                        "{:?} Node {} starting {:?}",
                        clock.elapsed(),
                        i,
                        delay
                    ));
                }

                if start_delay.is_some() {
                    // Drain any buffered messages
                    while !receiver.is_empty() {
                        _ = receiver.recv().expect(READ_CHAN_ERR);
                    }
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
                    s.spawn(move || {
                        let (delay_ch, cancel) = clock.new_timer(delay);
                        _ = delay_ch.recv();
                        _ = v_chan_tx_send.send(i);

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
                } else if is_leader(&test.instance, 1, i) {
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

        let mut results = BTreeMap::<i64, Msg<i64, i64, i64>>::new();
        let mut count = 0;
        let mut decided = false;
        let mut done = 0;
        let mut broadcasts = 0usize;
        let mut pending = Vec::<PendingBroadcast>::new();
        let mut next_fuzz_at = test.fuzz.then_some(Duration::from_millis(100));
        let mut fuzz_counter = 0_u64;

        loop {
            broadcasts += deliver_ready_broadcasts(
                &mut pending,
                &receives,
                &test.drop_prob,
                seed,
                &trace,
                &clock,
            );

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
                    clock.advance(Duration::from_millis(1));
                    if clock.elapsed() > Duration::from_secs(180) || real_start.elapsed() > Duration::from_secs(20) {
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
                                if !is_leader(&test.instance, commit.round(), commit.value()) {
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
                    thread::sleep(time::Duration::from_micros(1));
                    clock.advance(Duration::from_millis(1));
                    if clock.elapsed() > Duration::from_secs(180) || real_start.elapsed() > Duration::from_secs(20) {
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
struct Trace(Arc<Mutex<Vec<String>>>);

impl Trace {
    fn new() -> Self {
        Self::default()
    }

    fn push(&self, line: String) {
        self.0.lock().unwrap().push(line);
    }

    fn dump(&self) -> String {
        let lines = self.0.lock().unwrap();
        let start = lines.len().saturating_sub(200);
        let mut out = String::new();
        for line in &lines[start..] {
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
fn make_is_leader(n: i64) -> impl Fn(&i64, i64, i64) -> bool + Clone {
    move |instance: &i64, round: i64, process: i64| -> bool { (instance + round) % n == process }
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
    justify: Option<&Vec<Msg<i64, i64, i64>>>,
) -> Msg<i64, i64, i64> {
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

// Delays the message broadcast by between 1x and 2x jitter_ms and drops
// messages.
fn bcast(
    broadcast: mpmc::Sender<BroadcastEvent>,
    msg: Msg<i64, i64, i64>,
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
    let ready = pending.drain(..ready_count).collect::<Vec<_>>();

    ready
        .into_iter()
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

fn random_msg(instance: i64, peer_idx: i64, seed: u64, counter: u64) -> Msg<i64, i64, i64> {
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

fn deterministic_unit(seed: u64, msg: &Msg<i64, i64, i64>, target: i64, stream_id: u64) -> f64 {
    let value = deterministic_msg_u64(seed, msg, target, stream_id) >> 11;
    value as f64 / ((1_u64 << 53) as f64)
}

fn deterministic_msg_u64(seed: u64, msg: &Msg<i64, i64, i64>, target: i64, stream_id: u64) -> u64 {
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

impl SomeMsg<i64, i64, i64> for TestMsg {
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

    fn justification(&self) -> Vec<Msg<i64, i64, i64>> {
        match self.justify {
            None => vec![],
            Some(ref j) => j
                .iter()
                .map(|j| Arc::new(j.clone()) as Msg<i64, i64, i64>)
                .collect(),
        }
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }
}

#[test]
fn happy_0() {
    test_qbft(Test {
        instance: 0,
        decide_round: 1,
        ..Default::default()
    });
}

#[test]
fn happy_1() {
    test_qbft(Test {
        instance: 1,
        decide_round: 1,
        ..Default::default()
    });
}

#[test]
fn prepare_round_1_decide_round_2() {
    test_qbft(Test {
        instance: 0,
        commits_after: 1,
        decide_round: 2,
        prepared_val: 1,
        ..Default::default()
    });
}

#[test]
fn prepare_round_2_decide_round_3() {
    test_qbft(Test {
        instance: 0,
        commits_after: 2,
        value_delay: HashMap::from([(1, Duration::from_secs(2))]),
        decide_round: 3,
        prepared_val: 2,
        const_period: true,
        ..Default::default()
    });
}

#[test]
fn leader_late_exp() {
    test_qbft(Test {
        instance: 0,
        start_delay: HashMap::from([(1, Duration::from_secs(2))]),
        decide_round: 2,
        ..Default::default()
    });
}

#[test]
fn leader_down_const() {
    test_qbft(Test {
        instance: 0,
        start_delay: HashMap::from([(1, Duration::from_secs(2))]),
        const_period: true,
        decide_round: 2,
        ..Default::default()
    });
}

#[test]
fn very_late_exp() {
    test_qbft(Test {
        instance: 3,
        start_delay: HashMap::from([(1, Duration::from_secs(5)), (2, Duration::from_secs(10))]),
        decide_round: 4,
        ..Default::default()
    });
}

#[test]
fn very_late_const() {
    test_qbft(Test {
        instance: 1,
        start_delay: HashMap::from([(1, Duration::from_secs(5)), (2, Duration::from_secs(10))]),
        const_period: true,
        random_round: true,
        ..Default::default()
    });
}

#[test]
fn stagger_start_exp() {
    test_qbft(Test {
        instance: 0,
        start_delay: HashMap::from([
            (1, Duration::from_secs(0)),
            (2, Duration::from_secs(1)),
            (3, Duration::from_secs(2)),
            (4, Duration::from_secs(3)),
        ]),
        random_round: true, // Takes 1 or 2 rounds.
        ..Default::default()
    });
}

#[test]
fn stagger_start_const() {
    test_qbft(Test {
        instance: 0,
        start_delay: HashMap::from([
            (1, Duration::from_secs(0)),
            (2, Duration::from_secs(1)),
            (3, Duration::from_secs(2)),
            (4, Duration::from_secs(3)),
        ]),
        const_period: true,
        random_round: true, // Takes 1 or 2 rounds.
        ..Default::default()
    });
}

#[test]
fn very_delayed_value_exp() {
    test_qbft(Test {
        instance: 3,
        value_delay: HashMap::from([(1, Duration::from_secs(5)), (2, Duration::from_secs(10))]),
        decide_round: 4,
        ..Default::default()
    });
}

#[test]
fn very_delayed_value_const() {
    test_qbft(Test {
        instance: 1,
        value_delay: HashMap::from([(1, Duration::from_secs(5)), (2, Duration::from_secs(10))]),
        const_period: true,
        random_round: true,
        ..Default::default()
    });
}

#[test]
fn stagger_delayed_value_exp() {
    test_qbft(Test {
        instance: 0,
        value_delay: HashMap::from([
            (1, Duration::from_secs(0)),
            (2, Duration::from_secs(1)),
            (3, Duration::from_secs(2)),
            (4, Duration::from_secs(3)),
        ]),
        random_round: true,
        ..Default::default()
    });
}

#[test]
fn stagger_delayed_value_const() {
    test_qbft(Test {
        instance: 0,
        value_delay: HashMap::from([
            (1, Duration::from_secs(0)),
            (2, Duration::from_secs(1)),
            (3, Duration::from_secs(2)),
            (4, Duration::from_secs(3)),
        ]),
        const_period: true,
        random_round: true,
        ..Default::default()
    });
}

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

#[test]
fn jitter_500ms_exp() {
    test_qbft(Test {
        instance: 3,
        bcast_jitter_ms: 500,
        random_round: true,
        ..Default::default()
    });
}

#[test]
fn jitter_200ms_const() {
    test_qbft(Test {
        instance: 3,
        bcast_jitter_ms: 200, // 0.2-0.4s network delay * 3msgs/round == 0.6-1.2s delay per 1s round
        const_period: true,
        random_round: true,
        ..Default::default()
    });
}

#[test]
fn drop_10_percent_const() {
    test_qbft(Test {
        instance: 1,
        drop_prob: HashMap::from([(1, 0.1), (2, 0.1), (3, 0.1), (4, 0.1)]),
        const_period: true,
        random_round: true,
        ..Default::default()
    });
}

#[test]
fn drop_30_percent_const() {
    test_qbft(Test {
        instance: 1,
        drop_prob: HashMap::from([(1, 0.3), (2, 0.3), (3, 0.3), (4, 0.3)]),
        const_period: true,
        random_round: true,
        ..Default::default()
    });
}

#[test]
fn fuzz() {
    test_qbft(Test {
        instance: 1,
        fuzz: true,
        const_period: true,
        decide_round: 1,
        ..Default::default()
    });
}

#[test]
fn fuzz_with_late_leader() {
    test_qbft(Test {
        instance: 1,
        fuzz: true,
        start_delay: HashMap::from([(1, Duration::from_secs(2)), (2, Duration::from_secs(2))]),
        const_period: true,
        random_round: true,
        ..Default::default()
    });
}

#[test]
fn fuzz_with_very_late_leader() {
    test_qbft(Test {
        instance: 1,
        fuzz: true,
        start_delay: HashMap::from([(1, Duration::from_secs(10)), (2, Duration::from_secs(10))]),
        const_period: true,
        random_round: true,
        ..Default::default()
    });
}

fn noop_definition() -> Definition<i64, i64, i64> {
    Definition {
        is_leader: Box::new(|_, _, _| false),
        new_timer: Box::new(|_| (mpmc::never(), Box::new(|| {}))),
        decide: Box::new(|_, _, _, _| {}),
        compare: Arc::new(|_, _, _, _, _, _| {}),
        nodes: 0,
        fifo_limit: 0,
        log_round_change: Box::new(|_, _, _, _, _, _| {}),
        log_unjust: Box::new(|_, _, _| {}),
        log_upon_rule: Box::new(|_, _, _, _, _| {}),
    }
}

fn noop_transport() -> Transport<i64, i64, i64> {
    Transport {
        broadcast: Box::new(|_, _, _, _, _, _, _, _, _| Ok(())),
        receive: mpmc::never(),
    }
}

#[test]
fn formulas() {
    let expected = [
        (1, 1, 0),
        (2, 2, 0),
        (3, 2, 0),
        (4, 3, 1),
        (5, 4, 1),
        (6, 4, 1),
        (7, 5, 2),
        (8, 6, 2),
        (9, 6, 2),
        (10, 7, 3),
        (11, 8, 3),
        (12, 8, 3),
        (13, 9, 4),
        (14, 10, 4),
        (15, 10, 4),
        (16, 11, 5),
        (17, 12, 5),
        (18, 12, 5),
        (19, 13, 6),
        (20, 14, 6),
        (21, 14, 6),
        (22, 15, 7),
    ];

    for (n, q, f) in expected {
        let d = Definition::<i64, i64, i64> {
            nodes: n,
            ..noop_definition()
        };
        assert_eq!(q, d.quorum(), "Quorum given N={n}");
        assert_eq!(f, d.faulty(), "Faulty given N={n}");
    }
}

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

#[test]
fn duplicate_pre_prepare_rules() {
    let cts = CancellationTokenSource::new();
    let ct = &cts.token().clone();

    const NO_LEADER: i64 = 1;
    const LEADER: i64 = 2;

    let new_preprepare = |round: i64| -> Msg<i64, i64, i64> {
        new_msg(
            MSG_PRE_PREPARE,
            0,
            LEADER,
            round,
            0,
            0,
            0,
            0,
            // Justification not required since nodes and quorum both 0.
            None,
        )
    };

    let mut def = noop_definition();
    def.is_leader = Box::new(|_, _, process| process == LEADER);
    def.log_upon_rule = Box::new(move |_, _, round, msg, upon_rule| {
        println!("UponRule: rule={} round={} ", upon_rule, msg.round());

        assert!(upon_rule == UPON_JUSTIFIED_PRE_PREPARE);

        if msg.round() == 1 {
            return;
        }

        if msg.round() == 2 {
            cts.cancel();
            return;
        }

        panic!("unexpected round {}", round);
    });
    def.compare = Arc::new(|_, _, _, _, return_err, _| {
        return_err.send(Ok(())).expect(WRITE_CHAN_ERR);
    });

    let (r_chan_tx, r_chan_rx) = mpmc::bounded::<Msg<i64, i64, i64>>(2);
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

#[test]
fn idle_run_returns_when_cancelled() {
    let cts = CancellationTokenSource::new();
    let token = cts.token().clone();
    let def = noop_definition();
    let transport = noop_transport();
    let (_input_tx, input_rx) = mpmc::bounded::<i64>(1);
    let (_source_tx, source_rx) = mpmc::bounded::<i64>(1);
    let (done_tx, done_rx) = mpmc::bounded(1);

    thread::spawn(move || {
        done_tx
            .send(qbft::run(
                &token, &def, &transport, &0, 1, input_rx, source_rx,
            ))
            .expect(WRITE_CHAN_ERR);
    });

    thread::sleep(Duration::from_millis(10));
    cts.cancel();

    assert!(matches!(
        done_rx
            .recv_timeout(Duration::from_millis(100))
            .expect("idle run must unblock on cancellation"),
        Err(QbftError::ContextCanceled)
    ));
}

#[test]
fn classify_rules() {
    let mut def = noop_definition();
    def.nodes = 4;
    def.is_leader = Box::new(make_is_leader(4));

    let preprepare = new_msg(MSG_PRE_PREPARE, 0, 1, 1, 1, 0, 0, 0, None);
    assert!(classify(&def, &0, 1, 2, &HashMap::new(), &preprepare).0 == UPON_JUSTIFIED_PRE_PREPARE);

    let prepares = vec![
        new_msg(MSG_PREPARE, 0, 1, 1, 2, 0, 0, 0, None),
        new_msg(MSG_PREPARE, 0, 2, 1, 2, 0, 0, 0, None),
        new_msg(MSG_PREPARE, 0, 3, 1, 2, 0, 0, 0, None),
    ];
    let buffer = buffer_by_source(&prepares);
    assert!(classify(&def, &0, 1, 2, &buffer, &prepares[2]).0 == UPON_QUORUM_PREPARES);

    let commits = vec![
        new_msg(MSG_COMMIT, 0, 1, 1, 2, 0, 0, 0, None),
        new_msg(MSG_COMMIT, 0, 2, 1, 2, 0, 0, 0, None),
        new_msg(MSG_COMMIT, 0, 3, 1, 2, 0, 0, 0, None),
    ];
    let buffer = buffer_by_source(&commits);
    assert!(classify(&def, &0, 1, 2, &buffer, &commits[2]).0 == UPON_QUORUM_COMMITS);

    let future_round_changes = vec![
        new_msg(MSG_ROUND_CHANGE, 0, 1, 3, 0, 0, 0, 0, None),
        new_msg(MSG_ROUND_CHANGE, 0, 2, 3, 0, 0, 0, 0, None),
    ];
    let buffer = buffer_by_source(&future_round_changes);
    assert!(
        classify(&def, &0, 1, 2, &buffer, &future_round_changes[1]).0 == UPON_F_PLUS1_ROUND_CHANGES
    );

    let unjust_round_changes = vec![
        new_msg(MSG_ROUND_CHANGE, 0, 1, 1, 0, 0, 2, 9, None),
        new_msg(MSG_ROUND_CHANGE, 0, 2, 1, 0, 0, 2, 9, None),
        new_msg(MSG_ROUND_CHANGE, 0, 3, 1, 0, 0, 2, 9, None),
    ];
    let buffer = buffer_by_source(&unjust_round_changes);
    assert!(
        classify(&def, &0, 1, 2, &buffer, &unjust_round_changes[2]).0
            == UPON_UNJUST_QUORUM_ROUND_CHANGES
    );
}

#[test]
fn justified_qrc_j1_and_j2() {
    let mut def = noop_definition();
    def.nodes = 4;
    let j1 = vec![
        new_msg(MSG_ROUND_CHANGE, 0, 1, 2, 0, 0, 0, 0, None),
        new_msg(MSG_ROUND_CHANGE, 0, 2, 2, 0, 0, 0, 0, None),
        new_msg(MSG_ROUND_CHANGE, 0, 3, 2, 0, 0, 0, 0, None),
    ];
    assert_eq!(Some(0), contains_justified_qrc(&def, &j1, 2));
    assert_eq!(3, get_justified_qrc(&def, &j1, 2).unwrap().len());

    let j2 = vec![
        new_msg(MSG_ROUND_CHANGE, 0, 1, 2, 0, 0, 1, 7, None),
        new_msg(MSG_ROUND_CHANGE, 0, 2, 2, 0, 0, 1, 7, None),
        new_msg(MSG_ROUND_CHANGE, 0, 3, 2, 0, 0, 0, 0, None),
        new_msg(MSG_PREPARE, 0, 1, 1, 7, 0, 0, 0, None),
        new_msg(MSG_PREPARE, 0, 2, 1, 7, 0, 0, 0, None),
        new_msg(MSG_PREPARE, 0, 3, 1, 7, 0, 0, 0, None),
    ];
    assert_eq!(Some(7), contains_justified_qrc(&def, &j2, 2));
    assert!(get_justified_qrc(&def, &j2, 2).unwrap().len() >= 6);
}

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

#[test]
fn compare_success_error_cached_value_source_and_timeout() {
    let cts = CancellationTokenSource::new();
    let msg = new_msg(MSG_PRE_PREPARE, 0, 1, 1, 7, 11, 0, 0, None);
    let (_vs_tx, vs_rx) = mpmc::bounded::<i64>(1);
    let timer = mpmc::never();
    let mut def = noop_definition();
    def.compare = Arc::new(|_, _, _, _, return_err, _| {
        return_err.send(Ok(())).expect(WRITE_CHAN_ERR);
    });
    assert!(matches!(
        compare(cts.token(), &def, &msg, &vs_rx, 0, &timer),
        (0, Ok(()))
    ));

    let mut def = noop_definition();
    def.compare = Arc::new(|_, _, _, _, return_err, _| {
        let return_err = return_err.clone();
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
    def.compare = Arc::new(|_, _, _, _, return_err, _| {
        return_err
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
    def.compare = Arc::new(
        |_, _, input_value_source_ch, input_value_source, return_err, return_value| {
            let cached = if *input_value_source == 0 {
                let value = input_value_source_ch.recv().expect(READ_CHAN_ERR);
                return_value.send(value).expect(WRITE_CHAN_ERR);
                value
            } else {
                *input_value_source
            };
            assert_eq!(42, cached);
            return_err.send(Ok(())).expect(WRITE_CHAN_ERR);
        },
    );
    assert!(matches!(
        compare(cts.token(), &def, &msg, &vs_rx, 0, &timer),
        (42, Ok(()))
    ));

    let (vs_tx, vs_rx) = mpmc::bounded::<i64>(1);
    vs_tx.send(43).expect(WRITE_CHAN_ERR);
    let mut def = noop_definition();
    def.compare = Arc::new(
        |_, _, input_value_source_ch, input_value_source, return_err, return_value| {
            let cached = if *input_value_source == 0 {
                let value = input_value_source_ch.recv().expect(READ_CHAN_ERR);
                return_value.send(value).expect(WRITE_CHAN_ERR);
                value
            } else {
                *input_value_source
            };
            assert_eq!(43, cached);
            return_err
                .send(Err(QbftError::CompareError))
                .expect(WRITE_CHAN_ERR);
        },
    );
    assert!(matches!(
        compare(cts.token(), &def, &msg, &vs_rx, 0, &timer),
        (43, Err(QbftError::CompareError))
    ));

    let (timer_tx, timer_rx) = mpmc::bounded(1);
    timer_tx.send(time::Instant::now()).expect(WRITE_CHAN_ERR);
    let mut def = noop_definition();
    def.compare = Arc::new(|_, _, _, _, return_err, _| {
        thread::sleep(Duration::from_millis(20));
        let _ = return_err.send(Ok(()));
    });
    assert!(matches!(
        compare(cts.token(), &def, &msg, &vs_rx, 44, &timer_rx),
        (44, Err(QbftError::TimeoutError))
    ));
}

#[test]
fn compare_timeout_does_not_wait_for_blocked_callback() {
    let cts = CancellationTokenSource::new();
    let msg = new_msg(MSG_PRE_PREPARE, 0, 1, 1, 7, 11, 0, 0, None);
    let (_vs_tx, vs_rx) = mpmc::bounded::<i64>(1);
    let (timer_tx, timer_rx) = mpmc::bounded(1);
    timer_tx.send(time::Instant::now()).expect(WRITE_CHAN_ERR);

    let mut def = noop_definition();
    def.compare = Arc::new(|ct, _, _, _, return_err, _| {
        while !ct.is_canceled() {
            thread::sleep(Duration::from_millis(1));
        }
        let _ = return_err.send(Ok(()));
    });

    let (result_tx, result_rx) = mpmc::bounded(1);
    thread::spawn(move || {
        result_tx
            .send(compare(cts.token(), &def, &msg, &vs_rx, 0, &timer_rx))
            .expect(WRITE_CHAN_ERR);
    });

    assert!(matches!(
        result_rx
            .recv_timeout(Duration::from_millis(100))
            .expect("compare must return on timer without waiting for blocked callback"),
        (0, Err(QbftError::TimeoutError))
    ));
}

#[test]
fn compare_parent_cancel_cancels_callback_token() {
    let cts = CancellationTokenSource::new();
    let token = cts.token().clone();
    let msg = new_msg(MSG_PRE_PREPARE, 0, 1, 1, 7, 11, 0, 0, None);
    let (_vs_tx, vs_rx) = mpmc::bounded::<i64>(1);
    let (timer_tx, timer_rx) = mpmc::bounded(1);
    let (token_cancelled_tx, token_cancelled_rx) = mpmc::bounded(1);

    let mut def = noop_definition();
    def.compare = Arc::new(move |ct, _, _, _, return_err, _| {
        while !ct.is_canceled() {
            thread::sleep(Duration::from_millis(1));
        }
        token_cancelled_tx.send(()).expect(WRITE_CHAN_ERR);
        return_err.send(Ok(())).expect(WRITE_CHAN_ERR);
    });

    let (result_tx, result_rx) = mpmc::bounded(1);
    thread::spawn(move || {
        result_tx
            .send(compare(&token, &def, &msg, &vs_rx, 0, &timer_rx))
            .expect(WRITE_CHAN_ERR);
    });

    thread::sleep(Duration::from_millis(10));
    cts.cancel();

    match result_rx.recv_timeout(Duration::from_millis(100)) {
        Ok(result) => assert!(matches!(result, (0, Ok(())))),
        Err(err) => {
            let _ = timer_tx.send(time::Instant::now());
            panic!("compare callback token must be canceled by parent token: {err}");
        }
    }
    token_cancelled_rx
        .recv_timeout(Duration::from_millis(100))
        .expect("callback token must be canceled by parent token");
}

fn buffer_by_source(msgs: &[Msg<i64, i64, i64>]) -> HashMap<i64, Vec<Msg<i64, i64, i64>>> {
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

#[test]
fn chain_split_same_value() {
    test_qbft_chain_split(ChainSplitTest {
        decide_round: 1,
        value_source: HashMap::from([(1, 1), (2, 1), (3, 1), (4, 1)]),
        prepared_val: 1,
        should_halt: false,
    });
}

#[test]
fn chain_split_non_leader_peer_has_different_value() {
    test_qbft_chain_split(ChainSplitTest {
        decide_round: 1,
        value_source: HashMap::from([(1, 1), (2, 3), (3, 1), (4, 1)]),
        prepared_val: 1,
        should_halt: false,
    });
}

#[test]
fn chain_split_first_leader_has_different_value_second_leader_succeeds() {
    test_qbft_chain_split(ChainSplitTest {
        decide_round: 2,
        value_source: HashMap::from([(1, 3), (2, 1), (3, 1), (4, 1)]),
        prepared_val: 1,
        should_halt: false,
    });
}

#[test]
fn zz_chain_split_no_consensus_halt() {
    test_qbft_chain_split(ChainSplitTest {
        decide_round: 0,
        value_source: HashMap::from([(1, 1), (2, 1), (3, 3), (4, 3)]),
        prepared_val: 0,
        should_halt: true,
    });
}

fn test_qbft_chain_split(test: ChainSplitTest) {
    const N: usize = 4;
    const MAX_ROUND: i64 = 10;
    const FIFO_LIMIT: i64 = 100;

    let clock = FakeClock::new(time::Instant::now());
    let cts = CancellationTokenSource::new();
    let trace = Trace::new();
    // Keep peer iteration deterministic. These fake-clock tests assert exact
    // rounds, and broadcast fanout order affects which node observes quorums
    // first when tests run in parallel.
    let mut receives = BTreeMap::<
        i64,
        (
            mpmc::Sender<Msg<i64, i64, i64>>,
            mpmc::Receiver<Msg<i64, i64, i64>>,
        ),
    >::new();
    let (broadcast_tx, broadcast_rx) = mpmc::unbounded::<Msg<i64, i64, i64>>();
    let (result_chan_tx, result_chan_rx) = mpmc::bounded::<Vec<Msg<i64, i64, i64>>>(N);
    let (run_chan_tx, run_chan_rx) = mpmc::bounded::<(i64, RunOutcome)>(N);
    let instance = 0;

    let defs = Arc::new(Definition {
        is_leader: Box::new(make_is_leader(N as i64)),
        new_timer: {
            let clock = clock.clone();
            Box::new(move |round| {
                clock.new_timer(Duration::from_secs(u64::pow(2, (round as u32) - 1)))
            })
        },
        decide: {
            let result_chan_tx = result_chan_tx.clone();
            Box::new(move |_, _, _, q_commit| {
                result_chan_tx.send(q_commit.clone()).expect(WRITE_CHAN_ERR);
            })
        },
        compare: Arc::new(
            |_, qcommit, input_value_source_ch, input_value_source, return_err, return_value| {
                let leader_value_source = qcommit.value_source().expect("value source");
                let local = if *input_value_source == 0 {
                    let value = input_value_source_ch.recv().expect(READ_CHAN_ERR);
                    return_value.send(value).expect(WRITE_CHAN_ERR);
                    value
                } else {
                    *input_value_source
                };

                if leader_value_source != local {
                    return_err
                        .send(Err(QbftError::CompareError))
                        .expect(WRITE_CHAN_ERR);
                    return;
                }

                return_err.send(Ok(())).expect(WRITE_CHAN_ERR);
            },
        ),
        nodes: N as i64,
        fifo_limit: FIFO_LIMIT,
        log_round_change: {
            let clock = clock.clone();
            let trace = trace.clone();
            Box::new(move |_, process, round, new_round, upon_rule, _| {
                trace.push(format!(
                    "{:?} - {}@{} change to {} ~= {}",
                    clock.elapsed(),
                    process,
                    round,
                    new_round,
                    upon_rule
                ));
            })
        },
        log_unjust: {
            let trace = trace.clone();
            Box::new(move |_, process, msg| {
                trace.push(format!("Unjust: process={} msg={:?}", process, msg))
            })
        },
        log_upon_rule: {
            let clock = clock.clone();
            let trace = trace.clone();
            Box::new(move |_, process, round, msg, upon_rule| {
                trace.push(format!(
                    "{:?} {} => {}@{} -> {}@{} ~= {}",
                    clock.elapsed(),
                    msg.source(),
                    msg.type_(),
                    msg.round(),
                    process,
                    round,
                    upon_rule
                ));
            })
        },
    });

    thread::scope(|s| {
        for i in 1..=N as i64 {
            let (sender, receiver) = mpmc::bounded::<Msg<i64, i64, i64>>(1000);
            receives.insert(i, (sender.clone(), receiver.clone()));
            let broadcast_tx = broadcast_tx.clone();
            let trace = trace.clone();
            let clock = clock.clone();

            let transport = Transport {
                broadcast: Box::new(
                    move |_, type_, instance, source, round, value, pr, pv, justification| {
                        if round > MAX_ROUND {
                            return Err(QbftError::MaxRoundReached);
                        }

                        trace.push(format!(
                            "{:?} {} => {}@{}",
                            clock.elapsed(),
                            source,
                            type_,
                            round
                        ));
                        let msg = new_msg(
                            type_,
                            *instance,
                            source,
                            round,
                            *value,
                            *value,
                            pr,
                            *pv,
                            justification,
                        );
                        sender.send(msg.clone()).expect(WRITE_CHAN_ERR);
                        broadcast_tx.send(msg).expect(WRITE_CHAN_ERR);
                        Ok(())
                    },
                ),
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

        let mut results = BTreeMap::<i64, Msg<i64, i64, i64>>::new();
        let mut count = 0;
        let mut decided = false;
        let mut done = 0;

        loop {
            mpmc::select! {
            recv(broadcast_rx) -> msg => {
                let msg = msg.expect(READ_CHAN_ERR);
                for (target, (out_tx, _)) in receives.iter() {
                    if *target == msg.source() {
                        continue;
                    }
                    out_tx.send(msg.clone()).expect(WRITE_CHAN_ERR);
                    if deterministic_unit(
                        seed_from_label(CHAIN_SPLIT_SEED_LABEL),
                        &msg,
                        *target,
                        TEST_STREAM_DUPLICATE,
                    ) < 0.1
                    {
                        out_tx.send(msg.clone()).expect(WRITE_CHAN_ERR);
                    }
                }
            }
            recv(result_chan_rx) -> res => {
                let q_commit = res.expect(READ_CHAN_ERR);
                for commit in q_commit.clone() {
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
                    results.insert(commit.source(), commit);
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
                thread::sleep(Duration::from_micros(1));
                let tick = if test.should_halt {
                    Duration::from_millis(100)
                } else {
                    Duration::from_millis(1)
                };
                clock.advance(tick);
                let limit = if test.should_halt {
                    let max_round = u32::try_from(MAX_ROUND).expect("MAX_ROUND fits u32");
                    let seconds = 1_u64
                        .checked_shl(max_round.checked_add(1).expect("MAX_ROUND permits timeout limit"))
                        .expect("MAX_ROUND permits timeout limit");
                    Duration::from_secs(seconds)
                } else {
                    Duration::from_secs(60)
                };
                if clock.elapsed() > limit {
                    cts.cancel();
                    clock.cancel();
                    panic!("chain split hang: decided={decided} done={done} count={count} elapsed={:?}\n{}", clock.elapsed(), trace.dump());
                }
            }
            }
        }
    });
}
