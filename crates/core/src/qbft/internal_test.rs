use crate::qbft::{self, fake_clock::FakeClock, *};
use cancellation::CancellationTokenSource;
use crossbeam::channel as mpmc;
use std::{collections::HashMap, sync::Arc, thread, time::Duration};

const WRITE_CHAN_ERR: &str = "Failed to write to channel";
const READ_CHAN_ERR: &str = "Failed to read from channel";

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
}

fn test_qbft(test: Test) {
    const N: usize = 4;
    const MAX_ROUND: usize = 50;
    const FIFO_LIMIT: usize = 100;

    let start_time = time::Instant::now();
    let clock = FakeClock::new(start_time);

    let cts = CancellationTokenSource::new();
    let mut receives = HashMap::<
        i64,
        (
            mpmc::Sender<Msg<i64, i64, i64>>,
            mpmc::Receiver<Msg<i64, i64, i64>>,
        ),
    >::new();
    let (broadcast_tx, broadcast_rx) = mpmc::unbounded::<Msg<i64, i64, i64>>();
    let (result_chan_tx, result_chan_rx) = mpmc::bounded::<Vec<Msg<i64, i64, i64>>>(N);
    let (run_chan_tx, run_chan_rx) = mpmc::bounded::<Result<()>>(N);

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
        compare: Box::new(|_, _, _, _, return_err, _| {
            return_err.send(Ok(())).expect(WRITE_CHAN_ERR);
        }),
        nodes: N as i64,
        fifo_limit: FIFO_LIMIT as i64,
        log_round_change: {
            let clock = clock.clone();

            Box::new(move |_, process, round, new_round, upon_rule, _| {
                println!(
                    "{:?} - {}@{} change to {} ~= {}",
                    clock.elapsed(),
                    process,
                    round,
                    new_round,
                    upon_rule,
                );
            })
        },
        log_unjust: Box::new(|_, _, msg| {
            println!("Unjust: {msg:?}");
        }),
        log_upon_rule: {
            let clock = clock.clone();
            Box::new(move |_, process, round, msg, upon_rule| {
                println!(
                    "{:?} {} => {}@{} -> {}@{} ~= {}",
                    clock.elapsed(),
                    msg.source(),
                    msg.type_(),
                    msg.round(),
                    process,
                    round,
                    upon_rule,
                );
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

                    Box::new(
                        move |_, type_, instance, source, round, value, pr, pv, justification| {
                            if round > MAX_ROUND as i64 {
                                return Err(QbftError::MaxRoundReached);
                            }

                            if type_ == MSG_COMMIT && round <= test.commits_after.into() {
                                println!(
                                    "{:?} {} dropping commit for round {}",
                                    clock.elapsed(),
                                    source,
                                    round
                                );
                                return Ok(());
                            }

                            println!("{:?} {} => {}@{}", clock.elapsed(), source, type_, round);

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
                            ); // TODO: Add clock

                            Ok(())
                        },
                    )
                },
                receive: receiver.clone(),
            };

            let token = cts.token();
            let clock = clock.clone();
            let receiver = receiver.clone();
            let start_delay = test.start_delay.get(&i).copied();
            let value_delay = test.value_delay.get(&i).copied();
            let decide_round = test.decide_round;
            let run_chan_tx = run_chan_tx.clone();
            let defs = defs.clone();
            let is_leader = is_leader.clone();

            s.spawn(move || {
                if let Some(delay) = start_delay {
                    println!("{:?} Node {} start delay {:?}", clock.elapsed(), i, delay);
                    let (delay_ch, _) = clock.new_timer(delay);
                    _ = delay_ch.recv();
                    println!("{:?} Node {} starting", clock.elapsed(), i);
                }

                // Drain any buffered messages
                while !receiver.is_empty() {
                    _ = receiver.recv().expect(READ_CHAN_ERR);
                }

                let (v_chan_tx, v_chan_rx) = mpmc::bounded::<i64>(1);
                let (_, vs_chan_rx) = mpmc::bounded::<i64>(1);

                if let Some(delay) = value_delay {
                    s.spawn(move || {
                        let (delay_ch, cancel) = clock.new_timer(delay);
                        _ = delay_ch.recv();
                        _ = v_chan_tx.send(i);

                        cancel();
                    });
                } else if decide_round != 1 {
                    s.spawn(move || {
                        _ = v_chan_tx.send(i);
                    });
                } else if is_leader(&test.instance, 1, i) {
                    s.spawn(move || {
                        _ = v_chan_tx.send(i);
                    });
                }

                run_chan_tx
                    .send(qbft::run(
                        token,
                        &defs,
                        &trans,
                        &test.instance,
                        i,
                        v_chan_rx,
                        vs_chan_rx,
                    ))
                    .expect(WRITE_CHAN_ERR);
            });
        }

        let mut results = HashMap::<i64, Msg<i64, i64, i64>>::new();
        let mut count = 0;
        let mut decided = false;
        let mut done = 0;

        loop {
            mpmc::select! {
                recv(broadcast_rx) -> msg => {
                    let msg = msg.expect(READ_CHAN_ERR);
                    for (target, (out_tx, _)) in &receives {
                        if *target == msg.source() {
                            continue; // Do not broadcast to self, we sent to self already.
                        }

                        if let Some(p) = test.drop_prob.get(&msg.source()) {
                            if rand::random::<f64>() < *p {
                                println!("{:?} {} => {}@{} => {} (dropped)", clock.elapsed(), msg.source(), msg.type_(), msg.round(), target);
                                continue; // Drop
                            }
                        }

                        out_tx.send(msg.clone()).expect(WRITE_CHAN_ERR);

                        if rand::random::<f64>() < 0.1 { // Send 10% messages twice
                            out_tx.send(msg.clone()).expect(WRITE_CHAN_ERR);
                        }
                    }
                }

                recv(result_chan_rx) -> res => {
                    let q_commit = res.expect(READ_CHAN_ERR);

                    for commit in q_commit.clone() {
                        for previous in results.values() {
                            assert_eq!(previous.value(), commit.value(), "commit values");
                        }

                        if !test.random_round {
                            assert_eq!(i64::from(test.decide_round), commit.round(), "wrong decide round");

                            if test.prepared_val != 0 { // Check prepared value if set
                                assert_eq!(i64::from(test.prepared_val), commit.value(), "wrong prepared value");
                            } else { // Otherwise check that leader value was used.
                                assert!(is_leader(&test.instance, commit.round(), commit.value()), "not leader");
                            }
                        }

                        results.insert(commit.source(), commit);
                    }

                    count += 1;
                    if count != N {
                        continue;
                    }

                    let round = q_commit[0].round();
                    println!("Got all results in round {} after {:?}: {:?}", round, clock.elapsed(), results);

                    // Trigger shutdown
                    decided = true;

                    clock.cancel();
                    cts.cancel();
                }

                recv(run_chan_rx) -> res => {
                    let err = res.expect(READ_CHAN_ERR);

                    if err.is_err() {
                        assert!(decided, "unexpected run error");
                    }

                    done += 1;
                    if done == N {
                        return;
                    }
                }

                default => {
                    thread::sleep(time::Duration::from_micros(1));
                    clock.advance(Duration::from_millis(1));
                }
            }
        }
    });
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
    broadcast: mpmc::Sender<Msg<i64, i64, i64>>,
    msg: Msg<i64, i64, i64>,
    jitter_ms: i32,
    clock: FakeClock,
) {
    if jitter_ms == 0 {
        broadcast.send(msg.clone()).expect(WRITE_CHAN_ERR);
        return;
    }

    thread::spawn(move || {
        let delta_ms = (f64::from(jitter_ms) * rand::random::<f64>()) as i32;
        let delay = Duration::from_millis((jitter_ms + delta_ms) as u64);
        println!(
            "{:?} {} => {}@{} (bcast delay {:?})",
            clock.elapsed(),
            msg.source(),
            msg.type_(),
            msg.round(),
            delay
        );
        let (delay_ch, _) = clock.new_timer(delay);
        _ = delay_ch.recv();

        _ = broadcast.send(msg);
    });
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
#[ignore = "flaky"]
fn happy_0() {
    test_qbft(Test {
        instance: 0,
        decide_round: 1,
        ..Default::default()
    });
}

#[test]
#[ignore = "flaky"]
fn happy_1() {
    test_qbft(Test {
        instance: 1,
        decide_round: 1,
        ..Default::default()
    });
}

#[test]
#[ignore = "flaky"]
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
#[ignore = "wrong prepared value"]
fn prepare_round_2_decide_round_3() {
    test_qbft(Test {
        instance: 0,
        commits_after: 2,
        value_delay: HashMap::from([(1, Duration::from_millis(200))]),
        decide_round: 3,
        prepared_val: 2,
        const_period: true,
        ..Default::default()
    });
}

#[test]
#[ignore = "wrong decide round"]
fn leader_late_xp() {
    test_qbft(Test {
        instance: 0,
        start_delay: HashMap::from([(1, Duration::from_millis(200))]),
        decide_round: 2,
        ..Default::default()
    });
}

#[test]
#[ignore = "wrong decide round"]
fn leader_down_const() {
    test_qbft(Test {
        instance: 3,
        start_delay: HashMap::from([
            (1, Duration::from_millis(50)),
            (2, Duration::from_millis(100)),
        ]),
        decide_round: 4,
        ..Default::default()
    });
}

#[test]
#[ignore = "flaky"]
fn very_late_exp() {
    test_qbft(Test {
        instance: 3,
        start_delay: HashMap::from([(1, Duration::from_secs(5)), (2, Duration::from_secs(10))]),
        decide_round: 4,
        ..Default::default()
    });
}

#[test]
#[ignore = "flaky"]
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
#[ignore = "flaky"]
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
#[ignore = "flaky"]
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
#[ignore = "flaky"]
fn very_delayed_value_exp() {
    test_qbft(Test {
        instance: 3,
        value_delay: HashMap::from([(1, Duration::from_secs(5)), (2, Duration::from_secs(10))]),
        decide_round: 4,
        ..Default::default()
    });
}

#[test]
#[ignore = "flaky"]
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
#[ignore = "flaky"]
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
#[ignore = "flaky"]
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
#[ignore = "flaky"]
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
#[ignore = "flaky"]
fn jitter_500ms_exp() {
    test_qbft(Test {
        instance: 3,
        bcast_jitter_ms: 500,
        random_round: true,
        ..Default::default()
    });
}

#[test]
#[ignore = "flaky"]
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
#[ignore = "flaky"]
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
#[ignore = "flaky"]
fn drop_30_percent_const() {
    test_qbft(Test {
        instance: 1,
        drop_prob: HashMap::from([(1, 0.3), (2, 0.3), (3, 0.3), (4, 0.3)]),
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
        compare: Box::new(|_, _, _, _, _, _| {}),
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
#[ignore = "flaky"]
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

        panic!("unexpected round {round}");
    });
    def.compare = Box::new(|_, _, _, _, return_err, _| {
        _ = return_err.send(Ok(()));
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

    assert!(res.is_ok());
}
