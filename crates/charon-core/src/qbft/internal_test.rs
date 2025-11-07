use crate::qbft::*;
use anyhow::{Result, bail};
use crossbeam::channel as mpmc;
use std::{any, collections::HashMap, sync::Arc, thread, time::Duration};

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
    /// Enables fuzzing by Node 1.
    pub fuzz: bool,
}

fn test_qbft(test: Test) {
    const n: usize = 4;
    const max_round: usize = 50;
    const fifo_limit: usize = 100;

    let mut receives = HashMap::<
        i64,
        (
            mpmc::Sender<Msg<i64, i64, i64>>,
            mpmc::Receiver<Msg<i64, i64, i64>>,
        ),
    >::new();
    let (broadcast_tx, broadcast_rx) = mpmc::unbounded::<Msg<i64, i64, i64>>();
    let (result_chan_tx, result_chan_rx) = mpmc::bounded::<Vec<Msg<i64, i64, i64>>>(n);
    let (run_chan_tx, run_chan_rx) = mpmc::bounded::<Result<()>>(n);

    let is_leader = make_is_leader(n as i64);

    let defs = Arc::new(Definition {
        is_leader: Box::new(is_leader),
        new_timer: Box::new(move |round: i64| {
            let d: Duration = if test.const_period {
                Duration::from_secs(1)
            } else {
                // If not constant periods, then exponential.
                Duration::from_secs_f64(f64::powf(2.0, (round - 1) as f64))
            };

            (mpmc::after(d), Box::new(|| {}))
        }),
        decide: {
            let result_chan_tx = result_chan_tx.clone();
            Box::new(
                move |_: &i64, _: &i64, q_commit: &Vec<Msg<i64, i64, i64>>| {
                    result_chan_tx.send(q_commit.clone()).expect(WRITE_CHAN_ERR);
                },
            )
        },
        compare: Box::new(
            |_: &Msg<i64, i64, i64>,
             _: &mpmc::Receiver<i64>,
             _: &i64,
             return_err: &mpmc::Sender<Result<()>>,
             _: &mpmc::Sender<i64>| {
                return_err.send(Ok(())).expect(WRITE_CHAN_ERR);
            },
        ),
        nodes: n as i64,
        fifo_limit: fifo_limit as i64,
        /* Ignored logging */
        log_round_change: Box::new(|_, _, _, _, _, _| {}),
        log_unjust: Box::new(|_, _, _| {}),
        log_upon_rule: Box::new(|_, _, _, _, _| {}),
    });

    thread::scope(|s| {
        for i in 1..=n as i64 {
            let (sender, receiver) = mpmc::bounded::<Msg<i64, i64, i64>>(1000);
            let broadcast_tx = broadcast_tx.clone();
            receives.insert(i, (sender.clone(), receiver.clone()));

            let trans = Transport {
                broadcast: Box::new(
                    move |type_: MessageType,
                          instance,
                          source,
                          round,
                          value,
                          pr,
                          pv,
                          justification| {
                        if round > max_round as i64 {
                            bail!("max round reach")
                        }

                        if type_ == MSG_COMMIT && round <= test.commits_after.into() {
                            return Ok(());
                        }

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

                        bcast(broadcast_tx.clone(), msg.clone(), test.bcast_jitter_ms);

                        Ok(())
                    },
                ),
                receive: receiver.clone(),
            };

            let receiver = receiver.clone();
            let start_delay = test.start_delay.get(&i).copied();
            let value_delay = test.value_delay.get(&i).copied();
            let decide_round = test.decide_round;
            let run_chan_tx = run_chan_tx.clone();
            let defs = defs.clone();

            s.spawn(move || {
                if let Some(delay) = start_delay {
                    thread::sleep(delay);
                }

                while !receiver.is_empty() {
                    _ = receiver.recv().expect(READ_CHAN_ERR);
                }

                let (v_chan_tx, v_chan_rx) = mpmc::bounded::<i64>(1);
                let (vs_chan_tx, vs_chan_rx) = mpmc::bounded::<i64>(1);

                if let Some(delay) = value_delay {
                    s.spawn(move || {
                        thread::sleep(delay);

                        v_chan_tx.send(i).expect(WRITE_CHAN_ERR);
                    });
                } else if decide_round != 1 {
                    s.spawn(move || {
                        v_chan_tx.send(i).expect(WRITE_CHAN_ERR);
                    });
                } else if is_leader_n(n as i64, test.instance, 1, i) {
                    s.spawn(move || {
                        v_chan_tx.send(i).expect(WRITE_CHAN_ERR);
                    });
                }

                run_chan_tx
                    .send(crate::qbft::run(
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
                    for (target, (out_tx, _)) in receives.iter() {
                        if *target == msg.source() {
                            continue; // Do not broadcast to self, we sent to self already.
                        }

                        if let Some(p) = test.drop_prob.get(&msg.source()) {
                            if rand::random::<f64>() < *p {
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

                    for commit in q_commit {
                        for (_, previous) in results.iter() {
                            assert_eq!(previous.value(), commit.value(), "commit values");
                        }

                        if !test.random_round {
                            assert_eq!(i64::from(test.decide_round), commit.round(), "wrong decide round");

                            if test.prepared_val != 0 { // Check prepared value if set
                                assert_eq!(i64::from(test.prepared_val), commit.value(), "wrong prepared value");
                            } else { // Otherwise check that leader value was used.
                                assert!(is_leader_n(n as i64, test.instance, commit.round(), commit.value()), "not leader");
                            }
                        }

                        results.insert(commit.source(), commit);
                    }

                    count += 1;
                    if count != n {
                        continue;
                    }

                    decided = true;
                }

                recv(run_chan_rx) -> res => {
                    let err = res.expect(READ_CHAN_ERR);

                    if err.is_err() {
                        if !decided {
                            panic!("unexpected run error");
                        }

                        done += 1;
                        if done == n {
                            return;
                        }
                    }
                }

                default => {
                    thread::sleep(time::Duration::from_millis(1));
                }
            }
        }
    });
}

/// Construct a leader election function.
fn make_is_leader(n: i64) -> impl Fn(&i64, i64, i64) -> bool {
    move |instance: &i64, round: i64, process: i64| -> bool { (instance + round) % n == process }
}

fn is_leader_n(n: i64, instance: i64, round: i64, process: i64) -> bool {
    (instance + round) % n == process
}

/// Returns a new message to be broadcast.
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

fn random_msg(instance: i64, peer_idx: i64) -> Msg<i64, i64, i64> {
    Arc::new(TestMsg {
        msg_type: MessageType(1 + rand::random_range(0..MSG_DECIDED.0)),
        instance,
        peer_idx,
        round: rand::random_range(0..10),
        value: rand::random_range(0..10),
        value_source: rand::random_range(0..10),
        pr: rand::random_range(0..10),
        pv: rand::random_range(0..10),
        justify: None,
    })
}

// Delays the message broadcast by between 1x and 2x jitter_ms and drops
// messages.
fn bcast(broadcast: mpmc::Sender<Msg<i64, i64, i64>>, msg: Msg<i64, i64, i64>, jitter_ms: i32) {
    if jitter_ms == 0 {
        broadcast.send(msg.clone()).expect(WRITE_CHAN_ERR);
    }

    thread::spawn(move || {
        let delta_ms = (f64::from(jitter_ms) * rand::random::<f64>()) as i32;
        let delay = Duration::from_millis((jitter_ms + delta_ms) as u64);
        thread::sleep(delay);

        broadcast.send(msg).expect(WRITE_CHAN_ERR);
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
#[ignore = "deadlock"]
fn happy_0() {
    test_qbft(Test {
        instance: 0,
        decide_round: 1,
        ..Default::default()
    });
}
