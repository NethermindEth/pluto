use crate::qbft::{Definition, MSG_COMMIT, MessageType, Msg, SomeMsg, Transport};
use anyhow::{Result, bail};
use crossbeam::channel as mpmc;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{self, Duration},
};

const WRITE_CHAN_ERR: &str = "Failed to write to channel";

struct Test {
    /// Consensus instance, only affects leader election.
    pub instance: i64,
    /// Results in 1s round timeout, otherwise exponential (1s,2s,4s...)
    pub const_period: bool,
    /// Delays start of certain processes
    pub start_delay: HashMap<i64, time::Duration>,
    /// Delays input value availability of certain processes
    pub value_delay: HashMap<i64, time::Duration>,
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

    let mut receives = HashMap::<i64, mpmc::Receiver<Msg<i64, i64, i64>>>::new();
    let broadcast = mpmc::unbounded::<Msg<i64, i64, i64>>();
    let (result_chan_tx, result_chan_rx) = mpmc::bounded::<Vec<Msg<i64, i64, i64>>>(n);
    let run_chan = mpmc::bounded::<Result<()>>(n);

    let is_leader = make_is_leader(n as i64);

    let defs = Definition {
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
    };

    for i in 1..=n as i64 {
        let (send, receive) = mpmc::bounded::<Msg<i64, i64, i64>>(1000);
        receives.insert(i, receive.clone());
        let trans = Transport {
            broadcast: Box::new(
                move |type_: MessageType, instance, source, round, value, pr, pv, justification| {
                    if round > max_round as i64 {
                        bail!("max round reach")
                    }

                    if type_ == MSG_COMMIT && round <= test.commits_after.into() {
                        return Ok(());
                    }

                    Ok(())
                },
            ),
            receive,
        };
    }
}

/// Construct a leader election function.
fn make_is_leader(n: i64) -> impl Fn(&i64, i64, i64) -> bool {
    move |instance: &i64, round: i64, process: i64| -> bool { (instance + round) % n == process }
}

fn new_msg(
    type_: MessageType,
    instance: i64,
    source: i64,
    round: i64,
    value: i64,
    value_source: i64,
    pr: i64,
    pv: i64,
    justify: Vec<Msg<i64, i64, i64>>,
) -> Msg<i64, i64, i64> {
    todo!()
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
    justify: Vec<TestMsg>,
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
        self.justify
            .iter()
            .map(|j| Arc::new(j.clone()) as Msg<i64, i64, i64>)
            .collect()
    }
}

#[test]
fn it_works() {
    assert_eq!(2 + 2, 4);
}
