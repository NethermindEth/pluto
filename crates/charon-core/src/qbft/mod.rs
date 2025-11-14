//! Package `qbft` is an implementation of the ["The Istanbul BFT Consensus Algorithm"](https://arxiv.org/pdf/2002.03613.pdf) by Henrique Moniz
//! as referenced by the [QBFT spec](https://github.com/ConsenSys/qbft-formal-spec-and-verification).
//!
//! ## Features
//!
//! - Simple API, just a single function: `qbft.Run`.
//! - Consensus on arbitrary data.
//! - Transport abstracted and not provided.
//! - Decoupled from process authentication and message signing (not provided).
//! - No dependencies.
//! - Explicit justifications.

// TODO: Remove these checks
#![allow(missing_docs)]
#![allow(clippy::type_complexity)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::arithmetic_side_effects)]

use anyhow::{Result, bail};
use cancellation::CancellationToken;
use crossbeam::channel as mpmc;
use std::{
    any,
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet},
    error,
    fmt::{self, Display},
    hash::Hash,
    sync, thread, time,
};

/// Abstracts the transport layer between processes in the consensus system.
pub struct Transport<I, V, C>
where
    V: PartialEq,
{
    /// Broadcast sends a message with the provided fields to all other
    /// processes in the system (including this process).
    ///
    /// Note that an error exits the algorithm.
    pub broadcast: Box<
        dyn Fn(
                /* ct */ &CancellationToken,
                /* type_ */ MessageType,
                /* instance */ &I,
                /* source */ i64,
                /* round */ i64,
                /* value */ &V,
                /* pr */ i64,
                /* pv */ &V,
                /* justification */ Option<&Vec<Msg<I, V, C>>>,
            ) -> Result<()>
            + Send
            + Sync,
    >,

    /// Receive returns a stream of messages received
    /// from other processes in the system (including this process).
    pub receive: mpmc::Receiver<Msg<I, V, C>>,
}

/// Defines the consensus system parameters that are external to the qbft
/// algorithm. This remains constant across multiple instances of consensus
/// (calls to Run).
pub struct Definition<I, V, C>
where
    V: PartialEq,
{
    /// A deterministic leader election function.
    pub is_leader:
        Box<dyn Fn(/* instance */ &I, /* round */ i64, /* process */ i64) -> bool + Send + Sync>,

    /// Returns a new timer channel and stop function for the round
    pub new_timer: Box<
        dyn Fn(
                /* rounds */ i64,
            ) -> (mpmc::Receiver<time::Instant>, Box<dyn Fn() + Send + Sync>)
            + Send
            + Sync,
    >,

    /// Called when leader proposes value and we compare it with our local
    /// value. It's an opt-in feature that should instantly return nil on
    /// returnErr channel if it is not turned on.
    pub compare: Box<
        dyn Fn(
                /* ct */ &CancellationToken,
                /* qcommit */ &Msg<I, V, C>,
                /* inputValueSourceCh */ &mpmc::Receiver<C>,
                /* inputValueSource */ &C,
                /* returnErr */ &mpmc::Sender<Result<()>>,
                /* returnValue */ &mpmc::Sender<C>,
            ) + Send
            + Sync,
    >,

    /// Called when consensus has been reached on a value.
    pub decide: Box<
        dyn Fn(
                /* ct */ &CancellationToken,
                /* instance */ &I,
                /* value */ &V,
                /* qcommit */ &Vec<Msg<I, V, C>>,
            ) + Send
            + Sync,
    >,

    /// Allows debug logging of triggered upon rules on message receipt.
    /// It includes the rule that triggered it and all received round messages.
    pub log_upon_rule: Box<
        dyn Fn(
                /* instance */ &I,
                /* process */ i64,
                /* round */ i64,
                /* msg */ &Msg<I, V, C>,
                /* uponRule */ UponRule,
            ) + Send
            + Sync,
    >,
    /// Allows debug logging of round changes.
    pub log_round_change: Box<
        dyn Fn(
                /* instance */ &I,
                /* process */ i64,
                /* round */ i64,
                /* newRound */ i64,
                /* uponRule */ UponRule,
                /* msgs */ &Vec<Msg<I, V, C>>,
            ) + Send
            + Sync,
    >,

    /// Allows debug logging of unjust messages.
    pub log_unjust:
        Box<dyn Fn(/* instance */ &I, /* process */ i64, /* msg */ Msg<I, V, C>) + Send + Sync>,

    /// Total number of nodes/processes participating in consensus.
    pub nodes: i64,

    /// Limits the amount of message buffered for each peer.
    pub fifo_limit: i64,
}

impl<I, V, C> Definition<I, V, C>
where
    V: PartialEq,
{
    /// Quorum count for the system.
    /// See IBFT 2.0 paper for correct formula: <https://arxiv.org/pdf/1909.10194.pdf>
    pub fn quorum(&self) -> i64 {
        ((self.nodes as f64 * 2.0) / 3.0).ceil() as i64
    }

    /// Maximum number of faulty/byzantium nodes supported in the system.
    /// See IBFT 2.0 paper for correct formula: <https://arxiv.org/pdf/1909.10194.pdf>
    pub fn faulty(&self) -> i64 {
        ((self.nodes - 1) as f64 / 3.0).floor() as i64
    }
}

/// Defines the QBFT message types
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct MessageType(i64);

// NOTE: message type ordering MUST not change, since it breaks backwards
// compatibility.
pub const MSG_UNKNOWN: MessageType = MessageType(0);
pub const MSG_PRE_PREPARE: MessageType = MessageType(1);
pub const MSG_PREPARE: MessageType = MessageType(2);
pub const MSG_COMMIT: MessageType = MessageType(3);
pub const MSG_ROUND_CHANGE: MessageType = MessageType(4);
pub const MSG_DECIDED: MessageType = MessageType(5);

const MSG_SENTINEL: MessageType = MessageType(6); // intentionally not public

impl MessageType {
    pub fn valid(&self) -> bool {
        self.0 > MSG_UNKNOWN.0 && self.0 < MSG_SENTINEL.0
    }
}

impl Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self.0 {
            0 => "unknown",
            1 => "pre_prepare",
            2 => "prepare",
            3 => "commit",
            4 => "round_change",
            5 => "decided",
            _ => panic!("invalid message type"),
        };
        write!(f, "{}", s)
    }
}

/// Defines the inter process messages.
pub trait SomeMsg<I, V, C>: Send + Sync + fmt::Debug
where
    V: PartialEq,
{
    /// Type of the message.
    fn type_(&self) -> MessageType;
    /// Consensus instance.
    fn instance(&self) -> I;
    /// Process that sent the message.
    fn source(&self) -> i64;
    /// The message pertains to.
    fn round(&self) -> i64;
    /// The value being proposed, usually a hash.
    fn value(&self) -> V;
    /// Usually the value that was hashed and is returned in `value`.
    fn value_source(&self) -> Result<C>;
    /// The justified prepared round.
    fn prepared_round(&self) -> i64;
    /// The justified prepared value.
    fn prepared_value(&self) -> V;
    /// Set of messages that explicitly justifies this message.
    fn justification(&self) -> Vec<Msg<I, V, C>>;

    /// Cast as `Any` to allow downcasting.
    fn as_any(&self) -> &dyn any::Any;
}

/// Alias for any `Msg` implementation tracked by reference counting.
pub type Msg<I, V, C> = sync::Arc<dyn SomeMsg<I, V, C>>;

/// Defines the event based rules that are triggered when messages are received.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct UponRule(i64);

pub const UPON_NOTHING: UponRule = UponRule(0);
pub const UPON_JUSTIFIED_PRE_PREPARE: UponRule = UponRule(1);
pub const UPON_QUORUM_PREPARES: UponRule = UponRule(2);
pub const UPON_QUORUM_COMMITS: UponRule = UponRule(3);
pub const UPON_UNJUST_QUORUM_ROUND_CHANGES: UponRule = UponRule(4);
pub const UPON_F_PLUS1_ROUND_CHANGES: UponRule = UponRule(5);
pub const UPON_QUORUM_ROUND_CHANGES: UponRule = UponRule(6);
pub const UPON_JUSTIFIED_DECIDED: UponRule = UponRule(7);
pub const UPON_ROUND_TIMEOUT: UponRule = UponRule(8); // This is not triggered by a message, but by a timer.

impl Display for UponRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self.0 {
            0 => "nothing",
            1 => "justified_pre_prepare",
            2 => "quorum_prepares",
            3 => "quorum_commits",
            4 => "unjust_quorum_round_changes",
            5 => "f_plus_1_round_changes",
            6 => "quorum_round_changes",
            7 => "justified_decided",
            8 => "round_timeout",
            _ => panic!("invalid upon rule"),
        };
        write!(f, "{}", s)
    }
}

/// Defines the key used to deduplicate upon rules.
#[derive(Eq, Hash, PartialEq)]
struct DedupKey {
    upon_rule: UponRule,
    round: i64,
}

#[derive(Debug)]
struct CompareError;

impl Display for CompareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "compare leader value with local value failed")
    }
}

impl error::Error for CompareError {}

#[derive(Debug)]
struct TimeoutError;

impl Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "timeout")
    }
}

impl error::Error for TimeoutError {}

/// Executes the consensus algorithm until the context is closed.
/// The generic type `I` is the instance of consensus and can be anything.
/// The generic type `V` is the arbitrary data value being proposed; it only
/// requires an Equal method. The generic type `C` is the compare value, used to
/// compare leader's proposed value with local value and can be anything.
pub fn run<I, V, C>(
    ct: &CancellationToken,
    d: &Definition<I, V, C>,
    t: &Transport<I, V, C>,
    instance: &I,
    process: i64,
    mut input_value_ch: mpmc::Receiver<V>,
    input_value_source_ch: mpmc::Receiver<C>,
) -> Result<()>
where
    V: PartialEq + Eq + Hash + Default,
    C: Clone + Send + Sync + Default,
{
    // === State ===
    let round: Cell<i64> = Cell::new(1);
    let input_value: RefCell<V> = RefCell::new(Default::default());
    let mut input_value_source: C = Default::default();
    let ppj_cache: RefCell<Option<Vec<Msg<I, V, C>>>> = RefCell::new(None); // Cached pre-prepare justification for the current round (`None` value is unset).
    let prepared_round: Cell<i64> = Cell::new(0);
    let prepared_value: RefCell<V> = RefCell::new(Default::default());
    let mut compare_failure_round: i64 = 0;
    let prepared_justification: RefCell<Option<Vec<Msg<I, V, C>>>> = RefCell::new(None);
    let mut q_commit: Option<Vec<Msg<I, V, C>>> = None;
    let buffer: RefCell<HashMap<i64, Vec<Msg<I, V, C>>>> = RefCell::new(HashMap::new());
    let dedup_rules: RefCell<HashMap<DedupKey, bool>> = RefCell::new(HashMap::new());
    let mut timer_chan: mpmc::Receiver<time::Instant>;
    let mut stop_timer: Box<dyn Fn()>;

    // === Helpers ==

    // Broadcasts a non-ROUND-CHANGE message for current round.
    let broadcast_msg =
        |type_: MessageType, value: &V, justification: Option<&Vec<Msg<I, V, C>>>| {
            (t.broadcast)(
                ct,
                type_,
                instance,
                process,
                round.get(),
                value,
                0,
                &Default::default(),
                justification,
            )
        };
    // Broadcasts a ROUND-CHANGE message with current state.
    let broadcast_round_change = || {
        (t.broadcast)(
            ct,
            MSG_ROUND_CHANGE,
            instance,
            process,
            round.get(),
            &Default::default(),
            prepared_round.get(),
            &prepared_value.borrow(),
            prepared_justification.borrow().as_ref(),
        )
    };

    // Broadcasts a PRE-PREPARE message with current state
    // and our own input value if present, otherwise it caches the justification
    // to be used when the input value becomes available.
    let broadcast_own_pre_prepare = |justification: Vec<Msg<I, V, C>>| {
        if ppj_cache.borrow().is_some() {
            panic!("bug: justification cache must be none")
        }

        if *input_value.borrow() == Default::default() {
            // Can't broadcast a pre-prepare yet, need to wait for an input value.
            ppj_cache.replace(Some(justification));
            return Ok(());
        }

        broadcast_msg(MSG_PRE_PREPARE, &input_value.borrow(), Some(&justification))
    };

    // Adds a message to each process' FIFO queue
    let buffer_msg = |msg: &Msg<I, V, C>| {
        let mut b = buffer.borrow_mut();
        let fifo = b.entry(msg.source()).or_default();

        fifo.push(msg.clone());
        if fifo.len() as i64 > d.fifo_limit {
            fifo.drain(0..(fifo.len() - d.fifo_limit as usize));
        }
    };

    // Returns true if the rule has been already executed since last round
    // change.
    let is_duplicated_rule = |upon_rule: UponRule, round: i64| {
        let k = DedupKey { upon_rule, round };
        dedup_rules.borrow_mut().insert(k, true).is_some()
    };

    // Updates round and clears the rule dedup state.
    let change_round = |new_round: i64, rule: UponRule| {
        if round.get() == new_round {
            return;
        }

        (d.log_round_change)(
            instance,
            process,
            round.get(),
            new_round,
            rule,
            &extract_round_messages(&buffer.borrow(), round.get()),
        );

        round.set(new_round);
        dedup_rules.replace(HashMap::new());
        ppj_cache.replace(None);
    };

    // Algorithm 1:11
    {
        if (d.is_leader)(instance, round.get(), process) {
            // Note round==1 at this point.
            broadcast_own_pre_prepare(vec![])?; // Empty justification since round==1
        }

        (timer_chan, stop_timer) = (d.new_timer)(round.get());
    }

    while !ct.is_canceled() {
        mpmc::select! {
            recv(input_value_ch) -> result => {
                let input_value = result?;

                if input_value == Default::default() {
                    bail!("zero input value not supported");
                }

                if let Some(ppj) = ppj_cache.borrow().as_ref() {
                    // Broadcast the pre-prepare now that we have a input value using the cached
                    // justification.
                    broadcast_msg(MSG_PRE_PREPARE, &input_value, Some(ppj))?;
                }

                // Don't read from this channel again.
                input_value_ch = mpmc::never();
            },

            recv(t.receive) -> result => {
                let msg = result?;
                if let Some(v) = q_commit.as_ref() {
                    if !v.is_empty() {
                        if msg.source() != process && msg.type_() == MSG_ROUND_CHANGE {
                            // Algorithm 3:17
                            broadcast_msg(MSG_DECIDED, &v[0].value(), Some(v))?;
                        }

                        continue;
                    }
                }

                // Drop unjust messages
                if !is_justified(d, instance, &msg, compare_failure_round) {
                    (d.log_unjust)(instance, process, msg);
                    continue;
                }

                buffer_msg(&msg);

                let (rule, justification) =
                    classify(d, instance, round.get(), process, &buffer.borrow(), &msg);
                if rule == UPON_NOTHING || is_duplicated_rule(rule, msg.round()) {
                    // Do nothing more if no rule or duplicate rule was triggered
                    continue;
                }

                (d.log_upon_rule)(instance, process, round.get(), &msg, rule);

                match rule {
                    // Algorithm 2:1
                    UPON_JUSTIFIED_PRE_PREPARE => {
                        change_round(msg.round(), rule);

                        stop_timer();
                        (timer_chan, stop_timer) = (d.new_timer)(round.get());

                        let compare_result = compare(
                            ct,
                            d,
                            &msg,
                            &input_value_source_ch, // TODO: Moved value
                            input_value_source.clone(),
                            &timer_chan,
                        );

                        match compare_result {
                            Ok(v) => {
                                input_value_source = v;
                                broadcast_msg(MSG_PREPARE, &msg.value(), None)?;
                            }
                            Err(some_error) => {
                                if some_error.downcast_ref::<CompareError>().is_some() {
                                    compare_failure_round = msg.round();
                                } else if some_error.downcast_ref::<TimeoutError>().is_some() {
                                    // As compare function is blocking on waiting local data, round
                                    // might timeout in the meantime. If
                                    // this happens, we trigger round change.
                                    // Algorithm 3:1
                                    change_round(round.get() + 1, UPON_ROUND_TIMEOUT);
                                    stop_timer();

                                    (timer_chan, stop_timer) = (d.new_timer)(round.get());

                                    broadcast_round_change()?;
                                } else {
                                    bail!("bug: expected only comparison or timeout error");
                                }
                            }
                        }
                    }
                    UPON_QUORUM_PREPARES => {
                        // Algorithm 2:4
                        // Only applicable to current round
                        prepared_round.set(round.get()); /* == msg.Round */
                        prepared_value.replace(msg.value());
                        prepared_justification.replace(justification);

                        broadcast_msg(MSG_COMMIT, &prepared_value.borrow(), None)?;
                    }
                    UPON_QUORUM_COMMITS | UPON_JUSTIFIED_DECIDED => {
                        // Algorithm 2:8
                        change_round(msg.round(), rule);
                        q_commit = justification;
                        stop_timer();

                        timer_chan = mpmc::never();

                        let justification = q_commit.as_ref()
                            .expect("Rules `UPON_QUORUM_COMMITS` and `UPON_JUSTIFIED_DECIDED` always include a justification");
                        (d.decide)(ct, instance, &msg.value(), justification);
                    }
                    UPON_F_PLUS1_ROUND_CHANGES => {
                        // Algorithm 3:5

                        let justification = justification.expect(
                            "Rule `UPON_F_PLUS1_ROUND_CHANGES` always includes a justification",
                        );

                        // Only applicable to future rounds
                        change_round(
                            next_min_round(d, &justification, round.get() /* < msg.Round */),
                            rule,
                        );

                        stop_timer();
                        (timer_chan, stop_timer) = (d.new_timer)(round.get());

                        broadcast_round_change()?;
                    }
                    UPON_QUORUM_ROUND_CHANGES => {
                        // Algorithm 3:11

                        let justification = justification
                            .expect("Rule `UPON_QUORUM_ROUND_CHANGES` always includes a justification");

                        // Only applicable to current round (round > 1)
                        match get_single_justified_pr_pv(d, &justification) {
                            Some((pr, pv)) if compare_failure_round != pr => {
                                broadcast_msg(MSG_PRE_PREPARE, &pv, Some(&justification))?
                            }
                            _ => broadcast_own_pre_prepare(justification)?,
                        }
                    }
                    UPON_UNJUST_QUORUM_ROUND_CHANGES => {
                        // Ignore bug or byzantine
                    }
                    _ => panic!("bug: invalid rule"),
                }
            },

            recv(timer_chan) -> result => {
                result?;

                change_round(round.get() + 1, UPON_ROUND_TIMEOUT);
                stop_timer();

                (timer_chan, stop_timer) = (d.new_timer)(round.get());

                broadcast_round_change()?;
            }

            default => {
                if ct.is_canceled() {
                    break;
                }
            }
        }
    }

    Ok(())
}

fn compare<I, V, C>(
    ct: &CancellationToken,
    d: &Definition<I, V, C>,
    msg: &Msg<I, V, C>,
    input_value_source_ch: &mpmc::Receiver<C>,
    input_value_source: C,
    timer_chan: &mpmc::Receiver<time::Instant>,
) -> Result<C>
where
    V: PartialEq,
    C: Clone + Send + Sync,
{
    let (compare_err_tx, compare_err_rx) = mpmc::bounded::<Result<()>>(1);
    let (compare_value_tx, compare_value_rx) = mpmc::bounded::<C>(1);

    // d.Compare has 2 roles:
    // 1. Read from the inputValueSourceCh (if inputValueSource is empty). If it
    //    read from the channel, it returns the value on compareValue channel.
    // 2. Compare the value read from inputValueSourceCh (or inputValueSource if it
    //    is not empty) to the value proposed by the leader.
    // If comparison or any other unexpected error occurs, the error is returned on
    // compareErr channel.

    thread::scope(|s| {
        let mut result = input_value_source.clone();
        let compare = &d.compare;

        s.spawn(move || {
            (compare)(
                ct,
                msg,
                input_value_source_ch,
                &input_value_source,
                &compare_err_tx,
                &compare_value_tx,
            );
        });

        loop {
            mpmc::select! {
                recv(compare_err_rx) -> msg => {
                    let err = msg?;

                    match err {
                        Ok(_) => return Ok(result),
                        Err(_) => bail!(CompareError),
                    }
                },

                recv(compare_value_rx) -> msg => {
                    let value = msg?;

                    result = value;
                },

                recv(timer_chan) -> msg => {
                    msg?;

                    bail!(TimeoutError);
                }
            }
        }
    })
}

/// Returns all messages from the provided round.
fn extract_round_messages<I, V, C>(
    buffer: &HashMap<i64, Vec<Msg<I, V, C>>>,
    round: i64,
) -> Vec<Msg<I, V, C>>
where
    V: PartialEq,
{
    let mut resp = vec![];

    for msgs in buffer.values() {
        for msg in msgs {
            if msg.round() == round {
                resp.push(msg.clone());
            }
        }
    }

    resp
}

/// Returns the rule triggered upon receipt of the last message and its
/// justifications.
fn classify<I, V, C>(
    d: &Definition<I, V, C>,
    instance: &I,
    round: i64,
    process: i64,
    buffer: &HashMap<i64, Vec<Msg<I, V, C>>>,
    msg: &Msg<I, V, C>,
) -> (UponRule, Option<Vec<Msg<I, V, C>>>)
where
    V: Eq + Hash + Default,
{
    match msg.type_() {
        MSG_DECIDED => (UPON_JUSTIFIED_DECIDED, Some(msg.justification())),
        MSG_PRE_PREPARE => {
            if msg.round() < round {
                (UPON_NOTHING, None)
            } else {
                (UPON_JUSTIFIED_PRE_PREPARE, None)
            }
        }
        MSG_PREPARE => {
            // Ignore other rounds, since PREPARE isn't justified.
            if msg.round() != round {
                return (UPON_NOTHING, None);
            }

            let prepares =
                filter_by_round_and_value(&flatten(buffer), MSG_PREPARE, msg.round(), msg.value());

            if prepares.len() as i64 >= d.quorum() {
                (UPON_QUORUM_PREPARES, Some(prepares))
            } else {
                (UPON_NOTHING, None)
            }
        }
        MSG_COMMIT => {
            // Ignore other rounds, since COMMIT isn't justified.
            if msg.round() != round {
                return (UPON_NOTHING, None);
            }

            let commits =
                filter_by_round_and_value(&flatten(buffer), MSG_COMMIT, msg.round(), msg.value());
            if commits.len() as i64 >= d.quorum() {
                (UPON_QUORUM_COMMITS, Some(commits))
            } else {
                (UPON_NOTHING, None)
            }
        }
        MSG_ROUND_CHANGE => {
            // Only ignore old rounds.
            if msg.round() < round {
                return (UPON_NOTHING, None);
            }

            let all = flatten(buffer);

            if msg.round() > round {
                // Jump ahead if we received F+1 higher ROUND-CHANGEs.
                if let Some(frc) = get_fplus1_round_changes(d, &all, round) {
                    return (UPON_F_PLUS1_ROUND_CHANGES, Some(frc));
                }

                return (UPON_NOTHING, None);
            }

            /* else msg.Round() == round */

            let qrc = filter_round_change(&all, msg.round());
            if (qrc.len() as i64) < d.quorum() {
                return (UPON_NOTHING, None);
            }

            let Some(qrc) = get_justified_qrc(d, &all, msg.round()) else {
                return (UPON_UNJUST_QUORUM_ROUND_CHANGES, None);
            };

            if !(d.is_leader)(instance, msg.round(), process) {
                return (UPON_NOTHING, None);
            }

            (UPON_QUORUM_ROUND_CHANGES, Some(qrc))
        }
        _ => {
            panic!("bug: invalid type");
        }
    }
}

/// Implements algorithm 3:6 and returns the next minimum round from received
/// round change messages.
fn next_min_round<I, V, C>(d: &Definition<I, V, C>, frc: &Vec<Msg<I, V, C>>, round: i64) -> i64
where
    V: PartialEq,
{
    // Get all RoundChange messages with round (rj) higher than current round (ri)
    if (frc.len() as i64) < d.faulty() + 1 {
        panic!("bug: Frc too short");
    }

    // Get the smallest round in the set.
    let mut rmin = i64::MAX;

    for msg in frc {
        if msg.type_() != MSG_ROUND_CHANGE {
            panic!("bug: Frc contain non-round change");
        } else if msg.round() <= round {
            panic!("bug: Frc round not in future");
        }

        if rmin > msg.round() {
            rmin = msg.round();
        }
    }

    rmin
}

/// Returns true if message is justified or if it does not need justification.
fn is_justified<I, V, C>(
    d: &Definition<I, V, C>,
    instance: &I,
    msg: &Msg<I, V, C>,
    compare_failure_round: i64,
) -> bool
where
    V: Eq + Hash + Default,
{
    match msg.type_() {
        MSG_PRE_PREPARE => is_justified_pre_prepare(d, instance, msg, compare_failure_round),
        MSG_PREPARE => true,
        MSG_COMMIT => true,
        MSG_ROUND_CHANGE => is_justified_round_change(d, msg),
        MSG_DECIDED => is_justified_decided(d, msg),
        _ => panic!("bug: invalid message type"),
    }
}

/// Returns true if the ROUND_CHANGE message's prepared round and value is
/// justified.
fn is_justified_round_change<I, V, C>(d: &Definition<I, V, C>, msg: &Msg<I, V, C>) -> bool
where
    V: PartialEq + Default,
{
    if msg.type_() != MSG_ROUND_CHANGE {
        panic!("bug: not a round change message");
    }

    // ROUND-CHANGE justification contains quorum PREPARE messages that justifies Pr
    // and Pv.
    let prepares = msg.justification();
    let pr = msg.prepared_round();
    let pv = msg.prepared_value();

    if prepares.is_empty() {
        return pr == 0 && pv == Default::default();
    }

    // No need to check for all possible combinations, since justified should only
    // contain a one.

    if (prepares.len() as i64) < d.quorum() {
        return false;
    }

    let mut uniq = uniq_source::<I, V, C>(vec![]);
    for prepare in prepares {
        if !uniq(&prepare) {
            return false;
        }

        if prepare.type_() != MSG_PREPARE {
            return false;
        }

        if prepare.round() != pr {
            return false;
        }

        if prepare.value() != pv {
            return false;
        }
    }

    true
}

/// Returns true if the decided message is justified by quorum COMMIT messages
/// of identical round and value.
fn is_justified_decided<I, V, C>(d: &Definition<I, V, C>, msg: &Msg<I, V, C>) -> bool
where
    V: PartialEq,
{
    if msg.type_() != MSG_DECIDED {
        panic!("bug: not a decided message");
    }

    let v = msg.value();
    let commits = filter_msgs(
        &msg.justification(),
        MSG_COMMIT,
        msg.round(),
        Some(&v),
        None,
        None,
    );

    (commits.len() as i64) >= d.quorum()
}

/// Returns true if the PRE-PREPARE message is justified.
fn is_justified_pre_prepare<I, V, C>(
    d: &Definition<I, V, C>,
    instance: &I,
    msg: &Msg<I, V, C>,
    compare_failure_round: i64,
) -> bool
where
    V: Eq + Hash + Default,
{
    if msg.type_() != MSG_PRE_PREPARE {
        panic!("bug: not a preprepare message");
    }

    if !(d.is_leader)(instance, msg.round(), msg.source()) {
        return false;
    }

    // Justified if PrePrepare is the first round OR if comparison failed previous
    // round.
    if msg.round() == 1 || (msg.round() == compare_failure_round + 1) {
        return true;
    }

    let Some(pv) = contains_justified_qrc(d, &msg.justification(), msg.round()) else {
        return false;
    };

    if pv == Default::default() {
        return true; // New value being proposed
    }

    msg.value() == pv // Ensure Pv is being proposed
}

/// Implements algorithm 4:1 and returns true and pv if the messages contains a
/// justified quorum ROUND_CHANGEs (Qrc).
fn contains_justified_qrc<I, V, C>(
    d: &Definition<I, V, C>,
    justification: &Vec<Msg<I, V, C>>,
    round: i64,
) -> Option<V>
where
    V: Eq + Hash + Default,
{
    let qrc = filter_round_change(justification, round);
    if (qrc.len() as i64) < d.quorum() {
        return None;
    }
    // No need to calculate J1 or J2 for all possible combinations,
    // since justification should only contain one.

    // J1: If qrc contains quorum ROUND-CHANGEs with null pv and null pr.
    let mut all_null = true;

    for rc in qrc.iter() {
        if rc.prepared_round() != 0 || rc.prepared_value() != Default::default() {
            all_null = false;
            break;
        }
    }

    if all_null {
        return Some(Default::default());
    }

    // J2: if the justification has a quorum of valid PREPARE messages
    // with pr and pv equaled to highest pr and pv in Qrc (other than null).

    // Get pr and pv from quorum PREPARES
    let (pr, pv) = get_single_justified_pr_pv(d, justification)?;

    let mut found = false;

    for rc in qrc {
        // Ensure no ROUND-CHANGE with higher pr
        if rc.prepared_round() > pr {
            return None;
        }
        // Ensure at least one ROUND-CHANGE with pr and pv
        if rc.prepared_round() == pr && rc.prepared_value() == pv {
            found = true;
        }
    }

    if found { Some(pv) } else { None }
}

/// Extracts the single justified Pr and Pv from quorum PREPARES in list of
/// messages. It expects only one possible combination.
fn get_single_justified_pr_pv<I, V, C>(
    d: &Definition<I, V, C>,
    msgs: &Vec<Msg<I, V, C>>,
) -> Option<(i64, V)>
where
    V: Eq + Hash + Default,
{
    let mut pr: i64 = 0;
    let mut pv: V = Default::default();
    let mut count: i64 = 0;
    let mut uniq = uniq_source::<I, V, C>(vec![]);

    for msg in msgs {
        if msg.type_() != MSG_PREPARE {
            continue;
        }

        if !uniq(msg) {
            return None;
        }

        if count == 0 {
            pr = msg.round();
            pv = msg.value();
        } else if pr != msg.round() || pv != msg.value() {
            return None;
        }

        count += 1;
    }

    if count >= d.quorum() {
        Some((pr, pv))
    } else {
        None
    }
}

/// Implements algorithm 4:1 and returns a justified quorum ROUND_CHANGEs (Qrc)
fn get_justified_qrc<I, V, C>(
    d: &Definition<I, V, C>,
    all: &Vec<Msg<I, V, C>>,
    round: i64,
) -> Option<Vec<Msg<I, V, C>>>
where
    V: Eq + Hash + Default,
{
    if let (qrc, true) = quorum_null_prepared(d, all, round) {
        // Return any quorum null pv ROUND_CHANGE messages as Qrc.
        return Some(qrc);
    }

    let round_changes = filter_round_change(all, round);

    for prepares in get_prepare_quorums(d, all) {
        // See if we have quorum ROUND-CHANGE with HIGHEST_PREPARED(qrc) ==
        // prepares.Round.
        let mut qrc: Vec<Msg<I, V, C>> = vec![];
        let mut has_highest_prepared = false;
        let pr = prepares[0].round();
        let pv = prepares[0].value();
        let mut uniq = uniq_source::<I, V, C>(vec![]);

        for rc in round_changes.iter() {
            if rc.prepared_round() > pr {
                continue;
            }

            if !uniq(rc) {
                continue;
            }

            if rc.prepared_round() == pr && rc.prepared_value() == pv {
                has_highest_prepared = true;
            }

            qrc.push(rc.clone());
        }

        if (qrc.len() as i64) >= d.quorum() && has_highest_prepared {
            qrc.extend(prepares.into_iter());
            return Some(qrc);
        }
    }

    None
}

/// Returns true and Faulty+1 ROUND-CHANGE messages (Frc) with the rounds higher
/// than the provided round. It returns the highest round per process in order
/// to jump furthest.
fn get_fplus1_round_changes<I, V, C>(
    d: &Definition<I, V, C>,
    all: &Vec<Msg<I, V, C>>,
    round: i64,
) -> Option<Vec<Msg<I, V, C>>>
where
    V: PartialEq,
{
    let mut highest_by_source = HashMap::<i64, Msg<I, V, C>>::new();

    for msg in all {
        if msg.type_() != MSG_ROUND_CHANGE {
            continue;
        }

        if msg.round() <= round {
            continue;
        }

        if let Some(highest) = highest_by_source.get(&msg.source()) {
            if highest.round() > msg.round() {
                continue;
            }
        }

        highest_by_source.insert(msg.source(), msg.clone());

        if (highest_by_source.len() as i64) == d.faulty() + 1 {
            break;
        }
    }

    if (highest_by_source.len() as i64) < d.faulty() + 1 {
        return None;
    }

    let resp = highest_by_source.into_values().collect::<Vec<_>>();

    Some(resp)
}

/// Defines the round and value of set of identical PREPARE messages.
#[derive(Eq, Hash, PartialEq)]
struct PreparedKey<V>
where
    V: Eq + Hash,
{
    round: i64,
    value: V,
}

fn get_prepare_quorums<I, V, C>(
    d: &Definition<I, V, C>,
    all: &Vec<Msg<I, V, C>>,
) -> Vec<Vec<Msg<I, V, C>>>
where
    V: Eq + Hash,
{
    let mut sets = HashMap::<PreparedKey<V>, HashMap<i64, Msg<I, V, C>>>::new();

    for msg in all {
        if msg.type_() != MSG_PREPARE {
            continue;
        }

        let key = PreparedKey {
            round: msg.round(),
            value: msg.value(),
        };

        sets.entry(key)
            .or_default()
            .insert(msg.source(), msg.clone());
    }

    let mut quorums = vec![];

    for (_, msgs) in sets {
        if (msgs.len() as i64) < d.quorum() {
            continue;
        }

        let mut quorum = vec![];
        for (_, msg) in msgs {
            quorum.push(msg);
        }

        quorums.push(quorum);
    }

    quorums
}

/// Implements condition J1 and returns Qrc and true if a quorum
/// of round changes messages (Qrc) for the round have null prepared round and
/// value.
fn quorum_null_prepared<I, V, C>(
    d: &Definition<I, V, C>,
    all: &Vec<Msg<I, V, C>>,
    round: i64,
) -> (Vec<Msg<I, V, C>>, bool)
where
    V: PartialEq + Default,
{
    let null_pr = Default::default();
    let null_pv = Some(&Default::default());

    let justification = filter_msgs(all, MSG_ROUND_CHANGE, round, None, Some(null_pr), null_pv);

    (
        justification.clone(),
        justification.len() as i64 >= d.quorum(),
    )
}

/// Returns the messages matching the type and value.
fn filter_by_round_and_value<I, V, C>(
    msgs: &Vec<Msg<I, V, C>>,
    message_type: MessageType,
    round: i64,
    value: V,
) -> Vec<Msg<I, V, C>>
where
    V: PartialEq,
{
    filter_msgs(msgs, message_type, round, Some(&value), None, None)
}

/// Returns all round change messages for the provided round.
fn filter_round_change<I, V, C>(msgs: &Vec<Msg<I, V, C>>, round: i64) -> Vec<Msg<I, V, C>>
where
    V: PartialEq,
{
    filter_msgs::<I, V, C>(msgs, MSG_ROUND_CHANGE, round, None, None, None)
}

/// Returns one message per process matching the provided type and round and
/// optional value, pr, pv.
fn filter_msgs<I, V, C>(
    msgs: &Vec<Msg<I, V, C>>,
    message_type: MessageType,
    round: i64,
    value: Option<&V>,
    pr: Option<i64>,
    pv: Option<&V>,
) -> Vec<Msg<I, V, C>>
where
    V: PartialEq,
{
    let mut resp = Vec::new();
    let mut uniq = uniq_source::<I, V, C>(vec![]);

    for msg in msgs {
        if message_type != msg.type_() {
            continue;
        }

        if round != msg.round() {
            continue;
        }

        if let Some(value) = value
            && msg.value() != *value
        {
            continue;
        }

        if let Some(pv) = pv
            && msg.prepared_value() != *pv
        {
            continue;
        }

        if let Some(pr) = pr
            && pr != msg.prepared_round()
        {
            continue;
        }

        if uniq(msg) {
            resp.push(msg.clone());
        }
    }

    resp
}

/// Produce a vector containing all the buffered messages as well as all their
/// justifications.
fn flatten<I, V, C>(buffer: &HashMap<i64, Vec<Msg<I, V, C>>>) -> Vec<Msg<I, V, C>>
where
    V: PartialEq,
{
    let mut resp: Vec<Msg<I, V, C>> = Vec::new();

    for msgs in buffer.values() {
        for msg in msgs {
            resp.push(msg.clone());
            for j in msg.justification() {
                resp.push(j.clone());
                if !j.justification().is_empty() {
                    panic!("bug: nested justifications");
                }
            }
        }
    }

    resp
}

/// Construct a function that returns true if the message is from a unique
/// source.
fn uniq_source<I, V, C>(vec: Vec<Msg<I, V, C>>) -> Box<impl FnMut(&Msg<I, V, C>) -> bool>
where
    V: PartialEq,
{
    let mut s = vec.iter().map(|msg| msg.source()).collect::<HashSet<_>>();
    Box::new(move |msg: &Msg<I, V, C>| {
        let source = msg.source();
        if s.contains(&source) {
            false
        } else {
            s.insert(source);
            true
        }
    })
}

#[cfg(test)]
mod internal_test;
