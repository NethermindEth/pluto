//! Package `qbft` is an implementation of ["The Istanbul BFT Consensus Algorithm"](https://arxiv.org/pdf/2002.03613.pdf) by Henrique Moniz
//! as referenced by the [QBFT spec](https://github.com/ConsenSys/qbft-formal-spec-and-verification).
//!
//! ## Features
//!
//! - Simple API, just a single function: `qbft::run`.
//! - Consensus on arbitrary data.
//! - Transport abstracted and not provided.
//! - Decoupled from process authentication and message signing (not provided).
//! - No domain-specific dependencies.
//! - Explicit justifications.

use cancellation::{CancellationToken, CancellationTokenSource};
use crossbeam::channel as mpmc;
use std::{
    any,
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet},
    fmt::{self, Display},
    hash::Hash,
    sync, thread, time,
};

mod callbacks;
use callbacks::{
    BroadcastFn, CompareFn, DecideFn, LeaderFn, RoundChangeLoggerFn, UnjustLoggerFn,
    UponRuleLoggerFn,
};
pub use callbacks::{
    BroadcastRequest, CompareRequest, DecideRequest, LeaderRequest, RoundChangeLog, Timer,
    UnjustLog, UponRuleLog,
};

type Result<T> = std::result::Result<T, QbftError>;

// The `cancellation` crate is callback-based, not channel-based, so it cannot
// be used directly in `crossbeam::select!`. Keep polling coarse: QBFT shutdown
// does not need sub-millisecond latency, and idle instances should stay cheap.
const CANCELLATION_POLL_INTERVAL: time::Duration = time::Duration::from_millis(50);

/// Associated types used by a QBFT instance.
pub trait QbftTypes: 'static {
    /// Consensus instance identifier.
    type Instance: Send + Sync + 'static;
    /// Consensus value.
    type Value: Eq + Hash + Default + 'static;
    /// Application value used by the compare callback.
    type Compare: Clone + Send + Sync + Default + 'static;
}

/// Errors returned by the QBFT core.
#[derive(Debug, thiserror::Error)]
pub enum QbftError {
    /// Round timer expired before compare completed.
    #[error("Timeout")]
    TimeoutError,

    /// Leader proposal failed application-level comparison.
    #[error("Compare leader value with local value failed")]
    CompareError,

    /// Compare returned an error variant that core does not expect.
    #[error("bug: expected only comparison or timeout error, got {0}")]
    UnexpectedCompareError(Box<QbftError>),

    /// Parent cancellation token was canceled.
    #[error("context canceled")]
    ContextCanceled,

    /// Test or caller configured maximum round was reached.
    #[error("Maximum round reached")]
    MaxRoundReached,

    /// Own input value was the null/default value.
    #[error("Zero input value not supported")]
    ZeroInputValue,

    /// Message value source was missing.
    #[error("value not found")]
    ValueNotFound,

    /// Node count must be positive.
    #[error("invalid node count: must be greater than zero, got {nodes}")]
    InvalidNodes {
        /// Configured node count.
        nodes: i64,
    },

    /// Per-source FIFO limit must be positive.
    #[error("invalid FIFO limit: must be greater than zero, got {fifo_limit}")]
    InvalidFifoLimit {
        /// Configured FIFO limit.
        fifo_limit: i64,
    },

    /// Receive channel closed unexpectedly.
    #[error("Failed to read from channel: {0}")]
    ChannelError(#[from] mpmc::RecvError),
}

/// Abstracts the transport layer between processes in the consensus system.
pub struct Transport<T: QbftTypes> {
    /// Broadcast sends a message with the provided fields to all other
    /// processes in the system (including this process).
    ///
    /// Note that an error exits the algorithm.
    pub broadcast: Box<BroadcastFn<T>>,

    /// Receive returns a stream of messages received
    /// from other processes in the system (including this process).
    pub receive: mpmc::Receiver<Msg<T>>,
}

/// Debug hooks for QBFT state transitions and rejected messages.
pub struct QbftLogger<T: QbftTypes> {
    /// Called when an upon-rule fires.
    pub upon_rule: Box<UponRuleLoggerFn<T>>,
    /// Called when the local process changes round.
    pub round_change: Box<RoundChangeLoggerFn<T>>,
    /// Called when an unjustified message is rejected.
    pub unjust: Box<UnjustLoggerFn<T>>,
}

/// Defines the consensus system parameters that are external to the qbft
/// algorithm. This remains constant across multiple instances of consensus
/// (calls to `run`).
pub struct Definition<T: QbftTypes> {
    /// A deterministic leader election function.
    pub is_leader: Box<LeaderFn<T>>,

    /// Returns a new timer channel and stop function for the round
    pub new_timer: Box<dyn Fn(i64) -> Timer + Send + Sync>,

    /// Charon parity hook called when the leader proposes a value. The core
    /// algorithm only runs this callback and reacts to its result; any
    /// value-source comparison policy belongs to the caller.
    pub compare: sync::Arc<CompareFn<T>>,

    /// Called when consensus has been reached on a value.
    pub decide: Box<DecideFn<T>>,

    /// Debug logging callbacks.
    pub logger: QbftLogger<T>,

    /// Total number of nodes/processes participating in consensus.
    pub nodes: i64,

    /// Limits the amount of message buffered for each peer.
    pub fifo_limit: i64,
}

impl<T: QbftTypes> Definition<T> {
    /// Quorum count for the system.
    /// See IBFT 2.0 paper for correct formula: <https://arxiv.org/pdf/1909.10194.pdf>
    pub fn quorum(&self) -> i64 {
        self.nodes
            .checked_mul(2)
            .and_then(|nodes| nodes.checked_add(2))
            .and_then(|nodes| nodes.checked_div(3))
            .expect("node count permits quorum calculation")
    }

    /// Maximum number of faulty/byzantine nodes supported in the system.
    /// See IBFT 2.0 paper for correct formula: <https://arxiv.org/pdf/1909.10194.pdf>
    pub fn faulty(&self) -> i64 {
        self.nodes
            .checked_sub(1)
            .and_then(|nodes| nodes.checked_div(3))
            .expect("node count permits faulty-node calculation")
    }

    fn quorum_count(&self) -> usize {
        usize::try_from(self.quorum()).expect("quorum fits usize")
    }

    fn faulty_plus_one_count(&self) -> usize {
        let threshold = self
            .faulty()
            .checked_add(1)
            .expect("faulty-node count permits threshold calculation");
        usize::try_from(threshold).expect("faulty-node threshold fits usize")
    }
}

/// Defines the QBFT message types
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct MessageType(i64);

// NOTE: message type ordering MUST not change, since it breaks backwards
// compatibility.
/// Unknown message type.
pub const MSG_UNKNOWN: MessageType = MessageType(0);
/// PRE-PREPARE message type.
pub const MSG_PRE_PREPARE: MessageType = MessageType(1);
/// PREPARE message type.
pub const MSG_PREPARE: MessageType = MessageType(2);
/// COMMIT message type.
pub const MSG_COMMIT: MessageType = MessageType(3);
/// ROUND-CHANGE message type.
pub const MSG_ROUND_CHANGE: MessageType = MessageType(4);
/// DECIDED catch-up message type.
pub const MSG_DECIDED: MessageType = MessageType(5);

const MSG_SENTINEL: MessageType = MessageType(6); // intentionally not public

impl MessageType {
    /// Converts a stable wire integer into a message type without clamping.
    pub fn from_wire(value: i64) -> Self {
        Self(value)
    }

    /// Returns true when the message type is one of the known QBFT wire types.
    pub fn valid(&self) -> bool {
        self.0 > MSG_UNKNOWN.0 && self.0 < MSG_SENTINEL.0
    }
}

impl Display for MessageType {
    /// Formats the message type using the stable wire/debug label.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self.0 {
            0 => "unknown",
            1 => "pre_prepare",
            2 => "prepare",
            3 => "commit",
            4 => "round_change",
            5 => "decided",
            _ => "",
        };
        write!(f, "{s}")
    }
}

/// Defines the inter process messages.
pub trait SomeMsg<T: QbftTypes>: Send + Sync + fmt::Debug {
    /// Type of the message.
    fn type_(&self) -> MessageType;
    /// Consensus instance.
    fn instance(&self) -> T::Instance;
    /// Process that sent the message.
    fn source(&self) -> i64;
    /// The round the message pertains to.
    fn round(&self) -> i64;
    /// The value being proposed, usually a hash.
    fn value(&self) -> T::Value;
    /// Usually the value that was hashed and is returned in `value`.
    fn value_source(&self) -> Result<T::Compare>;
    /// The justified prepared round.
    fn prepared_round(&self) -> i64;
    /// The justified prepared value.
    fn prepared_value(&self) -> T::Value;
    /// Set of messages that explicitly justifies this message.
    fn justification(&self) -> Vec<Msg<T>>;

    /// Cast as `Any` to allow downcasting.
    fn as_any(&self) -> &dyn any::Any;
}

/// Alias for any `Msg` implementation tracked by reference counting.
pub type Msg<T> = sync::Arc<dyn SomeMsg<T>>;

/// Defines the event based rules that are triggered when messages are received.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct UponRule(i64);

/// No upon-rule fired.
pub const UPON_NOTHING: UponRule = UponRule(0);
/// PRE-PREPARE was justified.
pub const UPON_JUSTIFIED_PRE_PREPARE: UponRule = UponRule(1);
/// Quorum PREPARE messages was received.
pub const UPON_QUORUM_PREPARES: UponRule = UponRule(2);
/// Quorum COMMIT messages was received.
pub const UPON_QUORUM_COMMITS: UponRule = UponRule(3);
/// Quorum ROUND-CHANGE messages was received but not justified.
pub const UPON_UNJUST_QUORUM_ROUND_CHANGES: UponRule = UponRule(4);
/// F+1 future ROUND-CHANGE messages was received.
pub const UPON_F_PLUS1_ROUND_CHANGES: UponRule = UponRule(5);
/// Quorum ROUND-CHANGE messages was received.
pub const UPON_QUORUM_ROUND_CHANGES: UponRule = UponRule(6);
/// DECIDED message was justified.
pub const UPON_JUSTIFIED_DECIDED: UponRule = UponRule(7);
/// Round timer expired.
pub const UPON_ROUND_TIMEOUT: UponRule = UponRule(8); // This is not triggered by a message, but by a timer.

impl Display for UponRule {
    /// Formats the upon-rule using the stable debug label.
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
            _ => "",
        };
        write!(f, "{s}")
    }
}

/// Defines the key used to deduplicate upon rules.
#[derive(Eq, Hash, PartialEq)]
struct DedupKey {
    upon_rule: UponRule,
    round: i64,
}

/// Executes one QBFT consensus instance until it errors or is cancelled.
///
/// Decisions are reported via `Definition::decide`. After deciding, `run`
/// remains active so it can answer later `ROUND_CHANGE` messages with `DECIDED`
/// catch-up messages.
///
/// `T::Instance` identifies the consensus instance, `T::Value` is the
/// comparable proposed value, and `T::Compare` is the application value used by
/// `Definition::compare` to compare a leader proposal with the local input
/// source.
pub fn run<T: QbftTypes>(
    ct: &CancellationToken,
    d: &Definition<T>,
    t: &Transport<T>,
    instance: &T::Instance,
    process: i64,
    mut input_value_ch: mpmc::Receiver<T::Value>,
    input_value_source_ch: mpmc::Receiver<T::Compare>,
) -> Result<()> {
    validate_definition(d)?;
    let fifo_limit = usize::try_from(d.fifo_limit).expect("validated FIFO limit fits usize");

    // === State ===
    let round: Cell<i64> = Cell::new(1);
    let input_value: RefCell<T::Value> = RefCell::new(Default::default());
    let mut input_value_source: T::Compare = Default::default();
    let ppj_cache: RefCell<Option<Vec<Msg<T>>>> = RefCell::new(None); // Cached pre-prepare justification for the current round (`None` value is unset).
    let prepared_round: Cell<i64> = Cell::new(0);
    let prepared_value: RefCell<T::Value> = RefCell::new(Default::default());
    let mut compare_failure_round: i64 = 0;
    let prepared_justification: RefCell<Option<Vec<Msg<T>>>> = RefCell::new(None);
    let mut q_commit: Option<Vec<Msg<T>>> = None;
    let buffer: RefCell<HashMap<i64, Vec<Msg<T>>>> = RefCell::new(HashMap::new());
    let dedup_rules: RefCell<HashSet<DedupKey>> = RefCell::new(HashSet::new());
    let mut timer_chan: mpmc::Receiver<time::Instant>;
    let mut stop_timer: Box<dyn Fn() + Send + Sync>;

    // === Helpers ==

    // Broadcasts a non-ROUND-CHANGE message for current round.
    let broadcast_msg =
        |type_: MessageType, value: &T::Value, justification: Option<&Vec<Msg<T>>>| {
            let default_value = T::Value::default();
            (t.broadcast)(BroadcastRequest {
                ct,
                type_,
                instance,
                source: process,
                round: round.get(),
                value,
                prepared_round: 0,
                prepared_value: &default_value,
                justification,
            })
        };
    // Broadcasts a ROUND-CHANGE message with current state.
    let broadcast_round_change = || {
        let default_value = T::Value::default();
        (t.broadcast)(BroadcastRequest {
            ct,
            type_: MSG_ROUND_CHANGE,
            instance,
            source: process,
            round: round.get(),
            value: &default_value,
            prepared_round: prepared_round.get(),
            prepared_value: &prepared_value.borrow(),
            justification: prepared_justification.borrow().as_ref(),
        })
    };

    // Broadcasts a PRE-PREPARE message with current state
    // and our own input value if present, otherwise it caches the justification
    // to be used when the input value becomes available.
    let broadcast_own_pre_prepare = |justification: Vec<Msg<T>>| {
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
    let buffer_msg = |msg: &Msg<T>| {
        let mut b = buffer.borrow_mut();
        let fifo = b.entry(msg.source()).or_default();

        fifo.push(msg.clone());
        if fifo.len() > fifo_limit {
            let expired = fifo
                .len()
                .checked_sub(fifo_limit)
                .expect("FIFO length exceeds limit");
            fifo.drain(0..expired);
        }
    };

    // Returns true if the rule has been already executed since last round
    // change.
    let is_duplicated_rule = |upon_rule: UponRule, round: i64| {
        let k = DedupKey { upon_rule, round };
        !dedup_rules.borrow_mut().insert(k)
    };

    // Updates round and clears the rule dedup state.
    let change_round = |new_round: i64, rule: UponRule| {
        if round.get() == new_round {
            return;
        }

        (d.logger.round_change)(RoundChangeLog {
            instance,
            process,
            round: round.get(),
            new_round,
            upon_rule: rule,
            msgs: &extract_round_messages(&buffer.borrow(), round.get()),
        });

        round.set(new_round);
        dedup_rules.replace(HashSet::new());
        ppj_cache.replace(None);
    };

    // Algorithm 1:11
    {
        if (d.is_leader)(LeaderRequest {
            instance,
            round: round.get(),
            process,
        }) {
            // Note round==1 at this point.
            broadcast_own_pre_prepare(vec![])?; // Empty justification since round==1
        }

        let timer = (d.new_timer)(round.get());
        timer_chan = timer.receive;
        stop_timer = timer.stop;
    }

    loop {
        if ct.is_canceled() {
            return Err(QbftError::ContextCanceled);
        }

        mpmc::select! {
            recv(input_value_ch) -> result => {
                let iv = result?;
                input_value.replace(iv);

                if *input_value.borrow() == Default::default() {
                    return Err(QbftError::ZeroInputValue);
                }

                if let Some(ppj) = ppj_cache.borrow().as_ref() {
                    // Broadcast the pre-prepare now that we have a input value using the cached
                    // justification.
                    broadcast_msg(MSG_PRE_PREPARE, &input_value.borrow(), Some(ppj))?;
                }

                // Don't read from this channel again.
                input_value_ch = mpmc::never();
            },

            recv(t.receive) -> result => {
                let msg = result?;
                if let Some(v) = q_commit.as_ref()
                    && !v.is_empty()
                {
                    if msg.source() != process && msg.type_() == MSG_ROUND_CHANGE {
                        // Algorithm 3:17
                        broadcast_msg(MSG_DECIDED, &v[0].value(), Some(v))?;
                    }

                    continue;
                }

                // Drop unjust messages
                if !is_justified(d, instance, &msg, compare_failure_round) {
                    (d.logger.unjust)(UnjustLog {
                        instance,
                        process,
                        msg,
                    });
                    continue;
                }

                buffer_msg(&msg);

                let (rule, justification) =
                    classify(d, instance, round.get(), process, &buffer.borrow(), &msg);
                if rule == UPON_NOTHING || is_duplicated_rule(rule, msg.round()) {
                    // Do nothing more if no rule or duplicate rule was triggered
                    continue;
                }

                (d.logger.upon_rule)(UponRuleLog {
                    instance,
                    process,
                    round: round.get(),
                    msg: &msg,
                    upon_rule: rule,
                });

                match rule {
                    // Algorithm 2:1
                    UPON_JUSTIFIED_PRE_PREPARE => {
                        change_round(msg.round(), rule);

                        stop_timer();
                        let timer = (d.new_timer)(round.get());
                        timer_chan = timer.receive;
                        stop_timer = timer.stop;

                        let (new_input_value_source, compare_result) = compare(
                            ct,
                            d,
                            &msg,
                            &input_value_source_ch,
                            input_value_source.clone(),
                            &timer_chan,
                        );
                        input_value_source = new_input_value_source;

                        match compare_result {
                            Ok(()) => broadcast_msg(MSG_PREPARE, &msg.value(), None)?,
                            Err(qbft_err) => {
                                match qbft_err {
                                    QbftError::CompareError => {
                                        compare_failure_round = msg.round();
                                    }
                                    QbftError::TimeoutError => {
                                        // As compare function is blocking on waiting local data, round
                                        // might timeout in the meantime. If
                                        // this happens, we trigger round change.
                                        // Algorithm 3:1
                                        let next_round = round
                                            .get()
                                            .checked_add(1)
                                            .expect("round permits increment");
                                        change_round(next_round, UPON_ROUND_TIMEOUT);
                                        stop_timer();

                                        let timer = (d.new_timer)(round.get());
                                        timer_chan = timer.receive;
                                        stop_timer = timer.stop;

                                        broadcast_round_change()?;
                                    }
                                    QbftError::ContextCanceled => return Err(QbftError::ContextCanceled),
                                    _ => {
                                        return Err(QbftError::UnexpectedCompareError(Box::new(
                                            qbft_err,
                                        )));
                                    }
                                }
                            }
                        }
                    }
                    UPON_QUORUM_PREPARES => {
                        // Algorithm 2:4
                        // Only applicable to current round
                        prepared_round.set(round.get()); /* == msg.round() */
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
                        (d.decide)(DecideRequest {
                            ct,
                            instance,
                            value: &msg.value(),
                            qcommit: justification,
                        });
                    }
                    UPON_F_PLUS1_ROUND_CHANGES => {
                        // Algorithm 3:5

                        let justification = justification.expect(
                            "Rule `UPON_F_PLUS1_ROUND_CHANGES` always includes a justification",
                        );

                        // Only applicable to future rounds
                        change_round(
                            next_min_round(d, &justification, round.get() /* < msg.round() */),
                            rule,
                        );

                        stop_timer();
                        let timer = (d.new_timer)(round.get());
                        timer_chan = timer.receive;
                        stop_timer = timer.stop;

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

                let next_round = round
                    .get()
                    .checked_add(1)
                    .expect("round permits increment");
                change_round(next_round, UPON_ROUND_TIMEOUT);
                stop_timer();

                let timer = (d.new_timer)(round.get());
                timer_chan = timer.receive;
                stop_timer = timer.stop;

                broadcast_round_change()?;
            }

            default(CANCELLATION_POLL_INTERVAL) => {
                if ct.is_canceled() {
                    return Err(QbftError::ContextCanceled);
                }
            }
        }
    }
}

fn validate_definition<T: QbftTypes>(d: &Definition<T>) -> Result<()> {
    if d.nodes <= 0 {
        return Err(QbftError::InvalidNodes { nodes: d.nodes });
    }

    if d.fifo_limit <= 0 {
        return Err(QbftError::InvalidFifoLimit {
            fifo_limit: d.fifo_limit,
        });
    }

    Ok(())
}

/// The callback may cache the local input source and return success/failure.
/// This helper only preserves that callback result and lets the round timer win
/// if the callback blocks.
fn compare<T: QbftTypes>(
    ct: &CancellationToken,
    d: &Definition<T>,
    msg: &Msg<T>,
    input_value_source_ch: &mpmc::Receiver<T::Compare>,
    input_value_source: T::Compare,
    timer_chan: &mpmc::Receiver<time::Instant>,
) -> (T::Compare, Result<()>) {
    let (compare_err_tx, mut compare_err_rx) = mpmc::bounded::<Result<()>>(1);
    let (compare_value_tx, mut compare_value_rx) = mpmc::bounded::<T::Compare>(1);

    // d.Compare has 2 roles:
    // 1. Read from the `input_value_source_ch` (if `input_value_source` is empty).
    //    If it read from the channel, it returns the value on `compare_value`
    //    channel.
    // 2. Compare the value read from `input_value_source_ch` (or
    //    `input_value_source` if it is not empty) to the value proposed by the
    //    leader.
    // If comparison or any other unexpected error occurs, the error is returned on
    // `compare_err` channel.

    let mut result = input_value_source.clone();
    let compare = d.compare.clone();
    let compare_cts = sync::Arc::new(CancellationTokenSource::new());
    let compare_ct = compare_cts.token().clone();
    let msg = msg.clone();
    let input_value_source_ch = input_value_source_ch.clone();

    // Detached by design, matching Charon's goroutine behavior: if a
    // caller-provided compare callback ignores cancellation and never reports,
    // it may outlive this call.
    thread::spawn(move || {
        (compare)(CompareRequest {
            ct: &compare_ct,
            qcommit: &msg,
            input_value_source_ch: &input_value_source_ch,
            input_value_source: &input_value_source,
            return_err: &compare_err_tx,
            return_value: &compare_value_tx,
        });
    });

    loop {
        if ct.is_canceled() {
            compare_cts.cancel();
            return (result, Err(QbftError::ContextCanceled));
        }

        mpmc::select! {
            recv(compare_err_rx) -> msg => {
                let err = match msg {
                    Ok(err) => err,
                    Err(_) => {
                        compare_err_rx = mpmc::never();
                        continue;
                    }
                };

                while let Ok(value) = compare_value_rx.try_recv() {
                    result = value;
                }

                compare_cts.cancel();
                if ct.is_canceled() {
                    return (result, Err(QbftError::ContextCanceled));
                }

                return match err {
                    Ok(()) => (result, Ok(())),
                    Err(_) => (result, Err(QbftError::CompareError)),
                };
            },

            recv(compare_value_rx) -> msg => {
                match msg {
                    Ok(value) => result = value,
                    Err(_) => compare_value_rx = mpmc::never(),
                }
            },

            recv(timer_chan) -> msg => {
                compare_cts.cancel();
                if let Err(err) = msg {
                    return (result, Err(QbftError::ChannelError(err)));
                }

                return (result, Err(QbftError::TimeoutError));
            }

            default(CANCELLATION_POLL_INTERVAL) => {
                if ct.is_canceled() {
                    compare_cts.cancel();
                    return (result, Err(QbftError::ContextCanceled));
                }
            }
        }
    }
}

/// Returns all messages from the provided round.
fn extract_round_messages<T: QbftTypes>(
    buffer: &HashMap<i64, Vec<Msg<T>>>,
    round: i64,
) -> Vec<Msg<T>> {
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
fn classify<T: QbftTypes>(
    d: &Definition<T>,
    instance: &T::Instance,
    round: i64,
    process: i64,
    buffer: &HashMap<i64, Vec<Msg<T>>>,
    msg: &Msg<T>,
) -> (UponRule, Option<Vec<Msg<T>>>) {
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

            if prepares.len() >= d.quorum_count() {
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
            if commits.len() >= d.quorum_count() {
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

            /* else msg.round() == round */

            let qrc = filter_round_change(&all, msg.round());
            if qrc.len() < d.quorum_count() {
                return (UPON_NOTHING, None);
            }

            let Some(qrc) = get_justified_qrc(d, &all, msg.round()) else {
                return (UPON_UNJUST_QUORUM_ROUND_CHANGES, None);
            };

            if !(d.is_leader)(LeaderRequest {
                instance,
                round: msg.round(),
                process,
            }) {
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
fn next_min_round<T: QbftTypes>(d: &Definition<T>, frc: &Vec<Msg<T>>, round: i64) -> i64 {
    // Get all RoundChange messages with round (rj) higher than current round (ri)
    if frc.len() < d.faulty_plus_one_count() {
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
fn is_justified<T: QbftTypes>(
    d: &Definition<T>,
    instance: &T::Instance,
    msg: &Msg<T>,
    compare_failure_round: i64,
) -> bool {
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
fn is_justified_round_change<T: QbftTypes>(d: &Definition<T>, msg: &Msg<T>) -> bool {
    if msg.type_() != MSG_ROUND_CHANGE {
        panic!("bug: not a round change message");
    }

    // ROUND-CHANGE justification contains quorum PREPARE messages that justifies Pr
    // and Pv.
    let prepares = msg.justification();
    let pr = msg.prepared_round();
    let pv = msg.prepared_value();

    // The IBFT paper requires ROUND-CHANGE prepared_round to be lower than the
    // target round. Go core currently omits this check, but valid Charon traffic
    // already satisfies it.
    if !valid_round_change_prepared_round(msg) {
        return false;
    }

    if prepares.is_empty() {
        return pr == 0 && pv == Default::default();
    }

    // No need to check for all possible combinations, since justified should only
    // contain a one.

    if prepares.len() < d.quorum_count() {
        return false;
    }

    let mut uniq = uniq_source();
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

fn valid_round_change_prepared_round<T: QbftTypes>(msg: &Msg<T>) -> bool {
    let pr = msg.prepared_round();
    pr >= 0 && pr < msg.round()
}

/// Returns true if the decided message is justified by quorum COMMIT messages
/// of identical round and value.
fn is_justified_decided<T: QbftTypes>(d: &Definition<T>, msg: &Msg<T>) -> bool {
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

    commits.len() >= d.quorum_count()
}

/// Returns true if the PRE-PREPARE message is justified.
fn is_justified_pre_prepare<T: QbftTypes>(
    d: &Definition<T>,
    instance: &T::Instance,
    msg: &Msg<T>,
    compare_failure_round: i64,
) -> bool {
    if msg.type_() != MSG_PRE_PREPARE {
        panic!("bug: not a preprepare message");
    }

    if !(d.is_leader)(LeaderRequest {
        instance,
        round: msg.round(),
        process: msg.source(),
    }) {
        return false;
    }

    // Justified if PrePrepare is the first round OR if comparison failed previous
    // round.
    let next_compare_round = compare_failure_round
        .checked_add(1)
        .expect("compare failure round permits increment");
    if msg.round() == 1 || (msg.round() == next_compare_round) {
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
fn contains_justified_qrc<T: QbftTypes>(
    d: &Definition<T>,
    justification: &Vec<Msg<T>>,
    round: i64,
) -> Option<T::Value> {
    let qrc = filter_round_change(justification, round)
        .into_iter()
        .filter(valid_round_change_prepared_round)
        .collect::<Vec<_>>();
    if qrc.len() < d.quorum_count() {
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
fn get_single_justified_pr_pv<T: QbftTypes>(
    d: &Definition<T>,
    msgs: &Vec<Msg<T>>,
) -> Option<(i64, T::Value)> {
    let mut pr: i64 = 0;
    let mut pv: T::Value = Default::default();
    let mut count: usize = 0;
    let mut uniq = uniq_source();

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

        count = count
            .checked_add(1)
            .expect("prepare count permits increment");
    }

    if count >= d.quorum_count() {
        Some((pr, pv))
    } else {
        None
    }
}

/// Implements algorithm 4:1 and returns a justified quorum ROUND_CHANGEs (Qrc)
fn get_justified_qrc<T: QbftTypes>(
    d: &Definition<T>,
    all: &Vec<Msg<T>>,
    round: i64,
) -> Option<Vec<Msg<T>>> {
    if let (qrc, true) = quorum_null_prepared(d, all, round) {
        // Return any quorum null pv ROUND_CHANGE messages as Qrc.
        return Some(qrc);
    }

    let round_changes = filter_round_change(all, round)
        .into_iter()
        .filter(valid_round_change_prepared_round)
        .collect::<Vec<_>>();

    for prepares in get_prepare_quorums(d, all) {
        // See if we have quorum ROUND-CHANGE with HIGHEST_PREPARED(qrc) ==
        // prepares.Round.
        let mut qrc: Vec<Msg<T>> = vec![];
        let mut has_highest_prepared = false;
        let pr = prepares[0].round();
        let pv = prepares[0].value();
        let mut uniq = uniq_source();

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

        if qrc.len() >= d.quorum_count() && has_highest_prepared {
            qrc.extend(prepares);
            return Some(qrc);
        }
    }

    None
}

/// Returns true and Faulty+1 ROUND-CHANGE messages (Frc) with the rounds higher
/// than the provided round. It returns the highest round per process in order
/// to jump furthest.
fn get_fplus1_round_changes<T: QbftTypes>(
    d: &Definition<T>,
    all: &Vec<Msg<T>>,
    round: i64,
) -> Option<Vec<Msg<T>>> {
    let mut highest_by_source = HashMap::<i64, Msg<T>>::new();

    for msg in all {
        if msg.type_() != MSG_ROUND_CHANGE {
            continue;
        }

        if msg.round() <= round {
            continue;
        }

        if let Some(highest) = highest_by_source.get(&msg.source())
            && highest.round() > msg.round()
        {
            continue;
        }

        highest_by_source.insert(msg.source(), msg.clone());

        if highest_by_source.len() == d.faulty_plus_one_count() {
            break;
        }
    }

    if highest_by_source.len() < d.faulty_plus_one_count() {
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

/// Returns all unique-source PREPARE quorums grouped by identical round and
/// value.
fn get_prepare_quorums<T: QbftTypes>(d: &Definition<T>, all: &Vec<Msg<T>>) -> Vec<Vec<Msg<T>>> {
    let mut sets = HashMap::<PreparedKey<T::Value>, HashMap<i64, Msg<T>>>::new();

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
        if msgs.len() < d.quorum_count() {
            continue;
        }

        quorums.push(msgs.into_values().collect());
    }

    quorums
}

/// Implements condition J1 and returns Qrc and true if a quorum
/// of round changes messages (Qrc) for the round have null prepared round and
/// value.
fn quorum_null_prepared<T: QbftTypes>(
    d: &Definition<T>,
    all: &Vec<Msg<T>>,
    round: i64,
) -> (Vec<Msg<T>>, bool) {
    let null_pr = Default::default();
    let null_pv = Some(&Default::default());

    let justification = filter_msgs(all, MSG_ROUND_CHANGE, round, None, Some(null_pr), null_pv);
    let has_quorum = justification.len() >= d.quorum_count();

    (justification, has_quorum)
}

/// Returns the messages matching the type and value.
fn filter_by_round_and_value<T: QbftTypes>(
    msgs: &Vec<Msg<T>>,
    message_type: MessageType,
    round: i64,
    value: T::Value,
) -> Vec<Msg<T>> {
    filter_msgs(msgs, message_type, round, Some(&value), None, None)
}

/// Returns all round change messages for the provided round.
fn filter_round_change<T: QbftTypes>(msgs: &Vec<Msg<T>>, round: i64) -> Vec<Msg<T>> {
    filter_msgs::<T>(msgs, MSG_ROUND_CHANGE, round, None, None, None)
}

/// Returns one message per process matching the provided type and round and
/// optional value, pr, pv.
fn filter_msgs<T: QbftTypes>(
    msgs: &Vec<Msg<T>>,
    message_type: MessageType,
    round: i64,
    value: Option<&T::Value>,
    pr: Option<i64>,
    pv: Option<&T::Value>,
) -> Vec<Msg<T>> {
    let mut resp = Vec::new();
    let mut uniq = uniq_source();

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
fn flatten<T: QbftTypes>(buffer: &HashMap<i64, Vec<Msg<T>>>) -> Vec<Msg<T>> {
    let mut resp: Vec<Msg<T>> = Vec::new();

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
fn uniq_source<T: QbftTypes>() -> impl FnMut(&Msg<T>) -> bool {
    let mut sources = HashSet::new();
    move |msg: &Msg<T>| sources.insert(msg.source())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_from_wire_preserves_known_types() {
        assert_eq!(MessageType::from_wire(0), MSG_UNKNOWN);
        assert_eq!(MessageType::from_wire(1), MSG_PRE_PREPARE);
        assert_eq!(MessageType::from_wire(2), MSG_PREPARE);
        assert_eq!(MessageType::from_wire(3), MSG_COMMIT);
        assert_eq!(MessageType::from_wire(4), MSG_ROUND_CHANGE);
        assert_eq!(MessageType::from_wire(5), MSG_DECIDED);
    }

    #[test]
    fn message_type_from_wire_preserves_unknown_wire_value() {
        let message_type = MessageType::from_wire(99);

        assert_eq!(message_type, MessageType(99));
        assert!(!message_type.valid());
        assert_eq!(message_type.to_string(), "");
    }

    #[test]
    fn upon_rule_display_unknown_value_does_not_panic() {
        assert_eq!(UponRule(99).to_string(), "");
    }
}

#[cfg(test)]
mod fake_clock;
#[cfg(test)]
mod internal_test;
