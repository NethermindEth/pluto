// TODO: Remove these checks
#![allow(dead_code)]
#![allow(clippy::type_complexity)]

use anyhow::{Result, bail};
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    hash::Hash,
    sync::mpsc,
};

type SomeMsg<I, V, C> = Box<dyn Msg<I, V, C> + Send + Sync>;

struct Transport<I, V, C>
where
    V: PartialEq,
{
    pub broadcast: Box<dyn Fn(MessageType, I, i64, i64, V, i64, V) -> Result<()>>,
    pub receive: mpsc::Receiver<SomeMsg<I, V, C>>,
}

struct Definition<I, V, C>
where
    V: PartialEq,
{
    /// A deterministic leader election function.
    pub is_leader: Box<dyn Fn(/* instance */ &I, /* round */ i64, /* process */ i64) -> bool>,

    /// Returns a new timer channel and stop function for the round
    pub new_timer: Box<dyn Fn(/* rounds */ i64) -> (mpsc::Receiver<()>, Box<dyn Fn()>)>,

    // Called when leader proposes value and we compare it with our local value.
    // It's an opt-in feature that should instantly return nil on returnErr channel if it is not
    // turned on.
    pub compare: Box<
        dyn Fn(
                /* qcommit */ &SomeMsg<I, V, C>,
                /* inputValueSourceCh */ mpsc::Receiver<C>,
                /* inputValueSource */ &C,
                /* returnErr */ mpsc::SyncSender<Result<()>>,
                /* returnValue */ mpsc::SyncSender<C>,
            ) + Send
            + Sync,
    >,

    // Called when consensus has been reached on a value.
    pub decide: Box<dyn Fn(I, V, Vec<SomeMsg<I, V, C>>)>,

    /// Allows debug logging of triggered upon rules on message receipt.
    /// It includes the rule that triggered it and all received round messages.
    pub log_upon_rule: Box<
        dyn Fn(
            /* instance */ I,
            /* process */ i64,
            /* round */ i64,
            /* msg */ SomeMsg<I, V, C>,
            /* uponRule */ UponRule,
        ),
    >,
    /// Allows debug logging of round changes.
    pub log_round_change: Box<
        dyn Fn(
            /* instance */ &I,
            /* process */ i64,
            /* round */ i64,
            /* newRound */ i64,
            /* uponRule */ UponRule,
            /* msgs */ dyn Iterator<Item = &SomeMsg<I, V, C>>,
        ),
    >,

    /// Allows debug logging of unjust messages.
    pub log_unjust: Box<dyn Fn(/* instance */ I, /* process */ i64, /* msg */ SomeMsg<I, V, C>)>,

    /// Total number of nodes/processes participating in consensus.
    nodes: i64,

    /// Limits the amount of message buffered for each peer.
    fifo_limit: i64,
}

impl<I, V, C> Definition<I, V, C>
where
    V: PartialEq,
{
    /// Quorum count for the system.
    /// See IBFT 2.0 paper for correct formula: https://arxiv.org/pdf/1909.10194.pdf
    fn quorum(&self) -> i64 {
        ((self.nodes as f64 * 2.0) / 3.0).ceil() as i64
    }

    /// Maximum number of faulty/byzantium nodes supported in the system.
    /// See IBFT 2.0 paper for correct formula: https://arxiv.org/pdf/1909.10194.pdf
    fn faulty(&self) -> i64 {
        ((self.nodes - 1) as f64 / 3.0).floor() as i64
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct MessageType(i64);

pub const MSG_UNKNOWN: MessageType = MessageType(0);
pub const MSG_PRE_PREPARE: MessageType = MessageType(1);
pub const MSG_PREPARE: MessageType = MessageType(2);
pub const MSG_COMMIT: MessageType = MessageType(3);
pub const MSG_ROUND_CHANGE: MessageType = MessageType(4);
pub const MSG_DECIDED: MessageType = MessageType(5);

const MSG_SENTINEL: MessageType = MessageType(6); // intentionally not public

impl MessageType {
    fn valid(&self) -> bool {
        self.0 > MSG_UNKNOWN.0 && self.0 < MSG_SENTINEL.0
    }
}

impl Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
pub trait Msg<I, V, C>
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
    /// Uusually the value that was hashed and is returned in `value`.
    fn value_source(&self) -> Result<C>;
    /// The justified prepared round.
    fn prepared_round(&self) -> i64;
    /// the justified prepared value
    fn prepared_value(&self) -> V;
    // Set of messages that explicitly justifies this message.
    fn justification(&self) -> Vec<&SomeMsg<I, V, C>>;
}

/// Defines the event based rules that are triggered when messages are received.
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
struct DedupKey {
    upon_rule: UponRule,
    round: i64,
}

fn compare<I, V, C>(
    d: &Definition<I, V, C>,
    msg: &SomeMsg<I, V, C>,
    input_value_source_ch: mpsc::Receiver<C>,
    mut input_value_source: C,
    timer_chan: mpsc::Receiver<()>,
) -> Result<C>
where
    V: PartialEq,
    C: Clone + Copy + Send + Sync,
{
    let (compare_err_tx, compare_err_rx) = mpsc::sync_channel::<Result<()>>(1);
    let (compare_value_tx, compare_value_rx) = mpsc::sync_channel::<C>(1);

    // d.Compare has 2 roles:
    // 1. Read from the inputValueSourceCh (if inputValueSource is empty). If it
    //    read from the channel, it returns the value on compareValue channel.
    // 2. Compare the value read from inputValueSourceCh (or inputValueSource if it
    //    is not empty) to the value proposed by the leader.
    // If comparison or any other unexpected error occurs, the error is returned on
    // compareErr channel.

    return std::thread::scope(|s| {
        let compare = d.compare.as_ref();

        s.spawn(move || {
            (compare)(
                &msg,
                input_value_source_ch,
                &input_value_source,
                compare_err_tx,
                compare_value_tx,
            );
        });

        loop {
            if let Ok(result) = compare_err_rx.try_recv() {
                match result {
                    Ok(()) => return Ok(input_value_source),
                    Err(error) => {
                        bail!("compare leader value with local value failed: {}", error);
                    }
                }
            }
            if let Ok(value) = compare_value_rx.try_recv() {
                input_value_source = value;
            }
            if let Ok(_) = timer_chan.try_recv() {
                bail!(
                    "timeout on waiting for data used for comparing local and leader proposed data"
                );
            }
        }
    });
}

/// Returns all messages from the provided round.
fn extract_round_messages<I, V, C>(
    buffer: &HashMap<i64, Vec<SomeMsg<I, V, C>>>,
    round: i64,
) -> Vec<&SomeMsg<I, V, C>>
where
    V: PartialEq,
{
    let mut resp = vec![];

    for msgs in buffer.values() {
        for msg in msgs {
            if msg.round() == round {
                resp.push(msg);
            }
        }
    }

    resp
}

/// Returns the rule triggered upon receipt of the last message and its
/// justifications.
fn classify<'a, I, V, C>(
    d: &Definition<I, V, C>,
    instance: &I,
    round: i64,
    process: i64,
    buffer: &'a HashMap<i64, Vec<&SomeMsg<I, V, C>>>,
    msg: &'a SomeMsg<I, V, C>,
) -> (UponRule, Vec<&'a SomeMsg<I, V, C>>)
where
    V: Eq + Hash + Default,
{
    match msg.type_() {
        MSG_DECIDED => (UPON_JUSTIFIED_DECIDED, msg.justification()),
        MSG_PRE_PREPARE => {
            if msg.round() < round {
                (UPON_NOTHING, vec![])
            } else {
                (UPON_JUSTIFIED_PRE_PREPARE, vec![])
            }
        }
        MSG_PREPARE => {
            // Ignore other rounds, since PREPARE isn't justified.
            if msg.round() != round {
                return (UPON_NOTHING, vec![]);
            }

            let prepares =
                filter_by_round_and_value(flatten(buffer), MSG_PREPARE, msg.round(), msg.value());

            if prepares.len() as i64 >= d.quorum() {
                (UPON_QUORUM_PREPARES, prepares)
            } else {
                (UPON_NOTHING, vec![])
            }
        }
        MSG_COMMIT => {
            // Ignore other rounds, since COMMIT isn't justified.
            if msg.round() != round {
                return (UPON_NOTHING, vec![]);
            }

            let commits =
                filter_by_round_and_value(flatten(buffer), MSG_COMMIT, msg.round(), msg.value());
            if commits.len() as i64 >= d.quorum() {
                (UPON_QUORUM_COMMITS, commits)
            } else {
                (UPON_NOTHING, vec![])
            }
        }
        MSG_ROUND_CHANGE => {
            // Only ignore old rounds.
            if msg.round() < round {
                return (UPON_NOTHING, vec![]);
            }

            let all = flatten(buffer);

            if msg.round() > round {
                // Jump ahead if we received F+1 higher ROUND-CHANGEs.
                if let Some(frc) = get_fplus1_round_changes(d, all.clone(), round) {
                    return (UPON_F_PLUS1_ROUND_CHANGES, frc);
                }

                return (UPON_NOTHING, vec![]);
            }

            /* else msg.Round() == round */

            let qrc = filter_round_change(all.clone(), msg.round());
            if (qrc.len() as i64) < d.quorum() {
                return (UPON_NOTHING, vec![]);
            }

            let Some(qrc) = get_justified_qrc(d, all.clone(), msg.round()) else {
                return (UPON_UNJUST_QUORUM_ROUND_CHANGES, vec![]);
            };

            if !(d.is_leader)(instance, msg.round(), process) {
                return (UPON_NOTHING, vec![]);
            }

            (UPON_QUORUM_ROUND_CHANGES, qrc)
        }
        _ => {
            panic!("bug: invalid type");
        }
    }
}

/// Implements algorithm 3:6 and returns the next minimum round from received
/// round change messages.
fn min_next_round<I, V, C>(d: &Definition<I, V, C>, frc: Vec<&SomeMsg<I, V, C>>, round: i64) -> i64
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
    msg: &SomeMsg<I, V, C>,
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
fn is_justified_round_change<I, V, C>(d: &Definition<I, V, C>, msg: &SomeMsg<I, V, C>) -> bool
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
        if !uniq(prepare) {
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
fn is_justified_decided<I, V, C>(d: &Definition<I, V, C>, msg: &SomeMsg<I, V, C>) -> bool
where
    V: PartialEq,
{
    if msg.type_() != MSG_DECIDED {
        panic!("bug: not a decided message");
    }

    let v = msg.value();
    let commits = filter_msgs(
        msg.justification(),
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
    msg: &SomeMsg<I, V, C>,
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

    let Some(pv) = contains_justified_qrc(d, msg.justification(), msg.round()) else {
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
    justification: Vec<&SomeMsg<I, V, C>>,
    round: i64,
) -> Option<V>
where
    V: Eq + Hash + Default,
{
    let qrc = filter_round_change(justification.clone(), round);
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
    let (pr, pv) = get_single_justified_pr_pv(d, justification.clone())?;

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
    msgs: Vec<&SomeMsg<I, V, C>>,
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
fn get_justified_qrc<'a, I, V, C>(
    d: &Definition<I, V, C>,
    all: Vec<&'a SomeMsg<I, V, C>>,
    round: i64,
) -> Option<Vec<&'a SomeMsg<I, V, C>>>
where
    V: Eq + Hash + Default,
{
    if let (qrc, true) = quorum_null_prepared(&d, all.clone(), round) {
        // Return any quorum null pv ROUND_CHANGE messages as Qrc.
        return Some(qrc);
    }

    let round_changes = filter_round_change(all.clone(), round);

    for prepares in get_prepare_quorums(&d, all.clone()) {
        // See if we have quorum ROUND-CHANGE with HIGHEST_PREPARED(qrc) ==
        // prepares.Round.
        let mut qrc: Vec<&SomeMsg<I, V, C>> = vec![];
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

            qrc.push(*rc);
        }

        if (qrc.len() as i64) >= d.quorum() && has_highest_prepared {
            qrc.extend(prepares.iter());
            return Some(qrc);
        }
    }

    None
}

/// Returns true and Faulty+1 ROUND-CHANGE messages (Frc) with the rounds higher
/// than the provided round. It returns the highest round per process in order
/// to jump furthest.
fn get_fplus1_round_changes<'a, I, V, C>(
    d: &Definition<I, V, C>,
    all: Vec<&'a SomeMsg<I, V, C>>,
    round: i64,
) -> Option<Vec<&'a SomeMsg<I, V, C>>>
where
    V: PartialEq,
{
    let mut highest_by_source = HashMap::<i64, &'a SomeMsg<I, V, C>>::new();

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

        highest_by_source.insert(msg.source(), msg);

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

fn get_prepare_quorums<'a, I, V, C>(
    d: &Definition<I, V, C>,
    all: Vec<&'a SomeMsg<I, V, C>>,
) -> Vec<Vec<&'a SomeMsg<I, V, C>>>
where
    V: Eq + Hash,
{
    let mut sets = HashMap::<PreparedKey<V>, HashMap<i64, &SomeMsg<I, V, C>>>::new();

    for msg in all {
        if msg.type_() != MSG_PREPARE {
            continue;
        }

        let key = PreparedKey {
            round: msg.round(),
            value: msg.value(),
        };

        sets.entry(key).or_default().insert(msg.source(), msg);
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
fn quorum_null_prepared<'a, I, V, C>(
    d: &Definition<I, V, C>,
    all: Vec<&'a SomeMsg<I, V, C>>,
    round: i64,
) -> (Vec<&'a SomeMsg<I, V, C>>, bool)
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
    msgs: Vec<&SomeMsg<I, V, C>>,
    message_type: MessageType,
    round: i64,
    value: V,
) -> Vec<&SomeMsg<I, V, C>>
where
    V: PartialEq,
{
    filter_msgs(msgs, message_type, round, Some(&value), None, None)
}

/// Returns all round change messages for the provided round.
fn filter_round_change<I, V, C>(msgs: Vec<&SomeMsg<I, V, C>>, round: i64) -> Vec<&SomeMsg<I, V, C>>
where
    V: PartialEq,
{
    filter_msgs::<I, V, C>(msgs, MSG_ROUND_CHANGE, round, None, None, None)
}

/// Returns one message per process matching the provided type and round and
/// optional value, pr, pv.
fn filter_msgs<'a, I, V, C>(
    msgs: Vec<&'a SomeMsg<I, V, C>>,
    message_type: MessageType,
    round: i64,
    value: Option<&V>,
    pr: Option<i64>,
    pv: Option<&V>,
) -> Vec<&'a SomeMsg<I, V, C>>
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
            resp.push(msg);
        }
    }

    resp
}

/// Produce a vector containing all the buffered messages as well as all their
/// justifications.
fn flatten<'a, I, V, C>(
    buffer: &HashMap<i64, Vec<&'a SomeMsg<I, V, C>>>,
) -> Vec<&'a SomeMsg<I, V, C>>
where
    V: PartialEq,
{
    let mut resp: Vec<&SomeMsg<I, V, C>> = Vec::new();

    for msgs in buffer.values() {
        for msg in msgs {
            resp.push(msg);
            for j in msg.justification() {
                resp.push(j);
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
fn uniq_source<I, V, C>(vec: Vec<SomeMsg<I, V, C>>) -> Box<impl FnMut(&SomeMsg<I, V, C>) -> bool>
where
    V: PartialEq,
{
    let mut s = vec.iter().map(|msg| msg.source()).collect::<HashSet<_>>();
    Box::new(move |msg: &SomeMsg<I, V, C>| {
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
mod tests {

    struct Foo {
        f: Box<dyn Fn(Vec<&i32>) -> i32>,
    }

    #[test]
    fn it_works() {
        let foo = Foo {
            f: Box::new(|vec: Vec<&i32>| -> i32 {
                let mut sum = 0;
                for v in vec {
                    sum += *v;
                }
                sum
            }),
        };
        let v = [1, 2, 3, 4, 5];
        let collected: Vec<&i32> = v.iter().collect();
        let result = (foo.f)(collected);
        assert_eq!(result, 15);
    }
}
