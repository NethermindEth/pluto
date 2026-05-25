use super::{MessageType, Msg, QbftTypes, Result, UponRule};
use cancellation::CancellationToken;
use crossbeam::channel as mpmc;
use std::time;

pub(super) type BroadcastFn<T> =
    dyn for<'a> Fn(BroadcastRequest<'a, T>) -> Result<()> + Send + Sync;
pub(super) type CompareFn<T> = dyn for<'a> Fn(CompareRequest<'a, T>) + Send + Sync + 'static;
pub(super) type UponRuleLoggerFn<T> = dyn for<'a> Fn(UponRuleLog<'a, T>) + Send + Sync;
pub(super) type RoundChangeLoggerFn<T> = dyn for<'a> Fn(RoundChangeLog<'a, T>) + Send + Sync;
pub(super) type UnjustLoggerFn<T> = dyn for<'a> Fn(UnjustLog<'a, T>) + Send + Sync;
pub(super) type LeaderFn<T> = dyn for<'a> Fn(LeaderRequest<'a, T>) -> bool + Send + Sync;
pub(super) type DecideFn<T> = dyn for<'a> Fn(DecideRequest<'a, T>) + Send + Sync;

/// Input passed to `Transport::broadcast`.
pub struct BroadcastRequest<'a, T: QbftTypes> {
    /// Parent cancellation token.
    pub ct: &'a CancellationToken,
    /// Message type to broadcast.
    pub type_: MessageType,
    /// Consensus instance identifier.
    pub instance: &'a T::Instance,
    /// Sending process.
    pub source: i64,
    /// Message round.
    pub round: i64,
    /// Proposal value.
    pub value: &'a T::Value,
    /// Prepared round carried by ROUND-CHANGE messages.
    pub prepared_round: i64,
    /// Prepared value carried by ROUND-CHANGE messages.
    pub prepared_value: &'a T::Value,
    /// Optional justification piggybacked on the message.
    pub justification: Option<&'a Vec<Msg<T>>>,
}

/// Input passed to `Definition::compare`.
pub struct CompareRequest<'a, T: QbftTypes> {
    /// Compare-scoped cancellation token.
    pub ct: &'a CancellationToken,
    /// Proposed commit quorum message.
    pub qcommit: &'a Msg<T>,
    /// Channel carrying the local compare value if it was not cached yet.
    pub input_value_source_ch: &'a mpmc::Receiver<T::Compare>,
    /// Cached local compare value.
    pub input_value_source: &'a T::Compare,
    /// Channel used by the callback to return compare status.
    pub return_err: &'a mpmc::Sender<Result<()>>,
    /// Channel used by the callback to cache the local compare value.
    pub return_value: &'a mpmc::Sender<T::Compare>,
}

/// Timer returned by `Definition::new_timer`.
pub struct Timer {
    /// Channel that fires when the timer expires.
    pub receive: mpmc::Receiver<time::Instant>,
    /// Stops the timer.
    pub stop: Box<dyn Fn() + Send + Sync>,
}

/// Input passed to `Definition::is_leader`.
pub struct LeaderRequest<'a, T: QbftTypes> {
    /// Consensus instance identifier.
    pub instance: &'a T::Instance,
    /// Round being evaluated.
    pub round: i64,
    /// Process being evaluated.
    pub process: i64,
}

/// Input passed to `Definition::decide`.
pub struct DecideRequest<'a, T: QbftTypes> {
    /// Parent cancellation token.
    pub ct: &'a CancellationToken,
    /// Consensus instance identifier.
    pub instance: &'a T::Instance,
    /// Decided value.
    pub value: &'a T::Value,
    /// Commit quorum justifying the decision.
    pub qcommit: &'a Vec<Msg<T>>,
}

/// Input passed to `QbftLogger::upon_rule`.
pub struct UponRuleLog<'a, T: QbftTypes> {
    /// Consensus instance identifier.
    pub instance: &'a T::Instance,
    /// Local process.
    pub process: i64,
    /// Current local round.
    pub round: i64,
    /// Message that triggered classification.
    pub msg: &'a Msg<T>,
    /// Rule that fired.
    pub upon_rule: UponRule,
}

/// Input passed to `QbftLogger::round_change`.
pub struct RoundChangeLog<'a, T: QbftTypes> {
    /// Consensus instance identifier.
    pub instance: &'a T::Instance,
    /// Local process.
    pub process: i64,
    /// Previous local round.
    pub round: i64,
    /// New local round.
    pub new_round: i64,
    /// Rule that caused the round change.
    pub upon_rule: UponRule,
    /// Messages from the previous round.
    pub msgs: &'a Vec<Msg<T>>,
}

/// Input passed to `QbftLogger::unjust`.
pub struct UnjustLog<'a, T: QbftTypes> {
    /// Consensus instance identifier.
    pub instance: &'a T::Instance,
    /// Local process.
    pub process: i64,
    /// Rejected message.
    pub msg: Msg<T>,
}
