//! Consensus round timers.
//!
//! This module provides the round-timeout strategies used by consensus
//! protocols. Each strategy returns a cancellable Tokio sleep for a round, and
//! timer selection follows the shared feature-set state.
//!
//! Public surface used by other modules:
//! - [`RoundTimer`] is the common timer interface.
//! - [`RoundTimerFuture`] is the cancellable timeout returned by a timer.
//! - [`RoundTimerFunc`] and [`get_round_timer_func`] select the concrete
//!   strategy.
//! - [`TimerType`] identifies the selected strategy for logging/metrics.
//! - [`IncreasingRoundTimer`], [`EagerDoubleLinearRoundTimer`], and
//!   [`LinearRoundTimer`] are the concrete strategy implementations.
//! - [`Error`] and [`Result`] carry timer construction failures.
//!
//! Usage:
//! - Call [`get_round_timer_func`] once when wiring consensus.
//! - Call the returned [`RoundTimerFunc`] once per duty/consensus instance.
//! - For each round, call [`RoundTimer::timer`] and await the returned future
//!   in the instance event loop. Dropping the future cancels that timeout.
//! - If [`TimerType::eager`] is true, start the first round timer before the
//!   proposal value is available so peers align on round boundaries.

use std::{
    collections::{HashMap, hash_map::Entry},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use pluto_featureset::{Feature, FeatureSet};
use tokio::time::{Instant, sleep_until};

use pluto_core::types::{Duty, DutyType};

/// Increasing timer round-1 base timeout.
pub const INC_ROUND_START: Duration = Duration::from_millis(750);
/// Increasing timer per-round increment.
pub const INC_ROUND_INCREASE: Duration = Duration::from_millis(250);
/// Eager double linear timer per-round increment.
pub const LINEAR_ROUND_INC: Duration = Duration::from_secs(1);

const PROPOSAL_TIMEOUT: Duration = Duration::from_millis(1_500);

/// Timer errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Round produced a negative duration.
    #[error("invalid consensus round: {round}")]
    InvalidRound {
        /// Invalid round.
        round: i64,
    },
    /// Timer duration arithmetic overflowed.
    #[error("timer duration overflow for round: {round}")]
    DurationOverflow {
        /// Round whose duration overflowed.
        round: i64,
    },
    /// Timer deadline arithmetic overflowed.
    #[error("timer deadline overflow for round: {round}")]
    DeadlineOverflow {
        /// Round whose deadline overflowed.
        round: i64,
    },
    /// Eager timer state lock was poisoned.
    #[error("timer state poisoned")]
    TimerStatePoisoned,
}

/// Timer result.
pub type Result<T> = std::result::Result<T, Error>;

/// Round timer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerType {
    /// Increasing timer.
    Increasing,
    /// Eager double linear timer.
    EagerDoubleLinear,
    /// Linear timer.
    Linear,
}

impl TimerType {
    /// Returns true if timer starts eagerly before proposal values exist.
    pub fn eager(self) -> bool {
        matches!(self, Self::EagerDoubleLinear)
    }

    /// Returns the stable timer type string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Increasing => "inc",
            Self::EagerDoubleLinear => "eager_dlinear",
            Self::Linear => "linear",
        }
    }
}

/// Cancellable future returned by a round timer.
///
/// Awaiting it waits for expiry and returns the scheduled deadline. Dropping it
/// cancels the timeout, which callers should do when the round changes or the
/// consensus instance exits.
pub type RoundTimerFuture = Pin<Box<dyn Future<Output = Instant> + Send>>;

/// Function that returns a round timer for a duty.
///
/// Call this once per consensus instance so timers that keep per-round state do
/// not share that state across duties.
pub type RoundTimerFunc = Box<dyn Fn(Duty) -> Box<dyn RoundTimer> + Send + Sync>;

/// Provides the duration for each consensus round.
pub trait RoundTimer: Send + Sync {
    /// Returns the timer type.
    fn timer_type(&self) -> TimerType;

    /// Returns a timeout for the round.
    ///
    /// The caller owns cancellation by dropping the returned future before it
    /// fires.
    fn timer(&self, round: i64) -> Result<RoundTimerFuture>;
}

/// Implements a linearly increasing round timer.
#[derive(Debug, Clone, Default)]
pub struct IncreasingRoundTimer {
    duty: Option<Duty>,
    feature_set: Arc<FeatureSet>,
}

impl IncreasingRoundTimer {
    /// Creates an increasing round timer.
    pub fn new() -> Self {
        Self {
            duty: None,
            feature_set: Arc::new(FeatureSet::new()),
        }
    }

    /// Creates an increasing round timer for a duty.
    pub fn with_duty(duty: Duty, feature_set: Arc<FeatureSet>) -> Self {
        Self {
            duty: Some(duty),
            feature_set,
        }
    }
}

impl RoundTimer for IncreasingRoundTimer {
    fn timer_type(&self) -> TimerType {
        TimerType::Increasing
    }

    fn timer(&self, round: i64) -> Result<RoundTimerFuture> {
        let timeout = match proposal_timeout_duration(self.duty.as_ref(), round, &self.feature_set)
        {
            Some(timeout) => timeout,
            None => increasing_round_timeout(round)?,
        };

        timeout_from_now(timeout, round)
    }
}

/// Implements an eager double linear round timer.
///
/// It doubles the round duration when a leader is active. Instead of resetting
/// the round timer on justified pre-prepare, it doubles the timeout. This keeps
/// all peer round end-times aligned with round start times.
///
/// Resetting the timer on justified pre-prepare makes leaders and followers
/// diverge: the leader resets at the start of the round, which has no effect,
/// while followers reset when they receive the justified pre-prepare. Leaders
/// then tend to get out of sync with the rest because they effectively do not
/// extend their rounds.
///
/// It is eager, meaning it starts at an absolute time before proposal values
/// are present. This aligns round start times across peers, which matters for
/// leader election.
///
/// It is linear, meaning the round duration increases linearly with the round
/// number: 1s, 2s, 3s, etc.
#[derive(Debug, Default)]
pub struct EagerDoubleLinearRoundTimer {
    duty: Option<Duty>,
    feature_set: Arc<FeatureSet>,
    first_deadlines: Mutex<HashMap<i64, Instant>>,
}

impl EagerDoubleLinearRoundTimer {
    /// Creates an eager double linear round timer.
    pub fn new() -> Self {
        Self {
            duty: None,
            feature_set: Arc::new(FeatureSet::new()),
            first_deadlines: Mutex::new(HashMap::new()),
        }
    }

    /// Creates an eager double linear round timer for a duty.
    pub fn with_duty(duty: Duty, feature_set: Arc<FeatureSet>) -> Self {
        Self {
            duty: Some(duty),
            feature_set,
            first_deadlines: Mutex::new(HashMap::new()),
        }
    }
}

impl RoundTimer for EagerDoubleLinearRoundTimer {
    fn timer_type(&self) -> TimerType {
        TimerType::EagerDoubleLinear
    }

    fn timer(&self, round: i64) -> Result<RoundTimerFuture> {
        let timeout = match proposal_timeout_duration(self.duty.as_ref(), round, &self.feature_set)
        {
            Some(timeout) => timeout,
            None => linear_round_timeout(round)?,
        };

        let mut first_deadlines = self
            .first_deadlines
            .lock()
            .map_err(|_| Error::TimerStatePoisoned)?;
        let deadline = match first_deadlines.entry(round) {
            // Deadline is either double the first timeout.
            Entry::Occupied(entry) => checked_deadline(*entry.get(), timeout, round)?,
            Entry::Vacant(entry) => {
                // Or the first timeout.
                let now = Instant::now();
                let first_deadline = checked_deadline(now, timeout, round)?;
                entry.insert(first_deadline);
                first_deadline
            }
        };

        Ok(timeout_for_deadline(deadline))
    }
}

/// Implements a linear round timer.
///
/// The first round has one second to complete consensus. If that round fails,
/// other peers already had time to fetch the proposal and therefore need less
/// time to reach consensus, so subsequent rounds start with a lower value and
/// increase linearly.
#[derive(Debug, Clone, Default)]
pub struct LinearRoundTimer {
    duty: Option<Duty>,
    feature_set: Arc<FeatureSet>,
}

impl LinearRoundTimer {
    /// Creates a linear round timer.
    pub fn new() -> Self {
        Self {
            duty: None,
            feature_set: Arc::new(FeatureSet::new()),
        }
    }

    /// Creates a linear round timer for a duty.
    pub fn with_duty(duty: Duty, feature_set: Arc<FeatureSet>) -> Self {
        Self {
            duty: Some(duty),
            feature_set,
        }
    }
}

impl RoundTimer for LinearRoundTimer {
    fn timer_type(&self) -> TimerType {
        TimerType::Linear
    }

    fn timer(&self, round: i64) -> Result<RoundTimerFuture> {
        let timeout = match proposal_timeout_duration(self.duty.as_ref(), round, &self.feature_set)
        {
            Some(timeout) => timeout,
            None if round == 1 => Duration::from_secs(1),
            None => linear_subsequent_round_timeout(round)?,
        };

        timeout_from_now(timeout, round)
    }
}

/// Returns a timer function based on the enabled features.
///
/// The injected `feature_set` is cloned into each built timer, which reads
/// `ProposalTimeout` from it per round.
pub fn get_round_timer_func(feature_set: Arc<FeatureSet>) -> RoundTimerFunc {
    if feature_set.enabled(Feature::Linear) {
        return Box::new(move |duty| {
            if is_proposer(&duty) {
                Box::new(LinearRoundTimer::with_duty(duty, feature_set.clone()))
            } else if feature_set.enabled(Feature::EagerDoubleLinear) {
                Box::new(EagerDoubleLinearRoundTimer::with_duty(
                    duty,
                    feature_set.clone(),
                ))
            } else {
                Box::new(IncreasingRoundTimer::with_duty(duty, feature_set.clone()))
            }
        });
    }

    if feature_set.enabled(Feature::EagerDoubleLinear) {
        Box::new(move |duty| {
            Box::new(EagerDoubleLinearRoundTimer::with_duty(
                duty,
                feature_set.clone(),
            ))
        })
    } else {
        Box::new(move |duty| Box::new(IncreasingRoundTimer::with_duty(duty, feature_set.clone())))
    }
}

/// Returns true for duties that use the proposer-specific timer path.
fn is_proposer(duty: &Duty) -> bool {
    matches!(&duty.duty_type, DutyType::Proposer)
}

/// Returns the proposer round-one override duration, when `ProposalTimeout` is
/// enabled and the duty is a proposer in round one.
fn proposal_timeout_duration(
    duty: Option<&Duty>,
    round: i64,
    feature_set: &FeatureSet,
) -> Option<Duration> {
    if round == 1 && duty.is_some_and(is_proposer) && feature_set.enabled(Feature::ProposalTimeout)
    {
        Some(PROPOSAL_TIMEOUT)
    } else {
        None
    }
}

/// Returns `INC_ROUND_START + INC_ROUND_INCREASE * round`.
fn increasing_round_timeout(round: i64) -> Result<Duration> {
    ensure_non_negative_round(round)?;

    let rounds = u32::try_from(round).map_err(|_| Error::DurationOverflow { round })?;
    let increment = INC_ROUND_INCREASE
        .checked_mul(rounds)
        .ok_or(Error::DurationOverflow { round })?;
    INC_ROUND_START
        .checked_add(increment)
        .ok_or(Error::DurationOverflow { round })
}

/// Returns `LINEAR_ROUND_INC * round`.
fn linear_round_timeout(round: i64) -> Result<Duration> {
    ensure_non_negative_round(round)?;

    let rounds = u32::try_from(round).map_err(|_| Error::DurationOverflow { round })?;
    LINEAR_ROUND_INC
        .checked_mul(rounds)
        .ok_or(Error::DurationOverflow { round })
}

/// Returns the reduced timeout used after linear round one.
fn linear_subsequent_round_timeout(round: i64) -> Result<Duration> {
    ensure_non_negative_round(round)?;

    // Charon fixed the previous bare `time.Duration(...)` bug in
    // ObolNetwork/charon#4537; subsequent linear rounds are milliseconds.
    let previous_round = round
        .checked_sub(1)
        .ok_or(Error::DurationOverflow { round })?;
    let increment_millis = previous_round
        .checked_mul(200)
        .ok_or(Error::DurationOverflow { round })?;
    let timeout_millis = increment_millis
        .checked_add(200)
        .ok_or(Error::DurationOverflow { round })?;
    let timeout_millis =
        u64::try_from(timeout_millis).map_err(|_| Error::DurationOverflow { round })?;

    Ok(Duration::from_millis(timeout_millis))
}

/// Rejects negative consensus rounds before duration arithmetic.
fn ensure_non_negative_round(round: i64) -> Result<()> {
    if round < 0 {
        return Err(Error::InvalidRound { round });
    }

    Ok(())
}

/// Returns a timeout future scheduled relative to current Tokio time.
fn timeout_from_now(timeout: Duration, round: i64) -> Result<RoundTimerFuture> {
    let deadline = checked_deadline(Instant::now(), timeout, round)?;

    Ok(timeout_for_deadline(deadline))
}

/// Returns a future that resolves at an absolute Tokio deadline.
fn timeout_for_deadline(deadline: Instant) -> RoundTimerFuture {
    Box::pin(async move {
        sleep_until(deadline).await;
        deadline
    })
}

/// Adds a timeout to an absolute start time with overflow reporting.
fn checked_deadline(start: Instant, timeout: Duration, round: i64) -> Result<Instant> {
    start
        .checked_add(timeout)
        .ok_or(Error::DeadlineOverflow { round })
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use pluto_featureset::{Config, FeatureSet};
    use test_case::test_case;
    use tokio::{task::JoinHandle, time::advance};

    use super::*;
    use pluto_core::types::SlotNumber;

    #[test_case(TimerType::Increasing, "inc" ; "increasing")]
    #[test_case(TimerType::EagerDoubleLinear, "eager_dlinear" ; "eager_double_linear")]
    #[test_case(TimerType::Linear, "linear" ; "linear")]
    fn timer_type_strings(timer_type: TimerType, want: &str) {
        assert_eq!(want, timer_type.as_str());
    }

    #[test_case(1, Duration::from_millis(1_000) ; "round_1")]
    #[test_case(2, Duration::from_millis(1_250) ; "round_2")]
    #[test_case(10, Duration::from_millis(3_250) ; "round_10")]
    #[tokio::test(start_paused = true)]
    async fn increasing_round_timer(round: i64, want: Duration) {
        let timer = IncreasingRoundTimer::new();
        let timeout = must_timer(timer.timer(round));

        assert_fires_after(timeout, want, &format!("Timer(round {round}) did not fire")).await;
    }

    #[tokio::test(start_paused = true)]
    async fn double_eager_linear_round_timer() {
        let timer = EagerDoubleLinearRoundTimer::new();

        assert!(timer.timer_type().eager());

        assert_fires_after(
            must_timer(timer.timer(1)),
            Duration::from_millis(1_000),
            "round 1 first timer did not fire",
        )
        .await;

        assert_fires_after(
            must_timer(timer.timer(1)),
            Duration::from_millis(1_000),
            "round 1 second timer did not fire",
        )
        .await;

        let timeout = spawn_timeout(must_timer(timer.timer(2)));
        advance(Duration::from_millis(1_500)).await;
        tokio::task::yield_now().await;
        assert!(!timeout.is_finished(), "round 2 first timer fired early");
        timeout.abort();

        assert_fires_after(
            must_timer(timer.timer(2)),
            Duration::from_millis(2_500),
            "round 2 second timer did not fire",
        )
        .await;

        assert_fires_after(
            must_timer(timer.timer(3)),
            Duration::from_millis(3_000),
            "round 3 first timer did not fire",
        )
        .await;

        let timeout = spawn_timeout(must_timer(timer.timer(3)));
        advance(Duration::from_millis(2_500)).await;
        tokio::task::yield_now().await;
        assert!(!timeout.is_finished(), "round 3 second timer fired early");
        assert_fires_after(
            join_timeout(timeout),
            Duration::from_millis(500),
            "round 3 second timer did not fire",
        )
        .await;
    }

    #[test_case(1, Duration::from_millis(1_000) ; "round_1")]
    #[test_case(2, Duration::from_millis(400) ; "round_2")]
    #[test_case(3, Duration::from_millis(600) ; "round_3")]
    #[test_case(4, Duration::from_millis(800) ; "round_4")]
    #[tokio::test(start_paused = true)]
    async fn linear_round_timer(round: i64, want: Duration) {
        let timer = LinearRoundTimer::new();
        let timeout = must_timer(timer.timer(round));
        let duration = if round == 1 {
            Duration::from_secs(1)
        } else {
            must_duration(linear_subsequent_round_timeout(round))
        };

        assert_eq!(want, duration);
        assert_fires_after(timeout, want, &format!("Timer(round {round}) did not fire")).await;
    }

    #[test]
    fn get_timer_func() {
        let attester = Duty::new_attester_duty(SlotNumber::from(0));
        let proposer = Duty::new_proposer_duty(SlotNumber::from(0));

        let fs = FeatureSet::new();
        let timer_func = get_round_timer_func(Arc::new(fs));
        assert_eq!(
            TimerType::EagerDoubleLinear,
            timer_func(attester.clone()).timer_type()
        );

        let fs = featureset(vec![], vec![Feature::EagerDoubleLinear]);
        let timer_func = get_round_timer_func(Arc::new(fs));
        assert_eq!(
            TimerType::Increasing,
            timer_func(attester.clone()).timer_type()
        );

        let fs = featureset(vec![Feature::Linear], vec![Feature::EagerDoubleLinear]);
        let timer_func = get_round_timer_func(Arc::new(fs));
        assert_eq!(
            TimerType::Increasing,
            timer_func(attester.clone()).timer_type()
        );

        let fs = featureset(vec![Feature::Linear], vec![]);
        let timer_func = get_round_timer_func(Arc::new(fs));
        assert_eq!(
            TimerType::EagerDoubleLinear,
            timer_func(attester).timer_type()
        );
        assert_eq!(TimerType::Linear, timer_func(proposer).timer_type());
    }

    #[tokio::test(start_paused = true)]
    async fn proposal_timeout_optimization_increasing_round_timer() {
        let duty = Duty::new_proposer_duty(SlotNumber::from(0));
        let timer = IncreasingRoundTimer::with_duty(duty, proposal_timeout_fs());

        let timeout = must_timer(timer.timer(1));
        assert_fires_after(
            timeout,
            Duration::from_millis(1_500),
            "round 1 proposer timer did not fire at 1.5s",
        )
        .await;

        let timeout = must_timer(timer.timer(2));
        assert_fires_after(
            timeout,
            Duration::from_millis(1_250),
            "round 2 proposer timer did not fire at original duration",
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn proposal_timeout_optimization_double_eager_linear_round_timer() {
        let duty = Duty::new_proposer_duty(SlotNumber::from(0));
        let timer = EagerDoubleLinearRoundTimer::with_duty(duty, proposal_timeout_fs());

        let timeout = must_timer(timer.timer(1));
        assert_fires_after(
            timeout,
            Duration::from_millis(1_500),
            "round 1 proposer timer did not fire at 1.5s",
        )
        .await;

        let timeout = must_timer(timer.timer(2));
        assert_fires_after(
            timeout,
            Duration::from_millis(2_000),
            "round 2 proposer timer did not fire at 2s",
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn proposal_timeout_optimization_double_eager_linear_round_one_doubles() {
        let duty = Duty::new_proposer_duty(SlotNumber::from(0));
        let timer = EagerDoubleLinearRoundTimer::with_duty(duty, proposal_timeout_fs());

        let timeout = {
            drop(must_timer(timer.timer(1)));
            must_timer(timer.timer(1))
        };
        let timeout = spawn_timeout(timeout);
        advance(Duration::from_millis(2_500)).await;
        tokio::task::yield_now().await;
        assert!(
            !timeout.is_finished(),
            "round 1 second proposer timer fired early"
        );
        assert_fires_after(
            join_timeout(timeout),
            Duration::from_millis(500),
            "round 1 second proposer timer did not fire at doubled deadline",
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn proposal_timeout_optimization_linear_round_timer() {
        let duty = Duty::new_proposer_duty(SlotNumber::from(0));
        let timer = LinearRoundTimer::with_duty(duty, proposal_timeout_fs());

        let timeout = must_timer(timer.timer(1));
        assert_fires_after(
            timeout,
            Duration::from_millis(1_500),
            "round 1 proposer timer did not fire at 1.5s",
        )
        .await;

        let timeout = must_timer(timer.timer(3));
        let want = Duration::from_millis(600);
        assert_eq!(want, must_duration(linear_subsequent_round_timeout(3)));
        assert_fires_after(timeout, want, "round 3 proposer timer did not fire").await;
    }

    #[test]
    fn negative_round_returns_error() {
        let timers: Vec<(&str, Box<dyn RoundTimer>)> = vec![
            ("increasing", Box::new(IncreasingRoundTimer::new())),
            (
                "eager_double_linear",
                Box::new(EagerDoubleLinearRoundTimer::new()),
            ),
            ("linear", Box::new(LinearRoundTimer::new())),
        ];

        for (name, timer) in timers {
            match timer.timer(-4) {
                Ok(_) => panic!("{name} negative round must fail"),
                Err(err) => assert_eq!(Error::InvalidRound { round: -4 }, err),
            }
        }
    }

    #[test]
    fn max_round_returns_duration_overflow() {
        let timers: Vec<(&str, Box<dyn RoundTimer>)> = vec![
            ("increasing", Box::new(IncreasingRoundTimer::new())),
            (
                "eager_double_linear",
                Box::new(EagerDoubleLinearRoundTimer::new()),
            ),
            ("linear", Box::new(LinearRoundTimer::new())),
        ];

        for (name, timer) in timers {
            match timer.timer(i64::MAX) {
                Ok(_) => panic!("{name} max round must overflow"),
                Err(err) => assert_eq!(Error::DurationOverflow { round: i64::MAX }, err),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn round_zero_matches_go_behavior() {
        assert_eq!(
            Duration::from_millis(750),
            must_duration(increasing_round_timeout(0))
        );
        assert_fires_after(
            must_timer(IncreasingRoundTimer::new().timer(0)),
            Duration::from_millis(750),
            "increasing round 0 timer did not fire at 750ms",
        )
        .await;

        assert_eq!(Duration::ZERO, must_duration(linear_round_timeout(0)));
        assert_fires_immediately(
            must_timer(EagerDoubleLinearRoundTimer::new().timer(0)),
            "eager double-linear round 0 timer did not fire immediately",
        )
        .await;

        assert_eq!(
            Duration::ZERO,
            must_duration(linear_subsequent_round_timeout(0))
        );
        assert_fires_immediately(
            must_timer(LinearRoundTimer::new().timer(0)),
            "linear round 0 timer did not fire immediately",
        )
        .await;
    }

    fn must_timer(result: Result<RoundTimerFuture>) -> RoundTimerFuture {
        match result {
            Ok(timeout) => timeout,
            Err(err) => panic!("timer failed: {err}"),
        }
    }

    fn must_duration(result: Result<Duration>) -> Duration {
        match result {
            Ok(duration) => duration,
            Err(err) => panic!("duration failed: {err}"),
        }
    }

    fn spawn_timeout(timeout: RoundTimerFuture) -> JoinHandle<Instant> {
        tokio::spawn(timeout)
    }

    fn join_timeout(timeout: JoinHandle<Instant>) -> RoundTimerFuture {
        Box::pin(async move {
            match timeout.await {
                Ok(deadline) => deadline,
                Err(err) => panic!("timer task failed: {err}"),
            }
        })
    }

    async fn assert_fires_after(timeout: RoundTimerFuture, duration: Duration, message: &str) {
        let timeout = spawn_timeout(timeout);

        advance(duration).await;
        tokio::task::yield_now().await;

        assert!(timeout.is_finished(), "{message}");
        match timeout.await {
            Ok(_) => {}
            Err(err) => panic!("timer task failed: {err}"),
        }
    }

    async fn assert_fires_immediately(timeout: RoundTimerFuture, message: &str) {
        let timeout = spawn_timeout(timeout);

        tokio::task::yield_now().await;

        if !timeout.is_finished() {
            timeout.abort();
            panic!("{message}");
        }
        match timeout.await {
            Ok(_) => {}
            Err(err) => panic!("timer task failed: {err}"),
        }
    }

    fn features_config(enabled: Vec<Feature>, disabled: Vec<Feature>) -> Config {
        Config {
            enabled,
            disabled,
            ..Config::default()
        }
    }

    fn featureset(enabled: Vec<Feature>, disabled: Vec<Feature>) -> FeatureSet {
        FeatureSet::from_config(features_config(enabled, disabled))
            .expect("test featureset is valid")
    }

    fn proposal_timeout_fs() -> Arc<FeatureSet> {
        Arc::new(featureset(vec![Feature::ProposalTimeout], vec![]))
    }
}
