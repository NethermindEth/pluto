//! Duty deadline tracking and notification functionality.
//!
//! Provides `DeadlinerHandle` for tracking duty deadlines and notifying when
//! duties expire. A background task spawned by `DeadlinerTask::start` manages
//! timers for multiple duties and emits expired ones on a channel.
//!
//! # Example
//!
//! ```no_run
//! use pluto_core::{
//!     deadline::{AddOutcome, DeadlinerTask, DutyDeadlineCalculator},
//!     types::{Duty, SlotNumber},
//! };
//! use pluto_eth2api::EthBeaconNodeApiClient;
//! use tokio_util::sync::CancellationToken;
//!
//! # async fn example(client: &EthBeaconNodeApiClient) -> anyhow::Result<()> {
//! let cancel_token = CancellationToken::new();
//! let calculator = DutyDeadlineCalculator::from_client(client).await?;
//! let (deadliner, mut rx) = DeadlinerTask::start(cancel_token, "example", calculator);
//!
//! let duty = Duty::new_attester_duty(SlotNumber::new(1));
//! match deadliner.add(duty).await {
//!     AddOutcome::Scheduled => {}
//!     AddOutcome::AlreadyExpired => eprintln!("duty already expired — skipped"),
//!     AddOutcome::NoDeadline => {}
//!     AddOutcome::FailedToCompute => eprintln!("deadline calculation failed"),
//! }
//!
//! while let Some(expired_duty) = rx.recv().await {
//!     println!("Duty expired: {}", expired_duty);
//! }
//! # Ok(())
//! # }
//! ```

mod calculator;
mod msecs;

pub use calculator::{DeadlineCalculator, DutyDeadlineCalculator, NeverExpiringCalculator};

use crate::types::{Duty, DutyType, SlotNumber};
use chrono::{DateTime, Utc};
use pluto_eth2api::EthBeaconNodeApiClientError;
use std::{collections::HashSet, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    time::sleep,
};
use tokio_util::sync::CancellationToken;

/// A safe far-future duration (~10 years) for timeout calculations.
/// Using Duration::MAX can cause panics when computing Instant::now() +
/// duration, so we use a large but representable value instead.
const FAR_FUTURE_DURATION: Duration = Duration::from_secs(3600 * 24 * 365 * 10);

/// Error types for deadline operations.
#[derive(Debug, thiserror::Error)]
pub enum DeadlineError {
    /// Failed to fetch beacon node configuration.
    #[error("Failed to fetch beacon node configuration: {0}")]
    BeaconNodeConfigError(#[from] EthBeaconNodeApiClientError),

    /// Arithmetic overflow in deadline calculation.
    #[error("Arithmetic overflow in deadline calculation")]
    ArithmeticOverflow,

    /// Duration conversion failed.
    #[error("Duration conversion failed")]
    DurationConversion,

    /// DateTime calculation failed.
    #[error("DateTime calculation failed")]
    DateTimeCalculation,
}

/// Result type for deadline operations.
pub type Result<T> = std::result::Result<T, DeadlineError>;

/// Converts a `std::time::Duration` to `chrono::Duration`.
fn to_chrono_duration(duration: Duration) -> Result<chrono::Duration> {
    chrono::Duration::from_std(duration).map_err(|_| DeadlineError::DurationConversion)
}

/// Outcome of [`DeadlinerHandle::add`].
///
/// Spells out the four distinct cases so callers can react specifically (e.g.
/// drop a duty that already expired vs. log a calculator error).
///
/// # Charon parity
///
/// Charon's `Deadliner.Add` returns a single `bool`: `true` when the duty was
/// scheduled, `false` otherwise (the other three cases here — already expired,
/// no deadline, and calculator error — are all folded into `false` there). See
/// the [`Add` doc comment][charon-add].
///
/// [charon-add]: https://github.com/ObolNetwork/charon/blob/main/core/deadline.go#L37-L39
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOutcome {
    /// The duty was accepted and a timer is now armed for its deadline.
    Scheduled,
    /// The duty's deadline is already in the past — nothing scheduled.
    AlreadyExpired,
    /// The calculator reports this duty type has no deadline (e.g. Exit,
    /// BuilderRegistration). Not an error — just not tracked.
    NoDeadline,
    /// The calculator returned an error while computing the deadline.
    FailedToCompute,
}

/// Internal message type for adding duties to the deadliner.
struct DeadlineInput {
    duty: Duty,
    response_tx: oneshot::Sender<AddOutcome>,
}

/// Public-facing handle returned (paired with the expired-duty receiver) by
/// [`DeadlinerTask::start`]. Cloning is cheap and shares the same background
/// task — share it freely across producers inside one service.
#[derive(Clone)]
pub struct DeadlinerHandle {
    cancel_token: CancellationToken,
    input_tx: mpsc::Sender<DeadlineInput>,
}

impl DeadlinerHandle {
    /// Adds a duty for deadline scheduling.
    ///
    /// Idempotent: re-adding a duty already tracked returns
    /// [`AddOutcome::Scheduled`] again. See [`AddOutcome`] for the meaning of
    /// each variant.
    pub async fn add(&self, duty: Duty) -> AddOutcome {
        if self.cancel_token.is_cancelled() {
            return AddOutcome::FailedToCompute;
        }

        let (response_tx, response_rx) = oneshot::channel();
        let input = DeadlineInput { duty, response_tx };

        if self.input_tx.send(input).await.is_err() {
            return AddOutcome::FailedToCompute;
        }

        // `FailedToCompute` if the task dropped the sender (shutdown race).
        response_rx.await.unwrap_or(AddOutcome::FailedToCompute)
    }
}

/// Owned state of the background task that drives a [`DeadlinerHandle`]'s
/// duty timers. Held exclusively by the spawned task — that's why it lives
/// outside the public handle and `run_task` can take `mut self`.
/// Constructed and spawned via [`DeadlinerTask::start`].
pub struct DeadlinerTask<C> {
    cancel_token: CancellationToken,
    label: String,
    calculator: C,
    input_rx: mpsc::Receiver<DeadlineInput>,
    output_tx: mpsc::Sender<Duty>,

    duties: HashSet<Duty>,
    curr_duty: Duty,
    curr_deadline: DateTime<Utc>,
}

impl<C: DeadlineCalculator> DeadlinerTask<C> {
    /// Spawns the background task and returns a `(handle, expired_rx)` pair.
    /// The cloneable `handle` is for adding duties from any number of
    /// producers; `expired_rx` is the single consumer's receiver of expired
    /// duties. The background loop exits when `cancel_token` is cancelled.
    pub fn start(
        cancel_token: CancellationToken,
        label: impl Into<String>,
        calculator: C,
    ) -> (DeadlinerHandle, mpsc::Receiver<Duty>) {
        // Matches Charon's `outputBuffer = 10` — big enough for all duty
        // types expiring simultaneously while the consumer drains synchronously.
        const OUTPUT_BUFFER: usize = 10;
        // Charon uses an unbuffered input channel. tokio's `mpsc` requires
        // capacity >= 1, so we use 1; the per-input `oneshot` ack already
        // serializes writers, making this behaviorally equivalent.
        const INPUT_BUFFER: usize = 1;

        let label = label.into();
        let (input_tx, input_rx) = mpsc::channel(INPUT_BUFFER);
        let (output_tx, output_rx) = mpsc::channel(OUTPUT_BUFFER);

        let task = Self {
            cancel_token: cancel_token.clone(),
            label,
            calculator,
            input_rx,
            output_tx,
            duties: HashSet::new(),
            curr_duty: Duty::new(SlotNumber::new(0), DutyType::Unknown),
            curr_deadline: DateTime::<Utc>::MAX_UTC,
        };
        tokio::spawn(task.run_task());

        let handle = DeadlinerHandle {
            cancel_token,
            input_tx,
        };

        (handle, output_rx)
    }

    /// Background task that manages duty deadlines.
    async fn run_task(mut self) {
        let sleep_fut = sleep(self.remaining_duration());
        tokio::pin!(sleep_fut);

        loop {
            tokio::select! {
                biased;

                _ = self.cancel_token.cancelled() => {
                    return;
                }

                Some(input) = self.input_rx.recv() => {
                    if let Some(new_timer) = self.handle_input(input) {
                        sleep_fut.set(sleep(new_timer));
                    }
                }

                _ = &mut sleep_fut => {
                    match self.handle_expired() {
                        Some(new_timer) => sleep_fut.set(sleep(new_timer)),
                        None => return,
                    }
                }
            }
        }
    }

    /// Time remaining until `self.curr_deadline`, clamped to zero if it's
    /// already in the past or arithmetic overflows.
    fn remaining_duration(&self) -> Duration {
        let now = Utc::now();
        if self.curr_deadline < now {
            Duration::ZERO
        } else {
            self.curr_deadline
                .signed_duration_since(now)
                .to_std()
                .unwrap_or(FAR_FUTURE_DURATION)
        }
    }

    /// Recomputes `curr_duty`/`curr_deadline` to the duty in `self.duties`
    /// with the earliest deadline. If none of the tracked duties have a finite
    /// deadline, resets to the sentinel (unknown duty, `MAX_UTC`).
    fn recompute_curr(&mut self) {
        let mut curr_duty = Duty::new(SlotNumber::new(0), DutyType::Unknown);
        let mut curr_deadline = DateTime::<Utc>::MAX_UTC;

        for duty in &self.duties {
            match self.calculator.deadline(duty) {
                Ok(Some(deadline)) => {
                    if deadline < curr_deadline {
                        curr_duty = duty.clone();
                        curr_deadline = deadline;
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        label = %self.label,
                        duty = %duty,
                        error = %err,
                        "Failed to compute deadline for duty"
                    );
                }
                Ok(None) => {
                    // Duties that never expire are not scheduled.
                }
            }
        }

        self.curr_duty = curr_duty;
        self.curr_deadline = curr_deadline;
    }

    /// Handles a new duty arriving from `input_rx`. Returns `Some(timer)` if
    /// the sleep timer should be reset to wake earlier, `None` otherwise.
    fn handle_input(&mut self, input: DeadlineInput) -> Option<Duration> {
        let duty = input.duty;
        match self.calculator.deadline(&duty) {
            Ok(Some(deadline)) => {
                if deadline < Utc::now() {
                    let _ = input.response_tx.send(AddOutcome::AlreadyExpired);
                    return None;
                }
                let _ = input.response_tx.send(AddOutcome::Scheduled);
                self.duties.insert(duty);
                if deadline < self.curr_deadline {
                    self.recompute_curr();
                    Some(self.remaining_duration())
                } else {
                    None
                }
            }
            Err(err) => {
                tracing::warn!(
                    label = %self.label,
                    duty = %duty,
                    error = %err,
                    "Failed to compute deadline for duty"
                );
                let _ = input.response_tx.send(AddOutcome::FailedToCompute);
                None
            }
            Ok(None) => {
                // Duty type has no deadline (Exit, BuilderRegistration) —
                // not tracked.
                let _ = input.response_tx.send(AddOutcome::NoDeadline);
                None
            }
        }
    }

    /// Handles the sleep timer firing: emits the expired duty, advances state,
    /// and returns the next timer. Returns `None` if the output channel was
    /// closed and the task should exit.
    fn handle_expired(&mut self) -> Option<Duration> {
        use mpsc::error::TrySendError::*;
        // No real duties tracked: the sentinel `FAR_FUTURE_DURATION` timer
        // fired. Just reschedule rather than emit the `(Unknown, slot 0)`
        // sentinel duty to the consumer.
        if self.duties.is_empty() {
            return Some(self.remaining_duration());
        }
        let duty = self.curr_duty.clone();
        match self.output_tx.try_send(duty) {
            Ok(()) => {}
            Err(Full(curr_duty)) => {
                tracing::warn!(
                    label = %self.label,
                    duty = %curr_duty,
                    "Deadliner output channel full"
                );
            }
            Err(Closed(_)) => {
                return None;
            }
        }
        self.duties.remove(&self.curr_duty);
        self.recompute_curr();
        Some(self.remaining_duration())
    }
}

#[cfg(test)]
mod tests {
    use super::{msecs::Msecs, *};
    use crate::types::SlotNumber;
    use anyhow::{Context, Result, bail, ensure};
    use pluto_testutil::BeaconMock;
    use tokio::time::timeout;

    /// Creates a mock beacon node API server and returns the client.
    async fn create_mock_beacon_client(
        genesis_time: DateTime<Utc>,
        slot_duration_secs: u64,
        slots_per_epoch: u64,
    ) -> BeaconMock {
        BeaconMock::builder()
            .genesis_time(genesis_time)
            .genesis_validators_root([0; 32])
            .slot_duration(Duration::from_secs(slot_duration_secs))
            .slots_per_epoch(slots_per_epoch)
            .build()
            .await
            .expect("should create beacon mock")
    }

    /// Helper function to create expired duties, non-expired duties, and
    /// far-future duties (exit duties that `TestCalculator` schedules 1h out).
    fn setup_data() -> (Vec<Duty>, Vec<Duty>, Vec<Duty>) {
        let expired_duties = vec![
            Duty::new_attester_duty(SlotNumber::new(1)),
            Duty::new_proposer_duty(SlotNumber::new(2)),
            Duty::new_randao_duty(SlotNumber::new(3)),
        ];

        let non_expired_duties = vec![
            Duty::new_proposer_duty(SlotNumber::new(1)),
            Duty::new_attester_duty(SlotNumber::new(2)),
        ];

        let future_duties = vec![
            Duty::new_voluntary_exit_duty(SlotNumber::new(2)),
            Duty::new_voluntary_exit_duty(SlotNumber::new(4)),
        ];

        (expired_duties, non_expired_duties, future_duties)
    }

    /// Helper function to add duties to the deadliner and send results to a
    /// channel.
    async fn add_duties(
        duties: Vec<Duty>,
        deadliner: DeadlinerHandle,
        result_tx: mpsc::Sender<AddOutcome>,
    ) {
        for duty in duties {
            let outcome = deadliner.add(duty).await;
            let _ = result_tx.send(outcome).await;
        }
    }

    /// Test calculator: voluntary exits expire 1h from `start_time`, listed
    /// `expired` duties expired 1h ago, everything else expires at
    /// `start_time + slot * 500ms` (500ms per slot gives enough headroom for
    /// scheduling jitter, test completes within ~1–2s).
    struct TestCalculator {
        start_time: DateTime<Utc>,
        expired: HashSet<Duty>,
    }

    impl DeadlineCalculator for TestCalculator {
        fn deadline(&self, duty: &Duty) -> Result<Option<DateTime<Utc>>, DeadlineError> {
            let one_hour =
                chrono::Duration::try_hours(1).ok_or(DeadlineError::DurationConversion)?;
            if duty.duty_type == DutyType::Exit {
                self.start_time
                    .checked_add_signed(one_hour)
                    .ok_or(DeadlineError::DateTimeCalculation)
                    .map(Some)
            } else if self.expired.contains(duty) {
                self.start_time
                    .checked_sub_signed(one_hour)
                    .ok_or(DeadlineError::DateTimeCalculation)
                    .map(Some)
            } else {
                Msecs::new(500)
                    .checked_mul_slot(duty.slot)?
                    .add_to(self.start_time)
                    .map(Some)
            }
        }
    }

    #[tokio::test]
    async fn deadliner() -> Result<()> {
        let (expired_duties, non_expired_duties, future_duties) = setup_data();

        // Use real time with generous durations to avoid flakiness on loaded CI.
        let start_time = Utc::now();
        let expired_set: HashSet<_> = expired_duties.iter().cloned().collect();
        let calculator = TestCalculator {
            start_time,
            expired: expired_set,
        };

        let cancel_token = CancellationToken::new();
        let (deadliner, mut output_rx) =
            DeadlinerTask::start(cancel_token.clone(), "test", calculator);

        let (expired_tx, mut expired_rx) = mpsc::channel(100);
        let (non_expired_tx, mut non_expired_rx) = mpsc::channel(100);

        let expired_len = expired_duties.len();
        let non_expired_len = non_expired_duties.len();
        let future_duties_len = future_duties.len();

        let handler_expired =
            tokio::spawn(add_duties(expired_duties, deadliner.clone(), expired_tx));
        let handler_non_expired = tokio::spawn(add_duties(
            non_expired_duties.clone(),
            deadliner.clone(),
            non_expired_tx.clone(),
        ));
        let handler_future_duties =
            tokio::spawn(add_duties(future_duties, deadliner.clone(), non_expired_tx));

        let (result_expired, result_non_expired, result_future_duties) =
            tokio::join!(handler_expired, handler_non_expired, handler_future_duties);
        result_expired?;
        result_non_expired?;
        result_future_duties?;

        for _ in 0..expired_len {
            let outcome = expired_rx.recv().await.context("expected expired ack")?;
            ensure!(
                outcome == AddOutcome::AlreadyExpired,
                "expired duties should report AlreadyExpired, got {outcome:?}"
            );
        }

        let added_count = non_expired_len
            .checked_add(future_duties_len)
            .context("added_count overflow")?;
        for _ in 0..added_count {
            let outcome = non_expired_rx
                .recv()
                .await
                .context("expected non-expired ack")?;
            ensure!(
                outcome == AddOutcome::Scheduled,
                "non-expired duties should be Scheduled, got {outcome:?}"
            );
        }

        // Collect expired duties from output channel.
        // Timeout must exceed the longest non-expired deadline (~1s for slot 2).
        let mut actual_duties = Vec::new();
        for _ in 0..non_expired_len {
            let duty = timeout(Duration::from_secs(5), output_rx.recv())
                .await
                .context("timeout waiting for expired duty")?
                .context("output channel closed before duty arrived")?;
            actual_duties.push(duty);
        }

        actual_duties.sort_by_key(|d| d.slot.inner());
        let mut expected_duties = non_expired_duties;
        expected_duties.sort_by_key(|d| d.slot.inner());

        assert_eq!(expected_duties, actual_duties);

        cancel_token.cancel();
        Ok(())
    }

    /// Two duties with clearly different deadlines must arrive on the output
    /// channel in deadline order — that's the actual contract of the
    /// deadliner.
    #[tokio::test]
    async fn expired_duties_arrive_in_deadline_order() -> Result<()> {
        let start_time = Utc::now();
        let calculator = TestCalculator {
            start_time,
            expired: HashSet::new(),
        };

        let cancel_token = CancellationToken::new();
        let (deadliner, mut output_rx) =
            DeadlinerTask::start(cancel_token.clone(), "order-test", calculator);

        // TestCalculator: deadline = start_time + slot * 500ms.
        // Insert the later one first to make sure ordering is by deadline,
        // not insertion order.
        let later = Duty::new_attester_duty(SlotNumber::new(3));
        let earlier = Duty::new_attester_duty(SlotNumber::new(1));

        let added_later = deadliner.add(later.clone()).await;
        ensure!(
            added_later == AddOutcome::Scheduled,
            "later duty should be Scheduled, got {added_later:?}"
        );
        let added_earlier = deadliner.add(earlier.clone()).await;
        ensure!(
            added_earlier == AddOutcome::Scheduled,
            "earlier duty should be Scheduled, got {added_earlier:?}"
        );

        let first = timeout(Duration::from_secs(5), output_rx.recv())
            .await
            .context("timeout waiting for first duty")?
            .context("output channel closed before first duty")?;
        ensure!(first == earlier, "expected earlier duty first, got {first}");

        let second = timeout(Duration::from_secs(5), output_rx.recv())
            .await
            .context("timeout waiting for second duty")?
            .context("output channel closed before second duty")?;
        ensure!(second == later, "expected later duty second, got {second}");

        cancel_token.cancel();
        Ok(())
    }

    #[test_case::test_case(DutyType::Exit ; "exit")]
    #[test_case::test_case(DutyType::BuilderRegistration ; "builder_registration")]
    #[tokio::test]
    async fn never_expire_duties(duty_type: DutyType) -> Result<()> {
        let genesis_time =
            DateTime::from_timestamp(1606824023, 0).context("invalid genesis timestamp")?;
        let slot_duration_secs = 12;
        let slots_per_epoch = 32;

        let mock =
            create_mock_beacon_client(genesis_time, slot_duration_secs, slots_per_epoch).await;
        let client = mock.client();

        let calculator = DutyDeadlineCalculator::from_client(client).await?;

        let duty = Duty::new(SlotNumber::new(100), duty_type);
        let result = calculator.deadline(&duty)?;

        assert_eq!(result, None, "duty should never expire");
        Ok(())
    }

    #[test_case::test_case(DutyType::Proposer ; "proposer")]
    #[test_case::test_case(DutyType::Attester ; "attester")]
    #[test_case::test_case(DutyType::Aggregator ; "aggregator")]
    #[test_case::test_case(DutyType::PrepareAggregator ; "prepare_aggregator")]
    #[test_case::test_case(DutyType::SyncMessage ; "sync_message")]
    #[test_case::test_case(DutyType::SyncContribution ; "sync_contribution")]
    #[test_case::test_case(DutyType::Randao ; "randao")]
    #[test_case::test_case(DutyType::InfoSync ; "info_sync")]
    #[test_case::test_case(DutyType::PrepareSyncContribution ; "prepare_sync_contribution")]
    #[tokio::test]
    async fn duty_deadline_durations(duty_type: DutyType) -> Result<()> {
        let genesis_time =
            DateTime::from_timestamp(1606824023, 0).context("invalid genesis timestamp")?;
        let slot_duration_secs = 12;
        let slots_per_epoch = 32;

        let mock =
            create_mock_beacon_client(genesis_time, slot_duration_secs, slots_per_epoch).await;
        let client = mock.client();

        let slot_duration = Duration::from_secs(slot_duration_secs);
        let margin = slot_duration.checked_div(12).context("margin overflow")?;

        // Use a fixed slot for deterministic testing
        let current_slot = 100u64;

        let slot_start = {
            let offset_secs = current_slot
                .checked_mul(slot_duration.as_secs())
                .context("slot offset overflow")?;
            let offset_i64 = i64::try_from(offset_secs).context("offset doesn't fit in i64")?;
            let offset =
                chrono::Duration::try_seconds(offset_i64).context("offset out of chrono range")?;
            genesis_time
                .checked_add_signed(offset)
                .context("slot_start overflow")?
        };

        let calculator = DutyDeadlineCalculator::from_client(client).await?;

        let expected_duration = match duty_type {
            DutyType::Proposer | DutyType::Randao => slot_duration
                .checked_div(3)
                .and_then(|d| d.checked_add(margin))
                .context("proposer/randao duration overflow")?,
            DutyType::Attester | DutyType::Aggregator | DutyType::PrepareAggregator => {
                slot_duration
                    .checked_mul(2)
                    .and_then(|d| d.checked_add(margin))
                    .context("attester duration overflow")?
            }
            DutyType::SyncMessage => slot_duration
                .checked_mul(2)
                .and_then(|d| d.checked_div(3))
                .and_then(|d| d.checked_add(margin))
                .context("sync_message duration overflow")?,
            DutyType::SyncContribution | DutyType::InfoSync | DutyType::PrepareSyncContribution => {
                slot_duration
                    .checked_add(margin)
                    .context("default duration overflow")?
            }
            _ => bail!("unexpected duty type: {duty_type:?}"),
        };

        let slot = SlotNumber::new(current_slot);
        let duty = Duty::new(slot, duty_type.clone());

        let expected_deadline = slot_start
            .checked_add_signed(to_chrono_duration(expected_duration)?)
            .context("expected_deadline overflow")?;

        let deadline = calculator
            .deadline(&duty)?
            .context("duty should have a deadline")?;

        assert_eq!(
            deadline, expected_deadline,
            "duty {duty_type:?}: deadline mismatch"
        );
        Ok(())
    }
}
