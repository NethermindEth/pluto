//! Duty deadline tracking and notification functionality.
//!
//! This module provides the [`Deadliner`] trait for tracking duty deadlines
//! and notifying when duties expire. It implements a background task that
//! manages timers for multiple duties and sends expired duties to a channel.
//!
//! # Example
//!
//! ```no_run
//! use chrono::{DateTime, Utc};
//! use pluto_core::{
//!     deadline::{DeadlineFunc, new_deadliner},
//!     types::{Duty, DutyType, SlotNumber},
//! };
//! use std::sync::Arc;
//! use tokio_util::sync::CancellationToken;
//!
//! # async fn example() {
//! let cancel_token = CancellationToken::new();
//!
//! // Define a deadline function
//! let deadline_func: DeadlineFunc = Arc::new(|_duty| {
//!     let deadline = DateTime::from_timestamp(1000, 0).unwrap();
//!     Ok(Some(deadline))
//! });
//!
//! let deadliner = new_deadliner(cancel_token, "example", deadline_func);
//!
//! // Add a duty
//! let duty = Duty::new_attester_duty(SlotNumber::new(1));
//! let added = deadliner.add(duty).await;
//!
//! // Receive expired duties
//! if let Some(mut rx) = deadliner.c() {
//!     while let Some(expired_duty) = rx.recv().await {
//!         println!("Duty expired: {}", expired_duty);
//!     }
//! }
//! # }
//! ```

mod calculator;

pub use calculator::{DeadlineCalculator, DutyDeadlineCalculator};

use crate::types::{Duty, DutyType, SlotNumber};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pluto_eth2api::{EthBeaconNodeApiClient, EthBeaconNodeApiClientError};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

/// A safe far-future duration (~10 years) for timeout calculations.
/// Using Duration::MAX can cause panics when computing Instant::now() +
/// duration, so we use a large but representable value instead.
const FAR_FUTURE_DURATION: Duration = Duration::from_secs(3600 * 24 * 365 * 10);

/// Type alias for the deadline function.
///
/// Takes a duty and returns an optional deadline.
/// Returns `Ok(Some(deadline))` if the duty expires at the given time.
/// Returns `Ok(None)` if the duty never expires.
pub type DeadlineFunc = Arc<dyn Fn(Duty) -> Result<Option<DateTime<Utc>>> + Send + Sync>;

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

/// Deadliner provides duty deadline functionality.
///
/// The `c()` method returns a channel for receiving expired duties.
/// It may only be called once and the returned channel should be used
/// by a single task. Multiple instances are required for different
/// components and use cases.
#[async_trait]
pub trait Deadliner: Send + Sync {
    /// Adds a duty for deadline scheduling.
    ///
    /// Returns `true` if the duty was added for future deadline scheduling.
    /// This method is idempotent and returns `true` if the duty was previously
    /// added and still awaits deadline scheduling.
    ///
    /// Returns `false` if:
    /// - The duty has already expired and cannot be scheduled
    /// - The duty never expires (e.g., Exit, BuilderRegistration)
    async fn add(&self, duty: Duty) -> bool;

    /// Returns the channel for receiving deadlined duties.
    ///
    /// This method may only be called once and returns `None` on subsequent
    /// calls. The returned channel should only be used by a single task.
    fn c(&self) -> Option<mpsc::Receiver<Duty>>;
}

/// Creates a deadline function from the Ethereum 2.0 beacon node configuration.
///
/// Fetches genesis time and slot duration from the beacon node and returns
/// a function that calculates deadlines for each duty type.
///
/// # Errors
///
/// Returns an error if fetching genesis time or slots config fails.
pub async fn new_duty_deadline_func(client: &EthBeaconNodeApiClient) -> Result<DeadlineFunc> {
    let genesis_time = client.fetch_genesis_time().await?;
    let (slot_duration, _slots_per_epoch) = client.fetch_slots_config().await?;

    // Convert std::time::Duration to chrono::Duration for slot_duration
    let slot_duration = to_chrono_duration(slot_duration)?;

    Ok(Arc::new(move |duty: Duty| {
        // Exit and BuilderRegistration duties never expire
        if matches!(
            duty.duty_type,
            DutyType::Exit | DutyType::BuilderRegistration
        ) {
            return Ok(None);
        }

        // Calculate slot start time
        // start = genesis_time + (slot * slot_duration)
        let slot_secs = duty
            .slot
            .inner()
            .checked_mul(
                u64::try_from(slot_duration.num_seconds())
                    .map_err(|_| DeadlineError::ArithmeticOverflow)?,
            )
            .ok_or(DeadlineError::ArithmeticOverflow)?;
        let secs_i64 = i64::try_from(slot_secs).map_err(|_| DeadlineError::ArithmeticOverflow)?;
        let slot_offset =
            chrono::Duration::try_seconds(secs_i64).ok_or(DeadlineError::DurationConversion)?;

        let start: DateTime<Utc> = genesis_time
            .checked_add_signed(slot_offset)
            .ok_or(DeadlineError::DateTimeCalculation)?;

        // Calculate margin: slot_duration / 12 (this whole fn is scheduled
        // for removal — see new DutyDeadlineCalculator in deadline::calculator)
        let margin = slot_duration
            .checked_div(12)
            .ok_or(DeadlineError::ArithmeticOverflow)?;

        // Calculate duty-specific duration
        let duration = match duty.duty_type {
            DutyType::Proposer | DutyType::Randao => {
                // duration = slot_duration / 3
                slot_duration
                    .checked_div(3)
                    .ok_or(DeadlineError::ArithmeticOverflow)?
            }
            DutyType::SyncMessage => {
                // duration = 2 * slot_duration / 3
                slot_duration
                    .checked_mul(2)
                    .and_then(|s| s.checked_div(3))
                    .ok_or(DeadlineError::ArithmeticOverflow)?
            }
            DutyType::Attester | DutyType::Aggregator | DutyType::PrepareAggregator => {
                // duration = 2 * slot_duration
                // Even though attestations and aggregations are acceptable after 2 slots,
                // the rewards are heavily diminished.
                slot_duration
                    .checked_mul(2)
                    .ok_or(DeadlineError::ArithmeticOverflow)?
            }
            _ => {
                // Default: duration = slot_duration
                slot_duration
            }
        };

        // Calculate final deadline: start + duration + margin
        let deadline = start
            .checked_add_signed(duration)
            .and_then(|t| t.checked_add_signed(margin))
            .ok_or(DeadlineError::DateTimeCalculation)?;

        Ok(Some(deadline))
    }))
}

/// Gets the duty with the earliest deadline from the duties map.
///
/// Returns a tuple of (duty, deadline). If no duties are available,
/// returns a sentinel far-future date (9999-01-01).
fn get_curr_duty(
    duties: &HashSet<Duty>,
    calculator: &dyn DeadlineCalculator,
) -> (Duty, DateTime<Utc>) {
    let mut curr_duty = Duty::new(SlotNumber::new(0), DutyType::Unknown);

    // Use far-future sentinel date (9999-01-01) matching Go implementation
    // This timestamp is a known constant and will never fail
    let mut curr_deadline = DateTime::<Utc>::MAX_UTC;

    for duty in duties.iter() {
        match calculator.deadline(duty) {
            Ok(Some(duty_deadline)) => {
                // Update if this duty has an earlier deadline
                if duty_deadline < curr_deadline {
                    curr_duty = duty.clone();
                    curr_deadline = duty_deadline;
                }
            }
            Err(err) => {
                tracing::warn!(
                    duty = %duty,
                    error = %err,
                    "Failed to compute deadline for duty"
                );
            }
            Ok(None) => {
                // Ignore duties that never expire
            }
        }
    }

    (curr_duty, curr_deadline)
}

/// Internal message type for adding duties to the deadliner.
struct DeadlineInput {
    duty: Duty,
    response_tx: oneshot::Sender<bool>,
}

/// Implementation of the Deadliner trait.
struct DeadlinerImpl {
    cancel_token: CancellationToken,
    input_tx: mpsc::Sender<DeadlineInput>,
    output_rx: Mutex<Option<mpsc::Receiver<Duty>>>,
}

#[async_trait]
impl Deadliner for DeadlinerImpl {
    async fn add(&self, duty: Duty) -> bool {
        // Check if shut down
        if self.cancel_token.is_cancelled() {
            return false;
        }

        let (response_tx, response_rx) = oneshot::channel();
        let input = DeadlineInput { duty, response_tx };

        // Send the duty to the background task
        if self.input_tx.send(input).await.is_err() {
            return false;
        }

        // Wait for response
        response_rx.await.unwrap_or(false)
    }

    fn c(&self) -> Option<mpsc::Receiver<Duty>> {
        self.output_rx
            .lock()
            .ok()
            .and_then(|mut guard| guard.take())
    }
}

impl DeadlinerImpl {
    /// Background task that manages duty deadlines.
    ///
    /// This is an associated function (not a method) because the DeadlinerImpl
    /// is immediately wrapped in Arc<dyn Deadliner>, preventing mutable access.
    async fn run_task(
        cancel_token: CancellationToken,
        label: String,
        calculator: Arc<dyn DeadlineCalculator>,
        mut input_rx: mpsc::Receiver<DeadlineInput>,
        output_tx: mpsc::Sender<Duty>,
    ) {
        let mut duties: HashSet<Duty> = HashSet::new();
        let (mut curr_duty, mut curr_deadline) = get_curr_duty(&duties, &*calculator);

        // Create initial timer
        let now: DateTime<Utc> = Utc::now();
        let initial_duration = if curr_deadline < now {
            Duration::ZERO
        } else {
            curr_deadline
                .signed_duration_since(now)
                .to_std()
                .unwrap_or(FAR_FUTURE_DURATION)
        };
        let sleep_fut = sleep(initial_duration);
        tokio::pin!(sleep_fut);

        loop {
            tokio::select! {
                biased;

                _ = cancel_token.cancelled() => {
                    return;
                }

                Some(input) = input_rx.recv() => {
                    let duty = input.duty;
                    match calculator.deadline(&duty) {
                        Ok(Some(deadline)) => {
                            let now = Utc::now();
                            let expired = deadline < now;

                            let _ = input.response_tx.send(!expired);

                            // Ignore expired duties
                            if expired {
                                continue;
                            }

                            // Add duty to the map (idempotent)
                            duties.insert(duty);

                            // Update timer if this deadline is earlier
                            if deadline < curr_deadline {
                                let (new_duty, new_deadline) = get_curr_duty(&duties, &*calculator);
                                curr_duty = new_duty;
                                curr_deadline = new_deadline;

                                let duration = curr_deadline
                                    .signed_duration_since(Utc::now())
                                    .to_std()
                                    .unwrap_or(FAR_FUTURE_DURATION);
                                sleep_fut.set(sleep(duration));
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                label = %label,
                                duty = %duty,
                                error = %err,
                                "Failed to compute deadline for duty"
                            );
                            let _ = input.response_tx.send(false);
                        }
                        Ok(None) => {
                            // Drop duties that never expire
                            let _ = input.response_tx.send(false);
                        }
                    }
                }

                _ = &mut sleep_fut => {
                    // Deadline expired - send duty to output channel
                    match output_tx.try_send(curr_duty.clone()) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                label = %label,
                                duty = %curr_duty,
                                "Deadliner output channel full"
                            );
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            return;
                        }
                    }

                    // Remove duty from map
                    duties.remove(&curr_duty);

                    // Update to next duty
                    let (new_duty, new_deadline) = get_curr_duty(&duties, &*calculator);
                    curr_duty = new_duty;
                    curr_deadline = new_deadline;

                    let duration = curr_deadline
                        .signed_duration_since(Utc::now())
                        .to_std()
                        .unwrap_or(FAR_FUTURE_DURATION);
                    sleep_fut.set(sleep(duration));
                }
            }
        }
    }
}

/// Creates a new Deadliner instance.
///
/// Starts a background task that manages duty deadlines and sends expired
/// duties to a channel. The background task runs until the cancellation token
/// is cancelled.
///
/// # Arguments
///
/// * `cancel_token` - Token to cancel the background task
/// * `label` - Label for logging purposes
/// * `calculator` - Computes per-duty deadlines (e.g.
///   [`DutyDeadlineCalculator`])
///
/// # Returns
///
/// An Arc-wrapped Deadliner trait object
pub fn new_deadliner(
    cancel_token: CancellationToken,
    label: impl Into<String>,
    calculator: Arc<dyn DeadlineCalculator>,
) -> Arc<dyn Deadliner> {
    const OUTPUT_BUFFER: usize = 256;
    const INPUT_BUFFER: usize = 256;

    let label = label.into();
    let (input_tx, input_rx) = mpsc::channel(INPUT_BUFFER);
    let (output_tx, output_rx) = mpsc::channel(OUTPUT_BUFFER);

    let impl_instance: Arc<dyn Deadliner> = Arc::new(DeadlinerImpl {
        cancel_token: cancel_token.clone(),
        input_tx,
        output_rx: Mutex::new(Some(output_rx)),
    });

    tokio::spawn(DeadlinerImpl::run_task(
        cancel_token,
        label,
        calculator,
        input_rx,
        output_tx,
    ));

    impl_instance
}

#[cfg(test)]
mod tests {
    use super::{calculator::Millis, *};
    use crate::types::SlotNumber;
    use anyhow::{Context, Result, bail};
    use pluto_testutil::BeaconMock;

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
    /// voluntary exits.
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

        let voluntary_exits = vec![
            Duty::new_voluntary_exit_duty(SlotNumber::new(2)),
            Duty::new_voluntary_exit_duty(SlotNumber::new(4)),
        ];

        (expired_duties, non_expired_duties, voluntary_exits)
    }

    /// Helper function to add duties to the deadliner and send results to a
    /// channel.
    async fn add_duties(
        duties: Vec<Duty>,
        deadliner: Arc<dyn Deadliner>,
        result_tx: mpsc::Sender<bool>,
    ) {
        for duty in duties {
            let added = deadliner.add(duty).await;
            let _ = result_tx.send(added).await;
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
                Millis::new(500)
                    .checked_mul_slot(duty.slot)?
                    .add_to(self.start_time)
                    .map(Some)
            }
        }
    }

    #[tokio::test]
    async fn deadliner() -> Result<()> {
        let (expired_duties, non_expired_duties, voluntary_exits) = setup_data();

        // Use real time with generous durations to avoid flakiness on loaded CI.
        let start_time = Utc::now();
        let expired_set: HashSet<_> = expired_duties.iter().cloned().collect();
        let calculator = TestCalculator {
            start_time,
            expired: expired_set,
        };

        let cancel_token = CancellationToken::new();
        let deadliner = new_deadliner(cancel_token.clone(), "test", Arc::new(calculator));

        let mut output_rx = deadliner.c().context("output receiver already taken")?;

        let (expired_tx, mut expired_rx) = mpsc::channel(100);
        let (non_expired_tx, mut non_expired_rx) = mpsc::channel(100);

        let expired_len = expired_duties.len();
        let non_expired_len = non_expired_duties.len();
        let voluntary_exits_len = voluntary_exits.len();

        let handler_expired = tokio::spawn(add_duties(
            expired_duties,
            Arc::clone(&deadliner),
            expired_tx,
        ));
        let handler_non_expired = tokio::spawn(add_duties(
            non_expired_duties.clone(),
            Arc::clone(&deadliner),
            non_expired_tx.clone(),
        ));
        let handler_voluntary_exits = tokio::spawn(add_duties(
            voluntary_exits,
            Arc::clone(&deadliner),
            non_expired_tx,
        ));

        let (result_expired, result_non_expired, result_voluntary_exits) = tokio::join!(
            handler_expired,
            handler_non_expired,
            handler_voluntary_exits
        );
        result_expired?;
        result_non_expired?;
        result_voluntary_exits?;

        for _ in 0..expired_len {
            let result = expired_rx.recv().await.context("expected expired ack")?;
            assert!(!result, "expired duties should return false");
        }

        let added_count = non_expired_len
            .checked_add(voluntary_exits_len)
            .context("added_count overflow")?;
        for _ in 0..added_count {
            let result = non_expired_rx
                .recv()
                .await
                .context("expected non-expired ack")?;
            assert!(result, "non-expired duties should return true");
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
