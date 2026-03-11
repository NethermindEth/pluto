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
use crate::types::{Duty, DutyType, SlotNumber};
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use pluto_eth2api::{EthBeaconNodeApiClient, EthBeaconNodeApiClientError};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};
use futures::future::FutureExt;
use tokio_util::sync::CancellationToken;

/// Fraction of slot duration to use as a margin for network delays.
const MARGIN_FACTOR: i32 = 12;

/// Type alias for the deadline function.
///
/// Takes a duty and returns an optional deadline.
/// Returns `Ok(Some(deadline))` if the duty expires at the given time.
/// Returns `Ok(None)` if the duty never expires.
pub type DeadlineFunc = Arc<dyn Fn(Duty) -> Result<Option<DateTime<Utc>>> + Send + Sync>;

/// Error types for deadline operations.
#[derive(Debug, thiserror::Error)]
pub enum DeadlineError {
    /// Failed to fetch genesis time from beacon node.
    #[error("Failed to fetch genesis time: {0}")]
    FetchGenesisTime(#[from] EthBeaconNodeApiClientError),

    /// Deadliner has been shut down.
    #[error("Deadliner has been shut down")]
    Shutdown,

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
fn to_chrono_duration(duration: std::time::Duration) -> Result<chrono::Duration> {
    chrono::Duration::from_std(duration).map_err(|_| DeadlineError::DurationConversion)
}

/// Converts seconds (u64) to `chrono::Duration`.
fn secs_to_chrono(secs: u64) -> Result<chrono::Duration> {
    let secs_i64 = i64::try_from(secs).map_err(|_| DeadlineError::ArithmeticOverflow)?;
    chrono::Duration::try_seconds(secs_i64).ok_or(DeadlineError::DurationConversion)
}

/// Deadliner provides duty deadline functionality.
///
/// The `c()` method returns a channel for receiving expired duties.
/// It may only be called once and the returned channel should be used
/// by a single task. Multiple instances are required for different
/// components and use cases.
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
    fn add(&self, duty: Duty) -> BoxFuture<'_, bool>;

    /// Returns the channel for receiving deadlined duties.
    ///
    /// This method may only be called once and returns `None` on subsequent
    /// calls. The returned channel should only be used by a single task.
    fn c(&self) -> Option<tokio::sync::mpsc::Receiver<Duty>>;
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
        match duty.duty_type {
            DutyType::Exit | DutyType::BuilderRegistration => {
                return Ok(None);
            }
            _ => {}
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
        let slot_offset = secs_to_chrono(slot_secs)?;

        let start: DateTime<Utc> = genesis_time
            .checked_add_signed(slot_offset)
            .ok_or(DeadlineError::DateTimeCalculation)?;

        // Calculate margin: slot_duration / MARGIN_FACTOR
        let margin = slot_duration
            .checked_div(MARGIN_FACTOR)
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
fn get_curr_duty(duties: &HashSet<Duty>, deadline_func: &DeadlineFunc) -> (Duty, DateTime<Utc>) {
    let mut curr_duty = Duty::new(SlotNumber::new(0), DutyType::Unknown);

    // Use far-future sentinel date (9999-01-01) matching Go implementation
    // This timestamp is a known constant and will never fail
    let mut curr_deadline =
        DateTime::from_timestamp(253402300799, 0).unwrap_or(DateTime::<Utc>::MAX_UTC);

    for duty in duties.iter() {
        let Ok(deadline_opt) = deadline_func(duty.clone()) else {
            continue;
        };

        // Ignore duties that never expire
        let Some(duty_deadline) = deadline_opt else {
            continue;
        };

        // Update if this duty has an earlier deadline
        if duty_deadline < curr_deadline {
            curr_duty = duty.clone();
            curr_deadline = duty_deadline;
        }
    }

    (curr_duty, curr_deadline)
}

/// Internal message type for adding duties to the deadliner.
struct DeadlineInput {
    duty: Duty,
    response_tx: tokio::sync::oneshot::Sender<bool>,
}

/// Implementation of the Deadliner trait.
struct DeadlinerImpl {
    cancel_token: CancellationToken,
    input_tx: tokio::sync::mpsc::UnboundedSender<DeadlineInput>,
    output_rx: Arc<Mutex<Option<tokio::sync::mpsc::Receiver<Duty>>>>,
}

impl Deadliner for DeadlinerImpl {
    fn add(&self, duty: Duty) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            // Check if shut down
            if self.cancel_token.is_cancelled() {
                return false;
            }

            let (response_tx, response_rx) = tokio::sync::oneshot::channel();
            let input = DeadlineInput { duty, response_tx };

            // Send the duty to the background task
            if self.input_tx.send(input).is_err() {
                return false;
            }

            // Wait for response
            response_rx.await.unwrap_or(false)
        })
    }

    fn c(&self) -> Option<tokio::sync::mpsc::Receiver<Duty>> {
        self.output_rx
            .lock()
            .ok()
            .and_then(|mut guard| guard.take())
    }
}

/// Clock trait for abstracting time operations.
trait Clock: Send + Sync {
    /// Returns the current time.
    fn now(&self) -> DateTime<Utc>;

    /// Creates a sleep future that completes after the given duration.
    fn sleep(&self, duration: std::time::Duration) -> BoxFuture<'static, ()>;
}

/// Real clock implementation using tokio::time.
struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn sleep(&self, duration: std::time::Duration) -> BoxFuture<'static, ()> {
        tokio::time::sleep(duration).boxed()
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
        deadline_func: DeadlineFunc,
        clock: Arc<dyn Clock>,
        mut input_rx: tokio::sync::mpsc::UnboundedReceiver<DeadlineInput>,
        output_tx: tokio::sync::mpsc::Sender<Duty>,
    ) {
        let mut duties: HashSet<Duty> = HashSet::new();
        let (mut curr_duty, mut curr_deadline) = get_curr_duty(&duties, &deadline_func);

        // Create initial timer
        let now = clock.now();
        let initial_duration = curr_deadline
            .signed_duration_since(now)
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        let mut timer = clock.sleep(initial_duration);

        loop {
            tokio::select! {
                biased;

                _ = cancel_token.cancelled() => {
                    return;
                }

                Some(input) = input_rx.recv() => {
                    let duty = input.duty;
                    let Ok(deadline_opt) = deadline_func(duty.clone()) else {
                        let _ = input.response_tx.send(false);
                        continue;
                    };

                    // Drop duties that never expire
                    let Some(deadline) = deadline_opt else {
                        let _ = input.response_tx.send(false);
                        continue;
                    };

                    let now = clock.now();
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
                        let (new_duty, new_deadline) = get_curr_duty(&duties, &deadline_func);
                        curr_duty = new_duty;
                        curr_deadline = new_deadline;

                        let duration = curr_deadline
                            .signed_duration_since(clock.now())
                            .to_std()
                            .unwrap_or(std::time::Duration::ZERO);
                        timer = clock.sleep(duration);
                    }
                }

                _ = &mut timer => {
                    // Deadline expired - send duty to output channel
                    match output_tx.try_send(curr_duty.clone()) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                label = %label,
                                duty = %curr_duty,
                                "Deadliner output channel full"
                            );
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            return;
                        }
                    }

                    // Remove duty from map
                    duties.remove(&curr_duty);

                    // Update to next duty
                    let (new_duty, new_deadline) = get_curr_duty(&duties, &deadline_func);
                    curr_duty = new_duty;
                    curr_deadline = new_deadline;

                    let duration = curr_deadline
                        .signed_duration_since(clock.now())
                        .to_std()
                        .unwrap_or(std::time::Duration::ZERO);
                    timer = clock.sleep(duration);
                }
            }
        }
    }

    /// Internal constructor for creating a deadliner with a specific clock.
    fn new_internal(
        cancel_token: CancellationToken,
        label: impl Into<String>,
        deadline_func: DeadlineFunc,
        clock: Arc<dyn Clock>,
    ) -> Arc<dyn Deadliner> {
        const OUTPUT_BUFFER: usize = 10;

        let label = label.into();
        let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel();
        let (output_tx, output_rx) = tokio::sync::mpsc::channel(OUTPUT_BUFFER);

        let impl_instance: Arc<dyn Deadliner> = Arc::new(DeadlinerImpl {
            cancel_token: cancel_token.clone(),
            input_tx,
            output_rx: Arc::new(Mutex::new(Some(output_rx))),
        });

        // Spawn background task
        tokio::spawn(Self::run_task(
            cancel_token,
            label,
            deadline_func,
            clock,
            input_rx,
            output_tx,
        ));

        impl_instance
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
/// * `deadline_func` - Function that calculates deadlines for duties
///
/// # Returns
///
/// An Arc-wrapped Deadliner trait object
pub fn new_deadliner(
    cancel_token: CancellationToken,
    label: impl Into<String>,
    deadline_func: DeadlineFunc,
) -> Arc<dyn Deadliner> {
    DeadlinerImpl::new_internal(cancel_token, label, deadline_func, Arc::new(RealClock))
}

/// Creates a new Deadliner instance for testing with a fake clock.
///
/// This constructor is intended for use in tests where you need to control
/// time progression.
///
/// # Arguments
///
/// * `cancel_token` - Token to cancel the background task
/// * `label` - Label for logging purposes
/// * `deadline_func` - Function that calculates deadlines for duties
/// * `clock` - Test clock for controlling time in tests
///
/// # Returns
///
/// An Arc-wrapped Deadliner trait object
#[cfg(test)]
fn new_deadliner_for_test(
    cancel_token: CancellationToken,
    label: impl Into<String>,
    deadline_func: DeadlineFunc,
    clock: Arc<TestClock>,
) -> Arc<dyn Deadliner> {
    DeadlinerImpl::new_internal(cancel_token, label, deadline_func, clock)
}


/// Fake clock implementation for testing.
#[cfg(test)]
type WakerList = Vec<(DateTime<Utc>, std::task::Waker)>;

#[cfg(test)]
struct TestClock {
    start: std::sync::Arc<std::sync::Mutex<DateTime<Utc>>>,
    wakers: std::sync::Arc<std::sync::Mutex<WakerList>>,
}

#[cfg(test)]
impl TestClock {
    fn new(start: DateTime<Utc>) -> Self {
        Self {
            start: std::sync::Arc::new(std::sync::Mutex::new(start)),
            wakers: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn advance(&self, duration: std::time::Duration) {
        let new_time = {
            let mut start = self.start.lock().unwrap();
            let chrono_duration = chrono::Duration::from_std(duration).unwrap();
            *start = start.checked_add_signed(chrono_duration).unwrap();
            *start
        };

        // Wake all timers that have expired
        let mut wakers = self.wakers.lock().unwrap();
        let (expired, pending): (Vec<_>, Vec<_>) = wakers
            .drain(..)
            .partition(|(deadline, _)| *deadline <= new_time);
        *wakers = pending;

        // Wake expired futures
        for (_, waker) in expired {
            waker.wake();
        }
    }
}

#[cfg(test)]
impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.start.lock().unwrap()
    }

    fn sleep(&self, duration: std::time::Duration) -> BoxFuture<'static, ()> {
        let deadline = self
            .now()
            .checked_add_signed(chrono::Duration::from_std(duration).unwrap())
            .unwrap();
        let wakers = Arc::clone(&self.wakers);
        let start = Arc::clone(&self.start);

        Box::pin(std::future::poll_fn(move |cx| {
            let now = *start.lock().unwrap();
            if now >= deadline {
                std::task::Poll::Ready(())
            } else {
                // Register waker
                let mut wakers = wakers.lock().unwrap();
                // Check if this waker is already registered for this deadline
                if !wakers.iter().any(|(d, _)| *d == deadline) {
                    wakers.push((deadline, cx.waker().clone()));
                }
                std::task::Poll::Pending
            }
        }))
    }
}