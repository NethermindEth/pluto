use crate::types::{Duty, DutyType};
use chrono::{DateTime, Utc};
use pluto_eth2api::EthBeaconNodeApiClientError;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// Fraction of slot duration to use as a margin for network delays.
const MARGIN_FACTOR: i32 = 12;

/// Type alias for the deadline function.
///
/// Takes a duty and returns an optional deadline.
/// Returns `Ok(Some(deadline))` if the duty expires at the given time.
/// Returns `Ok(None)` if the duty never expires.
pub type DeadlineFunc = Arc<dyn Fn(&Duty) -> Result<Option<DateTime<Utc>>> + Send + Sync>;

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

/// Creates a deadline function from the Ethereum 2.0 beacon node configuration.
///
/// Fetches genesis time and slot duration from the beacon node and returns
/// a function that calculates deadlines for each duty type.
///
/// # Errors
///
/// Returns an error if fetching genesis time or slots config fails.
pub async fn new_duty_deadline_func(
    client: &pluto_eth2api::client::EthBeaconNodeApiClient,
) -> Result<DeadlineFunc> {
    let genesis_time = client.fetch_genesis_time().await?;
    let (slot_duration, _slots_per_epoch) = client.fetch_slots_config().await?;

    let slot_duration =
        chrono::Duration::from_std(slot_duration).map_err(|_| DeadlineError::DurationConversion)?;

    Ok(Arc::new(move |duty: &Duty| {
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
        let slot_offset = {
            let secs_i64 =
                i64::try_from(slot_secs).map_err(|_| DeadlineError::ArithmeticOverflow)?;
            chrono::Duration::try_seconds(secs_i64).ok_or(DeadlineError::DurationConversion)
        }?;

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

/// Handle for pushing duties into the collection. Can be cloned and shared
/// across multiple producer tasks.
#[derive(Clone)]
pub struct DeadlineSender {
    tx: mpsc::UnboundedSender<(Duty, oneshot::Sender<bool>)>,
}

/// Handle for popping the next expired Duty.
pub struct DeadlineReceiver {
    rx: mpsc::UnboundedReceiver<Duty>,
}

/// Creates a new pair of [`DeadlineSender`] and [`DeadlineReceiver`].
///
/// The sender can be cloned and shared across multiple producer tasks.
/// The receiver yields `Duty` results in the order they expire.
pub fn new<FClock>(now: FClock, func: DeadlineFunc) -> (DeadlineSender, DeadlineReceiver)
where
    FClock: Fn() -> DateTime<Utc> + Send + 'static,
{
    let (duty_tx, mut duty_rx) = mpsc::unbounded_channel::<(Duty, oneshot::Sender<bool>)>();
    let (result_tx, result_rx) = mpsc::unbounded_channel::<Duty>();

    // Background task: receives duties, creates timers, and sends expired duties to
    // result channel.
    tokio::spawn(async move {
        let mut handles = tokio::task::JoinSet::new();

        // There is always a sentinel Duty that will never expire in the `handles` set
        handles.spawn(std::future::pending());

        loop {
            tokio::select! {
                // Accept new task handles from producers
                maybe_duty = duty_rx.recv() => {
                    match maybe_duty {
                        Some((duty, responder)) => {
                            match func(&duty) {
                                Err(_) => todo!("handle deadline function error"),
                                Ok(None) => {
                                    // Duty never expires, respond with false
                                    let _ = responder.send(false);
                                    continue;
                                }
                                Ok(Some(deadline)) => {
                                    let now = now();
                                    let expired = deadline < now;
                                    responder.send(!expired).ok();

                                    if expired {
                                        continue;
                                    }

                                    handles.spawn(async move {
                                        let sleep_duration = deadline
                                            .signed_duration_since(now)
                                            .to_std()
                                            .unwrap_or(std::time::Duration::ZERO);
                                        tokio::time::sleep(sleep_duration).await;
                                        duty
                                    });
                                }
                            }
                        }
                        None => {
                            // All senders dropped — drain remaining duties and exit
                            while let Some(result) = handles.join_next().await {
                                if let Ok(expired_duty) = result {
                                    if result_tx.send(expired_duty).is_err() {
                                        return;
                                    }
                                }
                            }
                            return;
                        }
                    }
                }
                // Forward expired duties to the receiver
                Some(result) = handles.join_next(), if !handles.is_empty() => {
                     if let Ok(expired_duty) = result {
                        if result_tx.send(expired_duty).is_err() {
                            return;
                        }
                    }
                }
            }
        }
    });

    (
        DeadlineSender { tx: duty_tx },
        DeadlineReceiver { rx: result_rx },
    )
}

impl DeadlineSender {
    /// Pushes a Duty into the collection for deadline tracking.
    ///
    /// Returns `true` if the Duty was submitted, `false` otherwise.
    pub async fn push(&self, duty: Duty) -> bool {
        let (ack_tx, ack_rx) = oneshot::channel();
        let _ = self.tx.send((duty, ack_tx));
        ack_rx.await.unwrap_or(false)
    }
}

impl DeadlineReceiver {
    /// Pops the next expired Duty.
    ///
    /// Returns `None` when all [`DeadlineSender`] have been dropped and all
    /// pending tasks have completed.
    pub async fn pop(&mut self) -> Option<Duty> {
        self.rx.recv().await
    }
}

#[cfg(test)]
mod tests {}
