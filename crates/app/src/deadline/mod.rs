use pluto_core::types::{Duty, DutyType};
use pluto_eth2api::{EthBeaconNodeApiClient, EthBeaconNodeApiClientError};

/// Defines the fraction of the slot duration to use as a margin.
/// This is to consider network delays and other factors that may affect the
/// timing.
pub const MARGIN_FACTOR: u32 = 12;

/// A function that returns the deadline for a duty.
pub type DeadlineFunc = Box<dyn Fn(Duty) -> Option<chrono::DateTime<chrono::Utc>> + Send + Sync>;

/// Error type for deadline-related operations.
#[derive(Debug, thiserror::Error)]
pub enum DeadlineError {
    /// Beacon client API error.
    #[error("Beacon client error: {0}")]
    BeaconClientError(#[from] EthBeaconNodeApiClientError),
}

type Result<T> = std::result::Result<T, DeadlineError>;

/// Create a function that provides duty deadline or [`None`] if the duty never
/// deadlines.
pub async fn new_duty_deadline_func(eth2_cl: &EthBeaconNodeApiClient) -> Result<DeadlineFunc> {
    let genesis_time = eth2_cl.fetch_genesis_time().await?;
    let (slot_duration, _) = eth2_cl.fetch_slots_config().await?;

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "Matches original implementation"
    )]
    Ok(Box::new(move |duty: Duty| match duty.duty_type {
        DutyType::Exit | DutyType::BuilderRegistration => None,
        _ => {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "TODO: unsupported operation in u64"
            )]
            let start = genesis_time + (slot_duration * (u64::from(duty.slot)) as u32);
            let margin = slot_duration / MARGIN_FACTOR;

            let duration = match duty.duty_type {
                DutyType::Proposer | DutyType::Randao => slot_duration / 3,
                DutyType::SyncMessage => 2 * slot_duration / 3,
                DutyType::Attester | DutyType::Aggregator | DutyType::PrepareAggregator => {
                    2 * slot_duration
                }
                _ => slot_duration,
            };
            Some(start + duration + margin)
        }
    }))
}
