// TODO: Requires `eth2client`
#![allow(unreachable_code)]
#![allow(unused_variables)]
#![allow(clippy::diverging_sub_expression)]

use charon_core::types::{Duty, DutyType};
use std::time;

/// Defines the fraction of the slot duration to use as a margin.
/// This is to consider network delays and other factors that may affect the
/// timing.
pub const MARGIN_FACTOR: u32 = 12;

/// A function that returns the deadline for a duty.
pub type DeadlineFunc = Box<dyn Fn(Duty) -> Option<chrono::DateTime<chrono::Utc>> + Send + Sync>;

/// Error type for deadline-related operations.
#[derive(Debug, thiserror::Error)]
pub enum DeadlineError {}

type Result<T> = std::result::Result<T, DeadlineError>;

/// Create a function that provides duty deadline or [`None`] if the duty never
/// deadlines.
pub fn new_duty_deadline_func() -> Result<DeadlineFunc> {
    let genesis_time: chrono::DateTime<chrono::Utc> = todo!("Fetch genesis time from eth2 client");

    let slot_duration: time::Duration = todo!("Fetch slot duration from eth2 client");

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
