use std::time::Duration as StdDuration;

pub(crate) const COMMITTEE_SIZE_PER_SLOT: u64 = 64;
pub(crate) const SUB_COMMITTEE_SIZE: u64 = 4;
pub(crate) const SLOT_TIME: StdDuration = StdDuration::from_secs(12);
pub(crate) const SLOTS_IN_EPOCH: u64 = 32;
pub(crate) const EPOCH_TIME: StdDuration = StdDuration::from_secs(SLOTS_IN_EPOCH * 12);
