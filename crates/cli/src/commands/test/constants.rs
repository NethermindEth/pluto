use std::{num::NonZero, time::Duration as StdDuration};

/// Ethereum beacon chain constants.
pub(crate) const COMMITTEE_SIZE_PER_SLOT: u64 = 64;
pub(crate) const SUB_COMMITTEE_SIZE: u64 = 4;
pub(crate) const SLOT_TIME_SECS: NonZero<u64> = NonZero::<u64>::new(12).unwrap();
pub(crate) const SLOT_TIME: StdDuration = StdDuration::from_secs(SLOT_TIME_SECS.get());
pub(crate) const SLOTS_IN_EPOCH: NonZero<u64> = NonZero::<u64>::new(32).unwrap();
pub(crate) const EPOCH_TIME: StdDuration = StdDuration::from_secs(SLOTS_IN_EPOCH.get() * 12);
