//! DutyDB — in-memory store for unsigned duty data.

pub mod memory;

pub use memory::{Error, MemDB};

// `UnsignedDataSet`/`UnsignedDutyData` now live in `core::types` (shared with
// the fetcher); re-exported here for backwards compatibility.
pub use crate::types::{UnsignedDataSet, UnsignedDutyData};
