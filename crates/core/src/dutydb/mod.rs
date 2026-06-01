//! DutyDB — in-memory store for unsigned duty data.

pub mod memory;

pub use memory::{Error, MemDB, UnsignedDataSet, UnsignedDutyData, unsigned_data_set_from_proto};
