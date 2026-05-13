//! DutyDB — in-memory store for unsigned duty data.
//!
//! Equivalent to charon's `core/dutydb` package.

pub mod memory;

pub use memory::{Error, MemDB, Result, UnsignedDataSet, UnsignedDutyData};
