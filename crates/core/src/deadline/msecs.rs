//! `Msecs` newtype: whole milliseconds in `i64` width with checked arithmetic.

use chrono::{DateTime, Duration, Utc};

use crate::types::SlotNumber;

use super::{DeadlineError::*, Result};

/// Whole milliseconds, stored in chrono's native `i64` width with checked
/// conversions. Lifts the `u64`/`i64` `try_from` juggling out of arithmetic
/// call sites: every conversion either succeeds or returns `DeadlineError`.
pub(crate) struct Msecs(i64);

impl From<Duration> for Msecs {
    fn from(d: Duration) -> Self {
        Self(d.num_milliseconds())
    }
}

impl Msecs {
    /// Constructs from a raw `i64` count of milliseconds.
    #[cfg(test)]
    pub(crate) fn new(ms: i64) -> Self {
        Self(ms)
    }

    /// Multiplies by a `SlotNumber`, checked for overflow on both the
    /// `u64`→`i64` slot conversion and the `i64`×`i64` multiplication.
    pub(crate) fn checked_mul_slot(self, slot: SlotNumber) -> Result<Self> {
        let mul = i64::try_from(slot.inner()).map_err(|_| ArithmeticOverflow)?;
        self.0.checked_mul(mul).map(Self).ok_or(ArithmeticOverflow)
    }

    /// Multiplies by `by`, returning `ArithmeticOverflow` on
    /// overflow.
    pub(crate) fn checked_mul(self, by: i64) -> Result<Self> {
        self.0.checked_mul(by).map(Self).ok_or(ArithmeticOverflow)
    }

    /// Divides by `by`, returning `ArithmeticOverflow` on division by zero
    /// (or the `i64::MIN / -1` overflow corner case).
    pub(crate) fn checked_div(self, by: i64) -> Result<Self> {
        self.0.checked_div(by).map(Self).ok_or(ArithmeticOverflow)
    }

    /// Adds two `Msecs`, returning `ArithmeticOverflow` on overflow.
    pub(crate) fn checked_add(self, other: Self) -> Result<Self> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(ArithmeticOverflow)
    }

    /// Returns `base + self`, with both the `Msecs → Duration` and the
    /// `DateTime` addition checked.
    pub(crate) fn add_to(self, base: DateTime<Utc>) -> Result<DateTime<Utc>> {
        let offset = Duration::try_milliseconds(self.0).ok_or(DurationConversion)?;
        base.checked_add_signed(offset).ok_or(DateTimeCalculation)
    }
}
