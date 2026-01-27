//! Duration wrapper with custom formatting and serialization.

use serde::{Deserialize, Serialize};
use std::{fmt, time::Duration as StdDuration};

/// Custom Duration wrapper with JSON serialization.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Duration {
    inner: StdDuration,
}

impl Duration {
    /// Creates a new Duration from a std::time::Duration.
    pub fn new(duration: StdDuration) -> Self {
        Self { inner: duration }
    }    
    
    /// Rounds the duration based on its magnitude
    #[allow(clippy::cast_possible_truncation, clippy::arithmetic_side_effects)]
    pub fn round(self) -> Self {
        let rounded = if self.inner > StdDuration::from_secs(1) {
            // Round to 10ms
            let millis = self.inner.as_millis();
            let rounded_millis = (millis + 5) / 10 * 10;
            StdDuration::from_millis(rounded_millis as u64)
        } else if self.inner > StdDuration::from_millis(1) {
            // Round to nearest 1ms
            let nanos = self.inner.as_nanos();
            let rounded_millis = (nanos + 500_000) / 1_000_000;
            StdDuration::from_millis(rounded_millis as u64)
        } else if self.inner > StdDuration::from_micros(1) {
            // Round to nearest 1μs
            let nanos = self.inner.as_nanos();
            let rounded_micros = (nanos + 500) / 1_000;
            StdDuration::from_micros(rounded_micros as u64)
        } else {
            self.inner
        };

        Self::new(rounded)
    }
}

impl From<StdDuration> for Duration {
    fn from(duration: StdDuration) -> Self {
        Self::new(duration)
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", humantime::format_duration(self.inner))
    }
}

impl Serialize for Duration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        if let Ok(nanos) = s.parse::<u64>() {
            return Ok(Self::new(StdDuration::from_nanos(nanos)));
        }

        humantime::parse_duration(&s)
            .map(Self::new)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_greater_than_second() {
        // > 1s: rounds to nearest 10ms
        let d = Duration::new(StdDuration::from_millis(1234));
        assert_eq!(d.round().inner, StdDuration::from_millis(1230));

        let d = Duration::new(StdDuration::from_millis(1235));
        assert_eq!(d.round().inner, StdDuration::from_millis(1240));

        let d = Duration::new(StdDuration::from_millis(1239));
        assert_eq!(d.round().inner, StdDuration::from_millis(1240));

        let d = Duration::new(StdDuration::from_millis(2001));
        assert_eq!(d.round().inner, StdDuration::from_millis(2000));
    }

    #[test]
    fn test_round_greater_than_millisecond() {
        // > 1ms: rounds to nearest 1ms
        let d = Duration::new(StdDuration::from_micros(1600));
        assert_eq!(d.round().inner, StdDuration::from_millis(2));

        let d = Duration::new(StdDuration::from_micros(1400));
        assert_eq!(d.round().inner, StdDuration::from_millis(1));

        let d = Duration::new(StdDuration::from_micros(1500));
        assert_eq!(d.round().inner, StdDuration::from_millis(2));

        let d = Duration::new(StdDuration::from_micros(1499));
        assert_eq!(d.round().inner, StdDuration::from_millis(1));
    }

    #[test]
    fn test_round_greater_than_microsecond() {
        // > 1µs: rounds to nearest 1µs
        let d = Duration::new(StdDuration::from_nanos(1600));
        assert_eq!(d.round().inner, StdDuration::from_micros(2));

        let d = Duration::new(StdDuration::from_nanos(1400));
        assert_eq!(d.round().inner, StdDuration::from_micros(1));

        let d = Duration::new(StdDuration::from_nanos(1500));
        assert_eq!(d.round().inner, StdDuration::from_micros(2));

        let d = Duration::new(StdDuration::from_nanos(1499));
        assert_eq!(d.round().inner, StdDuration::from_micros(1));
    }

    #[test]
    fn test_round_less_than_or_equal_microsecond() {
        // <= 1µs: no rounding
        let d = Duration::new(StdDuration::from_nanos(999));
        assert_eq!(d.round().inner, StdDuration::from_nanos(999));

        let d = Duration::new(StdDuration::from_nanos(1));
        assert_eq!(d.round().inner, StdDuration::from_nanos(1));

        let d = Duration::new(StdDuration::from_nanos(0));
        assert_eq!(d.round().inner, StdDuration::from_nanos(0));
    }

    #[test]
    fn test_round_boundary_cases() {
        let d = Duration::new(StdDuration::from_secs(1));
        assert_eq!(d.round().inner, StdDuration::from_secs(1));

        let d = Duration::new(StdDuration::from_millis(1));
        assert_eq!(d.round().inner, StdDuration::from_millis(1));

        let d = Duration::new(StdDuration::from_micros(1));
        assert_eq!(d.round().inner, StdDuration::from_micros(1));
    }
}
