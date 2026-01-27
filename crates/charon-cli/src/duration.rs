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

impl std::str::FromStr for Duration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try parsing as integer (nanoseconds)
        if let Ok(nanos) = s.parse::<u64>() {
            return Ok(Self::new(StdDuration::from_nanos(nanos)));
        }

        // Use humantime for duration string parsing
        humantime::parse_duration(s)
            .map(Self::new)
            .map_err(|e| e.to_string())
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Match Go's time.Duration.String() format exactly
        let duration = self.inner;

        if duration.is_zero() {
            return write!(f, "0s");
        }

        let nanos = duration.as_nanos();

        // For durations < 1 second, use the most appropriate unit
        if nanos < 1_000_000_000 {
            if nanos < 1_000 {
                return write!(f, "{}ns", nanos);
            } else if nanos < 1_000_000 {
                return write!(f, "{}µs", nanos / 1_000);
            } else {
                return write!(f, "{}ms", nanos / 1_000_000);
            }
        }

        let mut remaining = nanos;
        let mut parts = Vec::new();

        // Hours
        let hours = remaining / 3_600_000_000_000;
        if hours > 0 {
            parts.push(format!("{}h", hours));
            remaining %= 3_600_000_000_000;
        }

        // Minutes
        let minutes = remaining / 60_000_000_000;
        if minutes > 0 || hours > 0 {
            parts.push(format!("{}m", minutes));
            remaining %= 60_000_000_000;
        }

        // Seconds and sub-seconds
        let seconds = remaining / 1_000_000_000;
        remaining %= 1_000_000_000;

        if remaining == 0 {
            parts.push(format!("{}s", seconds));
        } else if hours > 0 || minutes > 0 {
            // For h/m/s format, include fractional seconds without padding
            let mut subsec_str = format!("{:09}", remaining);
            subsec_str = subsec_str.trim_end_matches('0').to_string();
            parts.push(format!("{}.{}s", seconds, subsec_str));
        } else {
            #[allow(clippy::cast_precision_loss)]
            // For >= 1 second durations without h/m, use 3 decimal places
            let total_seconds = (nanos as f64) / 1_000_000_000.0;
            parts.push(format!("{:.3}s", total_seconds));
        }

        write!(f, "{}", parts.join(""))
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
        use serde::de::{self, Visitor};

        struct DurationVisitor;

        impl<'de> Visitor<'de> for DurationVisitor {
            type Value = Duration;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a duration string or integer nanoseconds")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                v.parse::<Duration>().map_err(de::Error::custom)
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Duration::new(StdDuration::from_nanos(v)))
            }
        }

        deserializer.deserialize_any(DurationVisitor)
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

    // Tests converted from Go's cmd/duration_test.go

    #[test]
    fn test_serialize() {
        let tests = vec![
            ("millisecond", StdDuration::from_millis(1), "\"1ms\""),
            ("day", StdDuration::from_secs(24 * 3600), "\"24h0m0s\""),
            ("1000 nanoseconds", StdDuration::from_nanos(1000), "\"1µs\""),
            ("60 seconds", StdDuration::from_secs(60), "\"1m0s\""),
            ("empty", StdDuration::from_secs(0), "\"0s\""),
        ];

        for (name, duration, expected) in tests {
            let d = Duration::new(duration);
            let json = serde_json::to_string(&d).expect(name);
            assert_eq!(json, expected, "test case: {}", name);
        }
    }

    #[test]
    fn test_deserialize() {
        let tests = vec![
            ("millisecond", "\"1ms\"", StdDuration::from_millis(1), false),
            (
                "day",
                "\"24h0m0s\"",
                StdDuration::from_secs(24 * 3600),
                false,
            ),
            (
                "1000 nanoseconds",
                "\"1µs\"",
                StdDuration::from_nanos(1000),
                false,
            ),
            ("60 seconds", "\"1m0s\"", StdDuration::from_secs(60), false),
            ("zero", "\"0s\"", StdDuration::from_secs(0), false),
            (
                "millisecond number",
                "1000000",
                StdDuration::from_millis(1),
                false,
            ),
            (
                "day number",
                "86400000000000",
                StdDuration::from_secs(24 * 3600),
                false,
            ),
            (
                "1000 nanoseconds number",
                "1000",
                StdDuration::from_nanos(1000),
                false,
            ),
            (
                "60 seconds number",
                "60000000000",
                StdDuration::from_secs(60),
                false,
            ),
            ("zero number", "0", StdDuration::from_secs(0), false),
            ("text string", "\"second\"", StdDuration::from_secs(0), true),
            ("invalid json", "second", StdDuration::from_secs(0), true),
        ];

        for (name, input, expected, should_error) in tests {
            let result: Result<Duration, _> = serde_json::from_str(input);
            if should_error {
                assert!(result.is_err(), "test case: {} should error", name);
            } else {
                let d = result.expect(name);
                assert_eq!(d.inner, expected, "test case: {}", name);
            }
        }
    }

    #[test]
    fn test_display() {
        let tests = vec![
            ("millisecond", StdDuration::from_millis(1), "1ms"),
            ("day", StdDuration::from_secs(24 * 3600), "24h0m0s"),
            ("1000 nanoseconds", StdDuration::from_nanos(1000), "1µs"),
            ("60 seconds", StdDuration::from_secs(60), "1m0s"),
            ("empty", StdDuration::from_secs(0), "0s"),
        ];

        for (name, duration, expected) in tests {
            let d = Duration::new(duration);
            assert_eq!(d.to_string(), expected, "test case: {}", name);
        }
    }

    #[test]
    fn test_from_str() {
        let tests = vec![
            ("millisecond", "1ms", StdDuration::from_millis(1), false),
            ("day", "24h0m0s", StdDuration::from_secs(24 * 3600), false),
            (
                "1000 nanoseconds",
                "1µs",
                StdDuration::from_nanos(1000),
                false,
            ),
            ("60 seconds", "1m0s", StdDuration::from_secs(60), false),
            ("zero", "0s", StdDuration::from_secs(0), false),
            (
                "millisecond number",
                "1000000",
                StdDuration::from_millis(1),
                false,
            ),
            (
                "day number",
                "86400000000000",
                StdDuration::from_secs(24 * 3600),
                false,
            ),
            (
                "1000 nanoseconds number",
                "1000",
                StdDuration::from_nanos(1000),
                false,
            ),
            (
                "60 seconds number",
                "60000000000",
                StdDuration::from_secs(60),
                false,
            ),
            ("zero number", "0", StdDuration::from_secs(0), false),
            ("text string", "second", StdDuration::from_secs(0), true),
        ];

        for (name, input, expected, should_error) in tests {
            let result = input.parse::<Duration>();
            if should_error {
                assert!(result.is_err(), "test case: {} should error", name);
            } else {
                let d = result.expect(name);
                assert_eq!(d.inner, expected, "test case: {}", name);
            }
        }
    }

    #[test]
    fn test_round() {
        let tests = vec![
            (
                "15.151 milliseconds",
                StdDuration::from_micros(15151),
                StdDuration::from_millis(15),
            ),
            (
                "15.151515 milliseconds",
                StdDuration::from_nanos(15151515),
                StdDuration::from_millis(15),
            ),
            (
                "2.344444 seconds",
                StdDuration::from_micros(2344444),
                StdDuration::from_millis(2340),
            ),
            (
                "2.345555 seconds",
                StdDuration::from_micros(2345555),
                StdDuration::from_millis(2350),
            ),
            (
                "15.151 microsecond",
                StdDuration::from_nanos(15151),
                StdDuration::from_micros(15),
            ),
        ];

        for (name, input, expected) in tests {
            let d = Duration::new(input);
            let rounded = d.round();
            assert_eq!(rounded.inner, expected, "test case: {}", name);
        }
    }
}
