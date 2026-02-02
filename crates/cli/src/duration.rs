//! Duration wrapper with custom formatting and serialization.

use serde::{Deserialize, Serialize};
use std::{fmt, time::Duration as StdDuration};

const NANOSECOND: u64 = 1;
    const MICROSECOND: u64 = 1000 * NANOSECOND;
    const MILLISECOND: u64 = 1000 * MICROSECOND;
    const SECOND: u64 = 1000 * MILLISECOND;

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
        // Matches Go's `time.Duration.String()` (see Go's `time.Duration.format`).
        write!(f, "{}", format_go_duration(self.inner))
    }
}

/// Formats a duration like Go's `time.Duration.String()`.
fn format_go_duration(duration: StdDuration) -> String {
    let nanos_u128 = duration.as_nanos();
    let mut u: u64 = match u64::try_from(nanos_u128) {
        Ok(v) => v,
        Err(_) => u64::MAX,
    };

    let mut buf = [0_u8; 32];
    let mut w = buf.len();

    if u < SECOND {
        // Special case: if duration is smaller than a second, use smaller units, like
        // 1.2ms.
        let prec: usize;

        w -= 1;
        buf[w] = b's';

        match u {
            0 => {
                w -= 1;
                buf[w] = b'0';
                return String::from_utf8_lossy(&buf[w..]).into_owned();
            }
            0..MICROSECOND => {
                // nanoseconds: "ns"
                prec = 0;
                w -= 1;
                buf[w] = b'n';
            }
            MICROSECOND..MILLISECOND => {
                // microseconds: "µs" (U+00B5 'µ' as UTF-8 0xC2 0xB5)
                prec = 3;
                w -= 2;
                buf[w] = 0xC2;
                buf[w + 1] = 0xB5;
            }
            _ => {
                // milliseconds: "ms"
                prec = 6;
                w -= 1;
                buf[w] = b'm';
            }
        }

        let (nw, nv) = fmt_frac(&mut buf[..w], u, prec);
        w = nw;
        u = nv;
        w = fmt_int(&mut buf[..w], u);

        return String::from_utf8_lossy(&buf[w..]).into_owned();
    }

    // >= 1 second
    w -= 1;
    buf[w] = b's';

    let (nw, nv) = fmt_frac(&mut buf[..w], u, 9);
    w = nw;
    u = nv; // integer seconds

    w = fmt_int(&mut buf[..w], u % 60);
    u /= 60;

    if u > 0 {
        w -= 1;
        buf[w] = b'm';
        w = fmt_int(&mut buf[..w], u % 60);
        u /= 60;

        if u > 0 {
            w -= 1;
            buf[w] = b'h';
            w = fmt_int(&mut buf[..w], u);
        }
    }

    String::from_utf8_lossy(&buf[w..]).into_owned()
}

/// Formats the fraction of `v / 10**prec` into the tail of `buf`, omitting
/// trailing zeros. Returns the new start index and `v / 10**prec`.
fn fmt_frac(buf: &mut [u8], mut v: u64, prec: usize) -> (usize, u64) {
    // Omit trailing zeros up to and including decimal point.
    let mut w = buf.len();
    let mut print = false;

    for _ in 0..prec {
        let digit = (v % 10) as u8;
        print = print || digit != 0;
        if print {
            w -= 1;
            buf[w] = digit + b'0';
        }
        v /= 10;
    }

    if print {
        w -= 1;
        buf[w] = b'.';
    }

    (w, v)
}

/// Formats `v` into the tail of `buf`. Returns the index where the output
/// begins.
fn fmt_int(buf: &mut [u8], mut v: u64) -> usize {
    let mut w = buf.len();
    if v == 0 {
        w -= 1;
        buf[w] = b'0';
        return w;
    } else {
        while v > 0 {
            w -= 1;
            buf[w] = (v % 10) as u8 + b'0';
            v /= 10;
        }
    }

    w
}

impl Serialize for Duration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Match Go's `cmd.Duration.MarshalJSON` which marshals
        // `time.Duration.String()`.
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
            ("one second", StdDuration::from_secs(1), "1s"),
            ("three seconds", StdDuration::from_secs(3), "3s"),
            (
                "two point five seconds",
                StdDuration::from_millis(2500),
                "2.5s",
            ),
            (
                "three point one two three seconds",
                StdDuration::from_millis(3123),
                "3.123s",
            ),
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
