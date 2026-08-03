//! Duration wrapper with custom formatting and serialization.

use serde::{Deserialize, Serialize};
use std::{fmt, time::Duration as StdDuration};

const NANOSECOND: u64 = 1;
const MICROSECOND: u64 = 1000 * NANOSECOND;
const MILLISECOND: u64 = 1000 * MICROSECOND;
const SECOND: u64 = 1000 * MILLISECOND;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 60 * MINUTE;

/// Custom Duration wrapper with JSON serialization.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Duration {
    #[serde(
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
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

    /// Returns the total number of nanoseconds.
    pub fn as_nanos(&self) -> u128 {
        self.inner.as_nanos()
    }
}

impl From<StdDuration> for Duration {
    fn from(duration: StdDuration) -> Self {
        Self::new(duration)
    }
}

impl From<Duration> for StdDuration {
    fn from(d: Duration) -> Self {
        d.inner
    }
}

impl PartialOrd for Duration {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Duration {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl std::str::FromStr for Duration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try parsing as integer (nanoseconds), mirroring Charon's
        // `UnmarshalText` `strconv.ParseInt` branch.
        if let Ok(nanos) = s.parse::<u64>() {
            return Ok(Self::new(StdDuration::from_nanos(nanos)));
        }

        parse_go_duration(s).map(Self::new)
    }
}

/// Maximum duration representable by Go's `time.Duration` (`1<<63 - 1` ns).
const GO_MAX_DURATION_NANOS: u64 = (1 << 63) - 1;

/// Parses a duration string the way Go's `time.ParseDuration` does.
///
/// Accepted units: `ns`, `us`/`µs`/`μs`, `ms`, `s`, `m`, `h`. Multiple
/// `<number><unit>` segments concatenate (`1h30m`), numbers may be
/// fractional (`1.5h`), a leading `+` is allowed, and the bare string `"0"`
/// is a special case with no unit required.
// PARITY: Go time.ParseDuration, used by charon v1.7.1 cmd/duration.go
// UnmarshalText for all CLI duration flags. Deviation: a leading `-` is
// rejected (Go accepts negative durations) because `std::time::Duration`
// is unsigned and every flag using this parser is a non-negative
// timeout/delay.
pub fn parse_go_duration(s: &str) -> Result<StdDuration, String> {
    let orig = s;
    let mut rest = s;

    // Consume [-+]?
    let mut neg = false;
    if let Some(stripped) = rest.strip_prefix(['-', '+']) {
        neg = rest.starts_with('-');
        rest = stripped;
    }

    // Special case: if all that is left is "0", this is zero.
    if rest == "0" {
        return Ok(StdDuration::ZERO);
    }

    if rest.is_empty() {
        return Err(format!("invalid duration {orig:?}"));
    }

    if neg {
        return Err(format!("negative durations are not supported: {orig}"));
    }

    let mut total: u64 = 0;
    while !rest.is_empty() {
        // The next character must be [0-9.]
        if !rest.starts_with(|c: char| c == '.' || c.is_ascii_digit()) {
            return Err(format!("invalid duration {orig:?}"));
        }

        // Consume [0-9]*
        let (v, after_int) =
            leading_int(rest).map_err(|()| format!("invalid duration {orig:?}"))?;
        let pre = after_int.len() != rest.len();
        rest = after_int;

        // Consume (\.[0-9]*)?
        let mut frac: u64 = 0;
        let mut scale: f64 = 1.0;
        let mut post = false;
        if let Some(after_dot) = rest.strip_prefix('.') {
            let (f, sc, after_frac) = leading_fraction(after_dot);
            frac = f;
            scale = sc;
            post = after_frac.len() != after_dot.len();
            rest = after_frac;
        }

        if !pre && !post {
            // No digits (e.g. ".s").
            return Err(format!("invalid duration {orig:?}"));
        }

        // Consume unit: everything up to the next digit or '.'.
        let unit_len = rest
            .find(|c: char| c == '.' || c.is_ascii_digit())
            .unwrap_or(rest.len());
        if unit_len == 0 {
            return Err(format!("missing unit in duration {orig:?}"));
        }
        let unit_str = &rest[..unit_len];
        rest = &rest[unit_len..];
        let unit = unit_scale(unit_str)
            .ok_or_else(|| format!("unknown unit {unit_str:?} in duration {orig:?}"))?;

        let mut nanos = v
            .checked_mul(unit)
            .filter(|&n| n <= GO_MAX_DURATION_NANOS)
            .ok_or_else(|| format!("invalid duration {orig:?}"))?;
        if frac > 0 {
            // Match Go: float64 is nanosecond-accurate for fractions of the
            // largest unit (hours).
            #[allow(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss
            )]
            let frac_nanos = (frac as f64 * (unit as f64 / scale)) as u64;
            nanos = nanos
                .checked_add(frac_nanos)
                .filter(|&n| n <= GO_MAX_DURATION_NANOS)
                .ok_or_else(|| format!("invalid duration {orig:?}"))?;
        }

        total = total
            .checked_add(nanos)
            .filter(|&t| t <= GO_MAX_DURATION_NANOS)
            .ok_or_else(|| format!("invalid duration {orig:?}"))?;
    }

    Ok(StdDuration::from_nanos(total))
}

/// Consumes leading `[0-9]*` from `s`. Errors on overflow.
fn leading_int(s: &str) -> Result<(u64, &str), ()> {
    let mut x: u64 = 0;
    let mut end = 0;
    for (i, &b) in s.as_bytes().iter().enumerate() {
        if !b.is_ascii_digit() {
            break;
        }
        x = x
            .checked_mul(10)
            .and_then(|y| y.checked_add(u64::from(b.saturating_sub(b'0'))))
            .filter(|&y| y <= GO_MAX_DURATION_NANOS)
            .ok_or(())?;
        end = i.saturating_add(1);
    }
    Ok((x, &s[end..]))
}

/// Consumes leading `[0-9]*` from `s` as the value and scale of its decimal
/// fraction. Ignores digits beyond the overflow point, like Go.
fn leading_fraction(s: &str) -> (u64, f64, &str) {
    let mut x: u64 = 0;
    let mut scale: f64 = 1.0;
    let mut overflow = false;
    let mut end = 0;
    for (i, &b) in s.as_bytes().iter().enumerate() {
        if !b.is_ascii_digit() {
            break;
        }
        end = i.saturating_add(1);
        if overflow {
            continue;
        }
        match x
            .checked_mul(10)
            .and_then(|y| y.checked_add(u64::from(b.saturating_sub(b'0'))))
            .filter(|&y| y <= GO_MAX_DURATION_NANOS)
        {
            Some(y) => {
                x = y;
                scale *= 10.0;
            }
            None => overflow = true,
        }
    }
    (x, scale, &s[end..])
}

/// Returns the nanosecond scale of a Go duration unit, or `None` if unknown.
/// Go accepts both the micro sign `µ` (U+00B5) and the Greek mu `μ` (U+03BC).
fn unit_scale(unit: &str) -> Option<u64> {
    match unit {
        "ns" => Some(NANOSECOND),
        "us" | "\u{00b5}s" | "\u{03bc}s" => Some(MICROSECOND),
        "ms" => Some(MILLISECOND),
        "s" => Some(SECOND),
        "m" => Some(MINUTE),
        "h" => Some(HOUR),
        _ => None,
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Matches Go's `time.Duration.String()` (see Go's `time.Duration.format`).
        write!(f, "{}", format_go_duration(self.inner))
    }
}

/// Formats a duration like Go's `time.Duration.String()`.
#[allow(clippy::arithmetic_side_effects)]
fn format_go_duration(duration: StdDuration) -> String {
    let nanos_u128 = duration.as_nanos();
    let mut u: u64 = u64::try_from(nanos_u128).unwrap_or(u64::MAX);

    let mut buf = [0_u8; 32];
    let mut w = buf.len();

    if u < SECOND {
        // Special case: if duration is smaller than a second, use smaller units, like
        // 1.2ms.
        let prec: usize;

        w -= 1;
        buf[w] = b's';
        w -= 1;

        match u {
            0 => {
                buf[w] = b'0';
                return String::from_utf8_lossy(&buf[w..]).into_owned();
            }
            1..MICROSECOND => {
                // nanoseconds: "ns"
                prec = 0;
                buf[w] = b'n';
            }
            MICROSECOND..MILLISECOND => {
                // microseconds: "µs" (U+00B5 'µ' as UTF-8 0xC2 0xB5)
                prec = 3;
                w -= 1;
                buf[w] = 0xC2;
                buf[w + 1] = 0xB5;
            }
            _ => {
                // milliseconds: "ms"
                prec = 6;
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

        // u is now integer hours
        // Stop at hours because days can be different lengths
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
#[allow(clippy::arithmetic_side_effects)]
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
#[allow(clippy::arithmetic_side_effects)]
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

/// Serializes a StdDuration as a string matching Go's time.Duration format.
fn serialize_duration<S>(duration: &StdDuration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // Match Go's `cmd.Duration.MarshalJSON` which marshals
    // `time.Duration.String()`.
    serializer.serialize_str(&Duration::new(*duration).to_string())
}

/// Deserializes a StdDuration from either a string or integer nanoseconds.
fn deserialize_duration<'de, D>(deserializer: D) -> Result<StdDuration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};

    struct DurationVisitor;

    impl<'de> Visitor<'de> for DurationVisitor {
        type Value = StdDuration;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a duration string or integer nanoseconds")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.parse::<Duration>()
                .map(|d| d.inner)
                .map_err(de::Error::custom)
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(StdDuration::from_nanos(v))
        }
    }

    deserializer.deserialize_any(DurationVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(StdDuration::from_millis(1), "\"1ms\""; "millisecond")]
    #[test_case(StdDuration::from_secs(24 * 3600), "\"24h0m0s\""; "day")]
    #[test_case(StdDuration::from_nanos(1000), "\"1µs\""; "1000_nanoseconds")]
    #[test_case(StdDuration::from_secs(60), "\"1m0s\""; "60_seconds")]
    #[test_case(StdDuration::from_secs(0), "\"0s\""; "empty")]
    fn test_serialize(duration: StdDuration, expected: &str) {
        let d = Duration::new(duration);
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, expected);
    }

    #[test_case("\"1ms\"", StdDuration::from_millis(1); "millisecond")]
    #[test_case("\"24h0m0s\"", StdDuration::from_secs(24 * 3600); "day")]
    #[test_case("\"1µs\"", StdDuration::from_nanos(1000); "1000_nanoseconds")]
    #[test_case("\"1m0s\"", StdDuration::from_secs(60); "60_seconds")]
    #[test_case("\"0s\"", StdDuration::from_secs(0); "zero")]
    #[test_case("1000000", StdDuration::from_millis(1); "millisecond_number")]
    #[test_case("86400000000000", StdDuration::from_secs(24 * 3600); "day_number")]
    #[test_case("1000", StdDuration::from_nanos(1000); "1000_nanoseconds_number")]
    #[test_case("60000000000", StdDuration::from_secs(60); "60_seconds_number")]
    #[test_case("0", StdDuration::from_secs(0); "zero_number")]
    fn test_deserialize(input: &str, expected: StdDuration) {
        let result: Result<Duration, _> = serde_json::from_str(input);
        let d = result.unwrap();
        assert_eq!(d.inner, expected);
    }

    #[test_case("\"second\""; "text_string")]
    #[test_case("second"; "invalid_json")]
    fn test_deserialize_error(input: &str) {
        let result: Result<Duration, _> = serde_json::from_str(input);
        assert!(result.is_err());
    }

    #[test_case(StdDuration::from_millis(1), "1ms"; "millisecond")]
    #[test_case(StdDuration::from_secs(1), "1s"; "one_second")]
    #[test_case(StdDuration::from_secs(3), "3s"; "three_seconds")]
    #[test_case(StdDuration::from_millis(2500), "2.5s"; "two_point_five_seconds")]
    #[test_case(StdDuration::from_millis(3123), "3.123s"; "three_point_one_two_three_seconds")]
    #[test_case(StdDuration::from_secs(24 * 3600), "24h0m0s"; "day")]
    #[test_case(StdDuration::from_nanos(1000), "1µs"; "1000_nanoseconds")]
    #[test_case(StdDuration::from_secs(60), "1m0s"; "60_seconds")]
    #[test_case(StdDuration::from_secs(0), "0s"; "empty")]
    fn test_display(duration: StdDuration, expected: &str) {
        let d = Duration::new(duration);
        assert_eq!(d.to_string(), expected);
    }

    #[test_case("1ms", StdDuration::from_millis(1); "millisecond")]
    #[test_case("24h0m0s", StdDuration::from_secs(24 * 3600); "day")]
    #[test_case("1µs", StdDuration::from_nanos(1000); "1000_nanoseconds")]
    #[test_case("1m0s", StdDuration::from_secs(60); "60_seconds")]
    #[test_case("0s", StdDuration::from_secs(0); "zero")]
    #[test_case("1000000", StdDuration::from_millis(1); "millisecond_number")]
    #[test_case("86400000000000", StdDuration::from_secs(24 * 3600); "day_number")]
    #[test_case("1000", StdDuration::from_nanos(1000); "1000_nanoseconds_number")]
    #[test_case("60000000000", StdDuration::from_secs(60); "60_seconds_number")]
    #[test_case("0", StdDuration::from_secs(0); "zero_number")]
    fn test_from_str(input: &str, expected: StdDuration) {
        let result = input.parse::<Duration>();
        let d = result.unwrap();
        assert_eq!(d.inner, expected);
    }

    #[test_case("second"; "text_string")]
    #[test_case("1d"; "days_unit")]
    #[test_case("1w"; "weeks_unit")]
    fn test_from_str_error(input: &str) {
        let result = input.parse::<Duration>();
        assert!(result.is_err());
    }

    #[test_case("1ns", StdDuration::from_nanos(1); "one_nanosecond")]
    #[test_case("1us", StdDuration::from_micros(1); "one_microsecond_ascii")]
    #[test_case("1µs", StdDuration::from_micros(1); "one_microsecond_micro_sign")]
    #[test_case("1\u{03bc}s", StdDuration::from_micros(1); "one_microsecond_greek_mu")]
    #[test_case("1ms", StdDuration::from_millis(1); "one_millisecond")]
    #[test_case("1s", StdDuration::from_secs(1); "one_second")]
    #[test_case("2m", StdDuration::from_secs(120); "two_minutes")]
    #[test_case("1h", StdDuration::from_secs(3600); "one_hour")]
    #[test_case("1m0s", StdDuration::from_secs(60); "multi_segment_dkg_default")]
    #[test_case("1h30m", StdDuration::from_secs(5400); "multi_segment_hour_minute")]
    #[test_case("24h0m0s", StdDuration::from_secs(24 * 3600); "charon_round_trip")]
    #[test_case("1.5h", StdDuration::from_secs(5400); "fractional_hours")]
    #[test_case("2.5s", StdDuration::from_millis(2500); "fractional_seconds")]
    #[test_case("0.5s", StdDuration::from_millis(500); "fraction_below_one")]
    #[test_case(".5s", StdDuration::from_millis(500); "fraction_no_integer_part")]
    #[test_case("100ns", StdDuration::from_nanos(100); "hundred_nanoseconds")]
    #[test_case("+5s", StdDuration::from_secs(5); "leading_plus")]
    #[test_case("0", StdDuration::ZERO; "bare_zero_special_case")]
    #[test_case("-0", StdDuration::ZERO; "negative_zero_special_case")]
    #[test_case("0s", StdDuration::ZERO; "zero_seconds")]
    fn test_parse_go_duration(input: &str, expected: StdDuration) {
        assert_eq!(parse_go_duration(input).unwrap(), expected);
    }

    #[test_case("1d", "unknown unit"; "days_rejected")]
    #[test_case("1w", "unknown unit"; "weeks_rejected")]
    #[test_case("1y", "unknown unit"; "years_rejected")]
    #[test_case("1M", "unknown unit"; "months_rejected")]
    #[test_case("5sec", "unknown unit"; "humantime_spelling_rejected")]
    #[test_case("-5s", "negative durations"; "negative_seconds")]
    #[test_case("-1h", "negative durations"; "negative_hours")]
    #[test_case("1", "missing unit"; "unitless_integer")]
    #[test_case("1.5", "missing unit"; "unitless_fraction")]
    #[test_case("s", "invalid duration"; "unit_without_number")]
    #[test_case("", "invalid duration"; "empty")]
    #[test_case(".s", "invalid duration"; "dot_without_digits")]
    #[test_case("abc", "invalid duration"; "letters")]
    #[test_case("not-a-duration", "invalid duration"; "dashed_text")]
    #[test_case("9999999999999999999h", "invalid duration"; "overflow")]
    fn test_parse_go_duration_error(input: &str, expected_msg: &str) {
        let err = parse_go_duration(input).unwrap_err();
        assert!(
            err.contains(expected_msg),
            "error {err:?} does not contain {expected_msg:?}"
        );
    }

    #[test_case(StdDuration::from_micros(15151), StdDuration::from_millis(15); "15_151_milliseconds")]
    #[test_case(StdDuration::from_nanos(15151515), StdDuration::from_millis(15); "15_151515_milliseconds")]
    #[test_case(StdDuration::from_micros(2344444), StdDuration::from_millis(2340); "2_344444_seconds")]
    #[test_case(StdDuration::from_micros(2345555), StdDuration::from_millis(2350); "2_345555_seconds")]
    #[test_case(StdDuration::from_nanos(15151), StdDuration::from_micros(15); "15_151_microsecond")]
    fn test_round(input: StdDuration, expected: StdDuration) {
        let d = Duration::new(input);
        let rounded = d.round();
        assert_eq!(rounded.inner, expected);
    }
}
