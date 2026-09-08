//! Go-compatible duration formatting.

use std::time::Duration;

const NANOS_PER_MICRO: u64 = 1_000;
const NANOS_PER_MILLI: u64 = 1_000_000;
const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Formats a duration the way Go's `time.Duration.String()` does, e.g. `1s`,
/// `1.5s`, `1m0s`, `1h1m1.5s`, `12ms`, `1.5µs`, `999ns` and `0s`.
///
/// Durations beyond Go's `int64` nanosecond range are clamped to its maximum.
pub fn go_duration_string(duration: Duration) -> String {
    let total = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
    let total = total.min(u64::try_from(i64::MAX).unwrap_or(u64::MAX));

    if total < NANOS_PER_SECOND {
        if total == 0 {
            return "0s".to_string();
        }

        let (precision, unit) = if total < NANOS_PER_MICRO {
            (0, "ns")
        } else if total < NANOS_PER_MILLI {
            (3, "µs")
        } else {
            (6, "ms")
        };

        let (fraction, whole) = fmt_frac(total, precision);

        return format!("{whole}{fraction}{unit}");
    }

    let (fraction, seconds) = fmt_frac(total, 9);
    let secs = seconds.checked_rem(60).unwrap_or(0);
    let minutes_total = seconds.checked_div(60).unwrap_or(0);

    let mut out = String::new();
    if minutes_total > 0 {
        let hours = minutes_total.checked_div(60).unwrap_or(0);
        let minutes = minutes_total.checked_rem(60).unwrap_or(0);
        if hours > 0 {
            out.push_str(&format!("{hours}h"));
        }
        out.push_str(&format!("{minutes}m"));
    }
    out.push_str(&format!("{secs}{fraction}s"));

    out
}

/// Splits `value` into `(fraction, whole)` where `whole = value / 10^precision`
/// and `fraction` is the decimal fraction with trailing zeros removed
/// (including the point when the fraction is zero).
fn fmt_frac(value: u64, precision: u32) -> (String, u64) {
    let scale = 10u64.checked_pow(precision).unwrap_or(u64::MAX);
    let whole = value.checked_div(scale).unwrap_or(0);
    let frac = value.checked_rem(scale).unwrap_or(0);

    if frac == 0 {
        return (String::new(), whole);
    }

    let width = usize::try_from(precision).unwrap_or(0);
    let digits = format!("{frac:0width$}");
    let digits = digits.trim_end_matches('0');

    (format!(".{digits}"), whole)
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    // Vectors generated with Go's time.Duration.String().
    #[test_case(0, "0s")]
    #[test_case(1500, "1.5µs" ; "fractional_microseconds")]
    #[test_case(999_999_999, "999.999999ms")]
    #[test_case(60_000_000_000, "1m0s")]
    #[test_case(3_661_500_000_000, "1h1m1.5s")]
    #[test_case(9_223_372_036_854_775_807, "2562047h47m16.854775807s")]
    fn matches_go(nanos: u64, want: &str) {
        assert_eq!(go_duration_string(Duration::from_nanos(nanos)), want);
    }
}
