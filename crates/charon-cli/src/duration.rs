//! Duration wrapper with custom formatting and serialization.

use serde::{Deserialize, Serialize};
use std::{fmt, time::Duration as StdDuration};

/// Custom Duration wrapper with JSON serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Duration {
    inner: StdDuration,
}

impl Duration {
    /// Creates a new Duration from a std::time::Duration.
    pub fn new(duration: StdDuration) -> Self {
        Self { inner: duration }
    }

    /// Returns the inner std::time::Duration.
    pub fn as_std(&self) -> StdDuration {
        self.inner
    }

    /// Rounds the duration based on its magnitude (matching Go's
    /// RoundDuration).
    pub fn round(self) -> Self {
        let rounded = if self.inner > StdDuration::from_secs(1) {
            // Round to 10ms
            let millis = self.inner.as_millis();
            let rounded_millis = (millis + 5) / 10 * 10;
            StdDuration::from_millis(rounded_millis as u64)
        } else if self.inner > StdDuration::from_millis(1) {
            // Round to 1ms
            let millis = self.inner.as_millis();
            StdDuration::from_millis(millis as u64)
        } else if self.inner > StdDuration::from_micros(1) {
            // Round to 1μs
            let micros = self.inner.as_micros();
            StdDuration::from_micros(micros as u64)
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
        // Format duration as Go does: "1.234s", "123ms", "1.234µs", etc.
        let duration = self.inner;
        if duration >= StdDuration::from_secs(1) {
            write!(f, "{:.3}s", duration.as_secs_f64())
        } else if duration >= StdDuration::from_millis(1) {
            write!(f, "{}ms", duration.as_millis())
        } else if duration >= StdDuration::from_micros(1) {
            write!(f, "{}µs", duration.as_micros())
        } else {
            write!(f, "{}ns", duration.as_nanos())
        }
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

        // Try parsing as integer (nanoseconds)
        if let Ok(nanos) = s.parse::<u64>() {
            return Ok(Self::new(StdDuration::from_nanos(nanos)));
        }

        // Try parsing as duration string
        // This is a simplified parser - may need humantime crate for full compatibility
        if let Some(val) = s.strip_suffix("ns") {
            if let Ok(n) = val.parse::<u64>() {
                return Ok(Self::new(StdDuration::from_nanos(n)));
            }
        } else if let Some(val) = s.strip_suffix("µs") {
            if let Ok(n) = val.parse::<u64>() {
                return Ok(Self::new(StdDuration::from_micros(n)));
            }
        } else if let Some(val) = s.strip_suffix("ms") {
            if let Ok(n) = val.parse::<u64>() {
                return Ok(Self::new(StdDuration::from_millis(n)));
            }
        } else if let Some(val) = s.strip_suffix('s') {
            if let Ok(n) = val.parse::<f64>() {
                return Ok(Self::new(StdDuration::from_secs_f64(n)));
            }
        }

        Err(serde::de::Error::custom("invalid duration"))
    }
}
