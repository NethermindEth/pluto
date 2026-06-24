//! Health check errors.

use super::gatherer::GatherError;

/// Errors produced while evaluating health checks or gathering metrics.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A metric family expected to contain exactly one series did not.
    #[error("expected exactly one metric")]
    ExpectedExactlyOneMetric,

    /// A selector received a family that is neither a gauge nor a counter.
    #[error("bug: unsupported metric type")]
    UnsupportedMetricType,

    /// The increase reducer received a sample that is neither a counter nor a
    /// gauge.
    #[error("bug: unsupported metric passed")]
    UnsupportedMetricPassed,

    /// The gauge-max reducer received a non-gauge sample.
    #[error("bug: non-gauge metric passed")]
    NonGaugeMetricPassed,

    /// A label selector failed.
    #[error("label selector")]
    LabelSelector(#[source] Box<Error>),

    /// A series reducer failed.
    #[error("series reducer")]
    SeriesReducer(#[source] Box<Error>),

    /// Gathering metrics from the registry failed.
    #[error("gather metrics")]
    GatherMetrics(#[source] GatherError),

    /// An integer conversion overflowed.
    #[error("conversion error")]
    ConversionError(#[from] std::num::TryFromIntError),
}

/// Result type for health operations.
pub type Result<T> = std::result::Result<T, Error>;
