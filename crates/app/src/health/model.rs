//! In-memory Prometheus metric model used by the health checks.
//!
//! A minimal subset of the Prometheus metric model the checks rely on.
//! Per-sample timestamps are intentionally omitted: the reducers never read
//! them — the time dimension comes from the checker storing successive scrapes.

/// Type of a metric family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    /// A monotonically increasing counter.
    Counter,
    /// A gauge that can go up or down.
    Gauge,
    /// A histogram (not queried by any check; retained for the cardinality
    /// scan).
    Histogram,
    /// An info metric.
    Info,
    /// An unrecognised type.
    Unknown,
}

/// A name/value label pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelPair {
    /// Label name.
    pub name: String,
    /// Label value.
    pub value: String,
}

/// The typed value carried by a sample. A sample is either a counter or a
/// gauge; histogram/info/unknown samples carry no value (see
/// [`Metric::value`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SampleValue {
    /// A counter sample's value.
    Counter(f64),
    /// A gauge sample's value.
    Gauge(f64),
}

impl SampleValue {
    /// The underlying value, regardless of kind.
    pub fn value(self) -> f64 {
        match self {
            Self::Counter(v) | Self::Gauge(v) => v,
        }
    }
}

/// A single metric sample (one time series at one scrape).
#[derive(Debug, Clone)]
pub struct Metric {
    /// Labels on this series.
    pub labels: Vec<LabelPair>,
    /// The sample's value, or `None` for histogram/info/unknown samples.
    pub value: Option<SampleValue>,
}

impl Metric {
    /// The sample's value, defaulting to `0.0` when it carries none.
    pub fn value_or_zero(&self) -> f64 {
        self.value.map_or(0.0, SampleValue::value)
    }
}

/// A metric family: a named, typed group of series.
#[derive(Debug, Clone)]
pub struct MetricFamily {
    /// Family name.
    pub name: String,
    /// Family type.
    pub metric_type: MetricType,
    /// Series in this family.
    pub metrics: Vec<Metric>,
}
