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

/// A single metric sample (one time series at one scrape).
#[derive(Debug, Clone)]
pub struct Metric {
    /// Labels on this series.
    pub labels: Vec<LabelPair>,
    /// Counter value, if this is a counter sample.
    pub counter: Option<f64>,
    /// Gauge value, if this is a gauge sample.
    pub gauge: Option<f64>,
}

impl Metric {
    /// Counter value, defaulting to `0.0` when absent.
    pub fn counter_value(&self) -> f64 {
        self.counter.unwrap_or(0.0)
    }

    /// Gauge value, defaulting to `0.0` when absent.
    pub fn gauge_value(&self) -> f64 {
        self.gauge.unwrap_or(0.0)
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
