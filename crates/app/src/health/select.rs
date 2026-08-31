//! Label selectors: reduce a metric family to at most one synthetic gauge
//! sample.

use regex::Regex;

use super::{
    error::{Error, Result},
    model::{LabelPair, Metric, MetricFamily, MetricType, SampleValue},
};

/// Maps a metric family to at most one synthetic sample.
pub(crate) type Selector = Box<dyn Fn(&MetricFamily) -> Result<Option<Metric>>>;

/// Builds a synthetic gauge sample holding `value`.
fn gauge_metric(value: f64) -> Metric {
    Metric {
        labels: Vec::new(),
        value: Some(SampleValue::Gauge(value)),
    }
}

/// Counts the series in the family with a non-zero gauge or counter value.
pub(crate) fn count_non_zero_labels() -> Selector {
    Box::new(|fam: &MetricFamily| {
        let mut count = 0.0_f64;
        for metric in &fam.metrics {
            if metric.value_or_zero() != 0.0 {
                count += 1.0;
            }
        }
        Ok(Some(gauge_metric(count)))
    })
}

/// Returns the family's only series, erroring unless there is exactly one.
pub(crate) fn no_labels() -> Selector {
    Box::new(|fam: &MetricFamily| {
        let Some(metric) = fam.metrics.first() else {
            return Err(Error::ExpectedExactlyOneMetric);
        };
        if fam.metrics.len() != 1 {
            return Err(Error::ExpectedExactlyOneMetric);
        }
        Ok(Some(metric.clone()))
    })
}

/// A label name paired with the compiled regex its value must match, built
/// once per selector rather than once per metric series.
pub(crate) struct LabelMatcher {
    name: &'static str,
    /// [`None`] if the pattern failed to compile, which never matches.
    regex: Option<Regex>,
}

impl LabelMatcher {
    pub(crate) fn new(name: &'static str, pattern: &str) -> Self {
        Self {
            name,
            regex: Regex::new(pattern).ok(),
        }
    }
}

/// Sums the values of series matching all of `labels`.
pub(crate) fn count_labels(labels: &'static [LabelMatcher]) -> Selector {
    Box::new(move |fam: &MetricFamily| {
        let mut sum = 0.0_f64;
        for metric in &fam.metrics {
            if labels_contain(&metric.labels, labels) {
                sum += metric.value_or_zero();
            }
        }
        Ok(Some(gauge_metric(sum)))
    })
}

/// Sums the values of series matching all of `labels`; errors on non
/// gauge/counter families.
pub(crate) fn sum_labels(labels: &'static [LabelMatcher]) -> Selector {
    Box::new(move |fam: &MetricFamily| {
        if fam.metric_type != MetricType::Gauge && fam.metric_type != MetricType::Counter {
            return Err(Error::UnsupportedMetricType);
        }
        let mut sum = 0.0_f64;
        for metric in &fam.metrics {
            if labels_contain(&metric.labels, labels) {
                sum += metric.value_or_zero();
            }
        }
        Ok(Some(gauge_metric(sum)))
    })
}

/// Returns true if every matcher in `contain` matches some label in `labels`:
/// names must be equal and the matcher's regex must match the label value. A
/// matcher whose regex failed to compile is treated as no match.
pub(crate) fn labels_contain(labels: &[LabelPair], contain: &[LabelMatcher]) -> bool {
    contain.iter().all(|c| {
        labels
            .iter()
            .any(|l| l.name == c.name && c.regex.as_ref().is_some_and(|re| re.is_match(&l.value)))
    })
}
