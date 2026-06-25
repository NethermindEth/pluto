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

/// Sums the values of series matching all of `labels`.
pub(crate) fn count_labels(labels: Vec<LabelPair>) -> Selector {
    Box::new(move |fam: &MetricFamily| {
        let mut sum = 0.0_f64;
        for metric in &fam.metrics {
            if labels_contain(&metric.labels, &labels) {
                sum += metric.value_or_zero();
            }
        }
        Ok(Some(gauge_metric(sum)))
    })
}

/// Sums the values of series matching all of `labels`; errors on non
/// gauge/counter families.
pub(crate) fn sum_labels(labels: Vec<LabelPair>) -> Selector {
    Box::new(move |fam: &MetricFamily| {
        if fam.metric_type != MetricType::Gauge && fam.metric_type != MetricType::Counter {
            return Err(Error::UnsupportedMetricType);
        }
        let mut sum = 0.0_f64;
        for metric in &fam.metrics {
            if labels_contain(&metric.labels, &labels) {
                sum += metric.value_or_zero();
            }
        }
        Ok(Some(gauge_metric(sum)))
    })
}

/// Returns true if every pair in `contain` matches some label in `labels`:
/// names must be equal and the `contain` value is matched as a regex against
/// the label value. A regex that fails to compile is treated as no match.
pub(crate) fn labels_contain(labels: &[LabelPair], contain: &[LabelPair]) -> bool {
    for c in contain {
        let mut found = false;
        for l in labels {
            if l.name != c.name {
                continue;
            }
            if Regex::new(&c.value)
                .map(|re| re.is_match(&l.value))
                .unwrap_or(false)
            {
                found = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }
    true
}
