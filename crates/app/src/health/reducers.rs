//! Series reducers: reduce a time series of samples to a single value.

use super::{
    error::{Error, Result},
    model::Metric,
};

/// Reduces a time series of samples to a single value.
pub(crate) type Reducer = fn(&[Metric]) -> Result<f64>;

/// Returns the increase across a counter (or gauge) time series: the last
/// sample's value minus the first. Fewer than two samples yields `0.0`.
pub(crate) fn increase(samples: &[Metric]) -> Result<f64> {
    if samples.len() < 2 {
        return Ok(0.0);
    }

    let (Some(first), Some(last)) = (samples.first(), samples.last()) else {
        return Ok(0.0);
    };

    if first.counter.is_none() && first.gauge.is_none() {
        return Err(Error::UnsupportedMetricPassed);
    }

    let first_val = first.counter_value() + first.gauge_value();
    let last_val = last.counter_value() + last.gauge_value();

    Ok(last_val - first_val)
}

/// Returns the maximum value across a gauge time series. Errors if any sample
/// is not a gauge.
pub(crate) fn gauge_max(samples: &[Metric]) -> Result<f64> {
    let mut max_val = 0.0_f64;

    for sample in samples {
        if sample.gauge.is_none() {
            return Err(Error::NonGaugeMetricPassed);
        }

        let value = sample.gauge_value();
        if value > max_val {
            max_val = value;
        }
    }

    Ok(max_val)
}
