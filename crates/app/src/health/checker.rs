//! The health checker background service.

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::{
    checks::{CHECKS, Metadata},
    error::{Error, Result},
    gatherer::Gatherer,
    metrics::HEALTH_METRICS,
    model::{MetricFamily, MetricType},
    reducers::Reducer,
    select::Selector,
};

/// Period between metric scrapes.
const SCRAPE_PERIOD: Duration = Duration::from_secs(30);

/// Maximum number of scrapes retained in the rolling window.
const MAX_SCRAPES: usize = 10;

/// High-cardinality threshold for a single validator; for `n` validators the
/// effective threshold is `LABELS_CARDINALITY_THRESHOLD * n`.
const LABELS_CARDINALITY_THRESHOLD: usize = 100;

/// Name of the high-cardinality metric, skipped during the cardinality scan.
const HIGH_CARDINALITY_METRIC: &str = "app_health_metrics_high_cardinality";

/// Health checker: periodically scrapes metrics and publishes check results.
pub struct Checker {
    metadata: Metadata,
    metrics: Vec<Vec<MetricFamily>>,
    gatherer: Box<dyn Gatherer>,
    scrape_period: Duration,
    max_scrapes: usize,
    num_validators: usize,
}

impl Checker {
    /// Returns a new health checker.
    ///
    /// `num_validators` is used for the high-cardinality threshold and is
    /// distinct from [`Metadata::num_validators`] (which the checks use).
    pub fn new(metadata: Metadata, gatherer: Box<dyn Gatherer>, num_validators: usize) -> Self {
        Self {
            metadata,
            metrics: Vec::new(),
            gatherer,
            scrape_period: SCRAPE_PERIOD,
            max_scrapes: MAX_SCRAPES,
            num_validators,
        }
    }

    /// Runs the checker until `ct` is cancelled. All logs emitted while
    /// running carry the `health` topic.
    pub async fn run(mut self, ct: CancellationToken) {
        let span = tracing::debug_span!("health", topic = "health");
        // Full-path trait call so it doesn't shadow the inherent `instrument`.
        tracing::Instrument::instrument(self.run_loop(ct), span).await;
    }

    /// The scrape/instrument loop, ticking every [`Checker::scrape_period`].
    async fn run_loop(&mut self, ct: CancellationToken) {
        let mut interval = tokio::time::interval(self.scrape_period);
        // Skip the immediate first tick so the first scrape happens after one
        // full period rather than immediately.
        interval.tick().await;

        loop {
            tokio::select! {
                () = ct.cancelled() => return,
                _ = interval.tick() => {
                    if let Err(error) = self.scrape() {
                        warn!(?error, "Failed to scrape metrics");
                        continue;
                    }
                    self.instrument();
                }
            }
        }
    }

    /// Scrapes metrics into the rolling window, detecting high-cardinality
    /// families and re-gathering once if any are found.
    fn scrape(&mut self) -> Result<()> {
        let mut scrape = self.gatherer.gather().map_err(Error::GatherMetrics)?;

        let threshold = LABELS_CARDINALITY_THRESHOLD.saturating_mul(self.num_validators);
        let mut gather_again = false;

        for family in &scrape {
            if family.name == HIGH_CARDINALITY_METRIC {
                continue;
            }

            let max_labels = max_label_count(family);

            if max_labels > threshold {
                HEALTH_METRICS.metrics_high_cardinality[&family.name]
                    .set(i64::try_from(max_labels)?);
                gather_again = true;
            }
        }

        if gather_again {
            scrape = self.gatherer.gather().map_err(Error::GatherMetrics)?;
        }

        self.metrics.push(scrape);
        if self.metrics.len() > self.max_scrapes {
            self.metrics.remove(0);
        }

        Ok(())
    }

    /// Runs all checks against the rolling window and updates the gauge.
    fn instrument(&self) {
        let query = new_query_func(&self.metrics);
        for check in &CHECKS {
            let failing = match (check.func)(&query, &self.metadata) {
                Ok(failing) => failing,
                Err(error) => {
                    // Logged every tick (no rate-limiting). The gauge is still
                    // cleared (set to 0) when the check errors.
                    warn!(check = check.name, ?error, "Health check failed");
                    false
                }
            };

            let value: i64 = i64::from(failing);
            HEALTH_METRICS.checks[&(check.severity.as_str().to_owned(), check.name.to_owned())]
                .set(value);
        }
    }
}

/// Maximum label count across a family's series, used for high-cardinality
/// detection. For histograms the synthetic `le` bucket label is excluded so the
/// count matches the protobuf model, where `le` is bucket structure rather than
/// a label.
fn max_label_count(family: &MetricFamily) -> usize {
    let exclude_le = family.metric_type == MetricType::Histogram;
    family
        .metrics
        .iter()
        .map(|metric| {
            if exclude_le {
                metric
                    .labels
                    .iter()
                    .filter(|label| label.name != "le")
                    .count()
            } else {
                metric.labels.len()
            }
        })
        .max()
        .unwrap_or(0)
}

/// Query function bound to a rolling window of scrapes.
pub(crate) struct QueryFunc<'a> {
    metrics: &'a [Vec<MetricFamily>],
}

/// Returns a query function over `metrics` (a rolling window of scrapes).
pub(crate) fn new_query_func(metrics: &[Vec<MetricFamily>]) -> QueryFunc<'_> {
    QueryFunc { metrics }
}

impl QueryFunc<'_> {
    /// For each scrape, finds the first family matching `name` with at least
    /// one series, applies `selector` to it, and collects the resulting
    /// samples; then reduces them with `reducer`.
    pub(crate) fn query(&self, name: &str, selector: Selector, reducer: Reducer) -> Result<f64> {
        let mut selected = Vec::new();

        for scrape in self.metrics {
            for family in scrape {
                if family.name != name || family.metrics.is_empty() {
                    continue;
                }
                match selector(family).map_err(|e| Error::LabelSelector(Box::new(e)))? {
                    None => continue,
                    Some(metric) => {
                        selected.push(metric);
                        break;
                    }
                }
            }
        }

        reducer(&selected).map_err(|e| Error::SeriesReducer(Box::new(e)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::health::{
        gatherer::GatherError,
        model::{LabelPair, Metric, MetricType, SampleValue},
    };

    type Responder =
        Box<dyn Fn(usize) -> std::result::Result<Vec<MetricFamily>, GatherError> + Send + Sync>;

    struct MockGatherer {
        calls: Arc<AtomicUsize>,
        responder: Responder,
    }

    impl MockGatherer {
        fn new(responder: Responder) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    calls: Arc::clone(&calls),
                    responder,
                },
                calls,
            )
        }
    }

    impl Gatherer for MockGatherer {
        fn gather(&self) -> std::result::Result<Vec<MetricFamily>, GatherError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            (self.responder)(n)
        }
    }

    fn empty_checker(responder: Responder, num_validators: usize) -> (Checker, Arc<AtomicUsize>) {
        let (mock, calls) = MockGatherer::new(responder);
        let checker = Checker::new(Metadata::default(), Box::new(mock), num_validators);
        (checker, calls)
    }

    fn labeled_family(name: &str) -> MetricFamily {
        MetricFamily {
            name: name.to_owned(),
            metric_type: MetricType::Gauge,
            metrics: vec![Metric {
                labels: vec![LabelPair {
                    name: "peer".to_owned(),
                    value: "1".to_owned(),
                }],
                value: Some(SampleValue::Gauge(1.0)),
            }],
        }
    }

    #[test]
    fn scrape_trims_rolling_window() {
        let (mut checker, calls) = empty_checker(Box::new(|_| Ok(Vec::new())), 1);

        for _ in 0..(MAX_SCRAPES + 2) {
            checker.scrape().expect("scrape");
        }

        assert_eq!(checker.metrics.len(), MAX_SCRAPES);
        assert_eq!(calls.load(Ordering::SeqCst), MAX_SCRAPES + 2);
    }

    #[test]
    fn scrape_high_cardinality_regathers() {
        // num_validators = 0 → threshold = 0, so any labelled series trips it.
        let (mut checker, calls) = empty_checker(
            Box::new(|_| Ok(vec![labeled_family("p2p_ping_success")])),
            0,
        );

        checker.scrape().expect("scrape");

        // Gathered once for the scan, once more after detecting high cardinality.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(checker.metrics.len(), 1);
    }

    #[test]
    fn scrape_propagates_gather_error() {
        let (mut checker, _calls) = empty_checker(Box::new(|_| Err("boom".into())), 1);

        let err = checker.scrape().expect_err("should error");
        assert_eq!(err.to_string(), "gather metrics");
        assert!(checker.metrics.is_empty());
    }

    #[tokio::test]
    async fn run_scrapes_until_cancelled() {
        let (mut checker, calls) = empty_checker(Box::new(|_| Ok(Vec::new())), 1);
        checker.scrape_period = Duration::from_millis(5);

        let ct = CancellationToken::new();
        let handle = tokio::spawn(checker.run(ct.clone()));

        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_secs(2))
            .expect("deadline overflow");
        while calls.load(Ordering::SeqCst) < 2 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "checker did not scrape"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        ct.cancel();
        handle.await.expect("join run task");
    }

    #[test]
    fn max_label_count_excludes_le_only_for_histograms() {
        let series = |metric_type, labels: &[&str]| MetricFamily {
            name: "x".to_owned(),
            metric_type,
            metrics: vec![Metric {
                labels: labels
                    .iter()
                    .map(|&name| LabelPair {
                        name: name.to_owned(),
                        value: "v".to_owned(),
                    })
                    .collect(),
                value: Some(SampleValue::Gauge(1.0)),
            }],
        };

        // Histogram bucket series: `le` is bucket structure, not counted.
        assert_eq!(
            max_label_count(&series(MetricType::Histogram, &["peer", "le"])),
            1
        );
        // Non-histogram: a literal `le` label is counted (matches the protobuf model).
        assert_eq!(
            max_label_count(&series(MetricType::Gauge, &["peer", "le"])),
            2
        );
    }
}
