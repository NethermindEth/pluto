//! Bridge from vise's text exposition to the in-memory metric model.
//!
//! vise (via `prometheus-client`) exposes no structured/typed collection API;
//! metrics are only reachable by encoding to text. We encode the registry in
//! the exact format the `vise-exporter` serves to Prometheus
//! (`Format::OpenMetricsForPrometheus`) and parse it back, so the checker reads
//! the same metric names Prometheus/Grafana scrape. In that format vise strips
//! the OpenMetrics `_total` suffix from counter samples, so counter names match
//! the registered base name.

use vise::{Format, MetricsCollection, Registry};

use super::model::{LabelPair, Metric, MetricFamily, MetricType, SampleValue};

/// Error returned by a [`Gatherer`].
pub type GatherError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Source of metric families for the health checker.
pub trait Gatherer: Send + Sync {
    /// Gathers the current metric families.
    fn gather(&self) -> std::result::Result<Vec<MetricFamily>, GatherError>;
}

/// Gathers metrics from vise's global registry.
#[derive(Debug, Default)]
pub struct ViseGatherer;

impl Gatherer for ViseGatherer {
    fn gather(&self) -> std::result::Result<Vec<MetricFamily>, GatherError> {
        let registry = MetricsCollection::default().collect();
        gather_registry(&registry)
    }
}

/// Encodes `registry` to text and parses it into the metric model.
fn gather_registry(registry: &Registry) -> std::result::Result<Vec<MetricFamily>, GatherError> {
    let mut buffer = String::new();
    registry
        .encode(&mut buffer, Format::OpenMetricsForPrometheus)
        .map_err(|e| Box::new(e) as GatherError)?;
    Ok(parse_exposition(&buffer))
}

/// Parses a Prometheus/OpenMetrics text exposition into metric families.
///
/// Each `# TYPE` line starts a new family. A sample line is added to the
/// current family — except that a queried (counter/gauge) family rejects a
/// sample whose name doesn't match the `# TYPE` name, so a stray line can't be
/// folded into a queried metric; histogram/info families keep all their lines
/// for the cardinality scan. Comment lines and unparseable samples are skipped
/// (debug).
fn parse_exposition(text: &str) -> Vec<MetricFamily> {
    let mut families: Vec<MetricFamily> = Vec::new();
    let mut current: Option<MetricFamily> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("# TYPE ") {
            if let Some(family) = current.take() {
                families.push(family);
            }
            let (name, type_str) = split_once_ws(rest);
            current = Some(MetricFamily {
                name: name.to_owned(),
                metric_type: parse_type(type_str),
                metrics: Vec::new(),
            });
        } else if line.starts_with('#') {
            // # HELP / # UNIT / # EOF / other comment.
        } else if let Some(family) = current.as_mut() {
            if let Some((name, metric)) = parse_sample(line, family.metric_type) {
                // Counter/gauge families are queried by the checks, so they must
                // contain only their own series: reject a sample whose name does
                // not match the `# TYPE` name, which would otherwise be folded
                // into (e.g. summed onto) a queried metric. Histogram/info
                // families are never queried; keep all their lines so the
                // cardinality scan still sees them.
                let queried = matches!(family.metric_type, MetricType::Counter | MetricType::Gauge);
                if !queried || name == family.name {
                    family.metrics.push(metric);
                } else {
                    tracing::debug!(sample = line, "dropping sample: name mismatches its family");
                }
            } else {
                // We encode this text ourselves, so an unparseable sample means a
                // parser gap. Surface it at debug rather than dropping silently
                // (which could mask a queried metric). Not warn/error: those feed
                // back into `app_log_*_total` and the checker.
                tracing::debug!(sample = line, "dropping unparseable metric sample");
            }
        }
    }

    if let Some(family) = current.take() {
        families.push(family);
    }

    families
}

/// Parses a `# TYPE` type token into a [`MetricType`].
fn parse_type(type_str: &str) -> MetricType {
    match type_str.trim() {
        "counter" => MetricType::Counter,
        "gauge" => MetricType::Gauge,
        "histogram" => MetricType::Histogram,
        "info" => MetricType::Info,
        _ => MetricType::Unknown,
    }
}

/// Splits `s` at the first ASCII whitespace, trimming the remainder's leading
/// space.
fn split_once_ws(s: &str) -> (&str, &str) {
    match s.split_once(|c: char| c.is_ascii_whitespace()) {
        Some((head, tail)) => (head, tail.trim_start()),
        None => (s, ""),
    }
}

/// Parses one sample line (`name`, `name value`, or `name{labels} value`),
/// returning the sample's metric name and the parsed metric.
fn parse_sample(line: &str, metric_type: MetricType) -> Option<(&str, Metric)> {
    let (name, labels, value_str) = match line.split_once('{') {
        Some((name, rest)) => {
            let (labels, after) = scan_labels(rest)?;
            let value = after.split_ascii_whitespace().next()?;
            (name, labels, value)
        }
        None => {
            let mut parts = line.split_ascii_whitespace();
            let name = parts.next()?;
            let value = parts.next()?;
            (name, Vec::new(), value)
        }
    };

    let value: f64 = value_str.parse().ok()?;
    Some((name, make_metric(labels, value, metric_type)))
}

/// Scans label pairs starting just after the opening `{`, returning the pairs
/// and the remainder of the line after the closing `}`. Handles `\"`, `\\` and
/// `\n` escapes inside quoted values.
fn scan_labels(s: &str) -> Option<(Vec<LabelPair>, &str)> {
    let mut pairs = Vec::new();
    let mut chars = s.chars();

    loop {
        // Skip separators; detect the end of the label set.
        loop {
            let mut probe = chars.clone();
            match probe.next() {
                Some(c) if c == ',' || c.is_ascii_whitespace() => chars = probe,
                Some('}') => return Some((pairs, probe.as_str())),
                Some(_) => break,
                None => return None,
            }
        }

        // Read the label name up to '='.
        let mut name = String::new();
        loop {
            match chars.next() {
                Some('=') => break,
                Some(c) => name.push(c),
                None => return None,
            }
        }

        // Expect the opening quote.
        if chars.next() != Some('"') {
            return None;
        }

        // Read the value up to the closing quote, applying escapes.
        let mut value = String::new();
        loop {
            match chars.next() {
                Some('\\') => match chars.next() {
                    Some('n') => value.push('\n'),
                    Some('"') => value.push('"'),
                    Some('\\') => value.push('\\'),
                    Some(other) => value.push(other),
                    None => return None,
                },
                Some('"') => break,
                Some(c) => value.push(c),
                None => return None,
            }
        }

        pairs.push(LabelPair { name, value });
    }
}

/// Builds a [`Metric`] tagging `value` with the kind for `metric_type`.
/// Histogram/info/unknown samples carry no value.
fn make_metric(labels: Vec<LabelPair>, value: f64, metric_type: MetricType) -> Metric {
    let value = match metric_type {
        MetricType::Counter => Some(SampleValue::Counter(value)),
        MetricType::Gauge => Some(SampleValue::Gauge(value)),
        MetricType::Histogram | MetricType::Info | MetricType::Unknown => None,
    };
    Metric { labels, value }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vise::{Counter, Gauge, Histogram, LabeledFamily, Metrics, Registry};

    #[derive(Debug, Metrics)]
    #[metrics(prefix = "app_log")]
    struct LogLike {
        error_total: Counter,
    }

    #[derive(Debug, Metrics)]
    #[metrics(prefix = "core_tracker")]
    struct TrackerLike {
        #[metrics(labels = ["duty"])]
        failed_duties_total: LabeledFamily<String, Counter>,
    }

    #[derive(Debug, Metrics)]
    #[metrics(prefix = "p2p")]
    struct P2pLike {
        #[metrics(labels = ["peer"])]
        ping_success: LabeledFamily<String, Gauge>,
    }

    fn family<'a>(families: &'a [MetricFamily], name: &str) -> &'a MetricFamily {
        families
            .iter()
            .find(|f| f.name == name)
            .expect("family not found")
    }

    #[test]
    fn gather_emits_expected_names_and_strips_total() {
        let log = LogLike::default();
        log.error_total.inc();
        let tracker = TrackerLike::default();
        tracker.failed_duties_total[&"proposal".to_owned()].inc();
        let p2p = P2pLike::default();
        p2p.ping_success[&"peerA".to_owned()].set(1);

        let mut registry = Registry::empty();
        registry.register_metrics(&log);
        registry.register_metrics(&tracker);
        registry.register_metrics(&p2p);

        let families = gather_registry(&registry).expect("gather");

        // Counter `_total` is preserved as the registered base name (no doubling).
        let log_fam = family(&families, "app_log_error_total");
        assert_eq!(log_fam.metric_type, MetricType::Counter);
        assert_eq!(log_fam.metrics.len(), 1);
        assert_eq!(log_fam.metrics[0].value, Some(SampleValue::Counter(1.0)));

        let tracker_fam = family(&families, "core_tracker_failed_duties_total");
        assert_eq!(tracker_fam.metric_type, MetricType::Counter);
        assert_eq!(
            tracker_fam.metrics[0].value,
            Some(SampleValue::Counter(1.0))
        );
        assert_eq!(tracker_fam.metrics[0].labels[0].name, "duty");
        assert_eq!(tracker_fam.metrics[0].labels[0].value, "proposal");

        let p2p_fam = family(&families, "p2p_ping_success");
        assert_eq!(p2p_fam.metric_type, MetricType::Gauge);
        assert_eq!(p2p_fam.metrics[0].value, Some(SampleValue::Gauge(1.0)));
        assert_eq!(p2p_fam.metrics[0].labels[0].value, "peerA");
    }

    #[test]
    fn parses_labels_values_and_types() {
        let text = "\
# TYPE core_scheduler_validator_status gauge
core_scheduler_validator_status{pubkey=\"1\",status=\"pending\"} 1
core_scheduler_validator_status{pubkey=\"2\",status=\"active\"} 0
# HELP app_log_error_total Error count.
# TYPE app_log_error_total counter
app_log_error_total 7
# EOF";
        let families = parse_exposition(text);

        let status = family(&families, "core_scheduler_validator_status");
        assert_eq!(status.metric_type, MetricType::Gauge);
        assert_eq!(status.metrics.len(), 2);
        assert_eq!(status.metrics[0].labels.len(), 2);
        assert_eq!(status.metrics[0].labels[1].name, "status");
        assert_eq!(status.metrics[0].labels[1].value, "pending");
        assert_eq!(status.metrics[0].value, Some(SampleValue::Gauge(1.0)));

        let errors = family(&families, "app_log_error_total");
        assert_eq!(errors.metric_type, MetricType::Counter);
        assert_eq!(errors.metrics.len(), 1);
        assert!(errors.metrics[0].labels.is_empty());
        assert_eq!(errors.metrics[0].value, Some(SampleValue::Counter(7.0)));
    }

    #[test]
    fn unescapes_quoted_label_values() {
        let text = "\
# TYPE demo gauge
demo{path=\"a\\\"b\",note=\"x\\\\y\"} 3";
        let families = parse_exposition(text);
        let demo = family(&families, "demo");
        assert_eq!(demo.metrics[0].labels[0].value, "a\"b");
        assert_eq!(demo.metrics[0].labels[1].value, "x\\y");
    }

    #[derive(Debug, Metrics)]
    #[metrics(prefix = "demo")]
    struct Mixed {
        requests_total: Counter,
        #[metrics(labels = ["peer"])]
        connected: LabeledFamily<String, Gauge>,
        #[metrics(buckets = &[0.1, 1.0])]
        latency_seconds: Histogram,
    }

    #[test]
    fn histogram_does_not_corrupt_queried_families() {
        let m = Mixed::default();
        m.requests_total.inc_by(2);
        m.connected[&"peerA".to_owned()].set(1);
        m.latency_seconds.observe(0.5);
        m.latency_seconds.observe(2.0);

        let mut registry = Registry::empty();
        registry.register_metrics(&m);
        let families = gather_registry(&registry).expect("gather");

        // Queried counter family: exactly its own series and value — not
        // polluted by the histogram's `_bucket`/`_sum`/`_count` lines.
        let counter = family(&families, "demo_requests_total");
        assert_eq!(counter.metric_type, MetricType::Counter);
        assert_eq!(counter.metrics.len(), 1);
        assert_eq!(counter.metrics[0].value, Some(SampleValue::Counter(2.0)));

        // Queried gauge family: exactly its own series.
        let gauge = family(&families, "demo_connected");
        assert_eq!(gauge.metric_type, MetricType::Gauge);
        assert_eq!(gauge.metrics.len(), 1);
        assert_eq!(gauge.metrics[0].value, Some(SampleValue::Gauge(1.0)));

        // Histogram family is kept (for the cardinality scan); its sub-lines did
        // not leak into the families above and carry no counter/gauge value.
        let hist = family(&families, "demo_latency_seconds");
        assert_eq!(hist.metric_type, MetricType::Histogram);
        assert!(!hist.metrics.is_empty());
        assert!(hist.metrics.iter().all(|metric| metric.value.is_none()));
    }

    #[test]
    fn rejects_sample_name_mismatch_in_queried_family() {
        // A stray line whose name differs from the counter's `# TYPE` must not
        // be folded into the queried counter family.
        let text = "\
# TYPE app_log_error_total counter
app_log_error_total 5
app_log_error_total_bucket{le=\"1\"} 99";
        let families = parse_exposition(text);
        let errors = family(&families, "app_log_error_total");
        assert_eq!(errors.metrics.len(), 1);
        assert_eq!(errors.metrics[0].value, Some(SampleValue::Counter(5.0)));
    }

    #[test]
    fn format_pin_counter_encoding() {
        // Pins vise's OpenMetricsForPrometheus output: a future vise change
        // (e.g. `_total` doubling, a `_created` line, or different spacing) must
        // fail here rather than silently break the gatherer.
        let log = LogLike::default();
        log.error_total.inc_by(3);
        let mut registry = Registry::empty();
        registry.register_metrics(&log);

        let mut text = String::new();
        registry
            .encode(&mut text, vise::Format::OpenMetricsForPrometheus)
            .expect("encode");

        assert!(
            text.contains("# TYPE app_log_error_total counter"),
            "type line missing: {text}"
        );
        assert!(
            text.contains("app_log_error_total 3"),
            "sample line missing/changed: {text}"
        );
        assert!(
            !text.contains("app_log_error_total_total"),
            "_total must not be doubled: {text}"
        );
        assert!(
            !text.contains("_created"),
            "_created must not be emitted: {text}"
        );
    }

    #[test]
    fn special_float_values_parse() {
        // `+Inf` / `-Inf` / `NaN` are valid f64 strings, so such sample values
        // parse rather than being silently dropped.
        let text = "\
# TYPE g gauge
g{k=\"a\"} +Inf
g{k=\"b\"} -Inf
g{k=\"c\"} NaN
g{k=\"d\"} 1.5";
        let families = parse_exposition(text);
        let g = family(&families, "g");
        assert_eq!(g.metrics.len(), 4);
    }
}
