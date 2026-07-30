//! Prometheus metrics for beacon node requests.

use std::{future::Future, time::Instant};

use vise::{Counter, Histogram, LabeledFamily, Metrics};

/// Histogram buckets for beacon node request latency, in seconds.
const LATENCY_BUCKETS: [f64; 17] = [
    0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.25, 2.5, 2.75, 3.0, 5.0,
];

/// Metrics for beacon node requests, labelled by logical endpoint.
#[derive(Debug, Metrics)]
#[metrics(prefix = "app_eth2")]
pub struct Eth2Metrics {
    /// Latency in seconds for beacon node requests.
    #[metrics(buckets = &LATENCY_BUCKETS, labels = ["endpoint"])]
    pub latency_seconds: LabeledFamily<String, Histogram>,

    /// Total number of errors returned by beacon node requests.
    #[metrics(labels = ["endpoint"])]
    pub errors_total: LabeledFamily<String, Counter>,

    /// Total number of requests sent to the beacon node.
    #[metrics(labels = ["endpoint"])]
    pub requests_total: LabeledFamily<String, Counter>,
}

/// Global beacon node request metrics.
#[vise::register]
pub static ETH2_METRICS: vise::Global<Eth2Metrics> = vise::Global::new();

/// Awaits `fut`, recording a request, its latency, and (on `Err`) an error for
/// `endpoint`.
///
/// The generated beacon client methods return [`anyhow::Result`], so the
/// returned result type is preserved for the caller to handle as before.
pub async fn instrument<T, E, F>(endpoint: &str, fut: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let metrics = &*ETH2_METRICS;
    metrics.requests_total[endpoint].inc();

    let start = Instant::now();
    let result = fut.await;
    metrics.latency_seconds[endpoint].observe(start.elapsed().as_secs_f64());

    if result.is_err() {
        metrics.errors_total[endpoint].inc();
    }

    result
}

#[cfg(test)]
mod tests {
    use vise::{Format, Registry};

    use super::*;

    // Encodes the global metrics; tests use unique endpoint labels so their
    // counters never collide even though the global is shared.
    fn encode_global() -> String {
        let mut registry = Registry::empty();
        registry.register_metrics(&*ETH2_METRICS);

        let mut output = String::new();
        registry.encode(&mut output, Format::Prometheus).unwrap();
        output
    }

    #[tokio::test]
    async fn ok_records_request_and_latency_but_no_error() {
        instrument::<_, std::convert::Infallible, _>("test_ok", async { Ok(()) })
            .await
            .unwrap();
        let output = encode_global();

        assert!(output.contains(r#"app_eth2_requests_total{endpoint="test_ok"} 1"#));
        assert!(output.contains(r#"app_eth2_latency_seconds_count{endpoint="test_ok"} 1"#));
        assert!(!output.contains(r#"app_eth2_errors_total{endpoint="test_ok"}"#));
        for bucket in [
            "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "0.75", "1.0", "1.25", "1.5", "1.75",
            "2.0", "2.25", "2.5", "2.75", "3.0", "5.0",
        ] {
            assert!(
                output.contains(&format!(
                    r#"app_eth2_latency_seconds_bucket{{le="{bucket}",endpoint="test_ok"}}"#
                )),
                "missing bucket {bucket}: {output}"
            );
        }
    }

    #[tokio::test]
    async fn err_records_error() {
        let _: Result<(), &str> = instrument("test_err", async { Err("boom") }).await;
        let output = encode_global();

        assert!(output.contains(r#"app_eth2_requests_total{endpoint="test_err"} 1"#));
        assert!(output.contains(r#"app_eth2_errors_total{endpoint="test_err"} 1"#));
    }
}
