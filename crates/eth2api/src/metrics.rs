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

/// Whether a beacon-node response represents a successful (2xx) outcome.
///
/// The generated client surfaces beacon-node HTTP errors as
/// `Ok(Response::BadRequest(..))` (and other non-2xx variants) rather than an
/// `Err`, so a plain [`Result::is_err`] check never fires for them.
/// Implementations classify the response variant so [`instrument`] can count
/// HTTP errors, matching Charon's `eth2wrap` semantics.
pub trait BeaconResponse {
    /// Returns `true` when the response is a 2xx success variant.
    fn is_success(&self) -> bool;
}

// Unit responses (used by tests) always count as successful; error accounting
// for them relies solely on the `Result`.
impl BeaconResponse for () {
    fn is_success(&self) -> bool {
        true
    }
}

/// Implements [`BeaconResponse`] for generated response enums, treating the
/// listed variants (the 2xx statuses) as success and every other variant as an
/// error.
macro_rules! impl_beacon_response {
    ($($ty:ident => { $($ok:ident),+ $(,)? }),+ $(,)?) => {
        $(
            impl BeaconResponse for crate::$ty {
                fn is_success(&self) -> bool {
                    matches!(self, $( crate::$ty::$ok { .. } )|+)
                }
            }
        )+
    };
}

impl_beacon_response! {
    GetSpecResponse => { Ok },
    GetGenesisResponse => { Ok },
    GetForkScheduleResponse => { Ok },
    GetSyncingStatusResponse => { Ok },
    GetNodeVersionResponse => { Ok },
    GetPeerCountResponse => { Ok },
    GetAttesterDutiesResponse => { Ok },
    GetProposerDutiesResponse => { Ok },
    GetSyncCommitteeDutiesResponse => { Ok },
    ProduceBlockV3Response => { Ok, OkBinary },
    ProduceAttestationDataResponse => { Ok, OkBinary },
    GetAggregatedAttestationV2Response => { Ok, OkBinary },
    ProduceSyncCommitteeContributionResponse => { Ok },
    PostStateValidatorsResponse => { Ok },
    SubmitPoolAttestationsV2Response => { Ok },
    SubmitPoolVoluntaryExitResponse => { Ok },
    PublishBlockV2Response => { Ok, Accepted },
    RegisterValidatorResponse => { Ok },
    PublishContributionAndProofsResponse => { Ok },
}

/// Awaits `fut`, recording a request, its latency, and—on transport error or a
/// non-2xx response—an error for `endpoint`.
///
/// The generated beacon client methods return [`anyhow::Result`], so the
/// returned result type is preserved for the caller to handle as before.
/// Unlike a plain `Result::is_err` check, HTTP error responses (which the
/// client surfaces as `Ok(Response::BadRequest(..))` etc.) are counted as
/// errors, matching Charon's `eth2wrap` semantics.
pub async fn instrument<T, E, F>(endpoint: &str, fut: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
    T: BeaconResponse,
{
    let metrics = &*ETH2_METRICS;
    metrics.requests_total[endpoint].inc();

    let start = Instant::now();
    let result = fut.await;
    metrics.latency_seconds[endpoint].observe(start.elapsed().as_secs_f64());

    let is_error = match &result {
        Ok(response) => !response.is_success(),
        Err(_) => true,
    };
    if is_error {
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

    #[tokio::test]
    async fn non_2xx_response_records_error() {
        // The client surfaces beacon-node HTTP errors as an `Ok(non-2xx
        // variant)`, which must still be counted as an error.
        let _: Result<crate::GetAttesterDutiesResponse, std::convert::Infallible> =
            instrument("test_http_err", async {
                Ok(crate::GetAttesterDutiesResponse::Unknown)
            })
            .await;
        let output = encode_global();

        assert!(output.contains(r#"app_eth2_requests_total{endpoint="test_http_err"} 1"#));
        assert!(output.contains(r#"app_eth2_errors_total{endpoint="test_http_err"} 1"#));
    }

    #[tokio::test]
    async fn additional_2xx_variant_records_no_error() {
        // A non-`Ok` but still 2xx variant (e.g. `202 Accepted`) is a success
        // and must not increment the error counter.
        let _: Result<crate::PublishBlockV2Response, std::convert::Infallible> =
            instrument("test_http_accepted", async {
                Ok(crate::PublishBlockV2Response::Accepted)
            })
            .await;
        let output = encode_global();

        assert!(output.contains(r#"app_eth2_requests_total{endpoint="test_http_accepted"} 1"#));
        assert!(!output.contains(r#"app_eth2_errors_total{endpoint="test_http_accepted"}"#));
    }
}

#[cfg(test)]
mod exposition {
    use vise::{Format, MetricsCollection};

    use super::*;

    // Pins the exact `/metrics` exposition the beacon-node health Grafana panel
    // depends on: the OpenMetrics-for-Prometheus series names, the `endpoint`
    // label (used to exclude `submit_validator_registrations`), and the global
    // `cluster_*` labels the monitoring API stamps onto every series.
    #[tokio::test]
    async fn matches_beacon_health_dashboard_contract() {
        instrument::<_, std::convert::Infallible, _>("dashboard_probe", async { Ok(()) })
            .await
            .unwrap();
        let _: Result<(), &str> = instrument("dashboard_probe", async { Err("x") }).await;

        let registry = MetricsCollection::default()
            .with_labels([("cluster_peer".to_string(), "p0".to_string())])
            .collect();
        let mut output = String::new();
        registry
            .encode(&mut output, Format::OpenMetricsForPrometheus)
            .unwrap();

        // Series names the dashboard query references, exactly as exposed.
        assert!(output.contains("app_eth2_errors_total{"));
        assert!(output.contains("app_eth2_latency_seconds_count{"));
        assert!(output.contains("app_eth2_latency_seconds_bucket{"));
        // OpenMetrics counter suffixing must not double the `_total`.
        assert!(!output.contains("app_eth2_errors_total_total"));
        // `endpoint` label present for the dashboard's endpoint filter, and the
        // monitoring API's global labels stamped onto the series.
        assert!(output.contains(r#"endpoint="dashboard_probe""#));
        assert!(output.contains(r#"cluster_peer="p0""#));
    }
}
