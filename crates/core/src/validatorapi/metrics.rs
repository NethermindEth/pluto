//! Validator API Prometheus metrics.

use std::time::Instant;

use vise::{Counter, EncodeLabelSet, Family, Gauge, Histogram, LabeledFamily, Metrics};

/// Latency histogram buckets in seconds.
pub const BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Metrics for the validator API.
#[derive(Debug, Metrics)]
#[metrics(prefix = "core_validatorapi")]
pub struct ValidatorApiMetrics {
    /// Request latencies in seconds by endpoint.
    #[metrics(buckets = &BUCKETS, labels = ["endpoint"])]
    pub request_latency_seconds: LabeledFamily<String, Histogram>,

    /// Proxy request latencies in seconds by path.
    #[metrics(buckets = &BUCKETS, labels = ["path"])]
    pub proxy_request_latency_seconds: LabeledFamily<String, Histogram>,

    /// Total number of request errors by endpoint and status code.
    pub request_error_total: Family<EndpointStatusLabels, Counter>,

    /// Total number of requests by endpoint and content type.
    pub request_total: Family<EndpointContentTypeLabels, Counter>,

    /// Gauge set to 1 when a request from the given user agent is observed.
    #[metrics(labels = ["user_agent"])]
    pub vc_user_agent: LabeledFamily<String, Gauge>,
}

/// Labels for [`ValidatorApiMetrics::request_error_total`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct EndpointStatusLabels {
    /// Endpoint name as registered in the router.
    pub endpoint: String,
    /// HTTP status code as a string.
    pub status_code: String,
}

/// Labels for [`ValidatorApiMetrics::request_total`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct EndpointContentTypeLabels {
    /// Endpoint name as registered in the router.
    pub endpoint: String,
    /// Request content type (e.g. `application/json`,
    /// `application/octet-stream`).
    pub content_type: String,
}

/// Global validator API metrics registry.
#[vise::register]
pub static METRICS: vise::Global<ValidatorApiMetrics> = vise::Global::new();

/// Increments the request-error counter for the given endpoint and status.
pub fn inc_api_errors(endpoint: &str, status_code: u16) {
    METRICS.request_error_total[&EndpointStatusLabels {
        endpoint: endpoint.to_owned(),
        status_code: status_code.to_string(),
    }]
        .inc();
}

/// Records that a request with the given content type hit the given endpoint.
pub fn inc_content_type(endpoint: &str, content_type: &str) {
    METRICS.request_total[&EndpointContentTypeLabels {
        endpoint: endpoint.to_owned(),
        content_type: content_type.to_owned(),
    }]
        .inc();
}

/// Marks the given user agent as observed.
pub fn observe_user_agent(user_agent: &str) {
    METRICS.vc_user_agent[user_agent].set(1);
}

/// RAII timer that observes elapsed seconds into
/// [`ValidatorApiMetrics::request_latency_seconds`] when dropped.
#[must_use = "drop the guard to record latency, or hold it for the request lifetime"]
pub struct ApiLatencyTimer {
    endpoint: String,
    start: Instant,
}

impl ApiLatencyTimer {
    /// Starts a new latency timer for the given endpoint.
    pub fn start(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            start: Instant::now(),
        }
    }
}

impl Drop for ApiLatencyTimer {
    fn drop(&mut self) {
        METRICS.request_latency_seconds[self.endpoint.as_str()]
            .observe(self.start.elapsed().as_secs_f64());
    }
}

/// RAII timer that observes elapsed seconds into
/// [`ValidatorApiMetrics::proxy_request_latency_seconds`] when dropped.
///
/// The path label is normalised: `/` is replaced with `_` and leading and
/// trailing underscores are stripped.
#[must_use = "drop the guard to record latency, or hold it for the request lifetime"]
pub struct ProxyLatencyTimer {
    path_label: String,
    start: Instant,
}

impl ProxyLatencyTimer {
    /// Starts a new proxy latency timer for the given path.
    pub fn start(path: &str) -> Self {
        Self {
            path_label: path.replace('/', "_").trim_matches('_').to_owned(),
            start: Instant::now(),
        }
    }
}

impl Drop for ProxyLatencyTimer {
    fn drop(&mut self) {
        METRICS.proxy_request_latency_seconds[self.path_label.as_str()]
            .observe(self.start.elapsed().as_secs_f64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_path_transform() {
        let cases = [
            ("/eth/v1/node/version", "eth_v1_node_version"),
            ("/", ""),
            ("eth/v1", "eth_v1"),
            ("/a/b/", "a_b"),
        ];
        for (input, expected) in cases {
            let got = input.replace('/', "_");
            assert_eq!(got.trim_matches('_'), expected);
        }
    }

    #[test]
    fn helpers_do_not_panic() {
        inc_api_errors("test_endpoint", 500);
        inc_content_type("test_endpoint", "application/json");
        observe_user_agent("test-agent/1.0");
        {
            let _t = ApiLatencyTimer::start("test_endpoint");
        }
        {
            let _t = ProxyLatencyTimer::start("/eth/v1/test");
        }
    }
}
