//! Validator API Prometheus metrics.

use std::{
    sync::{Mutex, OnceLock},
    time::Instant,
};

use vise::{Counter, EncodeLabelSet, Family, Gauge, Histogram, LabeledFamily, Metrics};

/// Upper bound on the `user_agent` label length, matching Charon's
/// `maxUserAgentLen`. A VC is free to send an arbitrarily long header; without
/// a cap it would land verbatim in a metric label.
const MAX_USER_AGENT_LEN: usize = 128;

/// Canonical `content_type` label values. The raw header is never used as a
/// label: charset and boundary parameters would inflate cardinality.
pub const CONTENT_TYPE_JSON: &str = "application/json";
/// SSZ request bodies (block submission).
pub const CONTENT_TYPE_SSZ: &str = "application/octet-stream";

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

/// The user agent currently reported as active, so it can be zeroed when a
/// different one is seen. See [`observe_user_agent`].
static LAST_USER_AGENT: OnceLock<Mutex<Option<String>>> = OnceLock::new();

/// Marks the given user agent as observed, zeroing the previously observed one.
///
/// Charon uses a `ResetGaugeVec` and deletes every prior series so exactly one
/// `vc_user_agent` series exists at a time (`app/promauto/resetgauge.go`).
/// `vise::Family` exposes no removal API, so the closest equivalent is to set
/// the previous label to `0` and leave the (now-zero) series in place. Scrapers
/// still see a single series at `1`, which is what the dashboards key on.
///
/// The value is truncated to [`MAX_USER_AGENT_LEN`] bytes on a character
/// boundary and stripped of invalid UTF-8, matching Charon's guard.
pub fn observe_user_agent(user_agent: &str) {
    let user_agent = sanitise_user_agent(user_agent);
    if user_agent.is_empty() {
        return;
    }

    let mut last = LAST_USER_AGENT
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if last.as_deref() == Some(user_agent.as_str()) {
        return;
    }

    if let Some(previous) = last.as_deref() {
        METRICS.vc_user_agent[previous].set(0);
    }
    METRICS.vc_user_agent[user_agent.as_str()].set(1);
    *last = Some(user_agent);
}

/// Truncates to [`MAX_USER_AGENT_LEN`] bytes (never splitting a UTF-8
/// character) so a hostile or verbose VC cannot blow up the label.
fn sanitise_user_agent(user_agent: &str) -> String {
    let mut end = user_agent.len().min(MAX_USER_AGENT_LEN);
    while end > 0 && !user_agent.is_char_boundary(end) {
        end -= 1;
    }

    user_agent[..end].to_owned()
}

/// Normalises a `Content-Type` header into a bounded label value.
///
/// Mirrors Charon's negotiation (`core/validatorapi/router.go`): a missing
/// header is treated as JSON, anything containing `application/json` or
/// `application/octet-stream` maps to that canonical value, and an
/// unrecognised type yields `None` (the caller rejects it with `415` and does
/// *not* count it in `request_total`).
pub fn normalise_content_type(header: Option<&str>) -> Option<&'static str> {
    match header {
        None => Some(CONTENT_TYPE_JSON),
        Some(value) if value.contains(CONTENT_TYPE_JSON) => Some(CONTENT_TYPE_JSON),
        Some(value) if value.contains(CONTENT_TYPE_SSZ) => Some(CONTENT_TYPE_SSZ),
        Some(_) => None,
    }
}

/// Converts a request path into a bounded metric label by replacing dynamic
/// segments with placeholders.
///
/// Without this, paths like `/eth/v2/beacon/blocks/0x<root>` produce a unique
/// label value per block root, growing cardinality without bound. Ported from
/// Charon's `proxyPathLabel`.
pub fn proxy_path_label(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }

    let segments: Vec<&str> = trimmed.split('/').collect();
    let mut labels = Vec::with_capacity(segments.len());
    for (i, segment) in segments.iter().enumerate() {
        let label = if segment.starts_with("0x") {
            // Block/state roots, validator pubkeys.
            "{hex}"
        } else if !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()) {
            // Slots, epochs, validator indices.
            "{n}"
        } else if i > 0 && segments[i - 1] == "peers" {
            // libp2p peer IDs are base58/base32, neither hex nor numeric.
            "{peer_id}"
        } else {
            segment
        };
        labels.push(label);
    }

    labels.join("_")
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
/// The path label is bounded by [`proxy_path_label`].
#[must_use = "drop the guard to record latency, or hold it for the request lifetime"]
pub struct ProxyLatencyTimer {
    path_label: String,
    start: Instant,
}

impl ProxyLatencyTimer {
    /// Starts a new proxy latency timer for the given path.
    pub fn start(path: &str) -> Self {
        Self {
            path_label: proxy_path_label(path),
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
            // Dynamic segments collapse to placeholders.
            (
                "/eth/v2/beacon/blocks/0x0342020caa311b9f104cd1b223872b7d416d868d2e5add744e7af8265ba435ff",
                "eth_v2_beacon_blocks_{hex}",
            ),
            ("/eth/v2/beacon/blocks/head", "eth_v2_beacon_blocks_head"),
            (
                "/eth/v1/beacon/blocks/123456/root",
                "eth_v1_beacon_blocks_{n}_root",
            ),
            (
                "/eth/v1/beacon/states/head/validators/0xa1b2c3",
                "eth_v1_beacon_states_head_validators_{hex}",
            ),
            (
                "/eth/v1/validator/duties/attester/42",
                "eth_v1_validator_duties_attester_{n}",
            ),
            (
                "/eth/v1/node/peers/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N",
                "eth_v1_node_peers_{peer_id}",
            ),
            ("/eth/v1/node/peers", "eth_v1_node_peers"),
        ];
        for (input, expected) in cases {
            assert_eq!(proxy_path_label(input), expected, "path {input}");
        }
    }

    /// The whole point of the placeholders: distinct block roots must not mint
    /// a new series each.
    #[test]
    fn proxy_path_label_is_bounded() {
        let a = proxy_path_label(
            "/eth/v2/beacon/blocks/0x0342020caa311b9f104cd1b223872b7d416d868d2e5add744e7af8265ba435ff",
        );
        let b = proxy_path_label(
            "/eth/v2/beacon/blocks/0x04639c0c1fff050014a818280fcd12dc8880077583e83fee738afd74ade618c0",
        );
        assert_eq!(a, b);
    }

    #[test]
    fn content_type_normalisation() {
        assert_eq!(normalise_content_type(None), Some(CONTENT_TYPE_JSON));
        assert_eq!(
            normalise_content_type(Some("application/json")),
            Some(CONTENT_TYPE_JSON),
        );
        // Parameters must not leak into the label.
        assert_eq!(
            normalise_content_type(Some("application/json; charset=utf-8")),
            Some(CONTENT_TYPE_JSON),
        );
        assert_eq!(
            normalise_content_type(Some("application/octet-stream")),
            Some(CONTENT_TYPE_SSZ),
        );
        assert_eq!(normalise_content_type(Some("text/plain")), None);
    }

    #[test]
    fn user_agent_is_truncated_on_a_char_boundary() {
        let long = "é".repeat(MAX_USER_AGENT_LEN);
        let sanitised = sanitise_user_agent(&long);
        assert!(sanitised.len() <= MAX_USER_AGENT_LEN);
        // Truncation must not split the 2-byte character.
        assert!(long.starts_with(&sanitised));

        assert_eq!(sanitise_user_agent("lighthouse/v8"), "lighthouse/v8");
    }

    #[test]
    fn helpers_do_not_panic() {
        inc_api_errors("test_endpoint", 500);
        inc_content_type("test_endpoint", CONTENT_TYPE_JSON);
        observe_user_agent("test-agent/1.0");
        // A second, different agent zeroes the first.
        observe_user_agent("test-agent/2.0");
        observe_user_agent("");
        {
            let _t = ApiLatencyTimer::start("test_endpoint");
        }
        {
            let _t = ProxyLatencyTimer::start("/eth/v1/test");
        }
    }
}
