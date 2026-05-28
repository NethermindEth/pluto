//! Test-only request-capture helper for [`crate::BeaconMock`].
//!
//! The Go validator mock tests assert on what the SUT submits by setting
//! callback fields on `beaconmock.Mock` (`SubmitAttestationsFunc`,
//! `SubmitAggregateAttestationsFunc`, ...). `BeaconMock` has no such hook, so
//! tests register a high-priority [`wiremock::Mock`] that decodes the POST body
//! into JSON and appends it into a shared buffer.
//!
//! Mounts above [`mount_endpoint_override`](crate::beaconmock) and the default
//! routes, so the SUT sees a 200 and the test sees the request body.

use std::sync::{Arc, Mutex};

use serde_json::Value;
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path, path_regex},
};

/// Priority used by [`SubmissionCapture`]. Wiremock matches the lowest priority
/// first (and rejects `0`); `1` wins over both [`crate::beaconmock`]'s defaults
/// (`255`) and the override layer (`50`).
pub const CAPTURE_PRIORITY: u8 = 1;

/// Endpoint matcher — plain path or wiremock regex.
#[derive(Debug, Clone)]
pub enum EndpointMatch {
    /// Exact path (e.g. `"/eth/v1/beacon/pool/attestations"`).
    Path(String),
    /// `wiremock` path regex (must start with `^`).
    Regex(String),
}

impl EndpointMatch {
    /// Returns an [`EndpointMatch::Path`] from any string-like input.
    pub fn path(p: impl Into<String>) -> Self {
        Self::Path(p.into())
    }

    /// Returns an [`EndpointMatch::Regex`] from any string-like input.
    pub fn regex(p: impl Into<String>) -> Self {
        Self::Regex(p.into())
    }
}

/// Shared buffer of captured POST/PUT bodies, parsed as JSON.
#[derive(Debug, Clone, Default)]
pub struct SubmissionCapture {
    inner: Arc<Mutex<Vec<Value>>>,
}

impl SubmissionCapture {
    /// Mounts a capture handler on `server` matching `http_method` +
    /// `endpoint`, responding with `response_body` (200) and recording every
    /// request body for later inspection.
    pub async fn mount(
        server: &MockServer,
        http_method: &'static str,
        endpoint: EndpointMatch,
        response_body: Value,
    ) -> Self {
        let capture = Self::default();
        let writer = Arc::clone(&capture.inner);
        let response = ResponseTemplate::new(200).set_body_json(response_body);

        let route = Mock::given(method(http_method));
        let route = match endpoint {
            EndpointMatch::Path(p) => route.and(path(p)),
            EndpointMatch::Regex(r) => route.and(path_regex(r)),
        };

        route
            .respond_with(move |request: &Request| {
                if let Ok(value) = serde_json::from_slice::<Value>(&request.body) {
                    writer.lock().expect("capture mutex poisoned").push(value);
                }
                response.clone()
            })
            .with_priority(CAPTURE_PRIORITY)
            .mount(server)
            .await;

        capture
    }

    /// Captured bodies in submission order. Does not drain.
    pub fn snapshot(&self) -> Vec<Value> {
        self.inner.lock().expect("capture mutex poisoned").clone()
    }

    /// Drains the buffer and returns every captured body in submission order.
    pub fn take(&self) -> Vec<Value> {
        std::mem::take(&mut *self.inner.lock().expect("capture mutex poisoned"))
    }

    /// Number of captured submissions.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("capture mutex poisoned").len()
    }

    /// True if nothing has been captured.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beaconmock::BeaconMock;
    use serde_json::json;

    #[tokio::test]
    async fn captures_post_body() {
        let mock = BeaconMock::builder().build().await.expect("build mock");
        let capture = SubmissionCapture::mount(
            mock.server(),
            "POST",
            EndpointMatch::path("/eth/v1/beacon/pool/attestations"),
            json!({}),
        )
        .await;

        let url = format!("{}/eth/v1/beacon/pool/attestations", mock.uri());
        let body = json!([{ "slot": "1", "index": "0" }]);
        let status = reqwest::Client::new()
            .post(&url)
            .json(&body)
            .send()
            .await
            .expect("send")
            .status();
        assert_eq!(status, 200);

        let captured = capture.take();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0], body);
    }

    #[tokio::test]
    async fn regex_endpoint_matches() {
        let mock = BeaconMock::builder().build().await.expect("build mock");
        let capture = SubmissionCapture::mount(
            mock.server(),
            "POST",
            EndpointMatch::regex(r"^/eth/v1/validator/duties/attester/[0-9]+$"),
            json!({"data": []}),
        )
        .await;

        let url = format!("{}/eth/v1/validator/duties/attester/3", mock.uri());
        let status = reqwest::Client::new()
            .post(&url)
            .json(&json!(["1"]))
            .send()
            .await
            .expect("send")
            .status();
        assert_eq!(status, 200);
        assert_eq!(capture.len(), 1);
    }
}
