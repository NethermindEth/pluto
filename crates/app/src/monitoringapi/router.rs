//! HTTP routes for the monitoring API.

use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::get,
};
use vise::{Format, MetricsCollection};

use super::readiness::{ReadinessCheck, ReadinessError};

/// Shared state used by monitoring API handlers.
#[derive(Clone)]
pub struct MonitoringState {
    readiness: Arc<dyn ReadinessCheck>,
    /// Global labels stamped onto every series in the `/metrics` exposition
    /// (Charon parity: `cluster_hash`, `cluster_name`, `cluster_peer`, ...).
    labels: Arc<[(String, String)]>,
}

impl MonitoringState {
    /// Creates monitoring API state from a readiness checker, with no global
    /// metric labels (see [`with_labels`](Self::with_labels)).
    pub fn new(checker: impl ReadinessCheck) -> Self {
        Self {
            readiness: Arc::new(checker),
            labels: Arc::from([]),
        }
    }

    /// Creates monitoring API state from an already shared readiness checker.
    pub fn from_shared(checker: Arc<dyn ReadinessCheck>) -> Self {
        Self {
            readiness: checker,
            labels: Arc::from([]),
        }
    }

    /// Sets the global labels stamped onto every metric in the `/metrics`
    /// exposition.
    #[must_use]
    pub fn with_labels(mut self, labels: impl IntoIterator<Item = (String, String)>) -> Self {
        self.labels = labels.into_iter().collect();
        self
    }

    fn check_ready(&self) -> Result<(), ReadinessError> {
        self.readiness.check_ready()
    }
}

/// Builds a monitoring API router serving `/livez` and `/readyz`.
pub fn router(checker: impl ReadinessCheck) -> Router {
    router_with_state(MonitoringState::new(checker))
}

/// Builds a monitoring API router from preconstructed state, serving Prometheus
/// `/metrics` plus the `/livez` and `/readyz` probes.
pub fn router_with_state(state: MonitoringState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .with_state(state)
}

/// Serves the process metrics in the OpenMetrics-for-Prometheus text format —
/// the same exposition the `vise-exporter` produces. Encodes the global `vise`
/// registry on each scrape.
async fn metrics(State(state): State<MonitoringState>) -> Response {
    let registry = MetricsCollection::default()
        .with_labels(state.labels.iter().cloned())
        .collect();
    let mut buffer = String::new();
    if let Err(error) = registry.encode(&mut buffer, Format::OpenMetricsForPrometheus) {
        // Encoding the in-process registry should never fail; surface a 500
        // rather than a partial body if it somehow does.
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to encode metrics: {error}"),
        )
            .into_response();
    }

    ([(CONTENT_TYPE, Format::OPEN_METRICS_CONTENT_TYPE)], buffer).into_response()
}

async fn livez() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn readyz(State(state): State<MonitoringState>) -> Response {
    match state.check_ready() {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;

    use super::*;
    use crate::monitoringapi::{ReadinessError, ReadyState};

    const BODY_LIMIT: usize = 65_536;

    async fn get(app: Router, uri: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("failed to build request: {error}"));
        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("request failed: {error}"));
        let status = response.status();
        let body = to_bytes(response.into_body(), BODY_LIMIT)
            .await
            .unwrap_or_else(|error| panic!("failed to read response body: {error}"));
        let body = String::from_utf8(body.to_vec())
            .unwrap_or_else(|error| panic!("response body should be utf8: {error}"));

        (status, body)
    }

    #[tokio::test]
    async fn livez_returns_ok() {
        let app = router(ReadyState::new());

        let (status, body) = get(app, "/livez").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn readyz_returns_ok_when_ready() {
        let app = router(ReadyState::ready());

        let (status, body) = get(app, "/readyz").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn readyz_returns_failure_reason_when_not_ready() {
        let state = ReadyState::new();
        state.set_error(ReadinessError::BeaconNodeDown);
        let app = router(state);

        let (status, body) = get(app, "/readyz").await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, "beacon node down");
    }

    #[tokio::test]
    async fn metrics_serves_prometheus_exposition() {
        // Touch a monitoring gauge so the global `vise` registry is initialised
        // and its series appears in the exposition.
        crate::monitoringapi::MONITORING_METRICS
            .monitoring_readyz
            .set(1);

        let request = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .expect("build request");
        let response = router(ReadyState::new())
            .oneshot(request)
            .await
            .expect("request");

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("content-type header")
            .to_str()
            .expect("utf8 content-type")
            .to_owned();
        assert!(
            content_type.contains("openmetrics-text"),
            "unexpected content-type: {content_type}"
        );

        let body = to_bytes(response.into_body(), BODY_LIMIT)
            .await
            .expect("read body");
        let body = String::from_utf8(body.to_vec()).expect("utf8 body");
        assert!(
            body.contains("app_monitoring_readyz"),
            "metrics body missing readyz gauge: {body}"
        );
    }

    #[tokio::test]
    async fn metrics_stamps_global_labels_on_series() {
        crate::monitoringapi::MONITORING_METRICS
            .monitoring_readyz
            .set(1);

        let state = MonitoringState::new(ReadyState::new()).with_labels([
            ("cluster_network".to_owned(), "sepolia".to_owned()),
            ("cluster_peer".to_owned(), "test-peer".to_owned()),
        ]);
        let app = router_with_state(state);

        let (status, body) = get(app, "/metrics").await;

        assert_eq!(status, StatusCode::OK);
        // Every series carries the injected global labels.
        assert!(
            body.contains("cluster_network=\"sepolia\""),
            "metrics body missing global cluster_network label: {body}"
        );
        assert!(
            body.contains("cluster_peer=\"test-peer\""),
            "metrics body missing global cluster_peer label: {body}"
        );
    }

    #[tokio::test]
    async fn readyz_observes_readiness_state_updates() {
        let state = ReadyState::new();
        let app = router(state.clone());

        let (status, body) = get(app.clone(), "/readyz").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, "ready check uninitialised");

        state.set_ready();
        let (status, body) = get(app, "/readyz").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }
}
