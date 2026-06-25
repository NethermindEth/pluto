//! HTTP routes for the monitoring API.

use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};

use super::readiness::{ReadinessCheck, ReadinessError};

/// Shared state used by monitoring API handlers.
#[derive(Clone)]
pub struct MonitoringState {
    readiness: Arc<dyn ReadinessCheck>,
}

impl MonitoringState {
    /// Creates monitoring API state from a readiness checker.
    pub fn new(checker: impl ReadinessCheck) -> Self {
        Self {
            readiness: Arc::new(checker),
        }
    }

    /// Creates monitoring API state from an already shared readiness checker.
    pub fn from_shared(checker: Arc<dyn ReadinessCheck>) -> Self {
        Self { readiness: checker }
    }

    fn check_ready(&self) -> Result<(), ReadinessError> {
        self.readiness.check_ready()
    }
}

/// Builds a monitoring API router serving `/livez` and `/readyz`.
pub fn router(checker: impl ReadinessCheck) -> Router {
    router_with_state(MonitoringState::new(checker))
}

/// Builds a monitoring API router from preconstructed state.
pub fn router_with_state(state: MonitoringState) -> Router {
    Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .with_state(state)
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
