//! Validator API error type.

use std::fmt;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// A validator API error carrying the HTTP status, a human-readable message,
/// and an optional source error for debug logging.
#[derive(Debug)]
pub struct ApiError {
    /// HTTP status code returned to the client.
    pub status_code: StatusCode,
    /// Safe, human-readable message returned in the response body.
    pub message: String,
    /// Original error, surfaced in debug logs only.
    pub source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl ApiError {
    /// Builds a new `ApiError` with the given status and message.
    #[must_use]
    pub fn new(status_code: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status_code,
            message: message.into(),
            source: None,
        }
    }

    /// Convenience constructor for `404 NotFound` responses.
    #[must_use]
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "NotFound")
    }

    /// Attaches a source error for debug logging.
    #[must_use]
    pub fn with_source<E>(mut self, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(source));
        self
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(err) => write!(
                f,
                "api error[status={},msg={}]: {}",
                self.status_code.as_u16(),
                self.message,
                err
            ),
            None => write!(
                f,
                "api error[status={},msg={}]",
                self.status_code.as_u16(),
                self.message
            ),
        }
    }
}

impl std::error::Error for ApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// The JSON body Charon writes for any error response.
///
/// See `errorResponse` in `eth2types.go:20`.
#[derive(Debug, Serialize)]
struct ErrorBody {
    code: u16,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            code: self.status_code.as_u16(),
            message: self.message,
        };

        (self.status_code, Json(body)).into_response()
    }
}
