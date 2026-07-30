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

    /// Attaches a boxed source error for debug logging. Use this when the
    /// upstream error is not `std::error::Error` itself (e.g. `anyhow::Error`,
    /// which only implements `AsRef<dyn Error>` and converts via `.into()`).
    #[must_use]
    pub fn with_boxed_source(
        mut self,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        self.source = Some(source);
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
        // The `source` never reaches the client (it can carry internal detail),
        // but it is the only place the underlying cause is recorded — e.g. which
        // field an SSZ/JSON body failed to decode. Log it here, on the single
        // path every error response takes, otherwise it is silently dropped.
        if let Some(source) = &self.source {
            if self.status_code.is_server_error() {
                tracing::error!(
                    status = self.status_code.as_u16(),
                    message = %self.message,
                    source = %DisplayChain(source.as_ref()),
                    "validator api error"
                );
            } else {
                tracing::debug!(
                    status = self.status_code.as_u16(),
                    message = %self.message,
                    source = %DisplayChain(source.as_ref()),
                    "validator api error"
                );
            }
        }

        let body = ErrorBody {
            code: self.status_code.as_u16(),
            message: self.message,
        };

        (self.status_code, Json(body)).into_response()
    }
}

/// Renders an error together with its `source()` chain, so a wrapped cause
/// (such as the inner `ssz::DecodeError` behind a decode failure) is not
/// truncated to just the outermost message.
struct DisplayChain<'a>(&'a (dyn std::error::Error + 'static));

impl fmt::Display for DisplayChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut current = self.0.source();
        while let Some(err) = current {
            write!(f, ": {err}")?;
            current = err.source();
        }
        Ok(())
    }
}
