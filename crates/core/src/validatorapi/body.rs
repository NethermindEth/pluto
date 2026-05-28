//! HTTP request and response body shapes for the validator API.

use serde::Serialize;

/// Wire body for `GET /eth/v1/node/version`.
#[derive(Debug, Clone, Serialize)]
pub struct NodeVersionResponse {
    /// Version payload.
    pub data: NodeVersionData,
}

/// `data` field of [`NodeVersionResponse`].
#[derive(Debug, Clone, Serialize)]
pub struct NodeVersionData {
    /// Node version string.
    pub version: String,
}
