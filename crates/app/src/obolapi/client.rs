//! HTTP client for the Obol API.
//!
//! This module provides the main `Client` struct for interacting with the Obol
//! API and helper functions for making HTTP requests.

use std::time::Duration;

use bon::Builder;
use futures::StreamExt;
use pluto_cluster::lock::Lock;
use reqwest::{Method, StatusCode};
use url::Url;

use crate::obolapi::error::{Error, Result};

/// Default HTTP request timeout if not specified.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum body size read from a successful Obol API response (16 MB). A
/// full-exit response holds up to `share_count` hex BLS signatures; 16 MB is
/// orders of magnitude above any real cluster, so this never rejects a
/// legitimate response while bounding memory against a hostile upstream.
const OBOLAPI_MAX_BODY: usize = 16 * 1024 * 1024;

/// Maximum body size read from an HTTP error response (diagnostics only).
const OBOLAPI_MAX_ERROR_BODY: usize = 64 * 1024;

/// Reads a response body, failing with [`Error::BodyTooLarge`] if it would
/// exceed `max` bytes. Streams so the cap is enforced before full buffering.
async fn read_body_capped(response: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    // Fast-path reject if the server advertised an oversized length.
    if let Some(len) = response.content_length()
        && len > max as u64
    {
        return Err(Error::BodyTooLarge { limit: max });
    }

    let mut buf = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if buf.len().saturating_add(chunk.len()) > max {
            return Err(Error::BodyTooLarge { limit: max });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Reads an HTTP error body for diagnostics, truncating at `max` bytes so a
/// hostile error response cannot exhaust memory. Never fails (best-effort).
async fn read_error_body(response: reqwest::Response, max: usize) -> String {
    let mut buf = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(Ok(chunk)) = stream.next().await {
        let remaining = max.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
        if buf.len() >= max {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// REST client for Obol API requests.
#[derive(Debug, Clone)]
pub struct Client {
    /// Base Obol API URL.
    base_url: Url,

    /// HTTP request timeout.
    _req_timeout: Duration,

    /// Reqwest HTTP client.
    http_client: reqwest::Client,
}

/// Options for configuring the Obol API client.
#[derive(Debug, Default, Clone, Builder)]
pub struct ClientOptions {
    /// Optional HTTP request timeout override (defaults to 10 seconds).
    pub timeout: Option<Duration>,
}

impl Client {
    /// Creates a new Obol API client.
    pub fn new(url_str: &str, options: ClientOptions) -> Result<Self> {
        let req_timeout = options.timeout.unwrap_or(DEFAULT_TIMEOUT);

        let http_client = reqwest::Client::builder().timeout(req_timeout).build()?;

        // Ensure base_url ends with a trailing slash for proper URL joining
        let normalized_url = if url_str.ends_with('/') {
            url_str.to_string()
        } else {
            format!("{}/", url_str)
        };
        let base_url = Url::parse(&normalized_url)?;

        Ok(Self {
            base_url,
            _req_timeout: req_timeout,
            http_client,
        })
    }

    /// Returns the Launchpad cluster dashboard page for a
    /// given lock, on the given Obol API client.
    pub fn launchpad_url_for_lock(&self, lock: &Lock) -> Result<String> {
        let url = self.build_url(&launchpad_url_path(lock))?;
        Ok(url.to_string())
    }

    /// Returns a reference to the HTTP client for making requests.
    pub(crate) fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    /// Builds a URL by safely appending a path to the base URL.
    /// Strip leading '/' from path for proper URL joining
    pub(crate) fn build_url(&self, path: &str) -> Result<Url> {
        let path = path.trim_start_matches('/');
        Ok(self.base_url.join(path)?)
    }

    /// Makes an HTTP POST request.
    pub(crate) async fn http_post(
        &self,
        url: Url,
        body: Vec<u8>,
        headers: Option<&[(String, String)]>,
    ) -> Result<()> {
        let mut request = self
            .http_client()
            .post(url)
            .header("Content-Type", "application/json");

        if let Some(headers) = headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        let response = request.body(body).send().await?;

        let status = response.status();
        if !status.is_success() {
            let body_text = read_error_body(response, OBOLAPI_MAX_ERROR_BODY).await;

            return Err(Error::HttpError {
                method: Method::POST,
                status,
                body: body_text,
            });
        }

        Ok(())
    }

    /// Makes an HTTP GET request.
    pub(crate) async fn http_get(
        &self,
        url: Url,
        headers: Option<&[(String, String)]>,
    ) -> Result<Vec<u8>> {
        let mut request = self.http_client().get(url);

        if let Some(headers) = headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        let response = request.send().await?;

        let status = response.status();

        if !status.is_success() {
            if status == StatusCode::NOT_FOUND {
                return Err(Error::NoExit);
            }

            let body_text = read_error_body(response, OBOLAPI_MAX_ERROR_BODY).await;

            return Err(Error::HttpError {
                method: Method::GET,
                status,
                body: body_text,
            });
        }

        read_body_capped(response, OBOLAPI_MAX_BODY).await
    }

    /// Makes an HTTP DELETE request.
    pub(crate) async fn http_delete(
        &self,
        url: Url,
        headers: Option<&[(String, String)]>,
    ) -> Result<()> {
        let mut request = self.http_client().delete(url);

        if let Some(headers) = headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        let response = request.send().await?;

        let status = response.status();

        if !status.is_success() {
            if status == StatusCode::NOT_FOUND {
                return Err(Error::NoExit);
            }
            return Err(Error::HttpError {
                method: Method::default(),
                status,
                body: String::new(),
            });
        }

        Ok(())
    }
}

fn launchpad_url_path(lock: &Lock) -> String {
    let hash_hex = hex::encode(&lock.lock_hash).to_uppercase();
    format!("/lock/0x{}/launchpad", &hash_hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_cluster::definition::Definition;

    fn test_lock_with_hash(hash: Vec<u8>) -> Lock {
        Lock {
            definition: Definition {
                uuid: "test-uuid".to_string(),
                name: "test".to_string(),
                version: "v1.0.0".to_string(),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                num_validators: 0,
                threshold: 0,
                dkg_algorithm: "".to_string(),
                fork_version: vec![],
                operators: vec![],
                creator: Default::default(),
                validator_addresses: vec![],
                deposit_amounts: vec![],
                consensus_protocol: "".to_string(),
                target_gas_limit: 0,
                compounding: false,
                config_hash: vec![],
                definition_hash: vec![],
            },
            distributed_validators: vec![],
            lock_hash: hash,
            signature_aggregate: vec![],
            node_signatures: vec![],
        }
    }

    #[test]
    fn new_client_valid_url() {
        assert!(
            Client::new(
                "https://api.obol.tech",
                ClientOptions::builder()
                    .timeout(Duration::from_secs(10))
                    .build()
            )
            .is_ok()
        );
    }

    #[test]
    fn new_client_invalid_url() {
        assert!(Client::new("not-a-url", ClientOptions::default()).is_err());
    }

    #[test]
    fn base_url_normalization() {
        let c1 = Client::new("https://api.obol.tech", ClientOptions::default()).unwrap();
        assert_eq!(c1.base_url.as_str(), "https://api.obol.tech/");

        let c2 = Client::new("https://api.obol.tech/", ClientOptions::default()).unwrap();
        assert_eq!(c2.base_url.as_str(), "https://api.obol.tech/");

        let c3 = Client::new("https://api.obol.tech/v1", ClientOptions::default()).unwrap();
        assert_eq!(c3.base_url.as_str(), "https://api.obol.tech/v1/");

        let c4 = Client::new("https://api.obol.tech/v1/", ClientOptions::default()).unwrap();
        assert_eq!(c4.base_url.as_str(), "https://api.obol.tech/v1/");
    }

    #[test]
    fn build_url_root_base() {
        let client = Client::new("https://api.obol.tech", ClientOptions::default()).unwrap();
        assert_eq!(
            client.build_url("definition").unwrap().as_str(),
            "https://api.obol.tech/definition"
        );
        assert_eq!(
            client.build_url("/definition").unwrap().as_str(),
            "https://api.obol.tech/definition"
        );
        assert_eq!(
            client
                .build_url("exp/partial_exits/0xabc")
                .unwrap()
                .as_str(),
            "https://api.obol.tech/exp/partial_exits/0xabc"
        );
    }

    #[test]
    fn build_url_versioned_base() {
        let client = Client::new("https://api.obol.tech/v1", ClientOptions::default()).unwrap();
        assert_eq!(
            client.build_url("definition").unwrap().as_str(),
            "https://api.obol.tech/v1/definition"
        );
        assert_eq!(
            client.build_url("/lock").unwrap().as_str(),
            "https://api.obol.tech/v1/lock"
        );
        assert_eq!(
            client
                .build_url("exp/exit/0xlock/5/0xkey")
                .unwrap()
                .as_str(),
            "https://api.obol.tech/v1/exp/exit/0xlock/5/0xkey"
        );
    }

    #[test]
    fn launchpad_url_path_works() {
        let lock = test_lock_with_hash(vec![0x12, 0x34, 0xab, 0xcd]);
        assert_eq!(launchpad_url_path(&lock), "/lock/0x1234ABCD/launchpad");
    }

    #[test]
    fn launchpad_url_for_lock() {
        let lock = test_lock_with_hash(vec![0x12, 0x34, 0xab, 0xcd]);

        let c1 = Client::new("https://api.obol.tech", ClientOptions::default()).unwrap();
        assert_eq!(
            c1.launchpad_url_for_lock(&lock).unwrap(),
            "https://api.obol.tech/lock/0x1234ABCD/launchpad"
        );

        let c2 = Client::new("https://api.obol.tech/v1", ClientOptions::default()).unwrap();
        assert_eq!(
            c2.launchpad_url_for_lock(&lock).unwrap(),
            "https://api.obol.tech/v1/lock/0x1234ABCD/launchpad"
        );
    }
}
