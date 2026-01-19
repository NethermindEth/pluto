//! HTTP client for the Obol API.
//!
//! This module provides the main `Client` struct for interacting with the Obol
//! API and helper functions for making HTTP requests.

use std::time::Duration;

use charon_cluster::lock::Lock;
use reqwest::StatusCode;
use url::Url;

use crate::obolapi::error::{Error, Result};

/// Default HTTP request timeout if not specified.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Launchpad URL path format string for a given cluster lock hash.
const LAUNCHPAD_RETURN_PATH_FMT: &str = "/lock/0x{}/launchpad";

/// REST client for Obol API requests.
#[derive(Debug, Clone)]
pub struct Client {
    /// Base Obol API URL.
    base_url: String,

    /// HTTP request timeout.
    _req_timeout: Duration,

    /// Reqwest HTTP client.
    http_client: reqwest::Client,
}

/// Options for configuring the Obol API client.
#[derive(Debug, Default, Clone)]
pub struct ClientOptions {
    /// HTTP request timeout (defaults to 10 seconds).
    pub timeout: Option<Duration>,
}

impl ClientOptions {
    /// Creates new default client options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the HTTP request timeout for all Client calls.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl Client {
    /// Creates a new Obol API client.
    pub fn new(url_str: &str, options: ClientOptions) -> Result<Self> {
        Url::parse(url_str)?;

        let req_timeout = options.timeout.unwrap_or(DEFAULT_TIMEOUT);

        let http_client = reqwest::Client::builder()
            .timeout(req_timeout)
            .build()
            .map_err(Error::Reqwest)?;

        Ok(Self {
            base_url: url_str.to_string(),
            _req_timeout: req_timeout,
            http_client,
        })
    }

    /// Returns the base URL from the baseURL stored in client.
    pub(crate) fn url(&self) -> Url {
        Url::parse(&self.base_url).expect("parse Obol API URL, this should never happen")
    }

    /// Returns the Launchpad cluster dashboard page for a
    /// given lock, on the given Obol API client.
    pub fn launchpad_url_for_lock(&self, lock: &Lock) -> String {
        let url = self.build_url(&launchpad_url_path(lock));
        url.to_string()
    }

    /// Returns a reference to the HTTP client for making requests.
    pub(crate) fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    /// Builds a URL by safely appending a path to the base URL.
    pub(crate) fn build_url(&self, path: &str) -> Url {
        let mut base = self.url();
        let current = base.path().trim_end_matches('/');
        let new_path = path.trim_start_matches('/');

        if current.is_empty() {
            base.set_path(&format!("/{}", new_path));
        } else {
            base.set_path(&format!("{}/{}", current, new_path));
        }

        base
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
            let body_text = response
                .text()
                .await
                .unwrap_or_else(|_| String::from("failed to read body"));

            return Err(Error::HttpError {
                method: "POST".to_string(),
                status: status.as_u16(),
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

            let body_text = response
                .text()
                .await
                .unwrap_or_else(|_| String::from("failed to read body"));

            return Err(Error::HttpError {
                method: "GET".to_string(),
                status: status.as_u16(),
                body: body_text,
            });
        }

        let body_bytes = response.bytes().await?.to_vec();
        Ok(body_bytes)
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
                method: "DELETE".to_string(),
                status: status.as_u16(),
                body: String::new(),
            });
        }

        Ok(())
    }
}

fn launchpad_url_path(lock: &Lock) -> String {
    let hash_hex = hex::encode(&lock.lock_hash).to_uppercase();
    LAUNCHPAD_RETURN_PATH_FMT.replace("{}", &hash_hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use charon_cluster::definition::Definition;

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
    fn test_new_client_valid_url() {
        let client = Client::new("https://api.obol.tech", ClientOptions::default());
        assert!(client.is_ok());
    }

    #[test]
    fn test_new_client_invalid_url() {
        let client = Client::new("not-a-url", ClientOptions::default());
        assert!(client.is_err());
    }

    #[test]
    fn test_launchpad_url_path() {
        let lock = test_lock_with_hash(vec![0x12, 0x34, 0xab, 0xcd]);
        let path = launchpad_url_path(&lock);
        assert_eq!(path, "/lock/0x1234ABCD/launchpad");
    }

    #[test]
    fn test_launchpad_url_for_lock() {
        let client = Client::new("https://api.obol.tech", ClientOptions::default()).unwrap();
        let lock = test_lock_with_hash(vec![0x12, 0x34, 0xab, 0xcd]);
        let url = client.launchpad_url_for_lock(&lock);
        assert_eq!(url, "https://api.obol.tech/lock/0x1234ABCD/launchpad");
    }

    #[test]
    fn test_build_url_with_root_base() {
        // Base path is "/" (root)
        let client = Client::new("https://api.obol.tech/", ClientOptions::default()).unwrap();

        let url = client.build_url("/definition");
        assert_eq!(url.path(), "/definition");

        let url = client.build_url("definition");
        assert_eq!(url.path(), "/definition");
    }

    #[test]
    fn test_build_url_with_non_root_base() {
        // Base path is "/v1"
        let client = Client::new("https://api.obol.tech/v1", ClientOptions::default()).unwrap();

        let url = client.build_url("/definition");
        assert_eq!(url.path(), "/v1/definition");

        let url = client.build_url("definition");
        assert_eq!(url.path(), "/v1/definition");
    }

    #[test]
    fn test_build_url_with_trailing_slash() {
        // Base path has trailing slash
        let client = Client::new("https://api.obol.tech/api/", ClientOptions::default()).unwrap();

        let url = client.build_url("/definition");
        assert_eq!(url.path(), "/api/definition");

        let url = client.build_url("definition");
        assert_eq!(url.path(), "/api/definition");
    }

    #[test]
    fn test_build_url_empty_base() {
        // Edge case: empty path (should be treated as root)
        let client = Client::new("https://api.obol.tech", ClientOptions::default()).unwrap();

        let url = client.build_url("/definition");
        assert_eq!(url.path(), "/definition");
    }
}
