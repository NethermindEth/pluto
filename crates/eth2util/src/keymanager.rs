//! Package keymanager provides ETH2 keymanager API
//! (https://ethereum.github.io/keymanager-APIs/) functionalities.

use crate::keystore::Keystore;
use url::Url;

/// Errors that can occur when using the keymanager client.
#[derive(Debug, thiserror::Error)]
pub enum KeymanagerError {
    /// Keystores and passwords have mismatching lengths.
    #[error(
        "lengths of keystores and passwords don't match: keystores={keystores}, passwords={passwords}"
    )]
    LengthMismatch {
        /// Number of keystores provided.
        keystores: usize,
        /// Number of passwords provided.
        passwords: usize,
    },

    /// Connection attempt timed out.
    #[error("connection timed out: {addr}")]
    ConnectionTimedOut {
        /// The keymanager address that timed out.
        addr: String,
    },

    /// Failed to ping keymanager address via TCP.
    #[error("cannot ping address: {addr}: {kind:?}")]
    PingFailed {
        /// The keymanager address that could not be pinged.
        addr: String,
        /// The underlying error kind.
        kind: std::io::ErrorKind,
    },

    /// JSON (de)serialization failure.
    #[error("{0}")]
    SerdeJson(#[from] serde_json::Error),

    /// Failed to parse the keymanager base URL.
    #[error("parse address: {0}")]
    ParseUrl(#[from] url::ParseError),

    /// HTTP client error (request build/send/read).
    #[error("{0}")]
    Http(#[from] reqwest::Error),

    /// Keymanager returned a non-2xx status code.
    #[error("failed posting keys: status={status}, body={body}")]
    PostFailed {
        /// HTTP status code returned.
        status: reqwest::StatusCode,
        /// Response body.
        body: String,
    },
}

/// Result type for keymanager operations.
pub type Result<T> = std::result::Result<T, KeymanagerError>;

/// REST client for ETH2 Keymanager API requests.
#[derive(Debug, Clone)]
pub struct Client {
    base_url: Url,
    auth_token: String,
    http_client: reqwest::Client,
}

impl Client {
    /// Creates a new keymanager API client.
    pub fn new(base_url: impl AsRef<str>, auth_token: impl AsRef<str>) -> Result<Self> {
        // Normalizes `base_url` to always have a trailing slash so that
        // [`Url::join`] appends paths correctly.
        let base_url = base_url.as_ref();
        let normalized = if base_url.ends_with('/') {
            base_url.to_owned()
        } else {
            format!("{base_url}/")
        };
        Ok(Self {
            base_url: Url::parse(&normalized)?,
            auth_token: auth_token.as_ref().to_owned(),
            http_client: reqwest::Client::new(),
        })
    }

    /// Pushes the keystores and passwords to the keymanager.
    ///
    /// See <https://ethereum.github.io/keymanager-APIs/#/Local%20Key%20Manager/importKeystores>.
    pub async fn import_keystores(
        &self,
        keystores: &[Keystore],
        passwords: &[String],
    ) -> Result<()> {
        if keystores.len() != passwords.len() {
            return Err(KeymanagerError::LengthMismatch {
                keystores: keystores.len(),
                passwords: passwords.len(),
            });
        }

        let keystores_url = self.base_url.join("eth/v1/keystores")?;

        let req = new_req(keystores, passwords)?;

        self.post_keys(keystores_url, req).await
    }

    /// Returns an error if the provided keymanager address is not reachable via
    /// TCP.
    pub async fn verify_connection(&self) -> Result<()> {
        // Need to dial to host:port for the connection check
        let host = self.base_url.host_str().unwrap_or_default();
        let connect_addr = self
            .base_url
            .port()
            .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"));
        let addr = self.base_url.to_string();
        let addr_for_timeout = addr.clone();
        let timeout = std::time::Duration::from_secs(2);
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&connect_addr))
            .await
            .map_err(|_| KeymanagerError::ConnectionTimedOut {
                addr: addr_for_timeout,
            })?
            .map_err(|e| KeymanagerError::PingFailed {
                addr,
                kind: e.kind(),
            })?;

        Ok(())
    }

    /// Pushes secrets to the provided keymanager address.
    ///
    /// HTTP request timeout = 2s × number of keystores.
    async fn post_keys(&self, addr: Url, req_body: KeymanagerReq) -> Result<()> {
        // Timeout: 2s per keystore
        let secs = 2u64.saturating_mul(req_body.keystores.len() as u64);
        let timeout = std::time::Duration::from_secs(secs);

        let req_bytes = serde_json::to_vec(&req_body)?;

        let resp = self
            .http_client
            .post(addr)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .body(req_bytes)
            .timeout(timeout)
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            return Err(KeymanagerError::PostFailed { status, body });
        }

        Ok(())
    }
}

/// Keymanager API request body for POST `/eth/v1/keystores`.
///
/// Refer: <https://ethereum.github.io/keymanager-APIs/#/Local%20Key%20Manager/importKeystores>
#[derive(serde::Serialize)]
struct KeymanagerReq {
    keystores: Vec<String>,
    passwords: Vec<String>,
}

/// Builds the keymanager request body by serializing each keystore to a JSON
/// string.
fn new_req(keystores: &[Keystore], passwords: &[String]) -> Result<KeymanagerReq> {
    let keystores = keystores
        .iter()
        .map(serde_json::to_string)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(KeymanagerReq {
        passwords: passwords.to_vec(),
        keystores,
    })
}

#[cfg(test)]
mod tests {
    use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls};
    use test_case::test_case;

    use super::Client;
    use crate::keystore::{self, Keystore};

    const AUTH_TOKEN: &str = "api-token-test";

    #[derive(serde::Deserialize)]
    struct MockKeymanagerReq {
        keystores: Vec<String>,
        passwords: Vec<String>,
    }

    fn assert_err_contains(err: impl std::fmt::Display, expected: &str) {
        let actual = err.to_string();
        assert!(
            actual.contains(expected),
            "expected error containing '{expected}', got: {actual}"
        );
    }

    fn random_password() -> String {
        hex::encode(rand::random::<[u8; 16]>())
    }

    fn make_test_data(num_secrets: usize) -> (Vec<Keystore>, Vec<String>, Vec<String>) {
        let tbls = BlstImpl;
        let mut keystores = Vec::with_capacity(num_secrets);
        let mut passwords = Vec::with_capacity(num_secrets);
        let mut secret_hexes = Vec::with_capacity(num_secrets);

        for _ in 0..num_secrets {
            let secret = tbls.generate_secret_key(rand::thread_rng()).unwrap();
            let password = random_password();
            let mut rng = rand::thread_rng();
            let store = keystore::encrypt(&secret, &password, Some(16), &mut rng).unwrap();

            secret_hexes.push(hex::encode(secret.as_slice()));
            keystores.push(store);
            passwords.push(password);
        }

        (keystores, passwords, secret_hexes)
    }

    #[tokio::test]
    async fn import_keystores_2xx_response() {
        let (keystores, passwords, expected_secret_hexes) = make_test_data(4);

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/eth/v1/keystores"))
            .and(wiremock::matchers::header(
                "Authorization",
                &format!("Bearer {AUTH_TOKEN}"),
            ))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(server.uri(), AUTH_TOKEN).unwrap();
        client
            .import_keystores(&keystores, &passwords)
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);

        let req: MockKeymanagerReq = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(req.keystores.len(), req.passwords.len());
        assert_eq!(req.keystores.len(), 4);

        let mut received_secret_hexes = Vec::with_capacity(req.keystores.len());
        for (keystore_json, password) in req.keystores.iter().zip(req.passwords.iter()) {
            let keystore: Keystore = serde_json::from_str(keystore_json).unwrap();
            let decrypted = keystore::decrypt(&keystore, password).unwrap();
            received_secret_hexes.push(hex::encode(decrypted.as_slice()));
        }

        assert_eq!(expected_secret_hexes, received_secret_hexes);
    }

    #[tokio::test]
    async fn import_keystores_4xx_response() {
        let (keystores, passwords, _) = make_test_data(1);

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/eth/v1/keystores"))
            .respond_with(wiremock::ResponseTemplate::new(403).set_body_string("Forbidden"))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(server.uri(), AUTH_TOKEN).unwrap();
        let err = client
            .import_keystores(&keystores, &passwords)
            .await
            .unwrap_err();
        assert_err_contains(err, "failed posting keys");
    }

    #[tokio::test]
    async fn import_keystores_mismatching_lengths() {
        let (keystores, _, _) = make_test_data(4);

        let client = Client::new("http://localhost:9999", AUTH_TOKEN).unwrap();
        let err = client.import_keystores(&keystores, &[]).await.unwrap_err();
        assert_err_contains(err, "lengths of keystores and passwords don't match");
    }

    #[tokio::test]
    async fn import_keystores_with_path_prefix() {
        let (keystores, passwords, _) = make_test_data(1);

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/v1/eth/v1/keystores"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(format!("{}/api/v1", server.uri()), AUTH_TOKEN).unwrap();
        client
            .import_keystores(&keystores, &passwords)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn verify_connection_successful_ping() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let client = Client::new(format!("http://127.0.0.1:{port}"), AUTH_TOKEN).unwrap();
        client.verify_connection().await.unwrap();
    }

    #[tokio::test]
    async fn verify_connection_cannot_ping_address() {
        let client = Client::new("http://192.0.2.1:6553", AUTH_TOKEN).unwrap();
        let err = client.verify_connection().await.unwrap_err();
        // This address should not be reachable; often it times out.
        assert_err_contains(err, "connection timed out");
    }

    #[test_case("https://1.1.1.1:-1234", "invalid port number"; "malformed keymanager base URL")]
    #[test_case("1.1.0:34", "relative URL without a base"; "invalid address")]
    fn parse_url_failures(input: &str, expected: &str) {
        let err = Client::new(input, AUTH_TOKEN).unwrap_err();
        assert_err_contains(err, expected);
    }
}
