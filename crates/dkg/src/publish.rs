use std::time::Duration;

use pluto_app::obolapi;
use pluto_cluster::lock::Lock;
use tracing::debug;

/// Result type for DKG publish helpers.
pub type Result<T> = std::result::Result<T, PublishError>;

/// Error type for DKG publish helpers.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// Failed to create or use the Obol API client.
    #[error(transparent)]
    ObolApi(#[from] obolapi::ObolApiError),
}

/// Publishes the lock file and returns the launchpad dashboard URL.
pub async fn write_lock_to_api(
    publish_addr: &str,
    lock: &Lock,
    timeout: Duration,
) -> Result<String> {
    let client = obolapi::Client::new(
        publish_addr,
        obolapi::ClientOptions::builder().timeout(timeout).build(),
    )?;

    client.publish_lock(lock.clone()).await?;
    debug!(addr = publish_addr, "Published lock file");

    Ok(client.launchpad_url_for_lock(lock)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_lock_to_api_publishes_and_returns_launchpad_url() {
        let server = wiremock::MockServer::start().await;
        let (lock, ..) = pluto_cluster::test_cluster::new_for_test(1, 3, 4, 0);

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/lock"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let url = write_lock_to_api(&server.uri(), &lock, Duration::from_secs(3))
            .await
            .expect("publish should succeed");
        let client = obolapi::Client::new(&server.uri(), obolapi::ClientOptions::default())
            .expect("client should build");

        assert_eq!(url, client.launchpad_url_for_lock(&lock).unwrap());
    }
}
