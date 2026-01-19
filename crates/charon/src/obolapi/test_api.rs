//! Test-related API methods.
//!
//! This module provides methods for posting test results to the Obol API.

use crate::obolapi::{client::Client, error::Result};

/// URL path for posting test results.
const POST_TEST_PATH: &str = "/test";

impl Client {
    /// Posts test results to the Obol API.
    pub async fn post_test_result(&self, json_test_result: Vec<u8>) -> Result<()> {
        let url = self.build_url(POST_TEST_PATH);

        self.http_post(url, json_test_result, None).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obolapi::ClientOptions;

    #[test]
    fn test_build_post_test_url_root_base() {
        let client = Client::new("https://api.obol.tech", ClientOptions::default()).unwrap();
        let url = client.build_url(POST_TEST_PATH);
        assert_eq!(url.as_str(), "https://api.obol.tech/test");
    }

    #[test]
    fn test_build_post_test_url_v1_base() {
        let client = Client::new("https://api.obol.tech/v1", ClientOptions::default()).unwrap();
        let url = client.build_url(POST_TEST_PATH);
        assert_eq!(url.as_str(), "https://api.obol.tech/v1/test");
    }
}
