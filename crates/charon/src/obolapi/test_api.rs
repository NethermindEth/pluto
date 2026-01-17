//! Test-related API methods.
//!
//! This module provides methods for posting test results to the Obol API.

use crate::obolapi::{
    client::{Client, http_post},
    error::Result,
};

/// URL path for posting test results.
const POST_TEST_PATH: &str = "/test";

impl Client {
    /// Posts test results to the Obol API.
    pub async fn post_test_result(&self, json_test_result: Vec<u8>) -> Result<()> {
        let url = self.build_url(POST_TEST_PATH);

        http_post(self, url, json_test_result, None).await?;

        Ok(())
    }
}
