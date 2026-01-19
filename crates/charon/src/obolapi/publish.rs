//! Publish-related API methods and data models.
//!
//! This module provides methods for publishing cluster locks and definitions
//! to the Obol API, along with the associated data structures.

use charon_cluster::lock::Lock;
use serde::{Deserialize, Serialize};

use crate::obolapi::{
    client::Client,
    error::Result,
    helper::{bearer_string, to_0x},
};

/// Request to sign Obol's Terms and Conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSignTermsAndConditions {
    /// Ethereum address of the user.
    pub address: String,

    /// Version of the terms and conditions.
    pub version: u32,

    /// Hash of the terms and conditions document.
    pub terms_and_conditions_hash: String,

    /// Fork version (hex-encoded with 0x prefix).
    pub fork_version: String,
}

/// URL path for publishing a cluster lock.
const PUBLISH_LOCK_PATH: &str = "lock";

/// URL path for publishing a cluster definition.
const PUBLISH_DEFINITION_PATH: &str = "/definition";

/// URL path for signing Terms and Conditions.
const TERMS_AND_CONDITIONS_PATH: &str = "/termsAndConditions";

/// Hash of the terms and conditions that the user must sign.
const TERMS_AND_CONDITIONS_HASH: &str =
    "0xd33721644e8f3afab1495a74abe3523cec12d48b8da6cb760972492ca3f1a273";

impl Client {
    /// Publishes the lockfile to obol-api.
    /// It respects the timeout specified in the Client instance.
    pub async fn publish_lock(&self, lock: Lock) -> Result<()> {
        let url = self.build_url(PUBLISH_LOCK_PATH);

        let body = serde_json::to_vec(&lock)?;

        self.http_post(url, body, None).await?;

        Ok(())
    }

    /// Publishes the cluster definition to obol-api.
    /// It requires the cluster creator to previously sign Obol's Terms and
    /// Conditions.
    pub async fn publish_definition(
        &self,
        definition: charon_cluster::definition::Definition,
        signature: &[u8],
    ) -> Result<()> {
        let url = self.build_url(PUBLISH_DEFINITION_PATH);

        let body = serde_json::to_vec(&definition)?;

        let headers = vec![("Authorization".to_string(), bearer_string(signature))];

        self.http_post(url, body, Some(&headers)).await?;

        Ok(())
    }

    /// Signs and submits Obol's Terms and Conditions.
    ///
    /// This must be done by the cluster creator before publishing a definition.
    pub async fn sign_terms_and_conditions(
        &self,
        user_addr: &str,
        fork_version: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let url = self.build_url(TERMS_AND_CONDITIONS_PATH);

        let request = RequestSignTermsAndConditions {
            address: user_addr.to_string(),
            version: 1,
            terms_and_conditions_hash: TERMS_AND_CONDITIONS_HASH.to_string(),
            fork_version: to_0x(fork_version),
        };

        let body = serde_json::to_vec(&request)?;

        // Add authorization header with bearer token
        let headers = vec![("Authorization".to_string(), bearer_string(signature))];

        self.http_post(url, body, Some(&headers)).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obolapi::ClientOptions;

    #[test]
    fn test_build_publish_lock_url_root_base() {
        let client = Client::new("https://api.obol.tech", ClientOptions::default()).unwrap();
        let url = client.build_url(PUBLISH_LOCK_PATH);
        assert_eq!(url.as_str(), "https://api.obol.tech/lock");
    }

    #[test]
    fn test_build_publish_lock_url_v1_base() {
        let client = Client::new("https://api.obol.tech/v1", ClientOptions::default()).unwrap();
        let url = client.build_url(PUBLISH_LOCK_PATH);
        assert_eq!(url.as_str(), "https://api.obol.tech/v1/lock");
    }

    #[test]
    fn test_build_publish_definition_url_root_base() {
        let client = Client::new("https://api.obol.tech", ClientOptions::default()).unwrap();
        let url = client.build_url(PUBLISH_DEFINITION_PATH);
        assert_eq!(url.as_str(), "https://api.obol.tech/definition");
    }

    #[test]
    fn test_build_publish_definition_url_v1_base() {
        let client = Client::new("https://api.obol.tech/v1", ClientOptions::default()).unwrap();
        let url = client.build_url(PUBLISH_DEFINITION_PATH);
        assert_eq!(url.as_str(), "https://api.obol.tech/v1/definition");
    }

    #[test]
    fn test_build_terms_and_conditions_url_root_base() {
        let client = Client::new("https://api.obol.tech", ClientOptions::default()).unwrap();
        let url = client.build_url(TERMS_AND_CONDITIONS_PATH);
        assert_eq!(url.as_str(), "https://api.obol.tech/termsAndConditions");
    }

    #[test]
    fn test_build_terms_and_conditions_url_v1_base() {
        let client = Client::new("https://api.obol.tech/v1", ClientOptions::default()).unwrap();
        let url = client.build_url(TERMS_AND_CONDITIONS_PATH);
        assert_eq!(url.as_str(), "https://api.obol.tech/v1/termsAndConditions");
    }
}
