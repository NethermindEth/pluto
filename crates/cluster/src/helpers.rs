use chrono::{DateTime, Utc};
use pluto_crypto::tbls::Tbls;
use pluto_eth2util::helpers::{checksum_address, public_key_to_address};
use pluto_k1util::K1UtilError;
use serde::{Deserialize, Deserializer, Serializer};
use serde_with::{DeserializeAs, SerializeAs};
use std::path::PathBuf;

use crate::{
    definition::{self, Definition},
    eip712sigs, operator,
};

pub use pluto_ssz::{from_0x_hex_str, left_pad, to_0x_hex};

/// Error type returned by `verify_sig`.
#[derive(Debug, thiserror::Error)]
pub enum VerifySigError {
    /// Invalid expected Ethereum address.
    #[error("invalid expected Ethereum address: {0}")]
    InvalidExpectedAddress(#[from] pluto_eth2util::helpers::HelperError),

    /// Failed to recover public key from signature and digest.
    #[error("failed to recover public key from signature: {0}")]
    FailedToRecoverPubKey(#[from] K1UtilError),
}

/// Returns true if the signature matches the digest and expected address.
pub fn verify_sig(
    expected_addr: &str,
    digest: &[u8],
    sig: &[u8],
) -> std::result::Result<bool, VerifySigError> {
    let expected_addr = checksum_address(expected_addr)?;
    let recovered = pluto_k1util::recover(digest, sig)?;
    let actual_addr = public_key_to_address(&recovered);
    Ok(expected_addr == actual_addr)
}

/// Error type returned by `fetch_definition`.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// Timeout while fetching the definition.
    #[error("timeout {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    /// HTTP error while fetching the definition.
    #[error("HTTP error {0}")]
    Http(#[from] reqwest::Error),
}

/// Fetch cluster definition file from a remote URI.
pub async fn fetch_definition(
    url: impl reqwest::IntoUrl,
) -> std::result::Result<Definition, FetchError> {
    let definition = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let response = reqwest::get(url).await?.error_for_status()?;
        response.json::<Definition>().await
    })
    .await??;

    Ok(definition)
}

/// Creates a new directory for validator keys.
/// If the directory "validator_keys" exists, it checks if the directory is
/// empty.
pub async fn create_validator_keys_dir(
    parent_dir: impl AsRef<std::path::Path>,
) -> std::io::Result<PathBuf> {
    let vk_dir = parent_dir.as_ref().join("validator_keys");

    if let Err(e) = tokio::fs::create_dir(&vk_dir).await {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(e);
        }

        let mut entries = tokio::fs::read_dir(&vk_dir).await?;
        if entries.next_entry().await?.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "validator_keys directory exists and is not empty",
            ));
        }
    }

    Ok(vk_dir)
}

/// TimestampSeconds represents a timestamp in seconds since the Unix epoch.
pub struct TimestampSeconds;

impl SerializeAs<DateTime<Utc>> for TimestampSeconds {
    fn serialize_as<S>(value: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(value.timestamp())
    }
}

impl<'de> DeserializeAs<'de, DateTime<Utc>> for TimestampSeconds {
    fn deserialize_as<D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let timestamp = i64::deserialize(deserializer)?;
        DateTime::<Utc>::from_timestamp(timestamp, 0)
            .ok_or(serde::de::Error::custom("invalid timestamp"))
    }
}

/// Signs the creator's config hash.
pub fn sign_creator(
    secret: &k256::SecretKey,
    definition: &mut definition::Definition,
) -> Result<(), eip712sigs::EIP712Error> {
    let config_signature = eip712sigs::sign_eip712(
        secret,
        &eip712sigs::eip712_creator_config_hash(),
        definition,
        &operator::Operator::default(),
    )?;

    definition.creator.config_signature = config_signature;

    Ok(())
}

/// Signs the operator's config hash and enr.
pub fn sign_operator(
    secret: &k256::SecretKey,
    definition: &definition::Definition,
    operator: &mut operator::Operator,
) -> Result<(), crate::eip712sigs::EIP712Error> {
    let config_signature = crate::eip712sigs::sign_eip712(
        secret,
        &crate::eip712sigs::get_operator_eip712_type(&definition.version),
        definition,
        operator,
    )?;

    let enr_signature = crate::eip712sigs::sign_eip712(
        secret,
        &crate::eip712sigs::eip712_enr(),
        definition,
        operator,
    )?;

    operator.config_signature = config_signature;
    operator.enr_signature = enr_signature;

    Ok(())
}

/// Returns minimum threshold required for a cluster with given nodes.
/// This formula has been taken from: <https://github.com/ObolNetwork/charon/blob/a8fc3185bdda154412fe034dcd07c95baf5c1aaf/core/qbft/qbft.go#L63>
///
/// Computes ceil(2*nodes / 3) using integer arithmetic to avoid floating point
/// conversions.
pub fn threshold(nodes: u64) -> u64 {
    // Integer ceiling division: ceil(a/b) = (a + b - 1) / b
    // Here we compute: ceil(2*nodes / 3) = (2*nodes + 3 - 1) / 3 = (2*nodes + 2) /
    // 3
    let numerator = nodes.checked_mul(2).expect("threshold: nodes * 2 overflow");
    let adjusted = numerator
        .checked_add(2)
        .expect("threshold: numerator + 2 overflow");
    adjusted / 3
}

/// Returns a BLS aggregate signature of the message signed by all the shares.
pub fn agg_sign(
    secrets: &[Vec<pluto_crypto::types::PrivateKey>],
    message: &[u8],
) -> Result<pluto_crypto::types::Signature, pluto_crypto::types::Error> {
    let blst = pluto_crypto::blst_impl::BlstImpl;

    let sigs = secrets
        .iter()
        .flat_map(|shares| shares.iter())
        .map(|share| blst.sign(share, message))
        .collect::<Result<Vec<_>, _>>()?;

    blst.aggregate(&sigs)
}

#[cfg(test)]
mod tests {
    use crate::test_cluster;
    use pluto_ssz::serde_utils::Hex0x;
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestStruct {
        #[serde_as(as = "Hex0x")]
        data: Vec<u8>,

        #[serde_as(as = "Hex0x")]
        hash: [u8; 32],

        #[serde_as(as = "Option<Hex0x>")]
        optional_data: Option<Vec<u8>>,
    }

    #[test]
    fn with_serde_as() {
        let test = TestStruct {
            data: vec![0xde, 0xad, 0xbe, 0xef],
            hash: [0xaa; 32],
            optional_data: Some(vec![0x12, 0x34]),
        };

        let json = serde_json::to_string(&test).unwrap();
        let expected = r#"{"data":"0xdeadbeef","hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","optional_data":"0x1234"}"#;
        assert_eq!(json, expected);

        let decoded: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, test);
    }

    #[tokio::test]
    async fn fetch_definition_valid() {
        let (lock, ..) = test_cluster::new_for_test(1, 2, 3, 0);
        let expected_definition = lock.definition.clone();

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/validDef"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(lock.definition))
            .mount(&server)
            .await;

        let actual_definition = super::fetch_definition(format!("{}/validDef", &server.uri()))
            .await
            .unwrap();

        assert_eq!(actual_definition, expected_definition);
    }

    #[tokio::test]
    async fn fetch_definition_invalid() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/invalidDef"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_raw("r#{}#", "application/json"),
            )
            .mount(&server)
            .await;

        let response = super::fetch_definition(format!("{}/invalidDef", &server.uri())).await;

        assert!(matches!(response, Err(super::FetchError::Http(e)) if e.is_decode()));
    }

    #[tokio::test]
    async fn fetch_definition_non_200() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/non_ok"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let response = super::fetch_definition(format!("{}/non_ok", &server.uri())).await;

        assert!(matches!(response, Err(super::FetchError::Http(e)) if e.is_status()));
    }

    #[tokio::test]
    async fn create_validator_keys_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let parent_dir = tmp.path();

        // First attempt must succeed.
        let dir = super::create_validator_keys_dir(parent_dir).await.unwrap();
        assert!(dir.starts_with(parent_dir));
        assert!(dir.ends_with("validator_keys"));

        // Second attempt shall succeed as long as the dir is empty.
        let dir2 = super::create_validator_keys_dir(parent_dir).await.unwrap();
        assert_eq!(dir, dir2);

        // Create a file in the directory to make it non-empty.
        tokio::fs::write(dir.join("file"), b"data").await.unwrap();
        let err = super::create_validator_keys_dir(parent_dir)
            .await
            .unwrap_err();
        assert!(matches!(err, e if e.kind() == std::io::ErrorKind::AlreadyExists));

        // Parent directory does not exist
        let err = super::create_validator_keys_dir(&parent_dir.join("nonexistent"))
            .await
            .unwrap_err();
        assert!(matches!(err, e if e.kind() == std::io::ErrorKind::NotFound));
    }
}
