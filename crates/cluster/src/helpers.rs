use chrono::{DateTime, Utc};
use pluto_crypto::tbls;
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

/// Maximum cluster-definition response body read from a remote URI (16 MB). A
/// definition with the SSZ-max 65536 validators is well under this, so the cap
/// never rejects a legitimate definition while bounding memory against a
/// hostile upstream.
const DEFINITION_MAX_BODY: usize = 16 * 1024 * 1024;

/// Error type returned by `fetch_definition`.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// Timeout while fetching the definition.
    #[error("timeout {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    /// HTTP error while fetching the definition.
    #[error("HTTP error {0}")]
    Http(#[from] reqwest::Error),

    /// Response body exceeded the allowed size.
    #[error("definition body exceeds {0} bytes")]
    BodyTooLarge(usize),

    /// JSON decode error after the capped read.
    #[error("decode definition: {0}")]
    Decode(#[from] serde_json::Error),
}

/// Fetch cluster definition file from a remote URI.
pub async fn fetch_definition(
    url: impl reqwest::IntoUrl,
) -> std::result::Result<Definition, FetchError> {
    let definition = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let response = reqwest::get(url).await?.error_for_status()?;
        let buf = read_body_capped(response, DEFINITION_MAX_BODY).await?;
        Ok::<Definition, FetchError>(serde_json::from_slice::<Definition>(&buf)?)
    })
    .await??;

    Ok(definition)
}

/// Reads a response body, failing with [`FetchError::BodyTooLarge`] if it would
/// exceed `max` bytes. Streams so the cap bounds memory even without a
/// trustworthy `Content-Length` header.
async fn read_body_capped(
    response: reqwest::Response,
    max: usize,
) -> std::result::Result<Vec<u8>, FetchError> {
    use tokio_stream::StreamExt;

    // Reject early if the server advertised an oversized body.
    if let Some(len) = response.content_length()
        && len > max as u64
    {
        return Err(FetchError::BodyTooLarge(max));
    }

    let mut buf = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if buf.len().saturating_add(chunk.len()) > max {
            return Err(FetchError::BodyTooLarge(max));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
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
        &crate::eip712sigs::get_operator_eip712_type(&definition.version)?,
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
    let sigs = secrets
        .iter()
        .flat_map(|shares| shares.iter())
        .map(|share| tbls::sign(share, message))
        .collect::<Result<Vec<_>, _>>()?;

    tbls::aggregate(&sigs)
}

#[cfg(test)]
mod tests {
    use crate::test_cluster;
    use pluto_crypto::tbls;
    use pluto_eth2util::helpers::public_key_to_address;
    use pluto_ssz::serde_utils::HexBytes;
    use rand::SeedableRng;
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use test_case::test_case;

    #[serde_as]
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestStruct {
        #[serde_as(as = "HexBytes")]
        data: Vec<u8>,

        #[serde_as(as = "HexBytes")]
        hash: [u8; 32],

        #[serde_as(as = "Option<HexBytes>")]
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

        assert!(matches!(response, Err(super::FetchError::Decode(_))));
    }

    #[tokio::test]
    async fn read_body_capped_rejects_oversized() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/big"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_raw(vec![b'x'; 100], "application/json"),
            )
            .mount(&server)
            .await;

        let response = reqwest::get(format!("{}/big", &server.uri()))
            .await
            .unwrap();
        let result = super::read_body_capped(response, 10).await;
        assert!(matches!(result, Err(super::FetchError::BodyTooLarge(10))));
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

    /// Pinned oracle table for `ceil(2n/3)`: the expected values are written
    /// out rather than recomputed from the implementation under test.
    #[test_case(1, 1)]
    #[test_case(2, 2)]
    #[test_case(3, 2)]
    #[test_case(4, 3)]
    #[test_case(5, 4)]
    #[test_case(6, 4)]
    #[test_case(7, 5)]
    #[test_case(8, 6)]
    #[test_case(9, 6)]
    #[test_case(10, 7)]
    #[test_case(11, 8)]
    #[test_case(12, 8)]
    #[test_case(13, 9)]
    #[test_case(14, 10)]
    #[test_case(15, 10)]
    #[test_case(16, 11)]
    #[test_case(17, 12)]
    #[test_case(18, 12)]
    #[test_case(19, 13)]
    #[test_case(20, 14)]
    #[test_case(21, 14)]
    #[test_case(22, 15)]
    fn threshold_matches_oracle_table(nodes: u64, expected: u64) {
        assert_eq!(super::threshold(nodes), expected, "nodes = {nodes}");
    }

    /// `ceil(0/3)` is 0, not 1.
    #[test]
    fn threshold_zero_nodes() {
        assert_eq!(super::threshold(0), 0);
    }

    /// Exact `ceil(2n/3)` well past the table: the smallest `t` with `3t >=
    /// 2n`.
    #[test]
    fn threshold_is_exact_ceil_of_two_thirds() {
        for nodes in 0..=4096u64 {
            let t = super::threshold(nodes);
            assert!(3 * t >= 2 * nodes, "threshold({nodes}) = {t} is below 2n/3");
            assert!(
                3 * t < 2 * nodes + 3,
                "threshold({nodes}) = {t} overshoots ceil(2n/3)"
            );
        }
    }

    /// A fixed scalar, so the recovered address is stable across runs.
    fn k1_secret(byte: u8) -> k256::SecretKey {
        k256::SecretKey::from_slice(&[byte; 32]).expect("valid secp256k1 scalar")
    }

    #[test]
    fn verify_sig_accepts_the_signing_address() {
        let secret = k1_secret(1);
        let digest = [7u8; 32];
        let sig = pluto_k1util::sign(&secret, &digest).unwrap();
        let addr = public_key_to_address(&secret.public_key());

        assert!(super::verify_sig(&addr, &digest, &sig).unwrap());
    }

    /// The wrong signer is `Ok(false)`, not an error: recovery still succeeds.
    #[test]
    fn verify_sig_rejects_another_signers_address() {
        let signer = k1_secret(1);
        let other = k1_secret(2);
        let digest = [7u8; 32];
        let sig = pluto_k1util::sign(&signer, &digest).unwrap();
        let other_addr = public_key_to_address(&other.public_key());

        assert!(!super::verify_sig(&other_addr, &digest, &sig).unwrap());
    }

    /// A different digest recovers some other public key.
    #[test]
    fn verify_sig_rejects_a_different_digest() {
        let secret = k1_secret(1);
        let sig = pluto_k1util::sign(&secret, &[7u8; 32]).unwrap();
        let addr = public_key_to_address(&secret.public_key());

        assert!(!super::verify_sig(&addr, &[8u8; 32], &sig).unwrap());
    }

    #[test]
    fn verify_sig_rejects_a_malformed_expected_address() {
        let secret = k1_secret(1);
        let digest = [7u8; 32];
        let sig = pluto_k1util::sign(&secret, &digest).unwrap();

        assert!(matches!(
            super::verify_sig("not-an-address", &digest, &sig),
            Err(super::VerifySigError::InvalidExpectedAddress(_))
        ));
    }

    #[test]
    fn verify_sig_surfaces_recovery_failure() {
        let addr = public_key_to_address(&k1_secret(1).public_key());

        // Too short to be a 65-byte recoverable signature.
        assert!(matches!(
            super::verify_sig(&addr, &[7u8; 32], &[0u8; 10]),
            Err(super::VerifySigError::FailedToRecoverPubKey(_))
        ));

        // Right length, but an all-zero signature recovers no public key.
        assert!(matches!(
            super::verify_sig(&addr, &[7u8; 32], &[0u8; 65]),
            Err(super::VerifySigError::FailedToRecoverPubKey(_))
        ));
    }

    /// One signature per share, so the aggregate must verify against the
    /// flattened list of share public keys.
    #[test]
    fn agg_sign_round_trips() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(603);
        let secrets: Vec<Vec<pluto_crypto::types::PrivateKey>> = (0..3)
            .map(|_| {
                (0..2)
                    .map(|_| tbls::generate_insecure_secret(&mut rng).unwrap())
                    .collect()
            })
            .collect();
        let public_keys = secrets
            .iter()
            .flatten()
            .map(|s| tbls::secret_to_public_key(s).unwrap())
            .collect::<Vec<_>>();
        let message = b"cluster lock hash";

        let aggregate = super::agg_sign(&secrets, message).unwrap();

        tbls::verify_aggregate(&public_keys, aggregate, message)
            .expect("aggregate must verify against every signing share");

        assert!(tbls::verify_aggregate(&public_keys, aggregate, b"other message").is_err());

        assert!(tbls::verify_aggregate(&public_keys[1..], aggregate, message).is_err());
    }

    /// Not an error: aggregating nothing yields the G2 compressed point at
    /// infinity.
    #[test]
    fn agg_sign_of_no_shares_is_the_identity_signature() {
        let mut identity = [0u8; 96];
        identity[0] = 0xc0;

        assert_eq!(
            super::agg_sign(&[], b"cluster lock hash").unwrap(),
            identity
        );
        assert_eq!(
            super::agg_sign(&[vec![]], b"cluster lock hash").unwrap(),
            identity
        );
    }
}
