//! Graffiti construction for block proposals.

use std::collections::HashMap;

use pluto_eth2api::{EthBeaconNodeApiClient, GetNodeVersionRequest, GetNodeVersionResponse};

use crate::{
    types::PubKey,
    version::{VERSION, git_commit},
};

/// Obol token appended to graffiti unless client-append is disabled.
const OBOL_TOKEN: &str = "OB";

/// Graffiti is a fixed 32-byte field in the beacon block body.
const GRAFFITI_LEN: usize = 32;

/// Error returned while constructing a [`GraffitiBuilder`].
#[derive(Debug, thiserror::Error)]
pub enum GraffitiError {
    /// More than one graffiti value was provided but the count did not match
    /// the number of validators.
    #[error("graffiti length must match the number of validators or be a single value")]
    LengthMismatch,
}

/// Maps a beacon node product token (the first `/`-separated component of the
/// node version string) to its two-letter graffiti code, returning an empty
/// string for an unrecognized client.
pub fn client_graffiti_token(product_token: &str) -> &'static str {
    match product_token {
        "teku" => "TK",
        "Lighthouse" => "LH",
        "Lodestar" => "LS",
        "Prysm" => "PY",
        "Nimbus" => "NB",
        "Grandine" => "GD",
        _ => "",
    }
}

/// Builds per-validator graffiti used when proposing blocks.
#[derive(Debug, Clone, Default)]
pub struct GraffitiBuilder {
    default_graffiti: [u8; GRAFFITI_LEN],
    graffiti: HashMap<PubKey, [u8; GRAFFITI_LEN]>,
}

impl GraffitiBuilder {
    /// Creates a new graffiti builder.
    ///
    /// `graffiti` may be `None` (every validator gets the default graffiti), a
    /// single value (applied to every validator) or one value per validator.
    pub async fn new(
        pubkeys: &[PubKey],
        graffiti: Option<&[String]>,
        disable_client_append: bool,
        eth2_cl: &EthBeaconNodeApiClient,
    ) -> Result<Self, GraffitiError> {
        let default = default_graffiti();
        let mut builder = Self {
            default_graffiti: default,
            graffiti: HashMap::with_capacity(pubkeys.len()),
        };

        // Handle nil graffiti.
        let Some(graffiti) = graffiti else {
            for pubkey in pubkeys {
                builder.graffiti.insert(*pubkey, default);
            }

            return Ok(builder);
        };

        if graffiti.len() > 1 && graffiti.len() != pubkeys.len() {
            return Err(GraffitiError::LengthMismatch);
        }

        let token = fetch_beacon_node_token(eth2_cl).await;

        // Handle single graffiti case.
        if graffiti.len() == 1 {
            let single_graffiti = &graffiti[0];
            for pubkey in pubkeys {
                builder.graffiti.insert(
                    *pubkey,
                    build_graffiti(single_graffiti, &token, disable_client_append),
                );
            }

            return Ok(builder);
        }

        // Handle multiple graffiti case.
        for (idx, pubkey) in pubkeys.iter().enumerate() {
            builder.graffiti.insert(
                *pubkey,
                build_graffiti(&graffiti[idx], &token, disable_client_append),
            );
        }

        Ok(builder)
    }

    /// Returns the graffiti for a given pubkey, or the default graffiti when
    /// the pubkey is unknown.
    pub fn get_graffiti(&self, pubkey: &PubKey) -> [u8; GRAFFITI_LEN] {
        self.graffiti
            .get(pubkey)
            .copied()
            .unwrap_or(self.default_graffiti)
    }
}

/// Copies `s` into a fixed 32-byte array, truncating or zero-padding to match
/// Go's `copy(graffiti[:], s)` semantics.
fn graffiti_bytes(s: &str) -> [u8; GRAFFITI_LEN] {
    let mut out = [0u8; GRAFFITI_LEN];
    let bytes = s.as_bytes();
    let n = bytes.len().min(GRAFFITI_LEN);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// Builds the graffiti with optional Obol and beacon node token.
fn build_graffiti(graffiti: &str, token: &str, disable_client_append: bool) -> [u8; GRAFFITI_LEN] {
    if disable_client_append {
        graffiti_bytes(graffiti)
    } else {
        graffiti_bytes(&format!("{graffiti}{OBOL_TOKEN}{token}"))
    }
}

/// Returns the default graffiti: `pluto/<version>-<commit>`.
fn default_graffiti() -> [u8; GRAFFITI_LEN] {
    let (commit_sha, _) = git_commit();
    graffiti_bytes(&format!("pluto/{}-{}", *VERSION, commit_sha))
}

/// Queries the beacon node for its product token, returning an empty string on
/// any error or unrecognized client.
async fn fetch_beacon_node_token(eth2_cl: &EthBeaconNodeApiClient) -> String {
    let Some(version) = node_version(eth2_cl).await else {
        return String::new();
    };

    let product_token = version.split('/').next().unwrap_or_default();

    client_graffiti_token(product_token).to_string()
}

/// Fetches the beacon node version string (e.g. `Lighthouse/v0.1.5 (Linux
/// x86_64)`), or `None` on any error.
async fn node_version(eth2_cl: &EthBeaconNodeApiClient) -> Option<String> {
    match eth2_cl.get_node_version(GetNodeVersionRequest {}).await {
        Ok(GetNodeVersionResponse::Ok(resp)) => Some(resp.data.version),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use pluto_testutil::BeaconMock;
    use serde_json::json;

    use super::*;

    /// 48-byte BLS public key length used to build distinct test pubkeys.
    const PK_LEN: usize = 48;

    /// Builds a beacon mock whose `/eth/v1/node/version` endpoint returns
    /// `version`.
    async fn mock_with_version(version: &str) -> BeaconMock {
        BeaconMock::builder()
            .endpoint_overrides(vec![(
                "/eth/v1/node/version".to_string(),
                json!({ "data": { "version": version } }),
            )])
            .build()
            .await
            .expect("build mock")
    }

    #[tokio::test]
    async fn fetch_beacon_node_token() {
        // fetch token error: unreachable beacon node yields an empty token.
        let unreachable =
            EthBeaconNodeApiClient::with_base_url("http://127.0.0.1:1").expect("create client");
        assert_eq!(super::fetch_beacon_node_token(&unreachable).await, "");

        // fetch token unexpected response: no `/`-separated product token.
        let mock = mock_with_version("IncorrectUserAgent").await;
        assert_eq!(super::fetch_beacon_node_token(mock.client()).await, "");

        // fetch token not predicted in map.
        let mock = mock_with_version("Dune/v1.3 (Windows)").await;
        assert_eq!(super::fetch_beacon_node_token(mock.client()).await, "");

        // fetch token: Lighthouse maps to "LH".
        let mock = mock_with_version("Lighthouse/v0.1.5 (Linux x86_64)").await;
        assert_eq!(super::fetch_beacon_node_token(mock.client()).await, "LH");
    }

    #[test]
    fn build_graffiti() {
        let graffiti = "abcdefghij"; // 10 bytes
        let token = "BN";

        // disable client append.
        assert_eq!(
            super::build_graffiti(graffiti, token, true),
            graffiti_bytes(graffiti)
        );

        // enable client append.
        assert_eq!(
            super::build_graffiti(graffiti, token, false),
            graffiti_bytes(&format!("{graffiti}{OBOL_TOKEN}{token}"))
        );
    }

    #[test]
    fn default_graffiti() {
        let (commit_sha, _) = git_commit();
        let expected = graffiti_bytes(&format!("pluto/{}-{}", *VERSION, commit_sha));
        assert_eq!(super::default_graffiti(), expected);
    }

    #[test]
    fn get_graffiti() {
        let pubkeys = [
            PubKey::new([1u8; PK_LEN]),
            PubKey::new([2u8; PK_LEN]),
            PubKey::new([3u8; PK_LEN]),
        ];

        let mut g0 = [0u8; GRAFFITI_LEN];
        g0[0] = 1;
        let mut g1 = [0u8; GRAFFITI_LEN];
        g1[0] = 2;

        let builder = GraffitiBuilder {
            default_graffiti: super::default_graffiti(),
            graffiti: HashMap::from([(pubkeys[0], g0), (pubkeys[1], g1)]),
        };

        assert_eq!(builder.get_graffiti(&pubkeys[0]), g0);
        assert_eq!(builder.get_graffiti(&pubkeys[1]), g1);
        assert_eq!(builder.get_graffiti(&pubkeys[2]), super::default_graffiti());
    }

    /// Three distinct pubkeys used across the `GraffitiBuilder::new` tests.
    fn test_pubkeys() -> [PubKey; 3] {
        [
            PubKey::new([1u8; PK_LEN]),
            PubKey::new([2u8; PK_LEN]),
            PubKey::new([3u8; PK_LEN]),
        ]
    }

    #[tokio::test]
    async fn new_rejects_mismatched_graffiti_length() {
        let pubkeys = test_pubkeys();
        let mock = BeaconMock::builder().build().await.expect("build mock");

        // graffiti length greater than pubkeys.
        let graffiti = vec![
            "a".repeat(10),
            "b".repeat(15),
            "c".repeat(20),
            "d".repeat(25),
        ];
        let result = GraffitiBuilder::new(&pubkeys, Some(&graffiti), false, mock.client()).await;
        assert!(matches!(result, Err(GraffitiError::LengthMismatch)));

        // graffiti length lesser than pubkeys.
        let graffiti = vec!["a".repeat(10), "b".repeat(15)];
        let result = GraffitiBuilder::new(&pubkeys, Some(&graffiti), false, mock.client()).await;
        assert!(matches!(result, Err(GraffitiError::LengthMismatch)));
    }

    #[tokio::test]
    async fn new_with_nil_graffiti_uses_default() {
        let pubkeys = test_pubkeys();
        let mock = BeaconMock::builder().build().await.expect("build mock");

        let builder = GraffitiBuilder::new(&pubkeys, None, false, mock.client())
            .await
            .expect("build builder");
        for pubkey in &pubkeys {
            assert_eq!(builder.get_graffiti(pubkey), super::default_graffiti());
        }
    }

    #[tokio::test]
    async fn new_single_graffiti_with_append() {
        let pubkeys = test_pubkeys();

        // single graffiti with append (Grandine -> GD).
        let mock = mock_with_version("Grandine/v2.1.4 (Linux x86_64)").await;
        let graffiti = "x".repeat(GRAFFITI_LEN - OBOL_TOKEN.len() - 2);
        let builder = GraffitiBuilder::new(
            &pubkeys,
            Some(std::slice::from_ref(&graffiti)),
            false,
            mock.client(),
        )
        .await
        .expect("build builder");
        let expected = graffiti_bytes(&format!("{graffiti}{OBOL_TOKEN}GD"));
        for pubkey in &pubkeys {
            assert_eq!(builder.get_graffiti(pubkey), expected);
        }
    }

    #[tokio::test]
    async fn new_single_graffiti_without_append() {
        let pubkeys = test_pubkeys();

        let mock = mock_with_version("Teku/v4.2.1 (Linux x86_64)").await;
        let graffiti = "y".repeat(GRAFFITI_LEN);
        let builder = GraffitiBuilder::new(
            &pubkeys,
            Some(std::slice::from_ref(&graffiti)),
            true,
            mock.client(),
        )
        .await
        .expect("build builder");
        let expected = graffiti_bytes(&graffiti);
        for pubkey in &pubkeys {
            assert_eq!(builder.get_graffiti(pubkey), expected);
        }
    }

    #[tokio::test]
    async fn new_multiple_graffiti_with_append() {
        let pubkeys = test_pubkeys();

        // multiple graffiti with append (Prysm -> PY).
        let mock = mock_with_version("Prysm/v0.2.7 (Linux x86_64)").await;
        let graffiti = vec![
            "a".repeat(10),
            "b".repeat(GRAFFITI_LEN - OBOL_TOKEN.len() - 3),
            "c".repeat(GRAFFITI_LEN - OBOL_TOKEN.len() - 4),
        ];
        let builder = GraffitiBuilder::new(&pubkeys, Some(&graffiti), false, mock.client())
            .await
            .expect("build builder");
        for (idx, pubkey) in pubkeys.iter().enumerate() {
            let expected = graffiti_bytes(&format!("{}{OBOL_TOKEN}PY", graffiti[idx]));
            assert_eq!(builder.get_graffiti(pubkey), expected);
        }
    }

    #[tokio::test]
    async fn new_multiple_graffiti_without_append() {
        let pubkeys = test_pubkeys();

        // multiple graffiti without append (empty version -> empty token).
        let mock = mock_with_version("").await;
        let graffiti = vec![
            "a".repeat(10),
            "b".repeat(GRAFFITI_LEN - OBOL_TOKEN.len()),
            "c".repeat(GRAFFITI_LEN - OBOL_TOKEN.len() + 1),
        ];
        let builder = GraffitiBuilder::new(&pubkeys, Some(&graffiti), true, mock.client())
            .await
            .expect("build builder");
        for (idx, pubkey) in pubkeys.iter().enumerate() {
            let expected = graffiti_bytes(&graffiti[idx]);
            assert_eq!(builder.get_graffiti(pubkey), expected);
        }
    }
}
