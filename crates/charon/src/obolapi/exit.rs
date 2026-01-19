//! Exit-related API methods and data models.
//!
//! This module provides methods for managing partial and full validator exits
//! through the Obol API, along with the associated data structures.

use std::collections::HashMap;

use charon_crypto::{blst_impl::BlstImpl, tbls::Tbls, types::Signature};
use serde::{Deserialize, Serialize};

use charon_cluster::{
    helpers::left_pad,
    ssz_hasher::{HashWalker, Hasher, HasherError},
};
use eth2api::types::{
    GetPoolVoluntaryExitsResponseResponseDatum, Phase0SignedVoluntaryExitMessage,
};

/// Type alias for signed voluntary exit from eth2api.
pub type SignedVoluntaryExit = GetPoolVoluntaryExitsResponseResponseDatum;

use crate::obolapi::{
    client::Client,
    error::{Error, Result},
    helper::{bearer_string, from_0x, to_0x},
};

/// An exit message alongside its BLS12-381 hex-encoded signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitBlob {
    /// Validator public key (hex-encoded with 0x prefix).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// Signed voluntary exit message.
    pub signed_exit_message: SignedVoluntaryExit,
}

impl ExitBlob {
    /// Computes the SSZ hash tree root of this ExitBlob.
    pub fn hash_tree_root(&self) -> Result<[u8; 32]> {
        hash_exit_blob(self)
    }
}

/// An array of exit messages that have been signed with a partial key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PartialExits(pub Vec<ExitBlob>);

impl PartialExits {
    /// Computes the SSZ hash tree root of the partial exits list.
    pub fn hash_tree_root(&self) -> Result<[u8; 32]> {
        hash_partial_exits(&self.0)
    }
}

impl std::ops::Deref for PartialExits {
    type Target = Vec<ExitBlob>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for PartialExits {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<ExitBlob>> for PartialExits {
    fn from(v: Vec<ExitBlob>) -> Self {
        Self(v)
    }
}

impl From<PartialExits> for Vec<ExitBlob> {
    fn from(p: PartialExits) -> Self {
        p.0
    }
}

/// An unsigned blob of data sent to the Obol API server, which is stored in the
/// backend awaiting aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedPartialExitRequest {
    /// Partial exit messages.
    pub partial_exits: PartialExits,

    /// Share index of this node.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub share_idx: u64,
}

impl UnsignedPartialExitRequest {
    /// Computes the SSZ hash tree root of this UnsignedPartialExitRequest.
    pub fn hash_tree_root(&self) -> Result<[u8; 32]> {
        hash_unsigned_partial_exit_request(self)
    }
}

fn is_zero(val: &u64) -> bool {
    *val == 0
}

/// Signed blob of data sent to the Obol API server for aggregation.
///
/// The signature is an EC signature of the `UnsignedPartialExitRequest`'s
/// hash tree root, signed with the Charon node identity key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "PartialExitRequestDto", into = "PartialExitRequestDto")]
pub struct PartialExitRequest {
    /// Unsigned partial exit request.
    #[serde(flatten)]
    pub unsigned: UnsignedPartialExitRequest,

    /// K1 signature (65 bytes) over the hash tree root of the unsigned request.
    pub signature: Vec<u8>,
}

/// DTO for JSON serialization of PartialExitRequest.
#[derive(Debug, Serialize, Deserialize)]
struct PartialExitRequestDto {
    #[serde(flatten)]
    unsigned: UnsignedPartialExitRequest,
    signature: String,
}

impl TryFrom<PartialExitRequestDto> for PartialExitRequest {
    type Error = Error;

    fn try_from(dto: PartialExitRequestDto) -> Result<Self> {
        let signature = from_0x(&dto.signature, 65)?;

        Ok(Self {
            unsigned: dto.unsigned,
            signature,
        })
    }
}

impl From<PartialExitRequest> for PartialExitRequestDto {
    fn from(req: PartialExitRequest) -> Self {
        Self {
            unsigned: req.unsigned,
            signature: to_0x(&req.signature),
        }
    }
}

/// Response containing all partial signatures for a validator.
///
/// Signatures are ordered by share index and can be aggregated to create
/// a full exit message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullExitResponse {
    /// Epoch when the exit becomes valid.
    pub epoch: String,

    /// Validator index on the beacon chain.
    pub validator_index: u64,

    /// Partial BLS signatures (hex-encoded with 0x prefix), ordered by share
    /// index. Empty strings indicate missing signatures.
    pub signatures: Vec<String>,
}

/// Authentication data required by Obol API to download full exit blobs.
///
/// This blob is signed with the node's identity key to prove authorization.
#[derive(Debug, Clone)]
pub struct FullExitAuthBlob {
    /// Lock hash identifying the cluster.
    pub lock_hash: Vec<u8>,

    /// Validator public key (48 bytes).
    pub validator_pubkey: Vec<u8>,

    /// Share index of this node.
    pub share_index: u64,
}

impl FullExitAuthBlob {
    /// Computes the SSZ hash tree root of this FullExitAuthBlob.
    pub fn hash_tree_root(&self) -> Result<[u8; 32]> {
        hash_full_exit_auth_blob(self)
    }
}
const SSZ_MAX_EXITS: usize = 65536;
const SSZ_LEN_PUB_KEY: usize = 48;
const SSZ_LEN_BLS_SIG: usize = 96;

const LOCK_HASH_PATH: &str = "{lock_hash}";
const VAL_PUBKEY_PATH: &str = "{validator_pubkey}";
const SHARE_INDEX_PATH: &str = "{share_index}";

const SUBMIT_PARTIAL_EXIT_TMPL: &str = "/exp/partial_exits/{lock_hash}";
const DELETE_PARTIAL_EXIT_TMPL: &str =
    "/exp/partial_exits/{lock_hash}/{share_index}/{validator_pubkey}";
const FETCH_FULL_EXIT_TMPL: &str = "/exp/exit/{lock_hash}/{share_index}/{validator_pubkey}";

impl Client {
    /// Posts the set of msg's to the Obol API, for a given lock hash.
    // It respects the timeout specified in the Client instance.
    pub async fn post_partial_exits(
        &self,
        lock_hash: &[u8],
        share_index: u64,
        identity_key: &k256::SecretKey,
        mut exit_blobs: Vec<ExitBlob>,
    ) -> Result<()> {
        let lock_hash_str = to_0x(lock_hash);
        let path = submit_partial_exit_url(&lock_hash_str);

        let url = self.build_url(&path);

        // Sort by validator index ascending
        exit_blobs.sort_by_key(|blob| {
            blob.signed_exit_message
                .message
                .validator_index
                .parse::<u64>()
                .unwrap_or_default()
        });

        let unsigned_msg = UnsignedPartialExitRequest {
            partial_exits: exit_blobs.into(),
            share_idx: share_index,
        };

        let msg_root = unsigned_msg.hash_tree_root()?;
        let signature = charon_k1util::sign(identity_key, &msg_root)?;

        let signed_req = PartialExitRequest {
            unsigned: unsigned_msg,
            signature: signature.to_vec(),
        };

        let body = serde_json::to_vec(&signed_req)?;

        self.http_post(url, body, None).await?;

        Ok(())
    }

    /// Gets  the full exit message for a given validator public key, lock hash
    /// and share index. It respects the timeout specified in the Client
    /// instance.
    pub async fn get_full_exit(
        &self,
        val_pubkey: &str,
        lock_hash: &[u8],
        share_index: u64,
        identity_key: &k256::SecretKey,
    ) -> Result<ExitBlob> {
        // Validate public key is 48 bytes
        let val_pubkey_bytes = from_0x(val_pubkey, 48)?;

        let path = fetch_full_exit_url(val_pubkey, &to_0x(lock_hash), share_index);

        let url = self.build_url(&path);

        // Create authentication blob
        let exit_auth_data = FullExitAuthBlob {
            lock_hash: lock_hash.to_vec(),
            validator_pubkey: val_pubkey_bytes.clone(),
            share_index,
        };

        let exit_auth_data_root = exit_auth_data.hash_tree_root()?;

        let lock_hash_signature = charon_k1util::sign(identity_key, &exit_auth_data_root)?;

        let headers = vec![(
            "Authorization".to_string(),
            bearer_string(&lock_hash_signature),
        )];

        let response_body = self.http_get(url, Some(&headers)).await?;

        let exit_response: FullExitResponse = serde_json::from_slice(&response_body)?;

        // Aggregate partial signatures
        let mut raw_signatures: HashMap<u8, Signature> = HashMap::new();

        for (sig_idx, sig_str) in exit_response.signatures.iter().enumerate() {
            if sig_str.is_empty() {
                // Ignore, the associated share index didn't push a partial signature yet
                continue;
            }

            if sig_str.len() < 2 {
                return Err(Error::InvalidSignatureSize(sig_str.len()));
            }

            // A BLS signature is 96 bytes long
            let sig_bytes = from_0x(sig_str, 96)?;

            // Convert to Signature type
            let mut sig = [0u8; 96];
            sig.copy_from_slice(&sig_bytes);

            // Signature indices are 1-based in threshold BLS
            let share_idx = sig_idx
                .checked_add(1)
                .and_then(|idx| u8::try_from(idx).ok())
                .ok_or_else(|| Error::InvalidSignatureSize(sig_idx.saturating_add(1)))?;
            raw_signatures.insert(share_idx, sig);
        }

        // Perform threshold aggregation
        let full_sig = BlstImpl.threshold_aggregate(&raw_signatures)?;

        let epoch_u64: u64 = exit_response.epoch.parse()?;

        Ok(ExitBlob {
            public_key: Some(val_pubkey.to_string()),
            signed_exit_message: eth2api::types::GetPoolVoluntaryExitsResponseResponseDatum {
                message: eth2api::types::Phase0SignedVoluntaryExitMessage {
                    epoch: epoch_u64.to_string(),
                    validator_index: exit_response.validator_index.to_string(),
                },
                signature: to_0x(&full_sig),
            },
        })
    }

    /// Deletes the partial exit message for a given validator public key, lock
    /// hash and share index.
    // It respects the timeout specified in the Client instance.
    pub async fn delete_partial_exit(
        &self,
        val_pubkey: &str,
        lock_hash: &[u8],
        share_index: u64,
        identity_key: &k256::SecretKey,
    ) -> Result<()> {
        // Validate public key is 48 bytes
        let val_pubkey_bytes = from_0x(val_pubkey, 48)?;

        let path = delete_partial_exit_url(val_pubkey, &to_0x(lock_hash), share_index);

        let url = self.build_url(&path);

        let exit_auth_data = FullExitAuthBlob {
            lock_hash: lock_hash.to_vec(),
            validator_pubkey: val_pubkey_bytes,
            share_index,
        };

        let exit_auth_data_root = exit_auth_data.hash_tree_root()?;

        let lock_hash_signature = charon_k1util::sign(identity_key, &exit_auth_data_root)?;

        let headers = vec![(
            "Authorization".to_string(),
            bearer_string(&lock_hash_signature),
        )];

        self.http_delete(url, Some(&headers)).await?;

        Ok(())
    }
}

/// Returns the partial exit Obol API URL for a given lock hash.
fn submit_partial_exit_url(lock_hash: &str) -> String {
    SUBMIT_PARTIAL_EXIT_TMPL.replace(LOCK_HASH_PATH, lock_hash)
}

/// Returns the delete partial exit Obol API URL.
fn delete_partial_exit_url(val_pubkey: &str, lock_hash: &str, share_index: u64) -> String {
    DELETE_PARTIAL_EXIT_TMPL
        .replace(VAL_PUBKEY_PATH, val_pubkey)
        .replace(LOCK_HASH_PATH, lock_hash)
        .replace(SHARE_INDEX_PATH, &share_index.to_string())
}

/// Returns the full exit Obol API URL.
fn fetch_full_exit_url(val_pubkey: &str, lock_hash: &str, share_index: u64) -> String {
    FETCH_FULL_EXIT_TMPL
        .replace(VAL_PUBKEY_PATH, val_pubkey)
        .replace(LOCK_HASH_PATH, lock_hash)
        .replace(SHARE_INDEX_PATH, &share_index.to_string())
}

fn map_hasher_error(err: HasherError) -> Error {
    use charon_cluster::ssz::SSZError;
    Error::Ssz(SSZError::HashWalkerError(err))
}

fn map_walker_error<E: std::error::Error>(err: E) -> Error {
    use charon_cluster::ssz::SSZError;
    Error::Ssz(SSZError::UnsupportedVersion(err.to_string()))
}

fn put_bytes_n<H: HashWalker>(hh: &mut H, bytes: &[u8], expected_len: usize) -> Result<()> {
    if bytes.len() > expected_len {
        use charon_cluster::ssz::SSZError;
        return Err(Error::Ssz(SSZError::UnsupportedVersion(format!(
            "bytes too long: expected {}, got {}",
            expected_len,
            bytes.len()
        ))));
    }
    let padded: Vec<u8> = left_pad(bytes, expected_len);
    hh.put_bytes(&padded).map_err(map_walker_error)
}

fn hash_exit_blob(blob: &ExitBlob) -> Result<[u8; 32]> {
    let mut hh = Hasher::default();
    hash_exit_blob_with(blob, &mut hh)?;
    hh.hash_root().map_err(map_hasher_error)
}

fn hash_exit_blob_with<H: HashWalker>(blob: &ExitBlob, hh: &mut H) -> Result<()> {
    let index = hh.index();

    let pk = blob.public_key.as_ref().ok_or_else(|| {
        use charon_cluster::ssz::SSZError;
        Error::Ssz(SSZError::UnsupportedVersion(
            "missing public key".to_string(),
        ))
    })?;
    let pk_bytes = from_0x(pk, SSZ_LEN_PUB_KEY)?;
    hh.put_bytes(&pk_bytes).map_err(map_walker_error)?;

    hash_signed_voluntary_exit_with(&blob.signed_exit_message, hh)?;

    hh.merkleize(index).map_err(map_walker_error)?;
    Ok(())
}

fn hash_partial_exits(exits: &[ExitBlob]) -> Result<[u8; 32]> {
    let mut hh = Hasher::default();
    hash_partial_exits_with(exits, &mut hh)?;
    hh.hash_root().map_err(map_hasher_error)
}

fn hash_unsigned_partial_exit_request(req: &UnsignedPartialExitRequest) -> Result<[u8; 32]> {
    let mut hh = Hasher::default();
    hash_unsigned_partial_exit_request_with(req, &mut hh)?;
    hh.hash_root().map_err(map_hasher_error)
}

fn hash_unsigned_partial_exit_request_with<H: HashWalker>(
    req: &UnsignedPartialExitRequest,
    hh: &mut H,
) -> Result<()> {
    let index = hh.index();

    hash_partial_exits_with(&req.partial_exits, hh)?;
    hh.put_uint64(req.share_idx).map_err(map_walker_error)?;

    hh.merkleize(index).map_err(map_walker_error)?;
    Ok(())
}

fn hash_partial_exits_with<H: HashWalker>(exits: &[ExitBlob], hh: &mut H) -> Result<()> {
    let index = hh.index();
    let num = exits.len();

    for exit_blob in exits {
        hash_exit_blob_with(exit_blob, hh)?;
    }

    hh.merkleize_with_mixin(index, num, SSZ_MAX_EXITS)
        .map_err(map_walker_error)?;
    Ok(())
}

fn hash_full_exit_auth_blob(blob: &FullExitAuthBlob) -> Result<[u8; 32]> {
    let mut hh = Hasher::default();
    hash_full_exit_auth_blob_with(blob, &mut hh)?;
    hh.hash_root().map_err(map_hasher_error)
}

fn hash_full_exit_auth_blob_with<H: HashWalker>(blob: &FullExitAuthBlob, hh: &mut H) -> Result<()> {
    let index = hh.index();

    hh.put_bytes(&blob.lock_hash).map_err(map_walker_error)?;
    put_bytes_n(hh, &blob.validator_pubkey, SSZ_LEN_PUB_KEY)?;
    hh.put_uint64(blob.share_index).map_err(map_walker_error)?;

    hh.merkleize(index).map_err(map_walker_error)?;
    Ok(())
}

fn hash_signed_voluntary_exit_with<H: HashWalker>(
    exit: &SignedVoluntaryExit,
    hh: &mut H,
) -> Result<()> {
    let index = hh.index();

    hash_voluntary_exit_with(&exit.message, hh)?;
    let sig_bytes = from_0x(&exit.signature, SSZ_LEN_BLS_SIG)?;
    put_bytes_n(hh, &sig_bytes, SSZ_LEN_BLS_SIG)?;

    hh.merkleize(index).map_err(map_walker_error)?;
    Ok(())
}

fn hash_voluntary_exit_with<H: HashWalker>(
    message: &Phase0SignedVoluntaryExitMessage,
    hh: &mut H,
) -> Result<()> {
    let index = hh.index();

    let epoch = message.epoch.parse::<u64>().map_err(Error::EpochParse)?;
    let validator_index = message
        .validator_index
        .parse::<u64>()
        .map_err(Error::EpochParse)?;

    hh.put_uint64(epoch).map_err(map_walker_error)?;
    hh.put_uint64(validator_index).map_err(map_walker_error)?;

    hh.merkleize(index).map_err(map_walker_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obolapi::ClientOptions;

    #[test]
    fn test_submit_partial_exit_url() {
        let url = submit_partial_exit_url("0xabcd1234");
        assert_eq!(url, "/exp/partial_exits/0xabcd1234");
    }

    #[test]
    fn test_delete_partial_exit_url() {
        let url = delete_partial_exit_url("0xpubkey", "0xlockhash", 5);
        assert_eq!(url, "/exp/partial_exits/0xlockhash/5/0xpubkey");
    }

    #[test]
    fn test_fetch_full_exit_url() {
        let url = fetch_full_exit_url("0xpubkey", "0xlockhash", 5);
        assert_eq!(url, "/exp/exit/0xlockhash/5/0xpubkey");
    }

    #[test]
    fn test_build_submit_partial_exit_url_root_base() {
        let client = Client::new("https://api.obol.tech", ClientOptions::default()).unwrap();
        let path = submit_partial_exit_url("0xabcd1234");
        let url = client.build_url(&path);
        assert_eq!(
            url.as_str(),
            "https://api.obol.tech/exp/partial_exits/0xabcd1234"
        );
    }

    #[test]
    fn test_build_submit_partial_exit_url_v1_base() {
        let client = Client::new("https://api.obol.tech/v1", ClientOptions::default()).unwrap();
        let path = submit_partial_exit_url("0xabcd1234");
        let url = client.build_url(&path);
        assert_eq!(
            url.as_str(),
            "https://api.obol.tech/v1/exp/partial_exits/0xabcd1234"
        );
    }

    #[test]
    fn test_build_delete_partial_exit_url_root_base() {
        let client = Client::new("https://api.obol.tech", ClientOptions::default()).unwrap();
        let path = delete_partial_exit_url("0xpubkey", "0xlockhash", 5);
        let url = client.build_url(&path);
        assert_eq!(
            url.as_str(),
            "https://api.obol.tech/exp/partial_exits/0xlockhash/5/0xpubkey"
        );
    }

    #[test]
    fn test_build_delete_partial_exit_url_v1_base() {
        let client = Client::new("https://api.obol.tech/v1", ClientOptions::default()).unwrap();
        let path = delete_partial_exit_url("0xpubkey", "0xlockhash", 5);
        let url = client.build_url(&path);
        assert_eq!(
            url.as_str(),
            "https://api.obol.tech/v1/exp/partial_exits/0xlockhash/5/0xpubkey"
        );
    }

    #[test]
    fn test_build_fetch_full_exit_url_root_base() {
        let client = Client::new("https://api.obol.tech", ClientOptions::default()).unwrap();
        let path = fetch_full_exit_url("0xpubkey", "0xlockhash", 5);
        let url = client.build_url(&path);
        assert_eq!(
            url.as_str(),
            "https://api.obol.tech/exp/exit/0xlockhash/5/0xpubkey"
        );
    }

    #[test]
    fn test_build_fetch_full_exit_url_v1_base() {
        let client = Client::new("https://api.obol.tech/v1", ClientOptions::default()).unwrap();
        let path = fetch_full_exit_url("0xpubkey", "0xlockhash", 5);
        let url = client.build_url(&path);
        assert_eq!(
            url.as_str(),
            "https://api.obol.tech/v1/exp/exit/0xlockhash/5/0xpubkey"
        );
    }
}
