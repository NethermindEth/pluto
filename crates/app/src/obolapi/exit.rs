//! Exit-related API methods and data models.
//!
//! This module provides methods for managing partial and full validator exits
//! through the Obol API, along with the associated data structures.

use std::collections::HashMap;

use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls, types::Signature};
use serde::{Deserialize, Serialize};

use pluto_cluster::{
    helpers::to_0x_hex,
    ssz::{SSZ_LEN_BLS_SIG, SSZ_LEN_PUB_KEY},
};
use pluto_eth2api::types::{
    GetPoolVoluntaryExitsResponseResponseDatum, Phase0SignedVoluntaryExitMessage,
};
use pluto_ssz::{HashWalker, Hasher, put_bytes_n};

use crate::obolapi::{
    client::Client,
    error::{Error, Result},
    helper::{bearer_string, from_0x},
};

/// Type alias for signed voluntary exit from eth2api.
pub type SignedVoluntaryExit = GetPoolVoluntaryExitsResponseResponseDatum;

/// Trait for types that can be hashed using SSZ hash tree root.
pub trait SszHashable {
    /// Hashes this value into the provided hasher.
    fn hash_with(&self, hh: &mut Hasher) -> Result<()>;

    /// Computes the SSZ hash tree root of this value.
    fn hash_tree_root(&self) -> Result<[u8; 32]> {
        let mut hh = Hasher::default();
        self.hash_with(&mut hh)?;
        Ok(hh.hash_root()?)
    }
}

impl SszHashable for SignedVoluntaryExit {
    fn hash_with(&self, hh: &mut Hasher) -> Result<()> {
        let index = hh.index();

        self.message.hash_with(hh)?;
        let sig_bytes = from_0x(&self.signature, SSZ_LEN_BLS_SIG)?;
        put_bytes_n(hh, &sig_bytes, SSZ_LEN_BLS_SIG)?;

        hh.merkleize(index)?;
        Ok(())
    }
}

impl SszHashable for Phase0SignedVoluntaryExitMessage {
    fn hash_with(&self, hh: &mut Hasher) -> Result<()> {
        let index = hh.index();

        let epoch = self.epoch.parse::<u64>()?;
        let validator_index = self.validator_index.parse::<u64>()?;

        hh.put_uint64(epoch)?;
        hh.put_uint64(validator_index)?;

        hh.merkleize(index)?;
        Ok(())
    }
}

/// An exit message alongside its BLS12-381 hex-encoded signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitBlob {
    /// Validator public key (hex-encoded with 0x prefix).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// Signed voluntary exit message.
    pub signed_exit_message: SignedVoluntaryExit,
}

impl SszHashable for ExitBlob {
    fn hash_with(&self, hh: &mut Hasher) -> Result<()> {
        let index = hh.index();

        let pk = self.public_key.as_ref().ok_or_else(|| {
            use pluto_cluster::ssz::SSZError;
            Error::Ssz(SSZError::UnsupportedVersion(
                "missing public key".to_string(),
            ))
        })?;
        let pk_bytes = from_0x(pk, SSZ_LEN_PUB_KEY)?;
        hh.put_bytes(&pk_bytes)?;

        self.signed_exit_message.hash_with(hh)?;

        hh.merkleize(index)?;
        Ok(())
    }
}

/// An array of exit messages that have been signed with a partial key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PartialExits(pub Vec<ExitBlob>);

impl SszHashable for PartialExits {
    fn hash_with(&self, hh: &mut Hasher) -> Result<()> {
        let index = hh.index();
        let num = self.0.len();

        for exit_blob in &self.0 {
            exit_blob.hash_with(hh)?;
        }

        hh.merkleize_with_mixin(index, num, SSZ_MAX_EXITS)?;
        Ok(())
    }
}

impl From<Vec<ExitBlob>> for PartialExits {
    fn from(v: Vec<ExitBlob>) -> Self {
        Self(v)
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

impl SszHashable for UnsignedPartialExitRequest {
    fn hash_with(&self, hh: &mut Hasher) -> Result<()> {
        let index = hh.index();

        self.partial_exits.hash_with(hh)?;
        hh.put_uint64(self.share_idx)?;

        hh.merkleize(index)?;
        Ok(())
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
            signature: to_0x_hex(&req.signature),
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

impl SszHashable for FullExitAuthBlob {
    fn hash_with(&self, hh: &mut Hasher) -> Result<()> {
        let index = hh.index();

        hh.put_bytes(&self.lock_hash)?;
        put_bytes_n(hh, &self.validator_pubkey, SSZ_LEN_PUB_KEY)?;
        hh.put_uint64(self.share_index)?;

        hh.merkleize(index)?;
        Ok(())
    }
}
const SSZ_MAX_EXITS: usize = 65536;

impl Client {
    /// Posts the set of msg's to the Obol API, for a given lock hash.
    /// It respects the timeout specified in the Client instance.
    pub async fn post_partial_exits(
        &self,
        lock_hash: &[u8],
        share_index: u64,
        identity_key: &k256::SecretKey,
        mut exit_blobs: Vec<ExitBlob>,
    ) -> Result<()> {
        let lock_hash_str = to_0x_hex(lock_hash);
        let path = submit_partial_exit_url(&lock_hash_str);

        let url = self.build_url(&path)?;

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
        let signature = pluto_k1util::sign(identity_key, &msg_root)?;

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

        let path = fetch_full_exit_url(val_pubkey, &to_0x_hex(lock_hash), share_index);

        let url = self.build_url(&path)?;

        // Create authentication blob
        let exit_auth_data = FullExitAuthBlob {
            lock_hash: lock_hash.to_vec(),
            validator_pubkey: val_pubkey_bytes.clone(),
            share_index,
        };

        let exit_auth_data_root = exit_auth_data.hash_tree_root()?;

        let lock_hash_signature = pluto_k1util::sign(identity_key, &exit_auth_data_root)?;

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

            // Convert 0-indexed array position to 1-indexed share ID (API stores signatures
            // at array position share_id-1, e.g., share 1 at position 0)
            let share_idx = u8::try_from(sig_idx)
                .map_err(Error::FailedToConvertShareIndexToU8)?
                .checked_add(1)
                .ok_or(Error::MathOverflow)?;
            raw_signatures.insert(share_idx, sig);
        }

        // Perform threshold aggregation
        let full_sig = BlstImpl.threshold_aggregate(&raw_signatures)?;

        let epoch_u64: u64 = exit_response.epoch.parse()?;

        Ok(ExitBlob {
            public_key: Some(val_pubkey.to_string()),
            signed_exit_message: pluto_eth2api::types::GetPoolVoluntaryExitsResponseResponseDatum {
                message: pluto_eth2api::types::Phase0SignedVoluntaryExitMessage {
                    epoch: epoch_u64.to_string(),
                    validator_index: exit_response.validator_index.to_string(),
                },
                signature: to_0x_hex(&full_sig),
            },
        })
    }

    /// Deletes the partial exit message for a given validator public key, lock
    /// hash and share index.
    /// It respects the timeout specified in the Client instance.
    pub async fn delete_partial_exit(
        &self,
        val_pubkey: &str,
        lock_hash: &[u8],
        share_index: u64,
        identity_key: &k256::SecretKey,
    ) -> Result<()> {
        // Validate public key is 48 bytes
        let val_pubkey_bytes = from_0x(val_pubkey, 48)?;

        let path = delete_partial_exit_url(val_pubkey, &to_0x_hex(lock_hash), share_index);

        let url = self.build_url(&path)?;

        let exit_auth_data = FullExitAuthBlob {
            lock_hash: lock_hash.to_vec(),
            validator_pubkey: val_pubkey_bytes,
            share_index,
        };

        let exit_auth_data_root = exit_auth_data.hash_tree_root()?;

        let lock_hash_signature = pluto_k1util::sign(identity_key, &exit_auth_data_root)?;

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
    format!("/exp/partial_exits/{}", lock_hash)
}

/// Returns the delete partial exit Obol API URL.
fn delete_partial_exit_url(val_pubkey: &str, lock_hash: &str, share_index: u64) -> String {
    format!(
        "/exp/partial_exits/{}/{}/{}",
        lock_hash, share_index, val_pubkey
    )
}

/// Returns the full exit Obol API URL.
fn fetch_full_exit_url(val_pubkey: &str, lock_hash: &str, share_index: u64) -> String {
    format!("/exp/exit/{}/{}/{}", lock_hash, share_index, val_pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_partial_exit_url_works() {
        let url = submit_partial_exit_url("0xabcd1234");
        assert_eq!(url, "/exp/partial_exits/0xabcd1234");
    }

    #[test]
    fn delete_partial_exit_url_works() {
        let url = delete_partial_exit_url("0xpubkey", "0xlockhash", 5);
        assert_eq!(url, "/exp/partial_exits/0xlockhash/5/0xpubkey");
    }

    #[test]
    fn fetch_full_exit_url_works() {
        let url = fetch_full_exit_url("0xpubkey", "0xlockhash", 5);
        assert_eq!(url, "/exp/exit/0xlockhash/5/0xpubkey");
    }

    /// These test vectors were generated from Go `charon/app/obolapi` using
    /// fastssz
    #[test]
    fn ssz_root_parity_exit_models() -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn decode_hex(s: &str) -> std::result::Result<Vec<u8>, hex::FromHexError> {
            hex::decode(s)
        }

        fn decode_hex_32(s: &str) -> std::result::Result<[u8; 32], Box<dyn std::error::Error>> {
            let bytes = decode_hex(s)?;
            let len = bytes.len();
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| format!("expected 32 bytes, got {}", len))?;
            Ok(arr)
        }

        let lock_hash: Vec<u8> =
            decode_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?;
        let validator_pubkey: Vec<u8> = decode_hex(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\
2122232425262728292a2b2c2d2e2f30",
        )?;
        let bls_sig_hex = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

        let exit_blob = ExitBlob {
            public_key: Some(to_0x_hex(&validator_pubkey)),
            signed_exit_message: SignedVoluntaryExit {
                message: Phase0SignedVoluntaryExitMessage {
                    epoch: "194048".to_string(),
                    validator_index: "42".to_string(),
                },
                signature: bls_sig_hex.to_string(),
            },
        };
        let partial_exits: PartialExits = vec![exit_blob.clone()].into();
        let unsigned = UnsignedPartialExitRequest {
            partial_exits: partial_exits.clone(),
            share_idx: 3,
        };
        let auth = FullExitAuthBlob {
            lock_hash,
            validator_pubkey,
            share_index: 3,
        };

        let got_exit = exit_blob.hash_tree_root()?;
        let got_partial = partial_exits.hash_tree_root()?;
        let got_unsigned = unsigned.hash_tree_root()?;
        let got_auth = auth.hash_tree_root()?;

        let want_exit =
            decode_hex_32("af0b1a9d98ac628035219391f59ee2708d813a3d860c6d17fa8cae0fb0746d20")?;
        let want_partial =
            decode_hex_32("9f310361788c9dfc6b0a3cfd77febad4c9a834c368be91ae0e570a40f82e810e")?;
        let want_unsigned =
            decode_hex_32("b58b5989634e567fa82b7c141918e30e44051c1ed6d0c36c3269021c531f4669")?;
        let want_auth =
            decode_hex_32("f7fec0dccbdeba7a7aa5978058df8891d1c403bb455a481677ecb5360b2f7fd6")?;

        assert_eq!(got_exit, want_exit);
        assert_eq!(got_partial, want_partial);
        assert_eq!(got_unsigned, want_unsigned);
        assert_eq!(got_auth, want_auth);

        Ok(())
    }
}
