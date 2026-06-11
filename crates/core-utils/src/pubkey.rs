// In golang implementation they use pk_len = 98, which is 0x + [48 bytes]
// We use pk_len = 48, which is [48 bytes], the main difference is that we store
// the pub key as [u8; 48] instead of string.
// [original implementation](https://github.com/ObolNetwork/charon/blob/b3008103c5429b031b63518195f4c49db4e9a68d/core/types.go#L264)
/// Public key length
pub const PK_LEN: usize = 48;

use std::fmt::Display;

pub use pluto_crypto::types::{SIGNATURE_LENGTH, Signature};
use serde::{Deserialize, Serialize};

/// Public key struct
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PubKey(pub(crate) [u8; PK_LEN]);

impl Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl TryFrom<&str> for PubKey {
    type Error = PubKeyError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value.strip_prefix("0x").unwrap_or(value);
        let hex_value = hex::decode(value).map_err(|_| PubKeyError::InvalidString)?;
        PubKey::try_from(hex_value.as_slice())
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);

        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;

        if bytes.len() != PK_LEN {
            return Err(serde::de::Error::custom(format!(
                "invalid public key length: got {}, want {}",
                bytes.len(),
                PK_LEN
            )));
        }

        let mut pk = [0u8; PK_LEN];
        pk.copy_from_slice(&bytes);
        Ok(PubKey(pk))
    }
}

impl From<[u8; PK_LEN]> for PubKey {
    fn from(pk: [u8; PK_LEN]) -> Self {
        PubKey(pk)
    }
}

/// Public key error type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubKeyError {
    /// Invalid public key length.
    InvalidLength,
    /// Invalid public key string.
    InvalidString,
}

impl PubKey {
    /// Create a new public key.
    pub fn new(pk: [u8; PK_LEN]) -> Self {
        PubKey(pk)
    }

    /// Returns logging-friendly abbreviated form: "b82_97f"
    pub fn abbreviated(&self) -> String {
        let hex = hex::encode(self.0);
        format!("{}_{}", &hex[0..3], &hex[93..96])
    }
}

impl TryFrom<&[u8]> for PubKey {
    type Error = PubKeyError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != PK_LEN {
            return Err(PubKeyError::InvalidLength);
        }
        let mut arr = [0u8; PK_LEN];
        arr.copy_from_slice(bytes);
        Ok(PubKey(arr))
    }
}

impl Display for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

/// Implement AsRef<[u8]> for PubKey to allow for easy conversion to bytes.
impl AsRef<[u8]> for PubKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
