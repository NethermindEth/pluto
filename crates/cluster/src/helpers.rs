use chrono::{DateTime, Utc};
use pluto_crypto::tbls::Tbls;
use pluto_eth2util::helpers::{checksum_address, public_key_to_address};
use pluto_k1util::K1UtilError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs};
use std::borrow::Cow;

use crate::{
    definition::{self, ADDRESS_LEN},
    eip712sigs, operator,
    ssz::SSZError,
    ssz_hasher::HashWalker,
};

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

/// EthHex represents byte slices that are json formatted as 0x prefixed hex.
/// Can be used both as a standalone type and with serde_as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthHex(Vec<u8>);

// Standalone Serialize/Deserialize implementations
impl Serialize for EthHex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(&self.0)))
    }
}

impl<'de> Deserialize<'de> for EthHex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let cow = Cow::<str>::deserialize(deserializer)?;
        if cow.is_empty() {
            return Ok(EthHex(vec![]));
        }
        let hex_str = cow.strip_prefix("0x").unwrap_or(&cow);
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        Ok(EthHex(bytes))
    }
}

// SerializeAs/DeserializeAs implementations for use with serde_as
impl<T> SerializeAs<T> for EthHex
where
    T: AsRef<[u8]>,
{
    fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(value.as_ref())))
    }
}

impl<'de, T> DeserializeAs<'de, T> for EthHex
where
    T: TryFrom<Vec<u8>>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        let eth_hex = EthHex::deserialize(deserializer)?;
        T::try_from(eth_hex.0).map_err(|_| serde::de::Error::custom("failed to convert bytes"))
    }
}

// Helper methods and conversions
impl EthHex {
    /// Create a new EthHex from a byte slice.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Inner bytes.
    pub fn inner(&self) -> &Vec<u8> {
        &self.0
    }
}

impl From<Vec<u8>> for EthHex {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<EthHex> for Vec<u8> {
    fn from(eth_hex: EthHex) -> Self {
        eth_hex.0
    }
}

impl TryFrom<&str> for EthHex {
    type Error = hex::FromHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Ok(EthHex(vec![]));
        }
        let s = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex::decode(s)?;
        Ok(EthHex(bytes))
    }
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

/// Converts a 0x prefixed hex string to a byte slice.
pub fn from_0x_hex_str(s: &str, len: usize) -> Result<Vec<u8>, hex::FromHexError> {
    if s.is_empty() {
        return Ok(vec![]);
    }

    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    if bytes.len() != len {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    Ok(bytes)
}

/// `put_byte_list` appends a ssz byte list.
/// See reference:
/// github.com/attestantio/go-eth2-client/spec/bellatrix/
/// executionpayload_encoding.go:277-284.
pub fn put_byte_list<H: HashWalker>(
    hh: &mut H,
    bytes: &[u8],
    limit: usize,
    field: &str,
) -> Result<(), SSZError<H>> {
    let elem_indx = hh.index();

    let byte_len = bytes.len();

    if byte_len > limit {
        return Err(SSZError::<H>::IncorrectListSize {
            namespace: "put_byte_list",
            field: field.to_string(),
            actual: byte_len,
            expected: limit,
        });
    }

    hh.append_bytes32(bytes)
        .map_err(SSZError::<H>::HashWalkerError)?;

    hh.merkleize_with_mixin(elem_indx, byte_len, limit.div_ceil(32))
        .map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

/// `put_bytes_n` appends bytes as a ssz fixed size byte array of length n.
pub fn put_bytes_n<H: HashWalker>(hh: &mut H, bytes: &[u8], n: usize) -> Result<(), SSZError<H>> {
    if bytes.len() > n {
        return Err(SSZError::<H>::IncorrectListSize {
            namespace: "put_bytes_n",
            field: "".to_string(),
            actual: bytes.len(),
            expected: n,
        });
    }

    hh.put_bytes(&left_pad(bytes, n))
        .map_err(SSZError::<H>::HashWalkerError)?;

    Ok(())
}

/// `put_hex_bytes_20` appends a 20 byte fixed size byte ssz array from the
/// 0xhex address.
pub fn put_hex_bytes_20<H: HashWalker>(hh: &mut H, address: &str) -> Result<(), SSZError<H>> {
    let bytes = from_0x_hex_str(address, ADDRESS_LEN)?;
    hh.put_bytes(&left_pad(&bytes, ADDRESS_LEN))
        .map_err(SSZError::<H>::HashWalkerError)?;
    Ok(())
}

/// `left_pad` returns the byte slice left padded with zero to ensure a length
/// of at least len.
pub fn left_pad(bytes: &[u8], len: usize) -> Vec<u8> {
    if bytes.len() >= len {
        return bytes.to_vec();
    }

    let pad_count = len.saturating_sub(bytes.len());
    let mut padded = vec![0; pad_count];
    padded.extend_from_slice(bytes);
    padded
}
/// `to_0x_hex` converts a byte slice to a 0x prefixed hex string.
pub fn to_0x_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    format!("0x{}", hex::encode(bytes))
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

/// Returns a BLS aggregate signatures of the message signed by all the shares.
pub fn agg_sign(
    secrets: &Vec<Vec<pluto_crypto::types::PrivateKey>>,
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
    use super::*;
    use serde_with::serde_as;

    #[test]
    fn test_left_pad() {
        assert_eq!(left_pad(&[0x12, 0x34], 4), vec![0x00, 0x00, 0x12, 0x34]);
        assert_eq!(left_pad(&[0xab], 3), vec![0x00, 0x00, 0xab]);
        assert_eq!(left_pad(&[1, 2, 3], 3), vec![1, 2, 3]);
        assert_eq!(left_pad(&[1, 2, 3], 2), vec![1, 2, 3]);
    }

    #[test]
    fn test_eth_hex_serialize_deserialize() {
        let eth_hex = EthHex(vec![0x01, 0x02, 0x03]);
        let serialized = serde_json::to_string(&eth_hex).unwrap();
        assert_eq!(serialized, "\"0x010203\"");
        let deserialized: EthHex = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, eth_hex);
    }

    #[test]
    fn test_empty_eth_hex_serialize_deserialize() {
        let eth_hex = EthHex(vec![]);
        let serialized = serde_json::to_string(&eth_hex).unwrap();
        assert_eq!(serialized, "\"0x\"");
        let deserialized: EthHex = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, eth_hex);
    }

    #[test]
    fn test_empty_string_deserialize() {
        // Empty string should deserialize to empty EthHex
        let deserialized: EthHex = serde_json::from_str("\"\"").unwrap();
        assert_eq!(deserialized, EthHex(vec![]));

        // TryFrom should also handle empty string
        let from_str = EthHex::try_from("").unwrap();
        assert_eq!(from_str, EthHex(vec![]));
    }

    #[serde_as]
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestStruct {
        #[serde_as(as = "EthHex")]
        data: Vec<u8>,

        #[serde_as(as = "EthHex")]
        hash: [u8; 32],

        #[serde_as(as = "Option<EthHex>")]
        optional_data: Option<Vec<u8>>,
    }

    #[test]
    fn test_with_serde_as() {
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

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct MixedStruct {
        // Using EthHex as a type
        eth_hex_field: EthHex,

        // Using regular Vec<u8> without hex encoding
        regular_bytes: Vec<u8>,
    }

    #[test]
    fn test_mixed_usage() {
        let mixed = MixedStruct {
            eth_hex_field: EthHex::new(vec![0x01, 0x02, 0x03]),
            regular_bytes: vec![0x04, 0x05, 0x06],
        };

        let json = serde_json::to_string(&mixed).unwrap();
        assert!(json.contains("\"0x010203\""));
        assert!(json.contains("[4,5,6]"));
    }
}
