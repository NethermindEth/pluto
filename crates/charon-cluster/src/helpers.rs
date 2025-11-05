use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs};
use std::borrow::Cow;

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
        Ok(DateTime::<Utc>::from_timestamp(timestamp, 0).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_with::serde_as;

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
