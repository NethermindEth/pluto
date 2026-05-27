//! Generic serde helpers for SSZ-related types and JSON hex encoding.

use serde::{
    Deserialize, Deserializer, Serializer,
    de::{Error as DeError, Unexpected},
};
use serde_with::{DeserializeAs, SerializeAs};

/// Strips the `0x` or `0X` prefix from a hex string, returning `None` if
/// absent.
pub fn strip_0x_prefix(value: &str) -> Option<&str> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
}

/// Strips the `0x` or `0X` prefix from a hex string, returning the input
/// unchanged if absent.
pub fn trim_0x_prefix(value: &str) -> &str {
    strip_0x_prefix(value).unwrap_or(value)
}

/// Encodes bytes as lowercase `0x`-prefixed hex, always including the prefix.
///
/// Returns `"0x"` for empty input, matching the go-eth2-client convention for
/// execution-payload fields such as `extra_data`.
pub fn encode_0x_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Encodes bytes as lowercase `0x`-prefixed hex, or an empty string for empty
/// input.
///
/// Matches Charon's `to0xHex` convention used throughout cluster/definition
/// JSON: empty byte slices serialise as `""` rather than `"0x"`.
pub fn encode_hex_or_empty(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    format!("0x{}", hex::encode(bytes))
}

/// Decodes a `0x`-prefixed or unprefixed hex string.
pub fn decode_0x_hex<E: DeError>(s: &str) -> Result<Vec<u8>, E> {
    hex::decode(trim_0x_prefix(s)).map_err(E::custom)
}

/// Serde adapter for byte-like values encoded as `0x`-prefixed lowercase hex
/// strings.
///
/// Serialises empty input as `"0x"`, matching the go-eth2-client convention for
/// execution-payload fields. Use [`HexBytes`] for cluster/definition fields
/// that follow Charon's `to0xHex` convention (empty → `""`).
///
/// Deserialization accepts both prefixed (`0x...`) and unprefixed (`...`)
/// values, as well as `""` for empty.
pub struct Hex0x;

impl<T> SerializeAs<T> for Hex0x
where
    T: AsRef<[u8]>,
{
    fn serialize_as<S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_0x_hex(source.as_ref()))
    }
}

impl<'de, T> DeserializeAs<'de, T> for Hex0x
where
    T: TryFrom<Vec<u8>>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let decoded = decode_0x_hex::<D::Error>(value.as_str())?;
        decoded.try_into().map_err(|_err: T::Error| {
            D::Error::invalid_value(
                Unexpected::Str(value.as_str()),
                &"hex bytes convertible to target type",
            )
        })
    }
}

/// Serde adapter for cluster/definition byte fields following Charon's
/// `to0xHex` convention.
///
/// Serialises empty input as `""` and non-empty input as `"0x{hex}"`. This
/// matches the Charon JSON format for unsigned operator signatures and similar
/// optional fields. Use [`Hex0x`] for eth2 execution-payload fields that expect
/// `"0x"` for empty.
///
/// Deserialization accepts both `""` and `"0x"` for empty bytes.
pub struct HexBytes;

impl<T> SerializeAs<T> for HexBytes
where
    T: AsRef<[u8]>,
{
    fn serialize_as<S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex_or_empty(source.as_ref()))
    }
}

impl<'de, T> DeserializeAs<'de, T> for HexBytes
where
    T: TryFrom<Vec<u8>>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let decoded = decode_0x_hex::<D::Error>(value.as_str())?;
        decoded.try_into().map_err(|_err: T::Error| {
            D::Error::invalid_value(
                Unexpected::Str(value.as_str()),
                &"hex bytes convertible to target type",
            )
        })
    }
}

/// Serde helpers for SSZ lists of `u64` encoded as JSON strings.
pub mod ssz_list_u64_string_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};

    use crate::SszList;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrU64 {
        String(String),
        U64(u64),
    }

    /// Serializes an `SszList<u64, MAX>` as a JSON array of decimal strings.
    pub fn serialize<S, const MAX: usize>(
        value: &SszList<u64, MAX>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let strings: Vec<String> = value
            .0
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        strings.serialize(serializer)
    }

    /// Deserializes a JSON array of decimal strings or integers into an
    /// `SszList<u64, MAX>`.
    pub fn deserialize<'de, D, const MAX: usize>(
        deserializer: D,
    ) -> Result<SszList<u64, MAX>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Vec::<StringOrU64>::deserialize(deserializer)?;

        if MAX > 0 && raw.len() > MAX {
            return Err(D::Error::custom(format!(
                "list length {} exceeds max {}",
                raw.len(),
                MAX
            )));
        }

        let mut out = Vec::with_capacity(raw.len());
        for value in raw {
            let parsed = match value {
                StringOrU64::U64(value) => value,
                StringOrU64::String(value) => value.parse::<u64>().map_err(|err| {
                    D::Error::custom(format!("invalid integer string '{value}': {err}"))
                })?,
            };
            out.push(parsed);
        }

        Ok(SszList(out))
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    use super::*;

    #[serde_as]
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Eth2Field {
        #[serde_as(as = "Hex0x")]
        data: Vec<u8>,
    }

    #[serde_as]
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct ClusterField {
        #[serde_as(as = "HexBytes")]
        data: Vec<u8>,
    }

    #[test]
    fn encode_0x_hex_always_prefixed() {
        assert_eq!(encode_0x_hex(&[]), "0x");
        assert_eq!(encode_0x_hex(&[0xab, 0xcd]), "0xabcd");
    }

    #[test]
    fn encode_hex_or_empty_returns_empty_str_for_empty() {
        assert_eq!(encode_hex_or_empty(&[]), "");
        assert_eq!(encode_hex_or_empty(&[0xab, 0xcd]), "0xabcd");
    }

    // Regression: Hex0x must produce "0x" for empty bytes, not "".
    // go-eth2-client requires "0x" for empty extra_data and similar fields.
    #[test]
    fn hex0x_serializes_empty_as_0x() {
        let s = Eth2Field { data: vec![] };
        assert_eq!(serde_json::to_string(&s).unwrap(), r#"{"data":"0x"}"#);
    }

    // Regression: HexBytes must produce "" for empty bytes, matching Charon's
    // to0xHex used for unsigned operator signatures in cluster/definition JSON.
    #[test]
    fn hex_bytes_serializes_empty_as_empty_str() {
        let s = ClusterField { data: vec![] };
        assert_eq!(serde_json::to_string(&s).unwrap(), r#"{"data":""}"#);
    }

    #[test]
    fn both_adapters_deserialize_empty_variants() {
        let from_empty: Eth2Field = serde_json::from_str(r#"{"data":""}"#).unwrap();
        assert!(from_empty.data.is_empty());

        let from_0x: Eth2Field = serde_json::from_str(r#"{"data":"0x"}"#).unwrap();
        assert!(from_0x.data.is_empty());

        let cluster_from_empty: ClusterField = serde_json::from_str(r#"{"data":""}"#).unwrap();
        assert!(cluster_from_empty.data.is_empty());

        let cluster_from_0x: ClusterField = serde_json::from_str(r#"{"data":"0x"}"#).unwrap();
        assert!(cluster_from_0x.data.is_empty());
    }

    #[test]
    fn both_adapters_roundtrip_non_empty() {
        let eth2 = Eth2Field {
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let json = serde_json::to_string(&eth2).unwrap();
        assert_eq!(json, r#"{"data":"0xdeadbeef"}"#);
        assert_eq!(serde_json::from_str::<Eth2Field>(&json).unwrap(), eth2);

        let cluster = ClusterField {
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let json = serde_json::to_string(&cluster).unwrap();
        assert_eq!(json, r#"{"data":"0xdeadbeef"}"#);
        assert_eq!(
            serde_json::from_str::<ClusterField>(&json).unwrap(),
            cluster
        );
    }
}
