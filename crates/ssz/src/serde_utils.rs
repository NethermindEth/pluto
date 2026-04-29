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

/// Encodes bytes as lowercase `0x`-prefixed hex.
/// In case of empty bytes, returns an empty string.
pub fn encode_0x_hex(bytes: &[u8]) -> String {
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
/// Deserialization accepts both prefixed (`0x...`) and unprefixed (`...`)
/// values.
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
