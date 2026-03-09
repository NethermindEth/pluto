//! Shared serde helpers for consensus-spec JSON encoding.

use serde::{
    Deserialize, Deserializer, Serializer,
    de::{Error as DeError, Unexpected},
};
use serde_with::{DeserializeAs, SerializeAs};

pub(crate) fn strip_0x_prefix(value: &str) -> Option<&str> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
}

pub(crate) fn trim_0x_prefix(value: &str) -> &str {
    strip_0x_prefix(value).unwrap_or(value)
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
        let encoded = hex::encode(source.as_ref());
        let out = format!("0x{encoded}");
        serializer.serialize_str(out.as_str())
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
        let trimmed = trim_0x_prefix(value.as_str());
        let decoded = hex::decode(trimmed).map_err(D::Error::custom)?;
        decoded.try_into().map_err(|_err: T::Error| {
            D::Error::invalid_value(
                Unexpected::Str(value.as_str()),
                &"hex bytes convertible to target type",
            )
        })
    }
}

/// Serde helpers for SSZ lists of `u64` encoded as JSON strings.
pub(crate) mod ssz_list_u64_string_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};

    use crate::spec::ssz_types::SszList;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrU64 {
        String(String),
        U64(u64),
    }

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

/// JSON helpers for decimal-encoded `U256` values with optional `0x` input
/// support.
pub(crate) mod u256_dec_serde {
    use alloy::primitives::U256;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as DeError};

    pub fn serialize<S: Serializer>(value: &U256, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.to_string().as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<U256, D::Error> {
        let value = String::deserialize(deserializer)?;
        let (radix, digits) =
            if let Some(hex) = crate::spec::serde_utils::strip_0x_prefix(value.as_str()) {
                (16, hex)
            } else {
                (10, value.as_str())
            };

        U256::from_str_radix(digits, radix)
            .map_err(|err| D::Error::custom(format!("invalid u256: {err}")))
    }
}
