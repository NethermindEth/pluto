//! Shared serde helpers for consensus-spec JSON encoding.

/// JSON helpers for decimal-encoded `U256` values with optional `0x` input
/// support.
pub(crate) mod u256_dec_serde {
    use alloy::primitives::U256;
    use pluto_ssz::serde_utils::strip_0x_prefix;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as DeError};

    pub fn serialize<S: Serializer>(value: &U256, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.to_string().as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<U256, D::Error> {
        let value = String::deserialize(deserializer)?;
        let (radix, digits) = if let Some(hex) = strip_0x_prefix(value.as_str()) {
            (16, hex)
        } else {
            (10, value.as_str())
        };

        U256::from_str_radix(digits, radix)
            .map_err(|err| D::Error::custom(format!("invalid u256: {err}")))
    }
}
