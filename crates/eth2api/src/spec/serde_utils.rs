//! Shared serde helpers for consensus-spec JSON encoding.

use pluto_ssz::serde_utils::trim_0x_prefix;

/// Error raised while converting a loosely-typed beacon-API value (whose
/// numeric and byte fields are carried as decimal / `0x`-hex strings) into a
/// strongly-typed spec value.
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    /// A decimal-encoded integer field could not be parsed.
    #[error("parse integer field `{field}`")]
    ParseInt {
        /// Name of the offending field.
        field: &'static str,
    },
    /// A `0x`-hex field could not be decoded or had an unexpected length.
    #[error("decode hex field `{field}`")]
    DecodeHex {
        /// Name of the offending field.
        field: &'static str,
    },
}

/// Parses a decimal-encoded unsigned integer field.
pub(crate) fn parse_u64(value: &str, field: &'static str) -> Result<u64, ConversionError> {
    value
        .parse()
        .map_err(|_| ConversionError::ParseInt { field })
}

/// Decodes a `0x`-prefixed (or bare) hex string into a byte vector.
pub(crate) fn decode_hex_var(value: &str, field: &'static str) -> Result<Vec<u8>, ConversionError> {
    hex::decode(trim_0x_prefix(value)).map_err(|_| ConversionError::DecodeHex { field })
}

/// Decodes a `0x`-prefixed (or bare) hex string into a fixed-size byte array,
/// erroring when the decoded length does not match `N`.
pub(crate) fn decode_hex_fixed<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], ConversionError> {
    decode_hex_var(value, field)?
        .try_into()
        .map_err(|_| ConversionError::DecodeHex { field })
}

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
