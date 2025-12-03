use std::collections::HashMap;

use sha3::{Digest, Keccak256};

/// Primitive is a type alias for a string.
pub type Primitive = String;

/// PRIMITIVE_STRING is the string primitive type.
pub const PRIMITIVE_STRING: &str = "string";

/// PRIMITIVE_UINT64 is the uint64 primitive type.
pub const PRIMITIVE_UINT256: &str = "uint256";

/// TERMS_AND_CONDITION_TYPE_NAME is the terms and conditions type name.
pub const TERMS_AND_CONDITION_TYPE_NAME: &str = "TermsAndConditions";

/// TypedData represents a dynamically typed EIP-712 message.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedData {
    /// Domain of the EIP-712 message.
    pub domain: Domain,
    /// Primary type of the EIP-712 message.
    pub primary_type: Type,
}

/// Type represents the primary data-type of an EIP-712 message.
#[derive(Debug, Clone, PartialEq)]
pub struct Type {
    /// Name of the type.
    pub name: String,
    /// Fields of the type.
    pub fields: Vec<Field>,
}

/// Field is the field of an EIP-712 message primary data-type.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// Name of the field.
    pub name: String,
    /// Type of the field.
    pub field_type: String,
    /// Value of the field.
    pub value: Value,
}

impl Field {
    /// Creates a new field.
    pub fn new(name: String, field_type: String, value: Value) -> Self {
        Self {
            name,
            field_type,
            value,
        }
    }
}

/// Dynamic value type that can hold any EIP-712 value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// String value.
    String(String),
    /// Number value.
    Number(u64),
    /// Bool value.
    Bool(bool),
    /// Bytes value.
    Bytes(Vec<u8>),
    /// Array value.
    Array(Vec<Value>),
    /// Object value.
    Object(HashMap<String, Value>),
    /// Null value.
    Null,
}

/// Domain is the domain of an EIP-712 message.
#[derive(Debug, Clone, PartialEq)]
pub struct Domain {
    /// Name of the domain.
    pub name: String,
    /// Version of the domain.
    pub version: String,
    /// Chain ID of the domain.
    pub chain_id: u64,
}

fn domain_to_type(domain: &Domain) -> Type {
    Type {
        name: "EIP712Domain".to_string(),
        fields: vec![
            Field::new(
                "name".to_string(),
                PRIMITIVE_STRING.to_string(),
                Value::String(domain.name.clone()),
            ),
            Field::new(
                "version".to_string(),
                PRIMITIVE_STRING.to_string(),
                Value::String(domain.version.clone()),
            ),
            Field::new(
                "chainId".to_string(),
                PRIMITIVE_UINT256.to_string(),
                Value::Number(domain.chain_id),
            ),
        ],
    }
}

type Result<T> = std::result::Result<T, Eip712Error>;

/// Eip712Error is the error type for EIP-712 errors.
#[derive(Debug, thiserror::Error)]
pub enum Eip712Error {
    /// Unsupported field type.
    #[error("unsupported field type: {field_type}")]
    UnsupportedFieldType {
        /// Field type that is not supported.
        field_type: String,
    },
}

/// Hashes the typed data.
pub fn hash_typed_data(data: &TypedData) -> Result<Vec<u8>> {
    let mut domain_type = domain_to_type(&data.domain);

    // TODO: temporary hack until api is updated then remove
    // Currently, api doesn't have chainId field in the domain for
    // eip712 termsAndConditions message. This will change in the future.
    if data.primary_type.name == TERMS_AND_CONDITION_TYPE_NAME {
        domain_type.fields.remove(2);
    }

    let domain_hash = hash_data(domain_type)?;
    let data_hash = hash_data(data.primary_type.clone())?;

    let mut raw_data = vec![0x19, 0x01];
    raw_data.extend_from_slice(&domain_hash);
    raw_data.extend_from_slice(&data_hash);

    keccak_hash(&raw_data)
}

fn hash_data(typ: Type) -> Result<Vec<u8>> {
    let mut buffer: Vec<u8> = Vec::new();

    buffer.extend(hash_type(&typ)?);
    for field in typ.fields {
        buffer.extend(encode_field(&field)?);
    }

    keccak_hash(&buffer)
}

fn encode_field(field: &Field) -> Result<Vec<u8>> {
    match (field.field_type.as_str(), &field.value) {
        (PRIMITIVE_STRING, Value::String(s)) => Ok(keccak_hash(s.as_bytes())?),
        (PRIMITIVE_UINT256, Value::Number(n)) => {
            let mut bytes = [0u8; 32];
            bytes[24..].copy_from_slice(&n.to_be_bytes());
            Ok(bytes.to_vec())
        }
        _ => Err(Eip712Error::UnsupportedFieldType {
            field_type: field.field_type.clone(),
        }),
    }
}

fn hash_type(typ: &Type) -> Result<Vec<u8>> {
    keccak_hash(&encode_type(typ))
}

fn encode_type(typ: &Type) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend(typ.name.as_bytes());
    buffer.push(b'(');

    for (i, field) in typ.fields.iter().enumerate() {
        if i != 0 {
            buffer.push(b',');
        }
        buffer.extend(field.field_type.as_bytes());
        buffer.push(b' ');
        buffer.extend(field.name.as_bytes());
    }

    buffer.push(b')');

    buffer
}

fn keccak_hash(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher: Keccak256 = Digest::new();
    hasher.update(data);
    let digest = hasher.finalize();
    Ok(digest.to_vec())
}

#[cfg(test)]
mod tests {
    use crate::network::SEPOLIA;

    use super::*;

    #[test]
    fn test_creator_hash() {
        // Obtained from legacy unit tests.
        let data = TypedData {
            domain: Domain {
                name: "Obol".to_string(),
                version: "1".to_string(),
                chain_id: SEPOLIA.chain_id, // Sepolia chain ID
            },
            primary_type: Type {
                name: "CreatorConfigHash".to_string(),
                fields: vec![Field::new(
                    "creator_config_hash".to_string(),
                    PRIMITIVE_STRING.to_string(),
                    Value::String(
                        "0xe57f66637bdfa05cce6a78e8cf4120d67d305b485367a69baa5f738436533bcb"
                            .to_string(),
                    ),
                )],
            },
        };

        let result = hash_typed_data(&data).expect("hash_typed_data failed");
        let result_hex = hex::encode(&result);

        assert_eq!(
            result_hex,
            "7c8fe012e2f872ca7ec870164184f57b921166f80565ff74af7bee5796f973e4"
        );
    }
}
