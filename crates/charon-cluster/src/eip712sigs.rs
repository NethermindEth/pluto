use crate::{definition::Definition, operator::Operator, version::V1_3};
use charon_eth2::{
    eip712::{
        Domain, Field, PRIMITIVE_STRING, PRIMITIVE_UINT256, Primitive, Type, TypedData, Value,
        hash_typed_data,
    },
    network::fork_version_to_chain_id,
};
use charon_k1util::{self as k1util, K1UtilError};
use k256::SecretKey;

type ValueFunc = Box<dyn Fn(&Definition, &Operator) -> Value>;

type Result<T> = std::result::Result<T, EIP712Error>;

/// EIP712Error is the error type for EIP-712 errors.
#[derive(Debug, thiserror::Error)]
pub enum EIP712Error {
    /// Failed to convert fork version to chain ID.
    #[error("Network error: {0}")]
    NetworkError(#[from] charon_eth2::network::NetworkError),

    /// Failed to hash typed data.
    #[error("Failed to hash typed data: {0}")]
    FailedToHashTypedData(charon_eth2::eip712::Eip712Error),

    /// Failed to sign EIP-712.
    #[error("Failed to sign EIP-712: {0}")]
    FailedToSign(K1UtilError),
}

struct EIP712TypeField {
    pub field: &'static str,
    pub field_type: Primitive,
    pub value_func: ValueFunc,
}

struct EIP712Type {
    pub primary_type: &'static str,
    pub fields: Vec<EIP712TypeField>,
}

fn eip712_creator_config_hash() -> EIP712Type {
    EIP712Type {
        primary_type: "CreatorConfigHash",
        fields: vec![EIP712TypeField {
            field: "creator_config_hash",
            field_type: PRIMITIVE_STRING.to_string(),
            value_func: Box::new(|definition, _| {
                Value::String(format!("0x{}", hex::encode(&definition.config_hash)))
            }),
        }],
    }
}

fn eip712_operator_config_hash() -> EIP712Type {
    EIP712Type {
        primary_type: "OperatorConfigHash",
        fields: vec![EIP712TypeField {
            field: "operator_config_hash",
            field_type: PRIMITIVE_STRING.to_string(),
            value_func: Box::new(|definition, _| {
                Value::String(format!("0x{}", hex::encode(&definition.config_hash)))
            }),
        }],
    }
}

fn eip712_v1x3_config_hash() -> EIP712Type {
    EIP712Type {
        primary_type: "ConfigHash",
        fields: vec![EIP712TypeField {
            field: "config_hash",
            field_type: PRIMITIVE_STRING.to_string(),
            value_func: Box::new(|definition, _| {
                Value::String(format!("0x{}", hex::encode(&definition.config_hash)))
            }),
        }],
    }
}

#[allow(dead_code)] // todo: remove this once it's used
fn eip712_enr() -> EIP712Type {
    EIP712Type {
        primary_type: "ENR",
        fields: vec![EIP712TypeField {
            field: "ENR",
            field_type: PRIMITIVE_STRING.to_string(),
            value_func: Box::new(|_, operator| Value::String(operator.enr.clone())),
        }],
    }
}

fn eip712_terms_and_conditions() -> EIP712Type {
    EIP712Type {
        primary_type: "TermsAndConditions",
        fields: vec![
            EIP712TypeField {
                field: "terms_and_conditions_hash",
                field_type: PRIMITIVE_STRING.to_string(),
                value_func: Box::new(|_, _| {
                    Value::String(
                        "0xd33721644e8f3afab1495a74abe3523cec12d48b8da6cb760972492ca3f1a273"
                            .to_string(),
                    )
                }),
            },
            EIP712TypeField {
                field: "version",
                field_type: PRIMITIVE_UINT256.to_string(),
                value_func: Box::new(|_, _| Value::Number(1)),
            },
        ],
    }
}

#[allow(dead_code)] // todo: remove this once it's used
fn get_operator_eip712_type(version: &str) -> EIP712Type {
    if !Definition::support_eip712_sigs(version) {
        unreachable!("invalid eip712 signature version"); // This should never happen
    }

    if version == V1_3 {
        return eip712_v1x3_config_hash();
    }

    eip712_operator_config_hash()
}

fn digest_eip712(
    typ: &EIP712Type,
    definition: &Definition,
    operator: &Operator,
) -> Result<Vec<u8>> {
    let chain_id = fork_version_to_chain_id(definition.fork_version.as_ref())?;

    let mut data = TypedData {
        domain: Domain {
            name: "Obol".to_string(),
            version: "1".to_string(),
            chain_id,
        },
        primary_type: Type {
            name: typ.primary_type.to_string(),
            fields: vec![],
        },
    };

    for field in typ.fields.iter() {
        data.primary_type.fields.push(Field {
            name: field.field.to_string(),
            field_type: field.field_type.to_string(),
            value: (field.value_func)(definition, operator),
        });
    }

    let digest = hash_typed_data(&data).map_err(EIP712Error::FailedToHashTypedData)?;

    Ok(digest)
}

fn sign_eip712(
    secret_key: &SecretKey,
    typ: &EIP712Type,
    definition: &Definition,
    operator: &Operator,
) -> Result<Vec<u8>> {
    let digest = digest_eip712(typ, definition, operator)?;
    let signature = k1util::sign(secret_key, &digest).map_err(EIP712Error::FailedToSign)?;
    Ok(signature.to_vec())
}

/// sign_terms_and_conditions returns the EIP712 signature for Obol's Terms and
/// Conditions
pub fn sign_terms_and_conditions(
    secret_key: &SecretKey,
    definition: &Definition,
) -> Result<Vec<u8>> {
    sign_eip712(
        secret_key,
        &eip712_terms_and_conditions(),
        definition,
        &Operator::default(),
    )
}

/// sign_cluster_definition_hash returns the EIP712 signature for the cluster
/// definition hash
pub fn sign_cluster_definition_hash(
    secret_key: &SecretKey,
    definition: &Definition,
) -> Result<Vec<u8>> {
    sign_eip712(
        secret_key,
        &eip712_creator_config_hash(),
        definition,
        &Operator::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_terms_and_conditions() {
        let secret_key = SecretKey::from_slice(
            &hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
        )
        .unwrap();
        let definition = serde_json::from_str::<Definition>(include_str!(
            "examples/cluster-definition-000.json"
        ))
        .unwrap();
        let signature = sign_terms_and_conditions(&secret_key, &definition).unwrap();
        let expected_signature = hex::decode("4723ae21ae1d47cb76afc58177b40d1bf1b010147eec3eafedf467ad641290776c64336df8d3643eb637681b2d6429066f88877f987476a81ddf417603d74d0700").unwrap();
        assert_eq!(signature, expected_signature);
    }

    #[test]
    fn test_sign_cluster_definition_hash() {
        let secret_key = SecretKey::from_slice(
            &hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
        )
        .unwrap();
        let definition = serde_json::from_str::<Definition>(include_str!(
            "examples/cluster-definition-000.json"
        ))
        .unwrap();
        let signature = sign_cluster_definition_hash(&secret_key, &definition).unwrap();
        let expected_signature = hex::decode("4d06378b88544748d27e656871fefdb258329ecbbecf2316cb03b3da1d499a2137fc8f1caddcaf47a8fd17a22d8f68c9333b21a031fd281c1e6e99623c1bd7f301").unwrap();
        assert_eq!(signature, expected_signature);
    }
}
