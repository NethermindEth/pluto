use crate::{definition::Definition, operator::Operator, version::V1_3};
use k256::SecretKey;
use pluto_eth2util::{
    eip712::{
        Domain, Field, PRIMITIVE_STRING, PRIMITIVE_UINT256, Primitive, Type, TypedData, Value,
        hash_typed_data,
    },
    network::fork_version_to_chain_id,
};

type ValueFunc = Box<dyn Fn(&Definition, &Operator) -> Value>;

type Result<T> = std::result::Result<T, EIP712Error>;

/// EIP712Error is the error type for EIP-712 errors.
#[derive(Debug, thiserror::Error)]
pub enum EIP712Error {
    /// Failed to convert fork version to chain ID.
    #[error("Network error: {0}")]
    NetworkError(#[from] pluto_eth2util::network::NetworkError),

    /// Failed to hash typed data.
    #[error("Failed to hash typed data: {0}")]
    FailedToHashTypedData(pluto_eth2util::eip712::Eip712Error),

    /// Failed to sign EIP-712.
    #[error("Failed to sign EIP-712: {0}")]
    FailedToSign(pluto_k1util::K1UtilError),
}

struct EIP712TypeField {
    pub field: &'static str,
    pub field_type: Primitive,
    pub value_func: ValueFunc,
}

/// EIP-712 primary type and fields descriptor.
pub(crate) struct EIP712Type {
    primary_type: &'static str,
    fields: Vec<EIP712TypeField>,
}

/// EIP-712 type for creator config hash signatures.
pub(crate) fn eip712_creator_config_hash() -> EIP712Type {
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

/// EIP-712 type for operator ENR signatures.
pub(crate) fn eip712_enr() -> EIP712Type {
    EIP712Type {
        primary_type: "ENR",
        fields: vec![EIP712TypeField {
            field: "enr",
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

/// Returns the latest or legacy operator eip712 type.
pub(crate) fn get_operator_eip712_type(version: &str) -> EIP712Type {
    if !Definition::support_eip712_sigs(version) {
        unreachable!("invalid eip712 signature version"); // This should never happen
    }

    if version == V1_3 {
        return eip712_v1x3_config_hash();
    }

    eip712_operator_config_hash()
}

/// Returns the digest for the EIP712 structured type for the provided
/// definition and operator.
pub(crate) fn digest_eip712(
    typ: &EIP712Type,
    definition: &Definition,
    operator: &Operator,
) -> Result<Vec<u8>> {
    let chain_id = fork_version_to_chain_id(definition.fork_version.as_ref())?;

    let fields = typ
        .fields
        .iter()
        .map(|f| Field {
            name: f.field.to_string(),
            field_type: f.field_type.to_string(),
            value: (f.value_func)(definition, operator),
        })
        .collect::<Vec<_>>();

    let data = TypedData {
        domain: Domain {
            name: "Obol".to_string(),
            version: "1".to_string(),
            chain_id,
        },
        primary_type: Type {
            name: typ.primary_type.to_string(),
            fields,
        },
    };

    let digest = hash_typed_data(&data).map_err(EIP712Error::FailedToHashTypedData)?;

    Ok(digest)
}

/// Returns the EIP712 signature for the primary type.
pub(crate) fn sign_eip712(
    secret_key: &SecretKey,
    typ: &EIP712Type,
    definition: &Definition,
    operator: &Operator,
) -> Result<Vec<u8>> {
    let digest = digest_eip712(typ, definition, operator)?;
    let signature = pluto_k1util::sign(secret_key, &digest).map_err(EIP712Error::FailedToSign)?;
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
    fn sign_terms_and_conditions_works() {
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
    fn sign_cluster_definition_hash_works() {
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

    #[test]
    fn enr_digest() {
        let definition = serde_json::from_str::<Definition>(include_str!(
            "examples/cluster-definition-000.json"
        ))
        .unwrap();
        let operator = Operator {
            address: "0x0000000000000000000000000000000000000000".to_string(),
            enr: "enr:-HW4QHs55nmxJqiyphaaBNPII5TZGp3e5tIl8MwPJ87wj2NhqE0KEz4rFuReJBVZ2Z8swz9qb5ef1ZytLtYzmOaMMfqGAYUvKC24gmlkgnY0iXNlY3AyNTZrMaECzR5RvaCMXL19XRHoqEHkpPeKdvdZmkLGm1gXgMzfKLQ".to_string(),
            config_signature: vec![],
            enr_signature: vec![],
        };

        let digest = digest_eip712(&eip712_enr(), &definition, &operator).unwrap();

        let expected_digest =
            hex::decode("0908e8f9d77b25586b1d63ae0be32f2e2d4fd0276c8aa1b38dd48eeac386b2b8")
                .unwrap();
        assert_eq!(
            digest, expected_digest,
            "ENR digest must match expected value (ensures field name is lowercase 'enr')"
        );
    }
}
