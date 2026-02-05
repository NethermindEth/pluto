//! Add validators mutation implementation.

use prost::Message as _;

use crate::{
    helpers::from_0x_hex_str,
    manifestpb::v1::{
        Cluster, Mutation, SignedMutation, SignedMutationList, Validator, ValidatorList,
    },
};

use super::{
    ManifestError, Result, extract_mutation,
    helpers::{HASH_LEN, verify_empty_sig},
    types::{self, MutationType},
};

/// Ethereum address length in bytes.
const ADDRESS_LEN: usize = 20;

impl ::prost::Name for ValidatorList {
    const NAME: &'static str = "ValidatorList";
    const PACKAGE: &'static str = "cluster.manifestpb.v1";

    fn type_url() -> ::prost::alloc::string::String {
        format!(
            "type.googleapis.com/{}",
            <Self as ::prost::Name>::full_name()
        )
    }
}

/// Creates a new gen validators mutation.
pub fn new_gen_validators(parent: &[u8], validators: Vec<Validator>) -> Result<SignedMutation> {
    verify_gen_validators_list(&validators)?;

    if parent.len() != HASH_LEN {
        return Err(ManifestError::InvalidMutation(
            "invalid parent hash".to_string(),
        ));
    }

    let vals_any = prost_types::Any::from_msg(&ValidatorList { validators })
        .map_err(|e| ManifestError::InvalidMutation(format!("marshal validators: {}", e)))?;

    Ok(SignedMutation {
        mutation: Some(Mutation {
            parent: parent.to_vec().into(),
            r#type: MutationType::GenValidators.as_str().to_string(),
            data: Some(vals_any),
        }),
        // No signer or signature
        signer: Default::default(),
        signature: Default::default(),
    })
}

/// Verifies a gen validators list, ensuring validators are populated with valid
/// addresses.
fn verify_gen_validators_list(vals: &[Validator]) -> Result<()> {
    if vals.is_empty() {
        return Err(ManifestError::InvalidMutation("no validators".to_string()));
    }

    for validator in vals {
        from_0x_hex_str(&validator.fee_recipient_address, ADDRESS_LEN).map_err(|e| {
            ManifestError::InvalidMutation(format!("validate fee recipient address: {}", e))
        })?;

        from_0x_hex_str(&validator.withdrawal_address, ADDRESS_LEN).map_err(|e| {
            ManifestError::InvalidMutation(format!("validate withdrawal address: {}", e))
        })?;
    }

    Ok(())
}

/// Transforms a cluster with a gen validators mutation.
/// NOTE: @iamquang95, should we mutate the cluster?
pub(crate) fn transform_gen_validators(
    cluster: &Cluster,
    signed: &SignedMutation,
) -> Result<Cluster> {
    verify_empty_sig(signed)?;

    let mutation = extract_mutation(signed, MutationType::GenValidators)?;

    let data = mutation
        .data
        .as_ref()
        .ok_or_else(|| ManifestError::InvalidMutation("data is nil".to_string()))?;

    let vals = ValidatorList::decode(&*data.value)
        .map_err(|e| ManifestError::InvalidMutation(format!("unmarshal validators: {}", e)))?;

    let mut result = cluster.clone();
    result.validators.extend(vals.validators);

    Ok(result)
}

/// Creates a new add validators composite mutation from the provided gen
/// validators and node approvals.
pub fn new_add_validators(
    gen_validators: &SignedMutation,
    node_approvals: &SignedMutation,
) -> Result<SignedMutation> {
    let gen_mutation = extract_mutation(gen_validators, MutationType::GenValidators)?;
    let _node_approvals_mutation = extract_mutation(node_approvals, MutationType::NodeApprovals)?;

    let data_any = prost_types::Any::from_msg(&SignedMutationList {
        mutations: vec![gen_validators.clone(), node_approvals.clone()],
    })
    .map_err(|e| ManifestError::InvalidMutation(format!("marshal signed mutation list: {}", e)))?;

    Ok(SignedMutation {
        mutation: Some(Mutation {
            parent: gen_mutation.parent.clone(),
            r#type: MutationType::AddValidators.as_str().to_string(),
            data: Some(data_any),
        }),
        // Composite mutations have no signer or signature
        signer: Default::default(),
        signature: Default::default(),
    })
}

/// Transforms a cluster with an add validators composite mutation.
pub(crate) fn transform_add_validators(
    cluster: &Cluster,
    signed: &SignedMutation,
) -> Result<Cluster> {
    verify_empty_sig(signed)?;

    let mutation = extract_mutation(signed, MutationType::AddValidators)?;

    let data = mutation
        .data
        .as_ref()
        .ok_or_else(|| ManifestError::InvalidMutation("data is nil".to_string()))?;

    let list = SignedMutationList::decode(&*data.value).map_err(|e| {
        ManifestError::InvalidMutation(format!("unmarshal signed mutation list: {}", e))
    })?;

    if list.mutations.len() != 2 {
        return Err(ManifestError::InvalidMutation(
            "invalid mutation list length".to_string(),
        ));
    }

    let gen_validators = &list.mutations[0];
    let node_approvals = &list.mutations[1];

    let gen_mutation = extract_mutation(gen_validators, MutationType::GenValidators)?;

    if mutation.parent != gen_mutation.parent {
        return Err(ManifestError::InvalidMutation(
            "invalid gen validators parent".to_string(),
        ));
    }

    let approvals_mutation = extract_mutation(node_approvals, MutationType::NodeApprovals)?;

    let gen_hash = types::hash(gen_validators)?;
    if gen_hash != approvals_mutation.parent.to_vec() {
        return Err(ManifestError::InvalidMutation(
            "invalid node approvals parent".to_string(),
        ));
    }

    let result = types::transform(cluster, gen_validators)?;

    let result = types::transform(&result, node_approvals)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_testutil::random::random_bytes32_seed;

    fn create_test_validator(idx: u8) -> Validator {
        Validator {
            public_key: vec![idx; 48].into(),
            pub_shares: vec![vec![idx; 48].into()],
            fee_recipient_address: format!("0x{}", "ab".repeat(20)),
            withdrawal_address: format!("0x{}", "cd".repeat(20)),
            builder_registration_json: vec![].into(),
        }
    }

    #[test]
    fn new_gen_validators_test() {
        let parent = random_bytes32_seed(1);
        let validators = vec![create_test_validator(1), create_test_validator(2)];

        let signed = new_gen_validators(&parent, validators.clone()).unwrap();

        assert!(signed.mutation.is_some());
        let mutation = signed.mutation.as_ref().unwrap();
        assert_eq!(mutation.r#type, MutationType::GenValidators.as_str());
        assert!(signed.signer.is_empty());
        assert!(signed.signature.is_empty());
    }

    #[test]
    fn new_gen_validators_empty() {
        let parent = random_bytes32_seed(2);
        let validators = vec![];

        let result = new_gen_validators(&parent, validators);
        assert!(matches!(
            result.unwrap_err(),
            ManifestError::InvalidMutation(_)
        ));
    }

    #[test]
    fn new_gen_validators_invalid_parent() {
        let parent = [0u8; 16]; // Invalid length
        let validators = vec![create_test_validator(1)];

        let result = new_gen_validators(&parent, validators);
        assert!(matches!(
            result.unwrap_err(),
            ManifestError::InvalidMutation(_)
        ));
    }

    #[test]
    fn transform_gen_validators_test() {
        let parent = random_bytes32_seed(3);
        let validators = vec![create_test_validator(1), create_test_validator(2)];

        let signed = new_gen_validators(&parent, validators.clone()).unwrap();

        let cluster = Cluster::default();
        let result = transform_gen_validators(&cluster, &signed).unwrap();

        assert_eq!(result.validators.len(), 2);
    }

    #[test]
    fn new_add_validators_invalid_gen_type() {
        // Create a mutation with wrong type
        let parent = random_bytes32_seed(4);
        let wrong_type = SignedMutation {
            mutation: Some(Mutation {
                parent: parent.clone().into(),
                r#type: MutationType::NodeApproval.as_str().to_string(),
                data: None,
            }),
            ..Default::default()
        };

        let node_approvals = SignedMutation {
            mutation: Some(Mutation {
                parent: parent.into(),
                r#type: MutationType::NodeApprovals.as_str().to_string(),
                data: None,
            }),
            ..Default::default()
        };

        let result = new_add_validators(&wrong_type, &node_approvals);
        assert!(matches!(
            result.unwrap_err(),
            ManifestError::InvalidMutation(_)
        ));
    }

    #[test]
    fn gen_validators() {
        use super::super::helpers::validator_to_proto;
        use crate::lock::Lock;
        use std::{fs, path::PathBuf};

        let lock_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/manifest/testdata")
            .join("lock.json");
        let lock_json = fs::read_to_string(&lock_path).unwrap();
        let lock: Lock = serde_json::from_str(&lock_json).unwrap();

        let mut vals = Vec::new();
        for (i, validator) in lock.distributed_validators.iter().enumerate() {
            let val = validator_to_proto(validator, &lock.validator_addresses[i]).unwrap();
            vals.push(val);
        }

        let parent =
            hex::decode("605ec6de4f1ae997dd3545513b934c335a833f4635dc9fad7758314f79ff0fae")
                .unwrap();

        let signed = new_gen_validators(&parent, vals.clone()).unwrap();

        let cluster = Cluster::default();
        let result = transform_gen_validators(&cluster, &signed).unwrap();
        assert_eq!(result.validators.len(), vals.len());
        for (i, val) in vals.iter().enumerate() {
            assert_eq!(result.validators[i].public_key, val.public_key);
            assert_eq!(
                result.validators[i].fee_recipient_address,
                val.fee_recipient_address
            );
        }
    }
}
