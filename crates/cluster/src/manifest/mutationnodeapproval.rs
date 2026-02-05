//! Node approval mutation implementation.

use k256::SecretKey;
use prost::Message as _;
use prost_types::Timestamp;

use crate::manifestpb::v1::{Cluster, Mutation, SignedMutation, SignedMutationList};

use super::{
    ManifestError, Result,
    cluster::cluster_peers,
    extract_mutation,
    helpers::{HASH_LEN, now, sign_k1, verify_k1_signed_mutation},
    types::{self, MutationType},
};

/// Type URL for google.protobuf.Timestamp.
const TIMESTAMP_TYPE_URL: &str = "type.googleapis.com/google.protobuf.Timestamp";

impl ::prost::Name for SignedMutationList {
    const NAME: &'static str = "SignedMutationList";
    const PACKAGE: &'static str = "cluster.manifestpb.v1";

    fn type_url() -> ::prost::alloc::string::String {
        format!(
            "type.googleapis.com/{}",
            <Self as ::prost::Name>::full_name()
        )
    }
}

/// Helper to encode a Timestamp to prost_types::Any.
fn timestamp_to_any(timestamp: &Timestamp) -> Result<prost_types::Any> {
    let mut value = Vec::new();
    timestamp
        .encode(&mut value)
        .map_err(|e| ManifestError::InvalidMutation(format!("encode timestamp: {}", e)))?;

    Ok(prost_types::Any {
        type_url: TIMESTAMP_TYPE_URL.to_string(),
        value,
    })
}

/// Signs a node approval mutation.
pub fn sign_node_approval(parent: &[u8], secret: &SecretKey) -> Result<SignedMutation> {
    let timestamp = now();

    let timestamp_any = timestamp_to_any(&timestamp)?;

    if parent.len() != HASH_LEN {
        return Err(ManifestError::InvalidMutation(
            "invalid parent hash".to_string(),
        ));
    }

    let mutation = Mutation {
        parent: parent.to_vec().into(),
        r#type: MutationType::NodeApproval.as_str().to_string(),
        data: Some(timestamp_any),
    };

    sign_k1(&mutation, secret)
}

/// Creates a new node approvals composite mutation.
///
/// Note the approvals must be for all nodes in the cluster ordered by peer
/// index.
pub fn new_node_approvals_composite(approvals: Vec<SignedMutation>) -> Result<SignedMutation> {
    if approvals.is_empty() {
        return Err(ManifestError::InvalidMutation(
            "empty node approvals".to_string(),
        ));
    }

    let first_mutation = approvals[0]
        .mutation
        .as_ref()
        .ok_or(ManifestError::InvalidSignedMutation)?;
    let parent = first_mutation.parent.to_vec();

    for approval in &approvals {
        let mutation = approval
            .mutation
            .as_ref()
            .ok_or(ManifestError::InvalidSignedMutation)?;

        if mutation.parent.to_vec() != parent {
            return Err(ManifestError::InvalidMutation(
                "mismatching node approvals parent".to_string(),
            ));
        }

        verify_node_approval(approval)?;
    }

    let any_list = prost_types::Any::from_msg(&SignedMutationList {
        mutations: approvals.clone(),
    })
    .map_err(|e| ManifestError::InvalidMutation(format!("mutations to any: {}", e)))?;

    Ok(SignedMutation {
        mutation: Some(Mutation {
            parent: parent.into(),
            r#type: MutationType::NodeApprovals.as_str().to_string(),
            data: Some(any_list),
        }),
        // Composite types do not have signatures
        signer: Default::default(),
        signature: Default::default(),
    })
}

/// Verifies a node approval mutation.
pub(crate) fn verify_node_approval(signed: &SignedMutation) -> Result<()> {
    let mutation = extract_mutation(signed, MutationType::NodeApproval)?;

    let data = mutation
        .data
        .as_ref()
        .ok_or_else(|| ManifestError::InvalidMutation("data is nil".to_string()))?;

    // Verify that the data is a valid timestamp
    let _timestamp = Timestamp::decode(&*data.value).map_err(|e| {
        ManifestError::InvalidMutation(format!("invalid node approval timestamp data: {}", e))
    })?;

    verify_k1_signed_mutation(signed)
}

/// Transforms a cluster with a node approvals composite mutation.
pub(crate) fn transform_node_approvals(
    cluster: &Cluster,
    signed: &SignedMutation,
) -> Result<Cluster> {
    let mutation = extract_mutation(signed, MutationType::NodeApprovals)?;

    let data = mutation
        .data
        .as_ref()
        .ok_or_else(|| ManifestError::InvalidMutation("data is nil".to_string()))?;

    let list = SignedMutationList::decode(&*data.value)
        .map_err(|_| ManifestError::InvalidMutation("invalid node approval data".to_string()))?;

    let peers = cluster_peers(cluster)?;

    if peers.len() != list.mutations.len() {
        return Err(ManifestError::InvalidMutation(
            "invalid number of node approvals".to_string(),
        ));
    }

    let parent = list
        .mutations
        .first()
        .and_then(|m| m.mutation.as_ref())
        .ok_or(ManifestError::InvalidSignedMutation)?
        .parent
        .as_ref();

    let mut result = cluster.clone();

    for (i, approval) in list.mutations.iter().enumerate() {
        let approval_mutation = approval
            .mutation
            .as_ref()
            .ok_or(ManifestError::InvalidSignedMutation)?;

        // Verify all mutations have the same parent
        if approval_mutation.parent.as_ref() != parent {
            return Err(ManifestError::InvalidMutation(
                "mismatching node approvals parent".to_string(),
            ));
        }

        let pubkey = peers[i]
            .public_key()
            .map_err(|e| ManifestError::P2p(format!("get peer public key: {}", e)))?;

        // Compare compressed public key with signer
        let expected_signer = pubkey.to_sec1_bytes();
        if expected_signer.as_ref() != approval.signer.as_ref() {
            return Err(ManifestError::InvalidMutation(
                "invalid node approval signer".to_string(),
            ));
        }

        result = types::transform(&result, approval)?;
    }

    Ok(result)
}

/// Signs a node approval with a custom timestamp (for testing).
#[cfg(test)]
pub fn sign_node_approval_with_timestamp(
    parent: &[u8],
    secret: &SecretKey,
    timestamp: Timestamp,
) -> Result<SignedMutation> {
    let timestamp_any = timestamp_to_any(&timestamp)?;

    if parent.len() != HASH_LEN {
        return Err(ManifestError::InvalidMutation(
            "invalid parent hash".to_string(),
        ));
    }

    let mutation = Mutation {
        parent: parent.to_vec().into(),
        r#type: MutationType::NodeApproval.as_str().to_string(),
        data: Some(timestamp_any),
    };

    sign_k1(&mutation, secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_testutil::random::generate_insecure_k1_key;

    #[test]
    fn test_sign_node_approval() {
        let secret = generate_insecure_k1_key(1);
        let parent = [0u8; 32];

        let signed = sign_node_approval(&parent, &secret).unwrap();

        assert!(signed.mutation.is_some());
        let mutation = signed.mutation.as_ref().unwrap();
        assert_eq!(mutation.r#type, MutationType::NodeApproval.as_str());
        assert!(!signed.signer.is_empty());
        assert!(!signed.signature.is_empty());

        // Verify the signature
        verify_node_approval(&signed).unwrap();
    }

    #[test]
    fn test_sign_node_approval_invalid_parent() {
        let secret = generate_insecure_k1_key(1);
        let parent = [0u8; 16]; // Invalid length

        let result = sign_node_approval(&parent, &secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_node_approvals_composite() {
        let parent = [0u8; 32];
        let mut approvals = Vec::new();

        for i in 0..3 {
            let secret = generate_insecure_k1_key(i);
            let approval = sign_node_approval(&parent, &secret).unwrap();
            approvals.push(approval);
        }

        let composite = new_node_approvals_composite(approvals).unwrap();

        assert!(composite.mutation.is_some());
        let mutation = composite.mutation.as_ref().unwrap();
        assert_eq!(mutation.r#type, MutationType::NodeApprovals.as_str());
        assert!(composite.signer.is_empty());
        assert!(composite.signature.is_empty());
    }

    #[test]
    fn test_new_node_approvals_composite_empty() {
        let result = new_node_approvals_composite(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_node_approvals_composite_mismatching_parent() {
        let secret1 = generate_insecure_k1_key(1);
        let secret2 = generate_insecure_k1_key(2);

        let approval1 = sign_node_approval(&[0u8; 32], &secret1).unwrap();
        let approval2 = sign_node_approval(&[1u8; 32], &secret2).unwrap();

        let result = new_node_approvals_composite(vec![approval1, approval2]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("mismatching node approvals parent")
        );
    }
}
