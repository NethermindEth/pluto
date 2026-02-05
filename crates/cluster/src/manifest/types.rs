use prost::Message as _;

use crate::{
    lock::Lock,
    manifestpb::v1::{Cluster, LegacyLock, SignedMutation},
};

use super::{
    error::{ManifestError, Result},
    helpers::{HASH_LEN, hash_signed_mutation},
    mutationaddvalidator::{transform_add_validators, transform_gen_validators},
    mutationlegacylock::transform_legacy_lock,
    mutationnodeapproval::{transform_node_approvals, verify_node_approval},
};

/// Mutation type enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationType {
    /// Legacy lock mutation type.
    LegacyLock,
    /// Node approval mutation type.
    NodeApproval,
    /// Node approvals composite mutation type.
    NodeApprovals,
    /// Generate validators mutation type.
    GenValidators,
    /// Add validators composite mutation type.
    AddValidators,
}

impl MutationType {
    /// Returns the string representation of the mutation type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LegacyLock => "dv/legacy_lock/v0.0.1",
            Self::NodeApproval => "dv/node_approval/v0.0.1",
            Self::NodeApprovals => "dv/node_approvals/v0.0.1",
            Self::GenValidators => "dv/gen_validators/v0.0.1",
            Self::AddValidators => "dv/add_validators/v0.0.1",
        }
    }

    /// Parses a mutation type from a string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "dv/legacy_lock/v0.0.1" => Some(Self::LegacyLock),
            "dv/node_approval/v0.0.1" => Some(Self::NodeApproval),
            "dv/node_approvals/v0.0.1" => Some(Self::NodeApprovals),
            "dv/gen_validators/v0.0.1" => Some(Self::GenValidators),
            "dv/add_validators/v0.0.1" => Some(Self::AddValidators),
            _ => None,
        }
    }

    /// Transforms the cluster with the given signed mutation.
    pub fn transform(&self, cluster: &Cluster, signed: &SignedMutation) -> Result<Cluster> {
        match self {
            Self::LegacyLock => transform_legacy_lock(cluster, signed),
            Self::NodeApproval => {
                verify_node_approval(signed)?;
                Ok(cluster.clone())
            }
            Self::NodeApprovals => transform_node_approvals(cluster, signed),
            Self::GenValidators => transform_gen_validators(cluster, signed),
            Self::AddValidators => transform_add_validators(cluster, signed),
        }
    }
}

impl SignedMutation {
    /// Calculates the hash of this signed mutation.
    pub fn hash(&self) -> Result<Vec<u8>> {
        let mutation = self
            .mutation
            .as_ref()
            .ok_or(ManifestError::InvalidSignedMutation)?;

        // Special case for legacy lock: return the lock hash
        if mutation.r#type == MutationType::LegacyLock.as_str() {
            let data = mutation
                .data
                .as_ref()
                .ok_or_else(|| ManifestError::InvalidMutation("data is nil".to_string()))?;

            let legacy_lock =
                LegacyLock::decode(&*data.value).map_err(ManifestError::ProtobufDecode)?;

            let lock: Lock =
                serde_json::from_slice(&legacy_lock.json).map_err(ManifestError::Json)?;

            if lock.lock_hash.len() != HASH_LEN {
                return Err(ManifestError::InvalidLockHash);
            }

            return Ok(lock.lock_hash);
        }

        // Otherwise, return the hash of the signed mutation
        hash_signed_mutation(self)
    }

    /// Transforms a cluster with this signed mutation.
    pub fn transform(&self, cluster: &Cluster) -> Result<Cluster> {
        let mutation = self
            .mutation
            .as_ref()
            .ok_or(ManifestError::InvalidSignedMutation)?;

        let typ = MutationType::parse(&mutation.r#type)
            .ok_or_else(|| ManifestError::InvalidMutationType(mutation.r#type.clone()))?;

        typ.transform(cluster, self)
    }
}
