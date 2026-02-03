//! Cluster manifest mutation types.

use crate::manifestpb::v1::{Cluster, SignedMutation};

use super::{ManifestError, Result};

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
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dv/legacy_lock/v0.0.1" => Some(Self::LegacyLock),
            "dv/node_approval/v0.0.1" => Some(Self::NodeApproval),
            "dv/node_approvals/v0.0.1" => Some(Self::NodeApprovals),
            "dv/gen_validators/v0.0.1" => Some(Self::GenValidators),
            "dv/add_validators/v0.0.1" => Some(Self::AddValidators),
            _ => None,
        }
    }

    /// Returns true if the mutation type is valid.
    /// TODO: @iamquang95 remove this if no need
    pub fn valid(&self) -> bool {
        true
    }

    /// Transforms the cluster with the given signed mutation.
    pub fn transform(
        &self,
        _cluster: &Cluster,
        _signed: &SignedMutation,
    ) -> Result<Cluster> {
        unimplemented!("MutationType::transform")
    }
}

/// Calculates the hash of a signed mutation.
pub fn hash(_signed: &SignedMutation) -> Result<Vec<u8>> {
    unimplemented!("hash")
}

/// Transforms a cluster with a signed mutation.
pub fn transform(_cluster: &Cluster, _signed: &SignedMutation) -> Result<Cluster> {
    unimplemented!("transform")
}
