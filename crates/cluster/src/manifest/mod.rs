// Link to PR #4130: https://github.com/ObolNetwork/charon/pull/4130
// The manifest is removed and there is no use in production.

/// Cluster manifest management and coordination.
pub mod cluster;
/// Cluster manifest error types.
pub mod error;
/// Cluster manifest helpers management and coordination.
pub mod helpers;
/// Cluster manifest load management and coordination.
pub mod load;
/// Cluster manifest materialise management and coordination.
pub mod materialise;
/// Cluster manifest mutation add validator management and coordination.
pub mod mutationaddvalidator;
/// Cluster manifest mutation legacy lock management and coordination.
pub mod mutationlegacylock;
/// Cluster manifest mutation node approval management and coordination.
pub mod mutationnodeapproval;
/// Cluster manifest types management and coordination.
pub mod types;
