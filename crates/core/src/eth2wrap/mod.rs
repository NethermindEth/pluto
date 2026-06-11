//! Wrappers around the upstream beacon-node client.
//!
//! Mirrors Charon's `app/eth2wrap` package: a layer that decorates the
//! raw beacon-node API with cluster-wide concerns (caching, error
//! mapping). Lives in `pluto-core` so downstream modules (e.g. the
//! validator API [`crate::validatorapi`]) can consume the wrappers
//! without depending on `pluto-app`.

/// Cache of validators retrieved from the Beacon node.
pub mod valcache;
