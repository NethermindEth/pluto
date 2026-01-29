// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business
// Source License 1.1

/// List of supported cluster definition versions.
pub mod versions {
    /// Version v1.10.0 (Default)
    pub const V1_10: &str = "v1.10.0"; // Default
    /// Version v1.9.0
    pub const V1_9: &str = "v1.9.0";
    /// Version v1.8.0
    pub const V1_8: &str = "v1.8.0";
    /// Version v1.7.0
    pub const V1_7: &str = "v1.7.0";
    /// Version v1.6.0
    pub const V1_6: &str = "v1.6.0";
    /// Version v1.5.0
    pub const V1_5: &str = "v1.5.0";
    /// Version v1.4.0
    pub const V1_4: &str = "v1.4.0";
    /// Version v1.3.0
    pub const V1_3: &str = "v1.3.0";
    /// Version v1.2.0
    pub const V1_2: &str = "v1.2.0";
    /// Version v1.1.0
    pub const V1_1: &str = "v1.1.0";
    /// Version v1.0.0
    pub const V1_0: &str = "v1.0.0";
}

pub use versions::*;

/// The current version of the charon cluster definition format.
pub const CURRENT_VERSION: &str = V1_10;
/// Default DKG algorithm.
pub const DKG_ALGO: &str = "default";
/// Zero Nonce
pub const ZERO_NONCE: u64 = 0;
/// Min version required for partial deposits.
pub const MIN_VERSION_FOR_PARTIAL_DEPOSITS: &str = V1_8;

/// List of all supported version constants.
pub const SUPPORTED_VERSIONS: [&str; 11] = [
    V1_10, V1_9, V1_8, V1_7, V1_6, V1_5, V1_4, V1_3, V1_2, V1_1, V1_0,
];
