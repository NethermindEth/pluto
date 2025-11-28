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

/// Returns true if the given version matches any in the provided list of
/// versions.
pub fn is_any_version(version: &str, versions: &[&str]) -> bool {
    versions.contains(&version)
}

/// Returns true if the given version is v1.3.0.
pub fn is_v1x3(version: &str) -> bool {
    version == V1_3
}

/// Returns the supported definition versions (useful for tests).
pub fn supported_versions_for_test() -> Vec<&'static str> {
    SUPPORTED_VERSIONS.to_vec()
}

/// Returns true if pre-generated registrations are supported (versions v1.7 and
/// up).
pub fn support_pregen_registrations(version: &str) -> bool {
    !is_any_version(version, &[V1_0, V1_1, V1_2, V1_3, V1_4, V1_5, V1_6])
}

/// Returns true if node signatures are supported (versions v1.7 and up).
pub fn support_node_signatures(version: &str) -> bool {
    !is_any_version(version, &[V1_0, V1_1, V1_2, V1_3, V1_4, V1_5, V1_6])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_any_version() {
        assert!(is_any_version("v1.5.0", &[V1_5, V1_1]));
        assert!(!is_any_version("v1.10.0", &[V1_0, V1_3]));
    }

    #[test]
    fn test_is_v1x3() {
        assert!(is_v1x3("v1.3.0"));
        assert!(!is_v1x3("v1.2.0"));
    }

    #[test]
    fn test_supported_versions_for_test() {
        let versions = supported_versions_for_test();
        assert!(versions.contains(&V1_0));
        assert!(versions.contains(&V1_10));
        assert_eq!(versions.len(), 11);
    }

    #[test]
    fn test_support_pregen_registrations() {
        assert!(!support_pregen_registrations("v1.0.0"));
        assert!(!support_pregen_registrations("v1.3.0"));
        assert!(support_pregen_registrations("v1.7.0"));
        assert!(support_pregen_registrations("v1.10.0"));
    }

    #[test]
    fn test_support_node_signatures() {
        assert!(!support_node_signatures("v1.0.0"));
        assert!(support_node_signatures("v1.7.0"));
    }
}
