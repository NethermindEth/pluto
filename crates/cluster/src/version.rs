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

/// Returns true if the provided cluster definition version supports
/// pre-generated builder registrations.
#[must_use]
pub fn support_pregen_registrations(version: &str) -> bool {
    !matches!(version, V1_0 | V1_1 | V1_2 | V1_3 | V1_4 | V1_5 | V1_6)
}

/// Returns true if the provided cluster definition version supports partial
/// deposits.
#[must_use]
pub fn support_partial_deposits(version: &str) -> bool {
    !matches!(version, V1_0 | V1_1 | V1_2 | V1_3 | V1_4 | V1_5 | V1_6 | V1_7)
}

/// Returns true if the provided cluster lock version supports node signatures.
#[must_use]
pub fn support_node_signatures(version: &str) -> bool {
    !matches!(version, V1_0 | V1_1 | V1_2 | V1_3 | V1_4 | V1_5 | V1_6)
}

#[cfg(test)]
mod tests {
    use super::{
        V1_0, V1_1, V1_2, V1_3, V1_4, V1_5, V1_6, V1_7, V1_8, V1_9, V1_10,
        support_node_signatures, support_partial_deposits, support_pregen_registrations,
    };
    use test_case::test_case;

    #[test_case(V1_0, false; "v1.0.0")]
    #[test_case(V1_1, false; "v1.1.0")]
    #[test_case(V1_2, false; "v1.2.0")]
    #[test_case(V1_3, false; "v1.3.0")]
    #[test_case(V1_4, false; "v1.4.0")]
    #[test_case(V1_5, false; "v1.5.0")]
    #[test_case(V1_6, false; "v1.6.0")]
    #[test_case(V1_7, true; "v1.7.0")]
    #[test_case(V1_8, true; "v1.8.0")]
    #[test_case(V1_9, true; "v1.9.0")]
    #[test_case(V1_10, true; "v1.10.0")]
    #[test_case("invalid", true; "unknown version")]
    fn support_pregen_registrations_by_version(version: &str, expected: bool) {
        assert_eq!(support_pregen_registrations(version), expected);
    }

    #[test_case(V1_0, false; "v1.0.0")]
    #[test_case(V1_1, false; "v1.1.0")]
    #[test_case(V1_2, false; "v1.2.0")]
    #[test_case(V1_3, false; "v1.3.0")]
    #[test_case(V1_4, false; "v1.4.0")]
    #[test_case(V1_5, false; "v1.5.0")]
    #[test_case(V1_6, false; "v1.6.0")]
    #[test_case(V1_7, true; "v1.7.0")]
    #[test_case(V1_8, true; "v1.8.0")]
    #[test_case(V1_9, true; "v1.9.0")]
    #[test_case(V1_10, true; "v1.10.0")]
    #[test_case("invalid", true; "unknown version")]
    fn support_node_signatures_by_version(version: &str, expected: bool) {
        assert_eq!(support_node_signatures(version), expected);
    }

    #[test_case(V1_0, false; "v1.0.0")]
    #[test_case(V1_1, false; "v1.1.0")]
    #[test_case(V1_2, false; "v1.2.0")]
    #[test_case(V1_3, false; "v1.3.0")]
    #[test_case(V1_4, false; "v1.4.0")]
    #[test_case(V1_5, false; "v1.5.0")]
    #[test_case(V1_6, false; "v1.6.0")]
    #[test_case(V1_7, false; "v1.7.0")]
    #[test_case(V1_8, true; "v1.8.0")]
    #[test_case(V1_9, true; "v1.9.0")]
    #[test_case(V1_10, true; "v1.10.0")]
    #[test_case("invalid", true; "unknown version")]
    fn support_partial_deposits_by_version(version: &str, expected: bool) {
        assert_eq!(support_partial_deposits(version), expected);
    }
}
