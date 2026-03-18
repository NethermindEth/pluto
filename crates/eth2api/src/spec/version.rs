use core::fmt;

use serde::{Deserialize, Serialize};

/// Error returned when converting unknown data or builder versions.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum VersionError {
    /// Unknown data version.
    #[error("unknown data version")]
    UnknownDataVersion,
    /// Unknown builder version.
    #[error("unknown builder version")]
    UnknownBuilderVersion,
}

/// Consensus data version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataVersion {
    /// Unknown data version.
    #[default]
    Unknown,
    /// Phase0 data version.
    Phase0,
    /// Altair data version.
    Altair,
    /// Bellatrix data version.
    Bellatrix,
    /// Capella data version.
    Capella,
    /// Deneb data version.
    Deneb,
    /// Electra data version.
    Electra,
    /// Fulu data version.
    Fulu,
}

impl DataVersion {
    /// Returns a lowercase string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            DataVersion::Unknown => "unknown",
            DataVersion::Phase0 => "phase0",
            DataVersion::Altair => "altair",
            DataVersion::Bellatrix => "bellatrix",
            DataVersion::Capella => "capella",
            DataVersion::Deneb => "deneb",
            DataVersion::Electra => "electra",
            DataVersion::Fulu => "fulu",
        }
    }

    /// Returns the legacy pre-v0.18 numeric representation (phase0=0..).
    pub const fn to_legacy_u64(self) -> Result<u64, VersionError> {
        match self {
            DataVersion::Phase0 => Ok(0),
            DataVersion::Altair => Ok(1),
            DataVersion::Bellatrix => Ok(2),
            DataVersion::Capella => Ok(3),
            DataVersion::Deneb => Ok(4),
            DataVersion::Electra => Ok(5),
            DataVersion::Fulu => Ok(6),
            DataVersion::Unknown => Err(VersionError::UnknownDataVersion),
        }
    }

    /// Converts a legacy pre-v0.18 numeric value to an ETH2 data version.
    pub const fn from_legacy_u64(value: u64) -> Result<Self, VersionError> {
        match value {
            0 => Ok(DataVersion::Phase0),
            1 => Ok(DataVersion::Altair),
            2 => Ok(DataVersion::Bellatrix),
            3 => Ok(DataVersion::Capella),
            4 => Ok(DataVersion::Deneb),
            5 => Ok(DataVersion::Electra),
            6 => Ok(DataVersion::Fulu),
            _ => Err(VersionError::UnknownDataVersion),
        }
    }
}

impl fmt::Display for DataVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Builder API version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuilderVersion {
    /// Unknown builder version.
    #[default]
    Unknown,
    /// V1 builder version.
    V1,
}

impl BuilderVersion {
    /// Returns a lowercase string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            BuilderVersion::Unknown => "unknown",
            BuilderVersion::V1 => "v1",
        }
    }

    /// Returns the legacy pre-v0.18 numeric representation (v1=0).
    pub const fn to_legacy_u64(self) -> Result<u64, VersionError> {
        match self {
            BuilderVersion::V1 => Ok(0),
            BuilderVersion::Unknown => Err(VersionError::UnknownBuilderVersion),
        }
    }

    /// Converts a legacy pre-v0.18 numeric value to an ETH2 builder version.
    pub const fn from_legacy_u64(value: u64) -> Result<Self, VersionError> {
        match value {
            0 => Ok(BuilderVersion::V1),
            _ => Err(VersionError::UnknownBuilderVersion),
        }
    }
}

impl fmt::Display for BuilderVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Serde helpers for legacy numeric data-version encoding used by signeddata
/// wrappers.
pub mod serde_legacy_data_version {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::DataVersion;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Legacy(u64),
        Spec(DataVersion),
    }

    /// Serializes a data version as the legacy numeric encoding.
    pub fn serialize<S>(version: &DataVersion, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: u64 = version.to_legacy_u64().map_err(serde::ser::Error::custom)?;
        serializer.serialize_u64(encoded)
    }

    /// Deserializes either the legacy numeric encoding or the canonical spec
    /// string encoding.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<DataVersion, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Repr::deserialize(deserializer)? {
            Repr::Legacy(value) => {
                DataVersion::from_legacy_u64(value).map_err(serde::de::Error::custom)
            }
            Repr::Spec(version) => Ok(version),
        }
    }
}

/// Serde helpers for legacy numeric builder-version encoding used by signeddata
/// wrappers.
pub mod serde_legacy_builder_version {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::BuilderVersion;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Legacy(u64),
        Spec(BuilderVersion),
    }

    /// Serializes a builder version as the legacy numeric encoding.
    pub fn serialize<S>(version: &BuilderVersion, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = version.to_legacy_u64().map_err(serde::ser::Error::custom)?;
        serializer.serialize_u64(encoded)
    }

    /// Deserializes either the legacy numeric encoding or the canonical spec
    /// string encoding.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<BuilderVersion, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Repr::deserialize(deserializer)? {
            Repr::Legacy(value) => {
                BuilderVersion::from_legacy_u64(value).map_err(serde::de::Error::custom)
            }
            Repr::Spec(version) => Ok(version),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use test_case::test_case;

    fn assert_conversion_result<T, E>(
        actual: Result<T, E>,
        expected: Option<T>,
        expected_err: Option<E>,
    ) where
        T: PartialEq + core::fmt::Debug,
        E: PartialEq + core::fmt::Debug,
    {
        match (actual, expected, expected_err) {
            (Ok(actual), Some(expected), None) => assert_eq!(actual, expected),
            (Err(err), None, Some(expected_err)) => {
                assert!(matches!(err, actual if actual == expected_err))
            }
            _ => panic!("unexpected conversion result"),
        }
    }

    fn assert_spec_string_serde<T>(value: T, expected_json: &str)
    where
        T: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug,
    {
        assert_eq!(
            serde_json::to_string(&value).expect("serialize version"),
            expected_json
        );
        assert_eq!(
            serde_json::from_str::<T>(expected_json).expect("deserialize version"),
            value
        );
    }

    fn assert_invalid_spec_string<T>(invalid_json: &str)
    where
        T: DeserializeOwned + core::fmt::Debug,
    {
        assert!(matches!(
            serde_json::from_str::<T>(invalid_json),
            Err(err) if err.classify() == serde_json::error::Category::Data
        ));
    }

    fn assert_legacy_wrapper_deserializes<T>(legacy_json: &str, spec_json: &str, expected: T)
    where
        T: DeserializeOwned + PartialEq + core::fmt::Debug + Clone,
    {
        assert_eq!(
            serde_json::from_str::<T>(legacy_json).expect("deserialize legacy"),
            expected.clone()
        );
        assert_eq!(
            serde_json::from_str::<T>(spec_json).expect("deserialize spec"),
            expected
        );
    }

    fn assert_legacy_wrapper_serializes<T>(value: &T, expected_json: &str)
    where
        T: Serialize,
    {
        let json = serde_json::to_string(value).expect("serialize wrapper");
        assert_eq!(json, expected_json);
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct DataVersionWrapper {
        #[serde(with = "crate::spec::serde_legacy_data_version")]
        version: DataVersion,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct BuilderVersionWrapper {
        #[serde(with = "crate::spec::serde_legacy_builder_version")]
        version: BuilderVersion,
    }

    #[test_case(DataVersion::Phase0, "\"phase0\"" ; "phase0")]
    #[test_case(DataVersion::Deneb, "\"deneb\"" ; "deneb")]
    #[test_case(DataVersion::Fulu, "\"fulu\"" ; "fulu")]
    fn data_version_serde_uses_spec_strings(version: DataVersion, expected_json: &str) {
        assert_spec_string_serde(version, expected_json);
    }

    #[test]
    fn data_version_serde_rejects_unknown_spec_string() {
        assert_invalid_spec_string::<DataVersion>("\"unknown-fork\"");
    }

    #[test]
    fn builder_version_serde_uses_spec_strings() {
        assert_spec_string_serde(BuilderVersion::V1, "\"v1\"");
    }

    #[test]
    fn builder_version_serde_rejects_unknown_spec_string() {
        assert_invalid_spec_string::<BuilderVersion>("\"v2\"");
    }

    #[test_case(DataVersion::Unknown, None, Some(VersionError::UnknownDataVersion); "unknown")]
    #[test_case(DataVersion::Phase0, Some(0), None; "phase0")]
    #[test_case(DataVersion::Altair, Some(1), None; "altair")]
    #[test_case(DataVersion::Bellatrix, Some(2), None; "bellatrix")]
    #[test_case(DataVersion::Capella, Some(3), None; "capella")]
    #[test_case(DataVersion::Deneb, Some(4), None; "deneb")]
    #[test_case(DataVersion::Electra, Some(5), None; "electra")]
    #[test_case(DataVersion::Fulu, Some(6), None; "fulu")]
    fn data_version_to_legacy(
        version: DataVersion,
        expected: Option<u64>,
        expected_err: Option<VersionError>,
    ) {
        assert_conversion_result(version.to_legacy_u64(), expected, expected_err);
    }

    #[test_case(99, None, Some(VersionError::UnknownDataVersion); "unknown")]
    #[test_case(0, Some(DataVersion::Phase0), None; "phase0")]
    #[test_case(1, Some(DataVersion::Altair), None; "altair")]
    #[test_case(2, Some(DataVersion::Bellatrix), None; "bellatrix")]
    #[test_case(3, Some(DataVersion::Capella), None; "capella")]
    #[test_case(4, Some(DataVersion::Deneb), None; "deneb")]
    #[test_case(5, Some(DataVersion::Electra), None; "electra")]
    #[test_case(6, Some(DataVersion::Fulu), None; "fulu")]
    fn data_version_from_legacy(
        value: u64,
        expected: Option<DataVersion>,
        expected_err: Option<VersionError>,
    ) {
        assert_conversion_result(DataVersion::from_legacy_u64(value), expected, expected_err);
    }

    #[test]
    fn data_version_legacy_serde_accepts_both_forms() {
        assert_legacy_wrapper_deserializes(
            "{\"version\":6}",
            "{\"version\":\"fulu\"}",
            DataVersionWrapper {
                version: DataVersion::Fulu,
            },
        );
    }

    #[test]
    fn data_version_legacy_serde_serializes_numeric() {
        assert_legacy_wrapper_serializes(
            &DataVersionWrapper {
                version: DataVersion::Electra,
            },
            "{\"version\":5}",
        );
    }

    #[test_case(BuilderVersion::Unknown, None, Some(VersionError::UnknownBuilderVersion); "unknown")]
    #[test_case(BuilderVersion::V1, Some(0), None; "v1")]
    fn builder_version_to_legacy(
        version: BuilderVersion,
        expected: Option<u64>,
        expected_err: Option<VersionError>,
    ) {
        assert_conversion_result(version.to_legacy_u64(), expected, expected_err);
    }

    #[test_case(99, None, Some(VersionError::UnknownBuilderVersion); "unknown")]
    #[test_case(0, Some(BuilderVersion::V1), None; "v1")]
    fn builder_version_from_legacy(
        value: u64,
        expected: Option<BuilderVersion>,
        expected_err: Option<VersionError>,
    ) {
        assert_conversion_result(
            BuilderVersion::from_legacy_u64(value),
            expected,
            expected_err,
        );
    }

    #[test]
    fn builder_version_legacy_serde_accepts_both_forms() {
        assert_legacy_wrapper_deserializes(
            "{\"version\":0}",
            "{\"version\":\"v1\"}",
            BuilderVersionWrapper {
                version: BuilderVersion::V1,
            },
        );
    }

    #[test]
    fn builder_version_legacy_serde_serializes_numeric() {
        assert_legacy_wrapper_serializes(
            &BuilderVersionWrapper {
                version: BuilderVersion::V1,
            },
            "{\"version\":0}",
        );
    }
}
