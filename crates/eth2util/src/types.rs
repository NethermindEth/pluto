use core::fmt;

use pluto_eth2api::spec::{
    BuilderVersion as Eth2BuilderVersion, DataVersion as Eth2DataVersion, phase0,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use tree_hash_derive::TreeHash;

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

/// The spec version of the data in a response.
/// The number values match those of go-eth2-client v0.17 and earlier releases.
///
/// We should maybe migrate to serialising as strings to aligned with eth2 spec at which
/// point this type can be removed in favour of the go-eth2-client type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
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
            Self::Unknown => "unknown",
            Self::Phase0 => "phase0",
            Self::Altair => "altair",
            Self::Bellatrix => "bellatrix",
            Self::Capella => "capella",
            Self::Deneb => "deneb",
            Self::Electra => "electra",
            Self::Fulu => "fulu",
        }
    }

    /// Returns the eth2 spec equivalent to this data version.
    pub const fn to_eth2(self) -> Eth2DataVersion {
        match self {
            Self::Phase0 => Eth2DataVersion::Phase0,
            Self::Altair => Eth2DataVersion::Altair,
            Self::Bellatrix => Eth2DataVersion::Bellatrix,
            Self::Capella => Eth2DataVersion::Capella,
            Self::Deneb => Eth2DataVersion::Deneb,
            Self::Electra => Eth2DataVersion::Electra,
            Self::Fulu => Eth2DataVersion::Fulu,
            Self::Unknown => Eth2DataVersion::Unknown,
        }
    }

    /// Converts an eth2 spec data version to go-parity `DataVersion`.
    pub const fn from_eth2(version: Eth2DataVersion) -> Result<Self, VersionError> {
        match version {
            Eth2DataVersion::Phase0 => Ok(Self::Phase0),
            Eth2DataVersion::Altair => Ok(Self::Altair),
            Eth2DataVersion::Bellatrix => Ok(Self::Bellatrix),
            Eth2DataVersion::Capella => Ok(Self::Capella),
            Eth2DataVersion::Deneb => Ok(Self::Deneb),
            Eth2DataVersion::Electra => Ok(Self::Electra),
            Eth2DataVersion::Fulu => Ok(Self::Fulu),
            _ => Err(VersionError::UnknownDataVersion),
        }
    }

    /// Returns the legacy pre-v0.18 numeric representation (phase0=0..).
    pub const fn to_legacy_u64(self) -> Result<u64, VersionError> {
        match self {
            Self::Phase0 => Ok(0),
            Self::Altair => Ok(1),
            Self::Bellatrix => Ok(2),
            Self::Capella => Ok(3),
            Self::Deneb => Ok(4),
            Self::Electra => Ok(5),
            Self::Fulu => Ok(6),
            Self::Unknown => Err(VersionError::UnknownDataVersion),
        }
    }

    /// Converts a legacy pre-v0.18 numeric value to go-parity `DataVersion`.
    pub const fn from_legacy_u64(value: u64) -> Result<Self, VersionError> {
        match value {
            0 => Ok(Self::Phase0),
            1 => Ok(Self::Altair),
            2 => Ok(Self::Bellatrix),
            3 => Ok(Self::Capella),
            4 => Ok(Self::Deneb),
            5 => Ok(Self::Electra),
            6 => Ok(Self::Fulu),
            _ => Err(VersionError::UnknownDataVersion),
        }
    }
}

impl fmt::Display for DataVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for DataVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = self.to_legacy_u64().map_err(serde::ser::Error::custom)?;
        serializer.serialize_u64(encoded)
    }
}

impl<'de> Deserialize<'de> for DataVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = u64::deserialize(deserializer)?;
        Self::from_legacy_u64(encoded).map_err(D::Error::custom)
    }
}

/// Go-parity builder version used by signeddata wrappers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
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
            Self::Unknown => "unknown",
            Self::V1 => "v1",
        }
    }

    /// Returns the eth2 spec equivalent to this builder version.
    pub const fn to_eth2(self) -> Eth2BuilderVersion {
        match self {
            Self::V1 => Eth2BuilderVersion::V1,
            Self::Unknown => Eth2BuilderVersion::Unknown,
        }
    }

    /// Converts an eth2 spec builder version to go-parity `BuilderVersion`.
    pub const fn from_eth2(version: Eth2BuilderVersion) -> Result<Self, VersionError> {
        match version {
            Eth2BuilderVersion::V1 => Ok(Self::V1),
            _ => Err(VersionError::UnknownBuilderVersion),
        }
    }

    /// Returns the legacy pre-v0.18 numeric representation (v1=0).
    pub const fn to_legacy_u64(self) -> Result<u64, VersionError> {
        match self {
            Self::V1 => Ok(0),
            Self::Unknown => Err(VersionError::UnknownBuilderVersion),
        }
    }

    /// Converts a legacy pre-v0.18 numeric value to go-parity `BuilderVersion`.
    pub const fn from_legacy_u64(value: u64) -> Result<Self, VersionError> {
        match value {
            0 => Ok(Self::V1),
            _ => Err(VersionError::UnknownBuilderVersion),
        }
    }
}

impl fmt::Display for BuilderVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for BuilderVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = self.to_legacy_u64().map_err(serde::ser::Error::custom)?;
        serializer.serialize_u64(encoded)
    }
}

impl<'de> Deserialize<'de> for BuilderVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = u64::deserialize(deserializer)?;
        Self::from_legacy_u64(encoded).map_err(D::Error::custom)
    }
}

/// Signature of a corresponding epoch.
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct SignedEpoch {
    /// Epoch value.
    pub epoch: phase0::Epoch,
    /// BLS signature for the epoch.
    #[tree_hash(skip_hashing)]
    pub signature: phase0::BLSSignature,
}

impl Serialize for SignedEpoch {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct SignedEpochJson<'a> {
            epoch: String,
            signature: &'a str,
        }

        let signature = hex::encode(self.signature);
        let signature = format!("0x{signature}");

        SignedEpochJson {
            epoch: self.epoch.to_string(),
            signature: signature.as_str(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignedEpoch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SignedEpochJson {
            epoch: String,
            signature: String,
        }

        let json = SignedEpochJson::deserialize(deserializer)?;
        let epoch = json
            .epoch
            .parse::<phase0::Epoch>()
            .map_err(|err| D::Error::custom(format!("invalid epoch '{}': {err}", json.epoch)))?;
        let trimmed = json
            .signature
            .strip_prefix("0x")
            .or_else(|| json.signature.strip_prefix("0X"))
            .ok_or_else(|| D::Error::custom("signature must have 0x prefix"))?;
        let decoded = hex::decode(trimmed).map_err(D::Error::custom)?;
        let signature = decoded
            .try_into()
            .map_err(|_: Vec<u8>| D::Error::custom("signature must be 96 bytes"))?;

        Ok(Self { epoch, signature })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;
    use tree_hash::TreeHash;

    #[test_case(DataVersion::Unknown, Eth2DataVersion::Unknown; "unknown")]
    #[test_case(DataVersion::Phase0, Eth2DataVersion::Phase0; "phase0")]
    #[test_case(DataVersion::Altair, Eth2DataVersion::Altair; "altair")]
    #[test_case(DataVersion::Bellatrix, Eth2DataVersion::Bellatrix; "bellatrix")]
    #[test_case(DataVersion::Capella, Eth2DataVersion::Capella; "capella")]
    #[test_case(DataVersion::Deneb, Eth2DataVersion::Deneb; "deneb")]
    #[test_case(DataVersion::Electra, Eth2DataVersion::Electra; "electra")]
    #[test_case(DataVersion::Fulu, Eth2DataVersion::Fulu; "fulu")]
    fn data_version_to_eth2(version: DataVersion, expected: Eth2DataVersion) {
        assert_eq!(version.to_eth2(), expected);
    }

    #[test_case(Eth2DataVersion::Unknown, None, Some("unknown data version"); "unknown")]
    #[test_case(Eth2DataVersion::Phase0, Some(DataVersion::Phase0), None; "phase0")]
    #[test_case(Eth2DataVersion::Altair, Some(DataVersion::Altair), None; "altair")]
    #[test_case(Eth2DataVersion::Bellatrix, Some(DataVersion::Bellatrix), None; "bellatrix")]
    #[test_case(Eth2DataVersion::Capella, Some(DataVersion::Capella), None; "capella")]
    #[test_case(Eth2DataVersion::Deneb, Some(DataVersion::Deneb), None; "deneb")]
    #[test_case(Eth2DataVersion::Electra, Some(DataVersion::Electra), None; "electra")]
    #[test_case(Eth2DataVersion::Fulu, Some(DataVersion::Fulu), None; "fulu")]
    fn data_version_from_eth2(
        version: Eth2DataVersion,
        expected: Option<DataVersion>,
        expected_err: Option<&str>,
    ) {
        let actual = DataVersion::from_eth2(version);

        match expected_err {
            Some(expected_err) => {
                let err = actual.expect_err("expected error");
                assert!(err.to_string().contains(expected_err));
            }
            None => {
                assert_eq!(
                    actual.expect("expected version"),
                    expected.expect("expected value")
                );
            }
        }
    }

    #[test]
    fn signed_epoch_hash_root() {
        let epoch = SignedEpoch {
            epoch: 42,
            signature: [0x11; phase0::BLS_SIGNATURE_LEN],
        };

        assert_eq!(
            hex::encode(epoch.tree_hash_root()),
            "2a00000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn signed_epoch_json_roundtrip() {
        let epoch = SignedEpoch {
            epoch: 42,
            signature: [0x11; phase0::BLS_SIGNATURE_LEN],
        };

        let json = serde_json::to_string(&epoch).expect("marshal signed epoch");
        assert_eq!(
            json,
            format!(
                "{{\"epoch\":\"42\",\"signature\":\"0x{}\"}}",
                hex::encode(epoch.signature)
            )
        );

        let roundtrip: SignedEpoch = serde_json::from_str(&json).expect("unmarshal signed epoch");
        assert_eq!(roundtrip, epoch);
    }

    #[test]
    fn signed_epoch_requires_prefixed_signature() {
        let err = serde_json::from_str::<SignedEpoch>("{\"epoch\":\"42\",\"signature\":\"0011\"}")
            .expect_err("expected invalid signature");
        assert!(err.to_string().contains("0x prefix"));
    }
}
