use core::fmt;

use serde::{Deserialize, Serialize};

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
}

impl fmt::Display for BuilderVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
