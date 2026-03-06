//! Versioned wrappers and version enums used by signeddata flows.

use serde::{Deserialize, Serialize};

pub use crate::spec::{BuilderVersion, DataVersion};
use crate::{
    spec::{altair, bellatrix, capella, deneb, electra, fulu, phase0},
    v1,
};

/// Signed proposal wrapper across all supported forks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VersionedSignedProposal {
    /// Fork version of the payload.
    pub version: DataVersion,
    /// True if this proposal is blinded.
    pub blinded: bool,
    /// Phase0 proposal payload.
    pub phase0: Option<phase0::SignedBeaconBlock>,
    /// Altair proposal payload.
    pub altair: Option<altair::SignedBeaconBlock>,
    /// Bellatrix proposal payload.
    pub bellatrix: Option<bellatrix::SignedBeaconBlock>,
    /// Bellatrix blinded proposal payload.
    pub bellatrix_blinded: Option<bellatrix::SignedBlindedBeaconBlock>,
    /// Capella proposal payload.
    pub capella: Option<capella::SignedBeaconBlock>,
    /// Capella blinded proposal payload.
    pub capella_blinded: Option<capella::SignedBlindedBeaconBlock>,
    /// Deneb proposal payload.
    pub deneb: Option<deneb::SignedBlockContents>,
    /// Deneb blinded proposal payload.
    pub deneb_blinded: Option<deneb::SignedBlindedBeaconBlock>,
    /// Electra proposal payload.
    pub electra: Option<electra::SignedBlockContents>,
    /// Electra blinded proposal payload.
    pub electra_blinded: Option<electra::SignedBlindedBeaconBlock>,
    /// Fulu proposal payload.
    pub fulu: Option<fulu::SignedBlockContents>,
    /// Fulu blinded proposal payload.
    pub fulu_blinded: Option<electra::SignedBlindedBeaconBlock>,
}

/// Signed blinded proposal wrapper across all supported forks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VersionedSignedBlindedProposal {
    /// Fork version of the payload.
    pub version: DataVersion,
    /// Bellatrix blinded proposal payload.
    pub bellatrix: Option<bellatrix::SignedBlindedBeaconBlock>,
    /// Capella blinded proposal payload.
    pub capella: Option<capella::SignedBlindedBeaconBlock>,
    /// Deneb blinded proposal payload.
    pub deneb: Option<deneb::SignedBlindedBeaconBlock>,
    /// Electra blinded proposal payload.
    pub electra: Option<electra::SignedBlindedBeaconBlock>,
    /// Fulu blinded proposal payload.
    pub fulu: Option<electra::SignedBlindedBeaconBlock>,
}

/// Versioned attestation wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VersionedAttestation {
    /// Fork version of the payload.
    pub version: DataVersion,
    /// Optional validator index associated with the attestation.
    pub validator_index: Option<phase0::ValidatorIndex>,
    /// Phase0 attestation.
    pub phase0: Option<phase0::Attestation>,
    /// Altair attestation.
    pub altair: Option<phase0::Attestation>,
    /// Bellatrix attestation.
    pub bellatrix: Option<phase0::Attestation>,
    /// Capella attestation.
    pub capella: Option<phase0::Attestation>,
    /// Deneb attestation.
    pub deneb: Option<phase0::Attestation>,
    /// Electra attestation.
    pub electra: Option<electra::Attestation>,
    /// Fulu attestation.
    pub fulu: Option<electra::Attestation>,
}

/// Versioned signed aggregate-and-proof wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VersionedSignedAggregateAndProof {
    /// Fork version of the payload.
    pub version: DataVersion,
    /// Phase0 payload.
    pub phase0: Option<phase0::SignedAggregateAndProof>,
    /// Altair payload.
    pub altair: Option<phase0::SignedAggregateAndProof>,
    /// Bellatrix payload.
    pub bellatrix: Option<phase0::SignedAggregateAndProof>,
    /// Capella payload.
    pub capella: Option<phase0::SignedAggregateAndProof>,
    /// Deneb payload.
    pub deneb: Option<phase0::SignedAggregateAndProof>,
    /// Electra payload.
    pub electra: Option<electra::SignedAggregateAndProof>,
    /// Fulu payload.
    pub fulu: Option<electra::SignedAggregateAndProof>,
}

/// Versioned signed validator registration wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VersionedSignedValidatorRegistration {
    /// Builder API version of the payload.
    pub version: BuilderVersion,
    /// V1 payload.
    pub v1: Option<v1::SignedValidatorRegistration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_version_serde_uses_spec_strings() {
        assert_eq!(
            serde_json::to_string(&DataVersion::Phase0).expect("serialize phase0"),
            "\"phase0\""
        );
        assert_eq!(
            serde_json::to_string(&DataVersion::Fulu).expect("serialize fulu"),
            "\"fulu\""
        );

        let deneb: DataVersion = serde_json::from_str("\"deneb\"").expect("deserialize deneb");
        assert_eq!(deneb, DataVersion::Deneb);

        let err =
            serde_json::from_str::<DataVersion>("\"unknown-fork\"").expect_err("invalid version");
        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn builder_version_serde_uses_spec_strings() {
        assert_eq!(
            serde_json::to_string(&BuilderVersion::V1).expect("serialize v1"),
            "\"v1\""
        );

        let v1: BuilderVersion = serde_json::from_str("\"v1\"").expect("deserialize v1");
        assert_eq!(v1, BuilderVersion::V1);

        let err =
            serde_json::from_str::<BuilderVersion>("\"v2\"").expect_err("invalid builder version");
        assert!(err.to_string().contains("unknown variant"));
    }
}
