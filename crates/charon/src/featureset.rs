//! # Featureset
//!
//! Defines a set of global features and their rollout status.
//!
//! Features can be enabled or disabled via configuration, and the minimum
//! status determines which features are enabled by default.

use std::{
    collections::HashMap,
    fmt,
    sync::{LazyLock, RwLock},
};

use thiserror::Error;

/// Enumerates the rollout status of a feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    /// Explicitly disables a feature.
    Disable = 0,
    /// For internal devnet testing.
    Alpha = 1,
    /// For internal and external testnet testing.
    Beta = 2,
    /// For stable feature ready for production.
    Stable = 3,
    /// An internal tail-end placeholder.
    Sentinel = 4,
    /// Explicitly enables a feature.
    /// This ensures enable >= any status, so it's always enabled.
    Enable = i32::MAX as isize,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Disable => write!(f, "disable"),
            Status::Alpha => write!(f, "alpha"),
            Status::Beta => write!(f, "beta"),
            Status::Stable => write!(f, "stable"),
            Status::Sentinel => write!(f, "sentinel"),
            Status::Enable => write!(f, "enable"),
        }
    }
}

/// A feature being rolled out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Feature {
    /// A mock feature in alpha status for testing.
    MockAlpha,
    /// Enables Eager Double Linear round timer for consensus rounds.
    EagerDoubleLinear,
    /// Enables consensus participate feature in order to participate in an
    /// ongoing consensus round while still waiting for unsigned data from
    /// beacon node.
    ConsensusParticipate,
    /// Enables a newer, simpler implementation of `aggsigdb`.
    AggSigDBV2,
    /// Enables JSON requests for eth2 client.
    JsonRequests,
    /// Enables Gnosis/Chiado SSZ fix.
    /// The feature gets automatically enabled when the current network is
    /// gnosis|chiado, unless the user disabled this feature explicitly.
    GnosisBlockHotfix,
    /// Enables Linear round timer for consensus rounds.
    /// When active has precedence over EagerDoubleLinear round timer.
    Linear,
    /// Enables Scheduler to refresh duties when reorg occurs.
    SseReorgDuties,
    /// Enables tracking of on-chain inclusion for attestations. Previously
    /// this was the default behaviour, however, tracking on-chain inclusions
    /// post-electra is costly. The extra load that Charon puts the beacon
    /// node is deemed so high that it can throttle the completion of other
    /// duties.
    AttestationInclusion,
    /// Enables a longer first consensus round timeout of 1.5 seconds for
    /// proposal duty.
    ProposalTimeout,
    /// Enables the QUIC transport protocol in libp2p.
    Quic,
    /// Enables querying the beacon node for attestation data only for
    /// committee index 0.
    FetchOnlyCommIdx0,
    /// Compares locally fetched attestation's target and source to leader's
    /// proposed target and source attestation. In case they differ, Charon
    /// does not sign the attestation.
    ChainSplitHalt,
}

impl Feature {
    /// Returns the string representation of the feature.
    pub fn as_str(self) -> &'static str {
        match self {
            Feature::MockAlpha => "mock_alpha",
            Feature::EagerDoubleLinear => "eager_double_linear",
            Feature::ConsensusParticipate => "consensus_participate",
            Feature::AggSigDBV2 => "aggsigdb_v2",
            Feature::JsonRequests => "json_requests",
            Feature::GnosisBlockHotfix => "gnosis_block_hotfix",
            Feature::Linear => "linear",
            Feature::SseReorgDuties => "sse_reorg_duties",
            Feature::AttestationInclusion => "attestation_inclusion",
            Feature::ProposalTimeout => "proposal_timeout",
            Feature::Quic => "quic",
            Feature::FetchOnlyCommIdx0 => "fetch_only_commidx_0",
            Feature::ChainSplitHalt => "chain_split_halt",
        }
    }

    /// Returns all known features.
    pub fn all() -> &'static [Feature] {
        &[
            Feature::MockAlpha,
            Feature::EagerDoubleLinear,
            Feature::ConsensusParticipate,
            Feature::AggSigDBV2,
            Feature::JsonRequests,
            Feature::GnosisBlockHotfix,
            Feature::Linear,
            Feature::SseReorgDuties,
            Feature::AttestationInclusion,
            Feature::ProposalTimeout,
            Feature::Quic,
            Feature::FetchOnlyCommIdx0,
            Feature::ChainSplitHalt,
        ]
    }
}

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::convert::TryFrom<&str> for Feature {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Feature::all()
            .iter()
            .find(|feature| value.eq_ignore_ascii_case(feature.as_str()))
            .copied()
            .ok_or_else(|| format!("unknown feature: {}", value))
    }
}

/// Errors that can occur in the featureset module.
#[derive(Debug, Error)]
pub enum FeaturesetError {
    /// Unknown minimum status provided.
    #[error("unknown min status: {min_status}")]
    UnknownMinStatus {
        /// The invalid minimum status string that was provided.
        min_status: String,
    },
}

type Result<T> = std::result::Result<T, FeaturesetError>;

/// Global state for feature statuses.
pub struct FeatureSet {
    /// Defines the current rollout status of each feature.
    pub state: HashMap<Feature, Status>,
    /// Defines the minimum enabled status.
    pub min_status: Status,
}

impl Default for FeatureSet {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureSet {
    /// Creates a new feature set with default configuration.
    pub fn new() -> Self {
        Self::from_config(Default::default()).expect("default config should always be valid")
    }

    /// Creates a feature set from the given configuration.
    pub fn from_config(config: Config) -> Result<Self> {
        // Validate min_status is one of the allowed values
        match config.min_status {
            Status::Alpha | Status::Beta | Status::Stable => {}
            _ => {
                return Err(FeaturesetError::UnknownMinStatus {
                    min_status: config.min_status.to_string(),
                });
            }
        }

        // Initialize with default feature statuses
        let mut state = HashMap::from([
            (Feature::EagerDoubleLinear, Status::Stable),
            (Feature::ConsensusParticipate, Status::Stable),
            (Feature::MockAlpha, Status::Alpha),
            (Feature::AggSigDBV2, Status::Alpha),
            (Feature::JsonRequests, Status::Alpha),
            (Feature::GnosisBlockHotfix, Status::Alpha),
            (Feature::Linear, Status::Alpha),
            (Feature::SseReorgDuties, Status::Alpha),
            (Feature::AttestationInclusion, Status::Alpha),
            (Feature::ProposalTimeout, Status::Alpha),
            (Feature::Quic, Status::Alpha),
            (Feature::FetchOnlyCommIdx0, Status::Alpha),
            (Feature::ChainSplitHalt, Status::Alpha),
        ]);

        // Enable features
        for feature in config.enabled {
            state.insert(feature, Status::Enable);
        }

        // Disable features
        for feature in config.disabled {
            state.insert(feature, Status::Disable);
        }

        Ok(Self {
            state,
            min_status: config.min_status,
        })
    }

    /// Enables GnosisBlockHotfix if it was not disabled by the user.
    ///
    /// This is still a temporary workaround for the gnosis chain.
    /// When go-eth2-client is fully supporting custom specs, this function has
    /// to be removed with GnosisBlockHotfix feature.
    pub fn enable_gnosis_block_hotfix_if_not_disabled(&mut self, config: &Config) {
        let disabled = config.disabled.contains(&Feature::GnosisBlockHotfix);

        if disabled {
            tracing::warn!(
                "Feature gnosis_block_hotfix is required by gnosis/chiado, but explicitly disabled"
            );
        } else {
            self.state
                .insert(Feature::GnosisBlockHotfix, Status::Enable);
        }
    }

    /// Returns true if the feature is enabled.
    pub fn enabled(&self, feature: Feature) -> bool {
        // Get feature status, default to Disable (0) if not found
        let feature_status = self.state.get(&feature).copied().unwrap_or(Status::Disable);

        feature_status >= self.min_status
    }

    /// Returns all custom enabled features.
    pub fn custom_enabled_all(&self) -> Vec<Feature> {
        let mut custom_enabled_features: Vec<Feature> = Vec::new();

        for (feature, status) in &self.state {
            if *status > Status::Stable {
                custom_enabled_features.push(*feature);
            }
        }

        custom_enabled_features
    }
}

/// Global feature set state.
pub static GLOBAL_STATE: LazyLock<RwLock<FeatureSet>> =
    LazyLock::new(|| RwLock::new(FeatureSet::new()));

/// Config configures the feature set package.
#[derive(Debug, Clone)]
pub struct Config {
    /// The minimum enabled status.
    pub min_status: Status,
    /// Overrides min status and enables a list of features.
    pub enabled: Vec<Feature>,
    /// Overrides min status and disables a list of features.
    pub disabled: Vec<Feature>,
}

impl Default for Config {
    /// Returns the default config enabling only stable features.
    fn default() -> Self {
        Self {
            min_status: Status::Stable,
            enabled: Vec::new(),
            disabled: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_feature_status() {
        let featureset = FeatureSet::new();

        let features = Feature::all();

        for feature in features {
            let status = featureset.state.get(feature);
            assert!(status.is_some(), "feature {} should have status", feature);
            assert!(
                *status.unwrap() != Status::Disable,
                "feature {} should have positive status",
                feature
            );
        }
    }

    #[test]
    fn test_status_display() {
        assert_eq!(Status::Disable.to_string(), "disable");
        assert_eq!(Status::Alpha.to_string(), "alpha");
        assert_eq!(Status::Beta.to_string(), "beta");
        assert_eq!(Status::Stable.to_string(), "stable");
        assert_eq!(Status::Sentinel.to_string(), "sentinel");
        assert_eq!(Status::Enable.to_string(), "enable");
    }

    #[test]
    fn test_custom_enabled_all() {
        let featureset = FeatureSet::new();

        // Initially no custom enabled features
        let custom = featureset.custom_enabled_all();
        assert!(custom.is_empty());

        // Enable a feature
        let featureset = FeatureSet::from_config(Config {
            min_status: Status::Stable,
            enabled: vec![Feature::MockAlpha],
            disabled: Vec::new(),
        })
        .expect("from_config should work");

        let custom = featureset.custom_enabled_all();
        assert!(custom.contains(&Feature::MockAlpha));
        assert_eq!(custom.len(), 1);
    }

    #[test]
    fn test_config() {
        let featureset = FeatureSet::new();
        assert_eq!(featureset.min_status, Status::Stable);

        let featureset = FeatureSet::from_config(Config {
            min_status: Status::Alpha,
            enabled: vec![],
            disabled: vec![],
        })
        .expect("alpha config should work");

        // MockAlpha is Alpha status, min_status is now Alpha, so it should be enabled
        assert!(featureset.enabled(Feature::MockAlpha));
    }

    #[test]
    fn test_enable_feature() {
        let featureset = FeatureSet::new();

        // Initially disabled (MockAlpha is Alpha status, min_status is Stable)
        assert!(!featureset.enabled(Feature::MockAlpha));

        // Enable the feature
        let featureset = FeatureSet::from_config(Config {
            min_status: Status::Stable,
            enabled: vec![Feature::MockAlpha],
            disabled: vec![],
        })
        .expect("should not error");

        assert!(featureset.enabled(Feature::MockAlpha));
    }

    #[test]
    fn test_disable_feature() {
        // First create with a stable feature (EagerDoubleLinear is Stable by default)
        let featureset = FeatureSet::from_config(Config {
            min_status: Status::Stable,
            enabled: vec![],
            disabled: vec![],
        })
        .expect("from_config should work");

        // Should be enabled (it's Stable status)
        assert!(featureset.enabled(Feature::EagerDoubleLinear));

        // Now disable it
        let featureset = FeatureSet::from_config(Config {
            min_status: Status::Stable,
            enabled: vec![],
            disabled: vec![Feature::EagerDoubleLinear],
        })
        .expect("should not error");

        assert!(!featureset.enabled(Feature::EagerDoubleLinear));
    }

    #[test]
    fn test_enable_gnosis_block_hotfix_if_not_disabled() {
        // Test method when not disabled explicitly
        let config = Config::default();
        let mut featureset =
            FeatureSet::from_config(config.clone()).expect("from_config should work");
        featureset.enable_gnosis_block_hotfix_if_not_disabled(&config);
        assert!(featureset.enabled(Feature::GnosisBlockHotfix));

        // Test method when disabled explicitly
        let config_with_disabled = Config {
            min_status: Status::Stable,
            enabled: vec![],
            disabled: vec![Feature::GnosisBlockHotfix],
        };
        let mut featureset =
            FeatureSet::from_config(config_with_disabled.clone()).expect("from_config should work");
        featureset.enable_gnosis_block_hotfix_if_not_disabled(&config_with_disabled);
        assert!(!featureset.enabled(Feature::GnosisBlockHotfix));
    }
}
