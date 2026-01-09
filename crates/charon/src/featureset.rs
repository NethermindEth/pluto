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
    /// Disable explicitly disables a feature.
    Disable = 0,
    /// Alpha is for internal devnet testing.
    Alpha = 1,
    /// Beta is for internal and external testnet testing.
    Beta = 2,
    /// Stable is for stable feature ready for production.
    Stable = 3,
    /// Sentinel is an internal tail-end placeholder.
    Sentinel = 4,
    /// Enable explicitly enables a feature.
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

/// Feature is a feature being rolled out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Feature {
    /// MockAlpha is a mock feature in alpha status for testing.
    MockAlpha,
    /// EagerDoubleLinear enables Eager Double Linear round timer for consensus
    /// rounds.
    EagerDoubleLinear,
    /// ConsensusParticipate enables consensus participate feature in order to
    /// participate in an ongoing consensus round while still waiting for an
    /// unsigned data from beacon node.
    ConsensusParticipate,
    /// AggSigDBV2 enables a newer, simpler implementation of `aggsigdb`.
    AggSigDBV2,
    /// JSONRequests enables JSON requests for eth2 client.
    JsonRequests,
    /// GnosisBlockHotfix enables Gnosis/Chiado SSZ fix.
    /// The feature gets automatically enabled when the current network is
    /// gnosis|chiado, unless the user disabled this feature explicitly.
    GnosisBlockHotfix,
    /// Linear enables Linear round timer for consensus rounds.
    /// When active has precedence over EagerDoubleLinear round timer.
    Linear,
    /// SSEReorgDuties enables Scheduler to refresh duties when reorg occurs.
    SseReorgDuties,
    /// AttestationInclusion enables tracking of on-chain inclusion for
    /// attestations. Previously this was the default behaviour, however,
    /// tracking on-chain inclusions post-electra is costly. The extra load
    /// that Charon puts the beacon node is deemed so high that it can throttle
    /// the completion of other duties.
    AttestationInclusion,
    /// ProposalTimeout enables a longer first consensus round timeout of 1.5
    /// seconds for proposal duty.
    ProposalTimeout,
    /// QUIC enables the QUIC transport protocol in libp2p.
    Quic,
    /// FetchOnlyCommIdx0 enables querying the beacon node for attestation data
    /// only for committee index 0.
    FetchOnlyCommIdx0,
    /// ChainSplitHalt compares locally fetched attestation's target and source
    /// to leader's proposed target and source attestation. In case they
    /// differ, Charon does not sign the attestation.
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
    /// RwLock was poisoned, indicating a panic occurred while holding the lock.
    #[error("rwlock poisoned")]
    RwLockPoisoned,
}

type Result<T> = std::result::Result<T, FeaturesetError>;

/// Global state for feature statuses.
struct State {
    /// Defines the current rollout status of each feature.
    pub state: HashMap<Feature, Status>,
    /// Defines the minimum enabled status.
    pub min_status: Status,
}

impl State {
    /// Creates a new state with default feature statuses.
    fn new() -> Self {
        let state = HashMap::from([
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

        Self {
            state,
            min_status: Status::Stable,
        }
    }
}

static GLOBAL_STATE: LazyLock<RwLock<State>> = LazyLock::new(|| RwLock::new(State::new()));

/// Returns true if the feature is enabled.
pub fn enabled(feature: Feature) -> Result<bool> {
    let state = GLOBAL_STATE
        .read()
        .map_err(|_| FeaturesetError::RwLockPoisoned)?;

    // Get feature status, default to Disable (0) if not found
    let feature_status = state
        .state
        .get(&feature)
        .copied()
        .unwrap_or(Status::Disable);

    Ok(feature_status >= state.min_status)
}

/// CustomEnabledAll returns all custom enabled features.
pub fn custom_enabled_all() -> Result<Vec<Feature>> {
    let state = GLOBAL_STATE
        .read()
        .map_err(|_| FeaturesetError::RwLockPoisoned)?;

    let mut custom_enabled_features: Vec<Feature> = Vec::new();

    for (feature, status) in &state.state {
        if *status > Status::Stable {
            custom_enabled_features.push(*feature);
        }
    }

    Ok(custom_enabled_features)
}

/// Config configures the feature set package.
#[derive(Debug, Clone)]
pub struct Config {
    /// MinStatus defines the minimum enabled status.
    pub min_status: Status,
    /// Enabled overrides min status and enables a list of features.
    pub enabled: Vec<Feature>,
    /// Disabled overrides min status and disables a list of features.
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

/// Initialises the global feature set state.
pub fn init(config: Config) -> Result<()> {
    let mut state = GLOBAL_STATE
        .write()
        .map_err(|_| FeaturesetError::RwLockPoisoned)?;

    // Set min status
    // Validate min_status is one of the allowed values
    match config.min_status {
        Status::Alpha | Status::Beta | Status::Stable => {
            state.min_status = config.min_status;
        }
        _ => {
            return Err(FeaturesetError::UnknownMinStatus {
                min_status: config.min_status.to_string(),
            });
        }
    }

    // Enable features
    for feature in &config.enabled {
        state.state.insert(*feature, Status::Enable);
    }

    // Disable features
    for feature in &config.disabled {
        state.state.insert(*feature, Status::Disable);
    }

    Ok(())
}

/// Test utilities for enabling/disabling features in tests.
/// Available when running tests or when the `test-utils` feature is enabled.
///
/// # Warning: Global State and Concurrency
///
/// These utilities modify global state and are **not thread-safe** when used
/// in parallel tests. When using the `test-utils` feature, tests that call
/// `enable_for_test` or `disable_for_test` must be serialized using a tool
/// like `serial_test` to avoid race conditions.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use super::*;

    /// This is used by test helper functions to ensure cleanup happens.
    ///
    /// # Note
    ///
    /// This guard must be bound to a variable to remain in effect. If not bound
    /// (e.g., as a temporary expression), it will be dropped immediately,
    /// restoring the feature status before your test code runs.
    pub struct FeatureGuard {
        feature: Feature,
        cached_status: Status,
    }

    impl Drop for FeatureGuard {
        fn drop(&mut self) {
            if let Ok(mut state) = GLOBAL_STATE.write() {
                state.state.insert(self.feature, self.cached_status);
            }
        }
    }

    /// Enables a feature for testing and returns a guard that restores the
    /// original status when dropped.
    ///
    /// # Example
    /// ```
    /// use charon::featureset::{Feature, test_utils::enable_for_test};
    ///
    /// let _guard = enable_for_test(Feature::MockAlpha);
    /// // Feature is enabled here
    /// // Feature is automatically restored when _guard is dropped
    /// ```
    ///
    /// # Note
    ///
    /// The returned guard should be bound to a variable. See [`FeatureGuard`]
    /// for details.
    pub fn enable_for_test(feature: Feature) -> Result<FeatureGuard> {
        let mut state = GLOBAL_STATE
            .write()
            .map_err(|_| FeaturesetError::RwLockPoisoned)?;

        let cached_status = state
            .state
            .get(&feature)
            .copied()
            .unwrap_or(Status::Disable);

        state.state.insert(feature, Status::Enable);

        Ok(FeatureGuard {
            feature,
            cached_status,
        })
    }

    /// Disables a feature for testing and returns a guard that restores the
    /// original status when dropped.
    ///
    /// # Example
    /// ```
    /// use charon::featureset::{Feature, test_utils::disable_for_test};
    ///
    /// let _guard = disable_for_test(Feature::MockAlpha);
    /// // Feature is disabled here
    /// // Feature is automatically restored when _guard is dropped
    /// ```
    ///
    /// # Note
    ///
    /// The returned guard should be bound to a variable. See [`FeatureGuard`]
    /// for details.
    pub fn disable_for_test(feature: Feature) -> Result<FeatureGuard> {
        let mut state = GLOBAL_STATE
            .write()
            .map_err(|_| FeaturesetError::RwLockPoisoned)?;

        let cached_status = state
            .state
            .get(&feature)
            .copied()
            .unwrap_or(Status::Disable);

        state.state.insert(feature, Status::Disable);

        Ok(FeatureGuard {
            feature,
            cached_status,
        })
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::{test_utils::*, *};

    /// Setup initialises global variable per test.
    fn setup() {
        // Reset state to defaults first, then initialize with default config
        if let Ok(mut state) = GLOBAL_STATE.write() {
            *state = State::new();
        }
        init(Default::default()).expect("setup should initialize state");
    }

    #[test]
    #[serial(featureset)]
    fn test_all_feature_status() {
        setup();
        init(Default::default()).expect("init should work");

        let features = Feature::all();

        for feature in features {
            let state = GLOBAL_STATE.read().expect("rwlock poisoned");
            let status = state.state.get(feature);
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
    #[serial(featureset)]
    fn test_custom_enabled_all() {
        setup();
        init(Default::default()).expect("init should work");

        // Initially no custom enabled features
        let custom = custom_enabled_all().expect("should not error");
        assert!(custom.is_empty());

        // Enable a feature
        init(Config {
            min_status: Status::Stable,
            enabled: vec![Feature::MockAlpha],
            disabled: Vec::new(),
        })
        .expect("init should work");

        let custom = custom_enabled_all().expect("should not error");
        assert!(custom.contains(&Feature::MockAlpha));
        assert_eq!(custom.len(), 1);
    }

    #[test]
    #[serial(featureset)]
    fn test_config() {
        setup();

        init(Default::default()).expect("default config should work");

        init(Config {
            min_status: Status::Alpha,
            enabled: vec![],
            disabled: vec![],
        })
        .expect("alpha config should work");

        // MockAlpha is Alpha status, min_status is now Alpha, so it should be enabled
        assert!(enabled(Feature::MockAlpha).expect("should not error"));
    }

    #[test]
    #[serial(featureset)]
    fn test_enable_for_test_helper() {
        setup();
        init(Default::default()).expect("init should work");

        // Initially disabled
        assert!(!enabled(Feature::MockAlpha).expect("should not error"));

        // Enable using helper
        let _guard = enable_for_test(Feature::MockAlpha).expect("should not error");
        assert!(enabled(Feature::MockAlpha).expect("should not error"));

        // Drop the guard
        drop(_guard);

        // Should be restored to disabled
        assert!(!enabled(Feature::MockAlpha).expect("should not error"));
    }

    #[test]
    #[serial(featureset)]
    fn test_disable_for_test_helper() {
        setup();

        // First enable a stable feature
        init(Config {
            min_status: Status::Stable,
            enabled: vec![Feature::EagerDoubleLinear],
            disabled: vec![],
        })
        .expect("init should work");

        // Should be enabled (it's Stable status)
        assert!(enabled(Feature::EagerDoubleLinear).expect("should not error"));

        // Disable using helper
        let _guard = disable_for_test(Feature::EagerDoubleLinear).expect("should not error");
        assert!(!enabled(Feature::EagerDoubleLinear).expect("should not error"));

        // Drop the guard
        drop(_guard);

        // Should be restored to enabled
        assert!(enabled(Feature::EagerDoubleLinear).expect("should not error"));
    }
}
