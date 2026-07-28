//! Metrics published by the monitoring readiness checker.

use vise::{Gauge, Global, LabeledFamily, Metrics};

/// Metrics that back the monitoring API readiness checks.
#[derive(Debug, Metrics)]
#[metrics(prefix = "app")]
pub struct MonitoringMetrics {
    /// Current `/readyz` status code: 1 when ready, otherwise a
    /// Charon-compatible readiness failure code.
    pub monitoring_readyz: Gauge<i64>,

    /// Current beacon node syncing status: 1 when syncing, 0 when synced.
    pub monitoring_beacon_node_syncing: Gauge<i64>,

    /// Number of peers connected to the upstream beacon node.
    pub beacon_node_peers: Gauge<u64>,

    /// Constant gauge labelled with the upstream beacon node's version string,
    /// set to 1 for the current version. Mirrors Charon's
    /// `app_beacon_node_version`.
    #[metrics(labels = ["version"])]
    pub beacon_node_version: LabeledFamily<String, Gauge<i64>>,

    /// Parameters for each component of the validator stack this instance is
    /// deployed into, labelled by component and CLI parameters. Mirrors
    /// Charon's `app_validator_stack_params`.
    #[metrics(labels = ["component", "cli_parameters"])]
    pub validator_stack_params: LabeledFamily<(String, String), Gauge<i64>, 2>,

    /// Constant gauge labelled with the current app version, set to 1. Mirrors
    /// Charon's `app_version`.
    #[metrics(labels = ["version"])]
    pub version: LabeledFamily<String, Gauge<i64>>,

    /// Constant gauge labelled with this node's cluster peer name, set to 1.
    /// Mirrors Charon's `app_peer_name`; backs the dashboard's `cluster_peer`
    /// (and `cluster_name`/`cluster_hash`) template variables.
    #[metrics(labels = ["peer_name"])]
    pub peer_name: LabeledFamily<String, Gauge<i64>>,

    /// Constant gauge labelled with the build's git commit hash, set to 1.
    /// Mirrors Charon's `app_git_commit`.
    #[metrics(labels = ["git_hash"])]
    pub git_commit: LabeledFamily<String, Gauge<i64>>,

    /// Gauge set to this binary's start time in unix seconds. Mirrors Charon's
    /// `app_start_time_secs`.
    pub start_time_secs: Gauge<i64>,

    /// Constant gauge labelled with each custom-enabled feature flag, set to 1.
    /// Mirrors Charon's `app_feature_flags` (one series per
    /// `featureset.CustomEnabledAll()` entry).
    #[metrics(labels = ["feature_flags"])]
    pub feature_flags: LabeledFamily<String, Gauge<i64>>,
}

/// Global monitoring metrics.
#[vise::register]
pub static MONITORING_METRICS: Global<MonitoringMetrics> = Global::new();

/// Cluster-lock metrics, mirroring Charon's `cluster_*` startup gauges.
#[derive(Debug, Metrics)]
#[metrics(prefix = "cluster")]
pub struct ClusterMetrics {
    /// Aggregation threshold in the cluster lock. Mirrors Charon's
    /// `cluster_threshold`.
    pub threshold: Gauge<i64>,

    /// Number of operators in the cluster lock. Mirrors Charon's
    /// `cluster_operators`.
    pub operators: Gauge<i64>,

    /// Number of validators in the cluster lock. Mirrors Charon's
    /// `cluster_validators`.
    pub validators: Gauge<i64>,

    /// Constant gauge labelled with the current network (chain), set to 1.
    /// Mirrors Charon's `cluster_network`; `"unknown"` when the cluster's fork
    /// version matches no known network.
    #[metrics(labels = ["network"])]
    pub network: LabeledFamily<String, Gauge<i64>>,
}

/// Global cluster metrics.
#[vise::register]
pub static CLUSTER_METRICS: Global<ClusterMetrics> = Global::new();

/// Inputs for [`init_startup_metrics`], mirroring the arguments of Charon's
/// `initStartupMetrics`.
pub struct StartupMetrics<'a> {
    /// App version string (`app_version` label).
    pub version: &'a str,
    /// This node's cluster peer name (`app_peer_name` label).
    pub peer_name: &'a str,
    /// Build git commit hash, short form (`app_git_commit` label).
    pub git_hash: &'a str,
    /// Binary start time in unix seconds (`app_start_time_secs`).
    pub start_time_secs: i64,
    /// Aggregation threshold from the cluster lock (`cluster_threshold`).
    pub threshold: i64,
    /// Number of operators in the cluster lock (`cluster_operators`).
    pub operators: i64,
    /// Number of validators in the cluster lock (`cluster_validators`).
    pub validators: i64,
    /// Network the cluster's fork version resolves to, or `"unknown"`
    /// (`cluster_network` label).
    pub network: &'a str,
    /// Custom-enabled feature flags (one `app_feature_flags` series each).
    pub feature_flags: &'a [&'a str],
}

/// Sets the constant startup gauges — version, peer name, git commit, start
/// time, network, and custom feature flags — and the cluster-lock gauges,
/// mirroring Charon's `initStartupMetrics`.
///
/// The version/peer-name/git-commit/network/feature-flag gauges are constant
/// series (value 1) whose single purpose is to expose their label; the
/// dashboard reads those labels. `network` is `"unknown"` when the cluster's
/// fork version matches no known network, matching Charon.
pub fn init_startup_metrics(m: &StartupMetrics<'_>) {
    MONITORING_METRICS.version[&m.version.to_owned()].set(1);
    MONITORING_METRICS.peer_name[&m.peer_name.to_owned()].set(1);
    MONITORING_METRICS.git_commit[&m.git_hash.to_owned()].set(1);
    MONITORING_METRICS.start_time_secs.set(m.start_time_secs);

    for flag in m.feature_flags {
        MONITORING_METRICS.feature_flags[&(*flag).to_owned()].set(1);
    }

    CLUSTER_METRICS.threshold.set(m.threshold);
    CLUSTER_METRICS.operators.set(m.operators);
    CLUSTER_METRICS.validators.set(m.validators);
    CLUSTER_METRICS.network[&m.network.to_owned()].set(1);
}

/// Records the Ethereum validator stack components and their CLI parameters in
/// [`MonitoringMetrics::validator_stack_params`], mirroring Charon's
/// `stackComponents`.
///
/// Each entry pairs a component name with its CLI parameters; the gauge is set
/// to 1 for every reported component. Any previously-reported component absent
/// from `components` is reset to 0 first, since vise's `Family` cannot delete
/// series (Charon resets the whole gauge vec).
pub fn stack_components(components: &[(String, String)]) {
    for (labels, gauge) in MONITORING_METRICS.validator_stack_params.to_entries() {
        if !components.contains(&labels) {
            gauge.set(0);
        }
    }

    for labels in components {
        MONITORING_METRICS.validator_stack_params[labels].set(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gauge(component: &str, cli: &str) -> i64 {
        MONITORING_METRICS.validator_stack_params[&(component.to_owned(), cli.to_owned())].get()
    }

    #[test]
    fn stack_components_sets_current_and_resets_stale() {
        // Labels are unique to this test so it does not collide with other tests
        // mutating the global `validator_stack_params` family.
        stack_components(&[
            ("test-teku".to_owned(), "--network=mainnet".to_owned()),
            ("test-lighthouse".to_owned(), "--debug".to_owned()),
        ]);
        assert_eq!(gauge("test-teku", "--network=mainnet"), 1);
        assert_eq!(gauge("test-lighthouse", "--debug"), 1);

        // A subsequent report without `test-lighthouse` resets its stale series
        // to 0 while keeping the still-present component set.
        stack_components(&[("test-teku".to_owned(), "--network=mainnet".to_owned())]);
        assert_eq!(gauge("test-teku", "--network=mainnet"), 1);
        assert_eq!(gauge("test-lighthouse", "--debug"), 0);
    }

    #[test]
    fn init_startup_metrics_sets_network_and_feature_flags() {
        // Labels are unique to this test so it does not collide with other tests
        // mutating the global gauges.
        init_startup_metrics(&StartupMetrics {
            version: "v-test",
            peer_name: "peer-test",
            git_hash: "abc1234",
            start_time_secs: 42,
            threshold: 2,
            operators: 3,
            validators: 4,
            network: "test-network-xyz",
            feature_flags: &["test-feature-a", "test-feature-b"],
        });

        assert_eq!(
            CLUSTER_METRICS.network[&"test-network-xyz".to_owned()].get(),
            1,
        );
        assert_eq!(
            MONITORING_METRICS.feature_flags[&"test-feature-a".to_owned()].get(),
            1,
        );
        assert_eq!(
            MONITORING_METRICS.feature_flags[&"test-feature-b".to_owned()].get(),
            1,
        );
    }
}
