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
}

/// Global cluster metrics.
#[vise::register]
pub static CLUSTER_METRICS: Global<ClusterMetrics> = Global::new();

/// Sets the constant startup gauges — version, peer name, git commit, start
/// time — and the cluster-lock gauges, mirroring Charon's `initStartupMetrics`.
///
/// The version/peer-name/git-commit gauges are constant series (value 1) whose
/// single purpose is to expose their label; the dashboard reads those labels.
pub fn init_startup_metrics(
    version: &str,
    peer_name: &str,
    git_hash: &str,
    start_time_secs: i64,
    threshold: i64,
    operators: i64,
    validators: i64,
) {
    MONITORING_METRICS.version[&version.to_owned()].set(1);
    MONITORING_METRICS.peer_name[&peer_name.to_owned()].set(1);
    MONITORING_METRICS.git_commit[&git_hash.to_owned()].set(1);
    MONITORING_METRICS.start_time_secs.set(start_time_secs);

    CLUSTER_METRICS.threshold.set(threshold);
    CLUSTER_METRICS.operators.set(operators);
    CLUSTER_METRICS.validators.set(validators);
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
}
