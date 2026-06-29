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
}

/// Global monitoring metrics.
#[vise::register]
pub static MONITORING_METRICS: Global<MonitoringMetrics> = Global::new();

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
