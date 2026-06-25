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
