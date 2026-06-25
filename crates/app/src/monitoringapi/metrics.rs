//! Metrics published by the monitoring readiness checker.

use vise::{Gauge, Global, Metrics};

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
}

/// Global monitoring metrics.
#[vise::register]
pub static MONITORING_METRICS: Global<MonitoringMetrics> = Global::new();
