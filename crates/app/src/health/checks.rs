//! Health checks: severity, cluster metadata, the check type, the fixed list of
//! 9 checks, and the label-pair helper.

use super::{
    checker::QueryFunc,
    error::Result,
    model::LabelPair,
    reducers::{gauge_max, increase},
    select::{count_labels, count_non_zero_labels, no_labels, sum_labels},
};

/// Severity of a health check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Severity {
    /// Critical: the node is likely not performing its duties.
    Critical,
    /// Warning: something needs attention.
    Warning,
    /// Info: informational only.
    Info,
}

impl Severity {
    /// Returns the lowercase string used as the `severity` label value.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }
}

/// Metadata about the cluster, used by the health checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct Metadata {
    /// Number of validators in the cluster.
    pub num_validators: i64,
    /// Number of peers in the cluster.
    pub num_peers: i64,
    /// Number of peers required for quorum.
    pub quorum_peers: i64,
}

/// A health check.
pub(crate) struct Check {
    /// Name of the check (also the `name` label value).
    pub(crate) name: &'static str,
    /// Human-readable description. Not yet surfaced anywhere; retained for
    /// completeness.
    #[allow(
        dead_code,
        reason = "retained for completeness; surfaced by future tooling"
    )]
    pub(crate) description: &'static str,
    /// Severity.
    pub(crate) severity: Severity,
    /// Returns true if the check is failing.
    pub(crate) func: fn(&QueryFunc<'_>, &Metadata) -> Result<bool>,
}

/// Convenience constructor for a label pair.
fn label(name: &str, value: &str) -> LabelPair {
    LabelPair {
        name: name.to_owned(),
        value: value.to_owned(),
    }
}

/// Lossy `i64` → `f64` conversion used only for threshold comparisons.
#[allow(
    clippy::cast_precision_loss,
    reason = "validator/peer counts are small; threshold comparison does not require exactness"
)]
fn to_f64(n: i64) -> f64 {
    n as f64
}

fn high_error_log_rate(q: &QueryFunc<'_>, m: &Metadata) -> Result<bool> {
    // Allow 2 errors per validator.
    let value = q.query("app_log_error_total", sum_labels(Vec::new()), increase)?;
    Ok(value > 2.0 * to_f64(m.num_validators))
}

fn high_warning_log_rate(q: &QueryFunc<'_>, m: &Metadata) -> Result<bool> {
    // Deviation from Charon: Charon's check queries `app_log_warning_total`,
    // but the warn counter is emitted as `app_log_warn_total`, so Charon's own
    // check never matches it. We query the emitted name so this check fires.
    // Allow 2 warnings per validator.
    let value = q.query("app_log_warn_total", sum_labels(Vec::new()), increase)?;
    Ok(value > 2.0 * to_f64(m.num_validators))
}

fn beacon_node_syncing(q: &QueryFunc<'_>, _m: &Metadata) -> Result<bool> {
    let max_val = q.query("app_monitoring_beacon_node_syncing", no_labels(), gauge_max)?;
    Ok(max_val == 1.0)
}

fn insufficient_connected_peers(q: &QueryFunc<'_>, m: &Metadata) -> Result<bool> {
    let max_val = q.query("p2p_ping_success", count_non_zero_labels(), gauge_max)?;
    let required = to_f64(m.quorum_peers) - 1.0; // Exclude self.
    Ok(max_val < required)
}

fn pending_validators(q: &QueryFunc<'_>, _m: &Metadata) -> Result<bool> {
    let max_val = q.query(
        "core_scheduler_validator_status",
        count_labels(vec![label("status", "pending")]),
        gauge_max,
    )?;
    Ok(max_val > 0.0)
}

fn proposal_failures(q: &QueryFunc<'_>, _m: &Metadata) -> Result<bool> {
    let value = q.query(
        "core_tracker_failed_duties_total",
        sum_labels(vec![label("duty", ".*proposal")]),
        increase,
    )?;
    Ok(value > 0.0)
}

fn high_registration_failures_rate(q: &QueryFunc<'_>, _m: &Metadata) -> Result<bool> {
    let value = q.query(
        "core_bcast_recast_errors_total",
        sum_labels(Vec::new()),
        increase,
    )?;
    Ok(value > 0.0)
}

fn metrics_high_cardinality(q: &QueryFunc<'_>, _m: &Metadata) -> Result<bool> {
    let max_val = q.query(
        "app_health_metrics_high_cardinality",
        sum_labels(Vec::new()),
        gauge_max,
    )?;
    Ok(max_val > 0.0)
}

fn using_fallback_beacon_nodes(q: &QueryFunc<'_>, _m: &Metadata) -> Result<bool> {
    let max_val = q.query("app_eth2_using_fallback", sum_labels(Vec::new()), gauge_max)?;
    Ok(max_val > 0.0)
}

/// The full set of health checks.
pub(crate) const CHECKS: [Check; 9] = [
    Check {
        name: "high_error_log_rate",
        description: "High rate of error logs. Please check the logs for more details.",
        severity: Severity::Warning,
        func: high_error_log_rate,
    },
    Check {
        name: "high_warning_log_rate",
        description: "High rate of warning logs. Please check the logs for more details.",
        severity: Severity::Warning,
        func: high_warning_log_rate,
    },
    Check {
        name: "beacon_node_syncing",
        description: "Beacon Node in syncing state.",
        severity: Severity::Critical,
        func: beacon_node_syncing,
    },
    Check {
        name: "insufficient_connected_peers",
        description: "Not connected to at least quorum peers. Check logs for networking issue or coordinate with peers.",
        severity: Severity::Critical,
        func: insufficient_connected_peers,
    },
    Check {
        name: "pending_validators",
        description: "Pending validators detected. Activate them to start validating.",
        severity: Severity::Info,
        func: pending_validators,
    },
    Check {
        name: "proposal_failures",
        description: "Proposal failures detected. See <link to troubleshoot proposal failures>.",
        severity: Severity::Warning,
        func: proposal_failures,
    },
    Check {
        name: "high_registration_failures_rate",
        description: "High rate of failed validator registrations. Please check the logs for more details.",
        severity: Severity::Warning,
        func: high_registration_failures_rate,
    },
    Check {
        name: "metrics_high_cardinality",
        description: "Metrics reached high cardinality threshold. Please check metrics reported by app_health_metrics_high_cardinality.",
        severity: Severity::Warning,
        func: metrics_high_cardinality,
    },
    Check {
        name: "using_fallback_beacon_nodes",
        description: "Using fallback beacon nodes. Please check primary beacon nodes health.",
        severity: Severity::Warning,
        func: using_fallback_beacon_nodes,
    },
];

#[cfg(test)]
mod tests {
    //! Tests for the checks and the query function.

    use super::{CHECKS, Metadata};
    use crate::health::{
        checker::new_query_func,
        model::{LabelPair, Metric, MetricFamily, MetricType, SampleValue},
    };

    fn gen_labels(name_vals: &[&str]) -> Vec<LabelPair> {
        assert!(
            name_vals.len().is_multiple_of(2),
            "must have even number of name/value pairs"
        );
        name_vals
            .chunks(2)
            .map(|c| LabelPair {
                name: c[0].to_owned(),
                value: c[1].to_owned(),
            })
            .collect()
    }

    fn gen_counter(labels: &[LabelPair], values: &[i32]) -> Vec<Metric> {
        values
            .iter()
            .map(|&v| Metric {
                labels: labels.to_vec(),
                value: Some(SampleValue::Counter(f64::from(v))),
            })
            .collect()
    }

    fn gen_gauge(labels: &[LabelPair], values: &[i32]) -> Vec<Metric> {
        values
            .iter()
            .map(|&v| Metric {
                labels: labels.to_vec(),
                value: Some(SampleValue::Gauge(f64::from(v))),
            })
            .collect()
    }

    /// Transposes a set of series (series × time) into per-scrape families
    /// (time × family).
    fn gen_fam(name: &str, series: &[Vec<Metric>]) -> Vec<MetricFamily> {
        let metric_type = if series
            .first()
            .and_then(|s| s.first())
            .map(|m| matches!(m.value, Some(SampleValue::Gauge(_))))
            .unwrap_or(false)
        {
            MetricType::Gauge
        } else {
            MetricType::Counter
        };

        let max_len = series.iter().map(Vec::len).max().unwrap_or(0);
        let mut resp: Vec<MetricFamily> = (0..max_len)
            .map(|_| MetricFamily {
                name: name.to_owned(),
                metric_type,
                metrics: Vec::new(),
            })
            .collect();

        for s in series {
            for (i, metric) in s.iter().enumerate() {
                resp[i].metrics.push(metric.clone());
            }
        }

        resp
    }

    /// Interleaves the check's per-scrape families with two noise families,
    /// runs the named check, and asserts the outcome.
    fn test_check(m: &Metadata, check_name: &str, expect: bool, metrics: Vec<MetricFamily>) {
        let random_foo = gen_fam(
            "foo",
            &[
                gen_counter(&gen_labels(&["foo", "foo1"]), &[1, 2, 3]),
                gen_counter(&gen_labels(&["foo", "foo2"]), &[1, 4, 8]),
            ],
        );
        let random_bar = gen_fam(
            "bar",
            &[
                gen_gauge(&gen_labels(&["bar", "bar1"]), &[1, 1, 4]),
                gen_gauge(&gen_labels(&["bar", "bar2"]), &[1, 1, 1]),
            ],
        );

        let max_len = metrics.len().max(random_foo.len()).max(random_bar.len());
        let mut multi: Vec<Vec<MetricFamily>> = Vec::with_capacity(max_len);
        for i in 0..max_len {
            let mut fam = Vec::new();
            if i < metrics.len() {
                fam.push(metrics[i].clone());
            }
            if i < random_foo.len() {
                fam.push(random_foo[i].clone());
            }
            if i < random_bar.len() {
                fam.push(random_bar[i].clone());
            }
            multi.push(fam);
        }

        let query = new_query_func(&multi);
        let check = CHECKS
            .iter()
            .find(|c| c.name == check_name)
            .expect("check not found");
        let failed = (check.func)(&query, m).expect("check should not error");
        assert_eq!(failed, expect);
    }

    #[test]
    fn proposal_failures_check() {
        let m = Metadata {
            quorum_peers: 2,
            ..Metadata::default()
        };
        let name = "proposal_failures";
        let metric = "core_tracker_failed_duties_total";

        let proposal_full = gen_labels(&["duty", "proposal"]);
        let proposal_blind = gen_labels(&["duty", "builder_proposal"]);
        let attestation = gen_labels(&["duty", "attester"]);

        // no data
        test_check(&m, name, false, Vec::new());

        // no failures
        test_check(
            &m,
            name,
            false,
            gen_fam(
                metric,
                &[
                    gen_counter(&proposal_full, &[1, 1, 1, 1]),
                    gen_counter(&proposal_blind, &[0, 0, 0, 0]),
                    gen_counter(&attestation, &[2, 2, 2, 2]),
                ],
            ),
        );

        // full proposal failures
        test_check(
            &m,
            name,
            true,
            gen_fam(
                metric,
                &[
                    gen_counter(&proposal_full, &[0, 0, 1, 1]),
                    gen_counter(&proposal_blind, &[0, 0, 0, 0]),
                    gen_counter(&attestation, &[0, 0, 0, 0]),
                ],
            ),
        );

        // blind proposal failures
        test_check(
            &m,
            name,
            true,
            gen_fam(
                metric,
                &[
                    gen_counter(&proposal_full, &[0, 0, 0, 0]),
                    gen_counter(&proposal_blind, &[0, 0, 1, 1]),
                    gen_counter(&attestation, &[0, 0, 0, 0]),
                ],
            ),
        );

        // attestation failures
        test_check(
            &m,
            name,
            false,
            gen_fam(
                metric,
                &[
                    gen_counter(&proposal_full, &[0, 0, 0, 0]),
                    gen_counter(&proposal_blind, &[0, 0, 0, 0]),
                    gen_counter(&attestation, &[0, 0, 1, 1]),
                ],
            ),
        );

        // multiple failures
        test_check(
            &m,
            name,
            true,
            gen_fam(
                metric,
                &[
                    gen_counter(&proposal_full, &[0, 0, 1, 1]),
                    gen_counter(&proposal_blind, &[0, 0, 1, 1]),
                    gen_counter(&attestation, &[0, 0, 1, 1]),
                ],
            ),
        );
    }

    #[test]
    fn pending_validators_check() {
        let m = Metadata {
            quorum_peers: 2,
            ..Metadata::default()
        };
        let name = "pending_validators";
        let metric = "core_scheduler_validator_status";

        let val1_pending = gen_labels(&["pubkey", "1", "status", "pending"]);
        let val1_active = gen_labels(&["pubkey", "1", "status", "active"]);
        let val2_active = gen_labels(&["pubkey", "2", "status", "active"]);
        let val3_pending = gen_labels(&["pubkey", "3", "status", "pending"]);

        // no data
        test_check(&m, name, false, Vec::new());

        // single active
        test_check(
            &m,
            name,
            false,
            gen_fam(metric, &[gen_gauge(&val1_active, &[1, 1, 1, 1])]),
        );

        // single pending
        test_check(
            &m,
            name,
            true,
            gen_fam(metric, &[gen_gauge(&val1_pending, &[1, 1, 1, 1])]),
        );

        // single activated
        test_check(
            &m,
            name,
            true,
            gen_fam(
                metric,
                &[
                    gen_gauge(&val1_pending, &[1, 1, 0, 0]),
                    gen_gauge(&val1_active, &[0, 0, 1, 1]),
                ],
            ),
        );

        // 1o3 pending
        test_check(
            &m,
            name,
            true,
            gen_fam(
                metric,
                &[
                    gen_gauge(&val1_pending, &[0, 0, 0, 0]),
                    gen_gauge(&val1_active, &[1, 1, 1, 1]),
                    gen_gauge(&val2_active, &[1, 1, 1, 1]),
                    gen_gauge(&val3_pending, &[1, 1, 1, 1]),
                ],
            ),
        );
    }

    #[test]
    fn insufficient_peer_check() {
        let m = Metadata {
            quorum_peers: 2,
            ..Metadata::default()
        };
        let name = "insufficient_connected_peers";
        let metric = "p2p_ping_success";

        let peer1 = gen_labels(&["peer", "1"]);
        let peer2 = gen_labels(&["peer", "2"]);
        let peer3 = gen_labels(&["peer", "3"]);

        // no data
        test_check(&m, name, true, Vec::new());

        // no peers
        test_check(
            &m,
            name,
            true,
            gen_fam(
                metric,
                &[
                    gen_gauge(&peer1, &[0, 0, 0, 0]),
                    gen_gauge(&peer2, &[0, 0, 0, 0]),
                    gen_gauge(&peer3, &[0, 0, 0, 0]),
                ],
            ),
        );

        // all peers
        test_check(
            &m,
            name,
            false,
            gen_fam(
                metric,
                &[
                    gen_gauge(&peer1, &[1, 1, 1]),
                    gen_gauge(&peer2, &[1, 1, 1]),
                    gen_gauge(&peer3, &[1, 1, 1]),
                ],
            ),
        );

        // quorum peers
        test_check(
            &m,
            name,
            false,
            gen_fam(
                metric,
                &[
                    gen_gauge(&peer1, &[0, 0, 0]),
                    gen_gauge(&peer2, &[1, 1, 1]),
                    gen_gauge(&peer3, &[1, 1, 1]),
                ],
            ),
        );

        // blip
        test_check(
            &m,
            name,
            false,
            gen_fam(
                metric,
                &[
                    gen_gauge(&peer1, &[1, 0, 1]),
                    gen_gauge(&peer2, &[1, 0, 1]),
                    gen_gauge(&peer3, &[1, 0, 1]),
                ],
            ),
        );
    }

    #[test]
    fn bn_syncing_check() {
        let m = Metadata::default();
        let name = "beacon_node_syncing";
        let metric = "app_monitoring_beacon_node_syncing";

        // no data
        test_check(&m, name, false, Vec::new());

        // single zero
        test_check(&m, name, false, gen_fam(metric, &[gen_gauge(&[], &[0])]));

        // multiple constants
        test_check(
            &m,
            name,
            true,
            gen_fam(metric, &[gen_gauge(&[], &[1, 1, 1])]),
        );

        // blip
        test_check(
            &m,
            name,
            true,
            gen_fam(metric, &[gen_gauge(&[], &[0, 1, 0])]),
        );
    }

    #[test]
    fn error_logs_check() {
        let m = Metadata {
            num_validators: 10,
            ..Metadata::default()
        };
        let name = "high_error_log_rate";
        let metric = "app_log_error_total";

        let topic_a = gen_labels(&["topic", "a"]);
        let topic_b = gen_labels(&["topic", "b"]);

        // no data
        test_check(&m, name, false, Vec::new());

        // single zero
        test_check(
            &m,
            name,
            false,
            gen_fam(metric, &[gen_counter(&topic_a, &[0])]),
        );

        // multiple zeros
        test_check(
            &m,
            name,
            false,
            gen_fam(
                metric,
                &[
                    gen_counter(&topic_a, &[0, 0, 0]),
                    gen_counter(&topic_b, &[0, 0, 0]),
                ],
            ),
        );

        // multiple constants
        test_check(
            &m,
            name,
            false,
            gen_fam(metric, &[gen_counter(&topic_a, &[1, 1, 1])]),
        );

        // too few
        test_check(
            &m,
            name,
            false,
            gen_fam(metric, &[gen_counter(&topic_a, &[0, 0, 10])]),
        );

        // too few multi
        test_check(
            &m,
            name,
            false,
            gen_fam(
                metric,
                &[
                    gen_counter(&topic_a, &[0, 0, 5]),
                    gen_counter(&topic_b, &[0, 0, 5]),
                ],
            ),
        );

        // sufficient
        test_check(
            &m,
            name,
            true,
            gen_fam(metric, &[gen_counter(&topic_a, &[10, 20, 30, 40, 500])]),
        );
    }

    #[test]
    fn warn_logs_check() {
        let m = Metadata {
            num_validators: 10,
            ..Metadata::default()
        };
        let name = "high_warning_log_rate";
        let metric = "app_log_warn_total";

        let topic_a = gen_labels(&["topic", "a"]);
        let topic_b = gen_labels(&["topic", "b"]);

        // no data
        test_check(&m, name, false, Vec::new());

        // single zero
        test_check(
            &m,
            name,
            false,
            gen_fam(metric, &[gen_counter(&topic_a, &[0])]),
        );

        // multiple zeros
        test_check(
            &m,
            name,
            false,
            gen_fam(
                metric,
                &[
                    gen_counter(&topic_a, &[0, 0, 0]),
                    gen_counter(&topic_b, &[0, 0, 0]),
                ],
            ),
        );

        // multiple constants
        test_check(
            &m,
            name,
            false,
            gen_fam(metric, &[gen_counter(&topic_a, &[1, 1, 1])]),
        );

        // too few
        test_check(
            &m,
            name,
            false,
            gen_fam(metric, &[gen_counter(&topic_a, &[0, 0, 10])]),
        );

        // too few multi
        test_check(
            &m,
            name,
            false,
            gen_fam(
                metric,
                &[
                    gen_counter(&topic_a, &[0, 0, 5]),
                    gen_counter(&topic_b, &[0, 0, 5]),
                ],
            ),
        );

        // sufficient
        test_check(
            &m,
            name,
            true,
            gen_fam(metric, &[gen_counter(&topic_a, &[10, 20, 30, 40, 500])]),
        );
    }

    #[test]
    fn high_registration_failures_rate_check() {
        let m = Metadata::default();
        let name = "high_registration_failures_rate";
        let metric = "core_bcast_recast_errors_total";

        let pregen = gen_labels(&["source", "pregen"]);
        let downstream = gen_labels(&["source", "downstream"]);

        // no data
        test_check(&m, name, false, Vec::new());

        // same errors count
        test_check(
            &m,
            name,
            false,
            gen_fam(metric, &[gen_gauge(&pregen, &[1, 1, 1])]),
        );

        // incrementing errors count
        test_check(
            &m,
            name,
            true,
            gen_fam(metric, &[gen_gauge(&downstream, &[0, 1, 2, 10])]),
        );

        // both labels have stable errors count
        test_check(
            &m,
            name,
            false,
            gen_fam(
                metric,
                &[
                    gen_gauge(&pregen, &[1, 1, 1]),
                    gen_gauge(&downstream, &[1, 1, 1]),
                ],
            ),
        );

        // both labels have increasing errors count
        test_check(
            &m,
            name,
            true,
            gen_fam(
                metric,
                &[
                    gen_gauge(&pregen, &[10, 15, 18]),
                    gen_gauge(&downstream, &[1, 2, 3]),
                ],
            ),
        );
    }

    #[test]
    fn metrics_high_cardinality_check() {
        let m = Metadata::default();
        let name = "metrics_high_cardinality";
        let metric = "app_health_metrics_high_cardinality";

        // no data
        test_check(&m, name, false, Vec::new());

        // high cardinality
        test_check(
            &m,
            name,
            true,
            gen_fam(
                metric,
                &[
                    gen_gauge(&gen_labels(&["name", "metric1"]), &[1, 1, 1]),
                    gen_gauge(&gen_labels(&["name", "metric2"]), &[3, 5, 0]),
                ],
            ),
        );
    }

    #[test]
    fn using_fallback_beacon_nodes_check() {
        let m = Metadata::default();
        let name = "using_fallback_beacon_nodes";
        let metric = "app_eth2_using_fallback";

        // no data
        test_check(&m, name, false, Vec::new());

        // no fallback
        test_check(
            &m,
            name,
            false,
            gen_fam(metric, &[gen_gauge(&[], &[0, 0, 0])]),
        );

        // single fallback
        test_check(
            &m,
            name,
            true,
            gen_fam(metric, &[gen_gauge(&[], &[0, 1, 0])]),
        );
    }
}
