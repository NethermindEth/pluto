//! Prometheus metrics for the tracker.

use vise::*;

/// Metrics for the duty tracker.
#[derive(Debug, Metrics)]
#[metrics(prefix = "core_tracker")]
pub struct TrackerMetrics {
    /// Set to 1 if peer participated successfully for the given duty or
    /// else 0.
    #[metrics(labels = ["duty", "peer"])]
    pub participation: LabeledFamily<(String, String), Gauge, 2>,

    /// Total number of successful participations by peer and duty type.
    #[metrics(labels = ["duty", "peer"])]
    pub participation_success_total: LabeledFamily<(String, String), Counter, 2>,

    /// Total number of missed participations by peer and duty type.
    #[metrics(labels = ["duty", "peer"])]
    pub participation_missed_total: LabeledFamily<(String, String), Counter, 2>,

    /// Total number of expected participations (fail + success) by peer
    /// and duty type.
    #[metrics(labels = ["duty", "peer"])]
    pub participation_expected_total: LabeledFamily<(String, String), Counter, 2>,

    /// Total number of failed duties by type.
    #[metrics(labels = ["duty"])]
    pub failed_duties_total: LabeledFamily<String, Counter>,

    /// Total number of failed duties by type and reason code.
    #[metrics(labels = ["duty", "reason"])]
    pub failed_duty_reasons_total: LabeledFamily<(String, String), Counter, 2>,

    /// Total number of successful duties by type.
    #[metrics(labels = ["duty"])]
    pub success_duties_total: LabeledFamily<String, Counter>,

    /// Total number of expected duties (failed + success) by type.
    #[metrics(labels = ["duty"])]
    pub expect_duties_total: LabeledFamily<String, Counter>,

    /// Total number of unexpected events by peer.
    #[metrics(labels = ["peer"])]
    pub unexpected_events_total: LabeledFamily<String, Counter>,

    /// Total number of duties that contained inconsistent partial signed
    /// data by duty type.
    #[metrics(labels = ["duty"])]
    pub inconsistent_parsigs_total: LabeledFamily<String, Counter>,

    /// Cluster's average attestation inclusion delay in slots. Available
    /// only when the attestation_inclusion feature flag is enabled.
    pub inclusion_delay: Gauge<f64>,

    /// Total number of broadcast duties never included in any block by
    /// type.
    #[metrics(labels = ["duty"])]
    pub inclusion_missed_total: LabeledFamily<String, Counter>,
}

/// Global metrics for the duty tracker.
#[vise::register]
pub static TRACKER_METRICS: Global<TrackerMetrics> = Global::new();
