//! Prometheus metrics for consensus.

use pluto_core::types::Duty;
use vise::{Counter, Gauge, Histogram, LabeledFamily, Metrics};

use crate::{protocols::QBFT_V2_PROTOCOL_ID, timer::TimerType};

/// Histogram buckets for consensus duration metrics.
pub const CONSENSUS_DURATION_BUCKETS: [f64; 17] = [
    0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.25, 2.5, 2.75, 3.0, 5.0,
];

type ProtocolDutyTimerLabels = (String, String, String);
type ProtocolDutyLabels = (String, String);

/// Metrics for consensus protocols.
#[derive(Debug, Metrics)]
#[metrics(prefix = "core_consensus")]
pub struct ConsensusMetrics {
    /// Number of decided rounds by protocol, duty, and timer.
    #[metrics(labels = ["protocol", "duty", "timer"])]
    pub decided_rounds: LabeledFamily<ProtocolDutyTimerLabels, Gauge<i64>, 3>,

    /// Index of the decided leader by protocol and duty.
    #[metrics(labels = ["protocol", "duty"])]
    pub decided_leader_index: LabeledFamily<ProtocolDutyLabels, Gauge<i64>, 2>,

    /// Duration of the consensus process by protocol, duty, and timer.
    #[metrics(buckets = &CONSENSUS_DURATION_BUCKETS, labels = ["protocol", "duty", "timer"])]
    pub duration_seconds: LabeledFamily<ProtocolDutyTimerLabels, Histogram, 3>,

    /// Total count of consensus timeouts by protocol, duty, and timer.
    #[metrics(labels = ["protocol", "duty", "timer"])]
    pub timeout_total: LabeledFamily<ProtocolDutyTimerLabels, Counter, 3>,

    /// Total count of consensus errors by protocol.
    #[metrics(labels = ["protocol"])]
    pub error_total: LabeledFamily<String, Counter>,
}

impl ConsensusMetrics {
    /// Sets the number of decided rounds for a duty and timer.
    pub fn set_decided_rounds(&self, protocol: &str, duty: &str, timer: &str, rounds: i64) {
        self.decided_rounds[&labels(protocol, duty, timer)].set(rounds);
    }

    /// Sets the decided leader index for a duty.
    pub fn set_decided_leader_index(&self, protocol: &str, duty: &str, leader_index: i64) {
        self.decided_leader_index[&(protocol.to_owned(), duty.to_owned())].set(leader_index);
    }

    /// Observes the consensus duration for a duty and timer.
    pub fn observe_consensus_duration(
        &self,
        protocol: &str,
        duty: &str,
        timer: &str,
        duration_seconds: f64,
    ) {
        self.duration_seconds[&labels(protocol, duty, timer)].observe(duration_seconds);
    }

    /// Increments the consensus timeout counter for a duty and timer.
    pub fn inc_consensus_timeout(&self, protocol: &str, duty: &str, timer: &str) {
        self.timeout_total[&labels(protocol, duty, timer)].inc();
    }

    /// Increments the consensus error counter.
    pub fn inc_consensus_error(&self, protocol: &str) {
        self.error_total[protocol].inc();
    }
}

/// Global metrics for consensus.
#[vise::register]
pub static CONSENSUS_METRICS: vise::Global<ConsensusMetrics> = vise::Global::new();

/// Records the metrics emitted when QBFT decides a duty.
pub(crate) fn record_qbft_decision(
    duty: &Duty,
    timer_type: TimerType,
    round: i64,
    leader_index: i64,
) {
    let duty = duty.duty_type.to_string();
    let timer = timer_type.as_str();

    CONSENSUS_METRICS.set_decided_leader_index(QBFT_V2_PROTOCOL_ID, &duty, leader_index);
    CONSENSUS_METRICS.set_decided_rounds(QBFT_V2_PROTOCOL_ID, &duty, timer, round);
}

/// Records QBFT consensus duration after a local proposal decides.
pub(crate) fn observe_qbft_consensus_duration(
    duty: &Duty,
    timer_type: TimerType,
    duration_seconds: f64,
) {
    let duty = duty.duty_type.to_string();
    let timer = timer_type.as_str();
    CONSENSUS_METRICS.observe_consensus_duration(
        QBFT_V2_PROTOCOL_ID,
        &duty,
        timer,
        duration_seconds,
    );
}

/// Records a QBFT consensus timeout.
pub(crate) fn inc_qbft_consensus_timeout(duty: &Duty, timer_type: TimerType) {
    let duty = duty.duty_type.to_string();
    CONSENSUS_METRICS.inc_consensus_timeout(QBFT_V2_PROTOCOL_ID, &duty, timer_type.as_str());
}

/// Records a QBFT core consensus error.
pub(crate) fn inc_qbft_consensus_error() {
    CONSENSUS_METRICS.inc_consensus_error(QBFT_V2_PROTOCOL_ID);
}

fn labels(protocol: &str, duty: &str, timer: &str) -> ProtocolDutyTimerLabels {
    (protocol.to_owned(), duty.to_owned(), timer.to_owned())
}

#[cfg(test)]
mod tests {
    use vise::{Format, Registry};

    use super::*;

    #[test]
    fn decided_rounds_records_metric_name_labels_and_value() {
        let metrics = ConsensusMetrics::default();
        metrics.set_decided_rounds("test", "duty", "timer", 1);

        let output = encode(&metrics);

        assert!(output.contains(
            r#"core_consensus_decided_rounds{protocol="test",duty="duty",timer="timer"} 1"#
        ));
    }

    #[test]
    fn decided_leader_index_records_metric_name_labels_and_value() {
        let metrics = ConsensusMetrics::default();
        metrics.set_decided_leader_index("test", "duty", 123);

        let output = encode(&metrics);

        assert!(
            output.contains(
                r#"core_consensus_decided_leader_index{protocol="test",duty="duty"} 123"#
            )
        );
    }

    #[test]
    fn duration_records_metric_name_labels_and_exact_buckets() {
        let metrics = ConsensusMetrics::default();
        metrics.observe_consensus_duration("test", "duty", "timer", 1.0);

        let output = encode(&metrics);

        assert!(output.contains(
            r#"core_consensus_duration_seconds_count{protocol="test",duty="duty",timer="timer"} 1"#
        ));
        for bucket in [
            "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "0.75", "1.0", "1.25", "1.5", "1.75",
            "2.0", "2.25", "2.5", "2.75", "3.0", "5.0",
        ] {
            assert!(
                output.contains(&format!(
                    r#"core_consensus_duration_seconds_bucket{{le="{bucket}",protocol="test",duty="duty",timer="timer"}}"#
                )),
                "missing bucket {bucket}: {output}"
            );
        }
    }

    #[test]
    fn timeout_records_metric_name_labels_and_value() {
        let metrics = ConsensusMetrics::default();
        metrics.inc_consensus_timeout("test", "duty", "timer");

        let output = encode(&metrics);

        assert!(output.contains(
            r#"core_consensus_timeout_total{protocol="test",duty="duty",timer="timer"} 1"#
        ));
    }

    #[test]
    fn error_records_metric_name_labels_and_value() {
        let metrics = ConsensusMetrics::default();
        metrics.inc_consensus_error("test");

        let output = encode(&metrics);

        assert!(output.contains(r#"core_consensus_error_total{protocol="test"} 1"#));
    }

    fn encode(metrics: &ConsensusMetrics) -> String {
        let mut registry = Registry::empty();
        registry.register_metrics(metrics);

        let mut output = String::new();
        registry.encode(&mut output, Format::Prometheus).unwrap();
        output
    }
}
