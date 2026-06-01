//! Reporters that consume duty analysis results and emit metrics + logs.

use std::collections::HashMap;

use crate::{
    tracker::{
        PeerInfo,
        analysis::{DutyFailure, ParSigsByMsg, expect_inconsistent_par_sigs, msg_roots_consistent},
        metrics::TRACKER_METRICS,
        reason::{REASON_SYNC_CONTRIBUTION_ZERO_PREPARES, REASON_ZERO_AGGREGATOR_SELECTIONS},
        step::Step,
    },
    types::{Duty, DutyType},
};

pub(crate) trait DutyResultReporter: Send {
    fn report(&mut self, duty: &Duty, failed: bool, result: &DutyFailure);
}

pub(crate) trait ParticipationReporter: Send {
    fn report(
        &mut self,
        duty: &Duty,
        failed: bool,
        participated: &HashMap<u64, usize>,
        unexpected: &HashMap<u64, usize>,
        expected_per_peer: usize,
    );
}

/// Logs and reports failed/successful duties to Prometheus.
pub struct MetricsDutyReporter;

impl MetricsDutyReporter {
    /// Creates a reporter and zero-initialises per-duty-type counters so that
    /// Prometheus exports them even before the first event fires.
    pub fn new() -> Self {
        for dt in DutyType::all() {
            let dt_str = dt.to_string();
            TRACKER_METRICS.failed_duties_total[&dt_str].inc_by(0);
            TRACKER_METRICS.success_duties_total[&dt_str].inc_by(0);
            TRACKER_METRICS.expect_duties_total[&dt_str].inc_by(0);
        }
        Self
    }

    /// Reports the outcome of a duty: logs a warning on failure and updates
    /// per-duty counters. On success only `result.step` is read.
    pub fn report(&self, duty: &Duty, failed: bool, result: &DutyFailure) {
        if !failed {
            // Skip fetcher-level success counts to avoid double-counting duties
            // (matches Go's TODO around aggregator detection).
            if result.step == Step::Fetcher {
                return;
            }
            let dt = duty.duty_type.to_string();
            TRACKER_METRICS.expect_duties_total[&dt].inc();
            TRACKER_METRICS.success_duties_total[&dt].inc();
            return;
        }

        match result.err.as_ref() {
            Some(e) => tracing::warn!(
                step = %result.step,
                reason = %result.reason.short,
                reason_code = %result.reason.code,
                error = %e,
                duty = %duty,
                "Duty failed",
            ),
            None => tracing::warn!(
                step = %result.step,
                reason = %result.reason.short,
                reason_code = %result.reason.code,
                duty = %duty,
                "Duty failed",
            ),
        }

        let dt = duty.duty_type.to_string();
        TRACKER_METRICS.expect_duties_total[&dt].inc();
        TRACKER_METRICS.failed_duties_total[&dt].inc();
        TRACKER_METRICS.failed_duty_reasons_total[&(dt, result.reason.code.to_string())].inc();
    }
}

impl Default for MetricsDutyReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl DutyResultReporter for MetricsDutyReporter {
    fn report(&mut self, duty: &Duty, failed: bool, result: &DutyFailure) {
        MetricsDutyReporter::report(self, duty, failed, result);
    }
}

/// Suppresses repeated noise from duty types unsupported by the cluster's VCs
/// (attestation aggregation, sync committee contribution).
///
/// Mirrors Go's `newUnsupportedIgnorer` closure.
pub struct UnsupportedIgnorer {
    logged_no_aggregator: bool,
    logged_no_contribution: bool,
    aggregation_supported: bool,
    contribution_supported: bool,
}

impl UnsupportedIgnorer {
    /// Creates a fresh ignorer with no logged state.
    pub fn new() -> Self {
        Self {
            logged_no_aggregator: false,
            logged_no_contribution: false,
            aggregation_supported: false,
            contribution_supported: false,
        }
    }

    /// Returns true if this duty failure should be ignored — i.e. it's an
    /// unsupported feature we've already warned about. Also tracks
    /// successful aggregator/sync-contribution duties so future failures
    /// aren't silenced.
    pub fn check(&mut self, duty: &Duty, outcome: Option<&DutyFailure>) -> bool {
        let Some(f) = outcome else {
            if duty.duty_type == DutyType::Aggregator {
                self.aggregation_supported = true;
            }
            if duty.duty_type == DutyType::SyncContribution {
                self.contribution_supported = true;
            }
            return false;
        };

        if !self.aggregation_supported
            && duty.duty_type == DutyType::Aggregator
            && f.step == Step::Fetcher
            && f.reason == REASON_ZERO_AGGREGATOR_SELECTIONS
        {
            if !self.logged_no_aggregator {
                tracing::warn!(
                    "Ignoring attestation aggregation failures since VCs do not seem to support beacon committee selection aggregation",
                );
            }
            self.logged_no_aggregator = true;
            return true;
        }

        if !self.contribution_supported
            && duty.duty_type == DutyType::SyncContribution
            && f.step == Step::Fetcher
            && f.reason == REASON_SYNC_CONTRIBUTION_ZERO_PREPARES
        {
            if !self.logged_no_contribution {
                tracing::warn!(
                    "Ignoring sync contribution failures since VCs do not seem to support sync committee selection aggregation",
                );
            }
            self.logged_no_contribution = true;
            return true;
        }

        false
    }
}

impl Default for UnsupportedIgnorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Reports per-peer duty participation to metrics and logs absence changes.
pub struct MetricsParticipationReporter {
    peers: Vec<PeerInfo>,
    prev_absent: HashMap<DutyType, Vec<String>>,
}

impl MetricsParticipationReporter {
    /// Creates a reporter and zero-initialises per-peer × per-duty counters
    /// so that Prometheus exports them before the first event.
    pub fn new(peers: Vec<PeerInfo>) -> Self {
        for dt in DutyType::all() {
            let dt_str = dt.to_string();
            for peer in &peers {
                let labels = (dt_str.clone(), peer.name.clone());
                TRACKER_METRICS.participation_success_total[&labels].inc_by(0);
                TRACKER_METRICS.participation_missed_total[&labels].inc_by(0);
                TRACKER_METRICS.participation_expected_total[&labels].inc_by(0);
            }
        }
        Self {
            peers,
            prev_absent: HashMap::new(),
        }
    }

    /// Reports per-peer participation for a duty: updates counters, sets the
    /// participation gauge, and logs absence changes.
    pub fn report(
        &mut self,
        duty: &Duty,
        failed: bool,
        participated: &HashMap<u64, usize>,
        unexpected: &HashMap<u64, usize>,
        // Distinct validator pubkeys that had any event for this duty (matches
        // Go's pubkeyMapLen). For aggregator duties this may be fewer than the
        // cluster's total validator count if only some validators were selected.
        expected_per_peer: usize,
    ) {
        // Suppress no-op duties (e.g. aggregator slots with no selected peer)
        // unless the duty actually failed.
        if participated.is_empty() && !failed {
            return;
        }

        let mut absent: Vec<String> = Vec::new();
        let dt_str = duty.duty_type.to_string();

        for peer in &self.peers {
            let share_idx = peer.share_idx as u64;
            let part = participated.get(&share_idx).copied().unwrap_or(0);
            let unexp = unexpected.get(&share_idx).copied().unwrap_or(0);

            let labels = (dt_str.clone(), peer.name.clone());
            TRACKER_METRICS.participation_success_total[&labels].inc_by(part as u64);
            TRACKER_METRICS.participation_expected_total[&labels].inc_by(expected_per_peer as u64);
            TRACKER_METRICS.participation_missed_total[&labels]
                .inc_by(expected_per_peer.saturating_sub(part) as u64);

            if part > 0 {
                TRACKER_METRICS.participation[&labels].set(1);
            } else if unexp > 0 {
                tracing::warn!(
                    peer = %peer.name,
                    duty = %duty,
                    "Unexpected event found",
                );
                TRACKER_METRICS.unexpected_events_total[&peer.name].inc_by(unexp as u64);
            } else {
                absent.push(peer.name.clone());
                TRACKER_METRICS.participation[&labels].set(0);
            }
        }

        // Only log when the absent set changes from the previous duty of this
        // type, to avoid log spam every slot.
        if self.prev_absent.get(&duty.duty_type) != Some(&absent) {
            if absent.is_empty() {
                tracing::info!(duty = %duty, "All peers participated in duty");
            } else if absent.len() == self.peers.len() {
                tracing::info!(duty = %duty, "No peers participated in duty");
            } else {
                tracing::info!(duty = %duty, absent = ?absent, "Not all peers participated in duty");
            }
        }

        self.prev_absent.insert(duty.duty_type.clone(), absent);
    }
}

impl ParticipationReporter for MetricsParticipationReporter {
    fn report(
        &mut self,
        duty: &Duty,
        failed: bool,
        participated: &HashMap<u64, usize>,
        unexpected: &HashMap<u64, usize>,
        expected_per_peer: usize,
    ) {
        MetricsParticipationReporter::report(
            self,
            duty,
            failed,
            participated,
            unexpected,
            expected_per_peer,
        );
    }
}

/// Reports inconsistent partial signature data across peers.
pub fn report_par_sigs(duty: &Duty, parsigs: &ParSigsByMsg) {
    if msg_roots_consistent(parsigs) {
        return;
    }

    TRACKER_METRICS.inconsistent_parsigs_total[&duty.duty_type.to_string()].inc();

    for (pubkey, by_root) in parsigs {
        // Intentional fix over Go: Go checks len(parsigMsgs) (the outer map, i.e.
        // number of pubkeys) instead of the per-pubkey root count, so it
        // silently skips logging when only one pubkey has inconsistent roots
        // (tracker.go:851).
        if by_root.len() <= 1 {
            continue;
        }

        let groups: Vec<(String, Vec<u64>)> = by_root
            .iter()
            .map(|(root, sigs)| {
                let indexes: Vec<u64> = sigs.iter().map(|s| s.share_idx).collect();
                (hex::encode(root), indexes)
            })
            .collect();

        if expect_inconsistent_par_sigs(&duty.duty_type) {
            tracing::debug!(
                pubkey = %pubkey,
                duty = %duty,
                ?groups,
                "Inconsistent sync committee partial signed data",
            );
        } else {
            tracing::warn!(
                pubkey = %pubkey,
                duty = %duty,
                ?groups,
                "Inconsistent partial signed data",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tracker::reason::{REASON_BUG_AGGREGATION_ERROR, REASON_UNKNOWN},
        types::SlotNumber,
    };

    /// The ignorer is stateful, so order
    /// matters across assertions.
    #[test]
    fn unsupported_ignorer_state_machine() {
        let mut ignorer = UnsupportedIgnorer::new();

        // Attester with non-aggregator reason is never ignored.
        assert!(!ignorer.check(
            &Duty::new_attester_duty(SlotNumber::new(123)),
            Some(&DutyFailure {
                step: Step::SigAgg,
                reason: REASON_BUG_AGGREGATION_ERROR,
                err: None
            }),
        ));

        // First Aggregator / Fetcher / ZeroAggregatorSelections failure is ignored.
        assert!(ignorer.check(
            &Duty::new_aggregator_duty(SlotNumber::new(123)),
            Some(&DutyFailure {
                step: Step::Fetcher,
                reason: REASON_ZERO_AGGREGATOR_SELECTIONS,
                err: None
            }),
        ));

        // A successful Aggregator marks aggregation as supported.
        assert!(!ignorer.check(&Duty::new_aggregator_duty(SlotNumber::new(123)), None,));

        // After aggregation_supported is true, future Aggregator failures
        // are no longer ignored.
        assert!(!ignorer.check(
            &Duty::new_aggregator_duty(SlotNumber::new(123)),
            Some(&DutyFailure {
                step: Step::Fetcher,
                reason: REASON_ZERO_AGGREGATOR_SELECTIONS,
                err: None
            }),
        ));

        // First SyncContribution / Fetcher / ZeroPrepares failure is ignored.
        assert!(ignorer.check(
            &Duty::new_sync_contribution_duty(SlotNumber::new(123)),
            Some(&DutyFailure {
                step: Step::Fetcher,
                reason: REASON_SYNC_CONTRIBUTION_ZERO_PREPARES,
                err: None
            }),
        ));

        // A successful SyncContribution marks contribution as supported.
        assert!(!ignorer.check(
            &Duty::new_sync_contribution_duty(SlotNumber::new(123)),
            None,
        ));

        // Subsequent SyncContribution failures are no longer ignored.
        assert!(!ignorer.check(
            &Duty::new_sync_contribution_duty(SlotNumber::new(123)),
            Some(&DutyFailure {
                step: Step::Fetcher,
                reason: REASON_SYNC_CONTRIBUTION_ZERO_PREPARES,
                err: None
            }),
        ));
    }

    /// Unrelated reasons / steps are never ignored regardless of internal
    /// state.
    #[test]
    fn unsupported_ignorer_passes_unrelated_failures() {
        let mut ignorer = UnsupportedIgnorer::new();

        // Aggregator failure with a different reason → not ignored.
        assert!(!ignorer.check(
            &Duty::new_aggregator_duty(SlotNumber::new(1)),
            Some(&DutyFailure {
                step: Step::Fetcher,
                reason: REASON_UNKNOWN,
                err: None
            }),
        ));

        // SyncContribution failure at a non-Fetcher step → not ignored.
        assert!(!ignorer.check(
            &Duty::new_sync_contribution_duty(SlotNumber::new(1)),
            Some(&DutyFailure {
                step: Step::Consensus,
                reason: REASON_SYNC_CONTRIBUTION_ZERO_PREPARES,
                err: None
            }),
        ));
    }
}
