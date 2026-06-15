use chrono::Duration;
use vise::*;

use crate::types::{Duty, DutyType, PubKey};

const BROADCAST_DELAY_BUCKETS: [f64; 11] =
    [0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0];

const SOURCE_PREGEN: &str = "pregen";
const SOURCE_DOWNSTREAM: &str = "downstream";

/// Metrics for the core broadcaster.
#[derive(Debug, Metrics)]
#[metrics(prefix = "core_bcast")]
pub struct BcastMetrics {
    /// Successfully broadcast duties by type.
    #[metrics(labels = ["duty"])]
    pub broadcast_total: LabeledFamily<String, Counter>,

    /// Duty broadcast delay since expected duty submission, by type.
    #[metrics(buckets = &BROADCAST_DELAY_BUCKETS, labels = ["duty"])]
    pub broadcast_delay_seconds: LabeledFamily<String, Histogram>,

    /// Unique validator registrations stored in the recaster, by pubkey.
    #[metrics(labels = ["pubkey"])]
    pub recast_registration_total: LabeledFamily<String, Counter>,

    /// Recast registrations by source.
    #[metrics(labels = ["source"])]
    pub recast_total: LabeledFamily<String, Counter>,

    /// Failed recast registrations by source.
    #[metrics(labels = ["source"])]
    pub recast_errors_total: LabeledFamily<String, Counter>,
}

#[vise::register]
pub static BCAST_METRICS: Global<BcastMetrics> = Global::new();

pub(crate) fn instrument_duty(duty: &Duty, delay: Option<Duration>) {
    let duty_type = duty.duty_type.to_string();
    BCAST_METRICS.broadcast_total[&duty_type].inc();

    if let Some(delay) = delay {
        // Delays never approach f64's 2^53 ms exact range, so the cast is exact.
        #[allow(clippy::cast_precision_loss)]
        let seconds = delay.num_milliseconds() as f64 / 1_000.0;
        BCAST_METRICS.broadcast_delay_seconds[&duty_type].observe(seconds);
    }
}

pub(crate) fn instrument_recast_registration(pubkey: PubKey) {
    BCAST_METRICS.recast_registration_total[&pubkey.to_string()].inc();
}

pub(crate) fn instrument_recast(duty: &Duty) {
    if duty.duty_type != DutyType::BuilderRegistration {
        return;
    }

    BCAST_METRICS.recast_total[&source(duty)].inc();
}

pub(crate) fn instrument_recast_error(duty: &Duty) {
    if duty.duty_type != DutyType::BuilderRegistration {
        return;
    }

    BCAST_METRICS.recast_errors_total[&source(duty)].inc();
}

fn source(duty: &Duty) -> String {
    if duty.slot.inner() > 0 {
        SOURCE_DOWNSTREAM.to_string()
    } else {
        SOURCE_PREGEN.to_string()
    }
}
