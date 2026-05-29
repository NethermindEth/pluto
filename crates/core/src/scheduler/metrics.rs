use vise::*;

/// Metrics for the core scheduler.
#[derive(Debug, Metrics)]
#[metrics(prefix = "core_scheduler")]
pub struct SchedulerMetrics {
    /// The current slot.
    pub current_slot: Gauge<u64>,

    /// The current epoch.
    pub current_epoch: Gauge<u64>,

    /// The total count of duties scheduled by type.
    #[metrics(labels = ["duty"])]
    pub duty_total: LabeledFamily<String, Counter>,

    /// Number of active validators.
    pub validators_active: Gauge<u64>,

    /// Total balance of a validator by public key.
    #[metrics(labels = ["pubkey_full", "pubkey"])]
    pub validator_balance_gwei: LabeledFamily<(String, String), Gauge<u64>, 2>,

    /// Gauge with validator pubkey and status as labels, value=1 is current
    /// status, value=0 is previous.
    #[metrics(labels = ["pubkey_full", "pubkey", "status"])]
    pub validator_status: LabeledFamily<(String, String, String), Gauge<u64>, 3>,

    /// Total number of times slots were skipped.
    pub skipped_slots_total: Counter,
}

/// Global metrics for the core scheduler.
#[vise::register]
pub static SCHEDULER_METRICS: Global<SchedulerMetrics> = Global::new();
