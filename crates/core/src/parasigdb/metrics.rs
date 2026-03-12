use vise::*;

/// Metrics for the ParSigDB.
#[derive(Debug, Clone, Metrics)]
pub struct ParasigDBMetrics {
    /// Total number of partially signed voluntary exits per public key
    #[metrics(labels = ["pubkey"])]
    pub exit_total: LabeledFamily<String, Counter>,
}

/// Global metrics for the ParSigDB.
pub static PARASIG_DB_METRICS: Global<ParasigDBMetrics> = Global::new();
