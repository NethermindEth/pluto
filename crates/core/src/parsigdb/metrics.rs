use vise::*;

/// Metrics for the ParSigDB.
#[derive(Debug, Clone, Metrics)]
pub struct ParsigDBMetrics {
    /// Total number of partially signed voluntary exits per public key
    #[metrics(labels = ["pubkey"])]
    pub exit_total: LabeledFamily<String, Counter>,
}

/// Global metrics for the ParSigDB.
pub static PARSIG_DB_METRICS: Global<ParsigDBMetrics> = Global::new();
