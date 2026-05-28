use std::fmt::Display;

/// Step in the core workflow.
///
/// Variants are ordered by their position in the workflow; this ordering is
/// used when scanning backwards to find the last reached step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Step {
    /// No step reached (zero value).
    Zero = 0,
    /// Duty data fetched from beacon node.
    Fetcher = 1,
    /// Duty data consensus reached.
    Consensus = 2,
    /// Duty data stored in DutyDB.
    DutyDB = 3,
    /// Partial signed data submitted by local validator client.
    ValidatorAPI = 4,
    /// Partial signed data from local VC stored in parsigdb.
    ParSigDBInternal = 5,
    /// Partial signed data exchanged with peers.
    ParSigEx = 6,
    /// Partial signed data from peers stored in parsigdb.
    ParSigDBExternal = 7,
    /// Partial signed data aggregated.
    SigAgg = 8,
    /// Aggregated signed data stored in aggsigdb.
    AggSigDB = 9,
    /// Aggregated data submitted to beacon node.
    Bcast = 10,
    /// Aggregated data included in canonical chain.
    ChainInclusion = 11,
    /// Sentinel — must always be last.
    Sentinel = 12,
}

impl Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Step::Zero => "unknown",
            Step::Fetcher => "fetcher",
            Step::Consensus => "consensus",
            Step::DutyDB => "duty_db",
            Step::ValidatorAPI => "validator_api",
            Step::ParSigDBInternal => "parsig_db_local",
            Step::ParSigEx => "parsig_ex",
            Step::ParSigDBExternal => "parsig_db_external",
            Step::SigAgg => "sig_aggregation",
            Step::AggSigDB => "aggsig_db",
            Step::Bcast => "bcast",
            Step::ChainInclusion => "chain_inclusion",
            Step::Sentinel => "sentinel",
        };
        write!(f, "{s}")
    }
}
