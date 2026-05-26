/// Failure reason definitions for duty analysis.
pub mod reason;

use std::fmt::Display;

use crate::types::{Duty, ParSignedDataSet, PubKey};

/// Type-erased step error, matching Go's `error` interface.
pub type StepError = Box<dyn std::error::Error + Send + Sync>;

/// Step in the core workflow, matching Go's `tracker.step`.
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

/// Tracker receives events from core workflow components for duty analysis and
/// participation reporting, matching Go's `core.Tracker` interface.
///
/// Methods that only need validator pubkeys (fetcher, consensus, dutydb,
/// sigagg, aggsigdb, bcast) accept `&[PubKey]` for object safety. Methods
/// that also carry partial-signature data accept `&ParSignedDataSet`.
pub trait Tracker: Send + Sync {
    /// Called when the fetcher fetches duty data.
    fn fetcher_fetched(&self, duty: Duty, pubkeys: &[PubKey], err: Option<&StepError>);

    /// Called when consensus is reached on duty data.
    fn consensus_proposed(&self, duty: Duty, pubkeys: &[PubKey], err: Option<&StepError>);

    /// Called when duty data is stored in DutyDB.
    fn duty_db_stored(&self, duty: Duty, pubkeys: &[PubKey], err: Option<&StepError>);

    /// Called when local VC partial signatures are stored in parsigdb.
    fn par_sig_db_stored_internal(
        &self,
        duty: Duty,
        set: &ParSignedDataSet,
        err: Option<&StepError>,
    );

    /// Called when local VC partial signatures are broadcast to peers.
    fn par_sig_ex_broadcasted(&self, duty: Duty, set: &ParSignedDataSet, err: Option<&StepError>);

    /// Called when peer partial signatures are stored in parsigdb.
    fn par_sig_db_stored_external(
        &self,
        duty: Duty,
        set: &ParSignedDataSet,
        err: Option<&StepError>,
    );

    /// Called when partial signatures are aggregated.
    fn sig_agg_aggregated(&self, duty: Duty, pubkeys: &[PubKey], err: Option<&StepError>);

    /// Called when aggregated signed data is stored in aggsigdb.
    fn agg_sig_db_stored(&self, duty: Duty, pubkeys: &[PubKey], err: Option<&StepError>);

    /// Called when aggregated data is broadcast to the beacon node.
    fn broadcaster_broadcast(&self, duty: Duty, pubkeys: &[PubKey], err: Option<&StepError>);

    /// Called when chain inclusion is checked for a duty.
    fn inclusion_checked(&self, duty: Duty, pubkey: PubKey, err: Option<&StepError>);
}
