#![allow(dead_code)]

/// A reason for a duty failing, matching Go's `tracker.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reason {
    /// Short machine-readable code used as a metrics label.
    pub code: &'static str,
    /// One-line human-readable summary.
    pub short: &'static str,
    /// Full explanation shown in logs and documentation.
    pub long: &'static str,
}

/// Unknown error occurred.
pub(crate) const REASON_UNKNOWN: Reason = Reason {
    code: "unknown",
    short: "unknown error",
    long: "Reason `unknown` indicates an unknown error occurred.",
};

/// Beacon node returned an error when fetching duty data.
pub(crate) const REASON_FETCH_BN_ERROR: Reason = Reason {
    code: "fetch_bn_error",
    short: "couldn't fetch duty data from the beacon node",
    long: "Reason `fetch_bn_error` indicates a duty failed in the fetcher step when it failed to fetch the required data from the beacon node API. This indicates a problem with the upstream beacon node.",
};

/// Attestation aggregation failed because the prerequisite attester duty
/// failed.
pub(crate) const REASON_MISSING_AGGREGATOR_ATTESTATION: Reason = Reason {
    code: "missing_aggregator_attestation",
    short: "couldn't aggregate attestation due to failed attester duty",
    long: "Reason `missing_aggregator_attestation` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite attestation data. This indicates the associated attestation duty failed to obtain a cluster agreed upon value.",
};

/// Attestation aggregation failed due to insufficient beacon committee
/// selections.
pub(crate) const REASON_INSUFFICIENT_AGGREGATOR_SELECTIONS: Reason = Reason {
    code: "insufficient_aggregator_selections",
    short: "couldn't aggregate attestation due to insufficient partial beacon committee selections",
    long: "Reason `insufficient_aggregator_selections` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed due to insufficient partial beacon committee selections submitted by the cluster validator clients.",
};

/// Attestation aggregation failed because no beacon committee selections were
/// submitted.
pub(crate) const REASON_ZERO_AGGREGATOR_SELECTIONS: Reason = Reason {
    code: "zero_aggregator_prepares",
    short: "couldn't aggregate attestation due to zero partial beacon committee selections",
    long: "Reason `zero_aggregator_prepares` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed due to no partial beacon committee selections submitted by the cluster validator clients.",
};

/// Attestation aggregation failed because the prepare aggregator duty failed.
pub(crate) const REASON_FAILED_AGGREGATOR_SELECTION: Reason = Reason {
    code: "failed_aggregator_selection",
    short: "couldn't aggregate attestation due to failed prepare aggregator duty",
    long: "Reason `failed_aggregator_selection` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed.",
};

/// Attestation aggregation failed because no peer committee selections were
/// received.
pub(crate) const REASON_NO_AGGREGATOR_SELECTIONS: Reason = Reason {
    code: "no_aggregator_selections",
    short: "couldn't aggregate attestation due to no partial beacon committee selections received from peers",
    long: "Reason `no_aggregator_selections` indicates an attestation aggregation duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated beacon committee selections. This indicates the associated prepare aggregation duty failed due to no partial beacon committee selections received from peers.",
};

/// Block proposal failed due to insufficient partial RANDAO signatures from the
/// cluster.
pub(crate) const REASON_PROPOSER_INSUFFICIENT_RANDAOS: Reason = Reason {
    code: "proposer_insufficient_randaos",
    short: "couldn't propose block due to insufficient partial randao signatures",
    long: "Reason `proposer_insufficient_randaos` indicates a block proposer duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed due to insufficient partial randao signatures submitted by the cluster validator clients.",
};

/// Block proposal failed because no partial RANDAO signatures were submitted.
pub(crate) const REASON_PROPOSER_ZERO_RANDAOS: Reason = Reason {
    code: "proposer_zero_randaos",
    short: "couldn't propose block due to zero partial randao signatures",
    long: "Reason `proposer_zero_randaos` indicates a block proposer duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed due to no partial randao signatures submitted by the cluster validator clients.",
};

/// Block proposal failed because the prerequisite randao duty failed.
pub(crate) const REASON_FAILED_PROPOSER_RANDAO: Reason = Reason {
    code: "failed_proposer_randao",
    short: "couldn't propose block due to failed randao duty",
    long: "Reason `failed_proposer_randao` indicates a block proposer duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed.",
};

/// Block proposal failed because no peer RANDAO signatures were received.
pub(crate) const REASON_PROPOSER_NO_EXTERNAL_RANDAOS: Reason = Reason {
    code: "proposer_no_external_randaos",
    short: "couldn't propose block due to no partial randao signatures received from peers",
    long: "Reason `proposer_no_external_randaos` indicates a block proposer duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated RANDAO. This indicates the associated randao duty failed due to no partial randao signatures received from peers.",
};

/// Sync contribution failed because the prerequisite sync message duty failed.
pub(crate) const REASON_SYNC_CONTRIBUTION_NO_SYNC_MSG: Reason = Reason {
    code: "sync_contribution_no_sync_msg",
    short: "couldn't fetch sync contribution due to failed sync message duty",
    long: "Reason `sync_contribution_no_sync_msg` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite sync message. This indicates the associated sync message duty failed to obtain a cluster agreed upon value.",
};

/// Sync contribution failed due to insufficient partial sync contribution
/// selections.
pub(crate) const REASON_SYNC_CONTRIBUTION_FEW_PREPARES: Reason = Reason {
    code: "sync_contribution_few_prepares",
    short: "couldn't fetch sync contribution due to insufficient partial sync contribution selections",
    long: "Reason `sync_contribution_few_prepares` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed due to insufficient partial sync contribution selections submitted by the cluster validator clients.",
};

/// Sync contribution failed because no partial sync contribution selections
/// were submitted.
pub(crate) const REASON_SYNC_CONTRIBUTION_ZERO_PREPARES: Reason = Reason {
    code: "sync_contribution_zero_prepares",
    short: "couldn't fetch sync contribution due to zero partial sync contribution selections",
    long: "Reason `sync_contribution_zero_prepares` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed due to no partial sync contribution selections submitted by the cluster validator clients.",
};

/// Sync contribution failed because the prepare sync contribution duty failed.
pub(crate) const REASON_SYNC_CONTRIBUTION_FAILED_PREPARE: Reason = Reason {
    code: "sync_contribution_failed_prepare",
    short: "couldn't fetch sync contribution due to failed prepare sync contribution duty",
    long: "Reason `sync_contribution_failed_prepare` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed.",
};

/// Sync contribution failed because no peer sync contribution selections were
/// received.
pub(crate) const REASON_SYNC_CONTRIBUTION_NO_EXTERNAL_PREPARES: Reason = Reason {
    code: "sync_contribution_no_external_prepares",
    short: "couldn't fetch sync contribution due to no partial sync contribution selections received from peers",
    long: "Reason `sync_contribution_no_external_prepares` indicates a sync contribution duty failed in the fetcher step since it couldn't fetch the prerequisite aggregated sync contribution selections. This indicates the associated prepare sync contribution duty failed due to no partial sync contribution selections received from peers.",
};

/// Duty failed because the consensus algorithm did not complete.
pub(crate) const REASON_NO_CONSENSUS: Reason = Reason {
    code: "no_consensus",
    short: "consensus algorithm didn't complete",
    long: "Reason `no_consensus` indicates a duty failed in consensus step. This could indicate that insufficient honest peers participated in consensus or p2p network connection problems.",
};

/// Local validator client did not submit a partial signature for the duty.
pub(crate) const REASON_NO_LOCAL_VC_SIGNATURE: Reason = Reason {
    code: "no_local_vc_signature",
    short: "signed duty not submitted by local validator client",
    long: "Reason `no_local_vc_signature` indicates that partial signature we never submitted by the local validator client. This could indicate that the local validator client is offline, or has connection problems with pluto, or has some other problem. See validator client logs for more details.",
};

/// No partial signatures were received from any peer.
pub(crate) const REASON_NO_PEER_SIGNATURES: Reason = Reason {
    code: "no_peer_signatures",
    short: "no partial signatures received from peers",
    long: "Reason `no_peer_signatures` indicates that no partial signature for the duty was received from any peer. This indicates all peers are offline or p2p network connection problems.",
};

/// Insufficient partial signatures received; threshold not reached.
pub(crate) const REASON_INSUFFICIENT_PEER_SIGNATURES: Reason = Reason {
    code: "insufficient_peer_signatures",
    short: "insufficient partial signatures received, minimum required threshold not reached",
    long: "Reason `insufficient_peer_signatures` indicates that insufficient partial signatures for the duty was received from peers. This indicates problems with peers or p2p network connection problems.",
};

/// Known limitation: inconsistent sync committee partial signatures received.
pub(crate) const REASON_PAR_SIG_DB_INCONSISTENT_SYNC: Reason = Reason {
    code: "par_sig_db_inconsistent_sync",
    short: "known limitation: inconsistent sync committee signatures received",
    long: "Reason `par_sig_db_inconsistent_sync` indicates that partial signed data for the sync committee duty were inconsistent. This is known limitation in this version of pluto.",
};

/// Beacon node returned an error when broadcasting the aggregated duty.
pub(crate) const REASON_BROADCAST_BN_ERROR: Reason = Reason {
    code: "broadcast_bn_error",
    short: "failed to broadcast duty to beacon node",
    long: "Reason `broadcast_bn_error` indicates that beacon node returned an error while submitting aggregated duty signature to beacon node.",
};

/// Duty was broadcast successfully but was not included in the canonical chain.
pub(crate) const REASON_NOT_INCLUDED_ON_CHAIN: Reason = Reason {
    code: "not_included_onchain",
    short: "duty not included on-chain",
    long: "Reason `not_included_onchain` indicates that even though pluto broadcasted the duty successfully, it wasn't included in the beacon chain. This is expected for up to 20% of attestations. It may however indicate problematic pluto broadcast delays or beacon node network problems.",
};

/// Bug: fetcher step encountered an unexpected error.
pub(crate) const REASON_BUG_FETCH_ERROR: Reason = Reason {
    code: "bug_fetch_error",
    short: "bug: couldn't fetch due to unexpected error",
    long: "Reason `bug_fetch_error` indicates duty failed in fetcher step with some unexpected error. This indicates a problem in pluto as it is unexpected.",
};

/// Bug: partial signatures for a non-sync duty were inconsistent.
pub(crate) const REASON_BUG_PAR_SIG_DB_INCONSISTENT: Reason = Reason {
    code: "bug_par_sig_db_inconsistent",
    short: "bug: inconsistent partial signatures received",
    long: "Reason `bug_par_sig_db_inconsistent` indicates that partial signed data for the duty were inconsistent. This indicates a bug in pluto as it is unexpected (for non-sync-committee-duties).",
};

/// Bug: failed to store external partial signatures in parsigdb.
pub(crate) const REASON_BUG_PAR_SIG_DB_EXTERNAL: Reason = Reason {
    code: "bug_par_sig_db_external",
    short: "bug: failed to store external partial signatures in parsigdb",
    long: "Reason `bug_par_sig_db_external` indicates a bug in the partial signature database as it is unexpected.",
};

/// Bug: BLS threshold aggregation failed due to inconsistent signed data.
pub(crate) const REASON_BUG_SIG_AGG: Reason = Reason {
    code: "bug_sig_agg",
    short: "bug: threshold aggregation of partial signatures failed due to inconsistent signed data",
    long: "Reason `bug_sig_agg` indicates that BLS threshold aggregation of sufficient partial signatures failed. This indicates inconsistent signed data. This indicates a bug in pluto as it is unexpected.",
};

/// Bug: failed to store aggregated signature in aggsigdb.
pub(crate) const REASON_BUG_AGGREGATION_ERROR: Reason = Reason {
    code: "bug_aggregation_error",
    short: "bug: failed to store aggregated signature in aggsigdb",
    long: "Reason `bug_aggregation_error` indicates a bug in the aggregated signature database as it is unexpected.",
};

/// Bug: failed to store duty data in DutyDB.
pub(crate) const REASON_BUG_DUTY_DB_ERROR: Reason = Reason {
    code: "bug_duty_db_error",
    short: "bug: failed to store duty data in DutyDB",
    long: "Reason `bug_duty_db_error` indicates a bug in the DutyDB database as it is unexpected.",
};

/// Bug: parsigdb did not trigger partial signature exchange.
pub(crate) const REASON_BUG_PAR_SIG_DB_INTERNAL: Reason = Reason {
    code: "bug_par_sig_db_internal",
    short: "bug: partial signature database didn't trigger partial signature exchange, this is unexpected",
    long: "Reason `bug_par_sig_db_internal` indicates a bug in the partial signature database as it is unexpected. Note this may happen due to expiry race.",
};
