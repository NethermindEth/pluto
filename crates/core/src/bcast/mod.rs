//! Broadcasts aggregated signed duty data to the beacon node.

mod metrics;
mod recast;

use std::{any::Any, error::Error as StdError};

use chrono::{DateTime, Duration, Utc};
use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls};
use pluto_eth2api::{
    AttesterDuty, BeaconNodeClient, EthBeaconNodeApiClient,
    GetStateValidatorsResponseResponseDatum, ValidatorStatus, data_version_is_before_electra,
    spec::{altair, phase0},
    versioned,
};
use tree_hash::TreeHash;

pub use recast::Recaster;

use crate::{
    bcast::metrics::instrument_duty,
    signeddata::{
        SignedSyncContributionAndProof, SignedSyncMessage, SignedVoluntaryExit,
        VersionedAttestation, VersionedSignedAggregateAndProof, VersionedSignedProposal,
        VersionedSignedValidatorRegistration,
    },
    types::{Duty, DutyType, PubKey, SignedData, SignedDataSet},
};

/// Boxed client/provider error.
pub type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// Broadcaster result.
pub type Result<T> = std::result::Result<T, Error>;

/// Broadcaster error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Beacon client/provider error.
    #[error("{context}: {source}")]
    Client {
        /// Operation context.
        context: &'static str,
        /// Underlying error.
        #[source]
        source: BoxError,
    },

    /// Signed-data conversion error.
    #[error("{context}: {source}")]
    SignedData {
        /// Operation context.
        context: &'static str,
        /// Underlying error.
        #[source]
        source: crate::signeddata::SignedDataError,
    },

    /// Crypto operation error.
    #[error("{context}: {source}")]
    Crypto {
        /// Operation context.
        context: &'static str,
        /// Underlying error.
        #[source]
        source: pluto_crypto::types::Error,
    },

    /// Invalid time value.
    #[error("{context}: invalid time value {value}")]
    InvalidTime {
        /// Operation context.
        context: &'static str,
        /// Invalid value.
        value: i64,
    },

    /// Arithmetic overflow.
    #[error("{context}: arithmetic overflow")]
    ArithmeticOverflow {
        /// Operation context.
        context: &'static str,
    },

    /// Mutex poisoned.
    #[error("{0}: mutex poisoned")]
    MutexPoisoned(&'static str),

    /// `DutyBuilderProposer` is deprecated.
    #[error("deprecated duty DutyBuilderProposer")]
    DeprecatedDutyBuilderProposer,

    /// Expected one item in set.
    #[error("expected one item in set")]
    ExpectedOneItemInSet,

    /// Invalid proposal data.
    #[error("invalid proposal")]
    InvalidProposal,

    /// Invalid registration data.
    #[error("invalid registration")]
    InvalidRegistration,

    /// Invalid exit data.
    #[error("invalid exit")]
    InvalidExit,

    /// Invalid aggregate-and-proof data.
    #[error("invalid aggregate and proof")]
    InvalidAggregateAndProof,

    /// Invalid sync committee message.
    #[error("invalid sync committee message")]
    InvalidSyncCommitteeMessage,

    /// Invalid sync committee contribution.
    #[error("invalid sync committee contribution")]
    InvalidSyncCommitteeContribution,

    /// Invalid attestation data.
    #[error("invalid attestation")]
    InvalidAttestation,

    /// No attestations available.
    #[error("no attestations")]
    NoAttestations,

    /// Validator field could not be parsed.
    #[error("{context}: invalid validator field")]
    InvalidValidatorField {
        /// Operation context.
        context: &'static str,
    },

    /// Unsupported duty type.
    #[error("unsupported duty type")]
    UnsupportedDutyType,
}

/// Complete validator data needed for Electra attestation repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteValidator {
    /// Validator status.
    pub status: ValidatorStatus,
    /// Activation epoch.
    pub activation_epoch: phase0::Epoch,
}

impl TryFrom<&GetStateValidatorsResponseResponseDatum> for CompleteValidator {
    type Error = std::num::ParseIntError;

    fn try_from(
        datum: &GetStateValidatorsResponseResponseDatum,
    ) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            status: datum.status.clone(),
            activation_epoch: datum.validator.activation_epoch.parse()?,
        })
    }
}

#[derive(Debug, Clone)]
struct DelayCalculator {
    genesis_time: DateTime<Utc>,
    slot_duration: Duration,
}

impl DelayCalculator {
    fn delay(&self, slot: u64, duty_type: &DutyType) -> Result<Duration> {
        let slot_duration = self
            .slot_duration
            .to_std()
            .map_err(|_| Error::InvalidTime {
                context: "slot duration",
                value: self.slot_duration.num_milliseconds(),
            })?;
        let slot_count =
            u32::try_from(slot).map_err(|_| Error::ArithmeticOverflow { context: "slot" })?;
        let elapsed = slot_duration
            .checked_mul(slot_count)
            .ok_or(Error::ArithmeticOverflow {
                context: "slot elapsed",
            })?;
        let slot_start = self
            .genesis_time
            .checked_add_signed(Duration::from_std(elapsed).map_err(|_| {
                Error::ArithmeticOverflow {
                    context: "slot elapsed",
                }
            })?)
            .ok_or(Error::ArithmeticOverflow {
                context: "slot start",
            })?;

        let expected_submission = if duty_type == &DutyType::Attester {
            slot_start
                .checked_add_signed(div_duration(self.slot_duration, 3, "attester delay")?)
                .ok_or(Error::ArithmeticOverflow {
                    context: "attester delay",
                })?
        } else if matches!(duty_type, DutyType::Aggregator | DutyType::SyncContribution) {
            // Two-thirds of the slot; multiply before dividing to avoid the extra
            // rounding loss of (slot_duration / 3) * 2.
            let two_thirds = div_duration(
                mul_duration(self.slot_duration, 2, "aggregation delay")?,
                3,
                "aggregation delay",
            )?;
            slot_start
                .checked_add_signed(two_thirds)
                .ok_or(Error::ArithmeticOverflow {
                    context: "aggregation delay",
                })?
        } else {
            slot_start
        };

        Ok(Utc::now().signed_duration_since(expected_submission))
    }
}

/// Broadcasts aggregated signed duty data to the beacon node.
pub struct Broadcaster {
    client: BeaconNodeClient,
    delay_calculator: DelayCalculator,
}

impl Broadcaster {
    /// Creates a new broadcaster.
    pub async fn new(client: BeaconNodeClient) -> Result<Self> {
        let genesis_time =
            client
                .api()
                .fetch_genesis_time()
                .await
                .map_err(|source| Error::Client {
                    context: "fetch genesis time",
                    source: Box::new(source),
                })?;
        let (slot_duration, _) =
            client
                .api()
                .fetch_slots_config()
                .await
                .map_err(|source| Error::Client {
                    context: "fetch slots config",
                    source: Box::new(source),
                })?;
        let slot_duration =
            Duration::from_std(slot_duration).map_err(|_| Error::ArithmeticOverflow {
                context: "slot duration",
            })?;

        Ok(Self {
            client,
            delay_calculator: DelayCalculator {
                genesis_time,
                slot_duration,
            },
        })
    }

    /// Broadcasts aggregated signed duty data to the beacon node.
    /// Routes a duty's aggregated signed data to the matching submit handler.
    ///
    /// Dispatch on the duty type to a `broadcast_*` handler, then on
    /// success record the broadcast count and submission delay. Internal-only
    /// duties (randao, prepare-aggregator, prepare-sync-contribution) are
    /// no-ops; deprecated and unknown duty types return an error.
    pub async fn broadcast(&self, mut duty: Duty, set: SignedDataSet) -> Result<()> {
        match duty.duty_type {
            DutyType::Attester => self.broadcast_attester(&duty, &set).await?,
            DutyType::Proposer => self.broadcast_proposer(&duty, &set).await?,
            DutyType::BuilderProposer => return Err(Error::DeprecatedDutyBuilderProposer),
            DutyType::BuilderRegistration => {
                // Use first slot in current epoch for accurate delay calculations while
                // submitting builder registrations. This is because builder
                // registrations are submitted in first slot of every epoch.
                duty.slot = first_slot_in_current_epoch(self.client.api()).await?;
                self.broadcast_builder_registration(&duty, &set).await?;
            }
            DutyType::Exit => self.broadcast_exits(&duty, &set).await?,
            // Internal DVT duties; nothing is submitted to the beacon node.
            DutyType::Randao | DutyType::PrepareAggregator | DutyType::PrepareSyncContribution => {}
            DutyType::Aggregator => self.broadcast_aggregator(&duty, &set).await?,
            DutyType::SyncMessage => self.broadcast_sync_messages(&duty, &set).await?,
            DutyType::SyncContribution => self.broadcast_sync_contributions(&duty, &set).await?,
            DutyType::Unknown
            | DutyType::Signature
            | DutyType::InfoSync
            | DutyType::DutySentinel(_) => {
                return Err(Error::UnsupportedDutyType);
            }
        }

        // Always count a successful broadcast; record the delay only when it is
        // computable.
        let delay = self
            .delay_calculator
            .delay(duty.slot.inner(), &duty.duty_type)
            .inspect_err(|error| {
                tracing::warn!(%error, %duty, "Failed to compute broadcast delay");
            })
            .ok();
        instrument_duty(&duty, delay);

        Ok(())
    }

    /// Submits attestations.
    ///
    /// Convert the set to attestations; if an Electra attestation is
    /// missing its validator index, backfill it via
    /// `populate_missing_validator_indices`; submit. A `PriorAttestationKnown`
    /// response is treated as success (non-idempotent beacon node).
    async fn broadcast_attester(&self, duty: &Duty, set: &SignedDataSet) -> Result<()> {
        let mut attestations = set_to_attestations(set)?;

        // This has been introduced because of a bug in electra for versions v1.3.0,
        // v1.3.1, v1.4.0 and v1.4.1. The code block below will be triggered
        // only if:
        // - there is a charon node in the cluster at one of the above mentioned
        //   versions;
        // - the current charon node has received partially signed attestations ONLY
        //   from such nodes.
        //
        // As long as charon has received at least one partially signed attestation in
        // its threshold signatures from either:
        // - its own VC;
        // - another charon node at version v1.3.2, v1.4.2 or newer
        // this (expensive) code block will not be triggered.
        if attestations_need_validator_indices(&attestations) {
            tracing::warn!(
                error = "peer version causes slowdown",
                "There is a charon node in the cluster at one of the following versions: v1.3.0, v1.3.1, v1.4.0 or v1.4.1. Please update, as it causes performance degradation."
            );

            if attestations.is_empty() {
                return Err(Error::NoAttestations);
            }

            self.populate_missing_validator_indices(&mut attestations)
                .await?;
        }

        match self.client.api().submit_attestations(attestations).await {
            Ok(()) => Ok(()),
            Err(source) if source.to_string().contains("PriorAttestationKnown") => Ok(()),
            Err(source) => Err(Error::Client {
                context: "submit attestations",
                source: Box::new(source),
            }),
        }?;

        tracing::info!(%duty, "Successfully submitted v2 attestations to beacon node");
        Ok(())
    }

    /// Submits a block proposal.
    ///
    /// Take the single set entry as a proposal; if blinded, convert and
    /// submit via the blinded endpoint, otherwise submit the full proposal.
    async fn broadcast_proposer(&self, duty: &Duty, set: &SignedDataSet) -> Result<()> {
        let (pubkey, agg_data) = set_to_one(set)?;
        let block =
            downcast_signed_data::<VersionedSignedProposal>(agg_data, Error::InvalidProposal)?;
        let blinded = block.0.blinded;

        if blinded {
            let proposal = block.to_blinded().map_err(|source| Error::SignedData {
                context: "cannot broadcast, expected blinded proposal",
                source,
            })?;
            self.client
                .api()
                .submit_signed_blinded_proposal(proposal)
                .await
                .map_err(|source| Error::Client {
                    context: "submit blinded proposal",
                    source: Box::new(source),
                })?;
        } else {
            self.client
                .api()
                .submit_signed_proposal(block.0)
                .await
                .map_err(|source| Error::Client {
                    context: "submit proposal",
                    source: Box::new(source),
                })?;
        }

        tracing::info!(%duty, %pubkey, blinded, "Successfully submitted block proposal to beacon node");
        Ok(())
    }

    /// Submits builder validator registrations.
    ///
    /// Convert the set to registrations; submit them in one request.
    async fn broadcast_builder_registration(&self, duty: &Duty, set: &SignedDataSet) -> Result<()> {
        let registrations = set_to_registrations(set)?;
        self.client
            .api()
            .submit_validator_registrations(registrations)
            .await
            .map_err(|source| Error::Client {
                context: "submit validator registrations",
                source: Box::new(source),
            })?;

        tracing::info!(%duty, "Successfully submitted validator registrations to beacon node");
        Ok(())
    }

    /// Submits voluntary exits, one request per exit.
    ///
    /// Convert the whole set up front, then submit each exit; see the
    /// inline notes for the validate-first and surface-any-failure semantics.
    async fn broadcast_exits(&self, duty: &Duty, set: &SignedDataSet) -> Result<()> {
        // Two deliberate choices:
        // 1. set_to_exits validates every item up front, so a wrong-typed set fails
        //    before ANY exit is submitted (no partial submission on a bad set).
        // 2. Submit every exit and return an error if ANY failed, so a partial failure
        //    is always surfaced rather than masked by a later success.
        let mut last_error = None;
        for (pubkey, exit) in set_to_exits(set)? {
            match self.client.api().submit_voluntary_exit(exit).await {
                Ok(()) => {
                    tracing::info!(%duty, %pubkey, "Successfully submitted voluntary exit to beacon node")
                }
                Err(source) => last_error = Some(source),
            }
        }

        if let Some(source) = last_error {
            return Err(Error::Client {
                context: "submit voluntary exit",
                source: Box::new(source),
            });
        }

        Ok(())
    }

    /// Submits aggregate-and-proofs.
    ///
    /// Convert the set to aggregate-and-proofs; submit them.
    async fn broadcast_aggregator(&self, duty: &Duty, set: &SignedDataSet) -> Result<()> {
        let aggregate_and_proofs = set_to_agg_and_proof(set)?;
        self.client
            .api()
            .submit_aggregate_attestations(aggregate_and_proofs)
            .await
            .map_err(|source| Error::Client {
                context: "submit aggregate attestations",
                source: Box::new(source),
            })?;

        tracing::info!(%duty, "Successfully submitted v2 attestation aggregations to beacon node");
        Ok(())
    }

    /// Submits sync committee messages.
    ///
    /// Convert the set to sync committee messages; submit them.
    async fn broadcast_sync_messages(&self, duty: &Duty, set: &SignedDataSet) -> Result<()> {
        let messages = set_to_sync_messages(set)?;
        self.client
            .api()
            .submit_sync_committee_messages(messages)
            .await
            .map_err(|source| Error::Client {
                context: "submit sync committee messages",
                source: Box::new(source),
            })?;

        tracing::info!(%duty, "Successfully submitted sync committee messages to beacon node");
        Ok(())
    }

    /// Submits sync committee contributions.
    ///
    /// Convert the set to sync committee contributions; submit them.
    async fn broadcast_sync_contributions(&self, duty: &Duty, set: &SignedDataSet) -> Result<()> {
        let contributions = set_to_sync_contributions(set)?;
        self.client
            .api()
            .submit_sync_committee_contributions(contributions)
            .await
            .map_err(|source| Error::Client {
                context: "submit sync committee contributions",
                source: Box::new(source),
            })?;

        tracing::info!(%duty, "Successfully submitted sync committee contributions to beacon node");
        Ok(())
    }

    /// Backfills missing Electra attestation validator indices in place.
    ///
    /// Read the epoch/slot from the first attestation; resolve the active
    /// validator indices for that epoch; fetch their attester duties and the
    /// beacon-attester signing domain; then for each duty at the attestation's
    /// slot, find the attestation whose aggregate signature verifies against
    /// the duty's pubkey and stamp in that `validator_index`.
    async fn populate_missing_validator_indices(
        &self,
        attestations: &mut [versioned::VersionedAttestation],
    ) -> Result<()> {
        let att0_data = attestations
            .first()
            .and_then(|attestation| attestation.attestation.as_ref())
            .map(versioned::AttestationPayload::data)
            .ok_or(Error::InvalidAttestation)?;
        let epoch = att0_data.target.epoch;
        let slot = att0_data.slot;

        let val_idxs = resolve_active_validators_indices(&self.client, epoch).await?;
        let duties = self
            .client
            .api()
            .fetch_attester_duties_for_indices(epoch, val_idxs)
            .await
            .map_err(|source| Error::Client {
                context: "fetch attester duties",
                source: Box::new(source),
            })?;
        let domain = self
            .client
            .api()
            .fetch_beacon_attester_domain(epoch)
            .await
            .map_err(|source| Error::Client {
                context: "fetch beacon attester domain",
                source: Box::new(source),
            })?;

        // Try to find the matching attester duty and attestation by verifying the full
        // aggregated signature of the attestation with the pubkey found in the attester
        // duty. Once match is found, update the attestation's validator index
        // with the one from the attester duty.
        for attester_duty in duties {
            if attester_duty.slot != slot {
                continue;
            }

            for attestation in attestations.iter_mut() {
                if attestation_matches_duty(attestation, &attester_duty, domain)? {
                    attestation.validator_index = Some(attester_duty.validator_index);
                    break;
                }
            }
        }

        Ok(())
    }
}

fn downcast_signed_data<T>(data: &dyn SignedData, error: Error) -> Result<T>
where
    T: SignedData + Clone + 'static,
{
    let any = data as &dyn Any;
    any.downcast_ref::<T>().cloned().ok_or(error)
}

fn set_to_one(set: &SignedDataSet) -> Result<(PubKey, &dyn SignedData)> {
    if set.len() != 1 {
        return Err(Error::ExpectedOneItemInSet);
    }

    let Some((pubkey, data)) = set.iter().next() else {
        unreachable!("set length checked")
    };

    Ok((*pubkey, data.as_ref()))
}

fn set_values_to<T, U, E, M>(set: &SignedDataSet, error: E, map: M) -> Result<Vec<U>>
where
    T: SignedData + Clone + 'static,
    E: Fn() -> Error,
    M: Fn(T) -> U,
{
    set.values()
        .map(|data| {
            let value = downcast_signed_data::<T>(data.as_ref(), error())?;
            Ok(map(value))
        })
        .collect()
}

fn set_to_attestations(set: &SignedDataSet) -> Result<Vec<versioned::VersionedAttestation>> {
    set_values_to(
        set,
        || Error::InvalidAttestation,
        |attestation: VersionedAttestation| attestation.0,
    )
}

fn set_to_registrations(
    set: &SignedDataSet,
) -> Result<Vec<versioned::VersionedSignedValidatorRegistration>> {
    set_values_to(
        set,
        || Error::InvalidRegistration,
        |registration: VersionedSignedValidatorRegistration| registration.0,
    )
}

fn set_to_exits(set: &SignedDataSet) -> Result<Vec<(PubKey, phase0::SignedVoluntaryExit)>> {
    set.iter()
        .map(|(pubkey, data)| {
            downcast_signed_data::<SignedVoluntaryExit>(data.as_ref(), Error::InvalidExit)
                .map(|exit| (*pubkey, exit.0))
        })
        .collect()
}

fn set_to_agg_and_proof(
    set: &SignedDataSet,
) -> Result<Vec<versioned::VersionedSignedAggregateAndProof>> {
    set_values_to(
        set,
        || Error::InvalidAggregateAndProof,
        |aggregate_and_proof: VersionedSignedAggregateAndProof| aggregate_and_proof.0,
    )
}

fn set_to_sync_messages(set: &SignedDataSet) -> Result<Vec<altair::SyncCommitteeMessage>> {
    set_values_to(
        set,
        || Error::InvalidSyncCommitteeMessage,
        |message: SignedSyncMessage| message.0,
    )
}

fn set_to_sync_contributions(
    set: &SignedDataSet,
) -> Result<Vec<altair::SignedContributionAndProof>> {
    set_values_to(
        set,
        || Error::InvalidSyncCommitteeContribution,
        |contribution: SignedSyncContributionAndProof| contribution.0,
    )
}

fn attestations_need_validator_indices(attestations: &[versioned::VersionedAttestation]) -> bool {
    for attestation in attestations {
        if data_version_is_before_electra(attestation.version) {
            break;
        }

        if attestation.validator_index.is_none() {
            return true;
        }
    }

    false
}

async fn resolve_active_validators_indices(
    client: &BeaconNodeClient,
    epoch: phase0::Epoch,
) -> Result<Vec<phase0::ValidatorIndex>> {
    let validators = client
        .complete_validators()
        .await
        .map_err(|source| Error::Client {
            context: "complete validators",
            source: Box::new(source),
        })?;
    let mut indices = Vec::new();

    for (index, datum) in validators.iter() {
        let validator =
            CompleteValidator::try_from(datum).map_err(|_| Error::InvalidValidatorField {
                context: "activation epoch",
            })?;
        if !validator.status.is_active() && validator.activation_epoch != epoch {
            continue;
        }

        indices.push(*index);
    }

    Ok(indices)
}

fn attestation_matches_duty(
    attestation: &versioned::VersionedAttestation,
    attester_duty: &AttesterDuty,
    domain: phase0::Domain,
) -> Result<bool> {
    let payload = attestation
        .attestation
        .as_ref()
        .ok_or(Error::InvalidAttestation)?;
    let object_root = payload.data().tree_hash_root().0;
    let signing_root = phase0::SigningData {
        object_root,
        domain,
    }
    .tree_hash_root()
    .0;
    let signature = payload.signature();

    match BlstImpl.verify(&attester_duty.pubkey, &signing_root, &signature) {
        Ok(()) => Ok(true),
        Err(pluto_crypto::types::Error::VerificationFailed(_)) => Ok(false),
        Err(source) => Err(Error::Crypto {
            context: "sig verification",
            source,
        }),
    }
}

async fn first_slot_in_current_epoch(
    client: &EthBeaconNodeApiClient,
) -> Result<crate::types::SlotNumber> {
    let genesis_time = client
        .fetch_genesis_time()
        .await
        .map_err(|source| Error::Client {
            context: "fetch genesis time",
            source: Box::new(source),
        })?;
    let (slot_duration, slots_per_epoch) =
        client
            .fetch_slots_config()
            .await
            .map_err(|source| Error::Client {
                context: "fetch slots config",
                source: Box::new(source),
            })?;
    let slot_duration =
        Duration::from_std(slot_duration).map_err(|_| Error::ArithmeticOverflow {
            context: "slot duration",
        })?;

    let chain_age = Utc::now().signed_duration_since(genesis_time);
    let chain_age_ms = chain_age.num_milliseconds();
    let slot_duration_ms = slot_duration.num_milliseconds();
    if slot_duration_ms <= 0 {
        return Err(Error::InvalidTime {
            context: "slot duration",
            value: slot_duration_ms,
        });
    }
    let current_slot_i64 =
        chain_age_ms
            .checked_div(slot_duration_ms)
            .ok_or(Error::ArithmeticOverflow {
                context: "current slot",
            })?;
    let current_slot = u64::try_from(current_slot_i64).map_err(|_| Error::InvalidTime {
        context: "current slot",
        value: current_slot_i64,
    })?;
    let current_epoch =
        current_slot
            .checked_div(slots_per_epoch)
            .ok_or(Error::ArithmeticOverflow {
                context: "current epoch",
            })?;
    let first_slot =
        current_epoch
            .checked_mul(slots_per_epoch)
            .ok_or(Error::ArithmeticOverflow {
                context: "first slot in epoch",
            })?;

    Ok(crate::types::SlotNumber::new(first_slot))
}

fn div_duration(duration: Duration, divisor: i32, context: &'static str) -> Result<Duration> {
    let divisor = i64::from(divisor);
    let nanos = duration
        .num_nanoseconds()
        .ok_or(Error::ArithmeticOverflow { context })?;
    Ok(Duration::nanoseconds(
        nanos
            .checked_div(divisor)
            .ok_or(Error::ArithmeticOverflow { context })?,
    ))
}

fn mul_duration(duration: Duration, multiplier: i32, context: &'static str) -> Result<Duration> {
    duration
        .checked_mul(multiplier)
        .ok_or(Error::ArithmeticOverflow { context })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls};
    use pluto_eth2api::{
        GetStateValidatorsResponseResponse, ValidatorResponseValidator,
        spec::{bellatrix, electra, phase0},
        v1,
        valcache::ValidatorCache,
        versioned::{self, AttestationPayload},
    };
    use pluto_testutil::BeaconMock;
    use rand::{SeedableRng, rngs::StdRng};
    use serde_json::{Value, json};
    use tree_hash::TreeHash;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::{
        signeddata::{
            SignedSyncContributionAndProof, SignedSyncMessage, SignedVoluntaryExit,
            VersionedAttestation, VersionedSignedAggregateAndProof, VersionedSignedProposal,
            VersionedSignedValidatorRegistration,
        },
        types::{Duty, Slot, SlotNumber},
    };

    fn validator_datum(
        index: u64,
        pubkey: &phase0::BLSPubKey,
        status: ValidatorStatus,
        activation_epoch: u64,
    ) -> GetStateValidatorsResponseResponseDatum {
        GetStateValidatorsResponseResponseDatum {
            index: index.to_string(),
            balance: "32000000000".to_string(),
            status,
            validator: ValidatorResponseValidator {
                pubkey: hex0x(pubkey),
                withdrawal_credentials:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                effective_balance: "32000000000".to_string(),
                slashed: false,
                activation_eligibility_epoch: "0".to_string(),
                activation_epoch: activation_epoch.to_string(),
                exit_epoch: "18446744073709551615".to_string(),
                withdrawable_epoch: "18446744073709551615".to_string(),
            },
        }
    }

    /// Builds a [`BeaconNodeClient`] whose validator cache is backed by the
    /// `head` validators endpoint returning `datums`.
    async fn cached_client(
        beacon: &BeaconMock,
        datums: Vec<GetStateValidatorsResponseResponseDatum>,
    ) -> BeaconNodeClient {
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                GetStateValidatorsResponseResponse {
                    execution_optimistic: false,
                    finalized: true,
                    data: datums,
                },
            ))
            .with_priority(1)
            .mount(beacon.server())
            .await;

        let client = BeaconNodeClient::new(beacon.client().clone());
        client
            .set_validator_cache(ValidatorCache::new(beacon.client().clone(), vec![]))
            .await;
        client
    }

    fn pubkey(byte: u8) -> PubKey {
        PubKey::from([byte; 48])
    }

    fn signed_set(pubkey: PubKey, data: impl SignedData + 'static) -> SignedDataSet {
        HashMap::from([(pubkey, Box::new(data) as Box<dyn SignedData>)])
    }

    fn hex0x(bytes: impl AsRef<[u8]>) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    async fn new_broadcaster() -> (BeaconMock, Broadcaster) {
        let beacon = BeaconMock::builder().build().await.expect("beacon mock");
        mount_submit_successes(beacon.server()).await;
        let broadcaster = Broadcaster::new(BeaconNodeClient::new(beacon.client().clone()))
            .await
            .expect("broadcaster");

        (beacon, broadcaster)
    }

    async fn mount_submit_successes(server: &MockServer) {
        for endpoint in [
            "/eth/v2/beacon/pool/attestations",
            "/eth/v2/beacon/blocks",
            "/eth/v2/beacon/blinded_blocks",
            "/eth/v1/validator/register_validator",
            "/eth/v1/beacon/pool/voluntary_exits",
            "/eth/v2/validator/aggregate_and_proofs",
            "/eth/v1/beacon/pool/sync_committees",
            "/eth/v1/validator/contribution_and_proofs",
        ] {
            Mock::given(method("POST"))
                .and(path(endpoint))
                .respond_with(ResponseTemplate::new(200))
                .with_priority(1)
                .mount(server)
                .await;
        }
    }

    async fn mount_prior_attestation_known(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "code": 400,
                "message": "invalid attestation",
                "failures": [
                    { "index": 0, "message": "Verification: PriorAttestationKnown" }
                ]
            })))
            .with_priority(1)
            .mount(server)
            .await;
    }

    fn attester_duties_body(
        slot: phase0::Slot,
        validator_index: phase0::ValidatorIndex,
        pubkey: phase0::BLSPubKey,
    ) -> Value {
        json!({
            "data": [{
                "pubkey": hex0x(pubkey),
                "validator_index": validator_index.to_string(),
                "committee_index": "0",
                "committee_length": "1",
                "committees_at_slot": "1",
                "validator_committee_index": "0",
                "slot": slot.to_string()
            }],
            "dependent_root": hex0x([0u8; 32]),
            "execution_optimistic": false
        })
    }

    fn deterministic_electra_spec() -> Value {
        json!({
            "SECONDS_PER_SLOT": "12",
            "SLOTS_PER_EPOCH": "16",
            "GENESIS_FORK_VERSION": "0x01017000",
            "ALTAIR_FORK_VERSION": "0x20000910",
            "ALTAIR_FORK_EPOCH": "0",
            "BELLATRIX_FORK_VERSION": "0x30000910",
            "BELLATRIX_FORK_EPOCH": "1",
            "CAPELLA_FORK_VERSION": "0x40000910",
            "CAPELLA_FORK_EPOCH": "2",
            "DENEB_FORK_VERSION": "0x50000910",
            "DENEB_FORK_EPOCH": "2",
            "ELECTRA_FORK_VERSION": "0x60000910",
            "ELECTRA_FORK_EPOCH": "3",
            "FULU_FORK_VERSION": "0x70000910",
            "FULU_FORK_EPOCH": u64::MAX.to_string(),
            "DOMAIN_BEACON_ATTESTER": "0x01000000",
            "DOMAIN_VOLUNTARY_EXIT": "0x04000000",
        })
    }

    fn attestation_data(slot: u64, epoch: u64) -> phase0::AttestationData {
        phase0::AttestationData {
            slot,
            index: 3,
            beacon_block_root: [1; 32],
            source: phase0::Checkpoint {
                epoch: epoch.saturating_sub(1),
                root: [2; 32],
            },
            target: phase0::Checkpoint {
                epoch,
                root: [3; 32],
            },
        }
    }

    fn deneb_attestation() -> versioned::VersionedAttestation {
        versioned::VersionedAttestation {
            version: versioned::DataVersion::Deneb,
            validator_index: Some(7),
            attestation: Some(AttestationPayload::Deneb(phase0::Attestation {
                aggregation_bits: phase0::BitList::with_bits(8, &[0]),
                data: attestation_data(4, 1),
                signature: [4; 96],
            })),
        }
    }

    fn signed_electra_attestation(
        secret: &pluto_crypto::types::PrivateKey,
        domain: phase0::Domain,
        slot: u64,
        epoch: u64,
    ) -> versioned::VersionedAttestation {
        let data = attestation_data(slot, epoch);
        let signing_root = phase0::SigningData {
            object_root: data.tree_hash_root().0,
            domain,
        }
        .tree_hash_root()
        .0;
        let signature = BlstImpl.sign(secret, &signing_root).expect("sign");

        versioned::VersionedAttestation {
            version: versioned::DataVersion::Electra,
            validator_index: None,
            attestation: Some(AttestationPayload::Electra(electra::Attestation {
                aggregation_bits: phase0::BitList::with_bits(8, &[0]),
                data,
                signature,
                committee_bits: pluto_ssz::BitVector::with_bits(&[3]),
            })),
        }
    }

    fn phase0_body() -> phase0::BeaconBlockBody {
        phase0::BeaconBlockBody {
            randao_reveal: [0; 96],
            eth1_data: phase0::ETH1Data {
                deposit_root: [0; 32],
                deposit_count: 0,
                block_hash: [0; 32],
            },
            graffiti: [0; 32],
            proposer_slashings: phase0::SszList::from(vec![]),
            attester_slashings: phase0::SszList::from(vec![]),
            attestations: phase0::SszList::from(vec![]),
            deposits: phase0::SszList::from(vec![]),
            voluntary_exits: phase0::SszList::from(vec![]),
        }
    }

    fn phase0_signed_proposal() -> versioned::VersionedSignedProposal {
        versioned::VersionedSignedProposal {
            version: versioned::DataVersion::Phase0,
            blinded: false,
            block: versioned::SignedProposalBlock::Phase0(phase0::SignedBeaconBlock {
                message: phase0::BeaconBlock {
                    slot: 1,
                    proposer_index: 2,
                    parent_root: [3; 32],
                    state_root: [4; 32],
                    body: phase0_body(),
                },
                signature: [5; 96],
            }),
        }
    }

    fn bellatrix_blinded_proposal() -> versioned::VersionedSignedProposal {
        versioned::VersionedSignedProposal {
            version: versioned::DataVersion::Bellatrix,
            blinded: true,
            block: versioned::SignedProposalBlock::BellatrixBlinded(
                bellatrix::SignedBlindedBeaconBlock {
                    message: bellatrix::BlindedBeaconBlock {
                        slot: 1,
                        proposer_index: 2,
                        parent_root: [3; 32],
                        state_root: [4; 32],
                        body: bellatrix::BlindedBeaconBlockBody {
                            randao_reveal: [0; 96],
                            eth1_data: phase0::ETH1Data {
                                deposit_root: [0; 32],
                                deposit_count: 0,
                                block_hash: [0; 32],
                            },
                            graffiti: [0; 32],
                            proposer_slashings: phase0::SszList::from(vec![]),
                            attester_slashings: phase0::SszList::from(vec![]),
                            attestations: phase0::SszList::from(vec![]),
                            deposits: phase0::SszList::from(vec![]),
                            voluntary_exits: phase0::SszList::from(vec![]),
                            sync_aggregate: altair::SyncAggregate {
                                sync_committee_bits: Default::default(),
                                sync_committee_signature: [0; 96],
                            },
                            execution_payload_header: bellatrix::ExecutionPayloadHeader {
                                parent_hash: [0; 32],
                                fee_recipient: [0; 20],
                                state_root: [0; 32],
                                receipts_root: [0; 32],
                                logs_bloom: [0; 256],
                                prev_randao: [0; 32],
                                block_number: 0,
                                gas_limit: 0,
                                gas_used: 0,
                                timestamp: 0,
                                extra_data: phase0::SszList::from(vec![]),
                                base_fee_per_gas: alloy::primitives::U256::ZERO,
                                block_hash: [0; 32],
                                transactions_root: [0; 32],
                            },
                        },
                    },
                    signature: [9; 96],
                },
            ),
        }
    }

    fn registration() -> versioned::VersionedSignedValidatorRegistration {
        versioned::VersionedSignedValidatorRegistration {
            version: versioned::BuilderVersion::V1,
            v1: Some(v1::SignedValidatorRegistration {
                message: v1::ValidatorRegistration {
                    fee_recipient: [1; 20],
                    gas_limit: 30_000_000,
                    timestamp: 42,
                    pubkey: [2; 48],
                },
                signature: [3; 96],
            }),
        }
    }

    fn signed_exit(index: u64) -> phase0::SignedVoluntaryExit {
        phase0::SignedVoluntaryExit {
            message: phase0::VoluntaryExit {
                epoch: 1,
                validator_index: index,
            },
            signature: [4; 96],
        }
    }

    fn signed_aggregate() -> versioned::VersionedSignedAggregateAndProof {
        versioned::VersionedSignedAggregateAndProof {
            version: versioned::DataVersion::Deneb,
            aggregate_and_proof: versioned::SignedAggregateAndProofPayload::Deneb(
                phase0::SignedAggregateAndProof {
                    message: phase0::AggregateAndProof {
                        aggregator_index: 1,
                        aggregate: phase0::Attestation {
                            aggregation_bits: phase0::BitList::with_bits(8, &[0]),
                            data: attestation_data(4, 1),
                            signature: [5; 96],
                        },
                        selection_proof: [6; 96],
                    },
                    signature: [7; 96],
                },
            ),
        }
    }

    fn sync_message() -> altair::SyncCommitteeMessage {
        altair::SyncCommitteeMessage {
            slot: 1,
            beacon_block_root: [2; 32],
            validator_index: 3,
            signature: [4; 96],
        }
    }

    fn sync_contribution() -> altair::SignedContributionAndProof {
        altair::SignedContributionAndProof {
            message: altair::ContributionAndProof {
                aggregator_index: 1,
                contribution: altair::SyncCommitteeContribution {
                    slot: 2,
                    beacon_block_root: [3; 32],
                    subcommittee_index: 4,
                    aggregation_bits: Default::default(),
                    signature: [5; 96],
                },
                selection_proof: [6; 96],
            },
            signature: [7; 96],
        }
    }

    #[tokio::test]
    async fn broadcast_attester_submits_and_swallows_prior_known() {
        let beacon = BeaconMock::builder().build().await.expect("beacon mock");
        mount_prior_attestation_known(beacon.server()).await;
        let broadcaster = Broadcaster::new(BeaconNodeClient::new(beacon.client().clone()))
            .await
            .expect("broadcaster");
        let set = signed_set(
            pubkey(1),
            VersionedAttestation::new(deneb_attestation()).expect("attestation"),
        );

        broadcaster
            .broadcast(Duty::new_attester_duty(SlotNumber::new(1)), set)
            .await
            .expect("prior known swallowed");

        let post_paths = beacon
            .server()
            .received_requests()
            .await
            .expect("requests")
            .into_iter()
            .filter(|request| request.method.as_str() == "POST")
            .map(|request| request.url.path().to_string())
            .collect::<Vec<_>>();
        assert_eq!(post_paths, vec!["/eth/v2/beacon/pool/attestations"]);
    }

    #[tokio::test]
    async fn broadcast_attester_backfills_electra_validator_index() {
        let secret = BlstImpl
            .generate_insecure_secret(StdRng::seed_from_u64(42))
            .expect("secret");
        let public_key = BlstImpl.secret_to_public_key(&secret).expect("pubkey");
        let beacon = BeaconMock::builder()
            .spec(deterministic_electra_spec())
            .endpoint_overrides(vec![(
                "/eth/v1/validator/duties/attester/3".to_string(),
                attester_duties_body(12, 99, public_key),
            )])
            .build()
            .await
            .expect("beacon mock");
        let domain = beacon
            .client()
            .fetch_beacon_attester_domain(3)
            .await
            .expect("domain");
        let client = cached_client(
            &beacon,
            vec![validator_datum(
                99,
                &public_key,
                ValidatorStatus::ActiveOngoing,
                0,
            )],
        )
        .await;
        let attestation = signed_electra_attestation(&secret, domain, 12, 3);
        assert!(
            attestation_matches_duty(
                &attestation,
                &AttesterDuty {
                    slot: 12,
                    validator_index: 99,
                    pubkey: public_key,
                },
                domain,
            )
            .expect("matching attestation")
        );
        assert_eq!(
            beacon
                .client()
                .fetch_attester_duties_for_indices(3, vec![99])
                .await
                .expect("duties"),
            vec![AttesterDuty {
                slot: 12,
                validator_index: 99,
                pubkey: public_key,
            }]
        );
        assert_eq!(
            beacon
                .client()
                .fetch_beacon_attester_domain(3)
                .await
                .expect("domain"),
            domain
        );
        let broadcaster = Broadcaster::new(client).await.expect("broadcaster");

        let mut attestations = vec![attestation];
        broadcaster
            .populate_missing_validator_indices(&mut attestations)
            .await
            .expect("populate validator index");

        assert_eq!(attestations[0].validator_index, Some(99));
    }

    #[tokio::test]
    async fn broadcast_routes_all_submit_duties() {
        let (beacon, broadcaster) = new_broadcaster().await;

        let proposal = phase0_signed_proposal();
        broadcaster
            .broadcast(
                Duty::new_proposer_duty(SlotNumber::new(1)),
                signed_set(
                    pubkey(1),
                    VersionedSignedProposal::new(proposal.clone()).expect("proposal"),
                ),
            )
            .await
            .expect("proposal");

        let blinded = bellatrix_blinded_proposal();
        broadcaster
            .broadcast(
                Duty::new_proposer_duty(SlotNumber::new(1)),
                signed_set(
                    pubkey(1),
                    VersionedSignedProposal::new(blinded.clone()).expect("proposal"),
                ),
            )
            .await
            .expect("blinded");

        let registration = registration();
        broadcaster
            .broadcast(
                Duty::new_builder_registration_duty(SlotNumber::new(0)),
                signed_set(
                    pubkey(2),
                    VersionedSignedValidatorRegistration::new(registration.clone())
                        .expect("registration"),
                ),
            )
            .await
            .expect("registration");

        let exit = signed_exit(3);
        broadcaster
            .broadcast(
                Duty::new_voluntary_exit_duty(SlotNumber::new(1)),
                signed_set(pubkey(3), SignedVoluntaryExit::new(exit.clone())),
            )
            .await
            .expect("exit");

        let aggregate = signed_aggregate();
        broadcaster
            .broadcast(
                Duty::new_aggregator_duty(SlotNumber::new(1)),
                signed_set(
                    pubkey(4),
                    VersionedSignedAggregateAndProof::new(aggregate.clone()),
                ),
            )
            .await
            .expect("aggregate");

        let message = sync_message();
        broadcaster
            .broadcast(
                Duty::new_sync_message_duty(SlotNumber::new(1)),
                signed_set(pubkey(5), SignedSyncMessage::new(message.clone())),
            )
            .await
            .expect("sync message");

        let contribution = sync_contribution();
        broadcaster
            .broadcast(
                Duty::new_sync_contribution_duty(SlotNumber::new(1)),
                signed_set(
                    pubkey(6),
                    SignedSyncContributionAndProof::new(contribution.clone()),
                ),
            )
            .await
            .expect("sync contribution");

        let mut post_paths = beacon
            .server()
            .received_requests()
            .await
            .expect("requests")
            .into_iter()
            .filter(|request| request.method.as_str() == "POST")
            .map(|request| request.url.path().to_string())
            .collect::<Vec<_>>();
        post_paths.sort();
        assert_eq!(
            post_paths,
            vec![
                "/eth/v1/beacon/pool/sync_committees",
                "/eth/v1/beacon/pool/voluntary_exits",
                "/eth/v1/validator/contribution_and_proofs",
                "/eth/v1/validator/register_validator",
                "/eth/v2/beacon/blinded_blocks",
                "/eth/v2/beacon/blocks",
                "/eth/v2/validator/aggregate_and_proofs",
            ]
        );
    }

    #[tokio::test]
    async fn broadcast_other_duties_match_go_behavior() {
        let (_beacon, broadcaster) = new_broadcaster().await;

        assert!(matches!(
            broadcaster
                .broadcast(
                    Duty::new_builder_proposer_duty(SlotNumber::new(1)),
                    HashMap::new()
                )
                .await,
            Err(Error::DeprecatedDutyBuilderProposer)
        ));
        broadcaster
            .broadcast(Duty::new_randao_duty(SlotNumber::new(1)), HashMap::new())
            .await
            .expect("randao");
        broadcaster
            .broadcast(
                Duty::new_prepare_aggregator_duty(SlotNumber::new(1)),
                HashMap::new(),
            )
            .await
            .expect("prepare aggregator");
        broadcaster
            .broadcast(
                Duty::new_prepare_sync_contribution_duty(SlotNumber::new(1)),
                HashMap::new(),
            )
            .await
            .expect("prepare sync contribution");
        assert!(matches!(
            broadcaster
                .broadcast(Duty::new_info_sync_duty(SlotNumber::new(1)), HashMap::new())
                .await,
            Err(Error::UnsupportedDutyType)
        ));
    }

    #[test]
    fn set_conversion_errors_match_go_strings() {
        let bad = signed_set(pubkey(1), SignedVoluntaryExit::new(signed_exit(1)));

        assert_eq!(
            set_to_attestations(&bad).unwrap_err().to_string(),
            "invalid attestation"
        );
        assert_eq!(
            set_to_registrations(&bad).unwrap_err().to_string(),
            "invalid registration"
        );
        assert_eq!(
            set_to_agg_and_proof(&bad).unwrap_err().to_string(),
            "invalid aggregate and proof"
        );
        assert_eq!(
            set_to_sync_messages(&bad).unwrap_err().to_string(),
            "invalid sync committee message"
        );
        assert_eq!(
            set_to_sync_contributions(&bad).unwrap_err().to_string(),
            "invalid sync committee contribution"
        );
        assert_eq!(
            set_to_one(&HashMap::new()).unwrap_err().to_string(),
            "expected one item in set"
        );
    }

    #[tokio::test]
    async fn resolve_active_validators_indices_filters_active_and_activation_epoch() {
        let beacon = BeaconMock::builder().build().await.expect("beacon mock");
        let client = cached_client(
            &beacon,
            vec![
                // active -> included
                validator_datum(1, &[1u8; 48], ValidatorStatus::ActiveExiting, 0),
                // inactive but activates at the queried epoch -> included
                validator_datum(2, &[2u8; 48], ValidatorStatus::PendingQueued, 9),
                // inactive, activates later -> excluded
                validator_datum(3, &[3u8; 48], ValidatorStatus::PendingQueued, 10),
            ],
        )
        .await;

        let mut indices = resolve_active_validators_indices(&client, 9)
            .await
            .expect("indices");
        indices.sort_unstable();
        assert_eq!(indices, vec![1, 2]);
    }

    /// Builds a recaster whose active-validator set resolves to `pubkey(1)`.
    async fn active_recaster(beacon: &BeaconMock) -> Recaster {
        let client = cached_client(
            beacon,
            vec![validator_datum(
                1,
                &[1u8; 48],
                ValidatorStatus::ActiveOngoing,
                0,
            )],
        )
        .await;
        Recaster::new(client)
    }

    #[tokio::test]
    async fn recaster_recasts_only_first_epoch_active_latest_registration() {
        let beacon = BeaconMock::builder().build().await.expect("beacon mock");
        let recaster = active_recaster(&beacon).await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_clone = Arc::clone(&seen);
        recaster
            .subscribe(move |duty, set| {
                let seen = Arc::clone(&seen_clone);
                async move {
                    seen.lock().expect("seen").push((duty, set));
                    Ok(())
                }
            })
            .expect("subscribe");

        recaster
            .store(
                Duty::new_builder_registration_duty(SlotNumber::new(4)),
                &signed_set(
                    pubkey(1),
                    VersionedSignedValidatorRegistration::new(registration())
                        .expect("registration"),
                ),
            )
            .expect("store");
        recaster
            .store(
                Duty::new_builder_registration_duty(SlotNumber::new(2)),
                &signed_set(
                    pubkey(1),
                    VersionedSignedValidatorRegistration::new(registration())
                        .expect("registration"),
                ),
            )
            .expect("older ignored");
        recaster
            .store(
                Duty::new_builder_registration_duty(SlotNumber::new(5)),
                &signed_set(
                    pubkey(2),
                    VersionedSignedValidatorRegistration::new(registration())
                        .expect("registration"),
                ),
            )
            .expect("inactive stored");

        recaster
            .slot_ticked(Slot {
                slot: SlotNumber::new(5),
                time: Utc::now(),
                slot_duration: Duration::seconds(12),
                slots_per_epoch: 4,
            })
            .await
            .expect("not first");
        assert!(seen.lock().expect("seen").is_empty());

        recaster
            .slot_ticked(Slot {
                slot: SlotNumber::new(8),
                time: Utc::now(),
                slot_duration: Duration::seconds(12),
                slots_per_epoch: 4,
            })
            .await
            .expect("first");

        let seen = seen.lock().expect("seen");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0.slot, SlotNumber::new(4));
        assert!(seen[0].1.contains_key(&pubkey(1)));
        assert!(!seen[0].1.contains_key(&pubkey(2)));
    }

    #[tokio::test]
    async fn recaster_subscriber_error_is_not_returned() {
        let beacon = BeaconMock::builder().build().await.expect("beacon mock");
        let recaster = active_recaster(&beacon).await;
        recaster
            .subscribe(|_, _| async { Err(Error::UnsupportedDutyType) })
            .expect("subscribe");
        recaster
            .store(
                Duty::new_builder_registration_duty(SlotNumber::new(4)),
                &signed_set(
                    pubkey(1),
                    VersionedSignedValidatorRegistration::new(registration())
                        .expect("registration"),
                ),
            )
            .expect("store");

        recaster
            .slot_ticked(Slot {
                slot: SlotNumber::new(8),
                time: Utc::now(),
                slot_duration: Duration::seconds(12),
                slots_per_epoch: 4,
            })
            .await
            .expect("subscriber error logged only");
    }
}
