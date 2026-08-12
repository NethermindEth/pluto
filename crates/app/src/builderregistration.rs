//! Builder (validator) registration management.
//!
//! Port of `charon/app/builderregistration.go`.
//!
//! # Why this exists
//!
//! Registrations are *not* pushed through the DV duty workflow. The cluster
//! lock already carries a fully-aggregated, group-signed registration per
//! validator, so there is nothing to reach consensus on: each node holds the
//! same signed messages and submits them to its own beacon node once per
//! epoch. The validator client's own `register_validator` submissions are
//! ignored (see `pluto_core::validatorapi`), matching Charon.
//!
//! Two optional sources can override the lock's registrations, both keyed by
//! validator pubkey and both applied only when strictly newer than what they
//! replace:
//!
//! * an operator-managed JSON overrides file, watched for changes; and
//! * the Obol API, which aggregates partial signatures submitted by the
//!   cluster's operators (opt-in, off by default).

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use notify::{Event, EventKind, RecursiveMode, Watcher};
use pluto_core::{scheduler::metrics::SCHEDULER_METRICS, types::PubKey};
use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls, types::Signature};
use pluto_eth2api::{
    EthBeaconNodeApiClient, EthBeaconNodeApiClientError, ProposalPreparation,
    spec::{
        bellatrix::ExecutionAddress,
        phase0::{BLSPubKey, Version},
    },
    v1,
    validator_duty::ValidatorDutyError,
    versioned::{BuilderVersion, VersionedSignedValidatorRegistration},
};
use tokio_util::sync::CancellationToken;

use crate::obolapi::{Client, FeeRecipientValidator};

/// Poll interval while at least one validator still lacks a quorum of partial
/// signatures — the set is expected to change, so check back often.
const FETCH_INTERVAL_INCOMPLETE: Duration = Duration::from_secs(60 * 60);

/// Poll interval once every validator is fully signed. Nothing is expected to
/// change, so this is a low-frequency consistency check.
const FETCH_INTERVAL_COMPLETE: Duration = Duration::from_secs(24 * 60 * 60);

/// Errors constructing or reloading the service.
#[derive(Debug, thiserror::Error)]
pub enum BuilderRegistrationError {
    /// The overrides file could not be read.
    #[error("read builder registration overrides file {path}: {source}")]
    ReadOverrides {
        /// Path that failed to read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// The overrides file was not valid JSON, or not the expected shape.
    #[error("parse builder registration overrides file {path}: {source}")]
    ParseOverrides {
        /// Path that failed to parse.
        path: PathBuf,
        /// Underlying deserialisation error.
        source: serde_json::Error,
    },

    /// A registration in the overrides file has an invalid BLS signature. The
    /// whole file is rejected: a partially-applied override set would silently
    /// route some validators' rewards to an unintended address.
    #[error("verify builder registration override for 0x{pubkey}: {reason}")]
    InvalidOverrideSignature {
        /// Hex-encoded validator pubkey.
        pubkey: String,
        /// Why verification failed.
        reason: String,
    },
}

/// Snapshot of the effective registration state, swapped atomically on reload.
#[derive(Debug, Default)]
struct Effective {
    registrations: Vec<VersionedSignedValidatorRegistration>,
    fee_recipients: HashMap<PubKey, ExecutionAddress>,
}

/// Manages the cluster's builder registrations and fee recipients.
///
/// Cheap to clone: readers share one [`Arc`].
#[derive(Debug, Clone)]
pub struct BuilderRegistrationService {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// Overrides file, if configured.
    path: Option<PathBuf>,
    /// Genesis fork version, for registration signature verification.
    fork_version: Version,
    /// Registrations from the cluster lock — the always-present baseline.
    base_registrations: Vec<VersionedSignedValidatorRegistration>,
    /// Fee recipients from the cluster lock.
    base_fee_recipients: HashMap<PubKey, ExecutionAddress>,
    /// Obol API client, when background fetching is enabled.
    obol_client: Option<Client>,
    /// Cluster lock hash, scoping the Obol API requests.
    lock_hash: Vec<u8>,
    /// Current effective state. Only [`Inner::recompute`] writes it.
    effective: RwLock<Effective>,
}

/// Override sources, owned solely by the [`BuilderRegistrationService::run`]
/// task so they need no lock.
#[derive(Default)]
struct Overrides {
    file: Vec<VersionedSignedValidatorRegistration>,
    api: Vec<VersionedSignedValidatorRegistration>,
}

impl BuilderRegistrationService {
    /// Builds the service and applies the overrides file, if configured.
    ///
    /// A malformed overrides file is fatal here: it is operator-authored
    /// configuration, and starting with silently-ignored fee-recipient
    /// overrides is worse than refusing to start.
    pub fn new(
        path: Option<PathBuf>,
        fork_version: Version,
        base_registrations: Vec<VersionedSignedValidatorRegistration>,
        base_fee_recipients: HashMap<PubKey, ExecutionAddress>,
        obol_client: Option<Client>,
        lock_hash: Vec<u8>,
    ) -> Result<Self, BuilderRegistrationError> {
        let inner = Inner {
            path,
            fork_version,
            base_registrations,
            base_fee_recipients,
            obol_client,
            lock_hash,
            effective: RwLock::new(Effective::default()),
        };

        let mut overrides = Overrides::default();
        if let Some(path) = inner.path.as_deref() {
            overrides.file = load_overrides(path, inner.fork_version)?;
        }
        inner.recompute(&overrides);

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Returns the registrations to submit to the beacon node.
    pub fn registrations(&self) -> Vec<VersionedSignedValidatorRegistration> {
        self.inner.read_effective().registrations.clone()
    }

    /// Returns the effective fee recipient for `pubkey`, if known.
    pub fn fee_recipient(&self, pubkey: &PubKey) -> Option<ExecutionAddress> {
        self.inner
            .read_effective()
            .fee_recipients
            .get(pubkey)
            .copied()
    }

    /// Watches the overrides file and polls the Obol API until cancelled.
    ///
    /// Always runs until `ct` fires, even with nothing to watch — the node
    /// supervises this as a long-lived task and treats *any* task returning as
    /// a shutdown signal, so returning early would stop the node.
    pub async fn run(self, ct: CancellationToken) {
        if self.inner.path.is_none() && self.inner.obol_client.is_none() {
            // Nothing to watch: the lock's registrations are static.
            ct.cancelled().await;
            return;
        }

        let mut overrides = Overrides::default();
        if let Some(path) = self.inner.path.as_deref() {
            // Re-read rather than inherit from `new`, so `run` owns the state
            // it mutates and a reload failure here cannot desync the two. `new`
            // already validated the file, but it may have become unreadable in
            // the meantime — surface that rather than silently dropping every
            // override, as the reload arm below also does.
            overrides.file = load_overrides(path, self.inner.fork_version).unwrap_or_else(|err| {
                tracing::warn!(
                    %err,
                    path = %path.display(),
                    "Failed to load builder registration overrides at startup",
                );
                Vec::new()
            });
        }

        // Watch the *directory*, not the file: editors and `mv`-based atomic
        // writes replace the inode, which a file watch would stop following.
        let (file_tx, mut file_rx) = tokio::sync::mpsc::channel::<()>(1);
        let watcher = self
            .inner
            .path
            .as_deref()
            .and_then(|path| spawn_watcher(path, file_tx));
        // When the watcher failed to install, its sender was dropped and
        // `recv` would resolve `None` immediately, spinning the loop. Disable
        // that arm instead.
        let mut watching = watcher.is_some();
        let _watcher = watcher;

        // Fire the first fetch immediately, then back off by result.
        let mut fetch_interval = self
            .inner
            .obol_client
            .as_ref()
            .map(|_| Duration::from_millis(0));

        loop {
            let fetch_due = async {
                match fetch_interval {
                    Some(delay) => tokio::time::sleep(delay).await,
                    // No Obol client: never fires, leaving only the file watch.
                    None => std::future::pending().await,
                }
            };

            let file_changed = async {
                if watching {
                    file_rx.recv().await
                } else {
                    std::future::pending().await
                }
            };

            tokio::select! {
                () = ct.cancelled() => return,

                changed = file_changed => {
                    if changed.is_none() {
                        // Watcher stopped for good; fall back to API polling
                        // only (or idle until cancelled).
                        watching = false;
                        continue;
                    }
                    let Some(path) = self.inner.path.as_deref() else { continue };
                    match load_overrides(path, self.inner.fork_version) {
                        Ok(loaded) => {
                            overrides.file = loaded;
                            self.inner.recompute(&overrides);
                            tracing::info!(
                                path = %path.display(),
                                "Reloaded builder registration overrides from file",
                            );
                        }
                        Err(err) => tracing::warn!(
                            %err,
                            "Failed to reload builder registration overrides",
                        ),
                    }
                    // A file change may also mean new partial signatures were
                    // submitted, so re-fetch without waiting out the backoff.
                    if fetch_interval.is_some() {
                        fetch_interval = Some(Duration::from_millis(0));
                    }
                }

                () = fetch_due => {
                    let next = match self.inner.fetch_from_api(&mut overrides).await {
                        Ok(has_incomplete) if !has_incomplete => FETCH_INTERVAL_COMPLETE,
                        Ok(_) => FETCH_INTERVAL_INCOMPLETE,
                        Err(err) => {
                            tracing::warn!(%err, "Builder registration API fetch failed");
                            FETCH_INTERVAL_INCOMPLETE
                        }
                    };
                    fetch_interval = Some(next);
                }
            }
        }
    }
}

impl Inner {
    fn read_effective(&self) -> std::sync::RwLockReadGuard<'_, Effective> {
        self.effective
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Merges the override sources over the lock baseline and publishes the
    /// result.
    fn recompute(&self, overrides: &Overrides) {
        let mut fee_recipients = self.base_fee_recipients.clone();
        let merged = merge_overrides(&overrides.file, &overrides.api);

        let registrations = if merged.is_empty() {
            self.base_registrations.clone()
        } else {
            apply_overrides(&self.base_registrations, &merged, &mut fee_recipients)
        };

        let mut effective = self
            .effective
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        effective.registrations = registrations;
        effective.fee_recipients = fee_recipients;
    }

    /// Fetches from the Obol API and republishes. Returns whether any
    /// validator is still short of a quorum of partial signatures.
    async fn fetch_from_api(
        &self,
        overrides: &mut Overrides,
    ) -> Result<bool, crate::obolapi::ObolApiError> {
        let Some(client) = self.obol_client.as_ref() else {
            return Ok(false);
        };

        let response = client
            .post_fee_recipients_fetch(&self.lock_hash, Vec::new())
            .await?;
        let processed = process_validators(&response.validators);

        if !processed.aggregated.is_empty() {
            tracing::info!(
                fully_signed = processed.aggregated.len(),
                incomplete = processed.incomplete,
                "Fetched builder registrations from Obol API",
            );
        }

        overrides.api = filter_verified(processed.aggregated, self.fork_version);
        self.recompute(overrides);

        Ok(processed.incomplete > 0)
    }
}

/// Starts a directory watcher that signals `tx` when the overrides file
/// changes.
///
/// Returns `None` (with a warning) if the watcher cannot be created — file
/// watching is a convenience, not a correctness requirement, so the node
/// degrades to "overrides applied at startup" rather than failing.
fn spawn_watcher(
    path: &Path,
    tx: tokio::sync::mpsc::Sender<()>,
) -> Option<notify::RecommendedWatcher> {
    let dir = path.parent()?.to_path_buf();
    let base_name = path.file_name()?.to_owned();

    let mut watcher = notify::recommended_watcher(move |event: notify::Result<Event>| {
        let Ok(event) = event else {
            return;
        };
        if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            return;
        }
        if !event
            .paths
            .iter()
            .any(|changed| changed.file_name() == Some(base_name.as_os_str()))
        {
            return;
        }
        // A full channel already has a pending reload queued; coalescing the
        // burst an editor emits per save is the desired behaviour.
        let _ = tx.try_send(());
    })
    .inspect_err(|err| {
        tracing::warn!(
            %err,
            "Failed to create file watcher for builder registration overrides; \
             file watching disabled",
        );
    })
    .ok()?;

    watcher
        .watch(&dir, RecursiveMode::NonRecursive)
        .inspect_err(|err| {
            tracing::warn!(
                %err,
                dir = %dir.display(),
                "Failed to watch directory for builder registration overrides; \
                 file watching disabled",
            );
        })
        .ok()?;

    Some(watcher)
}

/// Outcome of processing an Obol API fetch response.
struct Processed {
    /// Registrations whose partial signatures reached quorum and were
    /// aggregated into a full signature.
    aggregated: Vec<VersionedSignedValidatorRegistration>,
    /// How many validators still lack a quorum.
    incomplete: usize,
}

/// Aggregates every quorum-reaching registration group and counts the rest.
fn process_validators(validators: &[FeeRecipientValidator]) -> Processed {
    let mut aggregated = Vec::new();
    let mut incomplete = 0usize;

    for validator in validators {
        let mut has_incomplete = false;

        for registration in &validator.builder_registrations {
            if !registration.quorum {
                has_incomplete = true;
                continue;
            }

            let partials: HashMap<u64, Signature> = registration
                .partial_signatures
                .iter()
                .filter_map(|partial| {
                    u64::try_from(partial.share_index)
                        .ok()
                        .map(|index| (index, partial.signature))
                })
                .collect();

            match BlstImpl.threshold_aggregate(&partials) {
                Ok(signature) => aggregated.push(VersionedSignedValidatorRegistration {
                    version: BuilderVersion::V1,
                    v1: Some(v1::SignedValidatorRegistration {
                        message: registration.message.clone(),
                        signature,
                    }),
                }),
                Err(err) => {
                    // One unusable group must not discard the whole fetch.
                    tracing::warn!(
                        %err,
                        pubkey = %validator.pubkey,
                        "Failed to aggregate builder registration partial signatures",
                    );
                    has_incomplete = true;
                }
            }
        }

        if has_incomplete {
            incomplete = incomplete.saturating_add(1);
        }
    }

    Processed {
        aggregated,
        incomplete,
    }
}

/// Drops registrations whose signature does not verify, keeping the rest.
///
/// Lenient by design: the API is a third party, and one bad entry should not
/// cost the cluster every other validator's override.
fn filter_verified(
    registrations: Vec<VersionedSignedValidatorRegistration>,
    fork_version: Version,
) -> Vec<VersionedSignedValidatorRegistration> {
    registrations
        .into_iter()
        .filter(
            |registration| match verify_registration(registration, fork_version) {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!(%err, "Skipping builder registration with invalid signature");
                    false
                }
            },
        )
        .collect()
}

/// Verifies a registration's BLS signature against the group pubkey carried in
/// its own message.
fn verify_registration(
    registration: &VersionedSignedValidatorRegistration,
    fork_version: Version,
) -> Result<(), BuilderRegistrationError> {
    let Some(v1) = registration.v1.as_ref() else {
        return Err(BuilderRegistrationError::InvalidOverrideSignature {
            pubkey: String::new(),
            reason: "missing V1 payload".to_owned(),
        });
    };

    let pubkey_hex = hex::encode(v1.message.pubkey);
    let signing_root =
        pluto_eth2util::registration::get_message_signing_root(&v1.message, fork_version);

    BlstImpl
        .verify(&v1.message.pubkey, &signing_root, &v1.signature)
        .map_err(|err| BuilderRegistrationError::InvalidOverrideSignature {
            pubkey: pubkey_hex,
            reason: err.to_string(),
        })
}

/// Reads and verifies the overrides file.
///
/// A missing file is not an error — overrides are optional. Any invalid
/// signature rejects the entire file (see
/// [`BuilderRegistrationError::InvalidOverrideSignature`]).
fn load_overrides(
    path: &Path,
    fork_version: Version,
) -> Result<Vec<VersionedSignedValidatorRegistration>, BuilderRegistrationError> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(BuilderRegistrationError::ReadOverrides {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let registrations: Vec<VersionedSignedValidatorRegistration> = serde_json::from_slice(&data)
        .map_err(|source| BuilderRegistrationError::ParseOverrides {
            path: path.to_path_buf(),
            source,
        })?;

    for registration in &registrations {
        verify_registration(registration, fork_version)?;
    }

    Ok(registrations)
}

/// Combines the two override sources, newest timestamp per pubkey winning.
/// File overrides win ties, so an operator's local file always beats the API.
fn merge_overrides(
    file: &[VersionedSignedValidatorRegistration],
    api: &[VersionedSignedValidatorRegistration],
) -> Vec<VersionedSignedValidatorRegistration> {
    if file.is_empty() {
        return api.to_vec();
    }
    if api.is_empty() {
        return file.to_vec();
    }

    merge_registrations(file, api)
}

/// Merges `incoming` into `base`, keeping the newer entry per pubkey. `base`
/// wins ties. Entries without a V1 payload are dropped. Output is sorted by
/// pubkey so the result is deterministic regardless of map iteration order.
fn merge_registrations(
    base: &[VersionedSignedValidatorRegistration],
    incoming: &[VersionedSignedValidatorRegistration],
) -> Vec<VersionedSignedValidatorRegistration> {
    let mut by_pubkey: HashMap<BLSPubKey, VersionedSignedValidatorRegistration> = HashMap::new();

    for registration in base {
        if let Some(v1) = registration.v1.as_ref() {
            by_pubkey.insert(v1.message.pubkey, registration.clone());
        }
    }

    for registration in incoming {
        let Some(v1) = registration.v1.as_ref() else {
            continue;
        };
        let is_newer = by_pubkey
            .get(&v1.message.pubkey)
            .and_then(|previous| previous.v1.as_ref())
            .is_none_or(|previous| v1.message.timestamp > previous.message.timestamp);

        if is_newer {
            by_pubkey.insert(v1.message.pubkey, registration.clone());
        }
    }

    // Every value came from a `v1`-carrying entry above, so the sort key is
    // always present; the fallback keeps this total without an unwrap.
    let mut merged: Vec<_> = by_pubkey.into_values().collect();
    merged.sort_by_key(|registration| {
        registration
            .v1
            .as_ref()
            .map_or([0u8; 48], |v1| v1.message.pubkey)
    });

    merged
}

/// Replaces baseline entries with strictly-newer overrides, updating the fee
/// recipient map alongside so both stay consistent.
fn apply_overrides(
    base: &[VersionedSignedValidatorRegistration],
    overrides: &[VersionedSignedValidatorRegistration],
    fee_recipients: &mut HashMap<PubKey, ExecutionAddress>,
) -> Vec<VersionedSignedValidatorRegistration> {
    let by_pubkey: HashMap<BLSPubKey, &VersionedSignedValidatorRegistration> = overrides
        .iter()
        .filter_map(|registration| {
            registration
                .v1
                .as_ref()
                .map(|v1| (v1.message.pubkey, registration))
        })
        .collect();

    base.iter()
        .map(|registration| {
            let Some(v1) = registration.v1.as_ref() else {
                return registration.clone();
            };
            let Some(override_registration) = by_pubkey.get(&v1.message.pubkey) else {
                return registration.clone();
            };
            let Some(override_v1) = override_registration.v1.as_ref() else {
                return registration.clone();
            };
            if override_v1.message.timestamp <= v1.message.timestamp {
                return registration.clone();
            }

            let pubkey = PubKey::new(v1.message.pubkey);
            fee_recipients.insert(pubkey, override_v1.message.fee_recipient);
            tracing::info!(
                pubkey = %hex::encode(v1.message.pubkey),
                fee_recipient = %format!("0x{}", hex::encode(override_v1.message.fee_recipient)),
                "Applied builder registration override",
            );

            (*override_registration).clone()
        })
        .collect()
}

/// Sentinel for "no epoch submitted yet". Real epochs never reach it.
const NO_EPOCH: u64 = u64::MAX;

/// Submits the cluster's builder registrations to the beacon node once per
/// epoch.
///
/// Charon drives this from inside the scheduler; Pluto registers it as a slot
/// subscriber instead, because `pluto-core` cannot depend on `pluto-app` and
/// `subscribe_slot` already provides per-event task spawning, error logging
/// and cancellation.
#[derive(Debug, Clone)]
pub struct RegistrationSubmitter {
    service: BuilderRegistrationService,
    eth2_cl: EthBeaconNodeApiClient,
    /// Last epoch whose submission *succeeded*, so a failure retries next
    /// epoch rather than being recorded as done.
    submitted_epoch: Arc<std::sync::atomic::AtomicU64>,
}

impl RegistrationSubmitter {
    /// Creates a submitter for the given service and beacon client.
    pub fn new(service: BuilderRegistrationService, eth2_cl: EthBeaconNodeApiClient) -> Self {
        Self {
            service,
            eth2_cl,
            submitted_epoch: Arc::new(std::sync::atomic::AtomicU64::new(NO_EPOCH)),
        }
    }

    /// Submits the registrations for `epoch`, unless that epoch already
    /// succeeded.
    pub async fn submit(&self, epoch: u64) -> Result<(), ValidatorDutyError> {
        if self
            .submitted_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            == epoch
        {
            return Ok(());
        }

        let registrations = self.service.registrations();
        if registrations.is_empty() {
            return Ok(());
        }

        let count = registrations.len();
        SCHEDULER_METRICS.submit_registration_total.inc();

        match self
            .eth2_cl
            .submit_validator_registrations(registrations)
            .await
        {
            Ok(()) => {
                self.submitted_epoch
                    .store(epoch, std::sync::atomic::Ordering::Release);
                tracing::info!(count, epoch, "Submitted validator registrations");
                Ok(())
            }
            Err(err) => {
                SCHEDULER_METRICS.submit_registration_errors_total.inc();
                tracing::error!(%err, epoch, "Failed to submit validator registrations");
                Err(err)
            }
        }
    }
}

/// Pushes each validator's fee recipient to the beacon node via
/// `prepare_beacon_proposer`.
///
/// The beacon node retains a preparation for the submitting epoch plus the
/// next two, so this is resent every epoch. Charon does the same in
/// `setFeeRecipient`; without it the beacon node builds locally-produced
/// blocks paying its own default address rather than the operator's.
pub async fn submit_proposal_preparations(
    service: &BuilderRegistrationService,
    eth2_cl: &EthBeaconNodeApiClient,
    validator_indices: &HashMap<PubKey, u64>,
) -> Result<(), EthBeaconNodeApiClientError> {
    if validator_indices.is_empty() {
        return Ok(());
    }

    let mut preparations: Vec<ProposalPreparation> = validator_indices
        .iter()
        .filter_map(|(pubkey, index)| {
            service
                .fee_recipient(pubkey)
                .map(|fee_recipient| ProposalPreparation {
                    validator_index: *index,
                    fee_recipient,
                })
        })
        .collect();

    if preparations.is_empty() {
        return Ok(());
    }

    // Deterministic order keeps the request body stable across epochs, which
    // makes diffing beacon-node logs practical.
    preparations.sort_by_key(|preparation| preparation.validator_index);

    eth2_cl.submit_proposal_preparations(&preparations).await?;
    tracing::debug!(
        count = preparations.len(),
        "Submitted proposal preparations to beacon node",
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use pluto_crypto::{
        tbls::Tbls,
        types::{PrivateKey, PublicKey},
    };

    use super::*;

    fn keypair(seed: u8) -> (PrivateKey, PublicKey) {
        let secret = BlstImpl.generate_secret_key(rand::thread_rng()).unwrap();
        let public = BlstImpl.secret_to_public_key(&secret).unwrap();
        // `seed` only documents intent at call sites; keys are random.
        let _ = seed;
        (secret, public)
    }

    fn signed_registration(
        secret: &PrivateKey,
        pubkey: PublicKey,
        fee_recipient: ExecutionAddress,
        timestamp: u64,
        fork_version: Version,
    ) -> VersionedSignedValidatorRegistration {
        let message = v1::ValidatorRegistration {
            fee_recipient,
            gas_limit: 30_000_000,
            timestamp,
            pubkey,
        };
        let root = pluto_eth2util::registration::get_message_signing_root(&message, fork_version);
        let signature = BlstImpl.sign(secret, &root).unwrap();

        VersionedSignedValidatorRegistration {
            version: BuilderVersion::V1,
            v1: Some(v1::SignedValidatorRegistration { message, signature }),
        }
    }

    const FORK: Version = [0x10, 0x00, 0x00, 0x38];

    #[test]
    fn base_registrations_are_served_without_overrides() {
        let (secret, pubkey) = keypair(1);
        let base = signed_registration(&secret, pubkey, [0x11; 20], 100, FORK);

        let service = BuilderRegistrationService::new(
            None,
            FORK,
            vec![base.clone()],
            HashMap::from([(PubKey::new(pubkey), [0x11; 20])]),
            None,
            vec![0xaa],
        )
        .unwrap();

        assert_eq!(service.registrations(), vec![base]);
        assert_eq!(
            service.fee_recipient(&PubKey::new(pubkey)),
            Some([0x11; 20]),
        );
    }

    /// A strictly-newer override replaces the lock entry and moves the fee
    /// recipient with it.
    #[test]
    fn newer_override_replaces_base_and_fee_recipient() {
        let (secret, pubkey) = keypair(1);
        let base = signed_registration(&secret, pubkey, [0x11; 20], 100, FORK);
        let newer = signed_registration(&secret, pubkey, [0x22; 20], 200, FORK);

        let mut fee_recipients = HashMap::from([(PubKey::new(pubkey), [0x11; 20])]);
        let applied = apply_overrides(&[base], std::slice::from_ref(&newer), &mut fee_recipients);

        assert_eq!(applied, vec![newer]);
        assert_eq!(fee_recipients[&PubKey::new(pubkey)], [0x22; 20]);
    }

    /// An older or equal-timestamp override is ignored — a stale file must not
    /// roll a validator's fee recipient backwards.
    #[test]
    fn older_or_equal_override_is_ignored() {
        let (secret, pubkey) = keypair(1);
        let base = signed_registration(&secret, pubkey, [0x11; 20], 200, FORK);

        for timestamp in [100, 200] {
            let candidate = signed_registration(&secret, pubkey, [0x22; 20], timestamp, FORK);
            let mut fee_recipients = HashMap::from([(PubKey::new(pubkey), [0x11; 20])]);
            let applied = apply_overrides(
                std::slice::from_ref(&base),
                &[candidate],
                &mut fee_recipients,
            );

            assert_eq!(applied, vec![base.clone()], "timestamp {timestamp}");
            assert_eq!(fee_recipients[&PubKey::new(pubkey)], [0x11; 20]);
        }
    }

    /// File overrides beat API overrides at the same timestamp.
    #[test]
    fn file_overrides_win_ties_against_api() {
        let (secret, pubkey) = keypair(1);
        let from_file = signed_registration(&secret, pubkey, [0xff; 20], 100, FORK);
        let from_api = signed_registration(&secret, pubkey, [0xaa; 20], 100, FORK);

        let merged = merge_overrides(std::slice::from_ref(&from_file), &[from_api]);

        assert_eq!(merged, vec![from_file]);
    }

    #[test]
    fn merge_prefers_newer_and_sorts_by_pubkey() {
        let (secret_a, pubkey_a) = keypair(1);
        let (secret_b, pubkey_b) = keypair(2);
        let older = signed_registration(&secret_a, pubkey_a, [0x11; 20], 100, FORK);
        let newer = signed_registration(&secret_a, pubkey_a, [0x22; 20], 300, FORK);
        let other = signed_registration(&secret_b, pubkey_b, [0x33; 20], 100, FORK);

        let merged = merge_registrations(&[older, other.clone()], std::slice::from_ref(&newer));

        assert_eq!(merged.len(), 2);
        let mut expected = vec![newer, other];
        expected.sort_by_key(|r| r.v1.as_ref().unwrap().message.pubkey);
        assert_eq!(merged, expected);
    }

    #[test]
    fn missing_overrides_file_is_not_an_error() {
        let loaded = load_overrides(Path::new("/nonexistent/overrides.json"), FORK).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn overrides_file_round_trips() {
        let (secret, pubkey) = keypair(1);
        let registration = signed_registration(&secret, pubkey, [0x22; 20], 200, FORK);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("overrides.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&vec![registration.clone()]).unwrap(),
        )
        .unwrap();

        assert_eq!(load_overrides(&path, FORK).unwrap(), vec![registration]);
    }

    /// A tampered signature rejects the whole file rather than silently
    /// dropping the entry: these decide where block rewards go.
    #[test]
    fn overrides_file_with_bad_signature_is_rejected() {
        let (secret, pubkey) = keypair(1);
        let mut registration = signed_registration(&secret, pubkey, [0x22; 20], 200, FORK);
        registration.v1.as_mut().unwrap().signature = [0x00; 96];

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("overrides.json");
        std::fs::write(&path, serde_json::to_vec(&vec![registration]).unwrap()).unwrap();

        assert!(matches!(
            load_overrides(&path, FORK),
            Err(BuilderRegistrationError::InvalidOverrideSignature { .. }),
        ));
    }

    /// The API is untrusted, so a bad entry is dropped and the good ones kept.
    #[test]
    fn api_registrations_with_bad_signatures_are_dropped_individually() {
        let (secret_a, pubkey_a) = keypair(1);
        let (secret_b, pubkey_b) = keypair(2);
        let good = signed_registration(&secret_a, pubkey_a, [0x11; 20], 100, FORK);
        let mut bad = signed_registration(&secret_b, pubkey_b, [0x22; 20], 100, FORK);
        bad.v1.as_mut().unwrap().signature = [0x00; 96];

        let kept = filter_verified(vec![good.clone(), bad], FORK);

        assert_eq!(kept, vec![good]);
    }

    /// Threshold-aggregated groups become full registrations; groups short of
    /// quorum are counted, not aggregated.
    #[test]
    fn process_validators_aggregates_quorum_groups() {
        use crate::obolapi::{FeeRecipientBuilderRegistration, FeeRecipientPartialSig};

        let secret = BlstImpl.generate_secret_key(rand::thread_rng()).unwrap();
        let pubkey = BlstImpl.secret_to_public_key(&secret).unwrap();
        let shares = BlstImpl.threshold_split(&secret, 4, 3).unwrap();

        let message = v1::ValidatorRegistration {
            fee_recipient: [0x33; 20],
            gas_limit: 30_000_000,
            timestamp: 500,
            pubkey,
        };
        let root = pluto_eth2util::registration::get_message_signing_root(&message, FORK);

        let partial_signatures = shares
            .iter()
            .take(3)
            .map(|(index, share)| FeeRecipientPartialSig {
                share_index: i64::try_from(*index).unwrap(),
                signature: BlstImpl.sign(share, &root).unwrap(),
            })
            .collect();

        let processed = process_validators(&[FeeRecipientValidator {
            pubkey: format!("0x{}", hex::encode(pubkey)),
            builder_registrations: vec![
                FeeRecipientBuilderRegistration {
                    message: message.clone(),
                    partial_signatures,
                    quorum: true,
                },
                FeeRecipientBuilderRegistration {
                    message,
                    partial_signatures: Vec::new(),
                    quorum: false,
                },
            ],
        }]);

        assert_eq!(processed.aggregated.len(), 1);
        assert_eq!(processed.incomplete, 1);
        // The aggregate must verify against the group pubkey, i.e. it is
        // usable as a real registration.
        verify_registration(&processed.aggregated[0], FORK).unwrap();
    }
}
