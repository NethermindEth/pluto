#![allow(missing_docs)]

use std::{
    collections::{HashMap, hash_map::Entry},
    time::Duration,
};

use backon::{BackoffBuilder, Retryable};
use pluto_eth2api::{EthBeaconNodeApiClientError, client};
use tokio::sync;
use tokio_util::{future::FutureExt, sync::CancellationToken};

use crate::{scheduler::metrics::SCHEDULER_METRICS, types, valcache};

mod metrics;

// Trim cached duties after 3 epochs. Note inclusion delay calculation requires
// now-32 slot duties.
const TRIM_EPOCH_OFFSET: u64 = 3;

/// Errors that can occur during the scheduling process.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    /// Beacon Node API client error.
    #[error("Error while fetching data from the Eth2 API: {0}")]
    EthBeaconNodeApiClientError(#[from] EthBeaconNodeApiClientError),

    /// Validator cache error.
    #[error("Error while accessing the validator cache: {0}")]
    ValidatorCacheError(#[from] valcache::ValidatorCacheError),

    /// Public key error.
    #[error("Error while processing public key: {0}")]
    PubKeyError(#[from] types::PubKeyError),

    /// Invalid duty pubkey.
    #[error("Invalid duty pubkey: expected {expected}, got {actual}")]
    InvalidDutyPubkey {
        /// Expected public key.
        expected: types::PubKey,
        /// Actual public key.
        actual: types::PubKey,
    },

    /// Attempted to use the deprecated [`types::DutyType::BuilderProposer`]
    /// duty type.
    #[error("Deprecated duty DutyType::BuilderProposer")]
    DeprecatedDutyBuilderProposer,

    /// Attempted to get a duty definition for an epoch that has already been
    /// trimmed.
    #[error("Epoch {epoch} has already been trimmed")]
    EpochAlreadyTrimmed {
        /// Trimmed epoch
        epoch: u64,

        /// Duty attempted to be accessed
        duty: types::Duty,
    },

    /// Attempted to get a duty definition for an epoch that has not been
    /// resolved yet.
    #[error("Epoch {epoch} has not been resolved yet")]
    EpochNotResolved { epoch: u64 },

    /// Duty definition not found for a resolved epoch.
    #[error("Duty {duty} definition set not found in the resolved epoch {epoch}")]
    DutyNotFound {
        /// The resolved epoch.
        epoch: u64,

        /// Duty attempted to be accessed
        duty: types::Duty,
    },
    /// Timed out while waiting for the scheduler to respond with a duty
    /// definition.
    #[error("Timed out while waiting for a duty definition")]
    TimeoutError,

    /// The underlying scheduler actor has been terminated.
    #[error("Scheduler actor has been terminated")]
    Terminated,
}

type Result<T> = std::result::Result<T, SchedulerError>;

pub struct Builder {
    slot_broadcast: sync::broadcast::Sender<types::Slot>,
    duty_broadcast: sync::broadcast::Sender<(types::Duty, types::DutyDefinitionSet)>,
    reorg_rx: sync::mpsc::Receiver<u64>,
}

impl Builder {
    /// Construct a default [`Builder`] with no chain reorg handling.
    pub fn new() -> Self {
        Builder {
            slot_broadcast: sync::broadcast::channel(100).0,
            duty_broadcast: sync::broadcast::channel(100).0,
            reorg_rx: sync::mpsc::channel(100).1, // A channel that never receives
        }
    }

    /// Subscribes a callback function for triggered slots.
    pub fn subscribe_slot(
        &mut self,
        f: impl Fn(&types::Slot) -> Result<()> + Send + 'static,
        label: impl AsRef<str> + Send + 'static,
    ) {
        let mut rx = self.slot_broadcast.subscribe();

        // TODO: We might want to return a handle so clients can `.abort()` them to drop
        // the subscription
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(slot) => {
                        if let Err(err) = f(&slot) {
                            tracing::error!(err = ?err, slot = %slot.slot, label = label.as_ref(), "Emit scheduled slot event");
                        }
                    }
                    // NOTE: A lagging subscriber requires further analysis.
                    // Log the error and terminate the subscription.
                    Err(sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::error!(
                            skipped,
                            label = label.as_ref(),
                            "Emit scheduled slot subscriber lagged"
                        );
                        break;
                    }
                    Err(sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    /// Subscribes a callback function for triggered duties.
    pub fn subscribe_duty(
        &mut self,
        f: impl Fn(&types::Duty, &types::DutyDefinitionSet) -> Result<()> + Send + 'static,
        label: impl AsRef<str> + Send + 'static,
    ) {
        let mut rx = self.duty_broadcast.subscribe();

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok((duty, set)) => {
                        if let Err(err) = f(&duty, &set) {
                            tracing::error!(err = ?err, label = label.as_ref(), "Trigger duty subscriber error");
                        }
                    }
                    // NOTE: Same as in `subscribe_slot`
                    Err(sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::error!(
                            skipped,
                            label = label.as_ref(),
                            "Trigger duty subscriber lagged"
                        );
                        break;
                    }
                    Err(sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    /// Add a source of chain reorgs to the scheduler.
    ///
    /// Disabled by default.
    pub fn with_chain_reorgs(&mut self, reorg_rx: sync::mpsc::Receiver<u64>) {
        // NOTE: The SSE feature check should be done by the caller
        self.reorg_rx = reorg_rx;
    }

    /// Construct a new Scheduler which runs in the background. This operation
    /// will block until the chain has started and the beacon node is synced.
    ///
    /// Listeners for duties and slots should be registered before calling this
    /// function.
    ///
    /// The returned [`Handle`] can be used to query the scheduler for duty
    /// definitions.
    pub async fn build(
        self,
        client: client::EthBeaconNodeApiClient,
        ct: CancellationToken,
    ) -> Result<Handle> {
        wait_chain_start(&client)
            .with_cancellation_token(&ct)
            .await
            .ok_or(SchedulerError::Terminated)??;
        wait_beacon_sync(&client)
            .with_cancellation_token(&ct)
            .await
            .ok_or(SchedulerError::Terminated)??;

        let slot_rx = new_slot_ticker(&client.clone(), ct.clone()).await?;

        let actor = Actor {
            client: client.clone(),
            // TODO: Figure out what to pass as `pub_keys`.
            // In Charon, these are not used (dead code)
            valcache: valcache::ValidatorCache::new(client.clone(), Vec::new()),

            slot_broadcast: self.slot_broadcast,
            duty_broadcast: self.duty_broadcast,

            resolved_epoch: u64::MAX,
            duties: HashMap::new(),
            duties_by_epoch: HashMap::new(),
        };

        let (msg_tx, msg_rx) = sync::mpsc::channel(100);
        let handle = Handle { sender: msg_tx };
        tokio::spawn(actor.run(slot_rx, msg_rx, self.reorg_rx, ct));

        Ok(handle)
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}
enum Message {
    GetDutyDefinition {
        duty: types::Duty,
        resp: sync::oneshot::Sender<Result<types::DutyDefinitionSet>>,
    },
}

pub struct Handle {
    sender: sync::mpsc::Sender<Message>,
}

impl Handle {
    /// Returns the definition for a duty if a definition exists for a resolved
    /// epoch.
    ///
    /// NOTE: this operation has a default timeout of 100 ms.
    pub async fn get_duty_definition(&self, duty: types::Duty) -> Result<types::DutyDefinitionSet> {
        let (tx, rx) = sync::oneshot::channel();
        let msg = Message::GetDutyDefinition { duty, resp: tx };

        self.sender
            .send(msg)
            .await
            .map_err(|_| SchedulerError::Terminated)?;

        // This has to be very rare event, when the requested epoch is being resolved.
        // We wait for the epoch to be resolved before returning the duty definition.
        tokio::time::timeout(Duration::from_millis(100), rx)
            .await
            .map_err(|_| SchedulerError::TimeoutError)?
            .map_err(|_| SchedulerError::Terminated)?
    }
}

struct Actor {
    client: client::EthBeaconNodeApiClient,
    valcache: valcache::ValidatorCache,

    slot_broadcast: sync::broadcast::Sender<types::Slot>,
    duty_broadcast: sync::broadcast::Sender<(types::Duty, types::DutyDefinitionSet)>,

    resolved_epoch: u64,
    duties: HashMap<types::Duty, types::DutyDefinitionSet>,
    duties_by_epoch: HashMap<u64, Vec<types::Duty>>,
}

impl Actor {
    async fn run(
        mut self,
        mut slot_rx: sync::mpsc::Receiver<types::Slot>,
        mut msg_rx: sync::mpsc::Receiver<Message>,
        mut reorg_rx: sync::mpsc::Receiver<u64>,
        ct: CancellationToken,
    ) {
        loop {
            tokio::select! {
                biased;

                _ = ct.cancelled() => break,

                Some(epoch) = reorg_rx.recv() => {
                    self.handle_chain_reorg(epoch).await;
                },

                Some(msg) = msg_rx.recv() => match msg {
                    Message::GetDutyDefinition { duty, resp } => {
                        let result = self.get_duty_definition(duty).await;
                        let _ = resp.send(result);
                    },
                },

                Some(slot) = slot_rx.recv() => {
                    tracing::debug!(slot = %slot.slot, "Slot ticked");

                    SCHEDULER_METRICS.current_slot.set(slot.slot.inner());
                    SCHEDULER_METRICS.current_epoch.set(slot.epoch());

                    // NOTE: Ignore send errors, it means that there are no subscribers.
                    let _ = self.slot_broadcast.send(slot.clone());

                    self.schedule_slot(slot, ct.clone()).await;
                },
            }
        }
    }

    /// In case of a reorg of an already resolved epoch trim all duties.
    ///
    /// Duties will be resolved again in the nex slot.
    pub async fn handle_chain_reorg(&mut self, epoch: u64) {
        let resolved_epoch = self.resolved_epoch;
        if epoch < resolved_epoch {
            self.trim_duties(resolved_epoch);
            self.resolved_epoch = u64::MAX;

            tracing::info!(
                reorg_epoch = epoch,
                resolved_epoch,
                "Chain reorg event handled, duties trimmed"
            )
        }
    }

    /// Returns the definition for a duty if a definition exists for a resolved
    /// epoch.
    async fn get_duty_definition(&mut self, duty: types::Duty) -> Result<types::DutyDefinitionSet> {
        if duty.duty_type == types::DutyType::BuilderProposer {
            return Err(SchedulerError::DeprecatedDutyBuilderProposer);
        }

        let (_, slots_per_epoch) = self.client.fetch_slots_config().await?;
        let epoch = duty.slot.inner() / slots_per_epoch;

        if !self.is_epoch_resolved(epoch) {
            return Err(SchedulerError::EpochNotResolved { epoch });
        }

        if self.is_epoch_trimmed(epoch) {
            return Err(SchedulerError::EpochAlreadyTrimmed { epoch, duty });
        }

        let def_set = self
            .duties
            .get(&duty)
            .ok_or_else(|| SchedulerError::DutyNotFound { epoch, duty })?;

        Ok(def_set.clone())
    }

    /// Resolves upcoming duties and triggers resolved duties for the given
    /// slot.
    async fn schedule_slot(&mut self, slot: types::Slot, ct: CancellationToken) {
        if self.resolved_epoch != slot.epoch() {
            tracing::debug!(slot = %slot.slot, epoch = %slot.epoch(), "Resolving duties for slot");

            if let Err(err) = self.resolve_duties(slot.clone()).await {
                tracing::warn!(err = ?err, slot = %slot.slot, "Resolving duties error (retrying next slot)");
            }
        }

        for duty_type in types::DutyType::all() {
            let duty = types::Duty {
                duty_type,
                slot: slot.slot,
            };

            let def_set = {
                let Some(def_set) = self.duties.get(&duty) else {
                    // Nothing for this duty.
                    continue;
                };

                def_set.clone()
            };

            let ct = ct.clone();
            let slot = slot.clone();
            let broadcast = self.duty_broadcast.clone();
            tokio::spawn(async move {
                if let None = delay_slot_offset(&slot, &duty)
                    .with_cancellation_token_owned(ct)
                    .await
                {
                    // Cancelled early
                    return;
                }

                SCHEDULER_METRICS.duty_total[&duty.duty_type.to_string()]
                    .inc_by(def_set.len() as u64);

                // NOTE: Ignore send errors, it means that there are no subscribers.
                let _ = broadcast.send((duty.clone(), def_set.clone()));
            });
        }

        if slot.last_in_epoch() {
            if let Err(err) = self.resolve_duties(slot.next_slot()).await {
                tracing::warn!(err = ?err, slot = %slot.slot, "Resolving duties error (retrying next slot)");
            }
        }
    }

    /// Resolves the duties for the slot's epoch, storing the results.
    async fn resolve_duties(&mut self, slot: types::Slot) -> Result<()> {
        // NOTE: Resolving duties requires fetching data from a Beacon node.
        // During this time the Scheduler actor is blocked.
        // This is the same behavior as in Charon, but it might not be desirable.

        let vals = resolve_active_validators(slot.epoch(), &self.valcache).await?;

        SCHEDULER_METRICS.validators_active.set(vals.len() as u64);

        if vals.is_empty() {
            tracing::info!(slot = %slot.slot, "No active validators for slot");
            self.resolved_epoch = slot.epoch();
            return Ok(());
        }

        // Resolve Attester duties
        {
            let att_duties = fetch_attester_duties(&slot, &vals, &self.client).await?;
            for att_duty in att_duties.into_iter() {
                if !self.set_duty_definition(
                    types::Duty::new_attester_duty(att_duty.slot),
                    slot.epoch(),
                    att_duty.pubkey,
                    types::DutyDefinition::Attester(att_duty.clone()),
                ) {
                    continue;
                }

                tracing::info!(
                    slot = %att_duty.slot,
                    vidx = %att_duty.v_idx,
                    pubkey = %att_duty.pubkey,
                    epoch = %slot.epoch(),
                    "Resolved attester duty"
                );

                // Schedule Aggregator duty as well
                let agg_duty = types::Duty::new_aggregator_duty(att_duty.slot);
                self.set_duty_definition(
                    agg_duty,
                    slot.epoch(),
                    att_duty.pubkey,
                    types::DutyDefinition::Attester(att_duty),
                );
            }
        }

        // Resolve Proposer duties
        {
            let pro_duties = fetch_proposer_duties(&slot, &vals, &self.client).await?;
            for pro_duty in pro_duties.into_iter() {
                if !self.set_duty_definition(
                    types::Duty::new_proposer_duty(pro_duty.slot),
                    slot.epoch(),
                    pro_duty.pubkey,
                    types::DutyDefinition::Proposer(pro_duty.clone()),
                ) {
                    continue;
                }

                tracing::info!(
                    slot = %pro_duty.slot,
                    vidx = %pro_duty.v_idx,
                    pubkey = %pro_duty.pubkey,
                    epoch = %slot.epoch(),
                    "Resolved proposer duty"
                );
            }
        }

        // Resolve Sync Committee duties
        {
            let sync_duties = fetch_sync_committee_duties(&slot, &vals, &self.client).await?;
            for sync_duty in sync_duties.into_iter() {
                // TODO(charon): sync committee duties start in the slot before the sync
                // committee period.
                // Refer: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#sync-committee
                for sl in slot
                    .iter()
                    .take_while(|other| other.epoch() == slot.epoch())
                {
                    self.set_duty_definition(
                        types::Duty::new_sync_contribution_duty(sl.slot),
                        sl.epoch(),
                        sync_duty.pubkey,
                        types::DutyDefinition::SyncCommittee(sync_duty.clone()),
                    );
                }

                tracing::info!(
                    vidx = %&sync_duty.validator_index,
                    pubkey = %sync_duty.pubkey,
                    epoch = %slot.epoch(),
                    "Resolved sync committee duty"
                );
            }
        }

        self.resolved_epoch = slot.epoch();
        self.trim_duties(slot.epoch().saturating_sub(TRIM_EPOCH_OFFSET));

        Ok(())
    }

    /// Inserts a duty definition for a given pubkey.
    ///
    /// Returns true if it's set, false if it was already set.
    fn set_duty_definition(
        &mut self,
        duty: types::Duty,
        epoch: u64,
        pub_key: types::PubKey,
        definition: types::DutyDefinition,
    ) -> bool {
        let def_set = self.duties.entry(duty.clone()).or_default();
        match def_set.entry(pub_key) {
            Entry::Occupied(_) => return false,
            Entry::Vacant(entry) => {
                entry.insert(definition);
            }
        };
        self.duties_by_epoch
            .entry(epoch)
            .or_insert(Vec::new())
            .push(duty);

        true
    }

    /// Deletes all duties for the given epoch.
    fn trim_duties(&mut self, epoch: u64) {
        let duties = self.duties_by_epoch.remove(&epoch);
        if let Some(duties) = duties
            && duties.len() > 0
        {
            for duty in duties {
                self.duties.remove(&duty);
            }
        }
    }

    /// Returns true if the epoch's duties have been trimmed
    fn is_epoch_trimmed(&self, epoch: u64) -> bool {
        if self.resolved_epoch == u64::MAX {
            return false;
        }

        self.resolved_epoch >= epoch + TRIM_EPOCH_OFFSET
    }

    /// Returns true if the epoch is resolved
    fn is_epoch_resolved(&self, epoch: u64) -> bool {
        if self.resolved_epoch == u64::MAX {
            return false;
        }

        self.resolved_epoch >= epoch
    }
}

/// Create a read channel that will be populated with new slots in real time.
/// It is also populated with the current slot immediately.
///
/// The production of slots is cancelled when the provided [`CancellationToken`]
/// is cancelled.
async fn new_slot_ticker(
    client: &client::EthBeaconNodeApiClient,
    ct: CancellationToken,
) -> Result<sync::mpsc::Receiver<types::Slot>> {
    let genesis_time = client.fetch_genesis_time().await?;
    let (slot_duration, slots_per_epoch) = client.fetch_slots_config().await?;
    let slot_duration = chrono::Duration::from_std(slot_duration).unwrap();

    let current_slot = move || {
        let chain_age = chrono::Utc::now() - genesis_time;
        let slot_ms = slot_duration.num_milliseconds();
        let slot = chain_age.num_milliseconds() / slot_ms;
        let start_time = genesis_time + chrono::Duration::milliseconds(slot * slot_ms);

        types::Slot {
            slot: types::SlotNumber::new(slot as u64),
            time: start_time,
            slots_per_epoch,
            slot_duration,
        }
    };

    let (tx, rx) = sync::mpsc::channel(100);
    tokio::spawn(async move {
        let mut slot = current_slot();

        loop {
            let wait = (slot.time - chrono::Utc::now())
                .to_std()
                .unwrap_or_default();
            tokio::time::sleep(wait).await;

            // Avoid "thundering herd" problem by skipping slots if missed due
            // to pause-the-world events (i.e. resources are already constrained).
            if chrono::Utc::now() > slot.next_slot().time {
                let actual = current_slot();
                tracing::warn!(actual_slot = %actual.slot, expect_slot = %slot.slot, "Slot(s) skipped");
                SCHEDULER_METRICS.skipped_slots_total.inc();
                slot = actual;
            }

            let next_slot = slot.next_slot();

            tokio::select! {
                _ = ct.cancelled() => break,
                _ = tx.send(slot) => {},
            }

            slot = next_slot;
        }
    });

    Ok(rx)
}

struct Validator {
    pubkey: types::PubKey,
    v_idx: pluto_eth2api::spec::phase0::ValidatorIndex,
}

/// Returns the active validators (including their validator index) for the
/// epoch.
async fn resolve_active_validators(
    epoch: u64,
    valcache: &valcache::ValidatorCache,
) -> Result<Vec<Validator>> {
    let (_, complete) = valcache.get_by_head().await?;

    let mut validators = vec![];
    for (index, val) in complete.iter() {
        let pubkey = types::PubKey::try_from(val.validator.pubkey.as_str())?;

        // Submit validator balance and status metrics.
        // Equivalent to Charon's `newMetricSubmitter` closure
        let pubkey_full = pubkey.to_string();
        let pubkey_abbrev = pubkey.abbreviated();
        let balance = val.balance.parse::<u64>().unwrap_or_default();
        SCHEDULER_METRICS.validator_balance_gwei[&(pubkey_full.clone(), pubkey_abbrev.clone())]
            .set(balance);

        // Emulate Charon's `statusGauge.Reset`:
        // Vise's `Family` cannot delete series, so instead set any previously-reported
        // status for this validator to 0 and the current one to 1.
        let status = val.status.to_string();
        for ((full, abbrev, prev_status), gauge) in SCHEDULER_METRICS.validator_status.to_entries()
        {
            if full == pubkey_full && abbrev == pubkey_abbrev && prev_status != status {
                gauge.set(0);
            }
        }
        SCHEDULER_METRICS.validator_status[&(pubkey_full, pubkey_abbrev, status)].set(1);

        // Check for active validators for the given epoch.
        // The activation epoch needs to be checked in cases where this function is
        // called before the epoch starts.
        if !val.status.is_active() {
            let activation_epoch = val.validator.activation_epoch.parse::<u64>().map_err(|_| {
                pluto_eth2api::EthBeaconNodeApiClientError::ParseError("activation_epoch".into())
            })?;

            if activation_epoch != epoch {
                continue;
            }
        }

        validators.push(Validator {
            pubkey,
            v_idx: *index,
        });
    }

    Ok(validators)
}

// TODO: Duplicated from `crates/p2p/src/bootnode.rs`
fn fast_backoff() -> backon::ExponentialBuilder {
    /// Backoff configuration constants matching Go's expbackoff.FastConfig.
    const FAST_BASE_DELAY: Duration = Duration::from_millis(100);
    const FAST_MAX_DELAY: Duration = Duration::from_secs(5);
    const FAST_MULTIPLIER: f32 = 1.6;

    backon::ExponentialBuilder::default()
        .with_min_delay(FAST_BASE_DELAY)
        .with_max_delay(FAST_MAX_DELAY)
        .with_factor(FAST_MULTIPLIER)
        .without_max_times()
        .with_jitter()
}

fn default_backoff() -> backon::ExponentialBuilder {
    /// Backoff configuration constants matching Go's expbackoff.DefaultConfig.
    const DEFAULT_BASE_DELAY: Duration = Duration::from_secs(1);
    const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(120);
    const DEFAULT_MULTIPLIER: f32 = 1.6;

    backon::ExponentialBuilder::default()
        .with_min_delay(DEFAULT_BASE_DELAY)
        .with_max_delay(DEFAULT_MAX_DELAY)
        .with_factor(DEFAULT_MULTIPLIER)
        .without_max_times()
        .with_jitter()
}

/// Blocks until the beacon chain has started.
async fn wait_chain_start(client: &pluto_eth2api::client::EthBeaconNodeApiClient) -> Result<()> {
    let fetch = || client.fetch_genesis_time();
    let backoff = fast_backoff();
    let genesis_time = fetch
        .retry(backoff)
        .notify(|err, _| tracing::error!(err = ?err, "Failure getting genesis"))
        .await?;

    let now = chrono::Utc::now();
    if now < genesis_time {
        let delta = (genesis_time - now).to_std().unwrap_or_default();
        tracing::info!(genesis_time = %genesis_time, sleep = ?delta, "Sleeping until genesis time");
        tokio::time::sleep(delta).await;
    }

    Ok(())
}

/// Blocks until the beacon node is synced.
async fn wait_beacon_sync(client: &pluto_eth2api::client::EthBeaconNodeApiClient) -> Result<()> {
    let fetch = || client.get_syncing_status(pluto_eth2api::GetSyncingStatusRequest {});
    let fetch_backoff = fast_backoff();

    let mut is_syncing_backoff = default_backoff().build();

    loop {
        let response: pluto_eth2api::GetSyncingStatusResponse = fetch
            .retry(fetch_backoff)
            .notify(|err, _| tracing::error!(err = ?err, "Failure getting syncing status"))
            .await
            .map_err(pluto_eth2api::EthBeaconNodeApiClientError::RequestError)?;

        let state = match response {
            pluto_eth2api::GetSyncingStatusResponse::Ok(syncing) => Ok(syncing.data),
            _ => Err(pluto_eth2api::EthBeaconNodeApiClientError::UnexpectedResponse),
        }?;

        if state.is_syncing {
            tracing::info!(
                distance = state.sync_distance,
                "Waiting for beacon node to sync"
            );
            let duration = is_syncing_backoff
                .next()
                .expect("Infinite backoff should never return None");
            tokio::time::sleep(duration).await;
        } else {
            break;
        }
    }

    Ok(())
}

/// Blocks until the slot offset for the duty has been reached.
async fn delay_slot_offset(slot: &types::Slot, duty: &types::Duty) {
    let offset = match duty.duty_type {
        types::DutyType::Attester => slot.slot_duration / 3,
        types::DutyType::Aggregator => slot.slot_duration * 2 / 3,
        types::DutyType::SyncContribution => slot.slot_duration * 2 / 3,
        _ => return,
    };

    // Wait until the absolute deadline
    let deadline = slot.time + offset;
    let wait = (deadline - chrono::Utc::now()).to_std().unwrap_or_default();
    tokio::time::sleep(wait).await;
}

/// Fetches the attester duties for the given slot and validators, and validates
/// that the returned duties match the expected validators.
async fn fetch_attester_duties(
    slot: &types::Slot,
    validators: &Vec<Validator>,
    client: &client::EthBeaconNodeApiClient,
) -> Result<Vec<types::AttesterDutyDefinition>> {
    let req = pluto_eth2api::GetAttesterDutiesRequest::builder()
        .epoch(slot.epoch().to_string())
        .body(validators.iter().map(|v| v.v_idx.to_string()).collect())
        .build()
        .map_err(pluto_eth2api::EthBeaconNodeApiClientError::RequestError)?;
    let resp = client
        .get_attester_duties(req)
        .await
        .map_err(pluto_eth2api::EthBeaconNodeApiClientError::RequestError)?;

    let att_duties: Vec<types::AttesterDutyDefinition> = match resp {
        pluto_eth2api::GetAttesterDutiesResponse::Ok(duties) => duties
            .data
            .into_iter()
            .map(|d| {
                d.try_into()
                    .map_err(|_| pluto_eth2api::EthBeaconNodeApiClientError::UnexpectedResponse)
            })
            .collect::<std::result::Result<Vec<_>, _>>(),
        _ => Err(pluto_eth2api::EthBeaconNodeApiClientError::UnexpectedResponse),
    }?;

    let mut remaining = validators
        .iter()
        .map(|v| (v.v_idx, true))
        .collect::<std::collections::HashMap<_, _>>();

    let mut result = vec![];
    for att_duty in att_duties.into_iter() {
        remaining.remove(&att_duty.v_idx);

        if att_duty.slot < slot.slot {
            // Skip duties for earlier slots in initial epoch.
            continue;
        }

        let Some(pubkey) = validators
            .iter()
            .find(|v| v.v_idx == att_duty.v_idx)
            .map(|v| v.pubkey)
        else {
            tracing::warn!(
                vidx = att_duty.v_idx,
                slot = %slot.slot,
                "Ignoring unexpected attester duty"
            );
            continue;
        };

        if pubkey != att_duty.pubkey {
            return Err(SchedulerError::InvalidDutyPubkey {
                expected: pubkey,
                actual: att_duty.pubkey,
            });
        }

        result.push(att_duty);
    }

    if remaining.len() > 0 {
        tracing::warn!(
            slot = %slot.slot,
            epoch = %slot.epoch(),
            validator_indexes = ?remaining,
            "Missing attester duties",
        );
    }

    Ok(result)
}

/// Fetches the proposer duties for the given slot and validators, and validates
/// that the returned duties match the expected validators.
async fn fetch_proposer_duties(
    slot: &types::Slot,
    validators: &Vec<Validator>,
    client: &client::EthBeaconNodeApiClient,
) -> Result<Vec<types::ProposerDutyDefinition>> {
    let req = pluto_eth2api::GetProposerDutiesRequest::builder()
        .epoch(slot.epoch().to_string())
        .build()
        .map_err(pluto_eth2api::EthBeaconNodeApiClientError::RequestError)?;
    let resp = client
        .get_proposer_duties(req)
        .await
        .map_err(pluto_eth2api::EthBeaconNodeApiClientError::RequestError)?;

    let pro_duties: Vec<types::ProposerDutyDefinition> = match resp {
        pluto_eth2api::GetProposerDutiesResponse::Ok(duties) => duties
            .data
            .into_iter()
            .map(|d| {
                d.try_into()
                    .map_err(|_| pluto_eth2api::EthBeaconNodeApiClientError::UnexpectedResponse)
            })
            .collect::<std::result::Result<Vec<_>, _>>(),
        _ => Err(pluto_eth2api::EthBeaconNodeApiClientError::UnexpectedResponse),
    }?;

    let mut result = vec![];
    for pro_duty in pro_duties.into_iter() {
        if pro_duty.slot < slot.slot {
            // Skip duties for earlier slots in initial epoch.
            continue;
        }

        let Some(pubkey) = validators
            .iter()
            .find(|v| v.v_idx == pro_duty.v_idx)
            .map(|v| v.pubkey)
        else {
            tracing::warn!(
                vidx = pro_duty.v_idx,
                slot = %slot.slot,
                "Ignoring unexpected proposer duty"
            );
            continue;
        };

        if pubkey != pro_duty.pubkey {
            return Err(SchedulerError::InvalidDutyPubkey {
                expected: pubkey,
                actual: pro_duty.pubkey,
            });
        }

        result.push(pro_duty);
    }

    Ok(result)
}

/// Fetches the sync committee duties for the given slot and validators, and
/// validates that the returned duties match the expected validators.
async fn fetch_sync_committee_duties(
    slot: &types::Slot,
    validators: &Vec<Validator>,
    client: &client::EthBeaconNodeApiClient,
) -> Result<Vec<types::SyncCommitteeDutyDefinition>> {
    let req = pluto_eth2api::GetSyncCommitteeDutiesRequest::builder()
        .epoch(slot.epoch().to_string())
        .body(validators.iter().map(|v| v.v_idx.to_string()).collect())
        .build()
        .map_err(pluto_eth2api::EthBeaconNodeApiClientError::RequestError)?;
    let resp = client
        .get_sync_committee_duties(req)
        .await
        .map_err(pluto_eth2api::EthBeaconNodeApiClientError::RequestError)?;

    let sync_duties: Vec<types::SyncCommitteeDutyDefinition> = match resp {
        pluto_eth2api::GetSyncCommitteeDutiesResponse::Ok(duties) => duties
            .data
            .into_iter()
            .map(|d| {
                d.try_into()
                    .map_err(|_| pluto_eth2api::EthBeaconNodeApiClientError::UnexpectedResponse)
            })
            .collect::<std::result::Result<Vec<_>, _>>(),
        _ => Err(pluto_eth2api::EthBeaconNodeApiClientError::UnexpectedResponse),
    }?;

    let mut result = vec![];
    for sync_duty in sync_duties.into_iter() {
        let Some(pubkey) = validators
            .iter()
            .find(|v| v.v_idx == sync_duty.validator_index)
            .map(|v| v.pubkey)
        else {
            tracing::warn!(
                vidx = sync_duty.validator_index,
                slot = %slot.slot,
                "Ignoring unexpected sync committee duty"
            );
            continue;
        };

        if pubkey != sync_duty.pubkey {
            return Err(SchedulerError::InvalidDutyPubkey {
                expected: pubkey,
                actual: sync_duty.pubkey,
            });
        }

        result.push(sync_duty);
    }

    Ok(result)
}
