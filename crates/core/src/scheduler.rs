use std::{
    collections::{HashMap, hash_map::Entry},
    time::Duration,
};

use backon::{BackoffBuilder, Retryable};
use tokio::sync;
use tokio_util::{future::FutureExt, sync::CancellationToken};

use crate::{scheduler::metrics::SCHEDULER_METRICS, types};
use pluto_eth2api::valcache;

mod metrics;

// Trim cached duties after 3 epochs. Note inclusion delay calculation requires
// now-32 slot duties.
const TRIM_EPOCH_OFFSET: u64 = 3;

// Default buffer size for the channels used in the [`SchedulerActor`]
const CHANNEL_BUFFER_SIZE: usize = 100;

/// Errors that can occur during the scheduling process.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    /// Beacon Node API client error.
    #[error("Error while fetching data from the Eth2 API: {0}")]
    EthBeaconNodeApiClientError(#[from] pluto_eth2api::EthBeaconNodeApiClientError),

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
    EpochNotResolved {
        /// The unresolved epoch.
        epoch: u64,

        /// Duty attempted to be accessed
        duty: types::Duty,
    },

    /// Duty definition not found for a resolved epoch.
    #[error("Duty {duty} definition set not found in the resolved epoch {epoch}")]
    DutyNotFound {
        /// The resolved epoch.
        epoch: u64,

        /// Duty attempted to be accessed
        duty: types::Duty,
    },

    /// The underlying scheduler actor has been terminated.
    #[error("Scheduler actor has been terminated")]
    Terminated,
}

type Result<T> = std::result::Result<T, SchedulerError>;

/// A builder for the Scheduler.
///
/// Allows setting up subscriptions for slot and duty events, as well as
/// well as setting up a source of chain reorg events.
///
/// The Scheduler can be started by calling [`SchedulerBuilder::build`].
pub struct SchedulerBuilder {
    slot_broadcast: sync::broadcast::Sender<types::Slot>,
    duty_broadcast: sync::broadcast::Sender<(types::Duty, types::DutyDefinitionSet)>,
    reorg_rx: sync::mpsc::Receiver<u64>,
}

impl SchedulerBuilder {
    /// Construct a default [`SchedulerBuilder`] with no chain reorg handling.
    pub fn new() -> Self {
        SchedulerBuilder {
            slot_broadcast: sync::broadcast::channel(CHANNEL_BUFFER_SIZE).0,
            duty_broadcast: sync::broadcast::channel(CHANNEL_BUFFER_SIZE).0,
            reorg_rx: sync::mpsc::channel(CHANNEL_BUFFER_SIZE).1, // A channel that never receives
        }
    }

    /// Subscribes a callback function for triggered slots.
    pub fn subscribe_slot<F, Fut, E>(&mut self, f: F, label: impl AsRef<str> + Send + 'static)
    where
        F: Fn(&types::Slot) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = std::result::Result<(), E>> + Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        let mut rx = self.slot_broadcast.subscribe();

        // TODO: We might want to return a handle so clients can `.abort()` them to drop
        // the subscription
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(slot) => {
                        if let Err(err) = f(&slot).await {
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
    pub fn subscribe_duty<F, Fut, E>(&mut self, f: F, label: impl AsRef<str> + Send + 'static)
    where
        F: Fn(&types::Duty, &types::DutyDefinitionSet) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = std::result::Result<(), E>> + Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        let mut rx = self.duty_broadcast.subscribe();

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok((duty, set)) => {
                        if let Err(err) = f(&duty, &set).await {
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
    /// The returned [`SchedulerHandle`] can be used to query the scheduler for
    /// duty definitions.
    pub async fn build(
        self,
        client: pluto_eth2api::BeaconNodeClient,
        ct: CancellationToken,
    ) -> Result<SchedulerHandle> {
        wait_chain_start(&client)
            .with_cancellation_token(&ct)
            .await
            .ok_or(SchedulerError::Terminated)??;
        wait_beacon_sync(&client)
            .with_cancellation_token(&ct)
            .await
            .ok_or(SchedulerError::Terminated)??;

        let slot_rx = new_slot_ticker(&client, ct.clone()).await?;

        let actor = SchedulerActor {
            client: client.clone(),
            // TODO: Figure out what to pass as `pub_keys`.
            // In Charon, these are not used (dead code)
            slot_broadcast: self.slot_broadcast,
            duty_broadcast: self.duty_broadcast,

            resolved_epoch: u64::MAX,
            duties: HashMap::new(),
            duties_by_epoch: HashMap::new(),
        };

        let (msg_tx, msg_rx) = sync::mpsc::channel(CHANNEL_BUFFER_SIZE);
        let handle = SchedulerHandle { sender: msg_tx };
        tokio::spawn(actor.run(slot_rx, msg_rx, self.reorg_rx, ct));

        Ok(handle)
    }
}

impl Default for SchedulerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

enum SchedulerMessage {
    GetDutyDefinition {
        duty: types::Duty,
        resp: sync::oneshot::Sender<Result<types::DutyDefinitionSet>>,
    },
}

/// A handle to interact with the Scheduler actor.
///
/// Cloning the handle is cheap and allows sending messages to the actor from
/// multiple tasks.
#[derive(Clone)]
pub struct SchedulerHandle {
    sender: sync::mpsc::Sender<SchedulerMessage>,
}

impl SchedulerHandle {
    /// Returns the definition for a duty if a definition exists for a resolved
    /// epoch.
    pub async fn get_duty_definition(&self, duty: types::Duty) -> Result<types::DutyDefinitionSet> {
        let (tx, rx) = sync::oneshot::channel();
        let msg = SchedulerMessage::GetDutyDefinition { duty, resp: tx };

        self.sender
            .send(msg)
            .await
            .map_err(|_| SchedulerError::Terminated)?;

        rx.await.map_err(|_| SchedulerError::Terminated)?
    }
}

struct SchedulerActor {
    client: pluto_eth2api::BeaconNodeClient,

    slot_broadcast: sync::broadcast::Sender<types::Slot>,
    duty_broadcast: sync::broadcast::Sender<(types::Duty, types::DutyDefinitionSet)>,

    resolved_epoch: u64,
    duties: HashMap<types::Duty, types::DutyDefinitionSet>,
    duties_by_epoch: HashMap<u64, Vec<types::Duty>>,
}

impl SchedulerActor {
    async fn run(
        mut self,
        mut slot_rx: sync::mpsc::Receiver<types::Slot>,
        mut msg_rx: sync::mpsc::Receiver<SchedulerMessage>,
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
                    SchedulerMessage::GetDutyDefinition { duty, resp } => {
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
    async fn handle_chain_reorg(&mut self, epoch: u64) {
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

        // TODO: `client.fetch_slots_config` should be cached.
        let (_, slots_per_epoch) = self.client.api().fetch_slots_config().await?;
        let epoch = duty
            .slot
            .inner()
            .checked_div(slots_per_epoch)
            .expect("non-zero");

        if !self.is_epoch_resolved(epoch) {
            return Err(SchedulerError::EpochNotResolved { epoch, duty });
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
                if delay_slot_offset(&slot, &duty)
                    .with_cancellation_token_owned(ct)
                    .await
                    .is_none()
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

        if slot.last_in_epoch()
            && let Err(err) = self.resolve_duties(slot.next_slot()).await
        {
            tracing::warn!(err = ?err, slot = %slot.slot, "Resolving duties error (retrying next slot)");
        }
    }

    /// Resolves the duties for the slot's epoch, storing the results.
    async fn resolve_duties(&mut self, slot: types::Slot) -> Result<()> {
        // NOTE: Resolving duties requires fetching data from a Beacon node.
        // During this time the Scheduler actor is blocked.
        // This is the same behavior as in Charon, but it might not be desirable.

        let valcache = self.client.validator_cache().await;
        let vals = resolve_active_validators(slot.epoch(), &valcache).await?;

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
        // Only trim once there is an epoch old enough to trim.
        // NOTE: Charon relies on `uint64` underflow wrapping to a huge (absent) epoch
        // for epochs < 3. `checked_sub` reproduces that no-op
        if let Some(trim_epoch) = slot.epoch().checked_sub(TRIM_EPOCH_OFFSET) {
            self.trim_duties(trim_epoch);
        }

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
        self.duties_by_epoch.entry(epoch).or_default().push(duty);

        true
    }

    /// Deletes all duties for the given epoch.
    fn trim_duties(&mut self, epoch: u64) {
        let duties = self.duties_by_epoch.remove(&epoch);
        if let Some(duties) = duties
            && !duties.is_empty()
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

        self.resolved_epoch >= epoch.saturating_add(TRIM_EPOCH_OFFSET)
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
    client: &pluto_eth2api::BeaconNodeClient,
    ct: CancellationToken,
) -> Result<sync::mpsc::Receiver<types::Slot>> {
    let genesis_time = client.api().fetch_genesis_time().await?;
    let (slot_duration, slots_per_epoch) = client.api().fetch_slots_config().await?;
    let slot_duration = chrono::Duration::from_std(slot_duration).expect("within range");

    let current_slot = move || {
        let chain_age = chrono::Utc::now().signed_duration_since(genesis_time);
        let slot_ms = slot_duration.num_milliseconds();
        let slot = chain_age
            .num_milliseconds()
            .checked_div(slot_ms)
            .expect("non-zero");
        let start_offset =
            chrono::Duration::milliseconds(slot.checked_mul(slot_ms).expect("within range"));
        let start_time = genesis_time
            .checked_add_signed(start_offset)
            .expect("within range");

        types::Slot {
            slot: types::SlotNumber::new(slot.cast_unsigned()),
            time: start_time,
            slots_per_epoch,
            slot_duration,
        }
    };

    let (tx, rx) = sync::mpsc::channel(CHANNEL_BUFFER_SIZE);
    tokio::spawn(async move {
        let mut slot = current_slot();

        loop {
            let wait = slot
                .time
                .signed_duration_since(chrono::Utc::now())
                .to_std()
                .unwrap_or_default();

            if tokio::time::sleep(wait)
                .with_cancellation_token(&ct)
                .await
                .is_none()
            {
                // Cancelled early
                return;
            };

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
async fn wait_chain_start(client: &pluto_eth2api::BeaconNodeClient) -> Result<()> {
    let fetch = || client.api().fetch_genesis_time();
    let backoff = fast_backoff();
    let genesis_time = fetch
        .retry(backoff)
        .notify(|err, _| tracing::error!(err = ?err, "Failure getting genesis"))
        .await?;

    let now = chrono::Utc::now();
    if now < genesis_time {
        let delta = genesis_time
            .signed_duration_since(now)
            .to_std()
            .unwrap_or_default();
        tracing::info!(genesis_time = %genesis_time, sleep = ?delta, "Sleeping until genesis time");
        tokio::time::sleep(delta).await;
    }

    Ok(())
}

/// Blocks until the beacon node is synced.
async fn wait_beacon_sync(client: &pluto_eth2api::BeaconNodeClient) -> Result<()> {
    let fetch = || {
        client
            .api()
            .get_syncing_status(pluto_eth2api::GetSyncingStatusRequest {})
    };
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
    // A slot duration is small (~12s), so these never overflow chrono's range.
    let offset = match duty.duty_type {
        types::DutyType::Attester => slot.slot_duration.checked_div(3).expect("within range"),
        types::DutyType::Aggregator | types::DutyType::SyncContribution => slot
            .slot_duration
            .checked_mul(2)
            .and_then(|d| d.checked_div(3))
            .expect("within range"),
        _ => return,
    };

    // Wait until the absolute deadline
    let deadline = slot.time.checked_add_signed(offset).expect("within range");
    let wait = deadline
        .signed_duration_since(chrono::Utc::now())
        .to_std()
        .unwrap_or_default();
    tokio::time::sleep(wait).await;
}

/// Fetches the attester duties for the given slot and validators, and validates
/// that the returned duties match the expected validators.
async fn fetch_attester_duties(
    slot: &types::Slot,
    validators: impl AsRef<[Validator]>,
    client: &pluto_eth2api::BeaconNodeClient,
) -> Result<Vec<types::AttesterDutyDefinition>> {
    let validators = validators.as_ref();
    let req = pluto_eth2api::GetAttesterDutiesRequest::builder()
        .epoch(slot.epoch().to_string())
        .body(validators.iter().map(|v| v.v_idx.to_string()).collect())
        .build()
        .map_err(pluto_eth2api::EthBeaconNodeApiClientError::RequestError)?;
    let resp = client
        .api()
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
        .map(|v| v.v_idx)
        .collect::<std::collections::HashSet<_>>();

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

    if !remaining.is_empty() {
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
    validators: impl AsRef<[Validator]>,
    client: &pluto_eth2api::BeaconNodeClient,
) -> Result<Vec<types::ProposerDutyDefinition>> {
    let validators = validators.as_ref();
    let req = pluto_eth2api::GetProposerDutiesRequest::builder()
        .epoch(slot.epoch().to_string())
        .build()
        .map_err(pluto_eth2api::EthBeaconNodeApiClientError::RequestError)?;
    let resp = client
        .api()
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
    validators: impl AsRef<[Validator]>,
    client: &pluto_eth2api::BeaconNodeClient,
) -> Result<Vec<types::SyncCommitteeDutyDefinition>> {
    let validators = validators.as_ref();
    let req = pluto_eth2api::GetSyncCommitteeDutiesRequest::builder()
        .epoch(slot.epoch().to_string())
        .body(validators.iter().map(|v| v.v_idx.to_string()).collect())
        .build()
        .map_err(pluto_eth2api::EthBeaconNodeApiClientError::RequestError)?;
    let resp = client
        .api()
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use pluto_eth2api::{
        BeaconNodeClient, GetStateValidatorsResponseResponse,
        GetStateValidatorsResponseResponseDatum,
    };
    use pluto_testutil::{BeaconMock, ValidatorSet};
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::testutils::random_core_pub_key;

    /// Builds a beacon mock seeded with `ValidatorSetA` and deterministic
    /// duties for every duty type
    async fn duties_mock(slots_per_epoch: u64) -> BeaconMock {
        BeaconMock::builder()
            .validator_set(ValidatorSet::validator_set_a())
            .deterministic_attester_duties(0)
            .deterministic_proposer_duties(0)
            .deterministic_sync_comm_duties((2, 2))
            .slots_per_epoch(slots_per_epoch)
            .slot_duration(std::time::Duration::from_secs(12))
            .build()
            .await
            .expect("build beacon mock")
    }

    /// The `ValidatorSetA` validators as `/states/head/validators`.
    ///
    /// NOTE: the default mock only serves this endpoint over GET, but
    /// [`valcache::ValidatorCache::get_by_head`] queries it over POST.
    fn validator_set_a_datums() -> Vec<GetStateValidatorsResponseResponseDatum> {
        ValidatorSet::validator_set_a()
            .validators()
            .into_iter()
            .map(|v| GetStateValidatorsResponseResponseDatum {
                index: v.index.to_string(),
                balance: v.balance.to_string(),
                status: v.status,
                validator: v.validator,
            })
            .collect()
    }

    /// `ValidatorSetA` validators with their real indexes but random pubkeys,
    /// to force the [`SchedulerError::InvalidDutyPubkey`] mismatch path
    fn validator_set_a_mismatched() -> Vec<Validator> {
        ValidatorSet::validator_set_a()
            .validators()
            .into_iter()
            .map(|v| Validator {
                pubkey: random_core_pub_key(),
                v_idx: v.index,
            })
            .collect()
    }

    /// Mounts the POST `/states/head/validators` endpoint used by
    /// [`valcache::ValidatorCache::get_by_head`].
    async fn mount_head_validators(
        mock: &BeaconMock,
        data: Vec<GetStateValidatorsResponseResponseDatum>,
    ) {
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                GetStateValidatorsResponseResponse {
                    execution_optimistic: false,
                    finalized: true,
                    data,
                },
            ))
            .mount(mock.server())
            .await;
    }

    /// Builds an initial [`SchedulerActor`] wired to the mock's client. No
    /// epoch resolved yet.
    fn test_actor(mock: &BeaconMock) -> SchedulerActor {
        SchedulerActor {
            client: pluto_eth2api::BeaconNodeClient::new(mock.client().clone()),
            slot_broadcast: sync::broadcast::channel(CHANNEL_BUFFER_SIZE).0,
            duty_broadcast: sync::broadcast::channel(CHANNEL_BUFFER_SIZE).0,
            resolved_epoch: u64::MAX,
            duties: HashMap::new(),
            duties_by_epoch: HashMap::new(),
        }
    }

    /// A [`types::Slot`] dated far in the past so `delay_slot_offset` deadlines
    /// have already elapsed and duty broadcasts fire immediately.
    fn test_past_slot(slot: u64, slots_per_epoch: u64) -> types::Slot {
        types::Slot {
            slot: types::SlotNumber::new(slot),
            time: chrono::Utc::now()
                .checked_sub_signed(chrono::Duration::days(1))
                .expect("within chrono range"),
            slot_duration: chrono::Duration::seconds(12),
            slots_per_epoch,
        }
    }

    /// A [`types::Slot`] dated at `now` with a short slot duration, so
    /// `delay_slot_offset` still has a live wait pending when the duty task is
    /// spawned (unlike [`test_past_slot`], whose deadline has already elapsed).
    /// The sync-committee contribution offset is 2/3 of the slot duration
    /// (~600ms here), leaving a window to cancel before the broadcast fires.
    fn test_future_slot(slot: u64, slots_per_epoch: u64) -> types::Slot {
        types::Slot {
            slot: types::SlotNumber::new(slot),
            time: chrono::Utc::now(),
            slot_duration: chrono::Duration::milliseconds(900),
            slots_per_epoch,
        }
    }

    /// Builds an attester duty definition for tests.
    fn test_attester_def(pubkey: types::PubKey, v_idx: u64, slot: u64) -> types::DutyDefinition {
        let datum = pluto_eth2api::types::GetAttesterDutiesResponseResponseDatum {
            pubkey: pubkey.to_string(),
            validator_index: v_idx.to_string(),
            slot: slot.to_string(),
            ..Default::default()
        };
        let def: types::AttesterDutyDefinition = datum.try_into().expect("valid attester datum");
        types::DutyDefinition::Attester(def)
    }

    /// Drives the actor's `run` loop with test-controlled channels.
    struct TestHarness {
        slot_tx: sync::mpsc::Sender<types::Slot>,
        reorg_tx: sync::mpsc::Sender<u64>,
        handle: SchedulerHandle,
        slot_sub: sync::broadcast::Receiver<types::Slot>,
        duty_sub: sync::broadcast::Receiver<(types::Duty, types::DutyDefinitionSet)>,
        ct: CancellationToken,
    }

    fn spawn_actor(mock: &BeaconMock) -> TestHarness {
        let slot_broadcast = sync::broadcast::channel(CHANNEL_BUFFER_SIZE).0;
        let duty_broadcast = sync::broadcast::channel(CHANNEL_BUFFER_SIZE).0;
        let slot_sub = slot_broadcast.subscribe();
        let duty_sub = duty_broadcast.subscribe();

        let actor = SchedulerActor {
            client: pluto_eth2api::BeaconNodeClient::new(mock.client().clone()),
            slot_broadcast,
            duty_broadcast,
            resolved_epoch: u64::MAX,
            duties: HashMap::new(),
            duties_by_epoch: HashMap::new(),
        };

        let (slot_tx, slot_rx) = sync::mpsc::channel(CHANNEL_BUFFER_SIZE);
        let (msg_tx, msg_rx) = sync::mpsc::channel(CHANNEL_BUFFER_SIZE);
        let (reorg_tx, reorg_rx) = sync::mpsc::channel(CHANNEL_BUFFER_SIZE);
        let ct = CancellationToken::new();

        tokio::spawn(actor.run(slot_rx, msg_rx, reorg_rx, ct.clone()));

        TestHarness {
            slot_tx,
            reorg_tx,
            handle: SchedulerHandle { sender: msg_tx },
            slot_sub,
            duty_sub,
            ct,
        }
    }

    #[tokio::test]
    async fn fetch_attester_duties_rejects_mismatched_pubkey() {
        let mock = duties_mock(1).await;
        let err = fetch_attester_duties(
            &test_past_slot(0, 1),
            validator_set_a_mismatched(),
            &BeaconNodeClient::new(mock.client().clone()),
        )
        .await
        .expect_err("mismatched pubkey should be rejected");
        assert!(matches!(err, SchedulerError::InvalidDutyPubkey { .. }));
    }

    #[tokio::test]
    async fn fetch_proposer_duties_rejects_mismatched_pubkey() {
        let mock = duties_mock(1).await;
        let err = fetch_proposer_duties(
            &test_past_slot(0, 1),
            validator_set_a_mismatched(),
            &BeaconNodeClient::new(mock.client().clone()),
        )
        .await
        .expect_err("mismatched pubkey should be rejected");
        assert!(matches!(err, SchedulerError::InvalidDutyPubkey { .. }));
    }

    #[tokio::test]
    async fn fetch_sync_committee_duties_rejects_mismatched_pubkey() {
        let mock = duties_mock(1).await;
        let err = fetch_sync_committee_duties(
            &test_past_slot(0, 1),
            validator_set_a_mismatched(),
            &BeaconNodeClient::new(mock.client().clone()),
        )
        .await
        .expect_err("mismatched pubkey should be rejected");
        assert!(matches!(err, SchedulerError::InvalidDutyPubkey { .. }));
    }

    #[tokio::test]
    async fn epoch_resolved_and_trimmed_boundaries() {
        let mock = BeaconMock::builder().build().await.expect("build mock");
        let mut actor = test_actor(&mock);

        // Sentinel: nothing resolved yet.
        assert!(!actor.is_epoch_resolved(5));
        assert!(!actor.is_epoch_trimmed(5));

        actor.resolved_epoch = 10;
        assert!(actor.is_epoch_resolved(9));
        assert!(actor.is_epoch_resolved(10));
        assert!(!actor.is_epoch_resolved(11));

        // Trimmed iff resolved_epoch >= epoch + TRIM_EPOCH_OFFSET (epoch <= 7).
        assert!(actor.is_epoch_trimmed(7));
        assert!(!actor.is_epoch_trimmed(8));
    }

    #[tokio::test]
    async fn set_duty_definition_dedups_and_trim_removes() {
        let mock = BeaconMock::builder().build().await.expect("build mock");
        let mut actor = test_actor(&mock);

        let duty = types::Duty::new_attester_duty(types::SlotNumber::new(0));
        let pk = random_core_pub_key();
        let def = test_attester_def(pk, 1, 0);

        assert!(actor.set_duty_definition(duty.clone(), 0, pk, def.clone()));
        // Same pubkey for the same duty is a no-op and reports `false`.
        assert!(!actor.set_duty_definition(duty.clone(), 0, pk, def));
        assert!(actor.duties.contains_key(&duty));

        actor.trim_duties(0);
        assert!(!actor.duties.contains_key(&duty));
    }

    #[tokio::test]
    async fn get_duty_definition_variants() {
        let mock = BeaconMock::builder()
            .slots_per_epoch(1)
            .build()
            .await
            .expect("build mock");
        let mut actor = test_actor(&mock);
        let slot0 = types::SlotNumber::new(0);

        // Deprecated builder-proposer duty (checked before any network call).
        let builder = types::Duty::new(slot0, types::DutyType::BuilderProposer);
        assert!(matches!(
            actor.get_duty_definition(builder).await,
            Err(SchedulerError::DeprecatedDutyBuilderProposer)
        ));

        // Epoch not resolved yet (resolved_epoch == u64::MAX).
        let att = types::Duty::new_attester_duty(slot0);
        assert!(matches!(
            actor.get_duty_definition(att.clone()).await,
            Err(SchedulerError::EpochNotResolved { epoch: 0, .. })
        ));

        // Resolved but no duty stored.
        actor.resolved_epoch = 0;
        assert!(matches!(
            actor.get_duty_definition(att.clone()).await,
            Err(SchedulerError::DutyNotFound { epoch: 0, .. })
        ));

        // Resolved and present: returns a clone of the definition set.
        let pk = random_core_pub_key();
        actor.set_duty_definition(att.clone(), 0, pk, test_attester_def(pk, 1, 0));
        let set = actor
            .get_duty_definition(att.clone())
            .await
            .expect("resolved duty is returned");
        assert!(set.contains_key(&pk));

        // Advance resolved_epoch so epoch 0 is now trimmed.
        actor.resolved_epoch = TRIM_EPOCH_OFFSET;
        assert!(matches!(
            actor.get_duty_definition(att).await,
            Err(SchedulerError::EpochAlreadyTrimmed { epoch: 0, .. })
        ));
    }

    #[tokio::test]
    async fn resolve_duties_stores_all_duty_types() {
        let mock = duties_mock(16).await;
        mount_head_validators(&mock, validator_set_a_datums()).await;
        let mut actor = test_actor(&mock);

        actor
            .resolve_duties(test_past_slot(0, 16))
            .await
            .expect("resolve duties");

        assert_eq!(actor.resolved_epoch, 0);

        let slot0 = types::SlotNumber::new(0);
        // Attester duty plus its paired aggregator duty.
        assert!(
            actor
                .duties
                .contains_key(&types::Duty::new_attester_duty(slot0))
        );
        assert!(
            actor
                .duties
                .contains_key(&types::Duty::new_aggregator_duty(slot0))
        );
        // Proposer and sync-contribution duties.
        assert!(
            actor
                .duties
                .contains_key(&types::Duty::new_proposer_duty(slot0))
        );
        assert!(
            actor
                .duties
                .contains_key(&types::Duty::new_sync_contribution_duty(slot0))
        );
    }

    #[tokio::test]
    async fn resolve_duties_no_active_validators() {
        let mock = BeaconMock::builder()
            .slots_per_epoch(1)
            .build()
            .await
            .expect("build mock");
        mount_head_validators(&mock, Vec::new()).await;
        let mut actor = test_actor(&mock);

        actor
            .resolve_duties(test_past_slot(0, 1))
            .await
            .expect("resolve duties");

        assert_eq!(actor.resolved_epoch, 0);
        assert!(matches!(
            actor
                .get_duty_definition(types::Duty::new_attester_duty(types::SlotNumber::new(0)))
                .await,
            Err(SchedulerError::DutyNotFound { .. })
        ));
    }

    #[tokio::test]
    async fn handle_chain_reorg_trims_and_resets() {
        let mock = BeaconMock::builder().build().await.expect("build mock");
        let mut actor = test_actor(&mock);

        // Seed a resolved epoch 5 holding one duty.
        let duty = types::Duty::new_attester_duty(types::SlotNumber::new(5));
        let pk = random_core_pub_key();
        actor.set_duty_definition(duty.clone(), 5, pk, test_attester_def(pk, 1, 5));
        actor.resolved_epoch = 5;

        // A reorg at/after the resolved epoch is a no-op.
        actor.handle_chain_reorg(5).await;
        assert_eq!(actor.resolved_epoch, 5);
        assert!(actor.duties.contains_key(&duty));

        // A reorg before the resolved epoch trims duties and resets the epoch.
        actor.handle_chain_reorg(4).await;
        assert_eq!(actor.resolved_epoch, u64::MAX);
        assert!(!actor.duties.contains_key(&duty));
    }

    // ---- 6. Channel-driven actor (the full run loop) ----------------------

    #[test_case::test_case(0 ; "first slot in epoch 0 triggers duties")]
    #[test_case::test_case(16 ; "first slot in epoch 1 triggers duties")]
    #[tokio::test]
    async fn first_slot_broadcasts_slot_and_triggers_duties(slot_number: u64) {
        let mock = duties_mock(16).await;
        mount_head_validators(&mock, validator_set_a_datums()).await;
        let mut h = spawn_actor(&mock);

        h.slot_tx
            .send(test_past_slot(slot_number, 16))
            .await
            .expect("send slot");

        // The slot itself is broadcast immediately.
        let slot = tokio::time::timeout(Duration::from_secs(2), h.slot_sub.recv())
            .await
            .expect("slot broadcast within timeout")
            .expect("slot value");
        assert_eq!(slot.slot.inner(), slot_number);

        // Past-dated slot => duties broadcast (near-)immediately. Collect the
        // four expected duty types triggered for the given slot.
        let mut seen = HashSet::new();
        while seen.len() < 4 {
            let (duty, set) = tokio::time::timeout(Duration::from_secs(2), h.duty_sub.recv())
                .await
                .expect("duty broadcast within timeout")
                .expect("duty value");
            assert!(!set.is_empty());
            seen.insert(duty.duty_type);
        }
        assert!(seen.contains(&types::DutyType::Attester));
        assert!(seen.contains(&types::DutyType::Aggregator));
        assert!(seen.contains(&types::DutyType::Proposer));
        assert!(seen.contains(&types::DutyType::SyncContribution));

        h.ct.cancel();
    }

    #[test_case::test_case(1 ; "mid-epoch slot 1 triggers only sync contribution duties")]
    #[test_case::test_case(5 ; "mid-epoch slot 5 triggers only sync contribution duties")]
    #[test_case::test_case(15 ; "mid-epoch slot 15 triggers only sync contribution duties")]
    #[tokio::test]
    async fn mid_epoch_slot_broadcasts_slot_and_triggers_only_sync_contribution_duty(
        slot_number: u64,
    ) {
        let mock = duties_mock(16).await;
        mount_head_validators(&mock, validator_set_a_datums()).await;
        let mut h = spawn_actor(&mock);

        // Slot is mid-epoch (epoch 0 spans slots 0..=15). With the deterministic
        // Beacon setup:
        // - Attester duties are only included in the first slot of an epoch
        //      - The paired Aggregator duties are not included either
        // - Proposer duties are only included in the first slot of an epoch
        // - Sync-committee contribution duties are included in every slot of an epoch
        h.slot_tx
            .send(test_past_slot(slot_number, 16))
            .await
            .expect("send slot");

        // The slot itself is broadcast immediately.
        let slot = tokio::time::timeout(Duration::from_secs(2), h.slot_sub.recv())
            .await
            .expect("slot broadcast within timeout")
            .expect("slot value");
        assert_eq!(slot.slot.inner(), slot_number);

        // The only duty triggered for a mid-epoch slot is the sync-committee
        // contribution.
        let (duty, set) = tokio::time::timeout(Duration::from_secs(2), h.duty_sub.recv())
            .await
            .expect("duty broadcast within timeout")
            .expect("duty value");
        assert_eq!(duty.duty_type, types::DutyType::SyncContribution);
        assert!(!set.is_empty());

        // No attester/proposer/aggregator duty is broadcast for this slot.
        let next = tokio::time::timeout(Duration::from_millis(200), h.duty_sub.recv()).await;
        assert!(
            next.is_err(),
            "expected no further duty broadcasts, got {next:?}"
        );

        h.ct.cancel();
    }

    #[tokio::test]
    async fn get_duty_success_then_reorg_then_get_duty_fails() {
        let mock = duties_mock(16).await;
        mount_head_validators(&mock, validator_set_a_datums()).await;
        let mut h = spawn_actor(&mock);

        // Drive a slot in epoch 1 and wait for a duty broadcast, which only
        // happens once `resolve_duties` has completed for the epoch.
        h.slot_tx
            .send(test_past_slot(16, 16))
            .await
            .expect("send slot");
        tokio::time::timeout(Duration::from_secs(2), h.duty_sub.recv())
            .await
            .expect("duty broadcast within timeout")
            .expect("duty value");

        // The handle can now read the resolved attester duty.
        let att = types::Duty::new_attester_duty(types::SlotNumber::new(16));
        let set = h
            .handle
            .get_duty_definition(att.clone())
            .await
            .expect("resolved duty");
        assert!(!set.is_empty());

        // A reorg before the resolved epoch trims duties; the handle then
        // reports the epoch as unresolved. The reorg is handled first so an immediate
        // read observes the reset.
        h.reorg_tx.send(0).await.expect("send reorg");
        assert!(matches!(
            h.handle.get_duty_definition(att).await,
            Err(SchedulerError::EpochNotResolved { .. })
        ));

        h.ct.cancel();
    }

    #[tokio::test]
    async fn cancellation_during_slot_offset_suppresses_duty_broadcast() {
        let mock = duties_mock(16).await;
        mount_head_validators(&mock, validator_set_a_datums()).await;
        let mut h = spawn_actor(&mock);

        // A mid-epoch slot triggers only the sync-committee contribution duty,
        // whose broadcast is delayed by 2/3 of the slot duration (~600ms here).
        // Dated at `now`, the offset deadline is still in the future when the
        // duty task is spawned, so it parks on the live `delay_slot_offset` wait
        // inside `with_cancellation_token_owned`.
        h.slot_tx
            .send(test_future_slot(5, 16))
            .await
            .expect("send slot");

        // The slot itself broadcasts immediately, before the offset wait.
        let slot = tokio::time::timeout(Duration::from_secs(2), h.slot_sub.recv())
            .await
            .expect("slot broadcast within timeout")
            .expect("slot value");
        assert_eq!(slot.slot.inner(), 5);

        // Cancel while the duty task is still waiting on the offset.
        h.ct.cancel();

        // No duty value must ever arrive: the offset wait is cancelled before
        // its deadline. Wait past the ~600ms deadline to catch a regression
        // where cancellation is not wired into `delay_slot_offset`. A timeout or
        // a closed channel (the actor shut down and dropped its sender) both
        // mean no broadcast fired; only a received duty (`Ok(Ok(_))`) is a
        // failure.
        let next = tokio::time::timeout(Duration::from_secs(1), h.duty_sub.recv()).await;
        assert!(
            !matches!(next, Ok(Ok(_))),
            "expected no duty broadcast after cancellation, got {next:?}"
        );
    }
}
