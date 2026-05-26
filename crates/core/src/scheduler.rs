#![allow(dead_code, reason = "wip")]

use std::{
    collections::{HashMap, hash_map::Entry},
    ops::Div,
    time::Duration,
};

use backon::{BackoffBuilder, Retryable};
use pluto_eth2api::{EthBeaconNodeApiClientError, client};
use tokio::sync::Mutex;
use tokio_util::{future::FutureExt, sync::CancellationToken};

use crate::{types, valcache};

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

    /// Invalid epoch error.
    #[error("Invalid epoch")]
    InvalidEpoch(#[from] std::num::ParseIntError),
}

type Result<T> = std::result::Result<T, SchedulerError>;

struct Scheduler {
    client: client::EthBeaconNodeApiClient,
    valcache: valcache::ValidatorCache,

    slot_broadcast: tokio::sync::broadcast::Sender<types::Slot>,
    duty_broadcast: tokio::sync::broadcast::Sender<(types::Duty, types::DutyDefinitionSet)>,

    storage: Mutex<Inner>,
}

struct Inner {
    resolved_epoch: u64,
    resolving_epoch: u64,
    duties: HashMap<types::Duty, types::DutyDefinitionSet>,
    duties_by_epoch: HashMap<u64, Vec<types::Duty>>,
}

impl Inner {
    fn is_resolving_epoch(&self, epoch: u64) -> bool {
        if self.resolving_epoch == u64::MAX {
            return false;
        }

        self.resolving_epoch == epoch
    }

    fn is_epoch_resolved(&self, epoch: u64) -> bool {
        if self.resolved_epoch == u64::MAX {
            return false;
        }

        self.resolved_epoch >= epoch
    }

    fn is_epoch_trimmed(&self, epoch: u64) -> bool {
        if self.resolved_epoch == u64::MAX {
            return false;
        }

        epoch >= self.resolved_epoch + TRIM_EPOCH_OFFSET
    }

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
}

impl Scheduler {
    pub fn new(client: client::EthBeaconNodeApiClient, valcache: valcache::ValidatorCache) -> Self {
        Scheduler {
            client,
            valcache,
            slot_broadcast: tokio::sync::broadcast::channel(100).0,
            duty_broadcast: tokio::sync::broadcast::channel(100).0,
            storage: Mutex::new(Inner {
                resolved_epoch: u64::MAX,
                resolving_epoch: u64::MAX,
                duties: HashMap::new(),
                duties_by_epoch: HashMap::new(),
            }),
        }
    }

    pub async fn run(&mut self, ct: CancellationToken) -> Result<()> {
        wait_chain_start(&self.client).await?;
        wait_beacon_sync(&self.client).await?;

        let mut slot_ticker = new_slot_ticker(&self.client, ct.clone()).await?;

        loop {
            tokio::select! {
                _ = ct.cancelled() => break,

                Some(slot) = slot_ticker.recv() => {
                    tracing::debug!(slot = %slot.slot, "Slot ticked");

                    // TODO: metrics
                    // instrumentSlot(slot)

                    // NOTE: Ignore send errors, it means that there are no subscribers.
                    let _ = self.slot_broadcast.send(slot.clone());

                    self.schedule_slot(slot, ct.clone()).await;
                },
            }
        }

        Ok(())
    }

    /// Subscribes a callback function for triggered slots.
    /// Note this should be called *before* [`Scheduler::run`].
    pub async fn subscribe_slots(
        &mut self,
        f: impl Fn(&types::Slot) -> Result<()> + Send + 'static,
        label: impl AsRef<str> + Send + 'static,
    ) {
        let mut rx = self.slot_broadcast.subscribe();

        tokio::spawn(async move {
            while let Ok(slot) = rx.recv().await {
                if let Err(err) = f(&slot) {
                    tracing::error!(err = ?err, slot = %slot.slot, label = label.as_ref(), "Emit scheduled slot event");
                }
            }
        });
    }

    /// Subscribes a callback function for triggered duties.
    /// NOTE: this should be called *before* [`Scheduler::run`].
    pub async fn subscribe_duties(
        &mut self,
        f: impl Fn(&types::Duty, &types::DutyDefinitionSet) -> Result<()> + Send + 'static,
        label: impl AsRef<str> + Send + 'static,
    ) {
        let mut rx = self.duty_broadcast.subscribe();

        tokio::spawn(async move {
            while let Ok((duty, set)) = rx.recv().await {
                if let Err(err) = f(&duty, &set) {
                    tracing::error!(err = ?err, label = label.as_ref(), "Trigger duty subscriber error");
                }
            }
        });
    }

    async fn schedule_slot(&mut self, slot: types::Slot, ct: CancellationToken) {
        let resolved_epoch = self.storage.lock().await.resolved_epoch;
        if resolved_epoch != slot.epoch() {
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
                let storage = self.storage.lock().await;
                let Some(def_set) = storage.duties.get(&duty) else {
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

                // TODO:
                // instrument_duty(duty, def_set);

                // NOTE: Ignore send errors, it means that there are no subscribers.
                let _ = broadcast.send((duty.clone(), def_set.clone()));
            });
        }

        if slot.last_in_epoch() {
            if let Err(err) = self.resolve_duties(slot.next_slot()).await {
                tracing::warn!(err = ?err, slot = %slot.slot, "Resolving duties error (retrying next slot)");
            }
        }

        todo!()
    }

    async fn resolve_duties(&mut self, slot: types::Slot) -> Result<()> {
        todo!()
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
) -> Result<tokio::sync::mpsc::Receiver<types::Slot>> {
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

    let (tx, rx) = tokio::sync::mpsc::channel(100);
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
                // skipCounter.inc()
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

        // TODO: Support `submitter`
        // submitter(pubkey, v.Balance, val.status.to_string())

        // Check for active validators for the given epoch.
        // The activation epoch needs to be checked in cases where this function is
        // called before the epoch starts.
        if !val.status.is_active() {
            let activation_epoch = val
                .validator
                .activation_epoch
                .parse::<u64>()
                .map_err(SchedulerError::InvalidEpoch)?;

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
    let to_sleep = match duty.duty_type {
        types::DutyType::Attester => slot.slot_duration.div(3) * 1,
        types::DutyType::Aggregator => slot.slot_duration.div(3) * 2,
        types::DutyType::SyncContribution => slot.slot_duration.div(3) * 2,
        _ => return,
    };

    tokio::time::sleep(to_sleep.to_std().unwrap_or_default()).await;
}
