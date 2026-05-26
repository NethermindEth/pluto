use std::time::Duration;

use backon::{BackoffBuilder, Retryable};
use pluto_eth2api::{EthBeaconNodeApiClientError, client};
use tokio_util::sync::CancellationToken;

use crate::{types, valcache};

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
}

impl Scheduler {
    pub fn new(client: client::EthBeaconNodeApiClient, valcache: valcache::ValidatorCache) -> Self {
        Scheduler {
            client,
            valcache,
            slot_broadcast: tokio::sync::broadcast::channel(100).0,
        }
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

                    // ~ `emitCoreSlot`
                    if self.slot_broadcast.send(slot).is_err() {
                        tracing::debug!("No active subscribers for slot events, closing scheduler");
                        break;
                    }


                    // self.schedule_slot()
                },
            }
        }

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
