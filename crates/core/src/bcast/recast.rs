use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::{Arc, Mutex},
};

use futures::future::BoxFuture;
use pluto_eth2api::BeaconNodeClient;

use crate::{
    bcast::{
        Error, Result,
        metrics::{instrument_recast, instrument_recast_error, instrument_recast_registration},
    },
    types::{Duty, DutyType, PubKey, SignedData, SignedDataSet, Slot},
};

type RecastFuture = BoxFuture<'static, Result<()>>;
type RecastSubscriber = Arc<dyn Fn(Duty, SignedDataSet) -> RecastFuture + Send + Sync>;

#[derive(Clone)]
struct RecastTuple {
    duty: Duty,
    agg_data: Box<dyn SignedData>,
}

#[derive(Default)]
struct RecastState {
    tuples: HashMap<PubKey, RecastTuple>,
    subs: Vec<RecastSubscriber>,
}

/// Rebroadcasts builder registrations every epoch.
pub struct Recaster {
    client: BeaconNodeClient,
    state: Mutex<RecastState>,
}

impl Recaster {
    /// Creates a new recaster.
    pub fn new(client: BeaconNodeClient) -> Self {
        Self {
            client,
            state: Mutex::new(RecastState::default()),
        }
    }

    /// Subscribes to rebroadcasted duties.
    pub fn subscribe<F, Fut>(&self, sub: F) -> Result<()>
    where
        F: Fn(Duty, SignedDataSet) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        self.state
            .lock()
            .map_err(|_| Error::MutexPoisoned("recaster state"))?
            .subs
            .push(Arc::new(move |duty, set| Box::pin(sub(duty, set))));
        Ok(())
    }

    /// Stores aggregate signed builder registrations for rebroadcasting.
    pub fn store(&self, duty: Duty, set: &SignedDataSet) -> Result<()> {
        if duty.duty_type != DutyType::BuilderRegistration {
            return Ok(());
        }

        for (pubkey, agg_data) in set {
            self.store_one(duty.clone(), *pubkey, agg_data.as_ref())?;
        }

        Ok(())
    }

    fn store_one(&self, duty: Duty, pubkey: PubKey, agg_data: &dyn SignedData) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::MutexPoisoned("recaster state"))?;

        if let Some(tuple) = state.tuples.get(&pubkey)
            && tuple.duty.slot.inner() >= duty.slot.inner()
        {
            return Ok(());
        }

        let agg_data = dyn_clone::clone_box(agg_data);
        state.tuples.insert(pubkey, RecastTuple { duty, agg_data });
        instrument_recast_registration(pubkey);

        Ok(())
    }

    /// Called when new slots tick.
    pub async fn slot_ticked(&self, slot: Slot) -> Result<()> {
        if !slot.first_in_epoch() {
            return Ok(());
        }

        let active_validators: HashSet<PubKey> = self
            .client
            .active_validators()
            .await
            .map_err(|source| Error::Client {
                context: "get active validator",
                source: Box::new(source),
            })?
            .pubkeys()
            .map(|pubkey| PubKey::from(*pubkey))
            .collect();

        let (sets, subs) = {
            let state = self
                .state
                .lock()
                .map_err(|_| Error::MutexPoisoned("recaster state"))?;

            let mut sets: HashMap<Duty, SignedDataSet> = HashMap::new();
            for (pubkey, tuple) in &state.tuples {
                if !active_validators.contains(pubkey) {
                    continue;
                }

                sets.entry(tuple.duty.clone())
                    .or_default()
                    .insert(*pubkey, tuple.agg_data.clone());
            }

            (sets, state.subs.clone())
        };

        for (duty, mut set) in sets {
            let last_sub_idx = subs.len().saturating_sub(1);
            for (idx, sub) in subs.iter().enumerate() {
                let set_for_sub = if idx == last_sub_idx {
                    std::mem::take(&mut set)
                } else {
                    set.clone()
                };

                if let Err(error) = sub(duty.clone(), set_for_sub).await {
                    tracing::error!(%error, %duty, "Rebroadcast duty error (will retry next epoch)");
                    instrument_recast_error(&duty);
                }

                instrument_recast(&duty);
            }
        }

        Ok(())
    }
}
