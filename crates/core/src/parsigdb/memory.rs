use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    deadline::Deadliner,
    parsigdb::metrics::PARSIG_DB_METRICS,
    signeddata::SignedDataError,
    types::{Duty, DutyType, ParSignedData, ParSignedDataSet, PubKey},
};
use chrono::{DateTime, Utc};

/// Metadata for the memory ParSigDB.
pub struct MemDBMetadata {
    /// Slot duration in seconds
    pub slot_duration: u64,
    /// Genesis time
    pub genesis_time: DateTime<Utc>,
}

impl MemDBMetadata {
    /// Creates new memory ParSigDB metadata.
    pub fn new(slot_duration: u64, genesis_time: DateTime<Utc>) -> Self {
        Self {
            slot_duration,
            genesis_time,
        }
    }
}

/// Subscriber callback for internally generated partial signed data.
///
/// Called when the node generates partial signed data that needs to be
/// exchanged with peers.
pub type InternalSub = Arc<
    dyn Fn(&Duty, &ParSignedDataSet) -> Pin<Box<dyn Future<Output = Result<()>> + Send + Sync>>
        + Send
        + Sync
        + 'static,
>;

/// Subscriber callback for threshold-reached partial signed data.
///
/// Called when enough matching partial signatures have been collected
/// to meet the threshold requirement.
pub type ThreshSub = Arc<
    dyn Fn(
            &Duty,
            &HashMap<PubKey, Vec<ParSignedData>>,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + Sync>>
        + Send
        + Sync
        + 'static,
>;

/// Helper to create an internal subscriber from a closure.
///
/// The closure receives owned copies of the duty and data set. Since the
/// closure is `Fn` (can be called multiple times), you need to clone any
/// captured Arc values before the `async move` block.
///
/// # Example
/// ```ignore
/// let counter = Arc::new(Mutex::new(0));
/// let sub = internal_subscriber({
///     let counter = counter.clone();
///     move |_duty, _set| {
///         let counter = counter.clone();
///         async move {
///             *counter.lock().await += 1;
///             Ok(())
///         }
///     }
/// });
/// db.subscribe_internal(sub).await?;
/// ```
pub fn internal_subscriber<F, Fut>(f: F) -> InternalSub
where
    F: Fn(Duty, ParSignedDataSet) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + Sync + 'static,
{
    Arc::new(move |duty, set| {
        let fut = f(duty.clone(), set.clone());
        Box::pin(fut)
    })
}

/// Helper to create a threshold subscriber from a closure.
///
/// The closure receives owned copies of the duty and data. Since the closure
/// is `Fn` (can be called multiple times), you need to clone any captured Arc
/// values before the `async move` block.
///
/// # Example
/// ```ignore
/// let counter = Arc::new(Mutex::new(0));
/// let sub = threshold_subscriber({
///     let counter = counter.clone();
///     move |_duty, _data| {
///         let counter = counter.clone();
///         async move {
///             *counter.lock().await += 1;
///             Ok(())
///         }
///     }
/// });
/// db.subscribe_threshold(sub).await?;
/// ```
pub fn threshold_subscriber<F, Fut>(f: F) -> ThreshSub
where
    F: Fn(Duty, HashMap<PubKey, Vec<ParSignedData>>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + Sync + 'static,
{
    Arc::new(move |duty, data| {
        let fut = f(duty.clone(), data.clone());
        Box::pin(fut)
    })
}

/// Error type for the memory ParSigDB.
#[derive(Debug, thiserror::Error)]
pub enum MemDBError {
    /// Mismatching partial signed data.
    #[error("mismatching partial signed data: pubkey {pubkey}, share_idx {share_idx}")]
    ParsigDataMismatch {
        /// Public key of the validator
        pubkey: PubKey,
        /// Share index of the mismatched signature
        share_idx: u64,
    },

    /// Signed data error.
    #[error("signed data error: {0}")]
    SignedDataError(#[from] SignedDataError),
}

type Result<T> = std::result::Result<T, MemDBError>;

/// Key for indexing partial signed data in the database.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    /// The duty this partial signature is for
    pub duty: Duty,
    /// The public key of the validator
    pub pub_key: PubKey,
}

/// Internal state of the in-memory partial signature database.
pub struct MemDBInner {
    internal_subs: Vec<InternalSub>,
    thresh_subs: Vec<ThreshSub>,

    entries: HashMap<Key, Vec<ParSignedData>>,
    keys_by_duty: HashMap<Duty, Vec<Key>>,
}

/// In-memory partial signature database.
///
/// Stores partial signed data from cluster nodes and triggers callbacks
/// when threshold is reached or when internal data is generated.
pub struct MemDB {
    ct: CancellationToken,
    inner: Arc<Mutex<MemDBInner>>,
    deadliner: Arc<dyn Deadliner>,
    threshold: u64,
}

impl MemDB {
    /// Creates a new in-memory partial signature database.
    ///
    /// # Arguments
    /// * `ct` - Cancellation token for graceful shutdown
    /// * `threshold` - Number of matching partial signatures required
    /// * `deadliner` - Deadliner for managing duty expiration
    pub fn new(ct: CancellationToken, threshold: u64, deadliner: Arc<dyn Deadliner>) -> Self {
        Self {
            ct,
            inner: Arc::new(Mutex::new(MemDBInner {
                internal_subs: Vec::new(),
                thresh_subs: Vec::new(),
                entries: HashMap::new(),
                keys_by_duty: HashMap::new(),
            })),
            deadliner,
            threshold,
        }
    }
}

impl MemDB {
    /// Registers a subscriber for internally generated partial signed data.
    ///
    /// The subscriber will be called when the node generates partial signed
    /// data that needs to be exchanged with peers.
    pub async fn subscribe_internal(&self, sub: InternalSub) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.internal_subs.push(sub);
        Ok(())
    }

    /// Registers a subscriber for threshold-reached partial signed data.
    ///
    /// The subscriber will be called when enough matching partial signatures
    /// have been collected to meet the threshold requirement.
    pub async fn subscribe_threshold(&self, sub: ThreshSub) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.thresh_subs.push(sub);
        Ok(())
    }

    /// Stores internally generated partial signed data and notifies
    /// subscribers.
    ///
    /// This is called when the node generates partial signed data that needs to
    /// be stored and exchanged with peers. It first stores the data (via
    /// `store_external`), then calls all internal subscribers to trigger
    /// peer exchange.
    pub async fn store_internal(&self, duty: &Duty, signed_set: &ParSignedDataSet) -> Result<()> {
        self.store_external(duty, signed_set).await?;

        let subs = {
            let inner = self.inner.lock().await;
            inner.internal_subs.clone()
        };

        for sub in &subs {
            sub(duty, signed_set).await?;
        }

        Ok(())
    }

    /// Stores externally received partial signed data and checks for threshold.
    ///
    /// This is called when the node receives partial signed data from peers. It
    /// stores the data, checks if enough matching signatures have been
    /// collected to meet the threshold, and calls threshold subscribers
    /// when the threshold is reached.
    pub async fn store_external(&self, duty: &Duty, signed_data: &ParSignedDataSet) -> Result<()> {
        let _ = self.deadliner.add(duty.clone()).await;

        let mut output: HashMap<PubKey, Vec<ParSignedData>> = HashMap::new();

        for (pub_key, par_signed) in signed_data.inner().iter() {
            let sigs = self
                .store(
                    Key {
                        duty: duty.clone(),
                        pub_key: *pub_key,
                    },
                    par_signed.clone(),
                )
                .await?;

            let Some(sigs) = sigs else {
                debug!("Ignoring duplicate partial signature");

                continue;
            };

            let psigs = get_threshold_matching(&duty.duty_type, &sigs, self.threshold).await?;

            let Some(psigs) = psigs else {
                continue;
            };

            output.insert(*pub_key, psigs);
        }

        if output.is_empty() {
            return Ok(());
        }

        let subs = {
            let inner = self.inner.lock().await;
            inner.thresh_subs.clone()
        };

        for sub in &subs {
            sub(duty, &output).await?;
        }

        Ok(())
    }

    /// Trims expired duties from the database.
    ///
    /// This method runs in a loop, listening for expired duties from the
    /// deadliner and removing their associated data from the database. It
    /// should be spawned as a background task and will run until the
    /// cancellation token is triggered.
    pub async fn trim(&self) {
        let Some(mut deadliner_rx) = self.deadliner.c() else {
            warn!("Deadliner channel is not available");
            return;
        };

        loop {
            tokio::select! {
                biased;

                _ = self.ct.cancelled() => {
                    return;
                }

                Some(duty) = deadliner_rx.recv() => {
                    let mut inner = self.inner.lock().await;

                    for key in inner.keys_by_duty.get(&duty).cloned().unwrap_or_default() {
                        inner.entries.remove(&key);
                    }

                    inner.keys_by_duty.remove(&duty);

                    drop(inner);
                }
            }
        }
    }

    async fn store(&self, k: Key, value: ParSignedData) -> Result<Option<Vec<ParSignedData>>> {
        let mut inner = self.inner.lock().await;

        // Check if we already have an entry with this ShareIdx
        if let Some(existing_entries) = inner.entries.get(&k) {
            for s in existing_entries {
                if s.share_idx == value.share_idx {
                    if s == &value {
                        // Duplicate, return None to indicate no new data
                        return Ok(None);
                    } else {
                        return Err(MemDBError::ParsigDataMismatch {
                            pubkey: k.pub_key,
                            share_idx: value.share_idx,
                        });
                    }
                }
            }
        }

        inner
            .entries
            .entry(k.clone())
            .or_insert_with(Vec::new)
            .push(value.clone());
        inner
            .keys_by_duty
            .entry(k.duty.clone())
            .or_insert_with(Vec::new)
            .push(k.clone());

        if k.duty.duty_type == DutyType::Exit {
            PARSIG_DB_METRICS.exit_total[&k.pub_key.to_string()].inc();
        }

        let result = inner.entries.get(&k).cloned().unwrap_or_default();

        Ok(Some(result))
    }
}

async fn get_threshold_matching(
    typ: &DutyType,
    sigs: &[ParSignedData],
    threshold: u64,
) -> Result<Option<Vec<ParSignedData>>> {
    // Not enough signatures to meet threshold
    if (sigs.len() as u64) < threshold {
        return Ok(None);
    }

    if *typ == DutyType::Signature {
        // Signatures do not support message roots.
        if sigs.len() as u64 == threshold {
            return Ok(Some(sigs.to_vec()));
        } else {
            return Ok(None);
        }
    }

    // Group signatures by their message root
    let mut sigs_by_msg_root: HashMap<[u8; 32], Vec<ParSignedData>> = HashMap::new();

    for sig in sigs {
        let root = sig
            .signed_data
            .message_root()
            .map_err(MemDBError::SignedDataError)?;
        sigs_by_msg_root.entry(root).or_default().push(sig.clone());
    }

    // Return the first set that has exactly threshold number of signatures
    for set in sigs_by_msg_root.values() {
        if set.len() as u64 == threshold {
            return Ok(Some(set.clone()));
        }
    }

    Ok(None)
}

#[cfg(test)]
#[path = "memory_internal_test.rs"]
mod memory_internal_test;
