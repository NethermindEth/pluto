#![allow(missing_docs)]
use std::{collections::HashMap, pin::Pin, sync::Arc};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    deadline::Deadliner,
    parasigdb::metrics::PARASIG_DB_METRICS,
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

pub type InternalSub = Box<
    dyn Fn(&Duty, &ParSignedDataSet) -> Pin<Box<dyn Future<Output = Result<()>> + Send + Sync>>
        + Send
        + Sync
        + 'static,
>;

pub type ThreshSub = Box<
    dyn Fn(
            &Duty,
            &HashMap<PubKey, Vec<ParSignedData>>,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + Sync>>
        + Send
        + Sync
        + 'static,
>;

#[derive(Debug, thiserror::Error)]
pub enum MemDBError {
    #[error("mismatching partial signed data: pubkey {pubkey}, share_idx {share_idx}")]
    ParsigDataMismatch { pubkey: PubKey, share_idx: u64 },
}

type Result<T> = std::result::Result<T, MemDBError>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    pub duty: Duty,
    pub pub_key: PubKey,
}

pub struct MemDBInner {
    internal_subs: Vec<InternalSub>,
    thresh_subs: Vec<ThreshSub>,

    entries: HashMap<Key, Vec<ParSignedData>>,
    keys_by_duty: HashMap<Duty, Vec<Key>>,
}

pub struct MemDB {
    ct: CancellationToken,
    inner: Arc<Mutex<MemDBInner>>,
    deadliner: Arc<dyn Deadliner>,
    threshold: u64,
}

impl MemDB {
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
    pub async fn subscribe_internal(&self, sub: InternalSub) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.internal_subs.push(sub);
        Ok(())
    }

    pub async fn subscribe_threshold(&self, sub: ThreshSub) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.thresh_subs.push(sub);
        Ok(())
    }

    pub async fn store_internal(&self, duty: &Duty, signed_set: &ParSignedDataSet) -> Result<()> {
        let _ = self.store_external(duty, signed_set).await?;

        let inner = self.inner.lock().await;
        for sub in &inner.internal_subs {
            sub(&duty, &signed_set).await?;
        }
        drop(inner);

        Ok(())
    }

    pub async fn store_external(&self, duty: &Duty, signed_data: &ParSignedDataSet) -> Result<()> {
        let _ = self.deadliner.add(duty.clone()).await;

        let mut output: HashMap<PubKey, Vec<ParSignedData>> = HashMap::new();

        for (pub_key, par_signed) in signed_data.inner().iter() {
            let sigs = self
                .store(
                    Key {
                        duty: duty.clone(),
                        pub_key: pub_key.clone(),
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

            output.insert(pub_key.clone(), psigs);
        }

        if output.is_empty() {
            return Ok(());
        }

        let inner = self.inner.lock().await;
        for sub in inner.thresh_subs.iter() {
            sub(&duty, &output).await?;
        }
        drop(inner);

        Ok(())
    }

    pub async fn trim(&self) {
        let deadliner_rx = self.deadliner.c();
        if deadliner_rx.is_none() {
            warn!("Deadliner channel is not available");
            return;
        }

        let mut deadliner_rx = deadliner_rx.unwrap();

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
            PARASIG_DB_METRICS.exit_total[&k.pub_key.to_string()].inc();
        }

        let result = inner
            .entries
            .get(&k)
            .map(|entries| entries.clone())
            .unwrap_or_default();

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
        let root = sig.signed_data.message_root();
        sigs_by_msg_root
            .entry(root)
            .or_insert_with(Vec::new)
            .push(sig.clone());
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
