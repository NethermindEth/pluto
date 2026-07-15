//! In-memory FROST transport and ceremony driver shared by the unit tests
//! and the criterion benches (`bench-util` feature). Not for production use.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use pluto_frost::kryptology::{Round1Bcast, Round2Bcast, ShamirShare};
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;

use crate::{
    frost::{FTransport, FrostError, MsgKey, Round1Output, run_frost_parallel},
    share::Share,
};

/// In-memory [`FTransport`] delivering FROST round messages between
/// in-process participants without any networking.
pub struct FrostMemTransport {
    nodes: usize,
    inner: Mutex<FrostMemTransportInner>,
    notify: Notify,
}

#[derive(Default)]
struct FrostMemTransportInner {
    round1: usize,
    round1_bcast: HashMap<MsgKey, Round1Bcast>,
    round1_shares: HashMap<u32, HashMap<MsgKey, ShamirShare>>,
    round2: usize,
    round2_bcast: HashMap<MsgKey, Round2Bcast>,
}

impl FrostMemTransport {
    /// Creates a transport for `nodes` participants.
    pub fn new(nodes: usize) -> Self {
        Self {
            nodes,
            inner: Mutex::new(FrostMemTransportInner::default()),
            notify: Notify::new(),
        }
    }
}

#[async_trait]
impl FTransport for Arc<FrostMemTransport> {
    async fn round1(
        &mut self,
        cancellation: &CancellationToken,
        bcast: HashMap<MsgKey, Round1Bcast>,
        shares: HashMap<MsgKey, ShamirShare>,
    ) -> Result<Round1Output, FrostError> {
        let source_id = bcast
            .keys()
            .next()
            .map(|key| key.source_id)
            .ok_or(FrostError::MissingRoundState)?;
        debug_assert!(bcast.keys().all(|key| key.source_id == source_id));

        {
            let mut inner = self.inner.lock().await;
            if inner.round1 == self.nodes {
                inner.round1 = 0;
                inner.round1_bcast.clear();
                inner.round1_shares.clear();
            }
            for (key, round1_bcast) in bcast {
                inner.round1_bcast.insert(
                    MsgKey {
                        val_idx: key.val_idx,
                        source_id: key.source_id,
                        target_id: 0,
                    },
                    round1_bcast,
                );
            }
            for (key, share) in shares {
                inner
                    .round1_shares
                    .entry(key.target_id)
                    .or_default()
                    .insert(key, share);
            }
            inner.round1 = inner
                .round1
                .checked_add(1)
                .expect("test round counter should not overflow");
        }
        self.notify.notify_waiters();

        loop {
            let notified = self.notify.notified();
            {
                let inner = self.inner.lock().await;
                if inner.round1 == self.nodes {
                    return Ok((
                        inner.round1_bcast.clone(),
                        inner
                            .round1_shares
                            .get(&source_id)
                            .cloned()
                            .unwrap_or_default(),
                    ));
                }
            }

            tokio::select! {
                _ = cancellation.cancelled() => return Err(FrostError::Cancelled),
                _ = notified => {}
            }
        }
    }

    async fn round2(
        &mut self,
        cancellation: &CancellationToken,
        bcast: HashMap<MsgKey, Round2Bcast>,
    ) -> Result<HashMap<MsgKey, Round2Bcast>, FrostError> {
        {
            let mut inner = self.inner.lock().await;
            if inner.round2 == self.nodes {
                inner.round2 = 0;
                inner.round2_bcast.clear();
            }
            for (key, round2_bcast) in bcast {
                inner.round2_bcast.insert(
                    MsgKey {
                        val_idx: key.val_idx,
                        source_id: key.source_id,
                        target_id: 0,
                    },
                    round2_bcast,
                );
            }
            inner.round2 = inner
                .round2
                .checked_add(1)
                .expect("test round counter should not overflow");
        }
        self.notify.notify_waiters();

        loop {
            let notified = self.notify.notified();
            {
                let inner = self.inner.lock().await;
                if inner.round2 == self.nodes {
                    return Ok(inner.round2_bcast.clone());
                }
            }

            tokio::select! {
                _ = cancellation.cancelled() => return Err(FrostError::Cancelled),
                _ = notified => {}
            }
        }
    }
}

/// Runs a full in-process FROST DKG ceremony over the in-memory
/// transport and returns every node's shares.
///
/// # Panics
///
/// Panics when the ceremony fails; callers are tests and benches.
pub async fn run_mem_dkg(nodes: u32, threshold: u32, vals: u32) -> Vec<Vec<Share>> {
    let cancellation = CancellationToken::new();
    let tp = Arc::new(FrostMemTransport::new(
        usize::try_from(nodes).expect("nodes should fit"),
    ));

    let mut tasks = Vec::new();
    for i in 0..nodes {
        let mut tp = Arc::clone(&tp);
        let cancellation = cancellation.clone();
        tasks.push(tokio::spawn(async move {
            run_frost_parallel(
                cancellation,
                &mut tp,
                vals,
                nodes,
                threshold,
                i.checked_add(1).expect("share index should not overflow"),
                "0",
            )
            .await
        }));
    }

    let mut node_shares = Vec::new();
    for task in tasks {
        let shares = task
            .await
            .expect("task should not panic")
            .expect("DKG should run");
        assert_eq!(
            shares.len(),
            usize::try_from(vals).expect("vals should fit")
        );
        node_shares.push(shares);
    }

    node_shares
}
