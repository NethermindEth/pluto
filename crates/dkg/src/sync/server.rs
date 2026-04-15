//! Server handle for the DKG sync protocol.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use libp2p::PeerId;
use pluto_core::version::SemVer;
use tokio::sync::{Notify, RwLock};
use tokio_util::sync::CancellationToken;

use super::error::{Error, Result};

#[derive(Debug, Default)]
struct ServerState {
    shutdown: HashSet<PeerId>,
    connected: HashSet<PeerId>,
    steps: HashMap<PeerId, i64>,
    err: Option<Error>,
}

#[derive(Debug)]
struct ServerInner {
    all_count: usize,
    def_hash: Vec<u8>,
    version: SemVer,
    started: AtomicBool,
    notify: Notify,
    state: RwLock<ServerState>,
}

/// User-facing handle for the sync server state.
#[derive(Debug, Clone)]
pub struct Server {
    inner: Arc<ServerInner>,
}

impl Server {
    /// Creates a new server handle.
    pub fn new(all_count: usize, def_hash: Vec<u8>, version: SemVer) -> Self {
        Self {
            inner: Arc::new(ServerInner {
                all_count,
                def_hash,
                version,
                started: AtomicBool::new(false),
                notify: Notify::new(),
                state: RwLock::new(ServerState::default()),
            }),
        }
    }

    /// Starts the server side of the protocol.
    pub fn start(&self) {
        self.inner.started.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    /// Returns the current shared server error, if any.
    pub async fn err(&self) -> Option<Error> {
        self.inner.state.read().await.err.clone()
    }

    /// Waits until all peers have connected or an error occurs.
    pub async fn await_all_connected(&self, cancellation: CancellationToken) -> Result<()> {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);

            if !self.inner.started.load(Ordering::SeqCst) {
                tokio::select! {
                    _ = cancellation.cancelled() => return Err(Error::Canceled),
                    _ = &mut notified => {}
                }
                continue;
            }

            {
                let state = self.inner.state.read().await;
                if let Some(error) = &state.err {
                    return Err(error.clone());
                }
                if state.connected.len() == self.inner.all_count {
                    return Ok(());
                }
            }

            tokio::select! {
                _ = cancellation.cancelled() => return Err(Error::Canceled),
                _ = &mut notified => {}
            }
        }
    }

    /// Waits until all peers have reported shutdown.
    pub async fn await_all_shutdown(&self, cancellation: CancellationToken) -> Result<()> {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);

            {
                let state = self.inner.state.read().await;
                if let Some(error) = &state.err {
                    return Err(error.clone());
                }
                if state.shutdown.len() == self.inner.all_count {
                    return Ok(());
                }
            }

            tokio::select! {
                _ = cancellation.cancelled() => return Err(Error::Canceled),
                _ = &mut notified => {}
            }
        }
    }

    /// Waits until all peers have reached the given step or the next one.
    pub async fn await_all_at_step(
        &self,
        step: i64,
        cancellation: CancellationToken,
    ) -> Result<()> {
        let step_plus_one = step.checked_add(1).ok_or(Error::StepOverflow)?;
        let step_plus_two = step.checked_add(2).ok_or(Error::StepOverflow)?;

        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);

            {
                let state = self.inner.state.read().await;
                if let Some(error) = &state.err {
                    return Err(error.clone());
                }

                if state.steps.len() == self.inner.all_count {
                    let mut all_ok = true;
                    for actual in state.steps.values() {
                        if *actual >= step_plus_two {
                            return Err(Error::PeerStepTooFarAhead);
                        }

                        if *actual != step && *actual != step_plus_one {
                            all_ok = false;
                        }
                    }

                    if all_ok {
                        return Ok(());
                    }
                }
            }

            tokio::select! {
                _ = cancellation.cancelled() => return Err(Error::Canceled),
                _ = &mut notified => {}
            }
        }
    }

    pub(crate) fn def_hash(&self) -> &[u8] {
        &self.inner.def_hash
    }

    pub(crate) fn version(&self) -> &SemVer {
        &self.inner.version
    }

    pub(crate) fn expected_peer_count(&self) -> usize {
        self.inner.all_count
    }

    pub(crate) fn is_started(&self) -> bool {
        self.inner.started.load(Ordering::SeqCst)
    }

    pub(crate) async fn mark_connected(&self, peer_id: PeerId) -> (bool, usize) {
        let mut state = self.inner.state.write().await;
        let inserted = state.connected.insert(peer_id);
        let count = state.connected.len();
        if inserted {
            self.inner.notify.notify_waiters();
        }
        (inserted, count)
    }

    pub(crate) async fn clear_connected(&self, peer_id: PeerId) {
        self.mutate_state(|state| {
            state.connected.remove(&peer_id);
        })
        .await;
    }

    pub(crate) async fn set_shutdown(&self, peer_id: PeerId) {
        self.mutate_state(|state| {
            state.shutdown.insert(peer_id);
        })
        .await;
    }

    pub(crate) async fn set_err(&self, error: Error) {
        self.mutate_state(|state| {
            state.err = Some(error);
        })
        .await;
    }

    pub(crate) async fn update_step(&self, peer_id: PeerId, step: i64) -> Result<bool> {
        let mut state = self.inner.state.write().await;
        match state.steps.get(&peer_id).copied() {
            Some(current) => {
                if step < current {
                    return Err(Error::PeerStepBehind);
                }

                let current_plus_two = current.checked_add(2).ok_or(Error::StepOverflow)?;
                if step > current_plus_two {
                    return Err(Error::PeerStepAhead);
                }

                if step == current {
                    return Ok(false);
                }
            }
            None if !(0..=1).contains(&step) => {
                return Err(Error::AbnormalInitialStep);
            }
            None => {}
        }

        state.steps.insert(peer_id, step);
        self.inner.notify.notify_waiters();
        Ok(true)
    }

    async fn mutate_state(&self, mutate: impl FnOnce(&mut ServerState)) {
        let mut state = self.inner.state.write().await;
        mutate(&mut state);
        self.inner.notify.notify_waiters();
    }
}
