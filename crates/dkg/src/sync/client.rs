use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Duration,
};

use libp2p::PeerId;
use pluto_core::version::SemVer;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use super::Command;
use super::error::{Error, Result};

/// Default period between sync messages.
pub const DEFAULT_PERIOD: Duration = Duration::from_millis(100);

/// Configuration for a sync client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientConfig {
    /// Period between sync messages.
    pub period: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            period: DEFAULT_PERIOD,
        }
    }
}

#[derive(Debug)]
struct ClientInner {
    peer_id: PeerId,
    hash_sig: Vec<u8>,
    version: SemVer,
    period: Duration,
    active: AtomicBool,
    connected: AtomicBool,
    reconnect: AtomicBool,
    shutdown_requested: AtomicBool,
    finished: AtomicBool,
    outbound_claimed: AtomicBool,
    step: AtomicI64,
    done_tx: watch::Sender<Option<Result<()>>>,
    command_tx: Option<mpsc::UnboundedSender<Command>>,
}

/// User-facing handle for one outbound sync client.
#[derive(Debug, Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    /// Creates a new client with the default sync period.
    pub fn new(peer_id: PeerId, hash_sig: Vec<u8>, version: SemVer) -> Self {
        Self::new_with_config(peer_id, hash_sig, version, ClientConfig::default())
    }

    /// Creates a new client with an explicit config.
    pub fn new_with_config(
        peer_id: PeerId,
        hash_sig: Vec<u8>,
        version: SemVer,
        config: ClientConfig,
    ) -> Self {
        Self::new_with_command(peer_id, hash_sig, version, config, None)
    }

    pub(crate) fn new_wired(
        peer_id: PeerId,
        hash_sig: Vec<u8>,
        version: SemVer,
        config: ClientConfig,
        command_tx: mpsc::UnboundedSender<Command>,
    ) -> Self {
        Self::new_with_command(peer_id, hash_sig, version, config, Some(command_tx))
    }

    fn new_with_command(
        peer_id: PeerId,
        hash_sig: Vec<u8>,
        version: SemVer,
        config: ClientConfig,
        command_tx: Option<mpsc::UnboundedSender<Command>>,
    ) -> Self {
        let (done_tx, _done_rx) = watch::channel(None);
        Self {
            inner: Arc::new(ClientInner {
                peer_id,
                hash_sig,
                version,
                period: config.period,
                active: AtomicBool::new(false),
                connected: AtomicBool::new(false),
                reconnect: AtomicBool::new(true),
                shutdown_requested: AtomicBool::new(false),
                finished: AtomicBool::new(false),
                outbound_claimed: AtomicBool::new(false),
                step: AtomicI64::new(0),
                done_tx,
                command_tx,
            }),
        }
    }

    /// Returns the target peer for this client.
    pub fn peer_id(&self) -> PeerId {
        self.inner.peer_id
    }

    /// Runs the client until shutdown, fatal error, or cancellation.
    pub async fn run(&self, cancellation: CancellationToken) -> Result<()> {
        self.activate();
        self.wait_finished(cancellation, true).await
    }

    /// Sets the current client step.
    pub fn set_step(&self, step: i64) {
        self.inner.step.store(step, Ordering::SeqCst);
    }

    /// Returns whether the client currently has an active sync stream.
    pub fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }

    /// Requests a graceful shutdown and waits for the client to finish.
    pub async fn shutdown(&self, cancellation: CancellationToken) -> Result<()> {
        self.inner.shutdown_requested.store(true, Ordering::SeqCst);
        self.wait_finished(cancellation, false).await
    }

    /// Disables reconnecting for non-relay disconnects.
    pub fn disable_reconnect(&self) {
        self.inner.reconnect.store(false, Ordering::SeqCst);
    }

    pub(crate) fn version(&self) -> &SemVer {
        &self.inner.version
    }

    pub(crate) fn hash_sig(&self) -> &[u8] {
        &self.inner.hash_sig
    }

    pub(crate) fn period(&self) -> Duration {
        self.inner.period
    }

    pub(crate) fn should_run(&self) -> bool {
        self.inner.active.load(Ordering::SeqCst)
    }

    pub(crate) fn should_reconnect(&self) -> bool {
        self.inner.reconnect.load(Ordering::SeqCst)
    }

    pub(crate) fn shutdown_requested(&self) -> bool {
        self.inner.shutdown_requested.load(Ordering::SeqCst)
    }

    pub(crate) fn step(&self) -> i64 {
        self.inner.step.load(Ordering::SeqCst)
    }

    pub(crate) fn set_connected(&self, connected: bool) {
        self.inner.connected.store(connected, Ordering::SeqCst);
    }

    pub(crate) fn try_claim_outbound(&self) -> bool {
        !self.inner.outbound_claimed.swap(true, Ordering::SeqCst)
    }

    pub(crate) fn release_outbound(&self) {
        self.inner.outbound_claimed.store(false, Ordering::SeqCst);
    }

    pub(crate) fn finish(&self, result: Result<()>) {
        self.inner.active.store(false, Ordering::SeqCst);
        self.inner.connected.store(false, Ordering::SeqCst);
        self.release_outbound();

        if !self.inner.finished.swap(true, Ordering::SeqCst) {
            let _ = self.inner.done_tx.send(Some(result));
        }
    }

    pub(crate) fn activate(&self) {
        self.inner.active.store(true, Ordering::SeqCst);

        if let Some(command_tx) = &self.inner.command_tx {
            let _ = command_tx.send(Command::Activate(self.inner.peer_id));
        }
    }

    async fn wait_finished(
        &self,
        cancellation: CancellationToken,
        clear_on_cancel: bool,
    ) -> Result<()> {
        let mut done_rx = self.inner.done_tx.subscribe();

        loop {
            if let Some(result) = done_rx.borrow().clone() {
                return result;
            }

            tokio::select! {
                _ = cancellation.cancelled() => {
                    if clear_on_cancel {
                        self.inner.active.store(false, Ordering::SeqCst);
                        self.inner.connected.store(false, Ordering::SeqCst);
                    }
                    return Err(Error::Canceled);
                }
                changed = done_rx.changed() => {
                    if changed.is_err() {
                        return Err(Error::message("sync client completion channel closed"));
                    }
                }
            }
        }
    }
}
