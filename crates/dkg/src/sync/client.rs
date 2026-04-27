use std::{
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

use bon::Builder;
use libp2p::PeerId;
use pluto_core::version::SemVer;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use super::{
    Command,
    error::{Error, Result},
};

/// Default period between sync messages.
pub const DEFAULT_PERIOD: Duration = Duration::from_millis(100);

/// Configuration for a sync client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Builder)]
pub struct ClientConfig {
    /// Period between sync messages.
    #[builder(default = DEFAULT_PERIOD)]
    pub period: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self::builder().build()
    }
}

#[derive(Debug)]
struct ClientInner {
    peer_id: PeerId,
    hash_sig: Vec<u8>,
    version: SemVer,
    period: Duration,
    state: RwLock<ClientState>,
    stop_tx: watch::Sender<bool>,
    done_tx: watch::Sender<Option<Result<()>>>,
    command_tx: Option<mpsc::UnboundedSender<Command>>,
}

#[derive(Debug)]
struct ClientState {
    active: bool,
    connected: bool,
    reconnect: bool,
    step: i64,
    shutdown_requested: bool,
    finished: bool,
    outbound_claimed: bool,
}

/// User-facing handle for one outbound sync client.
#[derive(Debug, Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    /// Creates a new client with an explicit config.
    pub(crate) fn new(
        peer_id: PeerId,
        hash_sig: Vec<u8>,
        version: SemVer,
        config: ClientConfig,
        command_tx: Option<mpsc::UnboundedSender<Command>>,
    ) -> Self {
        let (stop_tx, _stop_rx) = watch::channel(false);
        let (done_tx, _done_rx) = watch::channel(None);
        Self {
            inner: Arc::new(ClientInner {
                peer_id,
                hash_sig,
                version,
                period: config.period,
                state: RwLock::new(ClientState {
                    active: false,
                    connected: false,
                    reconnect: true,
                    step: 0,
                    shutdown_requested: false,
                    finished: false,
                    outbound_claimed: false,
                }),
                stop_tx,
                done_tx,
                command_tx,
            }),
        }
    }

    /// Runs the client until shutdown, fatal error, or cancellation.
    pub async fn run(&self, cancellation: CancellationToken) -> Result<()> {
        self.activate()?;
        self.wait_finished(cancellation, true).await
    }

    /// Sets the current client step.
    pub fn set_step(&self, step: i64) {
        self.write_state().step = step;
    }

    /// Returns whether the client currently has an active sync stream.
    pub fn is_connected(&self) -> bool {
        self.read_state().connected
    }

    /// Requests a graceful shutdown and waits for the client to finish.
    pub async fn shutdown(&self, cancellation: CancellationToken) -> Result<()> {
        self.write_state().shutdown_requested = true;
        self.wait_finished(cancellation, false).await
    }

    /// Disables reconnecting for non-relay disconnects.
    pub fn disable_reconnect(&self) {
        self.write_state().reconnect = false;
    }

    pub(crate) fn peer_id(&self) -> PeerId {
        self.inner.peer_id
    }

    pub(crate) fn hash_sig(&self) -> &[u8] {
        &self.inner.hash_sig
    }

    pub(crate) fn version(&self) -> &SemVer {
        &self.inner.version
    }

    pub(crate) fn period(&self) -> Duration {
        self.inner.period
    }

    pub(crate) fn should_run(&self) -> bool {
        self.read_state().active
    }

    pub(crate) fn should_reconnect(&self) -> bool {
        self.read_state().reconnect
    }

    pub(crate) fn should_schedule_dial(&self) -> bool {
        let state = self.read_state();
        state.active && !state.connected && !state.shutdown_requested
    }

    pub(crate) fn outbound_message_state(&self) -> (bool, i64) {
        let state = self.read_state();
        (state.shutdown_requested, state.step)
    }

    pub(crate) fn set_connected(&self, connected: bool) {
        self.write_state().connected = connected;
    }

    /// Claims ownership of this client's outbound stream for one handler.
    pub(crate) fn try_claim_outbound(&self) -> bool {
        let mut state = self.write_state();
        if state.outbound_claimed {
            return false;
        }
        state.outbound_claimed = true;
        true
    }

    /// Releases the outbound stream claim after the handler exits.
    pub(crate) fn release_outbound(&self) {
        self.write_state().outbound_claimed = false;
    }

    /// Completes the client once and publishes the result to all waiters.
    pub(crate) fn finish(&self, result: Result<()>) {
        let should_send = {
            let mut state = self.write_state();
            state.active = false;
            state.connected = false;
            state.outbound_claimed = false;
            if state.finished {
                false
            } else {
                state.finished = true;
                true
            }
        };

        self.set_stop_requested(true);
        if should_send {
            let _ = self.inner.done_tx.send(Some(result));
        }
    }

    /// Subscribes to stop requests from an already-running outbound stream.
    pub(crate) fn stop_requested_rx(&self) -> watch::Receiver<bool> {
        self.inner.stop_tx.subscribe()
    }

    /// Marks the client active and asks the behaviour to open an outbound
    /// stream.
    pub(crate) fn activate(&self) -> Result<()> {
        self.write_state().active = true;
        self.set_stop_requested(false);

        if let Some(command_tx) = &self.inner.command_tx
            && command_tx
                .send(Command::Activate(self.inner.peer_id))
                .is_ok()
        {
            return Ok(());
        }

        self.write_state().active = false;
        Err(Error::ActivationChannelUnavailable)
    }

    /// Requests any live outbound stream loop to exit.
    fn request_stop(&self) {
        {
            let mut state = self.write_state();
            state.active = false;
            state.connected = false;
        }
        self.set_stop_requested(true);
    }

    /// Updates the stop flag without waking watchers when the value is
    /// unchanged.
    fn set_stop_requested(&self, stop_requested: bool) {
        self.inner.stop_tx.send_if_modified(|current| {
            if *current == stop_requested {
                false
            } else {
                *current = stop_requested;
                true
            }
        });
    }

    fn read_state(&self) -> RwLockReadGuard<'_, ClientState> {
        self.inner
            .state
            .read()
            .expect("sync client state lock poisoned")
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, ClientState> {
        self.inner
            .state
            .write()
            .expect("sync client state lock poisoned")
    }

    /// Waits for `finish` to publish a result or for local cancellation.
    async fn wait_finished(
        &self,
        cancellation: CancellationToken,
        clear_on_cancel: bool,
    ) -> Result<()> {
        // `run()` uses cancellation to stop the live stream. `shutdown()` has
        // already requested shutdown, so its cancellation only stops waiting.
        let mut done_rx = self.inner.done_tx.subscribe();

        loop {
            if let Some(result) = done_rx.borrow().clone() {
                return result;
            }

            tokio::select! {
                _ = cancellation.cancelled() => {
                    if clear_on_cancel {
                        self.request_stop();
                    }
                    return Err(Error::Canceled);
                }
                changed = done_rx.changed() => {
                    if changed.is_err() {
                        return Err(Error::CompletionChannelClosed);
                    }

                    if let Some(result) = done_rx.borrow().clone() {
                        return result;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use libp2p::PeerId;
    use pluto_core::version::SemVer;

    use super::*;

    #[tokio::test]
    async fn run_fails_immediately_if_activation_channel_is_closed() {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        drop(command_rx);

        let client = Client::new(
            PeerId::random(),
            vec![1, 2, 3],
            SemVer::parse("v1.7").expect("version"),
            ClientConfig::default(),
            Some(command_tx),
        );

        let error = client
            .run(CancellationToken::new())
            .await
            .expect_err("closed activation channel should fail immediately");

        assert!(matches!(error, Error::ActivationChannelUnavailable));
        assert!(!client.should_run());
    }

    #[tokio::test]
    async fn request_stop_notifies_outbound_waiters() {
        let client = Client::new(
            PeerId::random(),
            vec![1, 2, 3],
            SemVer::parse("v1.7").expect("version"),
            ClientConfig::default(),
            None,
        );
        let mut stop_rx = client.stop_requested_rx();

        assert!(!*stop_rx.borrow());

        client.request_stop();
        stop_rx
            .changed()
            .await
            .expect("stop sender should stay alive");

        assert!(*stop_rx.borrow());
    }
}
