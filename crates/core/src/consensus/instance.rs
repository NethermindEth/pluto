//! Consensus instance I/O channels.
//!
//! `InstanceIo` owns the bounded channels and one-time lifecycle flags for one
//! consensus instance.
//!
//! # Usage
//!
//! Keep one `InstanceIo<Message>` in component state for each active instance.
//! Producer paths enqueue through the crate-visible senders with `try_send`, so
//! a full channel surfaces immediately to the caller.
//!
//! Receiver ownership is explicit. Tokio receivers are single-consumer, so the
//! task that drives an instance must call each needed `take_*_rx` method once
//! at its ownership boundary. A second call returns
//! `Error::ReceiverAlreadyTaken`.
//!
//! The receive buffer accepts `RECV_BUFFER_SIZE` inbound messages before the
//! runner starts. The hash, protobuf value, verify, error, and decided-at
//! channels have capacity one because each represents one input or output slot
//! for this instance.
//!
//! `mark_proposed` and `mark_participated` reject duplicate entrypoints.
//! `maybe_start` performs the one-way transition into running state; only the
//! caller that receives `true` should spawn the runner.

use std::{
    error::Error as StdError,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use prost_types::Any;
use tokio::{sync::mpsc, time::Instant};

/// Receive-buffer channel capacity.
pub const RECV_BUFFER_SIZE: usize = 100;

/// Instance I/O errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Participate was already called for this instance.
    #[error("already participated")]
    AlreadyParticipated,

    /// Propose was already called for this instance.
    #[error("already proposed")]
    AlreadyProposed,

    /// Receiver ownership was already transferred.
    #[error("receiver already taken: {channel}")]
    ReceiverAlreadyTaken {
        /// Channel name.
        channel: &'static str,
    },
}

/// Instance I/O result.
pub type Result<T> = std::result::Result<T, Error>;

/// Boxed error returned by the runner on unsuccessful completion.
pub type RunnerError = Box<dyn StdError + Send + Sync + 'static>;

type ReceiverSlot<T> = Mutex<Option<mpsc::Receiver<T>>>;

/// Completion result sent by a consensus instance runner.
pub type RunnerResult = std::result::Result<(), RunnerError>;

/// Async input/output state for a single consensus instance.
///
/// Sender fields are crate-visible so component code can enqueue directly.
/// Receiver fields stay private because each receiver must move exactly once to
/// the task that owns that stream.
// TODO: Remove once the instance runner wires these senders.
#[allow(dead_code)]
#[derive(Debug)]
pub struct InstanceIo<T> {
    // Lifecycle flags are duplicate/start guards only. They do not publish or
    // synchronize channel payloads or runner state.
    participated: AtomicBool,
    proposed: AtomicBool,
    running: AtomicBool,

    /// Buffers inbound messages that may arrive before the runner starts.
    pub(crate) recv_tx: mpsc::Sender<T>,
    recv_rx: ReceiverSlot<T>,

    /// Supplies the local proposal hash.
    pub(crate) hash_tx: mpsc::Sender<[u8; 32]>,
    hash_rx: ReceiverSlot<[u8; 32]>,

    /// Supplies the local proposal value.
    ///
    /// `Any` is only the wire container at this boundary. Runner wiring owns
    /// the codec and type-url convention before decoding the concrete value.
    pub(crate) value_tx: mpsc::Sender<Any>,
    value_rx: ReceiverSlot<Any>,

    /// Supplies the value used to verify an external proposal.
    ///
    /// Uses the same `Any` wire-container convention as `value_tx`, keeping
    /// proposal and verification paths on one payload format.
    pub(crate) verify_tx: mpsc::Sender<Any>,
    verify_rx: ReceiverSlot<Any>,

    /// Publishes the runner completion result.
    pub(crate) err_tx: mpsc::Sender<RunnerResult>,
    err_rx: ReceiverSlot<RunnerResult>,

    /// Publishes the decision timestamp.
    pub(crate) decided_at_tx: mpsc::Sender<Instant>,
    decided_at_rx: ReceiverSlot<Instant>,
}

impl<T> InstanceIo<T> {
    /// Creates empty channels and clears all lifecycle flags.
    pub fn new() -> Self {
        let (recv_tx, recv_rx) = mpsc::channel(RECV_BUFFER_SIZE);
        let (hash_tx, hash_rx) = mpsc::channel(1);
        let (value_tx, value_rx) = mpsc::channel(1);
        let (verify_tx, verify_rx) = mpsc::channel(1);
        let (err_tx, err_rx) = mpsc::channel(1);
        let (decided_at_tx, decided_at_rx) = mpsc::channel(1);

        Self {
            participated: AtomicBool::new(false),
            proposed: AtomicBool::new(false),
            running: AtomicBool::new(false),
            recv_tx,
            recv_rx: Mutex::new(Some(recv_rx)),
            hash_tx,
            hash_rx: Mutex::new(Some(hash_rx)),
            value_tx,
            value_rx: Mutex::new(Some(value_rx)),
            verify_tx,
            verify_rx: Mutex::new(Some(verify_rx)),
            err_tx,
            err_rx: Mutex::new(Some(err_rx)),
            decided_at_tx,
            decided_at_rx: Mutex::new(Some(decided_at_rx)),
        }
    }

    /// Marks the participate entrypoint as used.
    ///
    /// Returns [`Error::AlreadyParticipated`] on duplicate calls.
    pub fn mark_participated(&self) -> Result<()> {
        self.participated
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .map(|_| ())
            .map_err(|_| Error::AlreadyParticipated)
    }

    /// Marks the propose entrypoint as used.
    ///
    /// Returns [`Error::AlreadyProposed`] on duplicate calls.
    pub fn mark_proposed(&self) -> Result<()> {
        self.proposed
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .map(|_| ())
            .map_err(|_| Error::AlreadyProposed)
    }

    /// Returns `true` if this call owns starting the runner.
    ///
    /// This is a one-way transition. Completion does not reset the flag.
    pub fn maybe_start(&self) -> bool {
        self.running
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Transfers receive-buffer ownership to the runner.
    pub fn take_recv_rx(&self) -> Result<mpsc::Receiver<T>> {
        take_receiver(&self.recv_rx, "recv")
    }

    /// Transfers local proposal hash ownership to the runner.
    pub fn take_hash_rx(&self) -> Result<mpsc::Receiver<[u8; 32]>> {
        take_receiver(&self.hash_rx, "hash")
    }

    /// Transfers local proposal value ownership to the runner.
    pub fn take_value_rx(&self) -> Result<mpsc::Receiver<Any>> {
        take_receiver(&self.value_rx, "value")
    }

    /// Transfers external proposal verification ownership to the runner.
    pub fn take_verify_rx(&self) -> Result<mpsc::Receiver<Any>> {
        take_receiver(&self.verify_rx, "verify")
    }

    /// Transfers runner result ownership to the waiting task.
    pub fn take_err_rx(&self) -> Result<mpsc::Receiver<RunnerResult>> {
        take_receiver(&self.err_rx, "err")
    }

    /// Transfers decision timestamp ownership to the waiting task.
    pub fn take_decided_at_rx(&self) -> Result<mpsc::Receiver<Instant>> {
        take_receiver(&self.decided_at_rx, "decided_at")
    }
}

impl<T> Default for InstanceIo<T> {
    fn default() -> Self {
        Self::new()
    }
}

fn take_receiver<T>(
    receiver: &Mutex<Option<mpsc::Receiver<T>>>,
    channel: &'static str,
) -> Result<mpsc::Receiver<T>> {
    receiver
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .ok_or(Error::ReceiverAlreadyTaken { channel })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::mpsc::error::TrySendError;

    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("test error")]
    struct TestError;

    #[test]
    fn mark_participated() {
        let io = InstanceIo::<()>::new();

        assert_eq!(Ok(()), io.mark_participated());
        assert_eq!(Err(Error::AlreadyParticipated), io.mark_participated());
    }

    #[test]
    fn mark_proposed() {
        let io = InstanceIo::<()>::new();

        assert_eq!(Ok(()), io.mark_proposed());
        assert_eq!(Err(Error::AlreadyProposed), io.mark_proposed());
    }

    #[test]
    fn maybe_start() {
        let io = InstanceIo::<()>::new();

        assert!(io.maybe_start());
        assert!(!io.maybe_start());
        assert!(!io.maybe_start());
    }

    #[test]
    fn recv_buffer_capacity_is_100() {
        let io = InstanceIo::<usize>::new();

        for msg in 0..RECV_BUFFER_SIZE {
            assert!(io.recv_tx.try_send(msg).is_ok());
        }

        assert!(matches!(
            io.recv_tx.try_send(RECV_BUFFER_SIZE),
            Err(TrySendError::Full(RECV_BUFFER_SIZE))
        ));
    }

    #[test]
    fn single_item_channels_have_capacity_1() {
        let io = InstanceIo::<()>::new();

        assert!(io.hash_tx.try_send([0; 32]).is_ok());
        match io.hash_tx.try_send([1; 32]) {
            Err(TrySendError::Full(value)) => assert_eq!([1; 32], value),
            result => panic!("unexpected hash send result: {result:?}"),
        }

        assert!(io.value_tx.try_send(proto_value()).is_ok());
        assert!(matches!(
            io.value_tx.try_send(proto_value()),
            Err(TrySendError::Full(_))
        ));

        assert!(io.verify_tx.try_send(proto_value()).is_ok());
        assert!(matches!(
            io.verify_tx.try_send(proto_value()),
            Err(TrySendError::Full(_))
        ));

        assert!(io.err_tx.try_send(Ok(())).is_ok());
        assert!(matches!(
            io.err_tx.try_send(Err(Box::new(TestError))),
            Err(TrySendError::Full(Err(_)))
        ));

        let decided_at = Instant::now();
        assert!(io.decided_at_tx.try_send(decided_at).is_ok());
        assert!(matches!(
            io.decided_at_tx.try_send(decided_at),
            Err(TrySendError::Full(_))
        ));
    }

    #[test]
    fn recv_tx_send_does_not_consume_start_token() {
        let io = InstanceIo::<u8>::new();

        assert!(io.recv_tx.try_send(1).is_ok());
        assert!(io.maybe_start());
        assert!(!io.maybe_start());
    }

    #[test]
    fn receiver_ownership_can_only_be_taken_once() {
        let io = InstanceIo::<()>::new();

        assert!(io.take_recv_rx().is_ok());
        assert_receiver_already_taken(io.take_recv_rx(), "recv");

        assert!(io.take_hash_rx().is_ok());
        assert_receiver_already_taken(io.take_hash_rx(), "hash");

        assert!(io.take_value_rx().is_ok());
        assert_receiver_already_taken(io.take_value_rx(), "value");

        assert!(io.take_verify_rx().is_ok());
        assert_receiver_already_taken(io.take_verify_rx(), "verify");

        assert!(io.take_err_rx().is_ok());
        assert_receiver_already_taken(io.take_err_rx(), "err");

        assert!(io.take_decided_at_rx().is_ok());
        assert_receiver_already_taken(io.take_decided_at_rx(), "decided_at");
    }

    #[test]
    fn concurrent_maybe_start_returns_true_once() {
        let io = Arc::new(InstanceIo::<()>::new());
        let mut handles = Vec::new();

        for _ in 0..32 {
            let io = Arc::clone(&io);
            handles.push(std::thread::spawn(move || io.maybe_start()));
        }

        let started = handles
            .into_iter()
            .map(|handle| match handle.join() {
                Ok(started) => started,
                Err(_) => panic!("maybe_start thread panicked"),
            })
            .filter(|started| *started)
            .count();

        assert_eq!(1, started);
        assert!(!io.maybe_start());
    }

    fn assert_receiver_already_taken<T>(
        result: std::result::Result<mpsc::Receiver<T>, Error>,
        channel: &'static str,
    ) {
        assert!(matches!(
            result,
            Err(Error::ReceiverAlreadyTaken { channel: actual }) if actual == channel
        ));
    }

    fn proto_value() -> Any {
        Any::default()
    }
}
