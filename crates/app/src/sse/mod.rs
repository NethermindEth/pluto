//! Beacon node Server-Sent-Events (SSE) listener.
//!
//! Subscribes to a beacon node's `/eth/v1/events` stream and processes `head`,
//! `chain_reorg`, `block` and `block_gossip` events to export timing metrics
//! and notify subscribers of chain reorgs.
//!
//! The listener follows the actor model: a [`SseListenerBuilder`] wires up
//! subscriptions, [`SseListenerBuilder::build`] spawns a background actor (and
//! a reconnecting stream "pump") that live until a [`CancellationToken`] fires,
//! and the returned [`SseListenerHandle`] allows interacting with the running
//! actor.

use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder, Retryable};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use tokio::sync;
use tokio_util::{future::FutureExt, sync::CancellationToken};

use pluto_eth2api::{BeaconNodeEvent, EthBeaconNodeApiClient, EventstreamRequestQueryTopic};

use crate::sse::{
    metrics::SSE_METRICS,
    types::{
        BLOCK_EVENT, BLOCK_GOSSIP_EVENT, BlockEventData, BlockGossipEventData, CHAIN_REORG_EVENT,
        ChainReorgEventData, HEAD_EVENT, HeadEventData, SseEvent,
    },
};

pub mod metrics;
pub mod types;

/// Default buffer size for the channels used by the listener.
const CHANNEL_BUFFER_SIZE: usize = 1024;

/// Base delay between SSE reconnection attempts.
const DEFAULT_RETRY: Duration = Duration::from_secs(1);

/// Topics the listener subscribes to.
const TOPICS: [EventstreamRequestQueryTopic; 4] = [
    EventstreamRequestQueryTopic::Head,
    EventstreamRequestQueryTopic::ChainReorg,
    EventstreamRequestQueryTopic::BlockGossip,
    EventstreamRequestQueryTopic::Block,
];

/// Errors that can occur while setting up or running the SSE listener.
#[derive(Debug, thiserror::Error)]
pub enum SseListenerError {
    /// Beacon Node API client error.
    #[error("Error while fetching data from the Eth2 API: {0}")]
    EthBeaconNodeApiClientError(#[from] pluto_eth2api::EthBeaconNodeApiClientError),

    /// The underlying SSE listener actor has been terminated.
    #[error("SSE listener actor has been terminated")]
    Terminated,
}

type Result<T> = std::result::Result<T, SseListenerError>;

/// A builder for the SSE listener.
///
/// Allows setting up chain reorg subscriptions before the listener is started.
/// The listener is started by calling [`SseListenerBuilder::build`].
pub struct SseListenerBuilder {
    // TODO: Prefer to use a `broadcast` channel here to simplify the subscription management.
    // Requires revisiting the potential subscribers.
    reorg_subs: Vec<sync::mpsc::Sender<u64>>,
}

impl SseListenerBuilder {
    /// Constructs a new [`SseListenerBuilder`] with no subscriptions.
    pub fn new() -> Self {
        SseListenerBuilder {
            reorg_subs: Vec::new(),
        }
    }

    /// Subscribes to chain reorg events, returning the receiving end of a
    /// channel that yields the (deduplicated) reorg epochs.
    ///
    /// The returned receiver can be passed directly to consumers such as the
    /// scheduler's `with_chain_reorgs`.
    pub fn subscribe_chain_reorg(&mut self) -> sync::mpsc::Receiver<u64> {
        let (tx, rx) = sync::mpsc::channel(CHANNEL_BUFFER_SIZE);
        self.reorg_subs.push(tx);
        rx
    }

    /// Starts the SSE listener in the background.
    ///
    /// Blocks until the beacon node's genesis time and slot configuration have
    /// been fetched (retrying on failure), then spawns the actor and a
    /// reconnecting stream pump that run until `ct` is cancelled.
    pub async fn build(
        self,
        client: EthBeaconNodeApiClient,
        ct: CancellationToken,
    ) -> Result<SseListenerHandle> {
        let (genesis_time, slot_duration, slots_per_epoch) = fetch_config(&client)
            .with_cancellation_token(&ct)
            .await
            .ok_or(SseListenerError::Terminated)??;

        let addr = client.base_url.to_string();

        let actor = SseListenerActor {
            addr: addr.clone(),
            genesis_time,
            slot_duration,
            slots_per_epoch,
            last_reorg_epoch: 0,
            reorg_subs: self.reorg_subs,
        };

        let (events_tx, events_rx) = sync::mpsc::channel(CHANNEL_BUFFER_SIZE);
        let (msg_tx, msg_rx) = sync::mpsc::channel(CHANNEL_BUFFER_SIZE);

        tokio::spawn(run_pump(client, addr, events_tx, ct.clone()));
        tokio::spawn(actor.run(events_rx, msg_rx, ct));

        Ok(SseListenerHandle { sender: msg_tx })
    }
}

impl Default for SseListenerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Messages sent to the [`SseListenerActor`].
enum SseListenerMessage {
    /// Subscribe to chain reorg events at runtime; the actor replies with the
    /// receiving end of a freshly created channel.
    SubscribeChainReorg {
        resp: sync::oneshot::Sender<sync::mpsc::Receiver<u64>>,
    },
}

/// A handle to interact with the SSE listener actor.
///
/// Cloning the handle is cheap and allows sending messages to the actor from
/// multiple tasks.
#[derive(Clone)]
pub struct SseListenerHandle {
    sender: sync::mpsc::Sender<SseListenerMessage>,
}

impl SseListenerHandle {
    /// Subscribes to chain reorg events at runtime, returning the receiving end
    /// of a channel that yields the (deduplicated) reorg epochs.
    pub async fn subscribe_chain_reorg(&self) -> Result<sync::mpsc::Receiver<u64>> {
        let (tx, rx) = sync::oneshot::channel();
        self.sender
            .send(SseListenerMessage::SubscribeChainReorg { resp: tx })
            .await
            .map_err(|_| SseListenerError::Terminated)?;

        rx.await.map_err(|_| SseListenerError::Terminated)
    }
}

struct SseListenerActor {
    addr: String,

    // Immutable network configuration.
    genesis_time: DateTime<Utc>,
    slot_duration: Duration,
    slots_per_epoch: u64,

    last_reorg_epoch: u64,
    reorg_subs: Vec<sync::mpsc::Sender<u64>>,
}

impl SseListenerActor {
    async fn run(
        mut self,
        mut events_rx: sync::mpsc::Receiver<SseEvent>,
        mut msg_rx: sync::mpsc::Receiver<SseListenerMessage>,
        ct: CancellationToken,
    ) {
        loop {
            tokio::select! {
                biased;

                _ = ct.cancelled() => break,

                Some(msg) = msg_rx.recv() => match msg {
                    SseListenerMessage::SubscribeChainReorg { resp } => {
                        let (tx, rx) = sync::mpsc::channel(CHANNEL_BUFFER_SIZE);
                        self.reorg_subs.push(tx);
                        let _ = resp.send(rx);
                    }
                },

                event = events_rx.recv() => match event {
                    Some(event) => self.handle_event(&event),
                    // The pump dropped its sender (e.g. it returned early or
                    // panicked). Stop instead of parking forever on a disabled
                    // branch with no events and no reconnection.
                    None => {
                        tracing::error!(addr = %self.addr, "SSE event channel closed; stopping listener");
                        break;
                    }
                },
            }
        }
    }

    fn handle_event(&mut self, event: &SseEvent) {
        match event.topic.as_str() {
            HEAD_EVENT => self.handle_head(event),
            CHAIN_REORG_EVENT => self.handle_chain_reorg(event),
            BLOCK_GOSSIP_EVENT => self.handle_block_gossip(event),
            BLOCK_EVENT => self.handle_block(event),
            _ => {}
        }
    }

    fn handle_head(&self, event: &SseEvent) {
        let head: HeadEventData = match serde_json::from_str(&event.data) {
            Ok(head) => head,
            Err(err) => {
                tracing::warn!(err = ?err, addr = %self.addr, topic = HEAD_EVENT, "Failed to parse SSE event");
                return;
            }
        };
        let slot = head.slot;

        // The chain's head is updated once a majority of the chain votes for a
        // block, which realistically happens between 2/3 and 3/3 of the slot.
        let window =
            chrono::Duration::from_std(self.slot_duration).unwrap_or(chrono::Duration::MAX);
        let (delay, ok) = self.compute_delay(slot, event.timestamp, |delay| delay < window);
        let delay_s = delay_secs(delay);

        if ok {
            SSE_METRICS.sse_head_delay[&self.addr].observe(delay_s);
        } else {
            tracing::debug!(addr = %self.addr, slot, delay_s, "Beacon node received head event too late");
        }

        SSE_METRICS.sse_head_slot[&self.addr].set(slot);

        tracing::debug!(
            addr = %self.addr,
            slot,
            delay_s,
            block = %head.block,
            prev_ddr = %head.previous_duty_dependent_root,
            curr_ddr = %head.current_duty_dependent_root,
            "SSE head event"
        );
    }

    fn handle_chain_reorg(&mut self, event: &SseEvent) {
        let reorg: ChainReorgEventData = match serde_json::from_str(&event.data) {
            Ok(reorg) => reorg,
            Err(err) => {
                tracing::warn!(err = ?err, addr = %self.addr, topic = CHAIN_REORG_EVENT, "Failed to parse SSE event");
                return;
            }
        };
        if reorg.slot < reorg.depth {
            tracing::warn!(addr = %self.addr, slot = reorg.slot, depth = reorg.depth, "Invalid chain reorg event: depth exceeds slot");
            return;
        }

        // `slot >= depth` is guaranteed above and `slots_per_epoch` is non-zero
        // (validated by `fetch_slots_config`).
        let reorg_epoch = reorg
            .slot
            .checked_sub(reorg.depth)
            .expect("slot >= depth")
            .checked_div(self.slots_per_epoch)
            .expect("non-zero slots per epoch");
        self.notify_chain_reorg(reorg_epoch);

        tracing::debug!(
            addr = %self.addr,
            slot = reorg.slot,
            epoch = reorg.epoch,
            reorg_epoch,
            depth = reorg.depth,
            old_head_block = %reorg.old_head_block,
            new_head_block = %reorg.new_head_block,
            "SSE chain reorg event"
        );

        // Reorg depths fit comfortably in a `u32`; `f64::from` is lossless.
        let depth_f64 = f64::from(u32::try_from(reorg.depth).unwrap_or(u32::MAX));
        SSE_METRICS.sse_chain_reorg_depth[&self.addr].observe(depth_f64);
    }

    fn handle_block_gossip(&self, event: &SseEvent) {
        let gossip: BlockGossipEventData = match serde_json::from_str(&event.data) {
            Ok(gossip) => gossip,
            Err(err) => {
                tracing::warn!(err = ?err, addr = %self.addr, topic = BLOCK_GOSSIP_EVENT, "Failed to parse SSE event");
                return;
            }
        };
        let slot = gossip.slot;

        // A block should be received via gossip between 0/3 and 1/3 of the slot.
        let third = self.slot_duration.checked_div(3).expect("non-zero divisor");
        let window = chrono::Duration::from_std(third).unwrap_or(chrono::Duration::MAX);
        let (delay, ok) = self.compute_delay(slot, event.timestamp, |delay| delay < window);
        let delay_s = delay_secs(delay);

        if !ok {
            tracing::debug!(addr = %self.addr, slot, delay_s, "Beacon node received block_gossip event too late");
        }

        tracing::debug!(addr = %self.addr, slot, delay_s, block = %gossip.block, "SSE block gossip event");

        SSE_METRICS.sse_block_gossip[&self.addr].observe(delay_s);
    }

    fn handle_block(&self, event: &SseEvent) {
        let block: BlockEventData = match serde_json::from_str(&event.data) {
            Ok(block) => block,
            Err(err) => {
                tracing::warn!(err = ?err, addr = %self.addr, topic = BLOCK_EVENT, "Failed to parse SSE event");
                return;
            }
        };
        let slot = block.slot;

        // A block should be imported into fork choice between 0/3 and 1/3 of the
        // slot.
        let third = self.slot_duration.checked_div(3).expect("non-zero divisor");
        let window = chrono::Duration::from_std(third).unwrap_or(chrono::Duration::MAX);
        let (delay, ok) = self.compute_delay(slot, event.timestamp, |delay| delay < window);
        let delay_s = delay_secs(delay);

        if !ok {
            tracing::debug!(addr = %self.addr, slot, delay_s, "Beacon node received block event too late");
        }

        tracing::debug!(addr = %self.addr, slot, delay_s, block = %block.block, "SSE block event");

        SSE_METRICS.sse_block[&self.addr].observe(delay_s);
    }

    /// Notifies subscribers of a chain reorg, deduplicating consecutive events
    /// for the same epoch. Subscribers whose receiver has been dropped are
    /// pruned.
    fn notify_chain_reorg(&mut self, epoch: u64) {
        if epoch == self.last_reorg_epoch {
            return;
        }
        self.last_reorg_epoch = epoch;

        let addr = &self.addr;
        self.reorg_subs.retain(|tx| match tx.try_send(epoch) {
            Ok(()) => true,
            Err(sync::mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(addr = %addr, epoch, "Chain reorg subscriber lagging, dropping event");
                true
            }
            Err(sync::mpsc::error::TrySendError::Closed(_)) => false,
        });
    }

    /// Computes the delay between the start of `slot` and the event timestamp,
    /// reporting whether it falls within the expected window.
    fn compute_delay(
        &self,
        slot: u64,
        event_ts: DateTime<Utc>,
        delay_ok: impl Fn(chrono::Duration) -> bool,
    ) -> (chrono::Duration, bool) {
        // Slot times are small in practice (slot duration is a few whole
        // seconds), so saturate on the unreachable overflow.
        let slot = i64::try_from(slot).unwrap_or(i64::MAX);
        let ms_per_slot = i64::try_from(self.slot_duration.as_millis()).unwrap_or(i64::MAX);
        let offset = chrono::Duration::milliseconds(slot.saturating_mul(ms_per_slot));
        let slot_start = self
            .genesis_time
            .checked_add_signed(offset)
            .unwrap_or(event_ts);
        let delay = event_ts.signed_duration_since(slot_start);

        (delay, delay_ok(delay))
    }
}

/// Fetches the genesis time, slot duration and slots per epoch, retrying on
/// failure.
async fn fetch_config(client: &EthBeaconNodeApiClient) -> Result<(DateTime<Utc>, Duration, u64)> {
    let genesis_time = (|| client.fetch_genesis_time())
        .retry(pluto_core::expbackoff::fast())
        .notify(|err, _| tracing::error!(err = ?err, "Failure fetching genesis time"))
        .await?;

    let (slot_duration, slots_per_epoch) = (|| client.fetch_slots_config())
        .retry(pluto_core::expbackoff::fast())
        .notify(|err, _| tracing::error!(err = ?err, "Failure fetching slots config"))
        .await?;

    Ok((genesis_time, slot_duration, slots_per_epoch))
}

/// Outcome of a single SSE stream connection.
enum StreamOutcome {
    /// The stream ended cleanly (server closed the connection). `productive`
    /// is true if at least one event was forwarded before the close.
    Ended { productive: bool },
    /// A connection or read error occurred; the caller should back off.
    /// `productive` is true if at least one event was forwarded before the
    /// error.
    Error { productive: bool },
    /// The actor's event channel was closed; the pump should stop.
    ChannelClosed,
    /// The cancellation token fired.
    Cancelled,
}

/// Connects to the beacon node SSE stream and reconnects with exponential
/// backoff until the cancellation token fires or the actor goes away.
async fn run_pump(
    client: EthBeaconNodeApiClient,
    addr: String,
    events_tx: sync::mpsc::Sender<SseEvent>,
    ct: CancellationToken,
) {
    let mut backoff = reconnect_backoff().build();

    loop {
        match stream_once(&client, &addr, &events_tx, &ct).await {
            StreamOutcome::Cancelled | StreamOutcome::ChannelClosed => break,
            StreamOutcome::Ended { productive } | StreamOutcome::Error { productive } => {
                // Reset the backoff only after a productive connection (one that
                // forwarded at least one event). Otherwise a server that accepts
                // and immediately closes the connection — or fails to connect —
                // would drive a tight reconnect loop with no rate limiting.
                if productive {
                    backoff = reconnect_backoff().build();
                }
                let delay = backoff
                    .next()
                    .expect("reconnect backoff is configured without a retry limit");
                tokio::select! {
                    biased;
                    _ = ct.cancelled() => break,
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }

    tracing::debug!(addr = %addr, "SSE pump stopped");
}

/// Opens a single SSE connection and forwards events into `events_tx` until the
/// stream ends, errors, the channel closes, or the token is cancelled.
async fn stream_once(
    client: &EthBeaconNodeApiClient,
    addr: &str,
    events_tx: &sync::mpsc::Sender<SseEvent>,
    ct: &CancellationToken,
) -> StreamOutcome {
    tracing::debug!(addr = %addr, "Connecting to SSE stream");

    let stream = match client.event_stream(&TOPICS).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!(err = %err, addr = %addr, "Failed to connect to SSE stream");
            return StreamOutcome::Error { productive: false };
        }
    };
    futures::pin_mut!(stream);

    let mut productive = false;
    loop {
        tokio::select! {
            biased;

            _ = ct.cancelled() => return StreamOutcome::Cancelled,

            item = stream.next() => match item {
                None => return StreamOutcome::Ended { productive },
                Some(Err(err)) => {
                    tracing::warn!(err = %err, addr = %addr, "SSE stream read error");
                    return StreamOutcome::Error { productive };
                }
                Some(Ok(BeaconNodeEvent { topic, data })) => {
                    if data.is_empty() {
                        continue;
                    }

                    let event = SseEvent { topic, data, timestamp: Utc::now() };
                    if events_tx.send(event).await.is_err() {
                        return StreamOutcome::ChannelClosed;
                    }
                    productive = true;
                }
            },
        }
    }
}

/// Backoff used between SSE reconnection attempts.
fn reconnect_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(DEFAULT_RETRY)
        .with_max_delay(DEFAULT_RETRY.checked_mul(2).expect("within range"))
        .with_factor(1.6)
        .without_max_times()
        .with_jitter()
}

/// Returns the delay in fractional seconds for metrics and logging.
///
/// Histogram values are non-negative seconds; a negative delay (an event
/// observed before the slot start, e.g. due to clock skew) is clamped to zero.
fn delay_secs(delay: chrono::Duration) -> f64 {
    delay
        .to_std()
        .map(|delay| delay.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT_DURATION: Duration = Duration::from_secs(12);
    const SLOTS_PER_EPOCH: u64 = 32;

    /// Ethereum mainnet genesis time.
    fn genesis() -> DateTime<Utc> {
        DateTime::from_timestamp(1_606_824_023, 0).expect("valid timestamp")
    }

    fn test_actor(reorg_subs: Vec<sync::mpsc::Sender<u64>>) -> SseListenerActor {
        SseListenerActor {
            addr: "test".to_string(),
            genesis_time: genesis(),
            slot_duration: SLOT_DURATION,
            slots_per_epoch: SLOTS_PER_EPOCH,
            last_reorg_epoch: 0,
            reorg_subs,
        }
    }

    fn event(topic: &str, data: &str, timestamp: DateTime<Utc>) -> SseEvent {
        SseEvent {
            topic: topic.to_string(),
            data: data.to_string(),
            timestamp,
        }
    }

    /// Returns the wall-clock time `offset_secs` into the given slot.
    fn slot_time(slot: u64, offset_secs: i64) -> DateTime<Utc> {
        let slot = i64::try_from(slot).unwrap();
        let per_slot = i64::try_from(SLOT_DURATION.as_secs()).unwrap();
        let secs = slot
            .checked_mul(per_slot)
            .unwrap()
            .checked_add(offset_secs)
            .unwrap();
        genesis()
            .checked_add_signed(chrono::Duration::seconds(secs))
            .unwrap()
    }

    #[test]
    fn compute_delay_inside_and_outside_window() {
        let actor = test_actor(vec![]);
        let slot = 10;
        let window = chrono::Duration::from_std(SLOT_DURATION).unwrap();

        let (delay, ok) = actor.compute_delay(slot, slot_time(slot, 5), |d| d < window);
        assert_eq!(delay, chrono::Duration::seconds(5));
        assert!(ok);

        let (delay, ok) = actor.compute_delay(slot, slot_time(slot, 13), |d| d < window);
        assert_eq!(delay, chrono::Duration::seconds(13));
        assert!(!ok);
    }

    #[test]
    fn chain_reorg_notifies_and_dedups() {
        let (tx, mut rx) = sync::mpsc::channel(8);
        let mut actor = test_actor(vec![tx]);

        // slot 64, depth 0 => reorg_epoch = 64 / 32 = 2.
        let data = r#"{"slot":"64","depth":"0","epoch":"2","old_head_block":"0xaa","new_head_block":"0xbb"}"#;
        actor.handle_event(&event(CHAIN_REORG_EVENT, data, genesis()));
        assert_eq!(rx.try_recv().unwrap(), 2);

        // Same epoch again => deduplicated, no notification.
        actor.handle_event(&event(CHAIN_REORG_EVENT, data, genesis()));
        assert!(rx.try_recv().is_err());

        // New epoch => notified.
        let data = r#"{"slot":"96","depth":"0","epoch":"3"}"#;
        actor.handle_event(&event(CHAIN_REORG_EVENT, data, genesis()));
        assert_eq!(rx.try_recv().unwrap(), 3);
    }

    #[test]
    fn chain_reorg_epoch_zero_first_event_is_deduped() {
        // Parity with Charon: `last_reorg_epoch` starts at 0, so a first reorg at
        // epoch 0 is treated as a duplicate and not notified.
        let (tx, mut rx) = sync::mpsc::channel(8);
        let mut actor = test_actor(vec![tx]);

        let data = r#"{"slot":"0","depth":"0","epoch":"0"}"#;
        actor.handle_event(&event(CHAIN_REORG_EVENT, data, genesis()));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn chain_reorg_depth_exceeding_slot_is_ignored() {
        let (tx, mut rx) = sync::mpsc::channel(8);
        let mut actor = test_actor(vec![tx]);

        let data = r#"{"slot":"5","depth":"10","epoch":"0"}"#;
        actor.handle_event(&event(CHAIN_REORG_EVENT, data, genesis()));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn malformed_payload_is_skipped_and_processing_continues() {
        let (tx, mut rx) = sync::mpsc::channel(8);
        let mut actor = test_actor(vec![tx]);

        // Malformed JSON is logged and skipped, not propagated as a failure.
        actor.handle_event(&event(CHAIN_REORG_EVENT, "{not json", genesis()));
        assert!(rx.try_recv().is_err());

        // A subsequent valid event is still processed.
        let data = r#"{"slot":"64","depth":"0","epoch":"2"}"#;
        actor.handle_event(&event(CHAIN_REORG_EVENT, data, genesis()));
        assert_eq!(rx.try_recv().unwrap(), 2);
    }

    #[test]
    fn handles_all_event_types_without_panicking() {
        let (tx, mut rx) = sync::mpsc::channel(8);
        let mut actor = test_actor(vec![tx]);
        let ts = slot_time(64, 5);

        actor.handle_event(&event(
            HEAD_EVENT,
            r#"{"slot":"64","block":"0xabc","previous_duty_dependent_root":"0x01","current_duty_dependent_root":"0x02"}"#,
            ts,
        ));
        actor.handle_event(&event(
            BLOCK_GOSSIP_EVENT,
            r#"{"slot":"64","block":"0xabc"}"#,
            ts,
        ));
        actor.handle_event(&event(BLOCK_EVENT, r#"{"slot":"64","block":"0xabc"}"#, ts));
        actor.handle_event(&event("unknown_topic", "{}", ts));

        // None of the above are chain reorgs, so nothing is notified.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn run_loop_forwards_events_and_stops_on_cancellation() {
        let ct = CancellationToken::new();
        let (events_tx, events_rx) = sync::mpsc::channel(8);
        let (_msg_tx, msg_rx) = sync::mpsc::channel(8);
        let (reorg_tx, mut reorg_rx) = sync::mpsc::channel(8);

        let actor = test_actor(vec![reorg_tx]);
        let handle = tokio::spawn(actor.run(events_rx, msg_rx, ct.clone()));

        let data = r#"{"slot":"64","depth":"0","epoch":"2"}"#;
        events_tx
            .send(event(CHAIN_REORG_EVENT, data, genesis()))
            .await
            .unwrap();

        assert_eq!(reorg_rx.recv().await.unwrap(), 2);

        ct.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn dynamic_subscription_via_handle() {
        let ct = CancellationToken::new();
        let (events_tx, events_rx) = sync::mpsc::channel(8);
        let (msg_tx, msg_rx) = sync::mpsc::channel(8);

        let actor = test_actor(vec![]);
        tokio::spawn(actor.run(events_rx, msg_rx, ct.clone()));

        let handle = SseListenerHandle { sender: msg_tx };
        let mut reorg_rx = handle.subscribe_chain_reorg().await.unwrap();

        let data = r#"{"slot":"64","depth":"0","epoch":"2"}"#;
        events_tx
            .send(event(CHAIN_REORG_EVENT, data, genesis()))
            .await
            .unwrap();

        assert_eq!(reorg_rx.recv().await.unwrap(), 2);

        ct.cancel();
    }

    const HEAD_EVENT_BODY: &str = "event: head\ndata: {\"slot\":\"10\"}\n\n";

    /// Starts a mock beacon node serving the given SSE body (and status) at
    /// `/eth/v1/events` and returns a client pointed at it. The returned
    /// `MockServer` must be kept alive for the duration of the test.
    async fn mock_sse(status: u16, body: &str) -> (wiremock::MockServer, EthBeaconNodeApiClient) {
        use wiremock::{
            Mock, ResponseTemplate,
            matchers::{method, path},
        };

        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/events"))
            .respond_with(
                ResponseTemplate::new(status).set_body_raw(body.to_owned(), "text/event-stream"),
            )
            .mount(&server)
            .await;

        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid url");
        (server, client)
    }

    #[tokio::test]
    async fn run_loop_stops_when_event_channel_closes() {
        // The pump dropping its sender must stop the actor, not leave it parked
        // forever with no events and no reconnection (the token is never fired).
        let ct = CancellationToken::new();
        let (events_tx, events_rx) = sync::mpsc::channel(8);
        let (_msg_tx, msg_rx) = sync::mpsc::channel(8);

        let actor = test_actor(vec![]);
        let handle = tokio::spawn(actor.run(events_rx, msg_rx, ct.clone()));

        drop(events_tx);

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("actor did not stop after the event channel closed")
            .expect("actor task panicked");
        assert!(
            !ct.is_cancelled(),
            "actor stopped on its own, without cancellation"
        );
    }

    #[tokio::test]
    async fn stream_once_forwards_event_and_reports_productive() {
        let (_server, client) = mock_sse(200, HEAD_EVENT_BODY).await;
        let (events_tx, mut events_rx) = sync::mpsc::channel(8);
        let ct = CancellationToken::new();

        let outcome = stream_once(&client, "test", &events_tx, &ct).await;

        assert!(matches!(outcome, StreamOutcome::Ended { productive: true }));
        let event = events_rx.try_recv().expect("event forwarded");
        assert_eq!(event.topic, HEAD_EVENT);
    }

    #[tokio::test]
    async fn stream_once_reports_unproductive_on_immediate_eof() {
        // A connection that accepts and immediately closes with no events must
        // report `productive: false` so the pump backs off instead of looping.
        let (_server, client) = mock_sse(200, "").await;
        let (events_tx, _events_rx) = sync::mpsc::channel(8);
        let ct = CancellationToken::new();

        let outcome = stream_once(&client, "test", &events_tx, &ct).await;

        assert!(matches!(
            outcome,
            StreamOutcome::Ended { productive: false }
        ));
    }

    #[tokio::test]
    async fn stream_once_reports_error_on_non_success_status() {
        let (_server, client) = mock_sse(500, "").await;
        let (events_tx, _events_rx) = sync::mpsc::channel(8);
        let ct = CancellationToken::new();

        let outcome = stream_once(&client, "test", &events_tx, &ct).await;

        assert!(matches!(
            outcome,
            StreamOutcome::Error { productive: false }
        ));
    }

    #[tokio::test]
    async fn stream_once_returns_cancelled_when_token_fires() {
        let (_server, client) = mock_sse(200, HEAD_EVENT_BODY).await;
        let (events_tx, _events_rx) = sync::mpsc::channel(8);
        let ct = CancellationToken::new();
        ct.cancel();

        let outcome = stream_once(&client, "test", &events_tx, &ct).await;

        assert!(matches!(outcome, StreamOutcome::Cancelled));
    }

    #[tokio::test]
    async fn stream_once_returns_channel_closed_when_receiver_dropped() {
        let (_server, client) = mock_sse(200, HEAD_EVENT_BODY).await;
        let (events_tx, events_rx) = sync::mpsc::channel(8);
        drop(events_rx);
        let ct = CancellationToken::new();

        let outcome = stream_once(&client, "test", &events_tx, &ct).await;

        assert!(matches!(outcome, StreamOutcome::ChannelClosed));
    }

    #[tokio::test]
    async fn run_pump_forwards_events_and_stops_on_cancellation() {
        let (_server, client) = mock_sse(200, HEAD_EVENT_BODY).await;
        let (events_tx, mut events_rx) = sync::mpsc::channel(8);
        let ct = CancellationToken::new();

        let pump = tokio::spawn(run_pump(client, "test".to_string(), events_tx, ct.clone()));

        let event = events_rx.recv().await.expect("event forwarded");
        assert_eq!(event.topic, HEAD_EVENT);

        ct.cancel();
        tokio::time::timeout(Duration::from_secs(5), pump)
            .await
            .expect("pump did not stop after cancellation")
            .expect("pump task panicked");
    }
}
