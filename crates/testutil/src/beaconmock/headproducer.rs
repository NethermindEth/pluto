//! Slot-driven head producer for the beacon mock.
//!
//! Mirrors Charon's `headProducer` (Go) — see
//! `charon/testutil/beaconmock/headproducer.go` — by ticking on every slot,
//! generating deterministic block/state roots, and exposing the resulting
//! head over `/eth/v1/events` (SSE) and
//! `/eth/v1/beacon/blocks/{block_id}/root`.
//!
//! Note on SSE: wiremock buffers a response body before sending, so events
//! cannot be streamed continuously. Each request to `/eth/v1/events` waits up
//! to ~one slot for the producer to have a current head and then returns a
//! single, well-formed SSE record (`event: <topic>\ndata: <json>\n\n`).
//! Subscribers should poll the endpoint to keep receiving events.
//!
//! The block-root endpoint matches Charon: it answers with the current head's
//! block root when `block_id` is `head` or matches the current head's slot,
//! and 400 otherwise.
//!
//! The ticker is shut down when the returned [`HeadProducer`] is dropped.

use std::{
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};
use pluto_eth2api::spec::phase0::{Root, Slot};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use tokio::sync::{Notify, watch};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path, path_regex},
};

use super::defaults::DEFAULT_MOCK_PRIORITY;

const TOPIC_HEAD: &str = "head";
const TOPIC_BLOCK: &str = "block";

/// Deterministic head event derived from a slot.
#[derive(Clone, Debug)]
struct HeadEvent {
    slot: Slot,
    block: Root,
    state: Root,
    current_duty_dependent_root: Root,
    previous_duty_dependent_root: Root,
}

/// Owns the slot ticker driving the head producer. Drop to stop the ticker.
#[derive(Debug)]
pub(crate) struct HeadProducer {
    shutdown: Arc<Notify>,
}

impl HeadProducer {
    /// Spawns the slot ticker and mounts SSE/block-root handlers on `server`.
    pub(crate) async fn spawn(
        server: &MockServer,
        genesis_time: DateTime<Utc>,
        slot_duration: Duration,
    ) -> Self {
        let state = Arc::new(SharedState::new());
        let shutdown = Arc::new(Notify::new());

        mount_events(server, Arc::clone(&state), slot_duration).await;
        mount_block_root(server, Arc::clone(&state)).await;

        spawn_slot_ticker(
            Arc::clone(&state),
            Arc::clone(&shutdown),
            genesis_time,
            slot_duration,
        );

        Self { shutdown }
    }
}

impl Drop for HeadProducer {
    fn drop(&mut self) {
        self.shutdown.notify_waiters();
    }
}

struct SharedState {
    current_head: RwLock<Option<HeadEvent>>,
    head_tx: watch::Sender<u64>,
    head_rx: watch::Receiver<u64>,
}

impl SharedState {
    fn new() -> Self {
        let (head_tx, head_rx) = watch::channel(0u64);
        Self {
            current_head: RwLock::new(None),
            head_tx,
            head_rx,
        }
    }

    fn set_current_head(&self, event: HeadEvent) {
        match self.current_head.write() {
            Ok(mut guard) => *guard = Some(event),
            Err(poisoned) => *poisoned.into_inner() = Some(event),
        }
        // Bump the generation counter so listeners wake up.
        let next = self.head_tx.borrow().wrapping_add(1);
        let _ = self.head_tx.send(next);
    }

    fn current_head(&self) -> Option<HeadEvent> {
        match self.current_head.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn subscribe(&self) -> watch::Receiver<u64> {
        self.head_rx.clone()
    }
}

fn spawn_slot_ticker(
    state: Arc<SharedState>,
    shutdown: Arc<Notify>,
    genesis_time: DateTime<Utc>,
    slot_duration: Duration,
) {
    // Mirror Go's startSlotTicker: compute current slot from chain age, then
    // tick once per slot until shutdown.
    let genesis = system_time_from(genesis_time);
    let slot_duration = if slot_duration.is_zero() {
        Duration::from_millis(1)
    } else {
        slot_duration
    };

    tokio::spawn(async move {
        let (mut height, mut next_tick) = initial_slot(genesis, slot_duration);
        let shutdown_fut = shutdown.notified();
        tokio::pin!(shutdown_fut);

        loop {
            update_head(&state, height);

            height = height.wrapping_add(1);
            next_tick = next_tick.checked_add(slot_duration).unwrap_or_else(|| {
                SystemTime::now()
                    .checked_add(slot_duration)
                    .unwrap_or(SystemTime::now())
            });
            let delay = next_tick
                .duration_since(SystemTime::now())
                .unwrap_or_default();

            tokio::select! {
                _ = &mut shutdown_fut => return,
                _ = tokio::time::sleep(delay) => {}
            }
        }
    });
}

fn initial_slot(genesis: SystemTime, slot_duration: Duration) -> (Slot, SystemTime) {
    let now = SystemTime::now();
    let chain_age = now.duration_since(genesis).unwrap_or_default();
    let nanos = u64::try_from(slot_duration.as_nanos())
        .unwrap_or(u64::MAX)
        .max(1);
    let height = u64::try_from(chain_age.as_nanos())
        .unwrap_or(0)
        .checked_div(nanos)
        .unwrap_or(0);
    let multiplier = u32::try_from(height).unwrap_or(u32::MAX);
    let start = genesis
        .checked_add(slot_duration.saturating_mul(multiplier))
        .unwrap_or(now);
    (height, start)
}

fn system_time_from(dt: DateTime<Utc>) -> SystemTime {
    let secs = dt.timestamp();
    if secs >= 0 {
        let secs_u64 = u64::try_from(secs).unwrap_or(0);
        UNIX_EPOCH
            .checked_add(Duration::from_secs(secs_u64))
            .unwrap_or(UNIX_EPOCH)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(secs.unsigned_abs()))
            .unwrap_or(UNIX_EPOCH)
    }
}

fn update_head(state: &SharedState, slot: Slot) {
    state.set_current_head(pseudo_random_head_event(slot));
}

fn pseudo_random_head_event(slot: Slot) -> HeadEvent {
    let mut rng = StdRng::seed_from_u64(slot);
    HeadEvent {
        slot,
        block: random_root(&mut rng),
        state: random_root(&mut rng),
        current_duty_dependent_root: random_root(&mut rng),
        previous_duty_dependent_root: random_root(&mut rng),
    }
}

fn random_root(rng: &mut StdRng) -> Root {
    let mut root = Root::default();
    rng.fill_bytes(&mut root);
    root
}

async fn mount_events(server: &MockServer, state: Arc<SharedState>, slot_duration: Duration) {
    let wait_budget = slot_duration
        .saturating_mul(2)
        .max(Duration::from_millis(50));

    Mock::given(method("GET"))
        .and(path("/eth/v1/events"))
        .respond_with(move |request: &Request| {
            let topics = parse_topics(request);
            if let Some(invalid) = topics.iter().find(|topic| !is_supported_topic(topic)) {
                return error_response(500, format!("unknown topic: {invalid}"));
            }

            // Wait synchronously (bounded) until at least one head is produced
            // so the buffered SSE body is non-empty.
            wait_for_first_head(&state, wait_budget);
            let Some(head) = state.current_head() else {
                return error_response(500, "head producer not ready".into());
            };

            let mut body = String::new();
            if topics.is_empty() || topics.iter().any(|t| t == TOPIC_HEAD) {
                push_sse_event(&mut body, TOPIC_HEAD, &head_event_json(&head));
            }
            if topics.iter().any(|t| t == TOPIC_BLOCK) {
                push_sse_event(&mut body, TOPIC_BLOCK, &block_event_json(&head));
            }

            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .insert_header("cache-control", "no-cache")
                .set_body_raw(body.into_bytes(), "text/event-stream")
        })
        .with_priority(DEFAULT_MOCK_PRIORITY - 1)
        .mount(server)
        .await;
}

async fn mount_block_root(server: &MockServer, state: Arc<SharedState>) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/eth/v1/beacon/blocks/[^/]+/root$"))
        .respond_with(move |request: &Request| {
            let Some(head) = state.current_head() else {
                return error_response(500, "head producer not ready".into());
            };

            let block_id = extract_block_id(request.url.path());
            if block_id != "head" && block_id != head.slot.to_string() {
                return error_response(400, format!("Invalid block ID: {block_id}"));
            }

            ResponseTemplate::new(200).set_body_json(json!({
                "execution_optimistic": false,
                "data": { "root": hex_0x(head.block) }
            }))
        })
        .with_priority(DEFAULT_MOCK_PRIORITY - 1)
        .mount(server)
        .await;
}

fn parse_topics(request: &Request) -> Vec<String> {
    request
        .url
        .query_pairs()
        .filter_map(|(k, v)| (k == "topics").then(|| v.into_owned()))
        .collect()
}

fn is_supported_topic(topic: &str) -> bool {
    topic == TOPIC_HEAD || topic == TOPIC_BLOCK
}

fn extract_block_id(path: &str) -> String {
    // Path matched by the regex above: ".../blocks/{block_id}/root".
    let mut parts = path.rsplit('/');
    let _ = parts.next(); // "root"
    parts.next().unwrap_or_default().to_string()
}

fn wait_for_first_head(state: &SharedState, budget: Duration) {
    if state.current_head().is_some() {
        return;
    }

    // Drive a short blocking wait without blocking the runtime worker for long:
    // poll the shared state with small sleeps until the budget elapses.
    let start = std::time::Instant::now();
    let mut rx = state.subscribe();
    while start.elapsed() < budget {
        if rx.has_changed().unwrap_or(false) {
            let _ = rx.borrow_and_update();
        }
        if state.current_head().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn push_sse_event(body: &mut String, topic: &str, data: &Value) {
    body.push_str("event: ");
    body.push_str(topic);
    body.push('\n');
    body.push_str("data: ");
    body.push_str(&data.to_string());
    body.push_str("\n\n");
}

fn head_event_json(head: &HeadEvent) -> Value {
    json!({
        "slot": head.slot.to_string(),
        "block": hex_0x(head.block),
        "state": hex_0x(head.state),
        "epoch_transition": false,
        "current_duty_dependent_root": hex_0x(head.current_duty_dependent_root),
        "previous_duty_dependent_root": hex_0x(head.previous_duty_dependent_root),
        "execution_optimistic": false,
    })
}

fn block_event_json(head: &HeadEvent) -> Value {
    json!({
        "slot": head.slot.to_string(),
        "block": hex_0x(head.block),
        "execution_optimistic": false,
    })
}

fn hex_0x(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes.as_ref()))
}

fn error_response(status: u16, message: String) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(json!({
        "code": status,
        "message": message,
    }))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use chrono::Utc;

    use crate::beaconmock::BeaconMock;

    #[tokio::test]
    async fn publishes_head_event_via_sse() {
        let mock = BeaconMock::builder()
            .slot_duration(Duration::from_millis(100))
            .genesis_time(Utc::now())
            .build()
            .await
            .expect("beacon mock");

        let url = format!("{}/eth/v1/events?topics=head", mock.uri());
        let client = reqwest::Client::new();

        // Poll the endpoint with a short timeout — the responder buffers a
        // single SSE event per request, so the test reads the body once a
        // head event has been produced.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let body = loop {
            assert!(
                std::time::Instant::now() < deadline,
                "no head event in time"
            );
            let resp = client
                .get(&url)
                .timeout(Duration::from_secs(1))
                .send()
                .await
                .expect("send");
            assert_eq!(resp.status().as_u16(), 200);
            let text = resp.text().await.expect("body");
            if text.contains("event: head") {
                break text;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };

        assert!(body.contains("event: head"));
        assert!(body.contains("\"slot\""));
        assert!(body.contains("\"block\""));
    }

    #[tokio::test]
    async fn rejects_unknown_topic() {
        let mock = BeaconMock::builder()
            .slot_duration(Duration::from_millis(100))
            .genesis_time(Utc::now())
            .build()
            .await
            .expect("beacon mock");

        let url = format!("{}/eth/v1/events?topics=bogus", mock.uri());
        let resp = reqwest::get(&url).await.expect("send");
        assert_eq!(resp.status().as_u16(), 500);
        let text = resp.text().await.expect("body");
        assert!(text.contains("unknown topic"));
    }

    #[tokio::test]
    async fn block_root_for_head() {
        let mock = BeaconMock::builder()
            .slot_duration(Duration::from_millis(100))
            .genesis_time(Utc::now())
            .build()
            .await
            .expect("beacon mock");

        // Wait for the ticker to publish at least one head.
        tokio::time::sleep(Duration::from_millis(150)).await;

        let url = format!("{}/eth/v1/beacon/blocks/head/root", mock.uri());
        let resp = reqwest::get(&url).await.expect("send");
        assert_eq!(resp.status().as_u16(), 200);
        let body: serde_json::Value = resp.json().await.expect("json");
        let root = body["data"]["root"].as_str().expect("root");
        assert!(root.starts_with("0x") && root.len() == 2 + 64);
    }

    #[tokio::test]
    async fn block_root_rejects_stale_id() {
        let mock = BeaconMock::builder()
            .slot_duration(Duration::from_millis(100))
            .genesis_time(Utc::now())
            .build()
            .await
            .expect("beacon mock");

        tokio::time::sleep(Duration::from_millis(150)).await;

        let url = format!("{}/eth/v1/beacon/blocks/999999/root", mock.uri());
        let resp = reqwest::get(&url).await.expect("send");
        assert_eq!(resp.status().as_u16(), 400);
    }
}
