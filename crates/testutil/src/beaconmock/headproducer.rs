//! Slot-driven head producer for the beacon mock.
//!
//! Mirrors Charon's `headProducer` (Go) — see
//! `charon/testutil/beaconmock/headproducer.go` — by ticking on every slot,
//! generating deterministic block/state roots, and exposing the resulting
//! head over `/eth/v1/events` (SSE) and
//! `/eth/v1/beacon/blocks/{block_id}/root`.
//!
//! Note on SSE: wiremock buffers a response body before sending, so events
//! cannot be streamed continuously. Each request to `/eth/v1/events` returns
//! a single, well-formed SSE record (`event: <topic>\ndata: <json>\n\n`) for
//! the current head. Subscribers should poll the endpoint to keep receiving
//! events.
//!
//! The block-root endpoint matches Charon: it answers with the current head's
//! block root when `block_id` is `head` or matches the current head's slot,
//! and 400 otherwise.
//!
//! [`HeadProducer::spawn`] synchronously publishes the initial head before
//! returning, so handlers never observe a `None` current head once the
//! producer is constructed. The ticker is shut down when the returned
//! [`HeadProducer`] is dropped.

use std::{
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};
use pluto_eth2api::spec::phase0::{Root, Slot};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path, path_regex},
};

use super::{defaults::DEFAULT_MOCK_PRIORITY, state::hex_0x};

const TOPIC_HEAD: &str = "head";
const TOPIC_BLOCK: &str = "block";

/// Deterministic head event derived from a slot.
///
/// Charon's Go reference has a typo in `headproducer.go` that renders
/// `PreviousDutyDependentRoot` from `currentHead.CurrentDutyDependentRoot`,
/// so only one dependent root is meaningful. We mirror that and keep a single
/// `duty_dependent_root` field rather than carrying two identical values.
#[derive(Clone, Debug)]
struct HeadEvent {
    slot: Slot,
    block: Root,
    state: Root,
    duty_dependent_root: Root,
}

/// Owns the slot ticker driving the head producer. Drop to stop the ticker.
#[derive(Debug)]
pub(crate) struct HeadProducer {
    cancel: CancellationToken,
}

impl HeadProducer {
    /// Spawns the slot ticker and mounts SSE/block-root handlers on `server`.
    ///
    /// The initial head is published synchronously before returning, so the
    /// mounted handlers can always observe a non-`None` current head.
    pub(crate) async fn spawn(
        server: &MockServer,
        genesis_time: DateTime<Utc>,
        slot_duration: Duration,
    ) -> Self {
        let state = Arc::new(SharedState::new());
        let cancel = CancellationToken::new();

        mount_events(server, Arc::clone(&state)).await;
        mount_block_root(server, Arc::clone(&state)).await;

        let genesis = system_time_from(genesis_time);
        let slot_duration = normalize_slot_duration(slot_duration);
        let (initial_height, initial_tick) = initial_slot(genesis, slot_duration);

        // Publish the initial head before handing control back to the caller
        // so the mounted handlers never see a None current head.
        update_head(&state, initial_height);

        spawn_slot_ticker(
            Arc::clone(&state),
            cancel.clone(),
            initial_height,
            initial_tick,
            slot_duration,
        );

        Self { cancel }
    }
}

impl Drop for HeadProducer {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct SharedState {
    current_head: RwLock<Option<HeadEvent>>,
}

impl SharedState {
    fn new() -> Self {
        Self {
            current_head: RwLock::new(None),
        }
    }

    fn set_current_head(&self, event: HeadEvent) {
        match self.current_head.write() {
            Ok(mut guard) => *guard = Some(event),
            Err(poisoned) => *poisoned.into_inner() = Some(event),
        }
    }

    fn current_head(&self) -> Option<HeadEvent> {
        match self.current_head.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

fn spawn_slot_ticker(
    state: Arc<SharedState>,
    cancel: CancellationToken,
    initial_height: Slot,
    initial_tick: SystemTime,
    slot_duration: Duration,
) {
    // The initial head was already published by `HeadProducer::spawn`. Start
    // the ticker at the next scheduled slot so it advances from there.
    let mut height = initial_height.wrapping_add(1);
    let mut next_tick = initial_tick.checked_add(slot_duration).unwrap_or_else(|| {
        SystemTime::now()
            .checked_add(slot_duration)
            .unwrap_or(SystemTime::now())
    });

    tokio::spawn(async move {
        loop {
            let delay = next_tick
                .duration_since(SystemTime::now())
                .unwrap_or_default();

            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(delay) => {}
            }

            update_head(&state, height);

            height = height.wrapping_add(1);
            next_tick = next_tick.checked_add(slot_duration).unwrap_or_else(|| {
                SystemTime::now()
                    .checked_add(slot_duration)
                    .unwrap_or(SystemTime::now())
            });
        }
    });
}

fn normalize_slot_duration(slot_duration: Duration) -> Duration {
    if slot_duration.is_zero() {
        Duration::from_millis(1)
    } else {
        slot_duration
    }
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

// Charon's `pseudoRandomHeadEvent` seeds Go's `math/rand` LCG with the slot
// number and draws four roots. We deliberately use ChaCha-based `StdRng`
// instead — the byte sequences differ from Charon, but Pluto does not assert
// on any specific head/state/dependent root value and ChaCha is portable and
// well-tested. The head event JSON shape and seeding-per-slot determinism are
// preserved.
fn pseudo_random_head_event(slot: Slot) -> HeadEvent {
    let mut rng = StdRng::seed_from_u64(slot);
    HeadEvent {
        slot,
        block: random_root(&mut rng),
        state: random_root(&mut rng),
        duty_dependent_root: random_root(&mut rng),
    }
}

fn random_root(rng: &mut StdRng) -> Root {
    let mut root = Root::default();
    rng.fill_bytes(&mut root);
    root
}

async fn mount_events(server: &MockServer, state: Arc<SharedState>) {
    Mock::given(method("GET"))
        .and(path("/eth/v1/events"))
        .respond_with(move |request: &Request| {
            let topics = parse_topics(request);
            if let Some(invalid) = topics.iter().find(|topic| !is_supported_topic(topic)) {
                return error_response(500, format!("unknown topic: {invalid}"));
            }

            // `HeadProducer::spawn` publishes the initial head before
            // returning, so the current head is always set here.
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
            // `HeadProducer::spawn` publishes the initial head before
            // returning, so the current head is always set here.
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
        // Charon renders the same value for both fields; see HeadEvent docs.
        "current_duty_dependent_root": hex_0x(head.duty_dependent_root),
        "previous_duty_dependent_root": hex_0x(head.duty_dependent_root),
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
        let resp = reqwest::get(&url).await.expect("send");
        assert_eq!(resp.status().as_u16(), 200);

        let body = resp.text().await.expect("body");
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

        let url = format!("{}/eth/v1/beacon/blocks/999999/root", mock.uri());
        let resp = reqwest::get(&url).await.expect("send");
        assert_eq!(resp.status().as_u16(), 400);
    }
}
