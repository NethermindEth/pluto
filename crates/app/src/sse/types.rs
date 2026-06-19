//! Event payloads and topics for the beacon node SSE stream.
//!
//! Only the fields consumed by the listener (for metrics, reorg detection, and
//! debug logging) are modelled; serde ignores any other fields the beacon node
//! sends. `#[serde(default)]` keeps deserialization lenient when a field is
//! absent. Numeric fields are sent by the beacon node as quoted strings and are
//! parsed directly into integers via [`serde_with::DisplayFromStr`].

use chrono::{DateTime, Utc};
use serde_with::{DisplayFromStr, serde_as};

/// SSE topic for `head` events.
pub const HEAD_EVENT: &str = "head";
/// SSE topic for `chain_reorg` events.
pub const CHAIN_REORG_EVENT: &str = "chain_reorg";
/// SSE topic for `block_gossip` events.
pub const BLOCK_GOSSIP_EVENT: &str = "block_gossip";
/// SSE topic for `block` events.
pub const BLOCK_EVENT: &str = "block";

/// A raw SSE event handed from the stream source to the listener actor.
///
/// `timestamp` is captured when the event is received (production) or set
/// explicitly (tests), and is used to compute the per-event delay.
#[derive(Debug, Clone)]
pub struct SseEvent {
    /// The event topic (the SSE `event:` field).
    pub topic: String,
    /// The raw, unparsed JSON `data` payload.
    pub data: String,
    /// The time the event was received.
    pub timestamp: DateTime<Utc>,
}

/// Payload of a `head` event.
#[serde_as]
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct HeadEventData {
    /// The slot of the new head.
    #[serde_as(as = "DisplayFromStr")]
    pub slot: u64,
    /// The block root of the new head.
    pub block: String,
    /// The previous duty dependent root.
    pub previous_duty_dependent_root: String,
    /// The current duty dependent root.
    pub current_duty_dependent_root: String,
}

/// Payload of a `chain_reorg` event.
#[serde_as]
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct ChainReorgEventData {
    /// The slot at which the reorg occurred.
    #[serde_as(as = "DisplayFromStr")]
    pub slot: u64,
    /// The depth of the reorg in slots.
    #[serde_as(as = "DisplayFromStr")]
    pub depth: u64,
    /// The epoch at which the reorg occurred.
    #[serde_as(as = "DisplayFromStr")]
    pub epoch: u64,
    /// The block root of the old head.
    pub old_head_block: String,
    /// The block root of the new head.
    pub new_head_block: String,
}

/// Payload of a `block_gossip` event.
#[serde_as]
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct BlockGossipEventData {
    /// The slot of the gossiped block.
    #[serde_as(as = "DisplayFromStr")]
    pub slot: u64,
    /// The block root.
    pub block: String,
}

/// Payload of a `block` event.
#[serde_as]
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct BlockEventData {
    /// The slot of the imported block.
    #[serde_as(as = "DisplayFromStr")]
    pub slot: u64,
    /// The block root.
    pub block: String,
}
