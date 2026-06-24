//! Prometheus metrics for the beacon node SSE listener.
//!
//! The `app_beacon_node` prefix and bucket boundaries reproduce Charon's
//! `app/beacon_node` SSE metrics. All metrics are labelled by beacon node
//! address.

use vise::{Gauge, Global, Histogram, LabeledFamily, Metrics};

/// Head delay buckets in seconds.
const HEAD_DELAY_BUCKETS: [f64; 6] = [2.0, 4.0, 6.0, 8.0, 10.0, 12.0];
/// Chain reorg depth buckets in slots.
const REORG_DEPTH_BUCKETS: [f64; 6] = [1.0, 2.0, 4.0, 6.0, 8.0, 16.0];
/// Block reception delay buckets in seconds.
const BLOCK_BUCKETS: [f64; 14] = [
    0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0, 6.0, 8.0, 10.0, 12.0,
];

/// Metrics for the beacon node SSE listener.
#[derive(Debug, Metrics)]
#[metrics(prefix = "app_beacon_node")]
pub struct SseMetrics {
    /// Current beacon node head slot, supplied by the SSE endpoint.
    #[metrics(labels = ["addr"])]
    pub sse_head_slot: LabeledFamily<String, Gauge<u64>>,

    /// Delay in seconds between slot start and head update.
    #[metrics(buckets = &HEAD_DELAY_BUCKETS, labels = ["addr"])]
    pub sse_head_delay: LabeledFamily<String, Histogram>,

    /// Chain reorg depth in slots.
    #[metrics(buckets = &REORG_DEPTH_BUCKETS, labels = ["addr"])]
    pub sse_chain_reorg_depth: LabeledFamily<String, Histogram>,

    /// Block reception via gossip delay in seconds.
    #[metrics(buckets = &BLOCK_BUCKETS, labels = ["addr"])]
    pub sse_block_gossip: LabeledFamily<String, Histogram>,

    /// Block imported into fork choice delay in seconds.
    #[metrics(buckets = &BLOCK_BUCKETS, labels = ["addr"])]
    pub sse_block: LabeledFamily<String, Histogram>,
}

/// Global metrics for the beacon node SSE listener.
#[vise::register]
pub static SSE_METRICS: Global<SseMetrics> = Global::new();
