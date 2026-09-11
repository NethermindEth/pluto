//! Node identity, peers, sync status and the event stream.

use crate::BeaconNodeContainer;
use pluto_eth2api::{EventTopic, v1};
use std::{pin::pin, time::Duration};
use tokio_stream::StreamExt;

#[tokio::test]
async fn get_node_version_reports_lighthouse_v8_0_1() {
    let node = BeaconNodeContainer::shared().await;

    let version = node
        .client()
        .get_node_version()
        .await
        .expect("get node version");

    assert!(
        version.starts_with("Lighthouse/v8.0.1"),
        "unexpected version {version:?}"
    );
}

#[tokio::test]
async fn get_peer_count_is_zero_for_an_isolated_node() {
    let node = BeaconNodeContainer::shared().await;

    let peers = node
        .client()
        .get_peer_count()
        .await
        .expect("get peer count");

    assert_eq!(
        peers,
        v1::PeerCount {
            connected: 0,
            connecting: 0,
            disconnected: 0,
            disconnecting: 0,
        }
    );
}

#[tokio::test]
async fn get_syncing_status_reports_a_head_at_genesis_without_an_execution_layer() {
    let node = BeaconNodeContainer::shared().await;

    let status = node
        .client()
        .get_syncing_status()
        .await
        .expect("get syncing status");

    assert_eq!(status.head_slot, 0);
    assert!(!status.is_optimistic, "head is not optimistic");
    assert!(status.el_offline, "no execution layer is attached");
}

#[tokio::test]
async fn event_stream_subscribes_and_stays_silent_on_an_idle_node() {
    let node = BeaconNodeContainer::shared().await;
    let client = node.client();

    let stream = client
        .event_stream(&[EventTopic::Head])
        .await
        .expect("subscribe to head events");
    let mut stream = pin!(stream);

    let first = tokio::time::timeout(Duration::from_secs(2), stream.next()).await;

    assert!(first.is_err(), "idle node emitted an event: {first:?}");
}
