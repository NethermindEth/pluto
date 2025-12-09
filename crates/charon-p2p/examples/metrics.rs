//! Example demonstrating the charon-p2p metrics functionality.
//!
//! To run this example, run the local Prometheus and Grafana containers:
//! ```bash
//! docker compose -f test-infra/docker-compose.yml up -d
//! ```
//!
//! Then run the example:
//! ```bash
//! cargo run --example metrics -p charon-p2p
//! ```
//!
//! Metrics will be available in Grafana at http://localhost:3000.

use std::net::SocketAddr;

use charon_p2p::metrics::{
    ConnectionType, Direction, P2P_METRICS, PeerConnectionLabels, PeerNetworkLabels,
    PeerStreamLabels, Protocol, RelayConnectionLabels,
};
use vise_exporter::MetricsExporter;

#[tokio::main]
async fn main() {
    let bind_address = SocketAddr::from(([0, 0, 0, 0], 9464));

    let exporter = MetricsExporter::default()
        .bind(bind_address)
        .await
        .expect("Failed to bind metrics exporter");
    tokio::spawn(async move {
        exporter
            .start()
            .await
            .expect("Failed to start metrics exporter");
    });

    P2P_METRICS.ping_latency_secs["rustnew"].observe(1.0);
    P2P_METRICS.ping_error_total["rustnew"].inc();
    P2P_METRICS.ping_success["rustnew"].set(1);
    P2P_METRICS.reachability_status.set(1);
    P2P_METRICS.relay_connections["rustnew"].set(1);
    P2P_METRICS.peer_connection_types
        [&PeerConnectionLabels::new("rustnew", ConnectionType::Direct, Protocol::Tcp)]
        .set(1);
    P2P_METRICS.relay_connection_types
        [&RelayConnectionLabels::new("rustnew", ConnectionType::Direct, Protocol::Tcp)]
        .set(1);
    P2P_METRICS.peer_streams[&PeerStreamLabels::new("rustnew", Direction::Inbound, Protocol::Tcp)]
        .set(1);
    P2P_METRICS.peer_connection_total["rustnew"].inc();
    P2P_METRICS.peer_network_receive_bytes_total[&PeerNetworkLabels::new("rustnew", Protocol::Tcp)]
        .inc();
    P2P_METRICS.peer_network_sent_bytes_total[&PeerNetworkLabels::new("rustnew", Protocol::Tcp)]
        .inc();

    // Wait for 10 seconds to see the logs in Loki
    std::thread::sleep(std::time::Duration::from_secs(20));
}
