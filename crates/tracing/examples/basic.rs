//! Basic example demonstrating the charon-tracing functionality.
//!
//! Run the following command to start the test infrastructure:
//! ```bash
//! docker compose -f test-infra/docker-compose.yml up -d
//! ```
//!
//! Run the following command to start the example:
//! ```bash
//! cargo run --example basic
//! ```
//!
//! You can see the logs in Grafana at http://localhost:3000.
use std::{collections::HashMap, net::SocketAddr};

use pluto_tracing::{LokiConfig, config::TracingConfig, init::init};
use tracing::{debug, error, info, instrument, trace, warn};
use vise_exporter::MetricsExporter;

#[tokio::main]
async fn main() {
    // Initialize tracing with default console config
    let config = TracingConfig::builder()
        .with_default_console()
        .with_metrics(true)
        .loki(LokiConfig {
            loki_url: "http://localhost:3100".to_string(),
            labels: HashMap::new(),
            extra_fields: HashMap::new(),
        })
        .override_env_filter("debug")
        .build();

    let background_task = init(&config)
        .expect("Failed to initialize tracing")
        .expect("Background task should be Some");

    tokio::spawn(background_task);

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

    // Test various log levels
    trace!("This is a trace message");
    debug!("This is a debug message");
    info!("This is an info message");
    warn!("This is a warning message");
    error!("This is an error message");

    // Test structured logging with fields
    info!(user_id = 42, action = "login", "User performed an action");

    instrumented_function();

    // Test spans
    let span = tracing::info_span!("processing", request_id = "abc-123");
    let _guard = span.enter();

    info!("Processing started");
    debug!("Debug info inside span");
    info!("Processing completed");

    // Wait for 10 seconds to see the logs in Loki
    std::thread::sleep(std::time::Duration::from_secs(10));
}

#[instrument]
fn instrumented_function() {
    info!("Instrumented function started");
    debug!("Debug info inside instrumented function");
    info!("Instrumented function completed");
}
