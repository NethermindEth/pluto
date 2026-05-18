use std::str::FromStr;

use tracing_loki::{BackgroundTask, BackgroundTaskController, url::Url};
use tracing_subscriber::{
    EnvFilter, Registry, layer::SubscriberExt as _, util::SubscriberInitExt as _,
};

use crate::{config::TracingConfig, layers::metrics::MetricsLayer};

/// Error type for tracing initialization errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to initialize tracing subscriber.
    #[error("failed to initialize tracing subscriber: {0}")]
    InitError(#[from] tracing_subscriber::util::TryInitError),

    /// Failed to parse Loki URL.
    #[error("failed to parse Loki URL: {0}")]
    ParseError(#[from] tracing_loki::url::ParseError),

    /// Failed to create Loki layer.
    #[error("failed to create Loki layer: {0}")]
    CreateLayerError(#[from] tracing_loki::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// Loki background task plus the controller used to signal graceful shutdown.
pub struct LokiInit {
    /// Handle used to tell the background task to drain its queue and exit.
    pub controller: BackgroundTaskController,
    /// Future that ships buffered events to Loki; must be spawned to run.
    pub task: BackgroundTask,
}

/// Initializes the tracing subscriber.
pub fn init(config: &TracingConfig) -> Result<Option<LokiInit>> {
    let env_filter = if let Some(override_env_filter) = config.override_env_filter.as_ref() {
        EnvFilter::from_str(override_env_filter).unwrap_or_else(|_| default_env_filter())
    } else {
        EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| default_env_filter())
    };

    let console_config = config.console.clone().unwrap_or_default();

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(console_config.with_target)
        .with_level(console_config.with_level)
        .with_thread_ids(console_config.with_thread_ids)
        .with_file(console_config.with_file)
        .with_line_number(console_config.with_line_number)
        .with_ansi(console_config.with_ansi);

    let registry = Registry::default()
        .with(env_filter)
        .with(fmt_layer)
        .with(MetricsLayer);

    if let Some(loki_config) = &config.loki {
        // Match the path-stripping behaviour of `tracing_loki::layer` so the
        // builder API keeps the same effective Loki endpoint.
        let loki_url = Url::parse(&loki_config.loki_url)?.join("/")?;

        let mut builder = tracing_loki::builder();
        for (key, value) in loki_config.labels.clone() {
            builder = builder.label(key, value)?;
        }
        for (key, value) in loki_config.extra_fields.clone() {
            builder = builder.extra_field(key, value)?;
        }
        let (loki_layer, controller, task) = builder.build_controller_url(loki_url)?;

        let registry = registry.with(loki_layer);
        registry.try_init()?;

        Ok(Some(LokiInit { controller, task }))
    } else {
        registry.try_init()?;
        Ok(None)
    }
}

fn default_env_filter() -> EnvFilter {
    EnvFilter::new("info")
}
