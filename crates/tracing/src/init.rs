use std::{str::FromStr, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use percent_encoding::percent_decode_str;
use tracing_loki::{BackgroundTaskController, url::Url};
use tracing_subscriber::{
    EnvFilter, Registry, layer::SubscriberExt as _, util::SubscriberInitExt as _,
};

use crate::{config::TracingConfig, layers::metrics::MetricsLayer};

/// Error type for tracing initialization errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to initialize tracing subscriber.
    #[error("failed to initialize tracing subscriber: {0}")]
    Init(#[from] tracing_subscriber::util::TryInitError),

    /// Failed to parse Loki URL.
    #[error("failed to parse Loki URL: {0}")]
    Parse(#[from] tracing_loki::url::ParseError),

    /// Failed to create Loki layer.
    #[error("failed to create Loki layer: {0}")]
    CreateLayer(#[from] tracing_loki::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// Grace period given to the Loki background task to flush buffered events once
/// shutdown has been signalled.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(3);

/// The running Loki background task, returned by [`init`] when Loki is
/// configured.
///
/// Dropping this rather than calling [`LokiWorker::shutdown`] loses every event
/// not yet posted to Loki.
pub struct LokiWorker {
    controller: BackgroundTaskController,
    handle: tokio::task::JoinHandle<()>,
}

impl LokiWorker {
    /// Drains buffered events and stops the worker.
    ///
    /// Signalling and draining share a single grace period so an unreachable
    /// Loki endpoint cannot wedge process exit; the worker is hard-aborted once
    /// the budget elapses.
    pub async fn shutdown(self) {
        let abort_handle = self.handle.abort_handle();

        let _ = tokio::time::timeout(FLUSH_TIMEOUT, async {
            self.controller.shutdown().await;
            let _ = self.handle.await;
        })
        .await;

        abort_handle.abort();
    }
}

/// Initializes the tracing subscriber.
///
/// When `config` enables Loki, the background task that ships events is spawned
/// here and returned so the caller can drain it before exit.
///
/// # Panics
///
/// Panics when Loki is configured and this is called outside a Tokio runtime.
pub fn init(config: &TracingConfig) -> Result<Option<LokiWorker>> {
    let env_filter = if let Some(override_env_filter) = config.override_env_filter.as_ref() {
        EnvFilter::from_str(override_env_filter).unwrap_or_else(|_| default_env_filter())
    } else {
        EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| default_env_filter())
    };

    let console_config = config.console.clone().unwrap_or_default();

    let fmt_layer = tracing_subscriber::fmt::layer()
        // Logs belong on stderr so a command's stdout stays pipeable.
        .with_writer(std::io::stderr)
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
        let parsed = Url::parse(&loki_config.loki_url)?;
        let basic_auth = extract_basic_auth(&parsed);
        let loki_url = strip_userinfo(parsed)?.join("/")?;

        let mut builder = tracing_loki::builder();
        if let Some(value) = basic_auth.as_deref() {
            // Move embedded basic-auth credentials into a request header so
            // `tracing-loki`'s own send-error logging (which prints the
            // request URL via `reqwest::Error`'s Display impl) cannot leak
            // them to stderr or back to Loki itself.
            builder = builder.http_header("Authorization", value)?;
        }
        for (key, value) in loki_config.labels.clone() {
            builder = builder.label(key, value)?;
        }
        for (key, value) in loki_config.extra_fields.clone() {
            builder = builder.extra_field(key, value)?;
        }
        let (loki_layer, controller, task) = builder.build_controller_url(loki_url)?;

        let registry = registry.with(loki_layer);
        registry.try_init()?;

        Ok(Some(LokiWorker {
            controller,
            handle: tokio::spawn(task),
        }))
    } else {
        registry.try_init()?;
        Ok(None)
    }
}

fn extract_basic_auth(url: &Url) -> Option<String> {
    if url.username().is_empty() && url.password().is_none() {
        return None;
    }
    // `Url::username` / `Url::password` return the *percent-encoded* form as
    // it appears in the URL. HTTP basic-auth expects the raw credentials, so
    // decode before base64-encoding; otherwise a username/password containing
    // `@`, `:`, `/`, etc. would authenticate with the literal `%xx` escapes.
    let user = percent_decode_str(url.username()).decode_utf8_lossy();
    let pass = percent_decode_str(url.password().unwrap_or("")).decode_utf8_lossy();
    Some(format!("Basic {}", BASE64.encode(format!("{user}:{pass}"))))
}

fn strip_userinfo(mut url: Url) -> Result<Url> {
    if url.set_username("").is_err() || url.set_password(None).is_err() {
        // `cannot-be-a-base` URLs (e.g. `data:`) cannot have userinfo set, so
        // an Err here means the URL never carried credentials in the first
        // place; safe to return as-is.
        return Ok(url);
    }
    Ok(url)
}

fn default_env_filter() -> EnvFilter {
    EnvFilter::new("info")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_extracted_from_user_and_password() {
        let url = Url::parse("https://alice:s3cr3t@loki.example.com/push").unwrap();
        let header = extract_basic_auth(&url).expect("should extract");
        // Base64("alice:s3cr3t") == "YWxpY2U6czNjcjN0"
        assert_eq!(header, "Basic YWxpY2U6czNjcjN0");
    }

    #[test]
    fn basic_auth_extracted_when_only_username_present() {
        let url = Url::parse("https://token@loki.example.com/push").unwrap();
        let header = extract_basic_auth(&url).expect("should extract");
        // Base64("token:") == "dG9rZW46"
        assert_eq!(header, "Basic dG9rZW46");
    }

    #[test]
    fn basic_auth_decodes_percent_encoded_userinfo() {
        // user = "bob@corp", pass = "p:/ss"
        let url = Url::parse("https://bob%40corp:p%3A%2Fss@loki.example.com/push").unwrap();
        let header = extract_basic_auth(&url).expect("should extract");
        // Base64("bob@corp:p:/ss") == "Ym9iQGNvcnA6cDovc3M="
        assert_eq!(header, "Basic Ym9iQGNvcnA6cDovc3M=");
    }

    #[test]
    fn no_basic_auth_when_url_has_no_userinfo() {
        let url = Url::parse("https://loki.example.com/push").unwrap();
        assert!(extract_basic_auth(&url).is_none());
    }

    #[test]
    fn strip_userinfo_removes_credentials() {
        let url = Url::parse("https://alice:s3cr3t@loki.example.com/push").unwrap();
        let stripped = strip_userinfo(url).unwrap();
        assert_eq!(stripped.as_str(), "https://loki.example.com/push");
    }

    #[test]
    fn strip_userinfo_is_noop_when_absent() {
        let url = Url::parse("https://loki.example.com/push").unwrap();
        let stripped = strip_userinfo(url).unwrap();
        assert_eq!(stripped.as_str(), "https://loki.example.com/push");
    }
}
