use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use percent_encoding::percent_decode_str;
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
    Init(#[from] tracing_subscriber::util::TryInitError),

    /// Failed to parse Loki URL.
    #[error("failed to parse Loki URL: {0}")]
    Parse(#[from] tracing_loki::url::ParseError),

    /// Failed to create Loki layer.
    #[error("failed to create Loki layer: {0}")]
    CreateLayer(#[from] tracing_loki::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// Loki background task plus the controller used to signal graceful shutdown.
///
/// For long-lived services, hold onto `controller` and call
/// `controller.shutdown().await` followed by awaiting the spawned `task`
/// before exit so buffered events are drained. Short-lived programs (e.g.
/// examples, one-shot CLI subcommands) may drop the controller; any logs
/// not yet posted to Loki at process exit will be lost.
#[must_use = "the background `task` must be spawned for events to reach Loki"]
pub struct LokiInit {
    /// Handle used to tell the background task to drain its queue and exit.
    pub controller: BackgroundTaskController,
    /// Future that ships buffered events to Loki; must be spawned to run.
    pub task: BackgroundTask,
}

/// Initializes the tracing subscriber.
pub fn init(config: &TracingConfig) -> Result<Option<LokiInit>> {
    let rust_log = std::env::var("RUST_LOG").ok();
    let env_filter = match resolve_filter_directive(
        rust_log.as_deref(),
        config.override_env_filter.as_deref(),
    ) {
        Some(directive) => EnvFilter::try_new(&directive).unwrap_or_else(|_| default_env_filter()),
        None => default_env_filter(),
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

        Ok(Some(LokiInit { controller, task }))
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

/// Selects the tracing filter directive using this precedence:
///
/// 1. `RUST_LOG` from the environment — the standard runtime escape hatch for
///    fine-grained, per-target filtering (e.g. `info,pluto_p2p=debug`) — when
///    set to a non-empty value;
/// 2. the config override, populated from `--log-level` / `CHARON_LOG_LEVEL`;
/// 3. `None`, meaning the caller should fall back to [`default_env_filter`].
///
/// `RUST_LOG` intentionally wins over `--log-level` so operators can crank up
/// specific targets without rebuilding or changing the flag the process was
/// launched with. Takes the `RUST_LOG` value as an argument rather than reading
/// the environment directly so the precedence logic is unit-testable.
fn resolve_filter_directive(
    rust_log: Option<&str>,
    override_env_filter: Option<&str>,
) -> Option<String> {
    if let Some(rust_log) = rust_log
        && !rust_log.trim().is_empty()
    {
        return Some(rust_log.to_string());
    }

    override_env_filter.map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_log_takes_precedence_over_override() {
        assert_eq!(
            resolve_filter_directive(Some("info,pluto_p2p=debug"), Some("warn")),
            Some("info,pluto_p2p=debug".to_string())
        );
    }

    #[test]
    fn override_used_when_rust_log_absent_or_blank() {
        assert_eq!(
            resolve_filter_directive(None, Some("debug")),
            Some("debug".to_string())
        );
        assert_eq!(
            resolve_filter_directive(Some("   "), Some("debug")),
            Some("debug".to_string())
        );
    }

    #[test]
    fn none_when_neither_set() {
        assert_eq!(resolve_filter_directive(None, None), None);
        assert_eq!(resolve_filter_directive(Some(""), None), None);
    }

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
