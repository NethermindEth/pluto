use std::{collections::HashMap, fmt};

use bon::Builder;

/// Configuration for the tracing.
#[derive(Debug, Clone, Default, Builder)]
pub struct TracingConfig {
    /// Loki configuration. Enables loki logging if provided. If not - no loki
    /// logging is enabled.
    pub loki: Option<LokiConfig>,

    /// Console layer options. Defaults are used when absent; console logging is
    /// always enabled.
    pub console: Option<ConsoleConfig>,

    /// Overrides the environment filter. If not - the environment filter is
    /// used.
    #[builder(into)]
    pub override_env_filter: Option<String>,
}

/// Configuration for the loki logging.
#[derive(Clone)]
pub struct LokiConfig {
    /// URL of the Loki instance.
    pub loki_url: String,

    /// Labels to add to the Loki logs.
    pub labels: HashMap<String, String>,

    /// Extra fields to add to the Loki logs.
    pub extra_fields: HashMap<String, String>,
}

impl fmt::Debug for LokiConfig {
    // Redacts basic-auth credentials embedded in `loki_url` so the value is
    // safe to log via `info!(config = ?config)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LokiConfig")
            .field("loki_url", &redact_url_userinfo(&self.loki_url))
            .field("labels", &self.labels)
            .field("extra_fields", &self.extra_fields)
            .finish()
    }
}

fn redact_url_userinfo(raw: &str) -> String {
    let Ok(mut url) = tracing_loki::url::Url::parse(raw) else {
        return raw.to_string();
    };
    if url.username().is_empty() && url.password().is_none() {
        return url.into();
    }
    if url.set_username("").is_err() || url.set_password(None).is_err() {
        return "<redacted: unable to strip credentials>".to_string();
    }
    url.into()
}

/// Configuration for the console logging.
///
/// [`Default`] is defined as
/// [`ConsoleConfig::builder().build()`](Self::builder), so the two are always
/// in lockstep by construction; `#[builder(default = ...)]` on each field pins
/// what those values are (see `crates/tracing`'s
/// `console_config_defaults_are_pinned` test).
#[derive(Debug, Clone, Builder)]
pub struct ConsoleConfig {
    /// Whether to include the target module in logs.
    #[builder(default = true)]
    pub with_target: bool,

    /// Whether to include the log level in logs.
    #[builder(default = true)]
    pub with_level: bool,

    /// Whether to include thread IDs in logs.
    #[builder(default = false)]
    pub with_thread_ids: bool,

    /// Whether to include the source file name in logs.
    #[builder(default = false)]
    pub with_file: bool,

    /// Whether to include line numbers in logs.
    #[builder(default = false)]
    pub with_line_number: bool,

    /// Whether to use ANSI colors in logs.
    #[builder(default = true)]
    pub with_ansi: bool,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self::builder().build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loki_with_url(url: &str) -> LokiConfig {
        LokiConfig {
            loki_url: url.to_string(),
            labels: HashMap::new(),
            extra_fields: HashMap::new(),
        }
    }

    #[test]
    fn debug_redacts_basic_auth_credentials() {
        let cfg = loki_with_url("https://user:secret@loki.example.com/push");
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("user"), "username leaked in Debug: {dbg}");
        assert!(!dbg.contains("secret"), "password leaked in Debug: {dbg}");
        assert!(dbg.contains("loki.example.com"));
    }

    #[test]
    fn debug_preserves_url_without_credentials() {
        let cfg = loki_with_url("https://loki.example.com/loki/api/v1/push");
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("loki.example.com/loki/api/v1/push"));
    }

    #[test]
    fn debug_falls_back_on_unparseable_url() {
        let cfg = loki_with_url("not a url");
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("not a url"));
    }

    /// Pins every [`ConsoleConfig`] default field value. The hand-rolled
    /// `TracingConfigBuilder::with_default_console` this replaces had no
    /// dedicated test; this is the equivalence anchor for the bon conversion.
    #[test]
    fn console_config_defaults_are_pinned() {
        let cfg = ConsoleConfig::default();
        assert!(cfg.with_target);
        assert!(cfg.with_level);
        assert!(!cfg.with_thread_ids);
        assert!(!cfg.with_file);
        assert!(!cfg.with_line_number);
        assert!(cfg.with_ansi);
    }

    /// [`TracingConfig::builder`] with nothing set must equal
    /// [`TracingConfig::default`] (all three fields absent).
    #[test]
    fn tracing_config_builder_matches_default() {
        let built = TracingConfig::builder().build();
        let default = TracingConfig::default();
        assert!(built.loki.is_none());
        assert!(built.console.is_none());
        assert!(built.override_env_filter.is_none());
        assert!(default.loki.is_none());
        assert!(default.console.is_none());
        assert!(default.override_env_filter.is_none());
    }
}
