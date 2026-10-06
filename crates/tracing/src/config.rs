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

    /// `EnvFilter` directives for the console layer; `info` when absent.
    /// Invalid directives are ignored.
    #[builder(into)]
    pub override_env_filter: Option<String>,
}

/// Configuration for the loki logging.
#[derive(Clone)]
pub struct LokiConfig {
    /// URL of the Loki instance.
    pub loki_url: String,

    /// `EnvFilter` directives for the Loki layer, independent of
    /// [`TracingConfig::override_env_filter`]. Invalid directives are ignored.
    pub env_filter: String,

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
            .field("env_filter", &self.env_filter)
            .field("labels", &self.labels)
            .field("extra_fields", &self.extra_fields)
            .finish()
    }
}

/// Strips the `user:password@` component from `raw` so the URL is safe to use
/// in log fields and metric labels. Returns `raw` unchanged if it does not
/// parse as a URL.
pub fn redact_url_userinfo(raw: &str) -> String {
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
            env_filter: String::new(),
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

    #[test]
    fn redact_url_userinfo_strips_credentials() {
        assert_eq!(
            redact_url_userinfo("https://user:secret@bn.example.com:5052/prefix"),
            "https://bn.example.com:5052/prefix"
        );
        assert_eq!(
            redact_url_userinfo("http://user@bn.example.com/"),
            "http://bn.example.com/"
        );
        assert_eq!(
            redact_url_userinfo("http://bn.example.com:5052"),
            "http://bn.example.com:5052/"
        );
    }

    /// Pins every [`ConsoleConfig`] default field value.
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
