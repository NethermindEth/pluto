use std::collections::HashMap;

/// Configuration for the tracing.
#[derive(Debug, Clone, Default)]
pub struct TracingConfig {
    /// Loki configuration. Enables loki logging if provided. If not - no loki
    /// logging is enabled.
    pub loki: Option<LokiConfig>,

    /// Console configuration. Enables console logging if provided. If not - no
    /// console logging is enabled.
    pub console: Option<ConsoleConfig>,

    /// Enables metrics logging. If not - no metrics logging is enabled.
    pub metrics: bool,

    /// Overrides the environment filter. If not - the environment filter is
    /// used.
    pub override_env_filter: Option<String>,
}

/// Configuration for the loki logging.
#[derive(Debug, Clone)]
pub struct LokiConfig {
    /// URL of the Loki instance.
    pub loki_url: String,

    /// Labels to add to the Loki logs.
    pub labels: HashMap<String, String>,

    /// Extra fields to add to the Loki logs.
    pub extra_fields: HashMap<String, String>,
}

/// Configuration for the console logging.
#[derive(Debug, Clone)]
pub struct ConsoleConfig {
    /// Whether to include the target module in logs.
    pub with_target: bool,

    /// Whether to include the log level in logs.
    pub with_level: bool,

    /// Whether to include thread IDs in logs.
    pub with_thread_ids: bool,

    /// Whether to include the source file name in logs.
    pub with_file: bool,

    /// Whether to include line numbers in logs.
    pub with_line_number: bool,

    /// Whether to use ANSI colors in logs.
    pub with_ansi: bool,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            with_target: true,
            with_level: true,
            with_thread_ids: false,
            with_file: false,
            with_line_number: false,
            with_ansi: true,
        }
    }
}

/// Builder for [`TracingConfig`].
#[derive(Debug, Clone, Default)]
pub struct TracingConfigBuilder {
    tracing_config: TracingConfig,
}

impl TracingConfigBuilder {
    /// Creates a new builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Loki configuration.
    pub fn loki(mut self, config: LokiConfig) -> Self {
        self.tracing_config.loki = Some(config);
        self
    }

    /// Sets the console configuration.
    pub fn console(mut self, config: ConsoleConfig) -> Self {
        self.tracing_config.console = Some(config);
        self
    }

    /// Enables console logging with default configuration.
    pub fn with_default_console(mut self) -> Self {
        self.tracing_config.console = Some(ConsoleConfig::default());
        self
    }

    /// Enables console logging and configures whether to include the target
    /// module.
    pub fn console_with_target(mut self, with_target: bool) -> Self {
        self.tracing_config
            .console
            .get_or_insert_with(ConsoleConfig::default)
            .with_target = with_target;
        self
    }

    /// Enables console logging and configures whether to include the log level.
    pub fn console_with_level(mut self, with_level: bool) -> Self {
        self.tracing_config
            .console
            .get_or_insert_with(ConsoleConfig::default)
            .with_level = with_level;
        self
    }

    /// Enables console logging and configures whether to include thread IDs.
    pub fn console_with_thread_ids(mut self, with_thread_ids: bool) -> Self {
        self.tracing_config
            .console
            .get_or_insert_with(ConsoleConfig::default)
            .with_thread_ids = with_thread_ids;
        self
    }

    /// Enables console logging and configures whether to include the source
    /// file name.
    pub fn console_with_file(mut self, with_file: bool) -> Self {
        self.tracing_config
            .console
            .get_or_insert_with(ConsoleConfig::default)
            .with_file = with_file;
        self
    }

    /// Enables console logging and configures whether to include line numbers.
    pub fn console_with_line_number(mut self, with_line_number: bool) -> Self {
        self.tracing_config
            .console
            .get_or_insert_with(ConsoleConfig::default)
            .with_line_number = with_line_number;
        self
    }

    /// Enables console logging and configures whether to use ANSI colors.
    pub fn console_with_ansi(mut self, with_ansi: bool) -> Self {
        self.tracing_config
            .console
            .get_or_insert_with(ConsoleConfig::default)
            .with_ansi = with_ansi;
        self
    }

    /// Enables metrics logging.
    pub fn with_metrics(mut self, enabled: bool) -> Self {
        self.tracing_config.metrics = enabled;
        self
    }

    /// Sets whether metrics logging is enabled.
    pub fn metrics(mut self, enabled: bool) -> Self {
        self.tracing_config.metrics = enabled;
        self
    }

    /// Sets the environment filter override.
    pub fn override_env_filter(mut self, filter: impl Into<String>) -> Self {
        self.tracing_config.override_env_filter = Some(filter.into());
        self
    }

    /// Builds the [`TracingConfig`].
    pub fn build(self) -> TracingConfig {
        self.tracing_config
    }
}

impl TracingConfig {
    /// Creates a new builder for [`TracingConfig`].
    pub fn builder() -> TracingConfigBuilder {
        TracingConfigBuilder::new()
    }
}
