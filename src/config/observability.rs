use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::{normalize_listen_addr, warn_unknown_fields};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    pub access: AccessLogConfig,
    pub setup: LogSetupConfig,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            access: AccessLogConfig::default(),
            setup: LogSetupConfig::default(),
            extra: Map::new(),
        }
    }
}

impl LogConfig {
    pub(super) fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "log",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
        self.access.emit_startup_warnings();
        self.setup.emit_startup_warnings();
    }
}

/// Tracing-subscriber setup. Drives the global subscriber installed at
/// startup by [`crate::observability::init_telemetry`].
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LogSetupConfig {
    pub level: TracingLevel,
    pub format: TracingFormat,
    /// Optional explicit `EnvFilter` directive (e.g.
    /// `"floria=debug,tower_http=info"`). When unset, falls back to
    /// `RUST_LOG` and finally to `level`.
    pub filter: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for LogSetupConfig {
    fn default() -> Self {
        Self {
            level: TracingLevel::Info,
            format: TracingFormat::Text,
            filter: None,
            extra: Map::new(),
        }
    }
}

impl LogSetupConfig {
    pub(super) fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "log.setup",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TracingLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl TracingLevel {
    pub fn as_directive(self) -> &'static str {
        match self {
            TracingLevel::Trace => "trace",
            TracingLevel::Debug => "debug",
            TracingLevel::Info => "info",
            TracingLevel::Warn => "warn",
            TracingLevel::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TracingFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AccessLogConfig {
    pub x_forwarded_for: bool,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for AccessLogConfig {
    fn default() -> Self {
        Self {
            x_forwarded_for: false,
            extra: Map::new(),
        }
    }
}

impl AccessLogConfig {
    pub(super) fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "log.access",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    pub prometheus: PrometheusConfig,
    pub opentracing: OpentracingConfig,
    pub sentry: SentryConfig,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            prometheus: PrometheusConfig::default(),
            opentracing: OpentracingConfig::default(),
            sentry: SentryConfig::default(),
            extra: Map::new(),
        }
    }
}

impl MetricsConfig {
    pub(super) fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "metrics",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
        self.prometheus.emit_startup_warnings();
        self.opentracing.emit_startup_warnings();
        self.sentry.emit_startup_warnings();
    }
}

/// OpenTelemetry / OTLP span-exporter configuration. Lives under
/// `metrics.opentracing` for parity with the rest of the metrics
/// section. Disabled by default; when enabled an OTLP endpoint must be
/// configured.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct OpentracingConfig {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub service_name: String,
    pub sample_rate: f64,
    pub timeout_seconds: u64,
    /// Reserved for future tracer back-ends. Currently OTLP / gRPC is
    /// the only supported implementation; the field is preserved so
    /// existing samples that set `implementation "jaeger"` keep working
    /// (the value is ignored).
    pub implementation: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for OpentracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            service_name: "floria".to_owned(),
            sample_rate: 1.0,
            timeout_seconds: 10,
            implementation: None,
            extra: Map::new(),
        }
    }
}

impl OpentracingConfig {
    pub(super) fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "metrics.opentracing",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }

    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self
            .endpoint
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty)
        {
            bail!("metrics.opentracing.enabled requires metrics.opentracing.endpoint to be set");
        }
        if !(0.0..=1.0).contains(&self.sample_rate) {
            bail!(
                "metrics.opentracing.sample_rate must be between 0.0 and 1.0; got {}",
                self.sample_rate
            );
        }
        Ok(())
    }
}

/// Sentry error-capture configuration. Hooks into the tracing
/// subscriber so any `tracing::error!` (and panics) are forwarded.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SentryConfig {
    pub enabled: bool,
    pub dsn: Option<String>,
    pub environment: Option<String>,
    pub release: Option<String>,
    /// Fraction of error events to send (0.0–1.0).
    pub sample_rate: f64,
    /// Fraction of transactions/spans to send (0.0–1.0).
    pub traces_sample_rate: f64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for SentryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dsn: None,
            environment: None,
            release: None,
            sample_rate: 1.0,
            traces_sample_rate: 0.0,
            extra: Map::new(),
        }
    }
}

impl SentryConfig {
    pub(super) fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "metrics.sentry",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }

    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.dsn.as_deref().map(str::trim).is_none_or(str::is_empty) {
            bail!("metrics.sentry.enabled requires metrics.sentry.dsn to be set");
        }
        if !(0.0..=1.0).contains(&self.sample_rate) {
            bail!(
                "metrics.sentry.sample_rate must be between 0.0 and 1.0; got {}",
                self.sample_rate
            );
        }
        if !(0.0..=1.0).contains(&self.traces_sample_rate) {
            bail!(
                "metrics.sentry.traces_sample_rate must be between 0.0 and 1.0; got {}",
                self.traces_sample_rate
            );
        }
        Ok(())
    }
}

/// Aggregated view passed to [`crate::observability::init_telemetry`].
/// Sourced from `log.setup`, `metrics.opentracing`, and `metrics.sentry`
/// — keeping the underlying config sections separate keeps user-visible
/// YAML/KDL grouped by domain (logging vs metrics) while still letting
/// the telemetry initialiser take a single argument.
#[derive(Debug, Clone, Default)]
pub struct ObservabilityConfig {
    pub tracing: LogSetupConfig,
    pub opentracing: OpentracingConfig,
    pub sentry: SentryConfig,
}

impl ObservabilityConfig {
    pub fn from_parts(
        tracing: LogSetupConfig,
        opentracing: OpentracingConfig,
        sentry: SentryConfig,
    ) -> Self {
        Self {
            tracing,
            opentracing,
            sentry,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.opentracing.validate()?;
        self.sentry.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PrometheusConfig {
    pub enabled: bool,
    pub address: String,
    pub port: u16,
    #[serde(flatten)]
    pub(super) extra: Map<String, Value>,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: "127.0.0.1".to_owned(),
            port: 8000,
            extra: Map::new(),
        }
    }
}

impl PrometheusConfig {
    pub fn listen_addr(&self) -> Result<String> {
        let address = if self.address.trim().is_empty() {
            "0.0.0.0"
        } else {
            self.address.as_str()
        };
        normalize_listen_addr(address, self.port)
    }

    pub(super) fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "metrics.prometheus",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }
}
