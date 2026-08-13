//! Telemetry / observability initialisation.
//!
//! Wires three independently-configurable sinks into a single
//! `tracing-subscriber` registry:
//!
//! 1. structured `tracing-subscriber` formatter (text or JSON), filtered by `EnvFilter` (defaults
//!    to `RUST_LOG`),
//! 2. OTLP / OpenTelemetry tracing exporter (gRPC) for spans,
//! 3. Sentry error capture from `tracing` events.
//!
//! `init_telemetry` returns a [`TelemetryGuard`] which, on drop, flushes
//! the OpenTelemetry exporter and ends the Sentry client session. The
//! guard must be kept alive for the lifetime of `main` — drop it after
//! the server tasks join.
//!
//! Every layer is opt-in via configuration; the default config produces
//! the same behaviour as the previous `init_tracing()` helper (compact
//! text formatter, `RUST_LOG`-driven filter, no exporters).

use std::time::Duration;

use anyhow::{Context, Result, bail};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use sentry::{ClientInitGuard, ClientOptions};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

use crate::config::{
    LogSetupConfig, ObservabilityConfig, OpentracingConfig, SentryConfig, TracingFormat,
};

/// Drop guard that flushes OpenTelemetry spans and ends the Sentry
/// client session when it goes out of scope.
///
/// Always returned from [`init_telemetry`]; the values inside are
/// `Option`s so test callers don't have to spin up real exporters.
#[must_use = "drop the TelemetryGuard at the end of `main` to flush spans and Sentry events"]
pub struct TelemetryGuard {
    tracer_provider: Option<SdkTracerProvider>,
    _sentry: Option<ClientInitGuard>,
}

impl TelemetryGuard {
    /// Returns a guard that owns no resources. Useful for callers that
    /// build a subscriber themselves (e.g. tests).
    pub fn empty() -> Self {
        Self {
            tracer_provider: None,
            _sentry: None,
        }
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take() {
            // Best-effort flush of pending spans before exporter shuts down.
            let _ = provider.shutdown();
        }
    }
}

/// Initialise the global tracing subscriber, OpenTelemetry exporter,
/// and Sentry client according to `config`.
///
/// Calling this more than once in the same process will fail because
/// the `tracing` global subscriber can only be installed once. Tests
/// that need to exercise the layer composition should use
/// [`build_subscriber_layers`] instead.
pub fn init_telemetry(config: &ObservabilityConfig) -> Result<TelemetryGuard> {
    // Sentry must be initialised before the subscriber so the
    // sentry-tracing layer can attach to a live client.
    let sentry_guard = init_sentry(&config.sentry)?;

    let (otel_provider, otel_layer) = init_opentelemetry(&config.opentracing)?;

    // Compose a `Vec<Box<dyn Layer<Registry>>>` so layer count doesn't
    // change the resulting subscriber type. Each layer carries its own
    // copy of the EnvFilter via `with_filter`, which is more flexible
    // than a single top-level filter (and side-steps the lifetime
    // gymnastics around composing typed Layered<...> chains here).
    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = Vec::new();

    let fmt_layer: Box<dyn Layer<Registry> + Send + Sync> = match config.tracing.format {
        TracingFormat::Json => Box::new(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .with_target(true)
                .with_filter(build_env_filter(&config.tracing)),
        ),
        TracingFormat::Text => Box::new(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .compact()
                .with_filter(build_env_filter(&config.tracing)),
        ),
    };
    layers.push(fmt_layer);

    if sentry_guard.is_some() {
        // Sentry layer captures errors / events at any level the user
        // is logging; let the format layer's EnvFilter drive verbosity.
        layers.push(Box::new(
            sentry_tracing::layer().with_filter(build_env_filter(&config.tracing)),
        ));
    }

    if let Some(layer) = otel_layer {
        layers.push(Box::new(
            layer.with_filter(build_env_filter(&config.tracing)),
        ));
    }

    Registry::default()
        .with(layers)
        .try_init()
        .context("install global tracing subscriber")?;

    Ok(TelemetryGuard {
        tracer_provider: otel_provider,
        _sentry: sentry_guard,
    })
}

/// Returns the `EnvFilter` that the tracing subscriber would use for
/// `config`. The filter prefers (in order): an explicit `filter` value
/// in config, the `RUST_LOG` env var, and finally the configured
/// `level`.
pub fn build_env_filter(config: &LogSetupConfig) -> EnvFilter {
    if let Some(filter) = config
        .filter
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return EnvFilter::try_new(filter)
            .unwrap_or_else(|_| EnvFilter::new(config.level.as_directive()));
    }
    EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(config.level.as_directive()))
}

type OpenTelemetryLayer =
    tracing_opentelemetry::OpenTelemetryLayer<Registry, opentelemetry_sdk::trace::Tracer>;

fn init_opentelemetry(
    config: &OpentracingConfig,
) -> Result<(Option<SdkTracerProvider>, Option<OpenTelemetryLayer>)> {
    if !config.enabled {
        return Ok((None, None));
    }
    let endpoint = config
        .endpoint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "metrics.opentracing.enabled requires metrics.opentracing.endpoint to be set"
            )
        })?;
    if !(0.0..=1.0).contains(&config.sample_rate) {
        bail!(
            "metrics.opentracing.sample_rate must be between 0.0 and 1.0; got {}",
            config.sample_rate
        );
    }
    global::set_text_map_propagator(TraceContextPropagator::new());

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.to_owned())
        .with_timeout(Duration::from_secs(config.timeout_seconds.max(1)))
        .build()
        .context("build OTLP span exporter")?;

    let resource = Resource::builder()
        .with_attribute(KeyValue::new("service.name", config.service_name.clone()))
        .build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .with_sampler(Sampler::TraceIdRatioBased(config.sample_rate))
        .build();

    let tracer = provider.tracer(config.service_name.clone());
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);

    global::set_tracer_provider(provider.clone());
    Ok((Some(provider), Some(layer)))
}

fn init_sentry(config: &SentryConfig) -> Result<Option<ClientInitGuard>> {
    if !config.enabled {
        return Ok(None);
    }
    let dsn = config
        .dsn
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("metrics.sentry.enabled requires metrics.sentry.dsn to be set")
        })?;
    if !(0.0..=1.0).contains(&config.sample_rate) {
        bail!(
            "metrics.sentry.sample_rate must be between 0.0 and 1.0; got {}",
            config.sample_rate
        );
    }
    let mut options = ClientOptions {
        dsn: Some(dsn.parse().context("parse Sentry DSN")?),
        sample_rate: config.sample_rate as f32,
        traces_sample_rate: config.traces_sample_rate as f32,
        attach_stacktrace: true,
        ..Default::default()
    };
    if let Some(env) = config
        .environment
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        options.environment = Some(env.to_owned().into());
    }
    if let Some(release) = config
        .release
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        options.release = Some(release.to_owned().into());
    }
    Ok(Some(sentry::init(options)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TracingLevel;

    #[test]
    fn empty_guard_drops_without_panicking() {
        drop(TelemetryGuard::empty());
    }

    #[test]
    fn build_env_filter_uses_explicit_filter_first() {
        let config = LogSetupConfig {
            filter: Some("floria=trace,info".to_owned()),
            ..Default::default()
        };
        let filter = build_env_filter(&config);
        // EnvFilter doesn't expose its directives; use Display.
        let rendered = format!("{filter}");
        assert!(
            rendered.contains("floria=trace") || rendered.contains("floria"),
            "rendered filter: {rendered}"
        );
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "the test mutates RUST_LOG before constructing the filter"
    )]
    fn build_env_filter_falls_back_to_level() {
        let config = LogSetupConfig {
            level: TracingLevel::Warn,
            format: TracingFormat::Text,
            filter: None,
            extra: serde_json::Map::new(),
        };
        // Ensure RUST_LOG isn't poisoning the test.
        // Safe: tests are single-threaded for this property by virtue of
        // `cargo test` running each binary serially per process.
        // SAFETY: env mutation happens on the test thread only.
        unsafe {
            std::env::remove_var("RUST_LOG");
        }
        let filter = build_env_filter(&config);
        assert!(format!("{filter}").contains("warn"));
    }

    fn err_message<T, E: std::fmt::Display>(result: Result<T, E>) -> String {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn opentelemetry_disabled_returns_no_layer() {
        let cfg = OpentracingConfig::default();
        let (provider, layer) = init_opentelemetry(&cfg).expect("disabled config must succeed");
        assert!(provider.is_none());
        assert!(layer.is_none());
    }

    #[test]
    fn opentelemetry_enabled_requires_endpoint() {
        let cfg = OpentracingConfig {
            enabled: true,
            endpoint: None,
            ..Default::default()
        };
        let error = err_message(init_opentelemetry(&cfg));
        assert!(
            error.contains("requires metrics.opentracing.endpoint"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn opentelemetry_rejects_out_of_range_sample_rate() {
        let cfg = OpentracingConfig {
            enabled: true,
            endpoint: Some("http://127.0.0.1:4317".to_owned()),
            sample_rate: 2.5,
            ..Default::default()
        };
        let error = err_message(init_opentelemetry(&cfg));
        assert!(error.contains("sample_rate"), "unexpected error: {error}");
    }

    #[test]
    fn sentry_disabled_returns_no_guard() {
        let cfg = SentryConfig::default();
        let guard = init_sentry(&cfg).expect("disabled config must succeed");
        assert!(guard.is_none());
    }

    #[test]
    fn sentry_enabled_requires_dsn() {
        let cfg = SentryConfig {
            enabled: true,
            dsn: None,
            ..Default::default()
        };
        let error = err_message(init_sentry(&cfg));
        assert!(
            error.contains("requires metrics.sentry.dsn"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn sentry_rejects_out_of_range_sample_rate() {
        let cfg = SentryConfig {
            enabled: true,
            dsn: Some("https://public@sentry.example.com/1".to_owned()),
            sample_rate: -0.1,
            ..Default::default()
        };
        let error = err_message(init_sentry(&cfg));
        assert!(error.contains("sample_rate"), "unexpected error: {error}");
    }

    #[test]
    fn validate_observability_passes_for_defaults() {
        let cfg = ObservabilityConfig::default();
        cfg.validate().expect("defaults must validate");
    }

    #[test]
    fn validate_observability_rejects_missing_otlp_endpoint() {
        let mut cfg = ObservabilityConfig::default();
        cfg.opentracing.enabled = true;
        cfg.opentracing.endpoint = None;
        let error = cfg.validate().unwrap_err().to_string();
        assert!(
            error.contains("metrics.opentracing.endpoint"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validate_observability_rejects_missing_sentry_dsn() {
        let mut cfg = ObservabilityConfig::default();
        cfg.sentry.enabled = true;
        cfg.sentry.dsn = None;
        let error = cfg.validate().unwrap_err().to_string();
        assert!(
            error.contains("metrics.sentry.dsn"),
            "unexpected error: {error}"
        );
    }
}
