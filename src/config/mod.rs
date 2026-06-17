use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Map, Value};
use tracing::warn;

mod audit_storage;
mod http;
mod kdl;
mod notify;
mod notify_auth;
mod observability;
mod schema;

#[cfg(test)]
mod tests;

pub use audit_storage::{AuditConfig, StorageConfig};
pub use http::{CircleRateLimitConfig, HttpConfig, InternalAuthConfig};
#[cfg(test)]
use kdl::parse_kdl_to_json;
pub use notify::{NotifyDedupConfig, NotifyRateLimitConfig, NotifyRetryQueueConfig};
pub use notify_auth::{
    NotifyAuthConfig, NotifyNonceStoreConfig, NotifyServicePrincipalConfig,
    is_plaintext_eligible_service_kind,
};
pub use observability::{
    AccessLogConfig, LogConfig, LogSetupConfig, MetricsConfig, ObservabilityConfig,
    OpentracingConfig, PrometheusConfig, SentryConfig, TracingFormat, TracingLevel,
};
pub use schema::config_json_schema;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub http: HttpConfig,
    pub audit: AuditConfig,
    pub storage: StorageConfig,
    pub log: LogConfig,
    pub metrics: MetricsConfig,
    pub proxy: Option<String>,
    pub apps: HashMap<String, AppConfig>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http: HttpConfig::default(),
            audit: AuditConfig::default(),
            storage: StorageConfig::default(),
            log: LogConfig::default(),
            metrics: MetricsConfig::default(),
            proxy: None,
            apps: HashMap::new(),
            extra: Map::new(),
        }
    }
}

impl Config {
    pub fn load() -> Result<(Self, PathBuf)> {
        let path = env::var("FLORIA_CONF").unwrap_or_else(|_| "floria.kdl".to_owned());
        let path = PathBuf::from(path);
        let body = fs::read_to_string(&path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let mut config = match path.extension().and_then(|ext| ext.to_str()) {
            Some("kdl") => {
                let json_value = kdl::parse_kdl_to_json(&body)
                    .with_context(|| format!("failed to parse KDL config {}", path.display()))?;
                serde_json::from_value(json_value).with_context(|| {
                    format!("failed to deserialize KDL config {}", path.display())
                })?
            }
            _ => serde_saphyr::from_str::<Self>(&body)
                .with_context(|| format!("failed to parse YAML config {}", path.display()))?,
        };
        if config.proxy.is_none() {
            config.proxy = env::var("HTTPS_PROXY")
                .ok()
                .filter(|value| !value.trim().is_empty());
        }
        config.validate()?;
        Ok((config, path))
    }

    pub fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "configuration",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
        self.http.emit_startup_warnings();
        self.audit.emit_startup_warnings();
        self.storage.emit_startup_warnings();
        self.log.emit_startup_warnings();
        self.metrics.emit_startup_warnings();
    }

    pub fn outbound_proxy(&self) -> Option<&str> {
        self.proxy
            .as_deref()
            .filter(|value| !value.trim().is_empty())
    }

    pub fn validate(&self) -> Result<()> {
        self.http.validate()?;
        self.audit.validate()?;
        self.storage.validate()?;
        self.metrics.opentracing.validate()?;
        self.metrics.sentry.validate()?;
        Ok(())
    }

    /// Snapshot the observability inputs for
    /// [`crate::observability::init_telemetry`]. Cheap clone — none of
    /// the underlying types own large allocations.
    pub fn observability(&self) -> ObservabilityConfig {
        ObservabilityConfig::from_parts(
            self.log.setup.clone(),
            self.metrics.opentracing.clone(),
            self.metrics.sentry.clone(),
        )
    }
}

impl Config {
    /// Bumped whenever the schema artifact emitted by [`config_json_schema`] changes.
    pub const SCHEMA_VERSION: &'static str = "2026-06-03.1";

    /// Parse a KDL config body into the intermediate JSON shape used by
    /// [`Config::load`]. Exposed for parity tests and ops tooling so
    /// callers can compare KDL ↔ YAML samples without re-rolling the
    /// parser. The shape matches what `serde_json::from_value::<Config>`
    /// expects, so consumers can deserialize directly.
    pub fn parse_kdl_to_json(body: &str) -> Result<Value> {
        kdl::parse_kdl_to_json(body)
    }
}

/// Accept both `"value"` and `["value", ...]` when deserializing a `Vec<String>`.
/// This lets KDL configs write `bind_addresses "127.0.0.1"` (single argument)
/// instead of requiring the dash-children array syntax.
pub(crate) fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or array of strings")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            Ok(vec![value.to_owned()])
        }
        fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
            Ok(vec![value])
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut vec = Vec::new();
            while let Some(value) = seq.next_element()? {
                vec.push(value);
            }
            Ok(vec)
        }
    }
    deserializer.deserialize_any(Visitor)
}

pub(crate) fn validate_bearer_token_hashes(scope: &str, hashes: &[String]) -> Result<()> {
    for value in hashes {
        let trimmed = value.trim();
        let normalized = trimmed.strip_prefix("sha256:").unwrap_or(trimmed);
        if normalized.is_empty() {
            bail!("{scope} must not contain empty values");
        }
        let bytes = hex::decode(normalized)
            .with_context(|| format!("{scope} values must be SHA-256 hex digests"))?;
        if bytes.len() != 32 {
            bail!("{scope} values must encode 32-byte SHA-256 digests");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AppConfig {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl AppConfig {
    pub fn require_kind(&self) -> Result<&str> {
        if self.kind.trim().is_empty() {
            bail!("app config is missing a non-empty type field");
        }
        Ok(self.kind.as_str())
    }

    pub fn warn_unknown_fields(&self, app_name: &str, known_keys: &[&str]) {
        let known: HashSet<&str> = known_keys.iter().copied().collect();
        let unknown = self
            .extra
            .keys()
            .filter(|key| !known.contains(key.as_str()))
            .map(String::as_str)
            .collect::<Vec<_>>();
        warn_unknown_fields(&format!("apps.{app_name}"), unknown);
    }

    pub fn get_string(&self, key: &str) -> Result<Option<String>> {
        match self.extra.get(key) {
            Some(Value::String(value)) => Ok(Some(value.clone())),
            Some(value) => Err(anyhow!("{key} must be a string, got {}", value_type(value))),
            None => Ok(None),
        }
    }

    pub fn get_bool(&self, key: &str) -> Result<Option<bool>> {
        match self.extra.get(key) {
            Some(Value::Bool(value)) => Ok(Some(*value)),
            Some(value) => Err(anyhow!(
                "{key} must be a boolean, got {}",
                value_type(value)
            )),
            None => Ok(None),
        }
    }

    pub fn get_u64(&self, key: &str) -> Result<Option<u64>> {
        match self.extra.get(key) {
            Some(Value::Number(value)) => value
                .as_u64()
                .ok_or_else(|| anyhow!("{key} must be an unsigned integer"))
                .map(Some),
            Some(value) => Err(anyhow!(
                "{key} must be an unsigned integer, got {}",
                value_type(value)
            )),
            None => Ok(None),
        }
    }

    pub fn get_object(&self, key: &str) -> Result<Option<Map<String, Value>>> {
        match self.extra.get(key) {
            Some(Value::Object(value)) => Ok(Some(value.clone())),
            Some(value) => Err(anyhow!(
                "{key} must be an object, got {}",
                value_type(value)
            )),
            None => Ok(None),
        }
    }

    pub fn get_string_list(&self, key: &str) -> Result<Option<Vec<String>>> {
        match self.extra.get(key) {
            Some(Value::Array(values)) => values
                .iter()
                .map(|value| match value {
                    Value::String(value) => Ok(value.clone()),
                    _ => Err(anyhow!(
                        "{key} must be an array of strings, got {}",
                        value_type(value)
                    )),
                })
                .collect::<Result<Vec<_>>>()
                .map(Some),
            // Accept a single string so KDL `key "value"` works for one-element lists.
            Some(Value::String(value)) => Ok(Some(vec![value.clone()])),
            Some(value) => Err(anyhow!(
                "{key} must be a string or array of strings, got {}",
                value_type(value)
            )),
            None => Ok(None),
        }
    }

    pub fn require_existing_file(&self, base_dir: &Path, key: &str) -> Result<Option<PathBuf>> {
        let Some(value) = self.get_string(key)? else {
            return Ok(None);
        };

        let path = resolve_path(base_dir, &value);
        if !path.exists() {
            bail!("{key} points to a missing file: {}", path.display());
        }
        Ok(Some(path))
    }
}

pub fn resolve_path(base_dir: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

pub(crate) fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub(crate) fn normalize_listen_addr(raw: &str, default_port: u16) -> Result<String> {
    let addr = raw.trim();
    if addr.is_empty() {
        bail!("listen address cannot be empty");
    }

    if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
        return Ok(socket_addr.to_string());
    }

    if let Some(host) = addr
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        if host.is_empty() {
            bail!("listen address `{raw}` is not valid");
        }
        return Ok(format!("[{host}]:{default_port}"));
    }

    let colon_count = addr.matches(':').count();
    if colon_count == 0 {
        return Ok(format!("{addr}:{default_port}"));
    }

    if colon_count == 1 {
        let mut parts = addr.splitn(2, ':');
        let host = parts.next().unwrap_or_default().trim();
        let port = parts.next().unwrap_or_default().trim();
        if host.is_empty() || port.is_empty() {
            bail!("listen address `{raw}` is not valid");
        }
        if port.parse::<u16>().is_ok() {
            return Ok(addr.to_owned());
        }
    }

    Ok(format!("[{addr}]:{default_port}"))
}

pub(crate) fn warn_unknown_fields(scope: &str, unknown_fields: Vec<&str>) {
    if unknown_fields.is_empty() {
        return;
    }

    let mut fields = unknown_fields;
    fields.sort_unstable();
    warn!(
        "the following configuration fields in `{scope}` are not understood: {:?}",
        fields
    );
}
