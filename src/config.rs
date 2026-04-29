use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use kdl::{KdlDocument, KdlNode, KdlValue};
use serde::Deserialize;
use serde_json::{Map, Value};
use tracing::warn;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub http: HttpConfig,
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
        let path = env::var("SOFLARE_CONF").unwrap_or_else(|_| "floria.kdl".to_owned());
        let path = PathBuf::from(path);
        let body = fs::read_to_string(&path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let mut config = match path.extension().and_then(|ext| ext.to_str()) {
            Some("kdl") => {
                let json_value = parse_kdl_to_json(&body)
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
        Ok((config, path))
    }

    pub fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "configuration",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
        self.http.emit_startup_warnings();
        self.log.emit_startup_warnings();
        self.metrics.emit_startup_warnings();
    }

    pub fn outbound_proxy(&self) -> Option<&str> {
        self.proxy
            .as_deref()
            .filter(|value| !value.trim().is_empty())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    pub port: u16,
    #[serde(deserialize_with = "string_or_vec")]
    pub bind_addresses: Vec<String>,
    pub notify_dedup_ttl_seconds: u64,
    pub notify_auth: NotifyAuthConfig,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// Accept both `"value"` and `["value", ...]` when deserializing a `Vec<String>`.
/// This lets KDL configs write `bind_addresses "127.0.0.1"` (single argument)
/// instead of requiring the dash-children array syntax.
fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
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

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            port: 5000,
            bind_addresses: vec!["127.0.0.1".to_owned()],
            notify_dedup_ttl_seconds: 0,
            notify_auth: NotifyAuthConfig::default(),
            extra: Map::new(),
        }
    }
}

impl HttpConfig {
    pub fn listen_addrs(&self) -> Result<Vec<String>> {
        if self.bind_addresses.is_empty() {
            bail!("http.bind_addresses must contain at least one address");
        }
        self.bind_addresses
            .iter()
            .map(|addr| normalize_listen_addr(addr, self.port))
            .collect()
    }

    fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "http",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
        self.notify_auth.emit_startup_warnings();
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct NotifyAuthConfig {
    #[serde(default, deserialize_with = "string_or_vec")]
    pub bearer_tokens: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub trusted_service_dids: Vec<String>,
    pub gateway_service_did: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl NotifyAuthConfig {
    pub fn enabled(&self) -> bool {
        !self.bearer_tokens.is_empty()
            || !self.trusted_service_dids.is_empty()
            || self.gateway_service_did.is_some()
    }

    fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "http.notify_auth",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    pub access: AccessLogConfig,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            access: AccessLogConfig::default(),
            extra: Map::new(),
        }
    }
}

impl LogConfig {
    fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "log",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
        self.access.emit_startup_warnings();
    }
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
    fn emit_startup_warnings(&self) {
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
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            prometheus: PrometheusConfig::default(),
            extra: Map::new(),
        }
    }
}

impl MetricsConfig {
    fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "metrics",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
        self.prometheus.emit_startup_warnings();
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PrometheusConfig {
    pub enabled: bool,
    pub address: String,
    pub port: u16,
    #[serde(flatten)]
    extra: Map<String, Value>,
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

    fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "metrics.prometheus",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }
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

fn normalize_listen_addr(raw: &str, default_port: u16) -> Result<String> {
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

// --- KDL support ---

fn parse_kdl_to_json(body: &str) -> Result<Value> {
    let doc: KdlDocument = body.parse().map_err(|e: kdl::KdlError| anyhow!("{e}"))?;
    Ok(kdl_document_to_json(&doc))
}

fn kdl_document_to_json(doc: &KdlDocument) -> Value {
    let mut map = Map::new();
    for node in doc.nodes() {
        let name = node.name().value().to_string();
        let value = kdl_node_to_json_value(node);
        map.insert(name, value);
    }
    Value::Object(map)
}

fn kdl_node_to_json_value(node: &KdlNode) -> Value {
    let positional: Vec<_> = node
        .entries()
        .iter()
        .filter(|e| e.name().is_none())
        .collect();

    match node.children() {
        // All children named `-` → array (KDL array convention).
        Some(children)
            if !children.nodes().is_empty()
                && children.nodes().iter().all(|n| n.name().value() == "-") =>
        {
            Value::Array(
                children
                    .nodes()
                    .iter()
                    .map(kdl_node_to_json_value)
                    .collect(),
            )
        }
        // Children block → object.
        Some(children) => {
            let mut obj = Map::new();
            for child in children.nodes() {
                obj.insert(
                    child.name().value().to_string(),
                    kdl_node_to_json_value(child),
                );
            }
            Value::Object(obj)
        }
        // Single positional argument → scalar.
        None if positional.len() == 1 => kdl_scalar_to_json(positional[0].value()),
        // Multiple positional arguments → array.
        None if positional.len() > 1 => Value::Array(
            positional
                .iter()
                .map(|e| kdl_scalar_to_json(e.value()))
                .collect(),
        ),
        // No arguments, no children → null.
        None => Value::Null,
    }
}

fn kdl_scalar_to_json(value: &KdlValue) -> Value {
    match value {
        KdlValue::String(s) => Value::String(s.clone()),
        KdlValue::Integer(n) => {
            if let Ok(n) = i64::try_from(*n) {
                Value::Number(n.into())
            } else {
                Value::Null
            }
        }
        KdlValue::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        KdlValue::Bool(b) => Value::Bool(*b),
        KdlValue::Null => Value::Null,
    }
}

fn warn_unknown_fields(scope: &str, unknown_fields: Vec<&str>) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_config_values() {
        let config: Config = serde_saphyr::from_str(
            r#"
apps: {}
"#,
        )
        .unwrap();

        assert_eq!(config.http.port, 5000);
        assert_eq!(config.http.bind_addresses, vec!["127.0.0.1"]);
        assert_eq!(config.http.notify_dedup_ttl_seconds, 0);
        assert!(!config.metrics.prometheus.enabled);
        assert_eq!(config.metrics.prometheus.address, "127.0.0.1");
        assert_eq!(config.metrics.prometheus.port, 8000);
        assert!(!config.log.access.x_forwarded_for);
    }

    #[test]
    fn formats_prometheus_ipv6_listen_address() {
        let config = PrometheusConfig {
            enabled: true,
            address: "::1".to_owned(),
            port: 9000,
            extra: Map::new(),
        };

        assert_eq!(config.listen_addr().unwrap(), "[::1]:9000");
    }

    #[test]
    fn keeps_explicit_http_ports() {
        let config = HttpConfig {
            port: 5000,
            bind_addresses: vec!["127.0.0.1:7000".to_owned(), "example.com:7100".to_owned()],
            notify_dedup_ttl_seconds: 0,
            notify_auth: NotifyAuthConfig::default(),
            extra: Map::new(),
        };

        assert_eq!(
            config.listen_addrs().unwrap(),
            vec!["127.0.0.1:7000", "example.com:7100"]
        );
    }

    #[test]
    fn supports_bracketed_ipv6_without_explicit_port() {
        let config = HttpConfig {
            port: 5000,
            bind_addresses: vec!["[::1]".to_owned()],
            notify_dedup_ttl_seconds: 0,
            notify_auth: NotifyAuthConfig::default(),
            extra: Map::new(),
        };

        assert_eq!(config.listen_addrs().unwrap(), vec!["[::1]:5000"]);
    }

    #[test]
    fn parses_kdl_config() {
        let kdl_input = r#"
http {
    port 8080
    bind_addresses "0.0.0.0"
}
apps {
    com.example.test {
        type "apns"
        keyfile "./test.p8"
    }
}
"#;
        let json_value = parse_kdl_to_json(kdl_input).unwrap();
        let config: Config = serde_json::from_value(json_value).unwrap();
        assert_eq!(config.http.port, 8080);
        assert_eq!(config.http.bind_addresses, vec!["0.0.0.0"]);
        assert_eq!(config.http.notify_dedup_ttl_seconds, 0);
        assert_eq!(config.apps.len(), 1);
        let app = config.apps.get("com.example.test").unwrap();
        assert_eq!(app.kind, "apns");
        assert_eq!(
            app.get_string("keyfile").unwrap(),
            Some("./test.p8".to_owned())
        );
    }

    #[test]
    fn kdl_array_from_multiple_arguments() {
        let kdl_input = r#"
http {
    bind_addresses "127.0.0.1" "0.0.0.0"
    port 5000
}
apps {}
"#;
        let json_value = parse_kdl_to_json(kdl_input).unwrap();
        let config: Config = serde_json::from_value(json_value).unwrap();
        assert_eq!(config.http.bind_addresses, vec!["127.0.0.1", "0.0.0.0"]);
    }

    #[test]
    fn kdl_array_from_dash_children() {
        let kdl_input = r#"
http {
    bind_addresses {
        - "127.0.0.1"
        - "0.0.0.0"
    }
    port 5000
}
apps {}
"#;
        let json_value = parse_kdl_to_json(kdl_input).unwrap();
        let config: Config = serde_json::from_value(json_value).unwrap();
        assert_eq!(config.http.bind_addresses, vec!["127.0.0.1", "0.0.0.0"]);
    }

    #[test]
    fn kdl_nested_objects() {
        let kdl_input = r#"
apps {
    com.example.jpush {
        type "jpush"
        app_key "test-key"
        master_secret "test-secret"
        third_party_channel {
            xiaomi {
                distribution "jpush"
            }
            huawei {
                distribution "first_ospush"
            }
        }
    }
}
"#;
        let json_value = parse_kdl_to_json(kdl_input).unwrap();
        let config: Config = serde_json::from_value(json_value).unwrap();
        let app = config.apps.get("com.example.jpush").unwrap();
        assert_eq!(app.kind, "jpush");
        let channel = app.get_object("third_party_channel").unwrap().unwrap();
        let xiaomi = channel.get("xiaomi").unwrap().as_object().unwrap();
        assert_eq!(xiaomi.get("distribution").unwrap(), "jpush");
    }

    #[test]
    fn kdl_defaults_for_missing_sections() {
        let json_value = parse_kdl_to_json("apps {}").unwrap();
        let config: Config = serde_json::from_value(json_value).unwrap();
        assert_eq!(config.http.port, 5000);
        assert_eq!(config.http.bind_addresses, vec!["127.0.0.1"]);
        assert_eq!(config.http.notify_dedup_ttl_seconds, 0);
        assert!(!config.metrics.prometheus.enabled);
    }
}
