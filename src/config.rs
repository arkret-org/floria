use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{env, fs};

use anyhow::{Context, Result, anyhow, bail};
use kdl::{KdlDocument, KdlNode, KdlValue};
use serde::Deserialize;
use serde_json::{Map, Value};
use tracing::warn;

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

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    pub port: u16,
    #[serde(deserialize_with = "string_or_vec")]
    pub bind_addresses: Vec<String>,
    pub notify_dedup_ttl_seconds: u64,
    pub notify_dedup: NotifyDedupConfig,
    pub notify_auth: NotifyAuthConfig,
    pub internal_auth: InternalAuthConfig,
    pub notify_rate_limits: NotifyRateLimitConfig,
    pub notify_retry_queue: NotifyRetryQueueConfig,
    /// CXP-0007 Circle primitive — when `true`, the per-(provider,
    /// scope) delivery counter (`floria_notify_delivery_total`) labels
    /// `scope_id` with the `circle_id` instead of the parent
    /// `realm_id` when a Circle is set. Default `false` keeps the
    /// label cardinality bounded by realm count; operators only opt
    /// in for environments where per-Circle delivery dashboards are
    /// needed.
    #[serde(default)]
    pub metrics_detailed_circle_labels: bool,
    /// CXP-0007 Circle primitive — per-Circle rate limits and
    /// concurrency caps. Default disabled.
    #[serde(default)]
    pub circle_rate_limits: CircleRateLimitConfig,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// CXP-0007 Circle primitive — per-Circle rate-limit configuration.
/// Defaults leave both knobs unset (no Circle-specific limits applied).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CircleRateLimitConfig {
    /// Max sustained notify QPS for a single Circle. `None` disables
    /// the per-Circle QPS cap.
    pub per_circle_qps: Option<u32>,
    /// Max in-flight notify dispatches for a single Circle. `None`
    /// disables the per-Circle concurrency cap.
    pub per_circle_concurrency: Option<u32>,
}

impl CircleRateLimitConfig {
    pub fn enabled(&self) -> bool {
        self.per_circle_qps.is_some() || self.per_circle_concurrency.is_some()
    }
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
            notify_dedup: NotifyDedupConfig::default(),
            notify_auth: NotifyAuthConfig::default(),
            internal_auth: InternalAuthConfig::default(),
            notify_rate_limits: NotifyRateLimitConfig::default(),
            notify_retry_queue: NotifyRetryQueueConfig::default(),
            metrics_detailed_circle_labels: false,
            circle_rate_limits: CircleRateLimitConfig::default(),
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
        self.notify_dedup.emit_startup_warnings();
        self.notify_auth.emit_startup_warnings();
        self.internal_auth.emit_startup_warnings();
        self.notify_rate_limits.emit_startup_warnings();
        self.notify_retry_queue.emit_startup_warnings();
    }

    pub fn validate(&self) -> Result<()> {
        let _ = self.listen_addrs()?;
        self.notify_dedup.validate(self.notify_dedup_ttl_seconds)?;
        self.notify_auth.validate()?;
        self.internal_auth.validate()?;
        self.notify_rate_limits.validate()?;
        self.notify_retry_queue.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct InternalAuthConfig {
    #[serde(default, deserialize_with = "string_or_vec")]
    pub bearer_tokens: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub bearer_token_hashes: Vec<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl InternalAuthConfig {
    pub fn enabled(&self) -> bool {
        !self.bearer_tokens.is_empty() || !self.bearer_token_hashes.is_empty()
    }

    fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "http.internal_auth",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }

    pub fn validate(&self) -> Result<()> {
        if self
            .bearer_tokens
            .iter()
            .any(|value| value.trim().is_empty())
        {
            bail!("http.internal_auth.bearer_tokens must not contain empty values");
        }
        validate_bearer_token_hashes(
            "http.internal_auth.bearer_token_hashes",
            &self.bearer_token_hashes,
        )?;
        Ok(())
    }
}

impl Default for InternalAuthConfig {
    fn default() -> Self {
        Self {
            bearer_tokens: Vec::new(),
            bearer_token_hashes: Vec::new(),
            extra: Map::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    pub backend: String,
    pub file_path: Option<String>,
    pub endpoint: Option<String>,
    pub bearer_token: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            backend: "disabled".to_owned(),
            file_path: None,
            endpoint: None,
            bearer_token: None,
            extra: Map::new(),
        }
    }
}

impl AuditConfig {
    pub fn backend_kind(&self) -> &str {
        let backend = self.backend.trim();
        if backend.is_empty() {
            "disabled"
        } else {
            backend
        }
    }

    pub fn file_path(&self) -> Option<&str> {
        self.file_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn bearer_token(&self) -> Option<&str> {
        self.bearer_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "audit",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }

    pub fn validate(&self) -> Result<()> {
        match self.backend_kind() {
            "disabled" => Ok(()),
            "file" => {
                if self.file_path().is_none() {
                    bail!("audit.file_path is required when audit.backend=file");
                }
                Ok(())
            }
            "http" => {
                let endpoint = self
                    .endpoint()
                    .ok_or_else(|| anyhow!("audit.endpoint is required when audit.backend=http"))?;
                let parsed = endpoint
                    .parse::<reqwest::Url>()
                    .with_context(|| "audit.endpoint must be an absolute HTTP(S) URL")?;
                match parsed.scheme() {
                    "http" | "https" => {
                        crate::egress::validate_url_for_egress(
                            &parsed,
                            "audit.endpoint",
                            crate::egress::private_networks_allowed(),
                        )
                        .map_err(anyhow::Error::msg)?;
                        Ok(())
                    }
                    scheme => bail!("audit.endpoint must use http or https, got `{scheme}`"),
                }
            }
            backend => bail!("audit.backend must be one of: disabled, file, http; got `{backend}`"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub postgres_url: Option<String>,
    pub deactivation_queue_table: String,
    pub push_contact_cache_table: String,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            postgres_url: None,
            deactivation_queue_table: "floria_push_delivery_queue".to_owned(),
            push_contact_cache_table: "floria_push_contact_cache".to_owned(),
            extra: Map::new(),
        }
    }
}

impl StorageConfig {
    pub fn postgres_url(&self) -> Option<&str> {
        self.postgres_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn postgres_enabled(&self) -> bool {
        self.postgres_url().is_some()
    }

    pub fn deactivation_queue_table(&self) -> &str {
        let value = self.deactivation_queue_table.trim();
        if value.is_empty() {
            "floria_push_delivery_queue"
        } else {
            value
        }
    }

    pub fn push_contact_cache_table(&self) -> &str {
        let value = self.push_contact_cache_table.trim();
        if value.is_empty() {
            "floria_push_contact_cache"
        } else {
            value
        }
    }

    fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "storage",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(url) = self.postgres_url() {
            crate::postgres_support::validate_postgres_url(url, "storage.postgres_url")?;
        }
        crate::postgres_support::SqlTableName::parse(
            self.deactivation_queue_table(),
            "storage.deactivation_queue_table",
        )?;
        crate::postgres_support::SqlTableName::parse(
            self.push_contact_cache_table(),
            "storage.push_contact_cache_table",
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NotifyDedupConfig {
    pub backend: String,
    pub redis_url: Option<String>,
    pub key_prefix: String,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for NotifyDedupConfig {
    fn default() -> Self {
        Self {
            backend: "memory".to_owned(),
            redis_url: None,
            key_prefix: "floria".to_owned(),
            extra: Map::new(),
        }
    }
}

impl NotifyDedupConfig {
    pub fn backend_kind(&self) -> &str {
        let backend = self.backend.trim();
        if backend.is_empty() {
            "memory"
        } else {
            backend
        }
    }

    pub fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "http.notify_dedup",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }

    pub fn key_prefix(&self) -> &str {
        let value = self.key_prefix.trim();
        if value.is_empty() { "floria" } else { value }
    }

    pub fn validate(&self, ttl_seconds: u64) -> Result<()> {
        match self.backend_kind() {
            "memory" => {}
            "redis" => {
                if ttl_seconds == 0 {
                    bail!(
                        "http.notify_dedup.backend=redis requires http.notify_dedup_ttl_seconds > 0"
                    );
                }
                if self
                    .redis_url
                    .as_deref()
                    .map(str::trim)
                    .is_none_or(|value| value.is_empty())
                {
                    bail!("http.notify_dedup.redis_url is required when backend=redis");
                }
            }
            backend => {
                bail!("http.notify_dedup.backend must be one of: memory, redis; got `{backend}`");
            }
        }
        if self.key_prefix().is_empty() {
            bail!("http.notify_dedup.key_prefix must not be empty");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NotifyAuthConfig {
    #[serde(default, deserialize_with = "string_or_vec")]
    pub bearer_tokens: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub bearer_token_hashes: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub trusted_service_dids: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub plaintext_metadata_service_dids: Vec<String>,
    pub gateway_service_did: Option<String>,
    pub require_message_signatures: bool,
    pub signature_max_skew_seconds: u64,
    pub mtls_verified_header: String,
    pub mtls_fingerprint_header: String,
    pub mtls_subject_dn_header: String,
    pub mtls_subject_alt_names_header: String,
    /// When true, refuse to accept bearer-only or anonymous notify
    /// requests; every authenticated caller must satisfy HTTP Message
    /// Signature or mTLS, and the gateway DID must be configured.
    /// Also forbids dev-only conveniences (anonymous bypass, bearer
    /// fallback when no signature is present on a known principal).
    pub production_mode: bool,
    /// When true, a bearer-only request MUST present a recognised
    /// origin_service_did and the gateway will only accept the request
    /// if that DID has a configured `service_principal` entry whose
    /// `bearer_tokens` / `bearer_token_hashes` match. This blocks a
    /// stolen gateway-wide bearer token from being used to impersonate
    /// an arbitrary tenant via the X-Cokret-Origin-Service-DID header.
    /// Has no effect in `production_mode` (which already disables the
    /// gateway-wide bearer fallback).
    pub bind_bearer_to_origin_did: bool,
    #[serde(default)]
    pub service_principals: HashMap<String, NotifyServicePrincipalConfig>,
    pub nonce_store: NotifyNonceStoreConfig,
    pub replay_window_seconds: u64,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl NotifyAuthConfig {
    pub fn enabled(&self) -> bool {
        !self.bearer_tokens.is_empty()
            || !self.bearer_token_hashes.is_empty()
            || !self.trusted_service_dids.is_empty()
            || !self.service_principals.is_empty()
            || self.gateway_service_did.is_some()
            || self.require_message_signatures
    }

    fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "http.notify_auth",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
        for (did, principal) in &self.service_principals {
            principal.emit_startup_warnings(did);
        }
        self.nonce_store.emit_startup_warnings();
    }

    pub fn signature_max_skew_seconds(&self) -> u64 {
        self.signature_max_skew_seconds.max(1)
    }

    pub fn mtls_verified_header(&self) -> &str {
        let value = self.mtls_verified_header.trim();
        if value.is_empty() {
            "x-client-certificate-verified"
        } else {
            value
        }
    }

    pub fn mtls_fingerprint_header(&self) -> &str {
        let value = self.mtls_fingerprint_header.trim();
        if value.is_empty() {
            "x-client-certificate-sha256"
        } else {
            value
        }
    }

    pub fn mtls_subject_dn_header(&self) -> &str {
        let value = self.mtls_subject_dn_header.trim();
        if value.is_empty() {
            "x-client-certificate-subject"
        } else {
            value
        }
    }

    pub fn mtls_subject_alt_names_header(&self) -> &str {
        let value = self.mtls_subject_alt_names_header.trim();
        if value.is_empty() {
            "x-client-certificate-san"
        } else {
            value
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.require_message_signatures && self.service_principals.is_empty() {
            bail!(
                "http.notify_auth.require_message_signatures requires at least one service_principal"
            );
        }
        validate_bearer_token_hashes(
            "http.notify_auth.bearer_token_hashes",
            &self.bearer_token_hashes,
        )?;
        for (did, principal) in &self.service_principals {
            principal.validate(did)?;
        }
        self.nonce_store.validate(self.replay_window_seconds)?;
        if self.production_mode {
            self.validate_production_mode()?;
        }
        Ok(())
    }

    pub fn replay_window_seconds(&self) -> u64 {
        self.replay_window_seconds
    }

    fn validate_production_mode(&self) -> Result<()> {
        if !self.enabled() {
            bail!(
                "http.notify_auth.production_mode requires authentication; configure service_principals or signed access"
            );
        }
        if self.gateway_service_did.is_none() {
            bail!("http.notify_auth.production_mode requires http.notify_auth.gateway_service_did");
        }
        if self.service_principals.is_empty() {
            bail!(
                "http.notify_auth.production_mode requires at least one configured service_principal"
            );
        }
        for (did, principal) in &self.service_principals {
            let has_signature = principal.signature_key_id.is_some()
                && principal.signature_public_key_hex.is_some();
            if !has_signature && !principal.require_mtls {
                bail!(
                    "http.notify_auth.production_mode requires service_principals.{did} to set HTTP Message Signature or require_mtls"
                );
            }
            if !principal.bearer_tokens.is_empty() {
                bail!(
                    "http.notify_auth.production_mode rejects plaintext bearer_tokens on service_principals.{did}; production callers must use HTTP Message Signature or mTLS"
                );
            }
            if principal.allow_plaintext_metadata {
                let kind = principal
                    .service_type
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                let Some(kind) = kind else {
                    bail!(
                        "http.notify_auth.production_mode requires service_principals.{did}.service_type when allow_plaintext_metadata is true"
                    );
                };
                if !is_plaintext_eligible_service_kind(kind) {
                    bail!(
                        "http.notify_auth.production_mode rejects allow_plaintext_metadata for service_type `{kind}` on service_principals.{did}"
                    );
                }
            }
        }
        if !self.bearer_tokens.is_empty() || !self.bearer_token_hashes.is_empty() {
            bail!(
                "http.notify_auth.production_mode rejects gateway-wide bearer_tokens; configure per-principal credentials instead"
            );
        }
        Ok(())
    }
}

/// Caller `service_type` values that are allowed to send plaintext
/// metadata (sender/realm/flow names, DID literals, etc.).
///
/// Active service kinds — kept in sync with `ck.profile.*` artifacts in
/// the principal services. New kinds must be reviewed for whether they
/// can legitimately read/forward plaintext bound to a user identity.
pub fn is_plaintext_eligible_service_kind(kind: &str) -> bool {
    matches!(
        kind.trim().to_ascii_lowercase().as_str(),
        "sync" | "sync_service" | "principal" | "principal_service"
    )
}

impl Default for NotifyAuthConfig {
    fn default() -> Self {
        Self {
            bearer_tokens: Vec::new(),
            bearer_token_hashes: Vec::new(),
            trusted_service_dids: Vec::new(),
            plaintext_metadata_service_dids: Vec::new(),
            gateway_service_did: None,
            require_message_signatures: false,
            signature_max_skew_seconds: 300,
            mtls_verified_header: "x-client-certificate-verified".to_owned(),
            mtls_fingerprint_header: "x-client-certificate-sha256".to_owned(),
            mtls_subject_dn_header: "x-client-certificate-subject".to_owned(),
            mtls_subject_alt_names_header: "x-client-certificate-san".to_owned(),
            production_mode: false,
            bind_bearer_to_origin_did: false,
            service_principals: HashMap::new(),
            nonce_store: NotifyNonceStoreConfig::default(),
            replay_window_seconds: 0,
            extra: Map::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NotifyNonceStoreConfig {
    pub backend: String,
    pub redis_url: Option<String>,
    pub key_prefix: String,
    /// Behaviour when the Redis backend is unreachable. `strict` (the
    /// default) is fail-closed: the gateway answers 503 on the calling
    /// site so the caller backs off instead of bypassing replay
    /// protection. `permissive` opts back into fail-open and MUST only be
    /// used in deployments that accept silent replay-protection bypass
    /// during Redis outages.
    pub redis_failure_policy: String,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for NotifyNonceStoreConfig {
    fn default() -> Self {
        Self {
            backend: "memory".to_owned(),
            redis_url: None,
            key_prefix: "floria".to_owned(),
            redis_failure_policy: "strict".to_owned(),
            extra: Map::new(),
        }
    }
}

impl NotifyNonceStoreConfig {
    pub fn backend_kind(&self) -> &str {
        let backend = self.backend.trim();
        if backend.is_empty() {
            "memory"
        } else {
            backend
        }
    }

    pub fn key_prefix(&self) -> &str {
        let value = self.key_prefix.trim();
        if value.is_empty() { "floria" } else { value }
    }

    pub fn failure_policy(&self) -> &str {
        let value = self.redis_failure_policy.trim();
        if value.is_empty() { "strict" } else { value }
    }

    fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "http.notify_auth.nonce_store",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }

    pub fn validate(&self, replay_window_seconds: u64) -> Result<()> {
        match self.backend_kind() {
            "memory" => {}
            "redis" => {
                if replay_window_seconds == 0 {
                    bail!(
                        "http.notify_auth.nonce_store.backend=redis requires http.notify_auth.replay_window_seconds > 0"
                    );
                }
                if self
                    .redis_url
                    .as_deref()
                    .map(str::trim)
                    .is_none_or(|value| value.is_empty())
                {
                    bail!("http.notify_auth.nonce_store.redis_url is required when backend=redis");
                }
            }
            backend => {
                bail!(
                    "http.notify_auth.nonce_store.backend must be one of: memory, redis; got `{backend}`"
                );
            }
        }
        match self.failure_policy() {
            "permissive" | "strict" => {}
            other => {
                bail!(
                    "http.notify_auth.nonce_store.redis_failure_policy must be one of: permissive, strict; got `{other}`"
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NotifyServicePrincipalConfig {
    pub service_type: Option<String>,
    pub allow_plaintext_metadata: bool,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub bearer_tokens: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub bearer_token_hashes: Vec<String>,
    pub signature_key_id: Option<String>,
    pub signature_public_key_hex: Option<String>,
    pub require_mtls: bool,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub mtls_cert_fingerprints: Vec<String>,
    /// Expected client-certificate Subject DN (exact, case-insensitive
    /// after whitespace normalisation). Set this when the reverse
    /// proxy can pass through the verified subject DN — it binds the
    /// cert to a specific issuer/subject so a fingerprint reuse on a
    /// different cert under the same trust root is still rejected.
    pub mtls_subject_dn: Option<String>,
    /// Subject Alternative Names that the verified client certificate
    /// is required to advertise. Each entry must appear in the SAN
    /// list passed by the reverse proxy. This is the typical hook
    /// for binding a service DID (`uri:did:web:sync.example.com`) to
    /// a particular cert.
    #[serde(default, deserialize_with = "string_or_vec")]
    pub mtls_subject_alt_names: Vec<String>,
    pub service_endpoint: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for NotifyServicePrincipalConfig {
    fn default() -> Self {
        Self {
            service_type: None,
            allow_plaintext_metadata: false,
            bearer_tokens: Vec::new(),
            bearer_token_hashes: Vec::new(),
            signature_key_id: None,
            signature_public_key_hex: None,
            require_mtls: false,
            mtls_cert_fingerprints: Vec::new(),
            mtls_subject_dn: None,
            mtls_subject_alt_names: Vec::new(),
            service_endpoint: None,
            extra: Map::new(),
        }
    }
}

impl NotifyServicePrincipalConfig {
    fn emit_startup_warnings(&self, did: &str) {
        warn_unknown_fields(
            &format!("http.notify_auth.service_principals.{did}"),
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }

    fn validate(&self, did: &str) -> Result<()> {
        match (
            self.signature_key_id.as_deref(),
            self.signature_public_key_hex.as_deref(),
        ) {
            (Some(_), Some(public_key_hex)) => {
                let bytes = hex::decode(public_key_hex).with_context(|| {
                    format!(
                        "http.notify_auth.service_principals.{did}.signature_public_key_hex must be hex"
                    )
                })?;
                if bytes.len() != 32 {
                    bail!(
                        "http.notify_auth.service_principals.{did}.signature_public_key_hex must encode 32 bytes"
                    );
                }
            }
            (None, None) => {}
            _ => {
                bail!(
                    "http.notify_auth.service_principals.{did} must set both signature_key_id and signature_public_key_hex or neither"
                );
            }
        }
        if self.require_mtls
            && self
                .mtls_cert_fingerprints
                .iter()
                .any(|value| value.trim().is_empty())
        {
            bail!(
                "http.notify_auth.service_principals.{did}.mtls_cert_fingerprints must not contain empty values"
            );
        }
        validate_bearer_token_hashes(
            &format!("http.notify_auth.service_principals.{did}.bearer_token_hashes"),
            &self.bearer_token_hashes,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NotifyRateLimitConfig {
    pub window_seconds: u64,
    pub per_origin_service: Option<u64>,
    pub per_app_id: Option<u64>,
    pub per_provider: Option<u64>,
    pub per_push_key_hash: Option<u64>,
    pub per_endpoint: Option<u64>,
    /// P5 — per-provider concurrent in-flight cap. Limits how many
    /// notify dispatches can be simultaneously running against any
    /// single provider (e.g. "apns_prod", "fcm_internal"). Defaults
    /// to 100 to prevent a single misbehaving provider from
    /// monopolising the dispatch worker pool. `Some(0)` disables the
    /// cap; `None` falls back to the 100 default.
    pub per_provider_concurrency: Option<u64>,
    pub backend: String,
    pub redis_url: Option<String>,
    pub key_prefix: String,
    /// `strict` (default) — fail-closed: reject with 429 so callers back
    /// off when Redis is unreachable. `permissive` opts into fail-open
    /// (rate limiting silently disabled during a Redis outage).
    pub redis_failure_policy: String,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for NotifyRateLimitConfig {
    fn default() -> Self {
        Self {
            window_seconds: 60,
            per_origin_service: None,
            per_app_id: None,
            per_provider: None,
            per_push_key_hash: None,
            per_endpoint: None,
            per_provider_concurrency: Some(100),
            backend: "memory".to_owned(),
            redis_url: None,
            key_prefix: "floria".to_owned(),
            redis_failure_policy: "strict".to_owned(),
            extra: Map::new(),
        }
    }
}

impl NotifyRateLimitConfig {
    pub fn enabled(&self) -> bool {
        [
            self.per_origin_service,
            self.per_app_id,
            self.per_provider,
            self.per_push_key_hash,
            self.per_endpoint,
        ]
        .into_iter()
        .flatten()
        .any(|limit| limit > 0)
    }

    pub fn backend_kind(&self) -> &str {
        let backend = self.backend.trim();
        if backend.is_empty() {
            "memory"
        } else {
            backend
        }
    }

    pub fn key_prefix(&self) -> &str {
        let value = self.key_prefix.trim();
        if value.is_empty() { "floria" } else { value }
    }

    pub fn failure_policy(&self) -> &str {
        let value = self.redis_failure_policy.trim();
        if value.is_empty() { "strict" } else { value }
    }

    pub fn validate(&self) -> Result<()> {
        match self.backend_kind() {
            "memory" => {}
            "redis" => {
                if self
                    .redis_url
                    .as_deref()
                    .map(str::trim)
                    .is_none_or(|value| value.is_empty())
                {
                    bail!("http.notify_rate_limits.redis_url is required when backend=redis");
                }
            }
            backend => {
                bail!(
                    "http.notify_rate_limits.backend must be one of: memory, redis; got `{backend}`"
                );
            }
        }
        match self.failure_policy() {
            "permissive" | "strict" => {}
            other => {
                bail!(
                    "http.notify_rate_limits.redis_failure_policy must be one of: permissive, strict; got `{other}`"
                );
            }
        }
        Ok(())
    }

    fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "http.notify_rate_limits",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NotifyRetryQueueConfig {
    pub enabled: bool,
    pub backend: String,
    pub redis_url: Option<String>,
    pub key_prefix: String,
    pub max_attempts: u32,
    pub default_backoff_seconds: u64,
    pub max_backoff_seconds: u64,
    pub dead_letter_capacity: u32,
    pub poll_interval_ms: u64,
    pub batch_size: u32,
    /// AEAD key (ChaCha20-Poly1305) for envelopes persisted on a Redis
    /// retry queue. The key material is hashed with SHA-256, so any
    /// non-empty string is acceptable; rotating the key invalidates
    /// every in-flight retry, so operators should drain the queue
    /// first or accept the loss as a deliberate forgetting event.
    /// Empty string (the default) disables encryption — backwards
    /// compatible with existing deployments.
    pub encryption_key: String,
    /// Path to a file containing the AEAD key material. Mutually
    /// exclusive with `encryption_key`; both unset means no
    /// encryption.
    pub encryption_key_file: Option<String>,
    /// Grace period (seconds) the main task waits for the retry worker
    /// to finish in-flight dispatches at shutdown. Default 30s.
    pub grace_period_secs: u64,
    /// Optional PostgreSQL URL for the dead-letter overlay. When set,
    /// every envelope that drops into the dead-letter ring is ALSO
    /// persisted to the `floria_retry_dead_letter` table so it survives
    /// a process restart. The in-memory ring stays authoritative for
    /// `dead_letter_snapshot()` — the PG overlay is operator-facing
    /// audit only. Field name on the wire is `deadletter_pg_url`.
    #[serde(default, alias = "deadletter_pg_url")]
    pub deadletter_pg_url: Option<String>,
    /// Override the PG table the deadletter overlay writes into.
    /// Defaults to `floria_retry_dead_letter`. Same shape rules as
    /// `storage.deactivation_queue_table`.
    #[serde(default = "default_deadletter_pg_table")]
    pub deadletter_pg_table: String,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

fn default_deadletter_pg_table() -> String {
    "floria_retry_dead_letter".to_owned()
}

impl Default for NotifyRetryQueueConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: "memory".to_owned(),
            redis_url: None,
            key_prefix: "floria".to_owned(),
            max_attempts: 5,
            default_backoff_seconds: 30,
            max_backoff_seconds: 15 * 60,
            dead_letter_capacity: 1024,
            poll_interval_ms: 1_000,
            batch_size: 32,
            encryption_key: String::new(),
            encryption_key_file: None,
            grace_period_secs: 30,
            deadletter_pg_url: None,
            deadletter_pg_table: default_deadletter_pg_table(),
            extra: Map::new(),
        }
    }
}

impl NotifyRetryQueueConfig {
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn grace_period(&self) -> Duration {
        Duration::from_secs(self.grace_period_secs.max(1))
    }

    /// Load the AEAD key material from inline config or external file.
    /// Returns `None` when no encryption is configured.
    pub fn encryption_key_material(&self) -> Result<Option<Vec<u8>>> {
        let inline = self.encryption_key.trim();
        if !inline.is_empty() {
            return Ok(Some(inline.as_bytes().to_vec()));
        }
        if let Some(path) = self
            .encryption_key_file
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let bytes = fs::read(path).with_context(|| {
                format!("failed to read notify_retry_queue.encryption_key_file `{path}`")
            })?;
            if bytes.iter().all(u8::is_ascii_whitespace) {
                bail!("http.notify_retry_queue.encryption_key_file is empty");
            }
            return Ok(Some(bytes));
        }
        Ok(None)
    }

    pub fn backend_kind(&self) -> &str {
        let backend = self.backend.trim();
        if backend.is_empty() {
            "memory"
        } else {
            backend
        }
    }

    pub fn key_prefix(&self) -> &str {
        let value = self.key_prefix.trim();
        if value.is_empty() { "floria" } else { value }
    }

    /// Returns the trimmed deadletter PG URL when set and non-blank.
    pub fn deadletter_pg_url(&self) -> Option<&str> {
        self.deadletter_pg_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    /// Returns the deadletter PG table name (defaults to
    /// `floria_retry_dead_letter`).
    pub fn deadletter_pg_table(&self) -> &str {
        let value = self.deadletter_pg_table.trim();
        if value.is_empty() {
            "floria_retry_dead_letter"
        } else {
            value
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.max_attempts == 0 {
            bail!("http.notify_retry_queue.max_attempts must be >= 1");
        }
        if self.default_backoff_seconds == 0 {
            bail!("http.notify_retry_queue.default_backoff_seconds must be >= 1");
        }
        if self.max_backoff_seconds < self.default_backoff_seconds {
            bail!("http.notify_retry_queue.max_backoff_seconds must be >= default_backoff_seconds");
        }
        // Deadletter PG overlay is optional; when set it must be a valid
        // libpq URL + a valid SQL identifier for the table.
        if let Some(url) = self.deadletter_pg_url() {
            crate::postgres_support::validate_postgres_url(
                url,
                "http.notify_retry_queue.deadletter_pg_url",
            )?;
            crate::postgres_support::SqlTableName::parse(
                self.deadletter_pg_table(),
                "http.notify_retry_queue.deadletter_pg_table",
            )?;
        }
        match self.backend_kind() {
            "memory" => Ok(()),
            "redis" => {
                if self
                    .redis_url
                    .as_deref()
                    .map(str::trim)
                    .is_none_or(|value| value.is_empty())
                {
                    bail!("http.notify_retry_queue.redis_url is required when backend=redis");
                }
                Ok(())
            }
            backend => bail!(
                "http.notify_retry_queue.backend must be one of: memory, redis; got `{backend}`"
            ),
        }
    }

    fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "http.notify_retry_queue",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }
}

fn validate_bearer_token_hashes(scope: &str, hashes: &[String]) -> Result<()> {
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
    fn emit_startup_warnings(&self) {
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
    fn emit_startup_warnings(&self) {
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
    fn emit_startup_warnings(&self) {
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
    fn emit_startup_warnings(&self) {
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
    fn emit_startup_warnings(&self) {
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

// --- Schema artifact ---

/// Returns the JSON schema for `floria.{kdl,yaml}` configuration.
///
/// Both YAML and KDL deserialize through the same `Config` struct, so a
/// single schema document covers both formats. Consumers (ops tooling,
/// editor tooling, soland config drift detection) should refresh when
/// `Config::SCHEMA_VERSION` changes.
pub fn config_json_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://cokret.dev/schema/floria/2026-06-03.1/floria.config.schema.json",
        "title": "floria gateway configuration",
        "description": "Schema for floria.kdl / floria.yaml; KDL is parsed to JSON via the same shape before deserialization.",
        "type": "object",
        "x-floria-schema-version": Config::SCHEMA_VERSION,
        "additionalProperties": false,
        "properties": {
            "http": http_schema(),
            "audit": audit_schema(),
            "storage": storage_schema(),
            "log": log_schema(),
            "metrics": metrics_schema(),
            "proxy": {"type": ["string", "null"], "description": "Outbound proxy URL for APNs/FCM/WebPush. Falls back to HTTPS_PROXY env."},
            "apps": {
                "type": "object",
                "additionalProperties": app_config_schema(),
                "description": "Map of app identifiers to provider configuration."
            }
        }
    })
}

fn storage_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "description": "Optional PostgreSQL storage for deactivation queue draining and push-contact PSI cache persistence.",
        "properties": {
            "postgres_url": {
                "type": ["string", "null"],
                "description": "PostgreSQL connection URL. When unset, deactivation bookkeeping and push-contact cache are in-memory only."
            },
            "deactivation_queue_table": {
                "type": "string",
                "default": "floria_push_delivery_queue",
                "description": "Table drained by account_deactivate_fanout. Must be `table` or `schema.table` with simple SQL identifiers."
            },
            "push_contact_cache_table": {
                "type": "string",
                "default": "floria_push_contact_cache",
                "description": "Table used by the PostgreSQL push-contact PSI cache overlay. Must be `table` or `schema.table` with simple SQL identifiers."
            }
        }
    })
}

fn audit_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "description": "Audit sink for policy-access and rejected-device events. disabled keeps audit events unavailable; file writes local JSONL; http POSTs JSON to the soland audit endpoint.",
        "properties": {
            "backend": {"type": "string", "enum": ["disabled", "file", "http"], "default": "disabled"},
            "file_path": {
                "type": ["string", "null"],
                "description": "JSONL file path used when backend=file. Relative paths resolve against the config file directory."
            },
            "endpoint": {
                "type": ["string", "null"],
                "format": "uri",
                "description": "HTTP(S) endpoint used when backend=http. floria POSTs the audit event JSON body to this URL."
            },
            "bearer_token": {
                "type": ["string", "null"],
                "description": "Optional bearer token for backend=http."
            }
        }
    })
}

fn http_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 5000},
            "bind_addresses": {
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}, "minItems": 1}
                ],
                "default": "127.0.0.1"
            },
            "notify_dedup_ttl_seconds": {"type": "integer", "minimum": 0, "default": 0},
            "notify_dedup": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "backend": {"type": "string", "enum": ["memory", "redis"], "default": "memory"},
                    "redis_url": {"type": ["string", "null"]},
                    "key_prefix": {"type": "string", "default": "floria"}
                }
            },
            "notify_auth": notify_auth_schema(),
            "internal_auth": internal_auth_schema(),
            "notify_rate_limits": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "window_seconds": {"type": "integer", "minimum": 1, "default": 60},
                    "per_origin_service": {"type": ["integer", "null"], "minimum": 0},
                    "per_app_id": {"type": ["integer", "null"], "minimum": 0},
                    "per_provider": {"type": ["integer", "null"], "minimum": 0},
                    "per_push_key_hash": {"type": ["integer", "null"], "minimum": 0},
                    "per_endpoint": {"type": ["integer", "null"], "minimum": 0},
                    "per_provider_concurrency": {
                        "type": ["integer", "null"],
                        "minimum": 0,
                        "default": 100,
                        "description": "Max concurrent in-flight notify dispatches per provider. 0 disables; null falls back to the 100 default."
                    },
                    "backend": {"type": "string", "enum": ["memory", "redis"], "default": "memory"},
                    "redis_url": {"type": ["string", "null"]},
                    "key_prefix": {"type": "string", "default": "floria"},
                    "redis_failure_policy": {"type": "string", "enum": ["strict", "permissive"], "default": "strict"}
                }
            },
            "notify_retry_queue": {
                "type": "object",
                "additionalProperties": false,
                "description": "Retry / dead-letter queue for transient pushkin failures.",
                "properties": {
                    "enabled": {"type": "boolean", "default": false},
                    "backend": {"type": "string", "enum": ["memory", "redis"], "default": "memory"},
                    "redis_url": {"type": ["string", "null"]},
                    "key_prefix": {"type": "string", "default": "floria"},
                    "max_attempts": {"type": "integer", "minimum": 1, "default": 5},
                    "default_backoff_seconds": {"type": "integer", "minimum": 1, "default": 30},
                    "max_backoff_seconds": {"type": "integer", "minimum": 1, "default": 900},
                    "dead_letter_capacity": {"type": "integer", "minimum": 1, "default": 1024},
                    "poll_interval_ms": {"type": "integer", "minimum": 100, "default": 1000},
                    "batch_size": {"type": "integer", "minimum": 1, "default": 32},
                    "encryption_key": {"type": "string", "default": ""},
                    "encryption_key_file": {"type": ["string", "null"]},
                    "grace_period_secs": {"type": "integer", "minimum": 1, "default": 30},
                    "deadletter_pg_url": {
                        "type": ["string", "null"],
                        "description": "Optional PostgreSQL URL for the dead-letter overlay. When set, every dead-lettered envelope is also persisted to `deadletter_pg_table` so it survives a process restart."
                    },
                    "deadletter_pg_table": {
                        "type": "string",
                        "default": "floria_retry_dead_letter",
                        "description": "Table the deadletter overlay writes into. Must be `table` or `schema.table` with simple SQL identifiers."
                    }
                }
            },
            "metrics_detailed_circle_labels": {
                "type": "boolean",
                "default": false,
                "description": "CXP-0007 Circle primitive. When true, the per-(provider, scope) delivery counter (floria_notify_delivery_total) labels scope_id with the circle_id instead of the parent realm_id. Default false bounds label cardinality by realm count."
            },
            "circle_rate_limits": {
                "type": "object",
                "additionalProperties": false,
                "description": "CXP-0007 Circle primitive. Per-Circle rate-limit caps applied on top of notify_rate_limits. Both knobs default to null (no per-Circle cap).",
                "properties": {
                    "per_circle_qps": {
                        "type": ["integer", "null"],
                        "minimum": 0,
                        "description": "Max sustained notify QPS for a single Circle."
                    },
                    "per_circle_concurrency": {
                        "type": ["integer", "null"],
                        "minimum": 0,
                        "description": "Max in-flight notify dispatches for a single Circle."
                    }
                }
            }
        }
    })
}

fn internal_auth_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "description": "Bearer/shared-secret authentication for internal and operator-only endpoints. When no token or hash is configured, those endpoints fail closed.",
        "properties": {
            "bearer_tokens": string_or_string_list_schema(),
            "bearer_token_hashes": {
                "description": "Plain or `sha256:`-prefixed 32-byte hex digests of internal bearer tokens.",
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}}
                ]
            }
        }
    })
}

fn notify_auth_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "bearer_tokens": string_or_string_list_schema(),
            "bearer_token_hashes": {
                "description": "Plain or `sha256:`-prefixed 32-byte hex digests of bearer tokens.",
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}}
                ]
            },
            "trusted_service_dids": string_or_string_list_schema(),
            "plaintext_metadata_service_dids": string_or_string_list_schema(),
            "gateway_service_did": {"type": ["string", "null"]},
            "require_message_signatures": {"type": "boolean", "default": false},
            "signature_max_skew_seconds": {"type": "integer", "minimum": 1, "default": 300},
            "mtls_verified_header": {"type": "string", "default": "x-client-certificate-verified"},
            "mtls_fingerprint_header": {"type": "string", "default": "x-client-certificate-sha256"},
            "mtls_subject_dn_header": {"type": "string", "default": "x-client-certificate-subject"},
            "mtls_subject_alt_names_header": {"type": "string", "default": "x-client-certificate-san"},
            "production_mode": {
                "type": "boolean",
                "default": false,
                "description": "When true, refuses to start in profiles that allow anonymous or bearer-only auth without HTTP Message Signature/mTLS."
            },
            "bind_bearer_to_origin_did": {
                "type": "boolean",
                "default": false,
                "description": "When true, gateway-wide bearer tokens are rejected; the bearer must match a per-principal token for the declared origin_service_did."
            },
            "service_principals": {
                "type": "object",
                "additionalProperties": service_principal_schema()
            },
            "nonce_store": {
                "type": "object",
                "additionalProperties": false,
                "description": "HTTP Message Signature replay-protection nonce store. Memory backend is single-instance; redis backend shares state across replicas.",
                "properties": {
                    "backend": {"type": "string", "enum": ["memory", "redis"], "default": "memory"},
                    "redis_url": {"type": ["string", "null"]},
                    "key_prefix": {"type": "string", "default": "floria"},
                    "redis_failure_policy": {"type": "string", "enum": ["strict", "permissive"], "default": "strict"}
                }
            },
            "replay_window_seconds": {
                "type": "integer",
                "minimum": 0,
                "default": 0,
                "description": "How long to remember a verified Signature fingerprint for replay rejection. 0 disables replay protection."
            }
        }
    })
}

fn service_principal_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "service_type": {"type": ["string", "null"]},
            "allow_plaintext_metadata": {"type": "boolean", "default": false},
            "bearer_tokens": string_or_string_list_schema(),
            "bearer_token_hashes": string_or_string_list_schema(),
            "signature_key_id": {"type": ["string", "null"]},
            "signature_public_key_hex": {"type": ["string", "null"], "pattern": "^[0-9a-fA-F]{64}$"},
            "require_mtls": {"type": "boolean", "default": false},
            "mtls_cert_fingerprints": string_or_string_list_schema(),
            "mtls_subject_dn": {"type": ["string", "null"]},
            "mtls_subject_alt_names": string_or_string_list_schema(),
            "service_endpoint": {"type": ["string", "null"]}
        }
    })
}

fn log_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "access": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "x_forwarded_for": {"type": "boolean", "default": false}
                }
            },
            "setup": {
                "type": "object",
                "additionalProperties": false,
                "description": "tracing-subscriber setup. Controls the global subscriber installed at startup.",
                "properties": {
                    "level": {
                        "type": "string",
                        "enum": ["trace", "debug", "info", "warn", "error"],
                        "default": "info"
                    },
                    "format": {
                        "type": "string",
                        "enum": ["text", "json"],
                        "default": "text"
                    },
                    "filter": {
                        "type": ["string", "null"],
                        "description": "Optional EnvFilter directive (e.g. `floria=debug,tower_http=info`). Falls back to RUST_LOG, then `level`."
                    }
                }
            }
        }
    })
}

fn metrics_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "prometheus": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "enabled": {"type": "boolean", "default": false},
                    "address": {"type": "string", "default": "127.0.0.1"},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 8000}
                }
            },
            "opentracing": {
                "type": "object",
                "additionalProperties": false,
                "description": "OpenTelemetry / OTLP span exporter (gRPC).",
                "properties": {
                    "enabled": {"type": "boolean", "default": false},
                    "endpoint": {
                        "type": ["string", "null"],
                        "description": "OTLP gRPC endpoint (e.g. http://otel-collector:4317). Required when enabled."
                    },
                    "service_name": {"type": "string", "default": "floria"},
                    "sample_rate": {"type": "number", "minimum": 0, "maximum": 1, "default": 1.0},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "default": 10},
                    "implementation": {
                        "type": ["string", "null"],
                        "description": "Reserved for future tracer back-ends; currently OTLP/gRPC is the only supported implementation. Existing values like `jaeger` are accepted but ignored."
                    }
                }
            },
            "sentry": {
                "type": "object",
                "additionalProperties": false,
                "description": "Sentry error capture via the tracing subscriber.",
                "properties": {
                    "enabled": {"type": "boolean", "default": false},
                    "dsn": {"type": ["string", "null"], "description": "Sentry DSN. Required when enabled."},
                    "environment": {"type": ["string", "null"]},
                    "release": {"type": ["string", "null"]},
                    "sample_rate": {"type": "number", "minimum": 0, "maximum": 1, "default": 1.0},
                    "traces_sample_rate": {"type": "number", "minimum": 0, "maximum": 1, "default": 0.0}
                }
            }
        }
    })
}

fn app_config_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "required": ["type"],
        "properties": {
            "type": {
                "type": "string",
                "enum": [
                    "apns",
                    "custom",
                    "fcm",
                    "honor",
                    "huawei",
                    "jpush",
                    "oneplus",
                    "oppo",
                    "vivo",
                    "webpush",
                    "xiaomi"
                ]
            },
            "inflight_request_limit": {"type": "integer", "minimum": 1, "default": 512},
            "max_connections": {"type": "integer", "minimum": 1, "default": 20}
        },
        "additionalProperties": true,
        "description": "Per-provider keys are passed through; required fields differ per `type` and are validated at startup."
    })
}

fn string_or_string_list_schema() -> Value {
    serde_json::json!({
        "oneOf": [
            {"type": "string"},
            {"type": "array", "items": {"type": "string"}}
        ]
    })
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
        parse_kdl_to_json(body)
    }
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
        assert_eq!(config.http.notify_dedup.backend_kind(), "memory");
        assert_eq!(config.audit.backend_kind(), "disabled");
        assert!(!config.storage.postgres_enabled());
        assert_eq!(
            config.storage.deactivation_queue_table(),
            "floria_push_delivery_queue"
        );
        assert!(!config.http.notify_rate_limits.enabled());
        assert!(!config.http.internal_auth.enabled());
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
            notify_dedup: NotifyDedupConfig::default(),
            notify_auth: NotifyAuthConfig::default(),
            internal_auth: InternalAuthConfig::default(),
            notify_rate_limits: NotifyRateLimitConfig::default(),
            notify_retry_queue: NotifyRetryQueueConfig::default(),
            metrics_detailed_circle_labels: false,
            circle_rate_limits: CircleRateLimitConfig::default(),
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
            notify_dedup: NotifyDedupConfig::default(),
            notify_auth: NotifyAuthConfig::default(),
            internal_auth: InternalAuthConfig::default(),
            notify_rate_limits: NotifyRateLimitConfig::default(),
            notify_retry_queue: NotifyRetryQueueConfig::default(),
            metrics_detailed_circle_labels: false,
            circle_rate_limits: CircleRateLimitConfig::default(),
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
    notify_rate_limits {
        window_seconds 30
        per_origin_service 10
        per_app_id 20
    }
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
        assert_eq!(config.http.notify_rate_limits.window_seconds, 30);
        assert_eq!(config.http.notify_rate_limits.per_origin_service, Some(10));
        assert_eq!(config.http.notify_rate_limits.per_app_id, Some(20));
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
        assert!(!config.http.notify_rate_limits.enabled());
        assert!(!config.metrics.prometheus.enabled);
    }

    #[test]
    fn validate_rejects_unknown_notify_dedup_backend() {
        let mut config = Config::default();
        config.http.notify_dedup.backend = "sqlite".to_owned();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("http.notify_dedup.backend must be one of"));
    }

    #[test]
    fn validate_requires_redis_url_for_redis_notify_dedup_backend() {
        let mut config = Config::default();
        config.http.notify_dedup_ttl_seconds = 60;
        config.http.notify_dedup.backend = "redis".to_owned();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("http.notify_dedup.redis_url is required"));
    }

    #[test]
    fn validate_requires_file_path_for_file_audit_backend() {
        let mut config = Config::default();
        config.audit.backend = "file".to_owned();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("audit.file_path is required"));
    }

    #[test]
    fn validate_requires_http_url_for_http_audit_backend() {
        let mut config = Config::default();
        config.audit.backend = "http".to_owned();
        config.audit.endpoint = Some("mailto:audit@example.com".to_owned());

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("audit.endpoint must use http or https"));
    }

    #[test]
    fn validate_rejects_unsafe_storage_table_names() {
        let mut config = Config::default();
        config.storage.push_contact_cache_table = "floria.cache;drop".to_owned();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("storage.push_contact_cache_table"));
    }

    #[test]
    fn validate_requires_service_principals_for_required_signatures() {
        let mut config = Config::default();
        config.http.notify_auth.require_message_signatures = true;

        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("require_message_signatures requires at least one service_principal")
        );
    }

    #[test]
    fn parses_plaintext_metadata_service_dids_and_endpoint_rate_limit() {
        let config: Config = serde_saphyr::from_str(
            r#"
http:
  notify_auth:
    plaintext_metadata_service_dids: did:web:sync.example.com
  notify_rate_limits:
    per_endpoint: 10
apps: {}
"#,
        )
        .unwrap();

        assert_eq!(
            config.http.notify_auth.plaintext_metadata_service_dids,
            vec!["did:web:sync.example.com"]
        );
        assert_eq!(config.http.notify_rate_limits.per_endpoint, Some(10));
    }

    #[test]
    fn validate_rejects_malformed_bearer_token_hash() {
        let mut config = Config::default();
        config.http.notify_auth.bearer_token_hashes = vec!["not-hex".to_owned()];

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("bearer_token_hashes"));
    }

    #[test]
    fn validate_rejects_malformed_internal_bearer_token_hash() {
        let mut config = Config::default();
        config.http.internal_auth.bearer_token_hashes = vec!["not-hex".to_owned()];

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("http.internal_auth.bearer_token_hashes"));
    }

    #[test]
    fn parses_internal_auth_hashes() {
        let config: Config = serde_saphyr::from_str(
            r#"
http:
  internal_auth:
    bearer_token_hashes: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
apps: {}
"#,
        )
        .unwrap();

        assert!(config.http.internal_auth.enabled());
        assert_eq!(
            config.http.internal_auth.bearer_token_hashes,
            vec!["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        );
    }

    #[test]
    fn production_mode_requires_signed_or_mtls_principal() {
        let mut config = Config::default();
        config.http.notify_auth.production_mode = true;
        config.http.notify_auth.gateway_service_did = Some("did:web:push.example.com".to_owned());
        let principal = NotifyServicePrincipalConfig {
            bearer_tokens: vec!["principal-token".to_owned()],
            ..Default::default()
        };
        config
            .http
            .notify_auth
            .service_principals
            .insert("did:web:sync.example.com".to_owned(), principal);

        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("HTTP Message Signature or require_mtls"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn production_mode_rejects_gateway_wide_bearer_tokens() {
        let mut config = Config::default();
        config.http.notify_auth.production_mode = true;
        config.http.notify_auth.gateway_service_did = Some("did:web:push.example.com".to_owned());
        config.http.notify_auth.bearer_tokens = vec!["gateway-token".to_owned()];
        let principal = NotifyServicePrincipalConfig {
            signature_key_id: Some("did:web:sync.example.com#push".to_owned()),
            signature_public_key_hex: Some("a".repeat(64)),
            ..Default::default()
        };
        config
            .http
            .notify_auth
            .service_principals
            .insert("did:web:sync.example.com".to_owned(), principal);

        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("rejects gateway-wide bearer_tokens"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn production_mode_rejects_plaintext_service_principal_bearer_tokens() {
        let mut config = Config::default();
        config.http.notify_auth.production_mode = true;
        config.http.notify_auth.gateway_service_did = Some("did:web:push.example.com".to_owned());
        let principal = NotifyServicePrincipalConfig {
            bearer_tokens: vec!["principal-token".to_owned()],
            signature_key_id: Some("did:web:sync.example.com#push".to_owned()),
            signature_public_key_hex: Some("d".repeat(64)),
            ..Default::default()
        };
        config
            .http
            .notify_auth
            .service_principals
            .insert("did:web:sync.example.com".to_owned(), principal);

        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains(
                "rejects plaintext bearer_tokens on service_principals.did:web:sync.example.com"
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn production_mode_rejects_plaintext_for_non_eligible_kind() {
        let mut config = Config::default();
        config.http.notify_auth.production_mode = true;
        config.http.notify_auth.gateway_service_did = Some("did:web:push.example.com".to_owned());
        let principal = NotifyServicePrincipalConfig {
            signature_key_id: Some("did:web:sync.example.com#push".to_owned()),
            signature_public_key_hex: Some("b".repeat(64)),
            allow_plaintext_metadata: true,
            service_type: Some("external_pusher".to_owned()),
            ..Default::default()
        };
        config
            .http
            .notify_auth
            .service_principals
            .insert("did:web:sync.example.com".to_owned(), principal);

        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("rejects allow_plaintext_metadata for service_type"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn production_mode_accepts_signed_eligible_principal() {
        let mut config = Config::default();
        config.http.notify_auth.production_mode = true;
        config.http.notify_auth.gateway_service_did = Some("did:web:push.example.com".to_owned());
        let principal = NotifyServicePrincipalConfig {
            signature_key_id: Some("did:web:sync.example.com#push".to_owned()),
            signature_public_key_hex: Some("c".repeat(64)),
            allow_plaintext_metadata: true,
            service_type: Some("sync".to_owned()),
            ..Default::default()
        };
        config
            .http
            .notify_auth
            .service_principals
            .insert("did:web:sync.example.com".to_owned(), principal);

        config
            .validate()
            .expect("eligible production principal must validate");
    }

    #[test]
    fn schema_artifact_matches_committed_snapshot() {
        let snapshot_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("floria.config.schema.json");
        let live = serde_json::to_string_pretty(&config_json_schema()).unwrap();
        let on_disk = std::fs::read_to_string(&snapshot_path).expect(
            "floria.config.schema.json missing — refresh with `cargo run --example emit_schema > floria.config.schema.json`",
        );
        let on_disk = on_disk.trim_end_matches(['\n', '\r']);
        assert_eq!(
            live.trim_end_matches(['\n', '\r']),
            on_disk,
            "floria.config.schema.json is stale — refresh with `cargo run --example emit_schema > floria.config.schema.json`"
        );
    }

    #[test]
    fn yaml_and_kdl_produce_equivalent_configs() {
        let yaml = r#"
http:
  port: 8080
  bind_addresses:
    - "0.0.0.0"
  notify_dedup_ttl_seconds: 30
  notify_dedup:
    backend: memory
    key_prefix: floria
  notify_rate_limits:
    window_seconds: 30
    per_origin_service: 10
    per_app_id: 20
metrics:
  prometheus:
    enabled: true
    address: "127.0.0.1"
    port: 9000
log:
  access:
    x_forwarded_for: true
apps:
  com.example.test:
    type: apns
    keyfile: "./test.p8"
    inflight_request_limit: 256
"#;
        let kdl = r#"
http {
    port 8080
    bind_addresses "0.0.0.0"
    notify_dedup_ttl_seconds 30
    notify_dedup {
        backend "memory"
        key_prefix "floria"
    }
    notify_rate_limits {
        window_seconds 30
        per_origin_service 10
        per_app_id 20
    }
}
metrics {
    prometheus {
        enabled #true
        address "127.0.0.1"
        port 9000
    }
}
log {
    access {
        x_forwarded_for #true
    }
}
apps {
    com.example.test {
        type "apns"
        keyfile "./test.p8"
        inflight_request_limit 256
    }
}
"#;

        let yaml_config: Config = serde_saphyr::from_str(yaml).unwrap();
        let kdl_json = parse_kdl_to_json(kdl).unwrap();
        let kdl_config: Config = serde_json::from_value(kdl_json).unwrap();

        // Compare via the public-shaped projection — both must produce
        // the same observable configuration.
        assert_eq!(yaml_config.http.port, kdl_config.http.port);
        assert_eq!(
            yaml_config.http.bind_addresses,
            kdl_config.http.bind_addresses
        );
        assert_eq!(
            yaml_config.http.notify_dedup_ttl_seconds,
            kdl_config.http.notify_dedup_ttl_seconds
        );
        assert_eq!(
            yaml_config.http.notify_dedup.backend_kind(),
            kdl_config.http.notify_dedup.backend_kind()
        );
        assert_eq!(
            yaml_config.http.notify_rate_limits.window_seconds,
            kdl_config.http.notify_rate_limits.window_seconds
        );
        assert_eq!(
            yaml_config.http.notify_rate_limits.per_origin_service,
            kdl_config.http.notify_rate_limits.per_origin_service
        );
        assert_eq!(
            yaml_config.http.notify_rate_limits.per_app_id,
            kdl_config.http.notify_rate_limits.per_app_id
        );
        assert_eq!(
            yaml_config.metrics.prometheus.enabled,
            kdl_config.metrics.prometheus.enabled
        );
        assert_eq!(
            yaml_config.metrics.prometheus.port,
            kdl_config.metrics.prometheus.port
        );
        assert_eq!(
            yaml_config.log.access.x_forwarded_for,
            kdl_config.log.access.x_forwarded_for
        );
        assert_eq!(yaml_config.apps.len(), kdl_config.apps.len());
        let yaml_app = yaml_config.apps.get("com.example.test").unwrap();
        let kdl_app = kdl_config.apps.get("com.example.test").unwrap();
        assert_eq!(yaml_app.kind, kdl_app.kind);
        assert_eq!(
            yaml_app.get_string("keyfile").unwrap(),
            kdl_app.get_string("keyfile").unwrap()
        );
        assert_eq!(
            yaml_app.get_u64("inflight_request_limit").unwrap(),
            kdl_app.get_u64("inflight_request_limit").unwrap()
        );
    }

    #[test]
    fn kdl_to_json_round_trip_preserves_nested_structure() {
        let kdl = r#"
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
        let parsed = parse_kdl_to_json(kdl).unwrap();
        let serialized = serde_json::to_string(&parsed).unwrap();
        let reparsed: Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed, reparsed);

        // Round-tripping through Config preserves the nested provider config.
        let config: Config = serde_json::from_value(parsed).unwrap();
        let app = config.apps.get("com.example.jpush").unwrap();
        let channel = app.get_object("third_party_channel").unwrap().unwrap();
        assert_eq!(
            channel
                .get("xiaomi")
                .and_then(|value| value.get("distribution"))
                .and_then(Value::as_str),
            Some("jpush"),
        );
        assert_eq!(
            channel
                .get("huawei")
                .and_then(|value| value.get("distribution"))
                .and_then(Value::as_str),
            Some("first_ospush"),
        );
    }
}
