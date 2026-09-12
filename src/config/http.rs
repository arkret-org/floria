use std::fmt;

use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::notify::{NotifyDedupConfig, NotifyRateLimitConfig, NotifyRetryQueueConfig};
use super::notify_auth::NotifyAuthConfig;
use super::{
    normalize_listen_addr, string_or_vec, validate_bearer_token_hashes, warn_unknown_fields,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    pub port: u16,
    #[serde(deserialize_with = "string_or_vec")]
    pub bind_addresses: Vec<String>,
    /// Canonical public Arkret transport root advertised in ServiceDescribe.
    pub public_base_url: String,
    pub notify_dedup_ttl_seconds: u64,
    pub notify_dedup: NotifyDedupConfig,
    pub notify_auth: NotifyAuthConfig,
    pub registration_sources: std::collections::BTreeMap<
        arkret_wire::DidCoreId,
        crate::registrations::RegistrationSourceConfig,
    >,
    pub provider_timing_bucket_seconds: u64,
    pub internal_auth: InternalAuthConfig,
    pub notify_rate_limits: NotifyRateLimitConfig,
    pub notify_retry_queue: NotifyRetryQueueConfig,
    /// AKP-0007 Circle primitive — when `true`, the per-(provider,
    /// scope) delivery counter (`floria_notify_delivery_total`) labels
    /// `scope_id` with the `circle_id` instead of the parent
    /// `realm_id` when a Circle is set. Default `false` keeps the
    /// label cardinality bounded by realm count; operators only opt
    /// in for environments where per-Circle delivery dashboards are
    /// needed.
    #[serde(default)]
    pub metrics_detailed_circle_labels: bool,
    #[serde(flatten)]
    pub(super) extra: Map<String, Value>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            port: 5000,
            bind_addresses: vec!["127.0.0.1".to_owned()],
            public_base_url: "http://127.0.0.1:5000/".to_owned(),
            notify_dedup_ttl_seconds: 0,
            notify_dedup: NotifyDedupConfig::default(),
            notify_auth: NotifyAuthConfig::default(),
            registration_sources: Default::default(),
            provider_timing_bucket_seconds: 60,
            internal_auth: InternalAuthConfig::default(),
            notify_rate_limits: NotifyRateLimitConfig::default(),
            notify_retry_queue: NotifyRetryQueueConfig::default(),
            metrics_detailed_circle_labels: false,
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

    pub(super) fn emit_startup_warnings(&self) {
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
        let public_base_url = reqwest::Url::parse(&self.public_base_url).map_err(|error| {
            anyhow::anyhow!("http.public_base_url must be an absolute URL: {error}")
        })?;
        if !matches!(public_base_url.scheme(), "http" | "https")
            || public_base_url.host_str().is_none()
            || public_base_url.as_str() != self.public_base_url
            || !public_base_url.path().ends_with('/')
            || public_base_url.query().is_some()
            || public_base_url.fragment().is_some()
            || !public_base_url.username().is_empty()
            || public_base_url.password().is_some()
        {
            bail!(
                "http.public_base_url must be a canonical absolute HTTP(S) base URL with a trailing slash and no userinfo, query or fragment"
            );
        }
        if self.notify_auth.production_mode && public_base_url.scheme() != "https" {
            bail!("http.public_base_url must use https when notify_auth.production_mode=true");
        }
        self.notify_dedup.validate(self.notify_dedup_ttl_seconds)?;
        self.notify_auth.validate()?;
        for (source, registration) in &self.registration_sources {
            if !self
                .notify_auth
                .service_principals
                .contains_key(source.as_str())
            {
                bail!("registration source must name a configured authenticated service principal");
            }
            crate::postgres_support::validate_postgres_url(
                &registration.postgres_url,
                "registration_sources.postgres_url",
            )?;
        }
        self.internal_auth.validate()?;
        self.notify_rate_limits.validate()?;
        self.notify_retry_queue.validate()?;
        Ok(())
    }
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct InternalAuthConfig {
    #[serde(default, deserialize_with = "string_or_vec")]
    pub bearer_tokens: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub bearer_token_hashes: Vec<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl fmt::Debug for InternalAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bearer_tokens = format!("<redacted:{}>", self.bearer_tokens.len());
        f.debug_struct("InternalAuthConfig")
            .field("bearer_tokens", &bearer_tokens)
            .field("bearer_token_hashes", &self.bearer_token_hashes.len())
            .field("extra_keys", &self.extra.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl InternalAuthConfig {
    pub fn enabled(&self) -> bool {
        !self.bearer_tokens.is_empty() || !self.bearer_token_hashes.is_empty()
    }

    pub(super) fn emit_startup_warnings(&self) {
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
