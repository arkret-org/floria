use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::warn_unknown_fields;

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

    pub(super) fn emit_startup_warnings(&self) {
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
    pub batch_item_count: u32,
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
    #[serde(default)]
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
            batch_item_count: 32,
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

    pub(super) fn emit_startup_warnings(&self) {
        warn_unknown_fields(
            "http.notify_retry_queue",
            self.extra.keys().map(String::as_str).collect::<Vec<_>>(),
        );
    }
}
