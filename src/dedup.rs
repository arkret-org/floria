//! `/notify` deduplication and per-device delivery suppression.
//!
//! ## Multi-instance semantics
//!
//! When `backend = "redis"`, multiple gateway instances share state via
//! a single Redis endpoint. Keys are emitted with Redis cluster hash
//! tags (`{...}`) around the dynamic component so that every key for a
//! given idempotency-key (or canonical request fingerprint) routes to
//! the same shard. This keeps the lookup → mark-delivered → cache
//! sequence consistent under cluster routing without forcing a single
//! `MULTI/EXEC` slot.
//!
//! Concurrent requests with the same idempotency key race the lookup:
//!  - The first-arriving instance misses and dispatches.
//!  - Other instances arriving inside the dispatch window also miss.
//!  - The last completed dispatch wins the cache slot; the others may
//!    therefore double-dispatch in this rare window.
//!
//! Per-device delivery suppression (`mark_delivered_device`) applies
//! best-effort across the cluster: if a delivery races, both instances
//! may dispatch to the provider, but the second instance's dedupe key
//! prevents the third try in the same TTL.
//!
//! Failure mode: if Redis is unreachable, lookups return `None` and
//! conflicts return `false` (fail-open) so /notify keeps serving — the
//! invariants degrade to "in-process only" until Redis recovers.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use blake2::Blake2s256;
use blake2::digest::Digest;
use redis::Commands;

use crate::auth::redact_url_credentials;
use crate::models::NotifyResponse;

/// Lightweight status snapshot for the `GET /api/v1/push/status/{key}`
/// endpoint. Derived from the dedup cache when the request completed,
/// or from the retry queue when the request is still pending.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NotifyStatus {
    pub idempotency_key: String,
    pub status: &'static str,
    pub attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CachedNotifyResponse {
    pub response: NotifyResponse,
}

#[derive(Debug)]
struct CacheEntry {
    expires_at: Instant,
    request_fingerprint: String,
    response: CachedNotifyResponse,
}

#[derive(Debug)]
struct MemoryNotifyDeduplicator {
    entries: Mutex<HashMap<String, CacheEntry>>,
    delivered_devices: Mutex<HashMap<String, Instant>>,
}

#[derive(Debug)]
struct RedisNotifyDeduplicator {
    client: redis::Client,
    target_label: String,
    key_prefix: String,
}

#[derive(Debug)]
enum NotifyDedupBackend {
    Memory(MemoryNotifyDeduplicator),
    Redis(RedisNotifyDeduplicator),
}

#[derive(Debug)]
pub struct NotifyDeduplicator {
    ttl: Duration,
    backend: NotifyDedupBackend,
}

impl NotifyDeduplicator {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            backend: NotifyDedupBackend::Memory(MemoryNotifyDeduplicator {
                entries: Mutex::new(HashMap::new()),
                delivered_devices: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn redis(ttl: Duration, redis_url: &str, key_prefix: impl Into<String>) -> Result<Self> {
        let client = redis::Client::open(redis_url).with_context(|| {
            format!(
                "invalid notify_dedup redis_url `{}`",
                redact_url_credentials(redis_url)
            )
        })?;
        Ok(Self {
            ttl,
            backend: NotifyDedupBackend::Redis(RedisNotifyDeduplicator {
                client,
                target_label: redact_url_credentials(redis_url),
                key_prefix: normalize_key_prefix(&key_prefix.into()),
            }),
        })
    }

    pub fn backend_name(&self) -> &'static str {
        match self.backend {
            NotifyDedupBackend::Memory(_) => "memory",
            NotifyDedupBackend::Redis(_) => "redis",
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn ready(&self) -> Result<(), String> {
        match &self.backend {
            NotifyDedupBackend::Memory(_) => Ok(()),
            NotifyDedupBackend::Redis(backend) => {
                backend.ready().map_err(|error| error.to_string())
            }
        }
    }

    pub fn lookup(&self, key: &str, request_fingerprint: &str) -> Option<CachedNotifyResponse> {
        match &self.backend {
            NotifyDedupBackend::Memory(backend) => backend.lookup(key, request_fingerprint),
            NotifyDedupBackend::Redis(backend) => backend.lookup(key, request_fingerprint),
        }
    }

    pub fn conflicts(&self, key: &str, request_fingerprint: &str) -> bool {
        match &self.backend {
            NotifyDedupBackend::Memory(backend) => backend.conflicts(key, request_fingerprint),
            NotifyDedupBackend::Redis(backend) => backend.conflicts(key, request_fingerprint),
        }
    }

    pub fn insert_success(&self, key: &str, request_fingerprint: &str, response: NotifyResponse) {
        if self.ttl.is_zero() {
            return;
        }

        match &self.backend {
            NotifyDedupBackend::Memory(backend) => {
                backend.insert_success(self.ttl, key, request_fingerprint, response)
            }
            NotifyDedupBackend::Redis(backend) => {
                backend.insert_success(self.ttl, key, request_fingerprint, response)
            }
        }
    }

    pub fn contains_delivered_device(
        &self,
        notification_key: &str,
        app_id: &str,
        push_key: &str,
    ) -> bool {
        match &self.backend {
            NotifyDedupBackend::Memory(backend) => {
                backend.contains_delivered_device(notification_key, app_id, push_key)
            }
            NotifyDedupBackend::Redis(backend) => {
                backend.contains_delivered_device(notification_key, app_id, push_key)
            }
        }
    }

    pub fn mark_delivered_device(&self, notification_key: &str, app_id: &str, push_key: &str) {
        if self.ttl.is_zero() {
            return;
        }

        match &self.backend {
            NotifyDedupBackend::Memory(backend) => {
                backend.mark_delivered_device(self.ttl, notification_key, app_id, push_key)
            }
            NotifyDedupBackend::Redis(backend) => {
                backend.mark_delivered_device(self.ttl, notification_key, app_id, push_key)
            }
        }
    }

    /// In-process delivered-device cache size. Returns `None` for the
    /// Redis backend (operators should rely on Redis's own metrics
    /// there). Used to populate the
    /// `floria_device_dedup_cache_size` gauge.
    pub fn delivered_devices_len(&self) -> Option<usize> {
        match &self.backend {
            NotifyDedupBackend::Memory(backend) => Some(backend.delivered_devices_len()),
            NotifyDedupBackend::Redis(_) => None,
        }
    }

    /// Best-effort status lookup for the `/push/status/{key}` endpoint.
    /// Looks up the cached response (the dedup key is the
    /// idempotency-key hash). Returns `None` when nothing was cached
    /// for that key — callers should treat that as "unknown" (the
    /// request may still be in flight, may have been completed before
    /// dedup was enabled, or may have already expired).
    pub fn status_for(&self, key: &str) -> Option<NotifyStatus> {
        let response = match &self.backend {
            NotifyDedupBackend::Memory(backend) => backend.cached_response(key)?,
            NotifyDedupBackend::Redis(backend) => backend.cached_response(key)?,
        };
        let attempts = if response.provider_retries.is_empty() {
            1
        } else {
            (response.provider_retries.len() as u32).saturating_add(1)
        };
        let status = if response.rejected.is_empty() && response.accepted > 0 {
            "completed"
        } else if !response.rejected.is_empty() && response.accepted > 0 {
            "partial"
        } else if response.accepted == 0 && !response.rejected.is_empty() {
            "rejected"
        } else {
            "unknown"
        };
        let last_error = response
            .rejected
            .iter()
            .find_map(|rejected| rejected.reason.clone());
        Some(NotifyStatus {
            idempotency_key: key.to_owned(),
            status,
            attempts,
            last_error,
            request_id: Some(response.request_id),
        })
    }
}

impl MemoryNotifyDeduplicator {
    fn lookup(&self, key: &str, request_fingerprint: &str) -> Option<CachedNotifyResponse> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, entry| entry.expires_at > now);
        let entry = entries.get(key)?;
        (entry.request_fingerprint == request_fingerprint).then(|| entry.response.clone())
    }

    fn conflicts(&self, key: &str, request_fingerprint: &str) -> bool {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, entry| entry.expires_at > now);
        entries
            .get(key)
            .is_some_and(|entry| entry.request_fingerprint != request_fingerprint)
    }

    fn insert_success(
        &self,
        ttl: Duration,
        key: &str,
        request_fingerprint: &str,
        response: NotifyResponse,
    ) {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, entry| entry.expires_at > now);
        entries.insert(
            key.to_owned(),
            CacheEntry {
                expires_at: now + ttl,
                request_fingerprint: request_fingerprint.to_owned(),
                response: CachedNotifyResponse { response },
            },
        );
    }

    fn contains_delivered_device(
        &self,
        notification_key: &str,
        app_id: &str,
        push_key: &str,
    ) -> bool {
        let key = delivered_device_key(notification_key, app_id, push_key);
        let now = Instant::now();
        let mut entries = self
            .delivered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, expires_at| *expires_at > now);
        entries.contains_key(&key)
    }

    fn mark_delivered_device(
        &self,
        ttl: Duration,
        notification_key: &str,
        app_id: &str,
        push_key: &str,
    ) {
        let key = delivered_device_key(notification_key, app_id, push_key);
        let now = Instant::now();
        let mut entries = self
            .delivered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, expires_at| *expires_at > now);
        entries.insert(key, now + ttl);
    }

    fn cached_response(&self, key: &str) -> Option<NotifyResponse> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, entry| entry.expires_at > now);
        entries
            .get(key)
            .map(|entry| entry.response.response.clone())
    }

    fn delivered_devices_len(&self) -> usize {
        let now = Instant::now();
        let mut entries = self
            .delivered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, expires_at| *expires_at > now);
        entries.len()
    }
}

impl RedisNotifyDeduplicator {
    fn ready(&self) -> Result<()> {
        let mut connection = self.connection()?;
        let pong: String = redis::cmd("PING")
            .query(&mut connection)
            .with_context(|| format!("failed to ping Redis backend {}", self.target_label))?;
        if pong == "PONG" {
            Ok(())
        } else {
            anyhow::bail!(
                "Redis backend {} returned unexpected PING response `{pong}`",
                self.target_label
            );
        }
    }

    fn lookup(&self, key: &str, request_fingerprint: &str) -> Option<CachedNotifyResponse> {
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, "failed to query Redis notify dedup cache");
                return None;
            }
        };
        let response_key = self.response_key(key);
        let stored_fingerprint = match connection
            .hget::<_, _, Option<String>>(&response_key, "request_fingerprint")
        {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, redis_key = %response_key, "failed to load Redis notify dedup fingerprint");
                return None;
            }
        }?;
        if stored_fingerprint != request_fingerprint {
            return None;
        }
        let response_json = match connection.hget::<_, _, Option<String>>(&response_key, "response")
        {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, redis_key = %response_key, "failed to load Redis notify dedup response");
                return None;
            }
        }?;
        match serde_json::from_str::<NotifyResponse>(&response_json) {
            Ok(response) => Some(CachedNotifyResponse { response }),
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, redis_key = %response_key, "failed to deserialize cached Redis notify response");
                None
            }
        }
    }

    fn conflicts(&self, key: &str, request_fingerprint: &str) -> bool {
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, "failed to query Redis notify dedup cache");
                return false;
            }
        };
        let response_key = self.response_key(key);
        match connection.hget::<_, _, Option<String>>(&response_key, "request_fingerprint") {
            Ok(Some(stored_fingerprint)) => stored_fingerprint != request_fingerprint,
            Ok(None) => false,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, redis_key = %response_key, "failed to compare Redis notify dedup fingerprint");
                false
            }
        }
    }

    fn insert_success(
        &self,
        ttl: Duration,
        key: &str,
        request_fingerprint: &str,
        response: NotifyResponse,
    ) {
        let ttl_seconds = ttl_seconds(ttl);
        let response_key = self.response_key(key);
        let response_json = match serde_json::to_string(&response) {
            Ok(response_json) => response_json,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, "failed to serialize notify response for Redis dedup cache");
                return;
            }
        };
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, "failed to connect to Redis notify dedup cache");
                return;
            }
        };
        let result: redis::RedisResult<()> = redis::pipe()
            .hset(&response_key, "request_fingerprint", request_fingerprint)
            .ignore()
            .hset(&response_key, "response", response_json)
            .ignore()
            .expire(&response_key, ttl_seconds)
            .ignore()
            .query(&mut connection);
        if let Err(error) = result {
            tracing::warn!(error = %error, backend = %self.target_label, redis_key = %response_key, "failed to store Redis notify dedup response");
        }
    }

    fn contains_delivered_device(
        &self,
        notification_key: &str,
        app_id: &str,
        push_key: &str,
    ) -> bool {
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, "failed to connect to Redis notify dedup cache");
                return false;
            }
        };
        let delivered_key = self.delivered_key(notification_key, app_id, push_key);
        match connection.exists::<_, bool>(&delivered_key) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, redis_key = %delivered_key, "failed to query Redis delivered-device cache");
                false
            }
        }
    }

    fn mark_delivered_device(
        &self,
        ttl: Duration,
        notification_key: &str,
        app_id: &str,
        push_key: &str,
    ) {
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, "failed to connect to Redis notify dedup cache");
                return;
            }
        };
        let delivered_key = self.delivered_key(notification_key, app_id, push_key);
        let ttl_seconds = ttl_seconds(ttl);
        if let Err(error) = connection.set_ex::<_, _, ()>(&delivered_key, "1", ttl_seconds as u64) {
            tracing::warn!(error = %error, backend = %self.target_label, redis_key = %delivered_key, "failed to store Redis delivered-device cache entry");
        }
    }

    fn connection(&self) -> Result<redis::Connection> {
        self.client
            .get_connection()
            .with_context(|| format!("failed to connect to Redis backend {}", self.target_label))
    }

    fn cached_response(&self, key: &str) -> Option<NotifyResponse> {
        let mut connection = self.connection().ok()?;
        let response_key = self.response_key(key);
        let response_json: Option<String> = connection
            .hget::<_, _, Option<String>>(&response_key, "response")
            .ok()
            .flatten();
        let response_json = response_json?;
        serde_json::from_str::<NotifyResponse>(&response_json).ok()
    }

    /// Wrap the dynamic component of the key in Redis cluster hash
    /// tags (`{...}`) so every key derived from the same dedup key
    /// hashes to the same slot. In single-node Redis the braces are
    /// just literal characters and have no effect.
    fn response_key(&self, key: &str) -> String {
        format!("{}:notify:response:{{{key}}}", self.key_prefix)
    }

    fn delivered_key(&self, notification_key: &str, app_id: &str, push_key: &str) -> String {
        let key = delivered_device_key(notification_key, app_id, push_key);
        format!(
            "{}:notify:delivered:{{{notification_key}}}:{key}",
            self.key_prefix
        )
    }
}

pub fn request_hash(request_body: &[u8]) -> String {
    let mut hasher = Blake2s256::new();
    hasher.update(request_body);
    hex::encode(hasher.finalize())
}

fn delivered_device_key(notification_key: &str, app_id: &str, push_key: &str) -> String {
    let mut hasher = Blake2s256::new();
    hasher.update(notification_key.as_bytes());
    hasher.update([0]);
    hasher.update(app_id.as_bytes());
    hasher.update([0]);
    hasher.update(push_key.as_bytes());
    hex::encode(hasher.finalize())
}

fn ttl_seconds(ttl: Duration) -> i64 {
    ttl.as_secs().max(1).min(i64::MAX as u64) as i64
}

fn normalize_key_prefix(key_prefix: &str) -> String {
    let trimmed = key_prefix.trim();
    if trimmed.is_empty() {
        "floria".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    use crate::models::RejectedDevice;

    #[test]
    fn returns_inserted_response_before_expiry() {
        let dedup = NotifyDeduplicator::new(Duration::from_secs(5));
        let response = NotifyResponse {
            request_id: "request-1".to_owned(),
            accepted: 1,
            rejected: vec![RejectedDevice::new(Some("com.example.app"), "push_key")],
            provider_retries: vec![],
            delivery_receipts: vec![],
        };
        let key = request_hash(br#"{"notification":{}}"#);

        dedup.insert_success(&key, &key, response.clone());

        assert_eq!(
            dedup.lookup(&key, &key).map(|cached| cached.response),
            Some(response)
        );
    }

    #[test]
    fn expires_entries_after_ttl() {
        let dedup = NotifyDeduplicator::new(Duration::from_millis(1));
        let key = request_hash(br#"{"notification":{}}"#);
        dedup.insert_success(
            &key,
            &key,
            NotifyResponse {
                request_id: "request-1".to_owned(),
                accepted: 0,
                rejected: vec![],
                provider_retries: vec![],
                delivery_receipts: vec![],
            },
        );

        std::thread::sleep(Duration::from_millis(5));

        assert!(dedup.lookup(&key, &key).is_none());
    }

    #[test]
    fn remembers_delivered_devices_until_expiry() {
        let dedup = NotifyDeduplicator::new(Duration::from_secs(5));
        let notification_key = request_hash(br#"{"notification":{}}"#);

        dedup.mark_delivered_device(&notification_key, "com.example.app", "push_key");

        assert!(dedup.contains_delivered_device(&notification_key, "com.example.app", "push_key"));
    }

    #[test]
    fn detects_duplicate_conflict_for_different_request_body() {
        let dedup = NotifyDeduplicator::new(Duration::from_secs(5));
        let key = request_hash(b"idempotency-key");
        let first_fingerprint = request_hash(br#"{"notification":{"event_id":"first"}}"#);
        let second_fingerprint = request_hash(br#"{"notification":{"event_id":"second"}}"#);
        dedup.insert_success(
            &key,
            &first_fingerprint,
            NotifyResponse {
                request_id: "request-1".to_owned(),
                accepted: 1,
                rejected: vec![],
                provider_retries: vec![],
                delivery_receipts: vec![],
            },
        );

        assert!(dedup.lookup(&key, &first_fingerprint).is_some());
        assert!(dedup.conflicts(&key, &second_fingerprint));
    }

    #[test]
    fn redis_backend_requires_valid_url() {
        let error = NotifyDeduplicator::redis(Duration::from_secs(5), "://bad-url", "floria")
            .unwrap_err()
            .to_string();

        assert!(error.contains("invalid notify_dedup redis_url"));
    }

    #[test]
    #[ignore = "Redis-backed local load scaffold; set FLORIA_REDIS_DEDUP_LOAD_RUN=1 and FLORIA_REDIS_URL"]
    fn redis_dedup_ttl_load() -> Result<()> {
        if env::var("FLORIA_REDIS_DEDUP_LOAD_RUN").ok().as_deref() != Some("1") {
            eprintln!(
                "set FLORIA_REDIS_DEDUP_LOAD_RUN=1 and FLORIA_REDIS_URL to run the Redis TTL load scaffold"
            );
            return Ok(());
        }

        let redis_url = env::var("FLORIA_REDIS_URL")
            .context("FLORIA_REDIS_URL is required for redis_dedup_ttl_load")?;
        let samples = env_usize("FLORIA_REDIS_DEDUP_LOAD_SAMPLES", 1_000);
        let ttl = Duration::from_secs(env_usize("FLORIA_REDIS_DEDUP_TTL_SECONDS", 30) as u64);
        let key_prefix = format!("floria:test:dedup-load:{}", std::process::id());
        let dedup = NotifyDeduplicator::redis(ttl, &redis_url, key_prefix)?;
        let backend = match &dedup.backend {
            NotifyDedupBackend::Redis(backend) => backend,
            NotifyDedupBackend::Memory(_) => unreachable!("load scaffold requires Redis backend"),
        };
        let mut connection = backend.connection()?;
        let mut keys = Vec::with_capacity(samples * 2);

        for index in 0..samples {
            let key = format!("load-key-{index}");
            let fingerprint = request_hash(format!("request-{index}").as_bytes());
            dedup.insert_success(&key, &fingerprint, sample_response(index));

            let response_key = backend.response_key(&key);
            assert_redis_ttl(&mut connection, &response_key, ttl)?;
            keys.push(response_key);

            let push_key = format!("push-key-{index}");
            dedup.mark_delivered_device(&key, "com.example.mobile", &push_key);
            let delivered_key = backend.delivered_key(&key, "com.example.mobile", &push_key);
            assert_redis_ttl(&mut connection, &delivered_key, ttl)?;
            keys.push(delivered_key);
        }

        for chunk in keys.chunks(256) {
            let mut command = redis::cmd("DEL");
            for key in chunk {
                command.arg(key);
            }
            let _: i64 = command.query(&mut connection)?;
        }
        Ok(())
    }

    fn sample_response(index: usize) -> NotifyResponse {
        NotifyResponse {
            request_id: format!("request-{index}"),
            accepted: 1,
            rejected: vec![],
            provider_retries: vec![],
            delivery_receipts: vec![],
        }
    }

    fn assert_redis_ttl(
        connection: &mut redis::Connection,
        key: &str,
        expected: Duration,
    ) -> Result<()> {
        let actual = connection
            .ttl::<_, i64>(key)
            .with_context(|| format!("failed to query TTL for {key}"))?;
        let expected = ttl_seconds(expected);
        anyhow::ensure!(
            (1..=expected).contains(&actual),
            "Redis key {key} TTL {actual} was outside 1..={expected}"
        );
        Ok(())
    }

    fn env_usize(name: &str, default: usize) -> usize {
        env::var(name)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(default)
    }
}
