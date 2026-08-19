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
//!  - The last completed dispatch wins the cache slot; the others may therefore double-dispatch in
//!    this rare window.
//!
//! Per-device delivery suppression (`mark_delivered_device`) applies
//! best-effort across the cluster: if a delivery races, both instances
//! may dispatch to the provider, but the second instance's dedupe key
//! prevents the third try in the same TTL.
//!
//! Failure mode: if Redis is unreachable, lookups return `None` and
//! conflicts return `false` (fail-open) so /notify keeps serving — the
//! invariants degrade to "in-process only" until Redis recovers.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use blake2::Blake2s256;
use blake2::digest::Digest;
use lru::LruCache;
use redis::Commands;

use crate::auth::redact_url_credentials;
use crate::models::FloriaPushNotifyOutcome as PushNotifyOutcome;
use crate::redis_support::{RedisConnection, RedisPool};

/// Lightweight status snapshot for the `GET /_floria/admin/push/status/{key}`
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
pub struct CachedPushNotifyOutcome {
    pub response: PushNotifyOutcome,
}

#[derive(Debug)]
struct CacheEntry {
    expires_at: Instant,
    request_fingerprint: String,
    response: CachedPushNotifyOutcome,
}

/// Upper bound on distinct in-memory dedup slots (request cache +
/// delivered-device suppression each get their own cache of this size).
/// Bounds memory under a high-cardinality unique-key flood from an
/// authenticated caller — the previous `HashMap` grew unbounded within a
/// TTL window and relied on an O(n) lazy `retain` to reclaim (FLO-02-003).
/// With an [`LruCache`] the slot count is capped and eviction is O(1).
const MEMORY_DEDUP_CAPACITY: usize = 100_000;

#[derive(Debug)]
struct MemoryNotifyDeduplicator {
    entries: Mutex<LruCache<String, CacheEntry>>,
    delivered_devices: Mutex<LruCache<String, Instant>>,
}

impl MemoryNotifyDeduplicator {
    fn new() -> Self {
        let cap = NonZeroUsize::new(MEMORY_DEDUP_CAPACITY).expect("MEMORY_DEDUP_CAPACITY non-zero");
        Self {
            entries: Mutex::new(LruCache::new(cap)),
            delivered_devices: Mutex::new(LruCache::new(cap)),
        }
    }
}

#[derive(Debug)]
struct RedisNotifyDeduplicator {
    pool: RedisPool,
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
            backend: NotifyDedupBackend::Memory(MemoryNotifyDeduplicator::new()),
        }
    }

    pub fn redis(ttl: Duration, redis_url: &str, key_prefix: impl Into<String>) -> Result<Self> {
        let client = redis::Client::open(redis_url).with_context(|| {
            format!(
                "invalid notify_dedup redis_url `{}`",
                redact_url_credentials(redis_url)
            )
        })?;
        let target_label = redact_url_credentials(redis_url);
        Ok(Self {
            ttl,
            backend: NotifyDedupBackend::Redis(RedisNotifyDeduplicator {
                pool: RedisPool::from_client(client, target_label.clone())?,
                target_label,
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

    pub fn lookup(&self, key: &str, request_fingerprint: &str) -> Option<CachedPushNotifyOutcome> {
        match &self.backend {
            NotifyDedupBackend::Memory(backend) => backend.lookup(key, request_fingerprint),
            NotifyDedupBackend::Redis(backend) => backend.lookup(key, request_fingerprint),
        }
    }

    /// Async-safe [`Self::lookup`]: see [`Self::conflicts_async`] for the
    /// memory-inline / redis-`spawn_blocking` rationale (FLO-02-002).
    pub async fn lookup_async(
        self: &Arc<Self>,
        key: &str,
        request_fingerprint: &str,
    ) -> Option<CachedPushNotifyOutcome> {
        match &self.backend {
            NotifyDedupBackend::Memory(backend) => backend.lookup(key, request_fingerprint),
            NotifyDedupBackend::Redis(_) => {
                let this = Arc::clone(self);
                let key = key.to_owned();
                let fingerprint = request_fingerprint.to_owned();
                tokio::task::spawn_blocking(move || this.lookup(&key, &fingerprint))
                    .await
                    .unwrap_or(None)
            }
        }
    }

    pub fn conflicts(&self, key: &str, request_fingerprint: &str) -> bool {
        match &self.backend {
            NotifyDedupBackend::Memory(backend) => backend.conflicts(key, request_fingerprint),
            NotifyDedupBackend::Redis(backend) => backend.conflicts(key, request_fingerprint),
        }
    }

    /// Async-safe [`Self::conflicts`]: the in-memory backend runs inline
    /// (lock-bounded, non-blocking) while the Redis backend — which opens
    /// a blocking connection and issues a blocking command — is offloaded
    /// to `spawn_blocking` so it never stalls a tokio worker thread
    /// (FLO-02-002).
    pub async fn conflicts_async(self: &Arc<Self>, key: &str, request_fingerprint: &str) -> bool {
        match &self.backend {
            NotifyDedupBackend::Memory(backend) => backend.conflicts(key, request_fingerprint),
            NotifyDedupBackend::Redis(_) => {
                let this = Arc::clone(self);
                let key = key.to_owned();
                let fingerprint = request_fingerprint.to_owned();
                tokio::task::spawn_blocking(move || this.conflicts(&key, &fingerprint))
                    .await
                    .unwrap_or(false)
            }
        }
    }

    pub fn insert_success(
        &self,
        key: &str,
        request_fingerprint: &str,
        response: PushNotifyOutcome,
    ) {
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

    pub async fn insert_success_async(
        self: &Arc<Self>,
        key: &str,
        request_fingerprint: &str,
        response: PushNotifyOutcome,
    ) {
        match &self.backend {
            NotifyDedupBackend::Memory(_) => {
                self.insert_success(key, request_fingerprint, response)
            }
            NotifyDedupBackend::Redis(_) => {
                let this = Arc::clone(self);
                let key = key.to_owned();
                let fingerprint = request_fingerprint.to_owned();
                let _ = tokio::task::spawn_blocking(move || {
                    this.insert_success(&key, &fingerprint, response)
                })
                .await
                .map_err(|error| {
                    tracing::warn!(error = %error, "notify dedup insert_success task failed");
                });
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

    pub async fn mark_delivered_device_async(
        self: &Arc<Self>,
        notification_key: &str,
        app_id: &str,
        push_key: &str,
    ) {
        match &self.backend {
            NotifyDedupBackend::Memory(_) => {
                self.mark_delivered_device(notification_key, app_id, push_key)
            }
            NotifyDedupBackend::Redis(_) => {
                let this = Arc::clone(self);
                let notification_key = notification_key.to_owned();
                let app_id = app_id.to_owned();
                let push_key = push_key.to_owned();
                let _ = tokio::task::spawn_blocking(move || {
                    this.mark_delivered_device(&notification_key, &app_id, &push_key)
                })
                .await
                .map_err(|error| {
                    tracing::warn!(error = %error, "notify dedup mark_delivered_device task failed");
                });
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
        let attempts = response
            .outcomes
            .iter()
            .filter(|outcome| {
                matches!(
                    outcome.reason_code,
                    Some(
                        arkret_models_integration::PushNotifyReasonCode::PushGatewayUnreachable
                            | arkret_models_integration::PushNotifyReasonCode::RateLimited
                    )
                )
            })
            .count()
            .saturating_add(1) as u32;
        let accepted = response.accepted();
        let rejected = response
            .outcomes
            .iter()
            .filter(|outcome| {
                outcome.gateway_status
                    == arkret_models_integration::PushNotifyGatewayStatus::Rejected
            })
            .count();
        let status = if rejected == 0 && accepted > 0 {
            "completed"
        } else if rejected > 0 && accepted > 0 {
            "partial"
        } else if accepted == 0 && rejected > 0 {
            "rejected"
        } else {
            "unknown"
        };
        let last_error = response
            .outcomes
            .iter()
            .find_map(|outcome| outcome.reason_code.map(|reason| reason.as_str().to_owned()));
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
    fn lookup(&self, key: &str, request_fingerprint: &str) -> Option<CachedPushNotifyOutcome> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = entries.get(key)?;
        if entry.expires_at <= now {
            entries.pop(key);
            return None;
        }
        let entry = entries.get(key)?;
        (entry.request_fingerprint == request_fingerprint).then(|| entry.response.clone())
    }

    fn conflicts(&self, key: &str, request_fingerprint: &str) -> bool {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match entries.get(key) {
            Some(entry) if entry.expires_at <= now => {
                entries.pop(key);
                false
            }
            Some(entry) => entry.request_fingerprint != request_fingerprint,
            None => false,
        }
    }

    fn insert_success(
        &self,
        ttl: Duration,
        key: &str,
        request_fingerprint: &str,
        response: PushNotifyOutcome,
    ) {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // LruCache caps total slots at MEMORY_DEDUP_CAPACITY and evicts
        // the least-recently-used entry on overflow (O(1)).
        entries.put(
            key.to_owned(),
            CacheEntry {
                expires_at: now + ttl,
                request_fingerprint: request_fingerprint.to_owned(),
                response: CachedPushNotifyOutcome { response },
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
        match entries.get(&key) {
            Some(expires_at) if *expires_at <= now => {
                entries.pop(&key);
                false
            }
            Some(_) => true,
            None => false,
        }
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
        entries.put(key, now + ttl);
    }

    fn cached_response(&self, key: &str) -> Option<PushNotifyOutcome> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = entries.get(key)?;
        if entry.expires_at <= now {
            entries.pop(key);
            return None;
        }
        entries
            .get(key)
            .map(|entry| entry.response.response.clone())
    }

    fn delivered_devices_len(&self) -> usize {
        let entries = self
            .delivered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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

    fn lookup(&self, key: &str, request_fingerprint: &str) -> Option<CachedPushNotifyOutcome> {
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
        match serde_json::from_str::<PushNotifyOutcome>(&response_json) {
            Ok(response) => Some(CachedPushNotifyOutcome { response }),
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
        response: PushNotifyOutcome,
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

    fn connection(&self) -> Result<RedisConnection> {
        self.pool.connection()
    }

    fn cached_response(&self, key: &str) -> Option<PushNotifyOutcome> {
        let mut connection = self.connection().ok()?;
        let response_key = self.response_key(key);
        let response_json: Option<String> = connection
            .hget::<_, _, Option<String>>(&response_key, "response")
            .ok()
            .flatten();
        let response_json = response_json?;
        serde_json::from_str::<PushNotifyOutcome>(&response_json).ok()
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
    use std::env;

    use super::*;

    #[test]
    fn returns_inserted_response_before_expiry() {
        let dedup = NotifyDeduplicator::new(Duration::from_secs(5));
        let response = PushNotifyOutcome {
            request_id: "request-1".to_owned(),
            push_target_id: "ak:pseudonym:push:01HYZ8Z000000000000000".to_owned(),
            outcomes: vec![],
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
            PushNotifyOutcome {
                request_id: "request-1".to_owned(),
                push_target_id: "ak:pseudonym:push:01HYZ8Z000000000000000".to_owned(),
                outcomes: vec![],
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
            PushNotifyOutcome {
                request_id: "request-1".to_owned(),
                push_target_id: "ak:pseudonym:push:01HYZ8Z000000000000000".to_owned(),
                outcomes: vec![],
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

    fn sample_response(index: usize) -> PushNotifyOutcome {
        PushNotifyOutcome {
            request_id: format!("request-{index}"),
            push_target_id: "ak:pseudonym:push:01HYZ8Z000000000000000".to_owned(),
            outcomes: vec![],
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
