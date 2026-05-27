//! Retry / dead-letter queue for transient `/notify` dispatch failures.
//!
//! When a pushkin returns `DispatchError::Temporary`, the gateway has
//! already replied to the caller with a retry-after hint. Rather than
//! drop those failures, we enqueue them on a per-instance retry queue
//! that a background worker drains: each entry is dispatched again
//! until the maximum attempt count is reached, after which it is
//! moved to the dead-letter ring buffer for operator inspection.
//!
//! ## Backends
//!
//! - `Memory`: in-process priority heap; suitable for single-instance
//!   deployments.
//! - `Redis`: shared sorted set so multiple gateway replicas drain
//!   together. Each replica claims an entry by `ZREMRANGEBYSCORE` /
//!   `ZADD NX` and the dead-letter ring lives on a fixed-length list.
//!
//! Failure mode mirrors the other Redis-backed components: connection
//! errors fail open (work stays in-process and gets re-dispatched on
//! the next worker tick) and a warning is logged.

use std::collections::{BinaryHeap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use redis::Commands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::redact_url_credentials;
use crate::postgres_support::SqlTableName;

/// AAD tag bound into every encrypted retry-queue envelope so a
/// payload moved between key prefixes / queues can't be replayed
/// against the wrong scope.
const RETRY_QUEUE_AAD: &[u8] = b"floria:retry_queue:v1";
const RETRY_NONCE_LEN: usize = 12;

/// Wraps an AEAD key for encrypting on-disk retry envelopes. The wire
/// shape is `base64(nonce || ciphertext)`; the key material is hashed
/// with SHA-256 so the caller can pass any byte string.
#[derive(Clone)]
pub struct RetryQueueCipher {
    cipher: ChaCha20Poly1305,
}

impl std::fmt::Debug for RetryQueueCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetryQueueCipher").finish_non_exhaustive()
    }
}

impl RetryQueueCipher {
    pub fn new(key_material: &[u8]) -> Self {
        let key = Sha256::digest(key_material);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        Self { cipher }
    }

    fn seal(&self, plaintext: &[u8]) -> Result<String> {
        let mut nonce_bytes = [0u8; RETRY_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: RETRY_QUEUE_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("retry-queue AEAD encryption failed"))?;
        let mut envelope = Vec::with_capacity(RETRY_NONCE_LEN + ciphertext.len());
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        Ok(base64::engine::general_purpose::STANDARD.encode(envelope))
    }

    fn open(&self, wire: &str) -> Result<Vec<u8>> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(wire)
            .context("retry-queue envelope is not valid base64")?;
        if bytes.len() < RETRY_NONCE_LEN {
            anyhow::bail!("retry-queue envelope is shorter than the nonce");
        }
        let (nonce_bytes, ciphertext) = bytes.split_at(RETRY_NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: RETRY_QUEUE_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("retry-queue AEAD decryption failed"))
    }
}

/// Optional PostgreSQL dead-letter overlay. Every envelope that drops
/// into the dead-letter ring is ALSO written to the configured PG
/// table so it survives a process restart. The overlay is fire-and-
/// forget — a connection failure is logged and dropped; the in-memory
/// ring stays authoritative for the live `dead_letter_snapshot()` API
/// and operator-facing dashboards.
///
/// Table schema (created by `ensure_schema`):
///
/// ```sql
/// CREATE TABLE IF NOT EXISTS <table> (
///   request_id   TEXT NOT NULL,
///   pushkin      TEXT NOT NULL,
///   last_error   TEXT NOT NULL,
///   occurred_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
///   PRIMARY KEY (request_id, pushkin, occurred_at)
/// );
/// ```
#[derive(Debug)]
pub struct DeadLetterPgOverlay {
    url: String,
    target_label: String,
    table: SqlTableName,
}

impl DeadLetterPgOverlay {
    /// Build an overlay. The table is validated via [`SqlTableName`] —
    /// the raw name is rejected if it contains anything other than
    /// `[A-Za-z0-9_]` plus an optional schema-qualifier dot.
    pub fn new(url: &str, table: &str) -> Result<Self> {
        let table = SqlTableName::parse(table, "notify_retry_queue.deadletter_pg_table")?;
        Ok(Self {
            url: url.to_owned(),
            target_label: redact_url_credentials(url),
            table,
        })
    }

    /// Idempotent schema bootstrap. Safe to call on every startup.
    pub fn ensure_schema(&self) -> Result<()> {
        use postgres::NoTls;
        let mut client = postgres::Client::connect(&self.url, NoTls).with_context(|| {
            format!("deadletter PG: failed to connect to {}", self.target_label)
        })?;
        let stmt = format!(
            "CREATE TABLE IF NOT EXISTS {table} (\n\
                 request_id  TEXT NOT NULL,\n\
                 pushkin     TEXT NOT NULL,\n\
                 last_error  TEXT NOT NULL,\n\
                 occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n\
                 PRIMARY KEY (request_id, pushkin, occurred_at)\n\
             )",
            table = self.table.as_sql()
        );
        client.batch_execute(&stmt).with_context(|| {
            format!(
                "deadletter PG: failed to create table {}",
                self.table.as_sql()
            )
        })?;
        Ok(())
    }

    /// Persist one dead-letter envelope. Best-effort: errors are
    /// logged and swallowed so a PG outage cannot block the live
    /// dispatch path.
    pub fn record(&self, envelope: &RetryEnvelope) {
        use postgres::NoTls;
        let mut client = match postgres::Client::connect(&self.url, NoTls) {
            Ok(c) => c,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, "deadletter PG: connect failed");
                return;
            }
        };
        let stmt = format!(
            "INSERT INTO {table} (request_id, pushkin, last_error) VALUES ($1, $2, $3)",
            table = self.table.as_sql()
        );
        if let Err(error) = client.execute(
            stmt.as_str(),
            &[
                &envelope.request_id,
                &envelope.pushkin,
                &envelope.last_error,
            ],
        ) {
            tracing::warn!(error = %error, backend = %self.target_label, request_id = %envelope.request_id, "deadletter PG: insert failed");
        }
    }
}

/// One pending retry attempt.
///
/// `retry_at_unix_ms` is the absolute timestamp at which the worker
/// is allowed to re-dispatch this entry. `attempts` counts the prior
/// dispatch attempts (the one that failed plus any retry attempts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryEnvelope {
    pub request_id: String,
    pub pushkin: String,
    pub app_id: String,
    pub push_key: String,
    pub retry_at_unix_ms: u64,
    pub attempts: u32,
    pub last_error: String,
}

impl RetryEnvelope {
    pub fn new(
        request_id: impl Into<String>,
        pushkin: impl Into<String>,
        app_id: impl Into<String>,
        push_key: impl Into<String>,
        retry_after: Duration,
        last_error: impl Into<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            pushkin: pushkin.into(),
            app_id: app_id.into(),
            push_key: push_key.into(),
            retry_at_unix_ms: now_unix_ms()
                .saturating_add(u64::try_from(retry_after.as_millis()).unwrap_or(u64::MAX)),
            attempts: 1,
            last_error: last_error.into(),
        }
    }

    pub fn with_attempt(mut self, attempts: u32) -> Self {
        self.attempts = attempts;
        self
    }
}

#[derive(Debug, Clone)]
pub struct RetryQueueConfig {
    pub max_attempts: u32,
    pub default_backoff: Duration,
    pub max_backoff: Duration,
    pub dead_letter_capacity: usize,
}

impl Default for RetryQueueConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            default_backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(15 * 60),
            dead_letter_capacity: 1024,
        }
    }
}

#[derive(Debug)]
struct MemoryQueue {
    pending: Mutex<BinaryHeap<MemoryEntry>>,
    dead_letter: Mutex<VecDeque<RetryEnvelope>>,
}

#[derive(Debug, Clone)]
struct MemoryEntry(RetryEnvelope);

impl PartialEq for MemoryEntry {
    fn eq(&self, other: &Self) -> bool {
        self.0.retry_at_unix_ms == other.0.retry_at_unix_ms
    }
}
impl Eq for MemoryEntry {}
impl PartialOrd for MemoryEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for MemoryEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // BinaryHeap is a max-heap; invert so the smallest retry_at
        // pops first.
        other.0.retry_at_unix_ms.cmp(&self.0.retry_at_unix_ms)
    }
}

#[derive(Debug)]
struct RedisQueue {
    client: redis::Client,
    target_label: String,
    key_prefix: String,
    dead_letter_capacity: usize,
    cipher: Option<RetryQueueCipher>,
}

#[derive(Debug)]
enum Backend {
    Memory(MemoryQueue),
    Redis(RedisQueue),
}

#[derive(Debug)]
pub struct RetryQueue {
    config: RetryQueueConfig,
    backend: Backend,
    /// Optional PostgreSQL dead-letter overlay. Wrapped in an Arc so
    /// async-spawning callers can clone cheaply; constructed up-front
    /// via [`RetryQueue::with_deadletter_pg`].
    deadletter_pg: Option<std::sync::Arc<DeadLetterPgOverlay>>,
}

impl RetryQueue {
    pub fn memory(config: RetryQueueConfig) -> Self {
        Self {
            config,
            backend: Backend::Memory(MemoryQueue {
                pending: Mutex::new(BinaryHeap::new()),
                dead_letter: Mutex::new(VecDeque::new()),
            }),
            deadletter_pg: None,
        }
    }

    /// Attach a PostgreSQL dead-letter overlay. The overlay's schema is
    /// bootstrapped synchronously here — if `CREATE TABLE` fails the
    /// caller gets the error rather than discovering it on the first
    /// dead-letter event.
    pub fn with_deadletter_pg(mut self, overlay: DeadLetterPgOverlay) -> Result<Self> {
        overlay.ensure_schema()?;
        self.deadletter_pg = Some(std::sync::Arc::new(overlay));
        Ok(self)
    }

    pub fn redis(
        config: RetryQueueConfig,
        redis_url: &str,
        key_prefix: impl Into<String>,
    ) -> Result<Self> {
        Self::redis_with_cipher(config, redis_url, key_prefix, None)
    }

    pub fn redis_with_cipher(
        config: RetryQueueConfig,
        redis_url: &str,
        key_prefix: impl Into<String>,
        cipher: Option<RetryQueueCipher>,
    ) -> Result<Self> {
        let client = redis::Client::open(redis_url).with_context(|| {
            format!(
                "invalid notify_retry_queue redis_url `{}`",
                redact_url_credentials(redis_url)
            )
        })?;
        let dead_letter_capacity = config.dead_letter_capacity;
        Ok(Self {
            config,
            backend: Backend::Redis(RedisQueue {
                client,
                target_label: redact_url_credentials(redis_url),
                key_prefix: normalize_key_prefix(&key_prefix.into()),
                dead_letter_capacity,
                cipher,
            }),
            deadletter_pg: None,
        })
    }

    pub fn config(&self) -> &RetryQueueConfig {
        &self.config
    }

    pub fn backend_name(&self) -> &'static str {
        match self.backend {
            Backend::Memory(_) => "memory",
            Backend::Redis(_) => "redis",
        }
    }

    pub fn ready(&self) -> Result<(), String> {
        match &self.backend {
            Backend::Memory(_) => Ok(()),
            Backend::Redis(backend) => backend.ready().map_err(|error| error.to_string()),
        }
    }

    /// Enqueue a fresh failure (attempts already incremented to 1)
    /// or a re-enqueue after a worker decides to keep retrying.
    pub fn enqueue(&self, envelope: RetryEnvelope) {
        if envelope.attempts >= self.config.max_attempts {
            self.dead_letter(envelope);
            return;
        }
        match &self.backend {
            Backend::Memory(backend) => backend.enqueue(envelope),
            Backend::Redis(backend) => backend.enqueue(envelope),
        }
    }

    pub fn dequeue_due(&self, limit: usize) -> Vec<RetryEnvelope> {
        if limit == 0 {
            return Vec::new();
        }
        match &self.backend {
            Backend::Memory(backend) => backend.dequeue_due(limit),
            Backend::Redis(backend) => backend.dequeue_due(limit),
        }
    }

    pub fn dead_letter(&self, envelope: RetryEnvelope) {
        // Persist to the PG overlay (if configured) FIRST. The overlay
        // is fire-and-forget — a PG outage must not block the in-mem
        // ring update that the dispatch loop actually reads from.
        if let Some(overlay) = &self.deadletter_pg {
            overlay.record(&envelope);
        }
        match &self.backend {
            Backend::Memory(backend) => {
                backend.push_dead_letter(envelope, self.config.dead_letter_capacity)
            }
            Backend::Redis(backend) => backend.push_dead_letter(envelope),
        }
    }

    /// True iff a PG dead-letter overlay is attached.
    pub fn has_deadletter_pg(&self) -> bool {
        self.deadletter_pg.is_some()
    }

    pub fn pending_len(&self) -> usize {
        match &self.backend {
            Backend::Memory(backend) => {
                backend.pending.lock().map(|guard| guard.len()).unwrap_or(0)
            }
            Backend::Redis(backend) => backend.pending_len().unwrap_or(0) as usize,
        }
    }

    /// P5 — best-effort per-(provider, app_id) breakdown of the
    /// pending depth. Used to feed `floria_notify_retry_queue_depth`
    /// when the operator opts in to per-provider labels. Memory
    /// backend reports an exact snapshot; the Redis backend returns
    /// an empty map — accurate per-provider depth would require
    /// scanning every envelope in the sorted set, which we explicitly
    /// avoid on the dispatcher poll loop. Operators running Redis
    /// can read the aggregate `floria_retry_queue_depth` gauge AND
    /// reconstruct provider deltas from `floria_notify_retry_*_total`
    /// counters.
    pub fn pending_breakdown_by_provider(&self) -> std::collections::HashMap<String, usize> {
        match &self.backend {
            Backend::Memory(backend) => {
                let guard = backend
                    .pending
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let mut counts: std::collections::HashMap<String, usize> =
                    std::collections::HashMap::new();
                for entry in guard.iter() {
                    *counts.entry(entry.0.pushkin.clone()).or_default() += 1;
                }
                counts
            }
            Backend::Redis(_) => std::collections::HashMap::new(),
        }
    }

    pub fn dead_letter_snapshot(&self, limit: usize) -> Vec<RetryEnvelope> {
        match &self.backend {
            Backend::Memory(backend) => backend.dead_letter_snapshot(limit),
            Backend::Redis(backend) => backend.dead_letter_snapshot(limit),
        }
    }

    /// Compute the next retry timestamp for an envelope that should
    /// be re-enqueued, applying exponential backoff capped by
    /// `max_backoff` and adding ±10% jitter so a stampede of clients
    /// hitting the same provider doesn't synchronise their retries.
    pub fn next_retry_at(&self, attempts: u32) -> Duration {
        let base = self.config.default_backoff;
        let factor = 1u32 << attempts.min(10);
        let backoff = base.saturating_mul(factor).min(self.config.max_backoff);
        apply_jitter(backoff)
    }
}

impl MemoryQueue {
    fn enqueue(&self, envelope: RetryEnvelope) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pending.push(MemoryEntry(envelope));
    }

    fn dequeue_due(&self, limit: usize) -> Vec<RetryEnvelope> {
        let now = now_unix_ms();
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut due = Vec::new();
        while due.len() < limit {
            match pending.peek() {
                Some(MemoryEntry(envelope)) if envelope.retry_at_unix_ms <= now => {
                    if let Some(MemoryEntry(envelope)) = pending.pop() {
                        due.push(envelope);
                    }
                }
                _ => break,
            }
        }
        due
    }

    fn push_dead_letter(&self, envelope: RetryEnvelope, capacity: usize) {
        let mut dead = self
            .dead_letter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if dead.len() >= capacity.max(1) {
            dead.pop_front();
        }
        dead.push_back(envelope);
    }

    fn dead_letter_snapshot(&self, limit: usize) -> Vec<RetryEnvelope> {
        let dead = self
            .dead_letter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        dead.iter().rev().take(limit).cloned().collect()
    }
}

impl RedisQueue {
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

    fn enqueue(&self, envelope: RetryEnvelope) {
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, "failed to enqueue retry on Redis; dropping envelope");
                return;
            }
        };
        let key = self.pending_key();
        let payload = match self.serialize_envelope(&envelope) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(error = %error, "failed to serialize/encrypt retry envelope");
                return;
            }
        };
        let result: redis::RedisResult<()> =
            connection.zadd(&key, payload, envelope.retry_at_unix_ms);
        if let Err(error) = result {
            tracing::warn!(error = %error, backend = %self.target_label, redis_key = %key, "failed to enqueue retry on Redis");
        }
    }

    fn serialize_envelope(&self, envelope: &RetryEnvelope) -> Result<String> {
        let json = serde_json::to_string(envelope).context("serialize retry envelope")?;
        match &self.cipher {
            Some(cipher) => cipher.seal(json.as_bytes()),
            None => Ok(json),
        }
    }

    fn deserialize_envelope(&self, payload: &str) -> Result<RetryEnvelope> {
        let bytes = match &self.cipher {
            Some(cipher) => cipher.open(payload)?,
            None => payload.as_bytes().to_vec(),
        };
        serde_json::from_slice(&bytes).context("deserialize retry envelope")
    }

    fn dequeue_due(&self, limit: usize) -> Vec<RetryEnvelope> {
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, "failed to read retries from Redis");
                return Vec::new();
            }
        };
        let key = self.pending_key();
        let now = now_unix_ms();
        let candidates: redis::RedisResult<Vec<String>> = redis::cmd("ZRANGEBYSCORE")
            .arg(&key)
            .arg(0)
            .arg(now)
            .arg("LIMIT")
            .arg(0)
            .arg(limit as i64)
            .query(&mut connection);
        let payloads = match candidates {
            Ok(payloads) => payloads,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, redis_key = %key, "failed to ZRANGEBYSCORE retries");
                return Vec::new();
            }
        };
        let mut envelopes = Vec::new();
        for payload in payloads {
            // Best-effort claim: ZREM returns 1 if we won the race.
            let removed: redis::RedisResult<i64> = connection.zrem(&key, &payload);
            if !matches!(removed, Ok(1)) {
                continue;
            }
            match self.deserialize_envelope(&payload) {
                Ok(envelope) => envelopes.push(envelope),
                Err(error) => {
                    tracing::warn!(error = %error, "failed to deserialize Redis retry envelope, dropping");
                }
            }
        }
        envelopes
    }

    fn push_dead_letter(&self, envelope: RetryEnvelope) {
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, "failed to write dead-letter to Redis");
                return;
            }
        };
        let key = self.dead_letter_key();
        let payload = match self.serialize_envelope(&envelope) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(error = %error, "failed to serialize/encrypt dead-letter envelope");
                return;
            }
        };
        let result: redis::RedisResult<()> = redis::pipe()
            .cmd("LPUSH")
            .arg(&key)
            .arg(&payload)
            .ignore()
            .cmd("LTRIM")
            .arg(&key)
            .arg(0)
            .arg(self.dead_letter_capacity.max(1) as i64 - 1)
            .ignore()
            .query(&mut connection);
        if let Err(error) = result {
            tracing::warn!(error = %error, backend = %self.target_label, redis_key = %key, "failed to write dead-letter on Redis");
        }
    }

    fn pending_len(&self) -> Result<i64> {
        let mut connection = self.connection()?;
        connection
            .zcard(self.pending_key())
            .context("failed to ZCARD retry pending")
    }

    fn dead_letter_snapshot(&self, limit: usize) -> Vec<RetryEnvelope> {
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, "failed to read dead-letter from Redis");
                return Vec::new();
            }
        };
        let key = self.dead_letter_key();
        let payloads: redis::RedisResult<Vec<String>> =
            connection.lrange(&key, 0, limit as isize - 1);
        match payloads {
            Ok(payloads) => payloads
                .into_iter()
                .filter_map(|payload| self.deserialize_envelope(&payload).ok())
                .collect(),
            Err(error) => {
                tracing::warn!(error = %error, backend = %self.target_label, redis_key = %key, "failed to read dead-letter snapshot");
                Vec::new()
            }
        }
    }

    fn connection(&self) -> Result<redis::Connection> {
        self.client
            .get_connection()
            .with_context(|| format!("failed to connect to Redis backend {}", self.target_label))
    }

    fn pending_key(&self) -> String {
        format!("{}:retry:pending", self.key_prefix)
    }

    fn dead_letter_key(&self) -> String {
        format!("{}:retry:dead_letter", self.key_prefix)
    }
}

fn normalize_key_prefix(key_prefix: &str) -> String {
    let trimmed = key_prefix.trim();
    if trimmed.is_empty() {
        "floria".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Apply ±10% jitter to a backoff duration. The implementation uses
/// `rand::thread_rng` so a fork-bombed process won't pin every retry
/// to the same `Instant`.
fn apply_jitter(backoff: Duration) -> Duration {
    let millis = backoff.as_millis().min(u64::MAX as u128) as u64;
    if millis == 0 {
        return backoff;
    }
    let jitter_span = millis / 10; // ±10%
    if jitter_span == 0 {
        return backoff;
    }
    let mut rng = rand::thread_rng();
    let offset_raw = (rng.next_u64() % (jitter_span * 2 + 1)) as i64 - jitter_span as i64;
    let adjusted = (millis as i64).saturating_add(offset_raw).max(0) as u64;
    Duration::from_millis(adjusted)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

/// Background-worker entry point. Drains due envelopes, re-dispatches
/// each through the registry, and either re-enqueues (with
/// exponential backoff) or dead-letters when `max_attempts` is hit.
///
/// The worker exits cleanly when `shutdown.recv().is_err()` (sender
/// dropped) or after observing a single shutdown notification.
pub async fn run_worker(
    queue: std::sync::Arc<RetryQueue>,
    registry: std::sync::Arc<crate::pushkin::PushkinRegistry>,
    poll_interval: Duration,
    batch_size: usize,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use crate::error::DispatchError;
    use crate::models::{Device, Notification, NotificationContext};
    use std::time::Instant;

    loop {
        if shutdown.has_changed().unwrap_or(false) && *shutdown.borrow() {
            break;
        }
        // Surface the pending queue depth on each loop so the
        // `floria_retry_queue_depth` gauge tracks the live backlog
        // rather than only the most recent enqueue. Cheap for memory
        // backends and a single ZCARD/EXISTS on Redis.
        crate::metrics::set_retry_queue_depth(queue.pending_len() as i64);
        // P5 — labelled breakdown. Memory backend reports exact
        // per-provider counts; Redis backend returns an empty map
        // (and the labelled metric simply stops getting updated for
        // that interval — operators read the aggregate gauge instead).
        // Scope label is always `realm` here because retry envelopes
        // do not currently carry circle_id; circle-keyed breakdown is
        // gated behind a future enhancement once that field flows
        // through the envelope.
        for (provider, depth) in queue.pending_breakdown_by_provider() {
            crate::metrics::set_notify_retry_queue_depth_labelled(
                &provider,
                "realm",
                None,
                depth as i64,
            );
        }
        let due = queue.dequeue_due(batch_size.max(1));
        if due.is_empty() {
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {}
                _ = shutdown.changed() => break,
            }
            continue;
        }
        for envelope in due {
            let pushkins = registry.find_pushkins(&envelope.app_id);
            let pushkin = match pushkins
                .iter()
                .find(|candidate| candidate.name() == envelope.pushkin)
            {
                Some(pushkin) => pushkin.clone(),
                None => {
                    tracing::warn!(
                        pushkin = %envelope.pushkin,
                        app_id = %envelope.app_id,
                        request_id = %envelope.request_id,
                        "dead-lettering retry: pushkin no longer registered"
                    );
                    crate::metrics::notify_dead_letter(&envelope.pushkin, "pushkin_unregistered");
                    queue.dead_letter(envelope);
                    continue;
                }
            };

            // Reconstruct a minimal Notification + Device shell. We
            // intentionally do not persist the original notification
            // body — the retry exists to re-attempt the wakeup, not
            // to replay payload metadata. Provider implementations
            // accept blind-wakeup defaults.
            let device = Device {
                app_id: envelope.app_id.clone(),
                push_key: envelope.push_key.clone(),
                ..Device::default()
            };
            let notification = Notification {
                devices: vec![device.clone()],
                prio: Some("low".to_owned()),
                push_hint: Some("new_message".to_owned()),
                ..Notification::default()
            };
            let context = NotificationContext {
                request_id: envelope.request_id.clone(),
                start_time: Instant::now(),
            };
            match pushkin
                .dispatch_notification(&notification, &device, &context)
                .await
            {
                Ok(rejected) if rejected.is_empty() => {
                    crate::metrics::notify_retry_replayed(&envelope.pushkin, "delivered");
                }
                Ok(_) => {
                    crate::metrics::notify_retry_replayed(&envelope.pushkin, "rejected");
                    queue.dead_letter(envelope);
                }
                Err(DispatchError::Temporary { retry_after, .. }) => {
                    let next_attempt = envelope.attempts.saturating_add(1);
                    if next_attempt >= queue.config().max_attempts {
                        crate::metrics::notify_dead_letter(&envelope.pushkin, "max_attempts");
                        crate::metrics::notify_retry_replayed(&envelope.pushkin, "dead_letter");
                        queue.dead_letter(envelope.with_attempt(next_attempt));
                    } else {
                        let backoff =
                            retry_after.unwrap_or_else(|| queue.next_retry_at(next_attempt));
                        let mut next = envelope.clone().with_attempt(next_attempt);
                        next.retry_at_unix_ms = now_unix_ms()
                            .saturating_add(u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX));
                        crate::metrics::notify_retry_replayed(&envelope.pushkin, "retry");
                        queue.enqueue(next);
                    }
                }
                Err(error) => {
                    crate::metrics::notify_retry_replayed(&envelope.pushkin, "remote_error");
                    crate::metrics::notify_dead_letter(&envelope.pushkin, "permanent_error");
                    let mut envelope = envelope;
                    envelope.last_error = error.to_string();
                    queue.dead_letter(envelope);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn dead_letters_after_max_attempts() {
        let queue = RetryQueue::memory(RetryQueueConfig {
            max_attempts: 2,
            ..RetryQueueConfig::default()
        });
        queue.enqueue(
            RetryEnvelope::new(
                "req",
                "apns",
                "com.example.app",
                "push_key",
                Duration::ZERO,
                "boom",
            )
            .with_attempt(1),
        );
        queue.enqueue(
            RetryEnvelope::new(
                "req",
                "apns",
                "com.example.app",
                "push_key",
                Duration::ZERO,
                "boom",
            )
            .with_attempt(2),
        );

        // First entry is still pending, second one short-circuits to
        // the dead-letter ring because attempts >= max_attempts.
        thread::sleep(Duration::from_millis(5));
        let due = queue.dequeue_due(10);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].attempts, 1);
        let dl = queue.dead_letter_snapshot(10);
        assert_eq!(dl.len(), 1);
        assert_eq!(dl[0].attempts, 2);
    }

    #[test]
    fn dequeue_returns_only_due_entries() {
        let queue = RetryQueue::memory(RetryQueueConfig::default());
        queue.enqueue(RetryEnvelope::new(
            "req",
            "apns",
            "com.example.app",
            "push_key",
            Duration::ZERO,
            "boom",
        ));
        queue.enqueue(RetryEnvelope::new(
            "req",
            "apns",
            "com.example.app",
            "push_key",
            Duration::from_secs(3600),
            "boom",
        ));

        thread::sleep(Duration::from_millis(2));
        let due = queue.dequeue_due(10);
        assert_eq!(due.len(), 1);
        assert_eq!(queue.pending_len(), 1);
    }

    #[test]
    fn next_retry_at_caps_at_max_backoff() {
        let queue = RetryQueue::memory(RetryQueueConfig {
            default_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            ..RetryQueueConfig::default()
        });
        // ±10% jitter around the 60s cap
        let backoff = queue.next_retry_at(20);
        assert!(
            backoff >= Duration::from_millis(54_000) && backoff <= Duration::from_millis(66_000),
            "backoff {backoff:?} outside expected jitter window"
        );
    }

    #[test]
    fn redis_backend_requires_valid_url() {
        let error = RetryQueue::redis(RetryQueueConfig::default(), "://bad-url", "floria")
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid notify_retry_queue redis_url"));
    }

    #[test]
    fn deadletter_pg_overlay_rejects_unsafe_table_identifier() {
        // SqlTableName parsing must reject anything outside [A-Za-z0-9_]
        // (plus an optional schema-qualifier dot). This is the only
        // path that touches a string-formatted SQL table name, so the
        // rejection is the load-bearing check against SQLi.
        let err = DeadLetterPgOverlay::new(
            "postgres://localhost/floria",
            "floria_retry_dead_letter;drop",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("must contain only ASCII"), "got {err}");
    }

    #[test]
    fn deadletter_pg_overlay_accepts_schema_qualified_table() {
        let overlay =
            DeadLetterPgOverlay::new("postgres://localhost/floria", "floria.retry_dead_letter")
                .expect("schema.table is valid");
        // SqlTableName quotes both identifiers.
        assert_eq!(
            format!("{:?}", overlay).contains("floria"),
            true,
            "overlay debug must include the table"
        );
    }

    #[test]
    fn retry_queue_without_pg_overlay_reports_none() {
        let queue = RetryQueue::memory(RetryQueueConfig::default());
        assert!(!queue.has_deadletter_pg());
    }
}
