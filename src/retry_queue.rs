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
//! - `Memory`: in-process priority heap; suitable for single-instance deployments.
//! - `Redis`: shared sorted set so multiple gateway replicas drain together. Each replica claims an
//!   entry by `ZREMRANGEBYSCORE` / `ZADD NX` and the dead-letter ring lives on a fixed-length list.
//!
//! Failure mode mirrors the other Redis-backed components: connection
//! errors fail open (work stays in-process and gets re-dispatched on
//! the next worker tick) and a warning is logged.

use std::collections::{BinaryHeap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use arkret_retry::{Jitter, RetryPolicy};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngExt;
use redis::Commands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::redact_url_credentials;
use crate::postgres_support::{PostgresPool, SqlTableName};
use crate::redis_support::{RedisConnection, RedisPool};

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
        // `chacha20poly1305 = "0.10"` is pinned to `generic-array = "0.14"`,
        // but `sha2 = "0.11"` from transitive deps exposes a deprecation
        // shim on `from_slice`. The chacha20poly1305 API still requires
        // this call shape until the crate moves to generic-array 1.x.
        #[allow(deprecated)]
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        Self { cipher }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<String> {
        let mut nonce_bytes = [0u8; RETRY_NONCE_LEN];
        rand::rng().fill(&mut nonce_bytes);
        #[allow(deprecated)]
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
        #[allow(deprecated)]
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
///   occurred_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
///   last_error   TEXT NOT NULL,
///   PRIMARY KEY (request_id, pushkin, occurred_at)
/// );
/// ```
#[derive(Debug)]
pub struct DeadLetterPgOverlay {
    pool: PostgresPool,
    target_label: String,
    table: SqlTableName,
}

impl DeadLetterPgOverlay {
    /// Build an overlay. The table is validated via [`SqlTableName`] —
    /// the raw name is rejected if it contains anything other than
    /// `[A-Za-z0-9_]` plus an optional schema-qualifier dot.
    pub fn new(url: &str, table: &str) -> Result<Self> {
        let table = SqlTableName::parse(table, "notify_retry_queue.deadletter_pg_table")?;
        let target_label = redact_url_credentials(url);
        Ok(Self {
            pool: PostgresPool::new(url, target_label.clone())?,
            target_label,
            table,
        })
    }

    /// Idempotent schema bootstrap. Safe to call on every startup.
    pub fn ensure_schema(&self) -> Result<()> {
        let stmt = format!(
            "CREATE TABLE IF NOT EXISTS {table} (\n\
                 request_id  TEXT NOT NULL,\n\
                 pushkin     TEXT NOT NULL,\n\
                 occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n\
                 last_error  TEXT NOT NULL,\n\
                 PRIMARY KEY (request_id, pushkin, occurred_at)\n\
             )",
            table = self.table.as_sql()
        );
        self.pool.with_client(|client| {
            client.batch_execute(&stmt).with_context(|| {
                format!(
                    "deadletter PG: failed to create table {}",
                    self.table.as_sql()
                )
            })
        })?;
        Ok(())
    }

    /// Persist one dead-letter envelope. Best-effort: errors are
    /// logged and swallowed so a PG outage cannot block the live
    /// dispatch path.
    pub fn record(&self, envelope: &RetryEnvelope) {
        let stmt = format!(
            "INSERT INTO {table} (request_id, pushkin, last_error) VALUES ($1, $2, $3)",
            table = self.table.as_sql()
        );
        if let Err(error) = self.pool.with_client(|client| {
            client
                .execute(
                    stmt.as_str(),
                    &[
                        &envelope.request_id,
                        &envelope.pushkin,
                        &envelope.last_error,
                    ],
                )
                .map(|_| ())
                .context("deadletter PG: insert failed")
        }) {
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
    pub source_id: arkret_wire::DidCoreId,
    pub notification: arkret_models_integration::PushNotificationEnvelope,
    pub retry_at_unix_ms: u64,
    pub attempts: u32,
    pub last_error: String,
}

impl RetryEnvelope {
    pub fn new(
        request_id: impl Into<String>,
        pushkin: impl Into<String>,
        source_id: arkret_wire::DidCoreId,
        notification: arkret_models_integration::PushNotificationEnvelope,
        retry_after: Duration,
        last_error: impl Into<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            pushkin: pushkin.into(),
            source_id,
            notification,
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
    pool: RedisPool,
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
        let target_label = redact_url_credentials(redis_url);
        Ok(Self {
            config,
            backend: Backend::Redis(RedisQueue {
                pool: RedisPool::from_client(client, target_label.clone())?,
                target_label,
                key_prefix: crate::config::trimmed_or(&key_prefix.into(), "floria").to_owned(),
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

    pub async fn enqueue_async(self: &std::sync::Arc<Self>, envelope: RetryEnvelope) {
        let _ = queue_operation(self, move |queue| queue.enqueue(envelope)).await;
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

    pub fn uses_blocking_io(&self) -> bool {
        matches!(self.backend, Backend::Redis(_)) || self.deadletter_pg.is_some()
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

    /// Async-safe [`Self::dead_letter_snapshot`]: the in-memory ring is
    /// read inline (lock-bounded, non-blocking) while the Redis backend
    /// — which opens a blocking connection and runs a blocking `LRANGE`
    /// — is offloaded to `spawn_blocking` so the operator route never
    /// stalls a tokio worker thread (FLO-02-002).
    pub async fn dead_letter_snapshot_async(
        self: &std::sync::Arc<Self>,
        limit: usize,
    ) -> Vec<RetryEnvelope> {
        queue_operation(self, move |queue| queue.dead_letter_snapshot(limit))
            .await
            .unwrap_or_default()
    }

    /// Compute the next retry timestamp for an envelope that should
    /// be re-enqueued, applying exponential backoff capped by
    /// `max_backoff` and adding the shared policy's 0–20% jitter so a
    /// stampede of clients hitting the same provider does not synchronise
    /// retries.
    pub fn next_retry_at(&self, attempts: u32) -> Duration {
        let policy = RetryPolicy::exponential(self.config.default_backoff, self.config.max_backoff);
        let mut jitter = Jitter::from_seed(rand::rng().random());
        policy.delay(attempts, &mut jitter)
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
        self.pool.ready()
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
            Some(cipher) => cipher.encrypt(json.as_bytes()),
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

    fn connection(&self) -> Result<RedisConnection> {
        self.pool.connection()
    }

    fn pending_key(&self) -> String {
        format!("{}:retry:pending", self.key_prefix)
    }

    fn dead_letter_key(&self) -> String {
        format!("{}:retry:dead_letter", self.key_prefix)
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

async fn queue_operation<T>(
    queue: &std::sync::Arc<RetryQueue>,
    operation: impl FnOnce(&RetryQueue) -> T + Send + 'static,
) -> Option<T>
where
    T: Send + 'static,
{
    if queue.uses_blocking_io() {
        let queue = queue.clone();
        tokio::task::spawn_blocking(move || operation(&queue))
            .await
            .map(Some)
            .unwrap_or_else(|error| {
                tracing::warn!(error = %error, "retry queue blocking operation task failed");
                None
            })
    } else {
        Some(operation(queue))
    }
}

async fn pending_len_for_worker(queue: &std::sync::Arc<RetryQueue>) -> usize {
    queue_operation(queue, RetryQueue::pending_len)
        .await
        .unwrap_or(0)
}

async fn dequeue_due_for_worker(
    queue: &std::sync::Arc<RetryQueue>,
    batch_item_count: usize,
) -> Vec<RetryEnvelope> {
    queue_operation(queue, move |queue| queue.dequeue_due(batch_item_count))
        .await
        .unwrap_or_default()
}

async fn enqueue_for_worker(queue: &std::sync::Arc<RetryQueue>, envelope: RetryEnvelope) {
    let _ = queue_operation(queue, move |queue| queue.enqueue(envelope)).await;
}

async fn dead_letter_for_worker(queue: &std::sync::Arc<RetryQueue>, envelope: RetryEnvelope) {
    let _ = queue_operation(queue, move |queue| queue.dead_letter(envelope)).await;
}

/// Background-worker entry point. Drains due envelopes, re-dispatches
/// each through the registry, and either re-enqueues (with
/// exponential backoff) or dead-letters when `max_attempts` is hit.
///
/// The worker exits cleanly when `shutdown.recv().is_err()` (sender
/// dropped) or after observing a single shutdown notification.
#[derive(Clone, Debug)]
pub struct RetryWorkerConfig {
    pub gateway_url: String,
    pub poll_interval: Duration,
    pub batch_item_count: usize,
}

pub async fn run_worker(
    queue: std::sync::Arc<RetryQueue>,
    registry: std::sync::Arc<crate::pushkin::PushkinRegistry>,
    registrations: std::sync::Arc<crate::registrations::RegistrationDirectory>,
    registration_handoff: Option<
        std::sync::Arc<crate::registration_handoff::RegistrationHandoffStore>,
    >,
    config: RetryWorkerConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use std::time::Instant;

    use crate::error::DispatchError;
    use crate::models::NotificationContext;

    loop {
        if shutdown.has_changed().unwrap_or(false) && *shutdown.borrow() {
            break;
        }
        // Surface the pending queue depth on each loop so the
        // `floria_retry_queue_depth` gauge tracks the live backlog
        // rather than only the most recent enqueue. Cheap for memory
        // backends and a single ZCARD/EXISTS on Redis.
        crate::metrics::set_retry_queue_depth(pending_len_for_worker(&queue).await as i64);
        // P5 — labelled breakdown. Memory backend reports exact
        // per-provider counts; Redis backend returns an empty map
        // (and the labelled metric simply stops getting updated for
        // that interval — operators read the aggregate gauge instead).
        // Scope label is always `realm` here because retry envelopes
        // do not currently carry circle_id; circle-keyed breakdown is
        // gated behind a future enhancement once that field strands
        // through the envelope.
        for (provider, depth) in queue.pending_breakdown_by_provider() {
            crate::metrics::set_notify_retry_queue_depth_labelled(
                &provider,
                "realm",
                None,
                depth as i64,
            );
        }
        let due = dequeue_due_for_worker(&queue, config.batch_item_count.max(1)).await;
        if due.is_empty() {
            tokio::select! {
                _ = tokio::time::sleep(config.poll_interval) => {}
                _ = shutdown.changed() => break,
            }
            continue;
        }
        for envelope in due {
            let (Some(target), [requested]) = (
                envelope.notification.push_target_id.as_ref(),
                envelope.notification.devices.as_slice(),
            ) else {
                dead_letter_for_worker(&queue, envelope).await;
                continue;
            };
            let device = match crate::resolve_registration(
                registrations.as_ref(),
                registration_handoff.as_deref(),
                &config.gateway_url,
                &envelope.source_id,
                target,
                &requested.device_id,
            )
            .await
            {
                Ok(Some(device)) => device,
                Ok(None) => {
                    crate::metrics::notify_dead_letter(&envelope.pushkin, "registration_unknown");
                    dead_letter_for_worker(&queue, envelope).await;
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, "registration store unavailable during retry");
                    let mut retry = envelope;
                    retry.retry_at_unix_ms = now_unix_ms()
                        .saturating_add(queue.config().default_backoff.as_millis() as u64);
                    queue.enqueue_async(retry).await;
                    continue;
                }
            };
            let Some(app_id) = device.app_id.as_deref() else {
                dead_letter_for_worker(&queue, envelope).await;
                continue;
            };
            let pushkins = registry.find_pushkins(app_id);
            let pushkin = match pushkins
                .iter()
                .find(|candidate| candidate.name() == envelope.pushkin)
            {
                Some(pushkin) => pushkin.clone(),
                None => {
                    tracing::warn!(
                        pushkin = %envelope.pushkin,
                        app_id = %app_id,
                        request_id = %envelope.request_id,
                        "dead-lettering retry: pushkin no longer registered"
                    );
                    crate::metrics::notify_dead_letter(&envelope.pushkin, "pushkin_unregistered");
                    dead_letter_for_worker(&queue, envelope).await;
                    continue;
                }
            };

            let notification = &envelope.notification;
            let context = NotificationContext {
                request_id: envelope.request_id.clone(),
                start_time: Instant::now(),
                allow_plaintext_metadata: false,
            };
            match pushkin
                .dispatch_notification(notification, &device, &context)
                .await
            {
                Ok(rejected) if rejected.is_empty() => {
                    crate::metrics::notify_retry_replayed(&envelope.pushkin, "delivered");
                }
                Ok(rejected) => {
                    let current_route_rejected = rejected
                        .iter()
                        .any(|push_key| push_key == device.push_key.as_str());
                    if current_route_rejected
                        && let Some(store) = registration_handoff.as_deref()
                        && let Err(error) = store
                            .terminalize_provider_invalidation(&envelope.source_id, &device)
                            .await
                    {
                        tracing::warn!(
                            %error,
                            request_id = %envelope.request_id,
                            registration_id = %device.registration_id,
                            "failed to durably tombstone provider-invalid registration during retry"
                        );
                        let mut retry = envelope;
                        retry.retry_at_unix_ms = now_unix_ms()
                            .saturating_add(queue.config().default_backoff.as_millis() as u64);
                        retry.last_error =
                            "registration invalidation persistence failed".to_owned();
                        crate::metrics::notify_retry_replayed(&retry.pushkin, "retry");
                        enqueue_for_worker(&queue, retry).await;
                        continue;
                    }
                    crate::metrics::notify_retry_replayed(&envelope.pushkin, "rejected");
                    dead_letter_for_worker(&queue, envelope).await;
                }
                Err(DispatchError::Temporary { retry_after, .. }) => {
                    let next_attempt = envelope.attempts.saturating_add(1);
                    if next_attempt >= queue.config().max_attempts {
                        crate::metrics::notify_dead_letter(&envelope.pushkin, "max_attempts");
                        crate::metrics::notify_retry_replayed(&envelope.pushkin, "dead_letter");
                        dead_letter_for_worker(&queue, envelope.with_attempt(next_attempt)).await;
                    } else {
                        let backoff =
                            retry_after.unwrap_or_else(|| queue.next_retry_at(next_attempt));
                        let mut next = envelope.clone().with_attempt(next_attempt);
                        next.retry_at_unix_ms = now_unix_ms()
                            .saturating_add(u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX));
                        crate::metrics::notify_retry_replayed(&envelope.pushkin, "retry");
                        enqueue_for_worker(&queue, next).await;
                    }
                }
                Err(error) => {
                    crate::metrics::notify_retry_replayed(&envelope.pushkin, "remote_error");
                    crate::metrics::notify_dead_letter(&envelope.pushkin, "permanent_error");
                    let mut envelope = envelope;
                    envelope.last_error = error.safe_summary().to_owned();
                    dead_letter_for_worker(&queue, envelope).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use arkret_models_integration::{
        PushNotificationEnvelope, PushRegistrationHandoffRequestBody, PushRegistrationRecord,
    };

    use super::*;

    struct CountingPushkin {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crate::pushkin::Pushkin for CountingPushkin {
        fn name(&self) -> &str {
            "org.arkret.fixture"
        }

        fn handles_app_id(&self, app_id: &str) -> bool {
            app_id == self.name()
        }

        async fn dispatch_notification(
            &self,
            _notification: &PushNotificationEnvelope,
            _device: &PushRegistrationRecord,
            _context: &crate::models::NotificationContext,
        ) -> Result<Vec<String>, crate::error::DispatchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    struct RejectingPushkin {
        calls: Arc<AtomicUsize>,
        started: Option<Arc<tokio::sync::Semaphore>>,
        release: Option<Arc<tokio::sync::Notify>>,
    }

    #[async_trait::async_trait]
    impl crate::pushkin::Pushkin for RejectingPushkin {
        fn name(&self) -> &str {
            "org.arkret.fixture"
        }

        fn handles_app_id(&self, app_id: &str) -> bool {
            app_id == self.name()
        }

        async fn dispatch_notification(
            &self,
            _notification: &PushNotificationEnvelope,
            device: &PushRegistrationRecord,
            _context: &crate::models::NotificationContext,
        ) -> Result<Vec<String>, crate::error::DispatchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(started) = &self.started {
                started.add_permits(1);
            }
            if let Some(release) = &self.release {
                release.notified().await;
            }
            Ok(vec![device.push_key.as_str().to_owned()])
        }
    }

    fn test_notification() -> arkret_models_integration::PushNotificationEnvelope {
        serde_json::from_value(serde_json::json!({"push_target_id":"ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8", "wakeup_kind":"message", "devices":[{"device_id":"ak:device:0196419b-0000-7000-8000-000000000001"}]})).unwrap()
    }

    async fn isolated_handoff_store(
        postgres_url: &str,
    ) -> (
        Arc<crate::registration_handoff::RegistrationHandoffStore>,
        arkret_wire::DidCoreId,
        String,
    ) {
        let gateway = arkret_wire::project_did_to_core_id(
            &arkret_wire::Did::new("did:web:gateway.example").unwrap(),
        )
        .unwrap();
        let table = format!("floria_retry_handoff_{}", uuid::Uuid::new_v4().simple());
        let mut config = crate::config::RegistrationHandoffConfig::default();
        config.postgres_url = Some(postgres_url.to_owned());
        config.table = table.clone();
        config.encryption_key_hex = Some(hex::encode([11_u8; 32]));
        config.receipt_signing_key_seed_hex = Some(hex::encode([7_u8; 32]));
        config.receipt_verification_method = Some("did:web:gateway.example#receipt".to_owned());
        let store = Arc::new(
            crate::registration_handoff::RegistrationHandoffStore::from_config(
                &config,
                gateway.clone(),
            )
            .await
            .unwrap()
            .unwrap(),
        );
        (store, gateway, table)
    }

    fn active_handoff_request(
        registration_id: impl serde::Serialize,
        push_key: &str,
        supersedes_registration_id: Option<&arkret_models_integration::PushRegistrationId>,
    ) -> PushRegistrationHandoffRequestBody {
        serde_json::from_value(serde_json::json!({
            "registration_id": registration_id,
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": push_key,
            "platform": "apns",
            "app_id": "org.arkret.fixture",
            "visible_notification_opt_in": false,
            "supersedes_registration_id": supersedes_registration_id
        }))
        .unwrap()
    }

    fn spawn_handoff_retry_worker(
        queue: Arc<RetryQueue>,
        store: Arc<crate::registration_handoff::RegistrationHandoffStore>,
        pushkin: Arc<dyn crate::pushkin::Pushkin>,
    ) -> (
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let registry = Arc::new(crate::pushkin::PushkinRegistry::new(HashMap::from([(
            "org.arkret.fixture".to_owned(),
            pushkin,
        )])));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(async move {
            run_worker(
                queue,
                registry,
                Arc::new(crate::registrations::RegistrationDirectory::default()),
                Some(store),
                RetryWorkerConfig {
                    gateway_url: "https://gateway.example/".to_owned(),
                    poll_interval: Duration::from_millis(5),
                    batch_item_count: 1,
                },
                shutdown_rx,
            )
            .await;
        });
        (shutdown_tx, handle)
    }

    async fn drain_one_handoff_retry(
        store: Arc<crate::registration_handoff::RegistrationHandoffStore>,
        source: arkret_wire::DidCoreId,
        expect_dispatches: usize,
    ) -> (usize, usize) {
        let queue = Arc::new(RetryQueue::memory(RetryQueueConfig::default()));
        queue.enqueue(RetryEnvelope::new(
            "handoff-retry",
            "org.arkret.fixture",
            source,
            test_notification(),
            Duration::ZERO,
            "push provider temporary failure",
        ));
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = Arc::new(crate::pushkin::PushkinRegistry::new(HashMap::from([(
            "org.arkret.fixture".to_owned(),
            Arc::new(CountingPushkin {
                calls: calls.clone(),
            }) as Arc<dyn crate::pushkin::Pushkin>,
        )])));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let worker_queue = queue.clone();
        let handle = tokio::spawn(async move {
            run_worker(
                worker_queue,
                registry,
                Arc::new(crate::registrations::RegistrationDirectory::default()),
                Some(store),
                RetryWorkerConfig {
                    gateway_url: "https://gateway.example/".to_owned(),
                    poll_interval: Duration::from_millis(5),
                    batch_item_count: 1,
                },
                shutdown_rx,
            )
            .await;
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let dead_letters = queue.dead_letter_snapshot(10).len();
                if queue.pending_len() == 0
                    && (calls.load(Ordering::SeqCst) == expect_dispatches || dead_letters == 1)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("retry worker did not settle the handoff envelope");
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap();
        (
            calls.load(Ordering::SeqCst),
            queue.dead_letter_snapshot(10).len(),
        )
    }

    #[tokio::test]
    async fn handoff_retry_uses_exact_source_and_honors_revocation() {
        let Ok(postgres_url) = std::env::var("FLORIA_HANDOFF_TEST_DATABASE_URL") else {
            return;
        };
        let gateway = arkret_wire::project_did_to_core_id(
            &arkret_wire::Did::new("did:web:gateway.example").unwrap(),
        )
        .unwrap();
        let mut config = crate::config::RegistrationHandoffConfig::default();
        config.postgres_url = Some(postgres_url);
        config.encryption_key_hex = Some(hex::encode([11_u8; 32]));
        config.receipt_signing_key_seed_hex = Some(hex::encode([7_u8; 32]));
        config.receipt_verification_method = Some("did:web:gateway.example#receipt".to_owned());
        let store = Arc::new(
            crate::registration_handoff::RegistrationHandoffStore::from_config(
                &config,
                gateway.clone(),
            )
            .await
            .unwrap()
            .unwrap(),
        );
        let source = arkret_wire::DidCoreId::new(format!(
            "ak:did_core:web:retry-{}.example",
            uuid::Uuid::new_v4().simple()
        ))
        .unwrap();
        let request: PushRegistrationHandoffRequestBody =
            serde_json::from_value(serde_json::json!({
                "registration_id": format!("registration_{}", uuid::Uuid::new_v4().simple()),
                "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
                "device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
                "state": "active",
                "push_key": "provider-secret-never-persisted-in-retry",
                "platform": "apns",
                "app_id": "org.arkret.fixture",
                "visible_notification_opt_in": false
            }))
            .unwrap();
        store
            .apply(source.clone(), gateway.clone(), request.clone())
            .await
            .unwrap();

        assert_eq!(
            drain_one_handoff_retry(store.clone(), source.clone(), 1).await,
            (1, 0),
            "an active exact-tenant handoff retry must reach the provider"
        );

        let other_source = arkret_wire::DidCoreId::new(format!(
            "ak:did_core:web:other-{}.example",
            uuid::Uuid::new_v4().simple()
        ))
        .unwrap();
        assert_eq!(
            drain_one_handoff_retry(store.clone(), other_source, 0).await,
            (0, 1),
            "a different source Station must not resolve the provider route"
        );

        let revoked: PushRegistrationHandoffRequestBody =
            serde_json::from_value(serde_json::json!({
                "registration_id": request.registration_id(),
                "push_target_id": request.push_target_id(),
                "device_id": request.device_id(),
                "state": "revoked"
            }))
            .unwrap();
        store.apply(source.clone(), gateway, revoked).await.unwrap();
        assert_eq!(
            drain_one_handoff_retry(store, source, 0).await,
            (0, 1),
            "a revoked route must be rejected before provider dispatch"
        );
    }

    #[tokio::test]
    async fn provider_rejection_durably_tombstones_handoff_before_dead_letter() {
        let Ok(postgres_url) = std::env::var("FLORIA_HANDOFF_TEST_DATABASE_URL") else {
            return;
        };
        let (store, gateway, _) = isolated_handoff_store(&postgres_url).await;
        let source = arkret_wire::DidCoreId::new(format!(
            "ak:did_core:web:retry-reject-{}.example",
            uuid::Uuid::new_v4().simple()
        ))
        .unwrap();
        let request = active_handoff_request(
            format!("registration_{}", uuid::Uuid::new_v4().simple()),
            "provider-invalid-retry-secret",
            None,
        );
        store
            .apply(source.clone(), gateway, request.clone())
            .await
            .unwrap();

        let queue = Arc::new(RetryQueue::memory(RetryQueueConfig::default()));
        queue.enqueue(RetryEnvelope::new(
            "handoff-provider-rejection",
            "org.arkret.fixture",
            source.clone(),
            test_notification(),
            Duration::ZERO,
            "push provider temporary failure",
        ));
        let calls = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, handle) = spawn_handoff_retry_worker(
            queue.clone(),
            store.clone(),
            Arc::new(RejectingPushkin {
                calls: calls.clone(),
                started: None,
                release: None,
            }),
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while queue.dead_letter_snapshot(10).len() != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("provider rejection did not reach the dead letter");
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            store
                .resolve(
                    &source,
                    request.push_target_id(),
                    request.device_id(),
                    "https://gateway.example/",
                )
                .await
                .unwrap()
                .is_none(),
            "the dead letter must not become visible until the provider-invalid route is tombstoned"
        );
    }

    #[tokio::test]
    async fn stale_retry_rejection_cannot_tombstone_a_successor_registration() {
        let Ok(postgres_url) = std::env::var("FLORIA_HANDOFF_TEST_DATABASE_URL") else {
            return;
        };
        let (store, gateway, _) = isolated_handoff_store(&postgres_url).await;
        let source = arkret_wire::DidCoreId::new(format!(
            "ak:did_core:web:retry-stale-{}.example",
            uuid::Uuid::new_v4().simple()
        ))
        .unwrap();
        let predecessor = active_handoff_request(
            format!("registration_{}", uuid::Uuid::new_v4().simple()),
            "stale-provider-secret",
            None,
        );
        store
            .apply(source.clone(), gateway.clone(), predecessor.clone())
            .await
            .unwrap();

        let queue = Arc::new(RetryQueue::memory(RetryQueueConfig::default()));
        queue.enqueue(RetryEnvelope::new(
            "handoff-stale-rejection",
            "org.arkret.fixture",
            source.clone(),
            test_notification(),
            Duration::ZERO,
            "push provider temporary failure",
        ));
        let started = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, handle) = spawn_handoff_retry_worker(
            queue.clone(),
            store.clone(),
            Arc::new(RejectingPushkin {
                calls: calls.clone(),
                started: Some(started.clone()),
                release: Some(release.clone()),
            }),
        );
        tokio::time::timeout(Duration::from_secs(2), started.acquire())
            .await
            .expect("provider dispatch did not start")
            .unwrap()
            .forget();

        let successor = active_handoff_request(
            format!("registration_{}", uuid::Uuid::new_v4().simple()),
            "successor-provider-secret",
            Some(predecessor.registration_id()),
        );
        store
            .apply(source.clone(), gateway, successor.clone())
            .await
            .unwrap();
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), async {
            while queue.dead_letter_snapshot(10).len() != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("stale provider rejection did not settle");
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap();

        let current = store
            .resolve(
                &source,
                successor.push_target_id(),
                successor.device_id(),
                "https://gateway.example/",
            )
            .await
            .unwrap()
            .expect("successor must remain active");
        assert_eq!(
            current.registration_id.as_str(),
            successor.registration_id().as_str()
        );
        assert_eq!(current.push_key.as_str(), "successor-provider-secret");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tombstone_storage_failure_requeues_instead_of_dead_lettering() {
        let Ok(postgres_url) = std::env::var("FLORIA_HANDOFF_TEST_DATABASE_URL") else {
            return;
        };
        let (store, gateway, table) = isolated_handoff_store(&postgres_url).await;
        let source = arkret_wire::DidCoreId::new(format!(
            "ak:did_core:web:retry-storage-{}.example",
            uuid::Uuid::new_v4().simple()
        ))
        .unwrap();
        let request = active_handoff_request(
            format!("registration_{}", uuid::Uuid::new_v4().simple()),
            "storage-failure-provider-secret",
            None,
        );
        store.apply(source.clone(), gateway, request).await.unwrap();

        let queue = Arc::new(RetryQueue::memory(RetryQueueConfig {
            default_backoff: Duration::from_secs(60),
            max_backoff: Duration::from_secs(60),
            ..RetryQueueConfig::default()
        }));
        queue.enqueue(RetryEnvelope::new(
            "handoff-storage-failure",
            "org.arkret.fixture",
            source,
            test_notification(),
            Duration::ZERO,
            "push provider temporary failure",
        ));
        let started = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, handle) = spawn_handoff_retry_worker(
            queue.clone(),
            store,
            Arc::new(RejectingPushkin {
                calls: calls.clone(),
                started: Some(started.clone()),
                release: Some(release.clone()),
            }),
        );
        tokio::time::timeout(Duration::from_secs(2), started.acquire())
            .await
            .expect("provider dispatch did not start")
            .unwrap()
            .forget();
        let postgres_url_for_drop = postgres_url.clone();
        tokio::task::spawn_blocking(move || {
            let mut client = postgres::Client::connect(&postgres_url_for_drop, postgres::NoTls)
                .expect("connect test PostgreSQL");
            client
                .batch_execute(&format!("DROP TABLE {table}"))
                .expect("drop isolated handoff table");
        })
        .await
        .unwrap();
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), async {
            while queue.pending_len() != 1 {
                assert!(queue.dead_letter_snapshot(10).is_empty());
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("failed tombstone was not requeued");
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(queue.pending_len(), 1);
        assert!(queue.dead_letter_snapshot(10).is_empty());
    }

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
                arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                test_notification(),
                Duration::ZERO,
                "boom",
            )
            .with_attempt(1),
        );
        queue.enqueue(
            RetryEnvelope::new(
                "req",
                "apns",
                arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                test_notification(),
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
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            test_notification(),
            Duration::ZERO,
            "boom",
        ));
        queue.enqueue(RetryEnvelope::new(
            "req",
            "apns",
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            test_notification(),
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
        // arkret-retry applies the spec-default 0–20% additive jitter on top
        // of the saturated 60s base.
        let backoff = queue.next_retry_at(20);
        assert!(
            backoff >= Duration::from_millis(60_000) && backoff <= Duration::from_millis(72_000),
            "backoff {backoff:?} outside expected jitter window"
        );
    }

    #[test]
    fn redis_backend_requires_valid_url() {
        let error = RetryQueue::redis_with_cipher(
            RetryQueueConfig::default(),
            "://bad-url",
            "floria",
            None,
        )
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
        assert!(
            format!("{overlay:?}").contains("floria"),
            "overlay debug must include the table"
        );
    }
}
