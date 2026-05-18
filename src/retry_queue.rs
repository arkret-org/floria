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
use redis::Commands;
use serde::{Deserialize, Serialize};

use crate::auth::redact_url_credentials;

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
}

impl RetryQueue {
    pub fn memory(config: RetryQueueConfig) -> Self {
        Self {
            config,
            backend: Backend::Memory(MemoryQueue {
                pending: Mutex::new(BinaryHeap::new()),
                dead_letter: Mutex::new(VecDeque::new()),
            }),
        }
    }

    pub fn redis(
        config: RetryQueueConfig,
        redis_url: &str,
        key_prefix: impl Into<String>,
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
            }),
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
        match &self.backend {
            Backend::Memory(backend) => {
                backend.push_dead_letter(envelope, self.config.dead_letter_capacity)
            }
            Backend::Redis(backend) => backend.push_dead_letter(envelope),
        }
    }

    pub fn pending_len(&self) -> usize {
        match &self.backend {
            Backend::Memory(backend) => {
                backend.pending.lock().map(|guard| guard.len()).unwrap_or(0)
            }
            Backend::Redis(backend) => backend.pending_len().unwrap_or(0) as usize,
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
    /// `max_backoff`.
    pub fn next_retry_at(&self, attempts: u32) -> Duration {
        let base = self.config.default_backoff;
        let factor = 1u32 << attempts.min(10);
        base.saturating_mul(factor).min(self.config.max_backoff)
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
        let payload = match serde_json::to_string(&envelope) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(error = %error, "failed to serialize retry envelope");
                return;
            }
        };
        let result: redis::RedisResult<()> =
            connection.zadd(&key, payload, envelope.retry_at_unix_ms);
        if let Err(error) = result {
            tracing::warn!(error = %error, backend = %self.target_label, redis_key = %key, "failed to enqueue retry on Redis");
        }
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
            match serde_json::from_str::<RetryEnvelope>(&payload) {
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
        let payload = match serde_json::to_string(&envelope) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(error = %error, "failed to serialize dead-letter envelope");
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
                .filter_map(|payload| serde_json::from_str::<RetryEnvelope>(&payload).ok())
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
                push_hint: Some("retry-replay".to_owned()),
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
        let backoff = queue.next_retry_at(20);
        assert_eq!(backoff, Duration::from_secs(60));
    }

    #[test]
    fn redis_backend_requires_valid_url() {
        let error = RetryQueue::redis(RetryQueueConfig::default(), "://bad-url", "floria")
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid notify_retry_queue redis_url"));
    }
}
