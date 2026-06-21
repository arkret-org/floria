//! Replay-window nonce store for HTTP Message Signature.
//!
//! After a signature passes static verification (key id, algorithm,
//! covered components, created/expires window, body digest, ed25519
//! check) we record a stable fingerprint of the signature bytes so a
//! replay arriving inside the `expires - created` window can be
//! rejected even though it is otherwise structurally valid.
//!
//! ## Backends
//!
//! - `Memory`: process-local; sufficient for single-instance deployments and CI; no cross-instance
//!   replay protection.
//! - `Redis`: shared across gateway replicas; uses `SET ... NX EX` so the first instance to claim a
//!   fingerprint wins; subsequent replays return a conflict.
//!
//! Failure mode: if Redis is unreachable the store fails *open* —
//! signatures pass replay protection but the existing static expiry
//! check still bounds the attack window. A warning is logged so the
//! operator notices.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use lru::LruCache;

use crate::auth::redact_url_credentials;
use crate::redis_support::{RedisConnection, RedisPool};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceCheck {
    Fresh,
    Replayed,
    /// Backend (Redis) is unreachable and the configured failure policy
    /// is `strict` — callers must treat this as a fail-closed signal
    /// (HTTP 503).
    BackendUnavailable,
}

/// Behaviour when the Redis backend is unreachable. `Strict` (the
/// default) is fail-closed: the gateway returns 503 from the calling site
/// rather than silently bypassing replay protection / rate limiting.
/// `Permissive` is the opt-in fail-open semantic for deployments that
/// accept silent bypass during a Redis outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedisFailurePolicy {
    #[default]
    Strict,
    Permissive,
}

impl RedisFailurePolicy {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "permissive" => Self::Permissive,
            // Default and any unrecognized value fail closed.
            _ => Self::Strict,
        }
    }

    pub fn is_strict(self) -> bool {
        matches!(self, Self::Strict)
    }
}

const DEFAULT_MEMORY_NONCE_MAX_ENTRIES: usize = 65_536;

#[derive(Debug)]
struct MemoryNonceStore {
    seen: Mutex<LruCache<String, Instant>>,
}

#[derive(Debug)]
struct RedisNonceStore {
    pool: RedisPool,
    target_label: String,
    key_prefix: String,
    failure_policy: RedisFailurePolicy,
}

#[derive(Debug)]
enum NonceBackend {
    Memory(MemoryNonceStore),
    Redis(RedisNonceStore),
}

#[derive(Debug)]
pub struct NonceStore {
    ttl: Duration,
    backend: NonceBackend,
}

impl NonceStore {
    pub fn memory(ttl: Duration) -> Self {
        Self {
            ttl,
            backend: NonceBackend::Memory(MemoryNonceStore {
                seen: Mutex::new(LruCache::new(
                    NonZeroUsize::new(DEFAULT_MEMORY_NONCE_MAX_ENTRIES)
                        .expect("DEFAULT_MEMORY_NONCE_MAX_ENTRIES is non-zero"),
                )),
            }),
        }
    }

    pub fn redis(ttl: Duration, redis_url: &str, key_prefix: impl Into<String>) -> Result<Self> {
        Self::redis_with_policy(ttl, redis_url, key_prefix, RedisFailurePolicy::Strict)
    }

    pub fn redis_with_policy(
        ttl: Duration,
        redis_url: &str,
        key_prefix: impl Into<String>,
        failure_policy: RedisFailurePolicy,
    ) -> Result<Self> {
        let client = redis::Client::open(redis_url).with_context(|| {
            format!(
                "invalid notify_auth.nonce_store redis_url `{}`",
                redact_url_credentials(redis_url)
            )
        })?;
        let target_label = redact_url_credentials(redis_url);
        Ok(Self {
            ttl,
            backend: NonceBackend::Redis(RedisNonceStore {
                pool: RedisPool::from_client(client, target_label.clone())?,
                target_label,
                key_prefix: normalize_key_prefix(&key_prefix.into()),
                failure_policy,
            }),
        })
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn backend_name(&self) -> &'static str {
        match self.backend {
            NonceBackend::Memory(_) => "memory",
            NonceBackend::Redis(_) => "redis",
        }
    }

    pub fn ready(&self) -> Result<(), String> {
        match &self.backend {
            NonceBackend::Memory(_) => Ok(()),
            NonceBackend::Redis(backend) => backend.ready().map_err(|error| error.to_string()),
        }
    }

    /// Atomically claim `fingerprint`. Returns `Fresh` if no prior
    /// observation existed within the TTL, `Replayed` if a previous
    /// caller already claimed the slot.
    pub fn observe(&self, fingerprint: &str) -> NonceCheck {
        if self.ttl.is_zero() {
            return NonceCheck::Fresh;
        }
        match &self.backend {
            NonceBackend::Memory(backend) => backend.observe(self.ttl, fingerprint),
            NonceBackend::Redis(backend) => backend.observe(self.ttl, fingerprint),
        }
    }

    /// Async-safe [`Self::observe`]: the in-memory backend runs inline
    /// (lock-bounded, non-blocking) while the Redis backend — which opens
    /// a blocking connection and runs a blocking `SET NX EX` — is
    /// offloaded to `spawn_blocking` so the /notify auth path never
    /// stalls a tokio worker thread (FLO-02-002).
    pub async fn observe_async(self: &Arc<Self>, fingerprint: &str) -> NonceCheck {
        if self.ttl.is_zero() {
            return NonceCheck::Fresh;
        }
        match &self.backend {
            NonceBackend::Memory(backend) => backend.observe(self.ttl, fingerprint),
            NonceBackend::Redis(_) => {
                let this = Arc::clone(self);
                let fingerprint = fingerprint.to_owned();
                tokio::task::spawn_blocking(move || this.observe(&fingerprint))
                    .await
                    .unwrap_or(NonceCheck::Fresh)
            }
        }
    }
}

impl MemoryNonceStore {
    fn observe(&self, ttl: Duration, fingerprint: &str) -> NonceCheck {
        let now = Instant::now();
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(expires_at) = seen.get(fingerprint)
            && *expires_at > now
        {
            return NonceCheck::Replayed;
        }
        seen.put(fingerprint.to_owned(), now + ttl);
        NonceCheck::Fresh
    }
}

impl RedisNonceStore {
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

    fn observe(&self, ttl: Duration, fingerprint: &str) -> NonceCheck {
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(error) => {
                if self.failure_policy.is_strict() {
                    tracing::warn!(error = %error, backend = %self.target_label, "failed to connect to Redis nonce store; failing closed (strict)");
                    return NonceCheck::BackendUnavailable;
                }
                tracing::warn!(error = %error, backend = %self.target_label, "failed to connect to Redis nonce store; failing open");
                return NonceCheck::Fresh;
            }
        };
        let key = self.key(fingerprint);
        let ttl_secs = ttl.as_secs().max(1);
        let result: redis::RedisResult<Option<String>> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query(&mut connection);
        match result {
            Ok(Some(_)) => NonceCheck::Fresh,
            Ok(None) => NonceCheck::Replayed,
            Err(error) => {
                if self.failure_policy.is_strict() {
                    tracing::warn!(error = %error, backend = %self.target_label, redis_key = %key, "failed to claim Redis nonce; failing closed (strict)");
                    return NonceCheck::BackendUnavailable;
                }
                tracing::warn!(error = %error, backend = %self.target_label, redis_key = %key, "failed to claim Redis nonce; failing open");
                NonceCheck::Fresh
            }
        }
    }

    fn connection(&self) -> Result<RedisConnection> {
        self.pool.connection()
    }

    fn key(&self, fingerprint: &str) -> String {
        format!("{}:auth:nonce:{{{fingerprint}}}", self.key_prefix)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_replayed_fingerprint() {
        let store = NonceStore::memory(Duration::from_secs(60));
        assert_eq!(store.observe("abc"), NonceCheck::Fresh);
        assert_eq!(store.observe("abc"), NonceCheck::Replayed);
    }

    #[test]
    fn allows_distinct_fingerprints() {
        let store = NonceStore::memory(Duration::from_secs(60));
        assert_eq!(store.observe("first"), NonceCheck::Fresh);
        assert_eq!(store.observe("second"), NonceCheck::Fresh);
    }

    #[test]
    fn zero_ttl_disables_observation() {
        let store = NonceStore::memory(Duration::from_secs(0));
        assert_eq!(store.observe("abc"), NonceCheck::Fresh);
        assert_eq!(store.observe("abc"), NonceCheck::Fresh);
    }

    #[test]
    fn redis_backend_requires_valid_url() {
        let error = NonceStore::redis(Duration::from_secs(60), "://bad-url", "floria")
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid notify_auth.nonce_store redis_url"));
    }
}
