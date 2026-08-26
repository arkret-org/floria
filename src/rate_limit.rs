use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arkret_rate_limit::{FixedWindowConfig, MemoryFixedWindowRateLimiter};
use redis::Commands;

use crate::auth::redact_url_credentials;
use crate::config::NotifyRateLimitConfig;
use crate::nonce_store::RedisFailurePolicy;
use crate::redis_support::{RedisConnection, RedisPool};

#[derive(Debug, Clone)]
pub struct NotifyRateLimitCheck {
    pub scope: &'static str,
    pub subject: String,
    pub limit: u64,
    pub units: u64,
}

#[derive(Debug, Clone)]
pub struct NotifyRateLimitRejection {
    pub scope: &'static str,
    pub subject: String,
    pub limit: u64,
    pub retry_after: Duration,
}

struct MemoryRateLimiter {
    counters: MemoryFixedWindowRateLimiter<String>,
}

#[derive(Debug)]
struct RedisRateLimiter {
    pool: RedisPool,
    target_label: String,
    key_prefix: String,
    failure_policy: RedisFailurePolicy,
}

enum RateLimiterBackend {
    Memory(MemoryRateLimiter),
    Redis(RedisRateLimiter),
}

pub struct NotifyRateLimiter {
    config: NotifyRateLimitConfig,
    window: Duration,
    backend: RateLimiterBackend,
}

impl std::fmt::Debug for NotifyRateLimiter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let backend = match &self.backend {
            RateLimiterBackend::Memory(_) => "memory",
            RateLimiterBackend::Redis(_) => "redis",
        };
        formatter
            .debug_struct("NotifyRateLimiter")
            .field("window", &self.window)
            .field("backend", &backend)
            .finish_non_exhaustive()
    }
}

impl NotifyRateLimiter {
    pub fn new(config: NotifyRateLimitConfig) -> Self {
        Self {
            window: Duration::from_secs(config.window_seconds.max(1)),
            config,
            backend: RateLimiterBackend::Memory(MemoryRateLimiter {
                counters: MemoryFixedWindowRateLimiter::new(FixedWindowConfig::new(
                    1,
                    Duration::from_secs(60),
                    MEMORY_RATE_LIMIT_MAX_ENTRIES,
                )),
            }),
        }
    }

    pub fn redis_with_policy(
        config: NotifyRateLimitConfig,
        redis_url: &str,
        key_prefix: impl Into<String>,
        failure_policy: RedisFailurePolicy,
    ) -> Result<Self> {
        let client = redis::Client::open(redis_url).with_context(|| {
            format!(
                "invalid notify_rate_limits redis_url `{}`",
                redact_url_credentials(redis_url)
            )
        })?;
        let target_label = redact_url_credentials(redis_url);
        Ok(Self {
            window: Duration::from_secs(config.window_seconds.max(1)),
            config,
            backend: RateLimiterBackend::Redis(RedisRateLimiter {
                pool: RedisPool::from_client(client, target_label.clone())?,
                target_label,
                key_prefix: normalize_key_prefix(&key_prefix.into()),
                failure_policy,
            }),
        })
    }

    pub fn config(&self) -> &NotifyRateLimitConfig {
        &self.config
    }

    pub fn backend_name(&self) -> &'static str {
        match &self.backend {
            RateLimiterBackend::Memory(_) => "memory",
            RateLimiterBackend::Redis(_) => "redis",
        }
    }

    pub fn ready(&self) -> Result<(), String> {
        match &self.backend {
            RateLimiterBackend::Memory(_) => Ok(()),
            RateLimiterBackend::Redis(backend) => {
                backend.ready().map_err(|error| error.to_string())
            }
        }
    }

    pub fn check_many(
        &self,
        checks: &[NotifyRateLimitCheck],
    ) -> Result<(), NotifyRateLimitRejection> {
        if checks.is_empty() {
            return Ok(());
        }

        match &self.backend {
            RateLimiterBackend::Memory(backend) => backend.check_many(self.window, checks),
            RateLimiterBackend::Redis(backend) => backend.check_many(self.window, checks),
        }
    }

    /// Async-safe [`Self::check_many`]: the in-memory backend runs inline
    /// (lock-bounded, non-blocking) while the Redis backend — which opens
    /// a blocking connection and runs a blocking EVAL — is offloaded to
    /// `spawn_blocking` so it never stalls a tokio worker thread
    /// (FLO-02-002).
    pub async fn check_many_async(
        self: &Arc<Self>,
        checks: &[NotifyRateLimitCheck],
    ) -> Result<(), NotifyRateLimitRejection> {
        if checks.is_empty() {
            return Ok(());
        }
        match &self.backend {
            RateLimiterBackend::Memory(backend) => backend.check_many(self.window, checks),
            RateLimiterBackend::Redis(_) => {
                let this = Arc::clone(self);
                let checks = checks.to_vec();
                tokio::task::spawn_blocking(move || this.check_many(&checks))
                    .await
                    .unwrap_or(Ok(()))
            }
        }
    }
}

impl MemoryRateLimiter {
    fn check_many(
        &self,
        window: Duration,
        checks: &[NotifyRateLimitCheck],
    ) -> Result<(), NotifyRateLimitRejection> {
        self.counters
            .check_many_with_config(checks.iter().map(|check| {
                (
                    counter_key(check.scope, &check.subject),
                    check.units,
                    FixedWindowConfig::new(check.limit, window, MEMORY_RATE_LIMIT_MAX_ENTRIES),
                )
            }))
            .map_err(|rejection| {
                let check = checks
                    .iter()
                    .find(|check| counter_key(check.scope, &check.subject) == rejection.key)
                    .expect("rejected key came from the supplied checks");
                NotifyRateLimitRejection {
                    scope: check.scope,
                    subject: check.subject.clone(),
                    limit: check.limit,
                    retry_after: rejection.retry_after.max(Duration::from_secs(1)),
                }
            })
    }
}

const MEMORY_RATE_LIMIT_MAX_ENTRIES: usize = 100_000;

/// Lua script that performs an all-or-nothing rate limit check across N
/// (key, limit, units) triples. ARGV is `[ttl_secs, limit_1, units_1, ...,
/// limit_n, units_n]`. Returns 0 on success or a 1-based index of the
/// failing check; failed checks roll back any earlier increments so the
/// overall semantic matches the in-memory all-or-nothing path.
const RATE_LIMIT_LUA: &str = r#"
local ttl = tonumber(ARGV[1])
local n = #KEYS
for i = 1, n do
  local limit = tonumber(ARGV[2 + (i - 1) * 2])
  local units = tonumber(ARGV[3 + (i - 1) * 2])
  local val = redis.call('INCRBY', KEYS[i], units)
  if val == units then
    redis.call('EXPIRE', KEYS[i], ttl)
  end
  if val > limit then
    for j = 1, i do
      local rollback_units = tonumber(ARGV[3 + (j - 1) * 2])
      redis.call('DECRBY', KEYS[j], rollback_units)
    end
    return i
  end
end
return 0
"#;

impl RedisRateLimiter {
    fn ready(&self) -> Result<()> {
        self.pool.ready()
    }

    fn check_many(
        &self,
        window: Duration,
        checks: &[NotifyRateLimitCheck],
    ) -> Result<(), NotifyRateLimitRejection> {
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(error) => {
                if self.failure_policy.is_strict() {
                    tracing::warn!(error = %error, backend = %self.target_label, "failed to connect to Redis rate limit cache; failing closed (strict)");
                    // Use the first check as the rejection subject. The
                    // strict policy treats backend unavailability as a
                    // 429 so callers back off instead of overwhelming a
                    // recovering Redis.
                    let check = &checks[0];
                    return Err(NotifyRateLimitRejection {
                        scope: check.scope,
                        subject: check.subject.clone(),
                        limit: check.limit,
                        retry_after: window.max(Duration::from_secs(1)),
                    });
                }
                tracing::warn!(error = %error, backend = %self.target_label, "failed to connect to Redis rate limit cache; allowing request");
                return Ok(());
            }
        };

        let ttl_secs = window.as_secs().max(1);
        let keys = checks
            .iter()
            .map(|check| self.counter_key(check.scope, &check.subject))
            .collect::<Vec<_>>();

        let mut script = redis::cmd("EVAL");
        script.arg(RATE_LIMIT_LUA);
        script.arg(keys.len());
        for key in &keys {
            script.arg(key);
        }
        script.arg(ttl_secs);
        for check in checks {
            script.arg(check.limit);
            script.arg(check.units);
        }

        let result: redis::RedisResult<i64> = script.query(&mut connection);
        match result {
            Ok(0) => Ok(()),
            Ok(index) if index >= 1 && (index as usize) <= checks.len() => {
                let check = &checks[(index as usize) - 1];
                Err(NotifyRateLimitRejection {
                    scope: check.scope,
                    subject: check.subject.clone(),
                    limit: check.limit,
                    retry_after: self.retry_after_for(
                        &mut connection,
                        &keys[(index as usize) - 1],
                        window,
                    ),
                })
            }
            Ok(other) => {
                tracing::warn!(
                    backend = %self.target_label,
                    "unexpected Redis rate limit script return value `{other}`; allowing request"
                );
                Ok(())
            }
            Err(error) => {
                if self.failure_policy.is_strict() {
                    tracing::warn!(error = %error, backend = %self.target_label, "Redis rate limit script failed; failing closed (strict)");
                    let check = &checks[0];
                    return Err(NotifyRateLimitRejection {
                        scope: check.scope,
                        subject: check.subject.clone(),
                        limit: check.limit,
                        retry_after: window.max(Duration::from_secs(1)),
                    });
                }
                tracing::warn!(error = %error, backend = %self.target_label, "Redis rate limit script failed; allowing request");
                Ok(())
            }
        }
    }

    fn retry_after_for(
        &self,
        connection: &mut RedisConnection,
        key: &str,
        window: Duration,
    ) -> Duration {
        match connection.ttl::<_, i64>(key) {
            Ok(seconds) if seconds > 0 => Duration::from_secs(seconds as u64),
            _ => window,
        }
        .max(Duration::from_secs(1))
    }

    fn connection(&self) -> Result<RedisConnection> {
        self.pool.connection()
    }

    /// Wrap the dynamic component in Redis cluster hash tags so every
    /// counter for a given subject hashes to the same slot — the EVAL
    /// script touches each KEYS[i] independently so this is mostly a
    /// stylistic guarantee, but it lets all per-subject keys share a
    /// node when operators run a clustered Redis.
    fn counter_key(&self, scope: &str, subject: &str) -> String {
        format!("{}:rl:{scope}:{{{subject}}}", self.key_prefix)
    }
}

fn counter_key(scope: &str, subject: &str) -> String {
    format!("{scope}\0{subject}")
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

    fn config() -> NotifyRateLimitConfig {
        let mut config = NotifyRateLimitConfig::default();
        config.window_seconds = 60;
        config.per_origin_service = Some(1);
        config
    }

    #[test]
    fn rejects_when_limit_is_exceeded() {
        let limiter = NotifyRateLimiter::new(config());
        let checks = vec![NotifyRateLimitCheck {
            scope: "origin_service",
            subject: "ak:did_core:web:sync.example.com".to_owned(),
            limit: 1,
            units: 1,
        }];

        assert!(limiter.check_many(&checks).is_ok());
        let rejection = limiter.check_many(&checks).unwrap_err();
        assert_eq!(rejection.scope, "origin_service");
        assert_eq!(rejection.subject, "ak:did_core:web:sync.example.com");
        assert_eq!(rejection.limit, 1);
        assert!(rejection.retry_after >= Duration::from_secs(1));
    }

    #[test]
    fn redis_backend_requires_valid_url() {
        let error = NotifyRateLimiter::redis_with_policy(
            config(),
            "://bad-url",
            "floria",
            RedisFailurePolicy::Strict,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("invalid notify_rate_limits redis_url"));
    }

    #[test]
    fn rolls_back_earlier_increments_when_a_later_check_fails() {
        // Memory all-or-nothing semantic: even if check #1 would have
        // accepted, when check #2 trips its limit, neither counter is
        // committed.
        let mut config = NotifyRateLimitConfig::default();
        config.window_seconds = 60;
        let limiter = NotifyRateLimiter::new(config);

        // Pre-saturate the second counter at limit=1.
        let saturate = vec![NotifyRateLimitCheck {
            scope: "endpoint",
            subject: "saturated".to_owned(),
            limit: 1,
            units: 1,
        }];
        assert!(limiter.check_many(&saturate).is_ok());

        // A combined batch should fail without consuming the new
        // origin_service budget.
        let combined = vec![
            NotifyRateLimitCheck {
                scope: "origin_service",
                subject: "ak:did_core:web:sync.example.com".to_owned(),
                limit: 1,
                units: 1,
            },
            NotifyRateLimitCheck {
                scope: "endpoint",
                subject: "saturated".to_owned(),
                limit: 1,
                units: 1,
            },
        ];
        assert!(limiter.check_many(&combined).is_err());

        // origin_service should still be free for a fresh single check.
        let probe = vec![NotifyRateLimitCheck {
            scope: "origin_service",
            subject: "ak:did_core:web:sync.example.com".to_owned(),
            limit: 1,
            units: 1,
        }];
        assert!(limiter.check_many(&probe).is_ok());
    }

    #[test]
    #[ignore = "long-running local soak scaffold; set FLORIA_SOAK_RUN=1 to execute"]
    fn soak_chaos_rate_limit_cleanup() {
        if env::var("FLORIA_SOAK_RUN").ok().as_deref() != Some("1") {
            eprintln!("set FLORIA_SOAK_RUN=1 to run the local soak/chaos scaffold");
            return;
        }

        let notifications_per_minute = env_usize("FLORIA_SOAK_NOTIFICATIONS_PER_MINUTE", 10_000);
        let minutes = env_usize("FLORIA_SOAK_MINUTES", 30);
        let realtime = env::var("FLORIA_SOAK_REALTIME").ok().as_deref() == Some("1");
        let window = if realtime {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(1)
        };

        let mut config = NotifyRateLimitConfig::default();
        config.window_seconds = window.as_secs();
        let limiter = NotifyRateLimiter::new(config);

        for minute in 0..minutes {
            for index in 0..notifications_per_minute {
                let check = NotifyRateLimitCheck {
                    scope: "soak_notification",
                    subject: format!("minute-{minute}-device-{index}"),
                    limit: 1,
                    units: 1,
                };
                limiter
                    .check_many(&[check])
                    .expect("soak rate-limit check should accept unique subjects");
            }

            let live_counters = memory_counter_len(&limiter);
            assert!(
                live_counters <= notifications_per_minute + 1,
                "rate-limit counters grew beyond one active window: {live_counters}"
            );

            std::thread::sleep(window + Duration::from_millis(50));
            let cleanup_probe = NotifyRateLimitCheck {
                scope: "soak_cleanup_probe",
                subject: format!("minute-{minute}"),
                limit: 1,
                units: 1,
            };
            limiter
                .check_many(&[cleanup_probe])
                .expect("cleanup probe should be accepted");
            assert_eq!(
                memory_counter_len(&limiter),
                1,
                "expired rate-limit counters should be retained only until the next check"
            );
        }
    }

    fn env_usize(name: &str, default: usize) -> usize {
        env::var(name)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(default)
    }

    fn memory_counter_len(limiter: &NotifyRateLimiter) -> usize {
        match &limiter.backend {
            RateLimiterBackend::Memory(backend) => backend.counters.entry_count(),
            RateLimiterBackend::Redis(_) => unreachable!("soak scaffold uses memory backend"),
        }
    }
}
