use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use redis::Commands;

use crate::auth::redact_url_credentials;
use crate::config::NotifyRateLimitConfig;

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

#[derive(Debug)]
struct WindowCounter {
    started_at: Instant,
    count: u64,
}

#[derive(Debug)]
struct MemoryRateLimiter {
    counters: Mutex<HashMap<String, WindowCounter>>,
}

#[derive(Debug)]
struct RedisRateLimiter {
    client: redis::Client,
    target_label: String,
    key_prefix: String,
}

#[derive(Debug)]
enum RateLimiterBackend {
    Memory(MemoryRateLimiter),
    Redis(RedisRateLimiter),
}

#[derive(Debug)]
pub struct NotifyRateLimiter {
    config: NotifyRateLimitConfig,
    window: Duration,
    backend: RateLimiterBackend,
}

impl NotifyRateLimiter {
    pub fn new(config: NotifyRateLimitConfig) -> Self {
        Self {
            window: Duration::from_secs(config.window_seconds.max(1)),
            config,
            backend: RateLimiterBackend::Memory(MemoryRateLimiter {
                counters: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn redis(
        config: NotifyRateLimitConfig,
        redis_url: &str,
        key_prefix: impl Into<String>,
    ) -> Result<Self> {
        let client = redis::Client::open(redis_url).with_context(|| {
            format!(
                "invalid notify_rate_limits redis_url `{}`",
                redact_url_credentials(redis_url)
            )
        })?;
        Ok(Self {
            window: Duration::from_secs(config.window_seconds.max(1)),
            config,
            backend: RateLimiterBackend::Redis(RedisRateLimiter {
                client,
                target_label: redact_url_credentials(redis_url),
                key_prefix: normalize_key_prefix(&key_prefix.into()),
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
}

impl MemoryRateLimiter {
    fn check_many(
        &self,
        window: Duration,
        checks: &[NotifyRateLimitCheck],
    ) -> Result<(), NotifyRateLimitRejection> {
        let now = Instant::now();
        let mut counters = self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counters.retain(|_, counter| now.duration_since(counter.started_at) < window);

        for check in checks {
            let counter = counters
                .entry(counter_key(check.scope, &check.subject))
                .or_insert_with(|| WindowCounter {
                    started_at: now,
                    count: 0,
                });
            if now.duration_since(counter.started_at) >= window {
                counter.started_at = now;
                counter.count = 0;
            }
            if counter.count.saturating_add(check.units) > check.limit {
                return Err(NotifyRateLimitRejection {
                    scope: check.scope,
                    subject: check.subject.clone(),
                    limit: check.limit,
                    retry_after: window
                        .saturating_sub(now.duration_since(counter.started_at))
                        .max(Duration::from_secs(1)),
                });
            }
        }

        for check in checks {
            let counter = counters
                .entry(counter_key(check.scope, &check.subject))
                .or_insert_with(|| WindowCounter {
                    started_at: now,
                    count: 0,
                });
            if now.duration_since(counter.started_at) >= window {
                counter.started_at = now;
                counter.count = 0;
            }
            counter.count = counter.count.saturating_add(check.units);
        }

        Ok(())
    }
}

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

    fn check_many(
        &self,
        window: Duration,
        checks: &[NotifyRateLimitCheck],
    ) -> Result<(), NotifyRateLimitRejection> {
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(error) => {
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
                tracing::warn!(error = %error, backend = %self.target_label, "Redis rate limit script failed; allowing request");
                Ok(())
            }
        }
    }

    fn retry_after_for(
        &self,
        connection: &mut redis::Connection,
        key: &str,
        window: Duration,
    ) -> Duration {
        match connection.ttl::<_, i64>(key) {
            Ok(seconds) if seconds > 0 => Duration::from_secs(seconds as u64),
            _ => window,
        }
        .max(Duration::from_secs(1))
    }

    fn connection(&self) -> Result<redis::Connection> {
        self.client
            .get_connection()
            .with_context(|| format!("failed to connect to Redis backend {}", self.target_label))
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
            subject: "did:web:sync.example.com".to_owned(),
            limit: 1,
            units: 1,
        }];

        assert!(limiter.check_many(&checks).is_ok());
        let rejection = limiter.check_many(&checks).unwrap_err();
        assert_eq!(rejection.scope, "origin_service");
        assert_eq!(rejection.subject, "did:web:sync.example.com");
        assert_eq!(rejection.limit, 1);
        assert!(rejection.retry_after >= Duration::from_secs(1));
    }

    #[test]
    fn redis_backend_requires_valid_url() {
        let error = NotifyRateLimiter::redis(config(), "://bad-url", "floria")
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
                subject: "did:web:sync.example.com".to_owned(),
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
            subject: "did:web:sync.example.com".to_owned(),
            limit: 1,
            units: 1,
        }];
        assert!(limiter.check_many(&probe).is_ok());
    }
}
