use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
pub struct NotifyRateLimiter {
    config: NotifyRateLimitConfig,
    window: Duration,
    counters: Mutex<HashMap<String, WindowCounter>>,
}

impl NotifyRateLimiter {
    pub fn new(config: NotifyRateLimitConfig) -> Self {
        Self {
            window: Duration::from_secs(config.window_seconds.max(1)),
            config,
            counters: Mutex::new(HashMap::new()),
        }
    }

    pub fn config(&self) -> &NotifyRateLimitConfig {
        &self.config
    }

    pub fn check_many(
        &self,
        checks: &[NotifyRateLimitCheck],
    ) -> Result<(), NotifyRateLimitRejection> {
        if checks.is_empty() {
            return Ok(());
        }

        let now = Instant::now();
        let mut counters = self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counters.retain(|_, counter| now.duration_since(counter.started_at) < self.window);

        for check in checks {
            let counter = counters
                .entry(counter_key(check.scope, &check.subject))
                .or_insert_with(|| WindowCounter {
                    started_at: now,
                    count: 0,
                });
            if now.duration_since(counter.started_at) >= self.window {
                counter.started_at = now;
                counter.count = 0;
            }
            if counter.count.saturating_add(check.units) > check.limit {
                return Err(NotifyRateLimitRejection {
                    scope: check.scope,
                    subject: check.subject.clone(),
                    limit: check.limit,
                    retry_after: self
                        .window
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
            if now.duration_since(counter.started_at) >= self.window {
                counter.started_at = now;
                counter.count = 0;
            }
            counter.count = counter.count.saturating_add(check.units);
        }

        Ok(())
    }
}

fn counter_key(scope: &str, subject: &str) -> String {
    format!("{scope}\0{subject}")
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
}
