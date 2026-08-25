//! AKP-0007 Circle primitive — per-(provider, realm, circle) circuit
//! breaker. Lightweight in-process breaker that opens a window when
//! consecutive failures cross a threshold and stays open for a
//! configurable cool-down. Designed so a single misbehaving Circle
//! does NOT trip a realm-wide or provider-wide outage.
//!
//! ## Scope
//!
//! Floria's existing rate limiter (`rate_limit::NotifyRateLimiter`)
//! handles *steady-state* shedding. The breaker is a *fault-isolation*
//! mechanism — when a provider's API to a specific Circle keeps
//! returning permanent errors, the breaker opens so subsequent
//! dispatches short-circuit immediately rather than burning quota or
//! hammering the upstream. The Realm-level and Circle-level state are
//! tracked independently so a Circle-scoped outage doesn't bleed up.
//!
//! ## Knobs
//!
//! The breaker is intentionally cheap and self-tuning: per-scope state
//! is just `(consecutive_failures, opened_at)`. There is no probabilistic
//! tripping, no half-open trickle — operators get a binary signal that
//! can be observed on `floria_circuit_breaker_state` and acted on by
//! ops dashboards.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

/// Per-Circle (or per-Realm, when no circle is set) breaker config.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before the breaker opens.
    pub failure_threshold: u32,
    /// How long the breaker stays open before it auto-resets to closed.
    /// There is no manual reset RPC in the current gateway contract, so
    /// the only reset path today is `open_for` elapsing. Operators should
    /// size `open_for` accordingly and watch the
    /// `floria_circuit_breaker_state` metric; do not configure a very
    /// long `open_for` expecting to clear it manually.
    pub open_for: Duration,
    /// Maximum number of distinct breaker-state slots to keep before
    /// LRU-evicting the oldest. Bounds memory under high cardinality
    /// (e.g. a malicious caller cycling through circle ids).
    pub max_breaker_states: usize,
    /// Per-provider override of `open_for`. Falls back to the global
    /// `open_for` when no provider-specific entry is set.
    pub open_for_by_provider: HashMap<String, Duration>,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_for: Duration::from_secs(30),
            max_breaker_states: 4_096,
            open_for_by_provider: HashMap::new(),
        }
    }
}

/// Provider + Realm + (optional) Circle composite key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BreakerKey {
    pub provider: String,
    pub realm_id: Option<String>,
    pub circle_id: Option<String>,
}

impl BreakerKey {
    pub fn new(
        provider: impl Into<String>,
        realm_id: Option<&str>,
        circle_id: Option<&str>,
    ) -> Self {
        Self {
            provider: provider.into(),
            realm_id: realm_id.map(str::to_owned),
            circle_id: circle_id.map(str::to_owned),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct BreakerState {
    consecutive_failures: u32,
    opened_at: Option<Instant>,
}

/// In-process circuit breaker keyed by `(provider, realm, circle)`.
/// Cheap enough to consult on every dispatch.
///
/// Backed by an [`LruCache`] so the breaker-state slot count is bounded
/// at `max_breaker_states` with O(1) access + eviction — a malicious
/// caller cycling through circle ids can no longer force an O(n) scan on
/// every dispatch (the previous hand-rolled `min_by_key` eviction).
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    inner: Mutex<LruCache<BreakerKey, BreakerState>>,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        let cap = NonZeroUsize::new(config.max_breaker_states.max(1))
            .expect("max_breaker_states.max(1) is non-zero");
        Self {
            config,
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    fn open_for(&self, provider: &str) -> Duration {
        self.config
            .open_for_by_provider
            .get(provider)
            .copied()
            .unwrap_or(self.config.open_for)
    }

    /// Returns `true` when the breaker for `key` is currently open and
    /// the caller should short-circuit rather than dispatch.
    pub fn is_open(&self, key: &BreakerKey) -> bool {
        let open_for = self.open_for(&key.provider);
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // `get_mut` bumps the slot to most-recently-used.
        let Some(state) = guard.get_mut(key) else {
            return false;
        };
        let Some(opened_at) = state.opened_at else {
            return false;
        };
        if opened_at.elapsed() >= open_for {
            // Auto-reset on cooldown.
            *state = BreakerState::default();
            false
        } else {
            true
        }
    }

    /// Record a successful dispatch. Resets the failure counter so a
    /// short blip doesn't latch the breaker open on the next failure.
    pub fn record_success(&self, key: &BreakerKey) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = guard.get_or_insert_mut(key.clone(), BreakerState::default);
        entry.consecutive_failures = 0;
    }

    /// Record a failed dispatch. Returns `true` when this failure
    /// caused the breaker to open (so the caller can emit a metric /
    /// log line at that moment).
    pub fn record_failure(&self, key: &BreakerKey) -> bool {
        let threshold = self.config.failure_threshold;
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = guard.get_or_insert_mut(key.clone(), BreakerState::default);
        if entry.opened_at.is_some() {
            return false;
        }
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        let opened = entry.consecutive_failures >= threshold;
        if opened {
            entry.opened_at = Some(Instant::now());
        }
        opened
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;

    use super::*;

    fn cfg() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 3,
            open_for: Duration::from_millis(50),
            max_breaker_states: 4_096,
            open_for_by_provider: HashMap::new(),
        }
    }

    #[test]
    fn lru_evicts_oldest_when_over_capacity() {
        let mut config = cfg();
        config.max_breaker_states = 2;
        let breaker = CircuitBreaker::new(config);
        let k1 = BreakerKey::new("fcm", Some("r"), Some("c1"));
        let k2 = BreakerKey::new("fcm", Some("r"), Some("c2"));
        let k3 = BreakerKey::new("fcm", Some("r"), Some("c3"));
        breaker.record_failure(&k1);
        breaker.record_failure(&k2);
        // k1 is the oldest — bump k2 so k1 stays oldest.
        breaker.record_success(&k2);
        breaker.record_failure(&k3);
        // k1 should have been evicted; k2 and k3 remain.
        let guard = breaker.inner.lock().expect("breaker mutex");
        assert!(!guard.contains(&k1));
        assert!(guard.contains(&k2));
        assert!(guard.contains(&k3));
    }

    #[test]
    fn per_provider_open_for_override() {
        let mut config = cfg();
        config
            .open_for_by_provider
            .insert("fcm".to_owned(), Duration::from_millis(200));
        let breaker = CircuitBreaker::new(config);
        let key = BreakerKey::new("fcm", Some("r"), Some("c"));
        breaker.record_failure(&key);
        breaker.record_failure(&key);
        breaker.record_failure(&key);
        assert!(breaker.is_open(&key));
        // Default cfg.open_for=50ms would have reset by now, but the
        // per-provider override extends it to 200ms.
        sleep(Duration::from_millis(75));
        assert!(breaker.is_open(&key));
    }

    #[test]
    fn closes_under_threshold() {
        let breaker = CircuitBreaker::new(cfg());
        let key = BreakerKey::new("fcm", Some("ak:realm:r"), Some("ak:circle:c"));
        assert!(!breaker.is_open(&key));
        assert!(!breaker.record_failure(&key));
        assert!(!breaker.record_failure(&key));
        assert!(!breaker.is_open(&key));
    }

    #[test]
    fn opens_at_threshold() {
        let breaker = CircuitBreaker::new(cfg());
        let key = BreakerKey::new("fcm", Some("ak:realm:r"), Some("ak:circle:c"));
        breaker.record_failure(&key);
        breaker.record_failure(&key);
        assert!(breaker.record_failure(&key));
        assert!(breaker.is_open(&key));
    }

    #[test]
    fn success_resets_consecutive_counter() {
        let breaker = CircuitBreaker::new(cfg());
        let key = BreakerKey::new("fcm", None, None);
        breaker.record_failure(&key);
        breaker.record_failure(&key);
        breaker.record_success(&key);
        // Two more failures should NOT open since the counter reset.
        assert!(!breaker.record_failure(&key));
        assert!(!breaker.record_failure(&key));
        assert!(!breaker.is_open(&key));
    }

    #[test]
    fn auto_resets_after_open_for_window() {
        let breaker = CircuitBreaker::new(cfg());
        let key = BreakerKey::new("fcm", Some("ak:realm:r"), Some("ak:circle:c"));
        breaker.record_failure(&key);
        breaker.record_failure(&key);
        breaker.record_failure(&key);
        assert!(breaker.is_open(&key));
        sleep(Duration::from_millis(75));
        assert!(!breaker.is_open(&key));
    }

    #[test]
    fn realm_and_circle_keys_are_independent() {
        let breaker = CircuitBreaker::new(cfg());
        let realm_key = BreakerKey::new("fcm", Some("ak:realm:r"), None);
        let circle_key = BreakerKey::new("fcm", Some("ak:realm:r"), Some("ak:circle:c"));
        breaker.record_failure(&realm_key);
        breaker.record_failure(&realm_key);
        breaker.record_failure(&realm_key);
        assert!(breaker.is_open(&realm_key));
        // A Circle-scoped breaker tripping must NOT bleed up into the
        // Realm-scoped breaker, and vice versa.
        assert!(!breaker.is_open(&circle_key));
    }
}
