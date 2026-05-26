//! CXP-0007 Circle primitive — per-(provider, realm, circle) circuit
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
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Per-Circle (or per-Realm, when no circle is set) breaker config.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before the breaker opens.
    pub failure_threshold: u32,
    /// How long the breaker stays open before it auto-resets to closed.
    /// Operators that want a manual reset should set this to something
    /// long and rely on the `floria_circuit_breaker_state` metric +
    /// the reset RPC (TODO(circle-rollout-P2C.5)).
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
    /// LRU tick — incremented on every access. The oldest tick is
    /// the next candidate for eviction.
    last_used_tick: u64,
}

/// In-process circuit breaker keyed by `(provider, realm, circle)`.
/// Cheap enough to consult on every dispatch.
#[derive(Debug, Default)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    inner: Mutex<CircuitBreakerInner>,
}

#[derive(Debug, Default)]
struct CircuitBreakerInner {
    state: HashMap<BreakerKey, BreakerState>,
    tick: u64,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(CircuitBreakerInner::default()),
        }
    }

    fn open_for(&self, provider: &str) -> Duration {
        self.config
            .open_for_by_provider
            .get(provider)
            .copied()
            .unwrap_or(self.config.open_for)
    }

    fn evict_if_needed(&self, inner: &mut CircuitBreakerInner) {
        let cap = self.config.max_breaker_states.max(1);
        while inner.state.len() > cap {
            let Some(oldest_key) = inner
                .state
                .iter()
                .min_by_key(|(_, state)| state.last_used_tick)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            inner.state.remove(&oldest_key);
        }
    }

    /// Returns `true` when the breaker for `key` is currently open and
    /// the caller should short-circuit rather than dispatch.
    pub fn is_open(&self, key: &BreakerKey) -> bool {
        let open_for = self.open_for(&key.provider);
        let mut guard = self.inner.lock().expect("circuit breaker mutex poisoned");
        let Some(state) = guard.state.get_mut(key) else {
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
        let mut guard = self.inner.lock().expect("circuit breaker mutex poisoned");
        guard.tick = guard.tick.saturating_add(1);
        let tick = guard.tick;
        let entry = guard.state.entry(key.clone()).or_default();
        entry.consecutive_failures = 0;
        entry.last_used_tick = tick;
        self.evict_if_needed(&mut guard);
    }

    /// Record a failed dispatch. Returns `true` when this failure
    /// caused the breaker to open (so the caller can emit a metric /
    /// log line at that moment).
    pub fn record_failure(&self, key: &BreakerKey) -> bool {
        let mut guard = self.inner.lock().expect("circuit breaker mutex poisoned");
        guard.tick = guard.tick.saturating_add(1);
        let tick = guard.tick;
        let state = guard.state.entry(key.clone()).or_default();
        state.last_used_tick = tick;
        if state.opened_at.is_some() {
            self.evict_if_needed(&mut guard);
            return false;
        }
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let opened = state.consecutive_failures >= self.config.failure_threshold;
        if opened {
            state.opened_at = Some(Instant::now());
        }
        self.evict_if_needed(&mut guard);
        opened
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

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
        assert!(!guard.state.contains_key(&k1));
        assert!(guard.state.contains_key(&k2));
        assert!(guard.state.contains_key(&k3));
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
        let key = BreakerKey::new("fcm", Some("cx:realm:r"), Some("cx:circle:c"));
        assert!(!breaker.is_open(&key));
        assert!(!breaker.record_failure(&key));
        assert!(!breaker.record_failure(&key));
        assert!(!breaker.is_open(&key));
    }

    #[test]
    fn opens_at_threshold() {
        let breaker = CircuitBreaker::new(cfg());
        let key = BreakerKey::new("fcm", Some("cx:realm:r"), Some("cx:circle:c"));
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
        let key = BreakerKey::new("fcm", Some("cx:realm:r"), Some("cx:circle:c"));
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
        let realm_key = BreakerKey::new("fcm", Some("cx:realm:r"), None);
        let circle_key = BreakerKey::new("fcm", Some("cx:realm:r"), Some("cx:circle:c"));
        breaker.record_failure(&realm_key);
        breaker.record_failure(&realm_key);
        breaker.record_failure(&realm_key);
        assert!(breaker.is_open(&realm_key));
        // A Circle-scoped breaker tripping must NOT bleed up into the
        // Realm-scoped breaker, and vice versa.
        assert!(!breaker.is_open(&circle_key));
    }
}
