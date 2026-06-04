pub mod audit;
pub mod auth;
pub mod broadcast;
pub mod circuit_breaker;
pub mod config;
pub mod deactivation;
pub mod dedup;
pub mod egress;
pub mod error;
pub mod metrics;
pub mod models;
pub mod nonce_store;
pub mod observability;
pub mod postgres_support;
pub mod push_contact_cache;
pub mod pushkin;
pub mod rate_limit;
pub mod retry_queue;
pub mod service;

use std::sync::Arc;

use audit::AuditSink;
use broadcast::InProcessBroadcastBus;
use config::{InternalAuthConfig, NotifyAuthConfig};
use deactivation::DeactivationLedger;
use dedup::NotifyDeduplicator;
use nonce_store::NonceStore;
use push_contact_cache::PushContactCache;
use pushkin::PushkinRegistry;
use rate_limit::NotifyRateLimiter;
use retry_queue::RetryQueue;

// Round R2/R3 (T07/T17) — broadcast-channel surfaces:
//
//   * `deactivation_ledger` accepts `account_deactivate_fanout` events from soland, performs
//     per-actor + per-device unbinds, and tracks whether the fanout completed fully or partially.
//     Sealed channels still count as drained so soland's fanout state isn't blocked on a dead push
//     provider.
//   * `push_contact_cache` accepts `consent_revoke{scope=any}` events and drops every cached PSI
//     verdict for the affected principal so the next push goes through a fresh consent check.
//
// Both are `Option<Arc<…>>` so deployments that do not subscribe to
// the soland broadcast bus / audit endpoint can leave them unset; the
// matching required routes then answer `503 service_unavailable` so
// misconfigurations surface in operator dashboards rather than silently
// swallowing broadcasts or audit events.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<PushkinRegistry>,
    pub audit_sink: Option<Arc<dyn AuditSink>>,
    pub notify_deduplicator: Option<Arc<NotifyDeduplicator>>,
    pub notify_auth: NotifyAuthConfig,
    pub internal_auth: InternalAuthConfig,
    pub notify_rate_limiter: Option<Arc<NotifyRateLimiter>>,
    pub notify_nonce_store: Option<Arc<NonceStore>>,
    pub notify_retry_queue: Option<Arc<RetryQueue>>,
    pub deactivation_ledger: Option<Arc<DeactivationLedger>>,
    pub push_contact_cache: Option<Arc<PushContactCache>>,
    pub broadcast_bus: Option<Arc<InProcessBroadcastBus>>,
    /// CKP-0007 — when `true`, per-(provider, scope) metrics use the
    /// `circle_id` (cardinality up to the number of active Circles).
    /// Default `false` — labels key off the parent `realm_id`.
    pub metrics_detailed_circle_labels: bool,
}

impl AppState {
    pub fn new(registry: Arc<PushkinRegistry>) -> Self {
        Self {
            registry,
            audit_sink: None,
            notify_deduplicator: None,
            notify_auth: NotifyAuthConfig::default(),
            internal_auth: InternalAuthConfig::default(),
            notify_rate_limiter: None,
            notify_nonce_store: None,
            notify_retry_queue: None,
            deactivation_ledger: None,
            push_contact_cache: None,
            broadcast_bus: None,
            metrics_detailed_circle_labels: false,
        }
    }

    pub fn with_notify_deduplicator(
        registry: Arc<PushkinRegistry>,
        notify_deduplicator: Arc<NotifyDeduplicator>,
    ) -> Self {
        Self {
            registry,
            audit_sink: None,
            notify_deduplicator: Some(notify_deduplicator),
            notify_auth: NotifyAuthConfig::default(),
            internal_auth: InternalAuthConfig::default(),
            notify_rate_limiter: None,
            notify_nonce_store: None,
            notify_retry_queue: None,
            deactivation_ledger: None,
            push_contact_cache: None,
            broadcast_bus: None,
            metrics_detailed_circle_labels: false,
        }
    }
}
