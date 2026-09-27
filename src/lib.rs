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
pub mod pushkin;
pub mod rate_limit;
pub(crate) mod redis_support;
pub mod registration_handoff;
pub mod registrations;
pub mod retry_queue;
pub mod sanitize;
pub mod service;

use std::sync::{Arc, OnceLock};

static RUSTLS_CRYPTO_PROVIDER: OnceLock<()> = OnceLock::new();

/// Install the process-wide rustls crypto provider, once.
///
/// `reqwest` is built with `rustls-no-provider` and `rustls` with `ring`, so
/// **every** TLS consumer must call this before constructing a client or
/// rustls panics ("No rustls crypto provider is configured"). Call it from each
/// entry point rather than relying on another one having run first: installing
/// it only alongside the PostgreSQL connector meant a deployment with no
/// Postgres overlay panicked as soon as a pushkin built its HTTP client.
pub(crate) fn ensure_rustls_crypto_provider() {
    RUSTLS_CRYPTO_PROVIDER.get_or_init(|| {
        // Errs only if a provider is already installed, which is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

use audit::AuditSink;
use broadcast::InProcessBroadcastBus;
use circuit_breaker::CircuitBreaker;
use config::{InternalAuthConfig, NotifyAuthConfig};
use deactivation::DeactivationLedger;
use dedup::NotifyDeduplicator;
use nonce_store::NonceStore;
use pushkin::PushkinRegistry;
use rate_limit::NotifyRateLimiter;
use retry_queue::RetryQueue;

// Account-deactivation broadcast state is independent from Contact,
// Direct Conversation, participation, Sidecar and operation-control admission.
// Those gates are evaluated by the upstream Sync / notification service before
// it constructs the closed push-notify envelope.
//
// `deactivation_ledger` accepts `account_deactivate_fanout` events from soland,
// performs per-actor + per-device unbinds, and tracks whether the fanout completed
// fully or partially.
//
// It is optional so deployments that do not subscribe to the soland
// broadcast bus can leave it unset; the endpoint then answers
// `503 service_unavailable` so misconfigurations surface in operator dashboards
// rather than silently swallowing broadcasts.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<PushkinRegistry>,
    pub public_base_url: String,
    pub audit_sink: Option<Arc<dyn AuditSink>>,
    pub notify_deduplicator: Option<Arc<NotifyDeduplicator>>,
    pub notify_auth: NotifyAuthConfig,
    pub gateway_service_resolution:
        Option<Arc<arkret_models_identity::AuthenticatedServiceResolution>>,
    pub registrations: Arc<registrations::RegistrationDirectory>,
    pub registration_handoff: Option<Arc<registration_handoff::RegistrationHandoffStore>>,
    pub provider_timing_bucket: std::time::Duration,
    pub internal_auth: InternalAuthConfig,
    pub notify_rate_limiter: Option<Arc<NotifyRateLimiter>>,
    pub notify_nonce_store: Option<Arc<NonceStore>>,
    pub notify_retry_queue: Option<Arc<RetryQueue>>,
    pub circuit_breaker: Option<Arc<CircuitBreaker>>,
    pub deactivation_ledger: Option<Arc<DeactivationLedger>>,
    pub broadcast_bus: Option<Arc<InProcessBroadcastBus>>,
    /// AKP-0007 — when `true`, per-(provider, scope) metrics use the
    /// `circle_id` (cardinality up to the number of active Circles).
    /// Default `false` — labels key off the parent `realm_id`.
    pub metrics_detailed_circle_labels: bool,
}

impl AppState {
    pub async fn resolve_registration(
        &self,
        source: &arkret_wire::DidCoreId,
        target: &arkret_wire::PushTargetId,
        device: &arkret_wire::DeviceId,
    ) -> anyhow::Result<Option<arkret_models_integration::PushRegistrationRecord>> {
        resolve_registration(
            self.registrations.as_ref(),
            self.registration_handoff.as_deref(),
            &self.public_base_url,
            source,
            target,
            device,
        )
        .await
    }

    pub fn new(registry: Arc<PushkinRegistry>) -> Self {
        Self {
            registry,
            public_base_url: "http://127.0.0.1:5000/".to_owned(),
            audit_sink: None,
            notify_deduplicator: None,
            notify_auth: NotifyAuthConfig::default(),
            gateway_service_resolution: None,
            registrations: Arc::new(registrations::RegistrationDirectory::default()),
            registration_handoff: None,
            provider_timing_bucket: std::time::Duration::ZERO,
            internal_auth: InternalAuthConfig::default(),
            notify_rate_limiter: None,
            notify_nonce_store: None,
            notify_retry_queue: None,
            circuit_breaker: Some(Arc::new(CircuitBreaker::default())),
            deactivation_ledger: None,
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
            public_base_url: "http://127.0.0.1:5000/".to_owned(),
            audit_sink: None,
            notify_deduplicator: Some(notify_deduplicator),
            notify_auth: NotifyAuthConfig::default(),
            gateway_service_resolution: None,
            registrations: Arc::new(registrations::RegistrationDirectory::default()),
            registration_handoff: None,
            provider_timing_bucket: std::time::Duration::ZERO,
            internal_auth: InternalAuthConfig::default(),
            notify_rate_limiter: None,
            notify_nonce_store: None,
            notify_retry_queue: None,
            circuit_breaker: Some(Arc::new(CircuitBreaker::default())),
            deactivation_ledger: None,
            broadcast_bus: None,
            metrics_detailed_circle_labels: false,
        }
    }
}

/// Resolve a provider route through the same tenant-bound sources used by
/// both the synchronous notify path and the asynchronous retry worker.
///
/// Keeping this merge in one place prevents a retry from silently falling
/// back to the shared-deployment directory after the original dispatch used
/// a public-Gateway handoff route.
pub async fn resolve_registration(
    registrations: &registrations::RegistrationDirectory,
    registration_handoff: Option<&registration_handoff::RegistrationHandoffStore>,
    public_base_url: &str,
    source: &arkret_wire::DidCoreId,
    target: &arkret_wire::PushTargetId,
    device: &arkret_wire::DeviceId,
) -> anyhow::Result<Option<arkret_models_integration::PushRegistrationRecord>> {
    let handed_off = match registration_handoff {
        Some(store) => {
            store
                .resolve(source, target, device, public_base_url)
                .await?
        }
        None => None,
    };
    let shared = registrations
        .resolve(source, target, device, public_base_url)
        .await?;
    match (handed_off, shared) {
        (Some(_), Some(_)) => {
            anyhow::bail!("registration exists in both public handoff and shared authority stores")
        }
        (Some(registration), None) | (None, Some(registration)) => Ok(Some(registration)),
        (None, None) => Ok(None),
    }
}
