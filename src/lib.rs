pub mod auth;
pub mod config;
pub mod dedup;
pub mod error;
pub mod metrics;
pub mod models;
pub mod pushkin;
pub mod rate_limit;
pub mod service;

use std::sync::Arc;

use config::NotifyAuthConfig;
use dedup::NotifyDeduplicator;
use pushkin::PushkinRegistry;
use rate_limit::NotifyRateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<PushkinRegistry>,
    pub notify_deduplicator: Option<Arc<NotifyDeduplicator>>,
    pub notify_auth: NotifyAuthConfig,
    pub notify_rate_limiter: Option<Arc<NotifyRateLimiter>>,
}

impl AppState {
    pub fn new(registry: Arc<PushkinRegistry>) -> Self {
        Self {
            registry,
            notify_deduplicator: None,
            notify_auth: NotifyAuthConfig::default(),
            notify_rate_limiter: None,
        }
    }

    pub fn with_notify_deduplicator(
        registry: Arc<PushkinRegistry>,
        notify_deduplicator: Arc<NotifyDeduplicator>,
    ) -> Self {
        Self {
            registry,
            notify_deduplicator: Some(notify_deduplicator),
            notify_auth: NotifyAuthConfig::default(),
            notify_rate_limiter: None,
        }
    }
}
