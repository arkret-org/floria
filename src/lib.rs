pub mod config;
pub mod dedup;
pub mod error;
pub mod metrics;
pub mod models;
pub mod pushkin;
pub mod service;

use std::sync::Arc;

use dedup::NotifyDeduplicator;
use pushkin::PushkinRegistry;

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<PushkinRegistry>,
    pub notify_deduplicator: Option<Arc<NotifyDeduplicator>>,
}

impl AppState {
    pub fn new(registry: Arc<PushkinRegistry>) -> Self {
        Self {
            registry,
            notify_deduplicator: None,
        }
    }

    pub fn with_notify_deduplicator(
        registry: Arc<PushkinRegistry>,
        notify_deduplicator: Arc<NotifyDeduplicator>,
    ) -> Self {
        Self {
            registry,
            notify_deduplicator: Some(notify_deduplicator),
        }
    }
}
