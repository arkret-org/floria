use std::sync::Arc;

use anyhow::{Context, Result, bail};
use floria::AppState;
use floria::auth::redact_url_credentials;
use floria::config::Config;
use floria::dedup::NotifyDeduplicator;
use floria::metrics;
use floria::nonce_store::NonceStore;
use floria::observability::{self, TelemetryGuard};
use floria::pushkin::PushkinRegistry;
use floria::rate_limit::NotifyRateLimiter;
use floria::retry_queue::{RetryQueue, RetryQueueConfig};
use floria::service::build_router_with_access_log;
use salvo::prelude::*;
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<()> {
    let (config, path) = Config::load()?;
    let _telemetry: TelemetryGuard = observability::init_telemetry(&config.observability())
        .context("initialise telemetry")?;
    tracing::info!(config = %path.display(), "using configuration file");
    config.emit_startup_warnings();
    metrics::init();

    let registry = Arc::new(PushkinRegistry::from_config(&config).await?);
    if registry.is_empty() {
        bail!("no app IDs are configured; define at least one entry under apps");
    }

    let mut state = if config.http.notify_dedup_ttl_seconds > 0 {
        let ttl = std::time::Duration::from_secs(config.http.notify_dedup_ttl_seconds);
        let backend_kind = config.http.notify_dedup.backend_kind();
        let deduplicator = match backend_kind {
            "memory" => Arc::new(NotifyDeduplicator::new(ttl)),
            "redis" => {
                let redis_url = config
                    .http
                    .notify_dedup
                    .redis_url
                    .as_deref()
                    .expect("validated notify_dedup.redis_url");
                tracing::info!(
                    ttl_secs = ttl.as_secs(),
                    backend = "redis",
                    redis = %redact_url_credentials(redis_url),
                    key_prefix = config.http.notify_dedup.key_prefix(),
                    "enabling notify request deduplication cache"
                );
                Arc::new(NotifyDeduplicator::redis(
                    ttl,
                    redis_url,
                    config.http.notify_dedup.key_prefix(),
                )?)
            }
            backend => bail!("unsupported notify_dedup backend `{backend}`"),
        };
        if backend_kind == "memory" {
            tracing::info!(
                ttl_secs = ttl.as_secs(),
                backend = "memory",
                "enabling notify request deduplication cache"
            );
        }
        AppState::with_notify_deduplicator(registry, deduplicator)
    } else {
        AppState::new(registry)
    };
    state.notify_auth = config.http.notify_auth.clone();
    if config.http.notify_auth.replay_window_seconds() > 0 {
        let ttl = std::time::Duration::from_secs(config.http.notify_auth.replay_window_seconds());
        let store_config = config.http.notify_auth.nonce_store.clone();
        let nonce_store = match store_config.backend_kind() {
            "redis" => {
                let redis_url = store_config
                    .redis_url
                    .clone()
                    .expect("validated notify_auth.nonce_store.redis_url");
                tracing::info!(
                    ttl_secs = ttl.as_secs(),
                    backend = "redis",
                    redis = %redact_url_credentials(&redis_url),
                    key_prefix = store_config.key_prefix(),
                    "enabling /notify HTTP Message Signature replay protection"
                );
                NonceStore::redis(ttl, &redis_url, store_config.key_prefix().to_owned())?
            }
            _ => {
                tracing::info!(
                    ttl_secs = ttl.as_secs(),
                    backend = "memory",
                    "enabling /notify HTTP Message Signature replay protection"
                );
                NonceStore::memory(ttl)
            }
        };
        state.notify_nonce_store = Some(Arc::new(nonce_store));
    }
    if config.http.notify_rate_limits.enabled() {
        let rate_config = config.http.notify_rate_limits.clone();
        let limiter = match rate_config.backend_kind() {
            "redis" => {
                let redis_url = rate_config
                    .redis_url
                    .clone()
                    .expect("validated notify_rate_limits.redis_url");
                tracing::info!(
                    window_secs = rate_config.window_seconds.max(1),
                    backend = "redis",
                    redis = %redact_url_credentials(&redis_url),
                    key_prefix = rate_config.key_prefix(),
                    "enabling /notify rate limits"
                );
                let key_prefix = rate_config.key_prefix().to_owned();
                NotifyRateLimiter::redis(rate_config, &redis_url, key_prefix)?
            }
            _ => {
                tracing::info!(
                    window_secs = rate_config.window_seconds.max(1),
                    backend = "memory",
                    "enabling /notify rate limits"
                );
                NotifyRateLimiter::new(rate_config)
            }
        };
        state.notify_rate_limiter = Some(Arc::new(limiter));
    }
    let mut retry_worker_handle: Option<(
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    )> = None;
    if config.http.notify_retry_queue.enabled() {
        let queue_config = config.http.notify_retry_queue.clone();
        let retry_config = RetryQueueConfig {
            max_attempts: queue_config.max_attempts,
            default_backoff: std::time::Duration::from_secs(queue_config.default_backoff_seconds),
            max_backoff: std::time::Duration::from_secs(queue_config.max_backoff_seconds),
            dead_letter_capacity: queue_config.dead_letter_capacity as usize,
        };
        let queue = match queue_config.backend_kind() {
            "redis" => {
                let redis_url = queue_config
                    .redis_url
                    .clone()
                    .expect("validated notify_retry_queue.redis_url");
                tracing::info!(
                    backend = "redis",
                    redis = %redact_url_credentials(&redis_url),
                    key_prefix = queue_config.key_prefix(),
                    max_attempts = queue_config.max_attempts,
                    "enabling /notify retry queue"
                );
                Arc::new(RetryQueue::redis(
                    retry_config,
                    &redis_url,
                    queue_config.key_prefix().to_owned(),
                )?)
            }
            _ => {
                tracing::info!(
                    backend = "memory",
                    max_attempts = queue_config.max_attempts,
                    "enabling /notify retry queue"
                );
                Arc::new(RetryQueue::memory(retry_config))
            }
        };
        state.notify_retry_queue = Some(queue.clone());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let registry_clone = state.registry.clone();
        let poll_interval = std::time::Duration::from_millis(queue_config.poll_interval_ms.max(50));
        let batch_size = queue_config.batch_size.max(1) as usize;
        retry_worker_handle = Some((
            shutdown_tx,
            tokio::spawn(async move {
                floria::retry_queue::run_worker(
                    queue,
                    registry_clone,
                    poll_interval,
                    batch_size,
                    shutdown_rx,
                )
                .await;
            }),
        ));
    }
    let state = Arc::new(state);
    let router = Arc::new(build_router_with_access_log(state, &config.log.access));

    let mut servers = JoinSet::new();
    for bind in config.http.listen_addrs()? {
        let router = router.clone();
        servers.spawn(async move {
            let acceptor = TcpListener::new(bind.clone()).bind().await;
            tracing::info!(listen = %bind, "starting server");
            Server::new(acceptor).serve(router).await;
            Result::<()>::Ok(())
        });
    }
    if config.metrics.prometheus.enabled {
        let bind = config.metrics.prometheus.listen_addr()?;
        let router = metrics::build_router();
        servers.spawn(async move {
            let acceptor = TcpListener::new(bind.clone()).bind().await;
            tracing::info!(listen = %bind, "starting prometheus metrics server");
            Server::new(acceptor).serve(router).await;
            Result::<()>::Ok(())
        });
    }

    while let Some(result) = servers.join_next().await {
        result.context("server task join failure")??;
    }

    if let Some((shutdown, handle)) = retry_worker_handle {
        let _ = shutdown.send(true);
        let _ = handle.await;
    }

    Ok(())
}
