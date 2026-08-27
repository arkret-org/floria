use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use floria::audit::{AuditSink, HttpAuditSink, JsonlAuditSink};
use floria::auth::redact_url_credentials;
use floria::broadcast::InProcessBroadcastBus;
use floria::config::{Config, resolve_path};
use floria::deactivation::{DeactivationLedger, PostgresDeactivationQueueDrain};
use floria::dedup::NotifyDeduplicator;
use floria::nonce_store::{NonceStore, RedisFailurePolicy};
use floria::observability::{self, TelemetryGuard};
use floria::pushkin::PushkinRegistry;
use floria::rate_limit::NotifyRateLimiter;
use floria::retry_queue::{RetryQueue, RetryQueueCipher, RetryQueueConfig};
use floria::service::build_router_with_access_log;
use floria::{AppState, metrics};
use salvo::prelude::*;
use tokio::task::JoinSet;

fn main() -> Result<()> {
    let loaded_config = Config::load_from_args()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(loaded_config))
}

async fn run((config, path): (Config, std::path::PathBuf)) -> Result<()> {
    let _telemetry: TelemetryGuard =
        observability::init_telemetry(&config.observability()).context("initialise telemetry")?;
    tracing::info!(config = %path.display(), "using configuration file");
    config.emit_startup_warnings();
    metrics::init();

    let registry = Arc::new(PushkinRegistry::from_config(&config)?);
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
    state.audit_sink = build_audit_sink(&config, path.parent().unwrap_or_else(|| Path::new(".")))?;
    let deactivation_ledger = build_broadcast_components(&config)?;
    state.deactivation_ledger = Some(deactivation_ledger.clone());
    state.broadcast_bus = Some(Arc::new(InProcessBroadcastBus::new(Some(
        deactivation_ledger,
    ))));
    state.notify_auth = config.http.notify_auth.clone();
    state.internal_auth = config.http.internal_auth.clone();
    if config.http.notify_auth.replay_window_seconds() > 0 {
        let ttl = std::time::Duration::from_secs(config.http.notify_auth.replay_window_seconds());
        let store_config = config.http.notify_auth.nonce_store.clone();
        let nonce_store = match store_config.backend_kind() {
            "redis" => {
                let redis_url = store_config
                    .redis_url
                    .clone()
                    .expect("validated notify_auth.nonce_store.redis_url");
                let policy = RedisFailurePolicy::parse(store_config.failure_policy());
                tracing::info!(
                    ttl_secs = ttl.as_secs(),
                    backend = "redis",
                    redis = %redact_url_credentials(&redis_url),
                    key_prefix = store_config.key_prefix(),
                    failure_policy = store_config.failure_policy(),
                    "enabling /notify HTTP Message Signature replay protection"
                );
                NonceStore::redis_with_policy(
                    ttl,
                    &redis_url,
                    store_config.key_prefix().to_owned(),
                    policy,
                )?
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
                let policy = RedisFailurePolicy::parse(rate_config.failure_policy());
                tracing::info!(
                    window_secs = rate_config.window_seconds.max(1),
                    backend = "redis",
                    redis = %redact_url_credentials(&redis_url),
                    key_prefix = rate_config.key_prefix(),
                    failure_policy = rate_config.failure_policy(),
                    "enabling /notify rate limits"
                );
                let key_prefix = rate_config.key_prefix().to_owned();
                NotifyRateLimiter::redis_with_policy(rate_config, &redis_url, key_prefix, policy)?
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
        std::time::Duration,
    )> = None;
    if config.http.notify_retry_queue.enabled() {
        let queue_config = config.http.notify_retry_queue.clone();
        let retry_config = RetryQueueConfig {
            max_attempts: queue_config.max_attempts,
            default_backoff: std::time::Duration::from_secs(queue_config.default_backoff_seconds),
            max_backoff: std::time::Duration::from_secs(queue_config.max_backoff_seconds),
            dead_letter_capacity: queue_config.dead_letter_capacity as usize,
        };
        let cipher = match queue_config.encryption_key_material()? {
            Some(material) => {
                tracing::info!("enabling AEAD encryption for notify retry queue envelopes");
                Some(RetryQueueCipher::new(&material))
            }
            None => None,
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
                    aead_enabled = cipher.is_some(),
                    deadletter_pg = queue_config.deadletter_pg_url().is_some(),
                    "enabling /notify retry queue"
                );
                RetryQueue::redis_with_cipher(
                    retry_config,
                    &redis_url,
                    queue_config.key_prefix().to_owned(),
                    cipher,
                )?
            }
            _ => {
                tracing::info!(
                    backend = "memory",
                    max_attempts = queue_config.max_attempts,
                    deadletter_pg = queue_config.deadletter_pg_url().is_some(),
                    "enabling /notify retry queue"
                );
                RetryQueue::memory(retry_config)
            }
        };
        let queue = if let Some(pg_url) = queue_config.deadletter_pg_url() {
            let overlay = floria::retry_queue::DeadLetterPgOverlay::new(
                pg_url,
                queue_config.deadletter_pg_table(),
            )?;
            queue.with_deadletter_pg(overlay)?
        } else {
            queue
        };
        let queue = Arc::new(queue);
        state.notify_retry_queue = Some(queue.clone());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let registry_clone = state.registry.clone();
        let poll_interval = std::time::Duration::from_millis(queue_config.poll_interval_ms.max(50));
        let batch_item_count = queue_config.batch_item_count.max(1) as usize;
        let grace = queue_config.grace_period();
        retry_worker_handle = Some((
            shutdown_tx,
            tokio::spawn(async move {
                floria::retry_queue::run_worker(
                    queue,
                    registry_clone,
                    poll_interval,
                    batch_item_count,
                    shutdown_rx,
                )
                .await;
            }),
            grace,
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
            let service = Service::new(router).catcher(salvo::catcher::Catcher::new(
                salvo::catcher::ProblemGoal::new(),
            ));
            Server::new(acceptor).serve(service).await;
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

    if let Some((shutdown, handle, grace)) = retry_worker_handle {
        let _ = shutdown.send(true);
        // Bounded wait so a stuck worker can't block shutdown forever.
        tracing::info!(
            grace_secs = grace.as_secs(),
            "waiting for retry-queue worker to drain"
        );
        match tokio::time::timeout(grace, handle).await {
            Ok(Ok(())) => tracing::info!("retry-queue worker exited cleanly"),
            Ok(Err(error)) => tracing::warn!(error = %error, "retry-queue worker join error"),
            Err(_) => tracing::warn!(
                grace_secs = grace.as_secs(),
                "retry-queue worker did not drain within grace period; abandoning"
            ),
        }
    }

    Ok(())
}

fn build_audit_sink(config: &Config, config_dir: &Path) -> Result<Option<Arc<dyn AuditSink>>> {
    match config.audit.backend_kind() {
        "disabled" => Ok(None),
        "file" => {
            let path = resolve_path(
                config_dir,
                config.audit.file_path().expect("validated audit.file_path"),
            );
            tracing::info!(path = %path.display(), "enabling JSONL audit sink");
            Ok(Some(Arc::new(JsonlAuditSink::new(path))))
        }
        "http" => {
            let endpoint = config
                .audit
                .endpoint()
                .expect("validated audit.endpoint")
                .to_owned();
            tracing::info!(
                endpoint = %endpoint,
                bearer_auth = config.audit.bearer_token().is_some(),
                "enabling HTTP audit sink"
            );
            Ok(Some(Arc::new(HttpAuditSink::new(
                endpoint,
                config.audit.bearer_token().map(ToOwned::to_owned),
            ))))
        }
        backend => bail!("unsupported audit backend `{backend}`"),
    }
}

fn build_broadcast_components(config: &Config) -> Result<Arc<DeactivationLedger>> {
    if let Some(postgres_url) = config.storage.postgres_url() {
        tracing::info!(
            postgres = %redact_url_credentials(postgres_url),
            deactivation_queue_table = config.storage.deactivation_queue_table(),
            "enabling PostgreSQL-backed broadcast state"
        );
        let drain = Arc::new(PostgresDeactivationQueueDrain::new(
            postgres_url.to_owned(),
            config.storage.deactivation_queue_table(),
        )?);
        Ok(Arc::new(DeactivationLedger::with_queue_drain(drain)))
    } else {
        tracing::info!("enabling in-memory broadcast state");
        Ok(Arc::new(DeactivationLedger::new()))
    }
}
