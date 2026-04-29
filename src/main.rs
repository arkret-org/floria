use std::sync::Arc;

use anyhow::{Context, Result, bail};
use floria::AppState;
use floria::config::Config;
use floria::dedup::NotifyDeduplicator;
use floria::metrics;
use floria::pushkin::PushkinRegistry;
use floria::service::build_router_with_access_log;
use salvo::prelude::*;
use tokio::task::JoinSet;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let (config, path) = Config::load()?;
    tracing::info!(config = %path.display(), "using configuration file");
    config.emit_startup_warnings();
    metrics::init();

    let registry = Arc::new(PushkinRegistry::from_config(&config).await?);
    if registry.is_empty() {
        bail!("no app IDs are configured; define at least one entry under apps");
    }

    let mut state = if config.http.notify_dedup_ttl_seconds > 0 {
        let ttl = std::time::Duration::from_secs(config.http.notify_dedup_ttl_seconds);
        tracing::info!(
            ttl_secs = ttl.as_secs(),
            "enabling notify request deduplication cache"
        );
        AppState::with_notify_deduplicator(registry, Arc::new(NotifyDeduplicator::new(ttl)))
    } else {
        AppState::new(registry)
    };
    state.notify_auth = config.http.notify_auth.clone();
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

    Ok(())
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .compact()
        .init();
}
