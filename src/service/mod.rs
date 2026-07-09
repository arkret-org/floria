use std::sync::Arc;
use std::time::Instant;

use salvo::http::StatusCode;
use salvo::prelude::*;

use crate::AppState;
#[cfg(test)]
use crate::auth::{DESTINATION_SERVICE_DID_HEADER, ORIGIN_SERVICE_DID_HEADER};
use crate::config::AccessLogConfig;

mod bridge_describe;
mod health;
mod integration_describe;
mod internal;
mod metrics;
mod notify;
mod server_describe;

pub const MAX_REQUEST_SIZE: usize = 512 * 1024;
const NOTIFY_OPERATION_ID: &str = "ck.edge.push.command.notify";

fn notify_route(path: &'static str) -> Router {
    Router::with_path(path)
        .post(notify::notify)
        .get(notify::notify_method_not_allowed)
        .put(notify::notify_method_not_allowed)
        .delete(notify::notify_method_not_allowed)
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::with_hoop(affix_state::inject(state))
        .push(notify_route("_arkret/edge/push/notify"))
        .push(
            Router::with_path("_floria/integration/describe")
                .get(integration_describe::integration_describe),
        )
        .push(
            Router::with_path("_floria/push/bridge/describe")
                .get(bridge_describe::bridge_describe),
        )
        .push(Router::with_path("_arkret/describe").get(server_describe::describe))
        // Round R2/R3 (T07/T17) — internal soland broadcast endpoints.
        .push(
            Router::with_path("_floria/internal/account_deactivate_fanout")
                .hoop(internal::require_internal_auth)
                .post(internal::account_deactivate_fanout),
        )
        .push(
            Router::with_path("_floria/internal/consent_revoke")
                .hoop(internal::require_internal_auth)
                .post(internal::consent_revoke),
        )
        // Phase B.4 — status lookup + internal device unregister.
        .push(
            Router::with_path("_floria/admin/push/status/{idempotency_key}")
                .hoop(internal::require_internal_auth)
                .get(internal::push_status),
        )
        .push(
            Router::with_path("_floria/admin/push/device/unregister")
                .hoop(internal::require_internal_auth)
                .post(internal::device_unregister),
        )
        .push(Router::with_path("health").get(health::health))
        .push(Router::with_path("ready").get(health::ready))
        .push(Router::with_path("readyz").get(health::readyz))
}

pub fn build_router_with_access_log(state: Arc<AppState>, access_log: &AccessLogConfig) -> Router {
    let use_forwarded_for = access_log.x_forwarded_for;
    Router::with_hoop(affix_state::inject(state))
        .hoop(AccessLogger { use_forwarded_for })
        .push(notify_route("_arkret/edge/push/notify"))
        .push(
            Router::with_path("_floria/integration/describe")
                .get(integration_describe::integration_describe),
        )
        .push(
            Router::with_path("_floria/push/bridge/describe")
                .get(bridge_describe::bridge_describe),
        )
        .push(Router::with_path("_arkret/describe").get(server_describe::describe))
        // Round R2/R3 (T07/T17) — internal soland broadcast endpoints.
        .push(
            Router::with_path("_floria/internal/account_deactivate_fanout")
                .hoop(internal::require_internal_auth)
                .post(internal::account_deactivate_fanout),
        )
        .push(
            Router::with_path("_floria/internal/consent_revoke")
                .hoop(internal::require_internal_auth)
                .post(internal::consent_revoke),
        )
        // Phase B.4 — status lookup + internal device unregister.
        .push(
            Router::with_path("_floria/admin/push/status/{idempotency_key}")
                .hoop(internal::require_internal_auth)
                .get(internal::push_status),
        )
        .push(
            Router::with_path("_floria/admin/push/device/unregister")
                .hoop(internal::require_internal_auth)
                .post(internal::device_unregister),
        )
        .push(Router::with_path("health").get(health::health))
        .push(Router::with_path("ready").get(health::ready))
        .push(Router::with_path("readyz").get(health::readyz))
}

struct AccessLogger {
    use_forwarded_for: bool,
}

#[handler]
impl AccessLogger {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        let remote_addr = if self.use_forwarded_for {
            req.header::<String>("x-forwarded-for")
                .and_then(|value| {
                    value
                        .split(',')
                        .next()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_else(|| req.remote_addr().to_string())
        } else {
            req.remote_addr().to_string()
        };
        let started = Instant::now();

        ctrl.call_next(req, depot, res).await;

        let status = res.status_code.unwrap_or(StatusCode::OK).as_u16();
        let elapsed = started.elapsed();

        if path == "/health" || path == "/ready" || path == "/readyz" {
            tracing::debug!(
                method = %method,
                path = %path,
                status = status,
                duration_ms = elapsed.as_millis() as u64,
                remote = %remote_addr,
                "request handled"
            );
        } else {
            tracing::info!(
                method = %method,
                path = %path,
                status = status,
                duration_ms = elapsed.as_millis() as u64,
                remote = %remote_addr,
                "request handled"
            );
        }
    }
}

#[cfg(test)]
mod tests;
