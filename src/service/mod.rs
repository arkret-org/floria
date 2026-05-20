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
const NOTIFY_OPERATION_ID: &str = "cx.push.notify";
const ACTIVE_EVENT_ID_PREFIX: &str = "cx:event:";
const ACTIVE_MESSAGE_ID_PREFIX: &str = "cx:message:";
const ACTIVE_FLOW_ID_PREFIX: &str = "cx:flow:";
// Realm/Space reversal: the security boundary is now Realm with typed
// prefix `cx:realm:`. The push wire model carries `realm_id`, never the
// container-level `space_id` (which is on the forbidden-key list).
const ACTIVE_REALM_ID_PREFIX: &str = "cx:realm:";

// Round R2/R3 (2026-05-20, spec 8b7978d) — ephemeral kinds bypass
// floria entirely. The four broadcast ephemeral signal kinds
// (`cx.presence`, `cx.typing`, `cx.receipt.read`, `cx.call.signal`)
// travel on dedicated `ephemeral_envelope` / device-message channels
// in the Sync Service, are dropped at TTL, and MUST NOT enter floria's
// durable Event-kind path. There is intentionally no code here that
// branches on those kind strings — `wakeup_kind` on a `cx.push.notify`
// is a closed enum (`message` / `incoming_call` / `mention` / …) plus
// a snake_case custom token form, and the validator in `notify.rs`
// rejects anything containing `did:` / `cx:` substrings, so an
// ephemeral kind cannot smuggle in via the wakeup_kind slot. If a
// future caller ever pipes an ephemeral as a durable Event, the
// `validate_active_notification_refs` ID-prefix gate (`cx:event:` /
// `cx:message:` / `cx:flow:` / `cx:realm:`) is the second line of
// defence — there is no `cx:presence:` or `cx:typing:` typed-id, so
// the prefix check rejects it.

fn notify_route(path: &'static str) -> Router {
    Router::with_path(path)
        .post(notify::notify)
        .get(notify::notify_method_not_allowed)
        .put(notify::notify_method_not_allowed)
        .delete(notify::notify_method_not_allowed)
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::with_hoop(affix_state::inject(state))
        .push(notify_route("api/v1/push/notify"))
        .push(
            Router::with_path("api/v1/integration/describe")
                .get(integration_describe::integration_describe),
        )
        .push(
            Router::with_path("api/v1/push/bridge/describe").get(bridge_describe::bridge_describe),
        )
        .push(Router::with_path("api/v1/push/describe").get(server_describe::describe))
        .push(Router::with_path("api/v1/server/describe").get(server_describe::describe))
        // Round R2/R3 (T07/T17) — internal soland broadcast endpoints.
        .push(
            Router::with_path("api/v1/internal/account_deactivate_fanout")
                .post(internal::account_deactivate_fanout),
        )
        .push(
            Router::with_path("api/v1/internal/consent_revoke").post(internal::consent_revoke),
        )
        .push(Router::with_path("health").get(health::health))
        .push(Router::with_path("ready").get(health::ready))
}

pub fn build_router_with_access_log(state: Arc<AppState>, access_log: &AccessLogConfig) -> Router {
    let use_forwarded_for = access_log.x_forwarded_for;
    Router::with_hoop(affix_state::inject(state))
        .hoop(AccessLogger { use_forwarded_for })
        .push(notify_route("api/v1/push/notify"))
        .push(
            Router::with_path("api/v1/integration/describe")
                .get(integration_describe::integration_describe),
        )
        .push(
            Router::with_path("api/v1/push/bridge/describe").get(bridge_describe::bridge_describe),
        )
        .push(Router::with_path("api/v1/push/describe").get(server_describe::describe))
        .push(Router::with_path("api/v1/server/describe").get(server_describe::describe))
        // Round R2/R3 (T07/T17) — internal soland broadcast endpoints.
        .push(
            Router::with_path("api/v1/internal/account_deactivate_fanout")
                .post(internal::account_deactivate_fanout),
        )
        .push(
            Router::with_path("api/v1/internal/consent_revoke").post(internal::consent_revoke),
        )
        .push(Router::with_path("health").get(health::health))
        .push(Router::with_path("ready").get(health::ready))
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

        if path == "/health" || path == "/ready" {
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
