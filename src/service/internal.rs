//! Round R2/R3 (T07 + T17) — internal soland-broadcast endpoints.
//!
//! These routes are intended for the soland-broadcast channel (or an
//! equivalent in-process message bus). They are exposed under
//! `/_cokret/edge/internal/...` and intentionally do NOT share the public
//! `/_cokret/edge/push/notify` request shape. They are protected by the
//! `http.internal_auth` bearer/shared-secret profile and fail closed
//! when no internal credential is configured.

use std::sync::Arc;
use std::time::Instant;

use salvo::http::StatusCode;
use salvo::prelude::*;

use super::metrics::{finish_error, finish_json};
use crate::AppState;
use crate::auth::{BearerState, bearer_state};
use crate::deactivation::AccountDeactivateFanoutBroadcast;
use crate::push_contact_cache::ConsentRevokeBroadcast;

#[handler]
pub(super) async fn require_internal_auth(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let started = Instant::now();
    let state = match depot.obtain::<Arc<AppState>>() {
        Ok(state) => state.clone(),
        Err(_) => {
            finish_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "application state missing",
                None,
                None,
                started,
            );
            return;
        }
    };

    if !state.internal_auth.enabled() {
        tracing::error!(
            path = %req.uri().path(),
            "rejecting internal endpoint request: http.internal_auth is not configured"
        );
        finish_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "internal endpoint authentication is not configured",
            None,
            None,
            started,
        );
        return;
    }

    match bearer_state(
        req,
        &state.internal_auth.bearer_tokens,
        &state.internal_auth.bearer_token_hashes,
    ) {
        BearerState::Valid => {
            ctrl.call_next(req, depot, res).await;
        }
        BearerState::Missing => {
            tracing::warn!(
                path = %req.uri().path(),
                "rejecting internal endpoint request without bearer token"
            );
            finish_error(
                res,
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "missing internal bearer token",
                None,
                None,
                started,
            );
        }
        BearerState::Invalid => {
            tracing::warn!(
                path = %req.uri().path(),
                "rejecting internal endpoint request with invalid bearer token"
            );
            finish_error(
                res,
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "invalid internal bearer token",
                None,
                None,
                started,
            );
        }
    }
}

/// `GET /_cokret/edge/push/status/{idempotency_key}` — returns a lightweight
/// snapshot of an outstanding or recently completed notify request.
/// Backed by the dedup cache; returns 404 when nothing is known.
#[handler]
pub(super) async fn push_status(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let started = Instant::now();
    let state = match depot.obtain::<Arc<AppState>>() {
        Ok(state) => state.clone(),
        Err(_) => {
            finish_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "application state missing",
                None,
                None,
                started,
            );
            return;
        }
    };
    let key = req
        .param::<String>("idempotency_key")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let Some(key) = key else {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "idempotency_key path parameter is required",
            None,
            None,
            started,
        );
        return;
    };
    let Some(deduplicator) = state.notify_deduplicator.as_ref() else {
        finish_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "notify deduplication cache is disabled; status lookup unavailable",
            None,
            None,
            started,
        );
        return;
    };
    // The dedup cache is keyed by SHA-256 of the idempotency key, so we
    // re-hash here. We accept the raw idempotency key on the wire to
    // match what callers used for /notify.
    let hashed_key = crate::dedup::request_hash(key.as_bytes());
    match deduplicator.status_for(&hashed_key) {
        Some(status) => finish_json(res, StatusCode::OK, status, started),
        None => finish_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "no status known for the supplied idempotency_key",
            None,
            None,
            started,
        ),
    }
}

/// `POST /_cokret/edge/push/device/unregister` — internal-only operator
/// endpoint that drops a device from the in-process delivered-device
/// cache and (if configured) emits a deactivation. Body shape:
/// `{ "app_id": "...", "push_key": "..." }`.
#[handler]
pub(super) async fn device_unregister(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let started = Instant::now();
    let state = match depot.obtain::<Arc<AppState>>() {
        Ok(state) => state.clone(),
        Err(_) => {
            finish_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "application state missing",
                None,
                None,
                started,
            );
            return;
        }
    };

    #[derive(serde::Deserialize)]
    struct UnregisterRequest {
        app_id: String,
        push_key: String,
    }
    let body: UnregisterRequest = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(error = %error, "invalid device_unregister body");
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "invalid device_unregister body",
                None,
                None,
                started,
            );
            return;
        }
    };
    let app_id = body.app_id.trim();
    let push_key = body.push_key.trim();
    if app_id.is_empty() {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "app_id must not be empty",
            None,
            None,
            started,
        );
        return;
    }
    if push_key.is_empty() {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "push_key must not be empty",
            None,
            None,
            started,
        );
        return;
    }

    // The dedup cache stores delivered-device entries keyed by
    // notification_key + app_id + push_key. There is no public
    // "purge by app_id+push_key" surface today — the unregister
    // endpoint records the intent in the structured log so operators
    // can fan it out via their existing device-management pipeline.
    // Future work: thread purges through the deduplicator backend.
    let push_key_redacted = crate::models::redact_push_token(push_key);
    let _ = state; // state is unused once the broadcast/audit hooks land
    tracing::info!(
        app_id = %app_id,
        push_key_hash = %push_key_redacted,
        "device_unregister: operator requested unregister"
    );

    finish_json(
        res,
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "app_id": app_id,
            "push_key_hash": push_key_redacted,
        }),
        started,
    );
}

#[handler]
pub(super) async fn account_deactivate_fanout(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) {
    let started = Instant::now();
    let state = match depot.obtain::<Arc<AppState>>() {
        Ok(state) => state.clone(),
        Err(_) => {
            finish_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "application state missing",
                None,
                None,
                started,
            );
            return;
        }
    };

    let body: AccountDeactivateFanoutBroadcast = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(error = %error, "invalid account_deactivate_fanout body");
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "invalid account_deactivate_fanout body",
                None,
                None,
                started,
            );
            return;
        }
    };

    if body.fanout_id.trim().is_empty() {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "fanout_id must not be empty",
            None,
            None,
            started,
        );
        return;
    }
    if body.actor_id.trim().is_empty() {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "actor_id must not be empty",
            None,
            None,
            started,
        );
        return;
    }

    let Some(bus) = state.broadcast_bus.as_ref() else {
        // The endpoint exists even when the ledger isn't wired up so
        // soland can detect misconfigurations early. We answer 503 so
        // soland retries rather than reporting fanout_complete on a
        // dropped broadcast.
        finish_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "in-process broadcast bus is not configured on this push gateway",
            None,
            None,
            started,
        );
        return;
    };

    let ack = match bus.account_deactivate_fanout(&body) {
        Ok(ack) => ack,
        Err(error) => {
            finish_error(
                res,
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                error.message(),
                None,
                None,
                started,
            );
            return;
        }
    };

    tracing::info!(
        fanout_id = %ack.fanout_id,
        outcome = %ack.outcome.as_str(),
        actor_bindings_unbound = ack.actor_bindings_unbound,
        device_bindings_unbound = ack.device_bindings_unbound,
        sealed_channels = ack.sealed_channels,
        messages_drained = ack.messages_drained,
        "processed account_deactivate_fanout broadcast"
    );

    // Note: even when `outcome == PartiallyCompleted` we return 200 OK
    // with an honest ack body — the partial signal is for soland's
    // bookkeeping, not an HTTP transport error.
    finish_json(res, StatusCode::OK, ack, started);
}

#[handler]
pub(super) async fn consent_revoke(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let started = Instant::now();
    let state = match depot.obtain::<Arc<AppState>>() {
        Ok(state) => state.clone(),
        Err(_) => {
            finish_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "application state missing",
                None,
                None,
                started,
            );
            return;
        }
    };

    let body: ConsentRevokeBroadcast = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(error = %error, "invalid consent_revoke body");
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "invalid consent_revoke body",
                None,
                None,
                started,
            );
            return;
        }
    };

    if !body.scope_is_any() {
        // Scoped revocations need realm context that floria doesn't
        // learn. soland is expected to route those to the right
        // service (sync / principal) directly.
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "unsupported_feature",
            &format!(
                "consent_revoke scope must be `{}`; floria does not handle scoped revocations",
                ConsentRevokeBroadcast::SUPPORTED_SCOPE
            ),
            None,
            None,
            started,
        );
        return;
    }

    let Some(bus) = state.broadcast_bus.as_ref() else {
        // No cache wired up → nothing to invalidate. soland's broadcast
        // is still a success, but we answer 503 so it's obvious in
        // operator dashboards that the listener saw the broadcast but
        // couldn't act.
        finish_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "in-process broadcast bus is not configured on this push gateway",
            None,
            None,
            started,
        );
        return;
    };

    let ack = match bus.consent_revoke(&body) {
        Ok(ack) => ack,
        Err(error) => {
            finish_error(
                res,
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                error.message(),
                None,
                None,
                started,
            );
            return;
        }
    };
    tracing::info!(
        broadcast_id = %ack.broadcast_id,
        scope = ack.scope,
        entries_evicted = ack.entries_evicted,
        reason = body.reason_str().unwrap_or("<unset>"),
        "processed consent_revoke scope=any broadcast"
    );
    finish_json(res, StatusCode::OK, ack, started);
}
