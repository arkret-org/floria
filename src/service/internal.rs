//! Internal account-lifecycle broadcast endpoints.
//!
//! These routes are intended for the soland-broadcast channel (or an
//! equivalent in-process message bus). They are exposed under
//! `/_floria/internal/...` and intentionally do NOT share the public
//! `/_arkret/edge/push/notify` request shape. They are protected by the
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

#[handler]
pub(super) async fn require_internal_auth(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let started = Instant::now();
    let state = match depot.get_typed::<Arc<AppState>>() {
        Ok(state) => state.clone(),
        Err(_) => {
            finish_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                arkret_wire::error_codes::ErrorCode::INTERNAL_ERROR,
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
            arkret_wire::error_codes::ErrorCode::SERVICE_UNAVAILABLE,
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
                arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
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
                arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
                "invalid internal bearer token",
                None,
                None,
                started,
            );
        }
    }
}

/// `GET /_floria/admin/push/status/{idempotency_key}` — returns a lightweight
/// snapshot of an outstanding or recently completed notify request.
/// Backed by the dedup cache; returns 404 when nothing is known.
#[handler]
pub(super) async fn push_status(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let started = Instant::now();
    let state = match depot.get_typed::<Arc<AppState>>() {
        Ok(state) => state.clone(),
        Err(_) => {
            finish_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                arkret_wire::error_codes::ErrorCode::INTERNAL_ERROR,
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
            arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
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
            arkret_wire::error_codes::ErrorCode::SERVICE_UNAVAILABLE,
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
            arkret_wire::error_codes::ErrorCode::NOT_FOUND,
            "no status known for the supplied idempotency_key",
            None,
            None,
            started,
        ),
    }
}

#[handler]
pub(super) async fn account_deactivate_fanout(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) {
    let started = Instant::now();
    let state = match depot.get_typed::<Arc<AppState>>() {
        Ok(state) => state.clone(),
        Err(_) => {
            finish_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                arkret_wire::error_codes::ErrorCode::INTERNAL_ERROR,
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
                arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
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
            arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
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
            arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
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
            arkret_wire::error_codes::ErrorCode::SERVICE_UNAVAILABLE,
            "in-process broadcast bus is not configured on this push gateway",
            None,
            None,
            started,
        );
        return;
    };

    let ack = match bus.account_deactivate_fanout_async(&body).await {
        Ok(ack) => ack,
        Err(error) => {
            finish_error(
                res,
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::error_codes::ErrorCode::SERVICE_UNAVAILABLE,
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
