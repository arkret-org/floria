//! Authenticated operator status and dead-letter inspection.

use std::sync::Arc;
use std::time::Instant;

use salvo::http::StatusCode;
use salvo::prelude::*;

use super::metrics::{finish_error, finish_json};
use crate::AppState;
use crate::auth::{BearerState, bearer_state};

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
    let hashed_key = crate::service::notify::idempotency_cache_key(&key);
    match deduplicator.status_for_async(&hashed_key).await {
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

/// Default page size for the dead-letter snapshot route.
const DEAD_LETTER_SNAPSHOT_DEFAULT_LIMIT: usize = 100;
/// Hard cap so an operator typo cannot ask a Redis backend to
/// deserialize an unbounded LRANGE in one request.
const DEAD_LETTER_SNAPSHOT_MAX_LIMIT: usize = 1000;

/// `GET /_floria/admin/push/dead-letters?limit=N` — operator snapshot of
/// the push retry dead-letter ring (newest first), for inspecting
/// exhausted-retry envelopes and extracting them for manual replay.
/// Backed by [`crate::retry_queue::RetryQueue::dead_letter_snapshot`];
/// returns 503 when the notify retry queue is disabled.
///
/// Every envelope is serialized to JSON and passed through
/// [`crate::sanitize::strip_egress_only_keys`] before it is rendered, so
/// gateway-internal routing/audit fields (`route_tokens`,
/// `realm_route_token`, `scope_route_token`, …)
/// can never leak through this operator surface even if the envelope
/// shape grows such fields later.
#[handler]
pub(super) async fn push_dead_letters(req: &mut Request, depot: &mut Depot, res: &mut Response) {
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
    let limit = match req.query::<String>("limit") {
        None => DEAD_LETTER_SNAPSHOT_DEFAULT_LIMIT,
        Some(raw) => match raw.trim().parse::<usize>() {
            Ok(value) if (1..=DEAD_LETTER_SNAPSHOT_MAX_LIMIT).contains(&value) => value,
            _ => {
                finish_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
                    "limit query parameter must be an integer between 1 and 1000",
                    None,
                    None,
                    started,
                );
                return;
            }
        },
    };
    let Some(queue) = state.notify_retry_queue.as_ref() else {
        finish_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::error_codes::ErrorCode::SERVICE_UNAVAILABLE,
            "notify retry queue is disabled; dead-letter snapshot unavailable",
            None,
            None,
            started,
        );
        return;
    };
    let envelopes = queue.dead_letter_snapshot_async(limit).await;
    let mut dead_letters = Vec::with_capacity(envelopes.len());
    for envelope in &envelopes {
        let mut value = match serde_json::to_value(envelope) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(error = %error, request_id = %envelope.request_id, "failed to serialize dead-letter envelope; skipping");
                continue;
            }
        };
        crate::sanitize::strip_egress_only_keys(&mut value);
        dead_letters.push(value);
    }
    finish_json(
        res,
        StatusCode::OK,
        serde_json::json!({
            "backend": queue.backend_name(),
            "limit": limit,
            "count": dead_letters.len(),
            "dead_letters": dead_letters,
        }),
        started,
    );
}
