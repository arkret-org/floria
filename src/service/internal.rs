//! Round R2/R3 (T07 + T17) — internal soland-broadcast endpoints.
//!
//! These routes are intended for the soland-broadcast channel (or an
//! equivalent in-process message bus). They are exposed under
//! `/api/v1/internal/...` and intentionally do NOT share the public
//! `/api/v1/push/notify` request shape. Auth is delegated to the
//! deployment (typically a private listener + service mesh mTLS); the
//! handlers themselves only validate wire shape.
//
// TODO(round23-T07): once the in-process broadcast bus lands, swap the
// HTTP shim for a direct channel subscriber. The handler bodies stay
// the same — they take the deserialized broadcast envelope and return
// a typed ack — only the transport changes.

use std::sync::Arc;
use std::time::Instant;

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Serialize;

use crate::AppState;
use crate::deactivation::{AccountDeactivateFanoutAck, AccountDeactivateFanoutBroadcast};
use crate::push_contact_cache::ConsentRevokeBroadcast;

use super::metrics::{finish_error, finish_json};

#[derive(Debug, Serialize)]
struct ConsentRevokeAck {
    broadcast_id: String,
    scope: &'static str,
    entries_evicted: usize,
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
    if body.actor_did.trim().is_empty() {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "actor_did must not be empty",
            None,
            None,
            started,
        );
        return;
    }

    let Some(ledger) = state.deactivation_ledger.as_ref() else {
        // The endpoint exists even when the ledger isn't wired up so
        // soland can detect mis-configurations early. We answer 503 so
        // soland retries rather than reporting fanout_complete on a
        // dropped broadcast.
        finish_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "deactivation ledger is not configured on this push gateway",
            None,
            None,
            started,
        );
        return;
    };

    let result = ledger.record_fanout(&body);

    // TODO(round23-T07): drain queued to-device messages for the
    // unbound (actor, device) cells here, then set messages_drained
    // honestly. For now the count is whatever the ledger reported
    // (currently 0 — see deactivation.rs).
    let ack = AccountDeactivateFanoutAck {
        fanout_id: body.fanout_id.clone(),
        outcome: result.outcome,
        actor_bindings_unbound: result.actor_bindings_unbound,
        device_bindings_unbound: result.device_bindings_unbound,
        sealed_channels: result.sealed_channels,
        messages_drained: result.messages_drained,
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

    let Some(cache) = state.push_contact_cache.as_ref() else {
        // No cache wired up → nothing to invalidate. soland's broadcast
        // is still a success, but we answer 503 so it's obvious in
        // operator dashboards that the listener saw the broadcast but
        // couldn't act.
        finish_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "push contact cache is not configured on this push gateway",
            None,
            None,
            started,
        );
        return;
    };

    let evicted = cache.invalidate_principal(&body.principal_did);
    let ack = ConsentRevokeAck {
        broadcast_id: body.broadcast_id.clone(),
        scope: ConsentRevokeBroadcast::SUPPORTED_SCOPE,
        entries_evicted: evicted,
    };
    tracing::info!(
        broadcast_id = %ack.broadcast_id,
        scope = ack.scope,
        entries_evicted = ack.entries_evicted,
        "processed consent_revoke scope=any broadcast"
    );
    finish_json(res, StatusCode::OK, ack, started);
}
