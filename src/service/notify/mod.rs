use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use salvo::http::header::{HeaderName, HeaderValue};
use salvo::http::{ParseError, StatusCode};
use salvo::prelude::*;
use serde_json::Value;
use uuid::Uuid;

use super::MAX_REQUEST_SIZE;
use super::metrics::{
    finish_error, record_delivery_receipt_outcomes, record_notify_delivery_by_scope,
    record_notify_delivery_outcomes,
};
use crate::audit::AuditEvent;
use crate::auth::authenticate_notify_request;
use crate::models::{
    FloriaPushNotifyEnvelope as PushNotifyRequestBody,
    FloriaPushNotifyOutcome as PushNotifyOutcome, NotificationContext, ProviderRetry,
};
use crate::{AppState, metrics as app_metrics};

mod helpers;
mod validation;

#[cfg(test)]
mod tests;

use helpers::{
    cache_success_response, dedup_provider_retries, delivery_receipt, enqueue_retry,
    finish_standard_notify_json, idempotency_cache_key, mark_delivered_devices,
    normalized_notify_dedup_key, notify_rate_limit_checks, optional_owned_string,
    record_rejected_devices_audit_or_finish, record_required_audit_event, rejected_device,
    request_destination_service_did, resolve_idempotency_key,
};
use validation::{
    AgentEventRouting, BLIND_PROFILE_PLAINTEXT_REASON, classify_agent_event_kind,
    validate_destination_service_did, validate_notification_contract,
    validate_notify_contract_shape, validate_origin_service_did,
    validate_plaintext_identity_metadata,
};

/// Round 4 — `reason_code=historical_only` short-circuits soland's
/// diagnostic replay. floria MUST NOT fan the request out a second
/// time; it answers 200 with an empty rejected list and no provider
/// retries. The wire constant comes from the SDK.
const HISTORICAL_ONLY_REASON: &str = cokret::ERROR_CODE_HISTORICAL_ONLY;

/// Round 4 — `ck.audit.policy_access.access_kind` value that diverts
/// to the audit pipeline. floria MUST NOT push-fan-out when the
/// inbound request carries this access_kind; it forwards to the audit
/// sink and only then acks with 200. The wire literal mirrors the SDK
/// enum serde repr (`snake_case`).
const E2EE_LATE_RECOVERY_ACCESS_KIND: &str = "e2ee_late_recovery";

/// Round 4 — wire reason floria attaches to a RejectedDevice when the
/// device's `target_actor_id` is not present in the
/// `mention_redirect_target_actor_ids` allow-list. Used by both the
/// device-loop reject path and the per-device dedup test that the
/// gate is fail-closed (no provider dispatch, no decryption attempt).
const MENTION_REDIRECT_NOT_TARGETED_REASON: &str = "mention_redirect_not_targeted";

#[handler]
pub(super) async fn notify_method_not_allowed(res: &mut Response) {
    let _ = res.add_header(
        HeaderName::from_static("allow"),
        HeaderValue::from_static("POST"),
        true,
    );
    finish_error(
        res,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "method not allowed",
        None,
        None,
        Instant::now(),
    );
}

#[handler]
pub(super) async fn notify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let started = Instant::now();
    let _inflight = app_metrics::track_inflight("V1NotifyHandler");

    let span = tracing::info_span!(
        "notify",
        request_id = tracing::field::Empty,
        caller = tracing::field::Empty,
        provider = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    let _entered = span.enter();

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
    let request_id = Uuid::new_v4().to_string();
    span.record("request_id", tracing::field::display(&request_id));

    let body = match req.payload_with_max_size(MAX_REQUEST_SIZE).await {
        Ok(bytes) => bytes.to_vec(),
        Err(ParseError::PayloadTooLarge) => {
            finish_error(
                res,
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "request body exceeds 512 KiB",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
        Err(error) => {
            tracing::warn!(error = %error, "failed to read request body");
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "failed to read request body",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };
    let caller = match authenticate_notify_request(
        req,
        body.as_ref(),
        &state.notify_auth,
        state.notify_nonce_store.as_ref(),
        &request_id,
    )
    .await
    {
        Ok(caller) => {
            span.record(
                "caller",
                tracing::field::display(&caller.origin_service_did),
            );
            caller
        }
        Err(error) => {
            finish_error(
                res,
                error.status,
                error.code,
                &error.message,
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };
    let raw_request_hash = crate::dedup::request_hash(body.as_ref());

    let _standard_request = match serde_json::from_slice::<cokret::PushNotifyRequestBody>(&body) {
        Ok(request) => request,
        Err(error) => {
            tracing::warn!(error = %error, "expected Cokret push notify request body");
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "expected Cokret push notify request body",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };
    let request = match serde_json::from_slice::<PushNotifyRequestBody>(&body) {
        Ok(request) => request,
        Err(error) => {
            tracing::warn!(error = %error, "expected JSON request body");
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "expected JSON request body",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };
    let request_value = match serde_json::to_value(&request) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(error = %error, "failed to build typed request validation view");
            finish_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to validate typed request",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };
    // SPEC-CR-016: `operation_id` is determined by the URL path
    // (operationId `ck.edge.push.command.notify`) and is no longer a body
    // field, so there is nothing to validate here.
    if let Err(error) = validate_origin_service_did(req, &caller, state.notify_auth.enabled()) {
        finish_error(
            res,
            error.status,
            error.code,
            &error.message,
            None,
            Some(&request_id),
            started,
        );
        return;
    }
    if let Err(error) =
        validate_destination_service_did(req, &state.notify_auth, state.notify_auth.enabled())
    {
        finish_error(
            res,
            error.status,
            error.code,
            &error.message,
            None,
            Some(&request_id),
            started,
        );
        return;
    }
    if let Err(message) = validate_notify_contract_shape(&request_value) {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            &message,
            None,
            Some(&request_id),
            started,
        );
        return;
    }
    // Round 4 (spec a77b995) — short-circuit the push pipeline when
    // soland tells us this is a diagnostic replay
    // (`reason_code=historical_only`). We answer 200 with an empty
    // fanout body so soland's idempotency cache stays consistent but
    // no provider call is issued and no per-device dedup state is
    // touched. Any other `reason_code` value is rejected — floria
    // only honors the well-known no-op shape on the request side.
    match request.reason_code.as_deref() {
        None => {}
        Some(value) if value == HISTORICAL_ONLY_REASON => {
            tracing::info!(
                request_id = %request_id,
                "answering 200 no-fanout ack for reason_code=historical_only"
            );
            let response = PushNotifyOutcome {
                request_id: request_id.clone(),
                accepted: 0,
                rejected: Vec::new(),
                provider_retries: Vec::new(),
                delivery_receipts: Vec::new(),
            };
            finish_standard_notify_json(res, StatusCode::OK, &response, started);
            return;
        }
        Some(_) => {
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "reason_code is only valid as `historical_only` on /push/notify",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    }
    // Phase P2 (CKP-0008 / CKP-0009) — route Personal Agent event kinds.
    //
    // The SDK exposes seven new `ck.agent.*` kinds. Floria does not
    // surface any of them onto user-device push by default:
    //
    //   * `ck.agent.{pause, resume, deactivate}` — durable lifecycle. Silently consumed: 200 OK +
    //     zero fanout. The authoritative capability-cache invalidation path for these state changes
    //     is the soland `consent_revoke` fanout (`reason=agent_paused` / `agent_deactivated`), not
    //     a push.
    //   * `ck.agent.{draft.propose, action_request, action_approve, action_reject}` —
    //     actor-private. Dropped: 200 OK + zero fanout. A future opt-in subscription gate may
    //     upgrade specific kinds onto a dedicated agent-runtime endpoint, but until that mechanism
    //     exists the default is drop.
    //
    // Either case answers 200 so the caller's pipeline advances; the
    // `accepted` count is 0 and the rejected list is empty.
    if let Some(kind) = request.event_kind.as_deref() {
        if let Some(routing) = classify_agent_event_kind(kind.trim()) {
            match routing {
                AgentEventRouting::DurableLifecycle => {
                    tracing::info!(
                        request_id = %request_id,
                        event_kind = %kind,
                        "answering 200 no-fanout ack: durable agent lifecycle \
                         event silently consumed (capability cache invalidation \
                         strands through consent_revoke)"
                    );
                }
                AgentEventRouting::ActorPrivateDrop => {
                    tracing::info!(
                        request_id = %request_id,
                        event_kind = %kind,
                        "answering 200 no-fanout ack: actor_private agent event \
                         dropped by default (no controller-private subscription \
                         mechanism wired up yet)"
                    );
                }
            }
            let response = PushNotifyOutcome {
                request_id: request_id.clone(),
                accepted: 0,
                rejected: Vec::new(),
                provider_retries: Vec::new(),
                delivery_receipts: Vec::new(),
            };
            finish_standard_notify_json(res, StatusCode::OK, &response, started);
            return;
        }
        // Any other `event_kind` string falls through — floria does not
        // gate non-agent kinds at this layer.
    }
    // Round 4 — route `ck.audit.policy_access{access_kind=
    // e2ee_late_recovery}` to the audit pipeline, NOT to push. floria
    // writes the audit event first, then acks 200 so the caller's
    // pipeline advances. It does not do push fanout for this shape.
    if let Some(audit_envelope) = request.audit_envelope.as_ref() {
        let access_kind = audit_envelope.access_kind.trim();
        if access_kind.is_empty() {
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "audit_envelope.access_kind must be a non-empty string",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
        let late_recovery_original_event_id =
            optional_owned_string(audit_envelope.late_recovery_original_event_id.as_ref());
        if access_kind == E2EE_LATE_RECOVERY_ACCESS_KIND
            && late_recovery_original_event_id.is_none()
        {
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "audit_envelope.access_kind=e2ee_late_recovery requires \
                 late_recovery_original_event_id",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
        let audit_event = AuditEvent::PolicyAccess {
            request_id: request_id.clone(),
            origin_service_did: caller.origin_service_did.clone(),
            destination_service_did: request_destination_service_did(req),
            access_kind: access_kind.to_owned(),
            late_recovery_original_event_id,
            notification_event_id: optional_owned_string(request.notification.event_id.as_ref()),
            notification_strand_id: optional_owned_string(request.notification.strand_id.as_ref()),
            notification_realm_id: request.notification.realm_id().map(ToOwned::to_owned),
        };
        if let Err(message) = record_required_audit_event(&state, &audit_event).await {
            tracing::error!(
                request_id = %request_id,
                error = %message,
                "failed to write policy_access audit event"
            );
            finish_error(
                res,
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                &message,
                None,
                Some(&request_id),
                started,
            );
            return;
        }
        tracing::info!(
            request_id = %request_id,
            access_kind = %access_kind,
            "answering 200 audit-pipeline ack after audit sink write; SKIPPING push fanout"
        );
        let response = PushNotifyOutcome {
            request_id: request_id.clone(),
            accepted: 0,
            rejected: Vec::new(),
            provider_retries: Vec::new(),
            delivery_receipts: Vec::new(),
        };
        finish_standard_notify_json(res, StatusCode::OK, &response, started);
        return;
    }
    let idempotency_key = match resolve_idempotency_key(req) {
        Ok(idempotency_key) => idempotency_key,
        Err(message) => {
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                &message,
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };

    let notification_object = request_value
        .get("notification")
        .and_then(Value::as_object)
        .cloned();
    let notification = request.notification;

    // T1.1 — for blind-only callers, additionally run the SDK
    // sanitizer over each device's `data.default_payload` subtree so
    // that any forbidden field or did:/ck: literal that survived the
    // wire-model allow-list gets stopped before fan-out.
    if !caller.allow_plaintext_metadata
        && let Some(devices) = notification_object
            .as_ref()
            .and_then(|obj| obj.get("devices"))
            .and_then(Value::as_array)
    {
        for (index, device) in devices.iter().enumerate() {
            let Some(default_payload) = device
                .get("data")
                .and_then(Value::as_object)
                .and_then(|data| data.get("default_payload"))
            else {
                continue;
            };
            let envelope = serde_json::json!({
                "notification": {
                    "push_target_id": "ck:pseudonym:push:0000000000000000000000",
                    "wakeup_kind": "message",
                },
                "default_payload": default_payload,
            });
            if let Err(err) = cokret::blind_payload_sanitizer::sanitize_blind_payload(&envelope) {
                finish_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    &format!(
                        "blind wakeup sanitizer rejected `notification.devices[{index}].data.default_payload.{}`: {}",
                        err.field_path, err.reason_code,
                    ),
                    None,
                    Some(&request_id),
                    started,
                );
                return;
            }
        }
    }

    match validate_notification_contract(&notification, &caller) {
        Ok(()) => {}
        // T4.3 — blind profile + plaintext metadata is a precondition
        // violation, not an authorization failure: the caller could
        // still have the right credentials, the request just can't
        // be carried by the blind profile they're scoped to.
        Err(message) if message.starts_with(BLIND_PROFILE_PLAINTEXT_REASON) => {
            finish_error(
                res,
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                &message,
                None,
                Some(&request_id),
                started,
            );
            return;
        }
        Err(message) if message.starts_with("caller is not authorized") => {
            finish_error(
                res,
                StatusCode::FORBIDDEN,
                "capability_denied",
                &message,
                None,
                Some(&request_id),
                started,
            );
            return;
        }
        Err(message) => {
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                &message,
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    }

    if let Some(notification) = notification_object.as_ref()
        && let Err(message) = validate_plaintext_identity_metadata(notification, &caller)
    {
        // T4.3 — same reasoning: surface `failed_precondition` when
        // the failure is "wrong profile", and `capability_denied`
        // when the caller lacks the credential entirely.
        let (status, code) = if message.starts_with(BLIND_PROFILE_PLAINTEXT_REASON) {
            (StatusCode::PRECONDITION_FAILED, "failed_precondition")
        } else {
            (StatusCode::FORBIDDEN, "capability_denied")
        };
        finish_error(
            res,
            status,
            code,
            &message,
            None,
            Some(&request_id),
            started,
        );
        return;
    }

    let request_fingerprint =
        normalized_notify_dedup_key(&notification).unwrap_or(raw_request_hash);
    let dedup_key = idempotency_key
        .as_deref()
        .map(idempotency_cache_key)
        .unwrap_or_else(|| request_fingerprint.clone());
    if let Some(deduplicator) = state.notify_deduplicator.as_ref() {
        if deduplicator
            .conflicts_async(&dedup_key, &request_fingerprint)
            .await
        {
            app_metrics::notify_dedup_lookup("conflict");
            finish_error(
                res,
                StatusCode::CONFLICT,
                "duplicate_conflict",
                "same idempotency key maps to different canonical request body",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
        if let Some(cached) = deduplicator
            .lookup_async(&dedup_key, &request_fingerprint)
            .await
        {
            app_metrics::notify_dedup_lookup("hit");
            app_metrics::notify_request_cache_hit();
            tracing::info!(
                request_id = %request_id,
                ttl_secs = deduplicator.ttl().as_secs(),
                idempotency_key = idempotency_key
                    .as_deref()
                    .unwrap_or("<canonical-request-hash>"),
                "serving /notify response from dedup cache"
            );
            let response = cached.response.with_request_id(request_id);
            finish_standard_notify_json(res, StatusCode::OK, &response, started);
            return;
        }
        app_metrics::notify_dedup_lookup("miss");
    }
    app_metrics::notification_received();

    if notification.devices.is_empty() {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "no devices in notification",
            None,
            Some(&request_id),
            started,
        );
        return;
    }

    if let Some(rate_limiter) = state.notify_rate_limiter.as_ref() {
        let checks = notify_rate_limit_checks(req, &state, &notification);
        if let Err(rejection) = rate_limiter.check_many_async(&checks).await {
            app_metrics::notify_rate_limit_reject(rejection.scope);
            tracing::warn!(
                request_id = %request_id,
                scope = rejection.scope,
                subject = %rejection.subject,
                limit = rejection.limit,
                retry_after_secs = rejection.retry_after.as_secs(),
                "rejecting /notify request due to rate limit"
            );
            finish_error(
                res,
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                &format!("notify rate limit exceeded for {}", rejection.scope),
                Some(rejection.retry_after),
                Some(&request_id),
                started,
            );
            return;
        }
    }

    let context = NotificationContext {
        request_id: request_id.clone(),
        start_time: Instant::now(),
    };

    let mut rejected = Vec::new();
    let mut delivered_now = 0usize;
    let mut skipped_delivered = 0usize;
    let mut provider_retries = Vec::new();
    let mut delivery_receipts = Vec::new();
    let mut seen_devices = HashSet::new();
    let mut first_remote_error: Option<String> = None;
    let mut first_temporary_error: Option<(String, Option<Duration>)> = None;
    let mut first_internal_error: Option<String> = None;
    for device in &notification.devices {
        let app_id = device.app_id.trim();
        let push_key = device.push_key.trim();
        if app_id.is_empty() || push_key.is_empty() {
            tracing::warn!(
                request_id = %context.request_id,
                app_id = %device.app_id,
                push_key_hash = %device.redacted_push_key(),
                "rejecting device with empty app_id or push_key"
            );
            rejected.push(rejected_device(device, Some(&device.push_key)));
            delivery_receipts.push(delivery_receipt(
                None,
                &device.push_key,
                "rejected",
                None,
                &context.request_id,
            ));
            continue;
        }

        if !seen_devices.insert((app_id.to_owned(), push_key.to_owned())) {
            tracing::info!(
                request_id = %context.request_id,
                app_id,
                push_key_hash = %device.redacted_push_key(),
                "skipping duplicate device entry"
            );
            continue;
        }

        // Round 4 (spec a77b995) — `mention_redirect_target_actor_ids`
        // plaintext routing gate. When soland set a non-empty allow-list
        // the device's `target_actor_id` MUST appear in it, otherwise
        // the device is fail-closed: no provider dispatch, no body
        // decryption is attempted, and the rejection is recorded with
        // the wire-safe `mention_redirect_not_targeted` reason so the
        // operator can tell why the device was skipped. Devices with
        // no `target_actor_id` cannot prove their inclusion in the
        // allow-list — same outcome (fail-closed).
        if !notification.mention_redirect_target_actor_ids().is_empty() {
            let allowed = device
                .target_actor_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some_and(|actor_id| {
                    notification
                        .mention_redirect_target_actor_ids()
                        .iter()
                        .any(|allowed| allowed.trim() == actor_id)
                });
            if !allowed {
                tracing::info!(
                    request_id = %context.request_id,
                    app_id,
                    push_key_hash = %device.redacted_push_key(),
                    "fail-closed: device.target_actor_id not in mention_redirect_target_actor_ids"
                );
                rejected.push(
                    rejected_device(device, Some(&device.push_key))
                        .with_reason_code(Some(MENTION_REDIRECT_NOT_TARGETED_REASON)),
                );
                delivery_receipts.push(delivery_receipt(
                    None,
                    &device.push_key,
                    "rejected",
                    None,
                    &context.request_id,
                ));
                continue;
            }
        }

        // T4.4 — Caller (Sync Service / soland) may have already
        // evaluated the v1 core push rule and decided `dont_notify`.
        // Honor that decision verbatim: record the rejection with the
        // caller-supplied wire-safe reason code and skip dispatch.
        // floria itself does not re-evaluate watch levels — that's the
        // Sync Service's job.
        if let Some(hint) = device.push_decision.as_ref()
            && !hint.deliver
        {
            tracing::debug!(
                request_id = %context.request_id,
                app_id,
                push_key_hash = %device.redacted_push_key(),
                reason_code = hint.reason_code.as_deref().unwrap_or(""),
                "skipping device per caller-supplied push_decision"
            );
            app_metrics::notify_suppressed(hint.reason_code.as_deref(), 1);
            rejected.push(
                rejected_device(device, Some(&device.push_key))
                    .with_reason_code(hint.reason_code.as_deref()),
            );
            delivery_receipts.push(delivery_receipt(
                None,
                &device.push_key,
                "rejected",
                None,
                &context.request_id,
            ));
            continue;
        }

        app_metrics::device_push_received();
        let pushkins = state.registry.find_pushkins(&device.app_id);
        match pushkins.as_slice() {
            [] => {
                tracing::warn!(request_id = %context.request_id, app_id = %device.app_id, push_key_hash = %device.redacted_push_key(), "unknown app id");
                rejected.push(rejected_device(device, Some(&device.push_key)));
                delivery_receipts.push(delivery_receipt(
                    None,
                    &device.push_key,
                    "rejected",
                    None,
                    &context.request_id,
                ));
                continue;
            }
            [pushkin] => {
                if state
                    .notify_deduplicator
                    .as_ref()
                    .is_some_and(|deduplicator| {
                        deduplicator.contains_delivered_device(&dedup_key, app_id, push_key)
                    })
                {
                    skipped_delivered += 1;
                    app_metrics::notify_device_skip_hit(1);
                    app_metrics::notify_device_skip_by_pushkin(pushkin.name(), 1);
                    delivery_receipts.push(delivery_receipt(
                        Some(pushkin.name()),
                        push_key,
                        "accepted_cached",
                        None,
                        &context.request_id,
                    ));
                    tracing::info!(
                        request_id = %context.request_id,
                        app_id,
                        push_key_hash = %device.redacted_push_key(),
                        pushkin = %pushkin.name(),
                        "skipping device already delivered within dedup ttl"
                    );
                    continue;
                }

                app_metrics::pushkin_selected(pushkin.name());
                let dispatch_targets = pushkin.dispatch_targets(&notification, device);
                let dispatch_started = Instant::now();
                let dispatch_result = pushkin
                    .dispatch_notification(&notification, device, &context)
                    .await;
                let dispatch_outcome = match &dispatch_result {
                    Ok(rejected) if rejected.is_empty() => "accepted",
                    Ok(_) => "partial",
                    Err(error) if error.is_temporary() => "retryable",
                    Err(error) if error.is_remote() => "remote_error",
                    Err(_) => "internal_error",
                };
                app_metrics::observe_pushkin_dispatch(
                    pushkin.name(),
                    dispatch_outcome,
                    dispatch_started.elapsed(),
                );
                app_metrics::notify_delivery_outcome_by_app(app_id, dispatch_outcome, 1);
                match dispatch_result {
                    Ok(mut pushkin_rejected) => {
                        let rejected_set = pushkin_rejected
                            .iter()
                            .cloned()
                            .collect::<HashSet<String>>();
                        let delivered_targets = dispatch_targets
                            .iter()
                            .filter(|target| !rejected_set.contains(&target.push_key))
                            .collect::<Vec<_>>();
                        if !delivered_targets.is_empty() {
                            delivered_now += delivered_targets.len();
                            for target in &delivered_targets {
                                delivery_receipts.push(delivery_receipt(
                                    Some(pushkin.name()),
                                    &target.push_key,
                                    "accepted",
                                    None,
                                    &context.request_id,
                                ));
                            }
                            mark_delivered_devices(
                                &state,
                                &dedup_key,
                                delivered_targets.iter().copied(),
                            );
                        }
                        rejected.extend(pushkin_rejected.drain(..).map(|push_key| {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &push_key,
                                "rejected",
                                None,
                                &context.request_id,
                            ));
                            rejected_device(device, Some(&push_key))
                        }));
                    }
                    Err(error) if error.is_temporary() => {
                        let retry_after = error.retry_after();
                        tracing::warn!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id = %device.app_id,
                            push_key_hash = %device.redacted_push_key(),
                            "temporary dispatch failure"
                        );
                        provider_retries.push(ProviderRetry::new(pushkin.name(), retry_after));
                        for target in &dispatch_targets {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &target.push_key,
                                "retryable",
                                retry_after,
                                &context.request_id,
                            ));
                            enqueue_retry(
                                &state,
                                &context.request_id,
                                pushkin.name(),
                                &target.app_id,
                                &target.push_key,
                                retry_after,
                                &error,
                            );
                        }
                        first_temporary_error
                            .get_or_insert_with(|| (error.to_string(), retry_after));
                    }
                    Err(error) if error.is_remote() => {
                        tracing::warn!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id = %device.app_id,
                            push_key_hash = %device.redacted_push_key(),
                            "remote dispatch failure"
                        );
                        for target in &dispatch_targets {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &target.push_key,
                                "failed",
                                None,
                                &context.request_id,
                            ));
                        }
                        first_remote_error.get_or_insert_with(|| error.to_string());
                    }
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id = %device.app_id,
                            push_key_hash = %device.redacted_push_key(),
                            "internal dispatch failure"
                        );
                        for target in &dispatch_targets {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &target.push_key,
                                "failed",
                                None,
                                &context.request_id,
                            ));
                        }
                        first_internal_error.get_or_insert_with(|| error.to_string());
                    }
                }
            }
            _ => {
                tracing::warn!(request_id = %context.request_id, app_id = %device.app_id, push_key_hash = %device.redacted_push_key(), "ambiguous app id");
                rejected.push(rejected_device(device, Some(&device.push_key)));
                delivery_receipts.push(delivery_receipt(
                    None,
                    &device.push_key,
                    "rejected",
                    None,
                    &context.request_id,
                ));
            }
        }
    }

    dedup_provider_retries(&mut provider_retries);

    let fully_settled = first_internal_error.is_none()
        && first_temporary_error.is_none()
        && first_remote_error.is_none();
    let had_errors = !fully_settled;

    if delivered_now > 0 {
        if had_errors {
            app_metrics::notify_partial_success(StatusCode::OK);
        }
        if skipped_delivered > 0 {
            app_metrics::notify_retry_with_skips(StatusCode::OK);
        }
        if let Some(message) = first_internal_error.as_deref() {
            tracing::warn!(
                request_id = %context.request_id,
                delivered = delivered_now,
                skipped_delivered,
                rejected = rejected.len(),
                error = %message,
                "returning success despite partial internal dispatch failures"
            );
        } else if let Some((message, retry_after)) = first_temporary_error.as_ref() {
            tracing::warn!(
                request_id = %context.request_id,
                delivered = delivered_now,
                skipped_delivered,
                rejected = rejected.len(),
                retry_after_secs = retry_after.map(|value| value.as_secs()),
                error = %message,
                "returning success despite partial temporary dispatch failures"
            );
        } else if let Some(message) = first_remote_error.as_deref() {
            tracing::warn!(
                request_id = %context.request_id,
                delivered = delivered_now,
                skipped_delivered,
                rejected = rejected.len(),
                error = %message,
                "returning success despite partial remote dispatch failures"
            );
        } else if skipped_delivered > 0 {
            tracing::info!(
                request_id = %context.request_id,
                delivered = delivered_now,
                skipped_delivered,
                rejected = rejected.len(),
                "returning success with cached delivered devices"
            );
        }
        let response = PushNotifyOutcome {
            request_id: context.request_id.clone(),
            accepted: delivered_now + skipped_delivered,
            rejected,
            provider_retries,
            delivery_receipts,
        };
        if !record_rejected_devices_audit_or_finish(
            &state,
            &context.request_id,
            &caller,
            &notification,
            &response.rejected,
            res,
            started,
        )
        .await
        {
            return;
        }
        if fully_settled {
            cache_success_response(&state, &dedup_key, &request_fingerprint, &response);
        }
        record_notify_delivery_outcomes(&response);
        record_notify_delivery_by_scope(
            &notification,
            &response.delivery_receipts,
            state.metrics_detailed_circle_labels,
        );
        finish_standard_notify_json(res, StatusCode::OK, &response, started);
        return;
    }

    if skipped_delivered > 0 {
        let status = if first_internal_error.is_some() {
            StatusCode::INTERNAL_SERVER_ERROR
        } else if first_temporary_error.is_some() {
            StatusCode::SERVICE_UNAVAILABLE
        } else if first_remote_error.is_some() {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::OK
        };
        app_metrics::notify_retry_with_skips(status);
        tracing::info!(
            request_id = %context.request_id,
            skipped_delivered,
            rejected = rejected.len(),
            "all currently delivered devices came from dedup cache"
        );
    }

    if let Some(message) = first_internal_error {
        if !record_rejected_devices_audit_or_finish(
            &state,
            &context.request_id,
            &caller,
            &notification,
            &rejected,
            res,
            started,
        )
        .await
        {
            return;
        }
        record_delivery_receipt_outcomes(
            &delivery_receipts,
            delivered_now + skipped_delivered,
            rejected.len(),
        );
        finish_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &message,
            None,
            Some(&context.request_id),
            started,
        );
        return;
    }

    if let Some((message, retry_after)) = first_temporary_error {
        if !record_rejected_devices_audit_or_finish(
            &state,
            &context.request_id,
            &caller,
            &notification,
            &rejected,
            res,
            started,
        )
        .await
        {
            return;
        }
        record_delivery_receipt_outcomes(
            &delivery_receipts,
            delivered_now + skipped_delivered,
            rejected.len(),
        );
        finish_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            &message,
            retry_after,
            Some(&context.request_id),
            started,
        );
        return;
    }

    if let Some(message) = first_remote_error {
        if !record_rejected_devices_audit_or_finish(
            &state,
            &context.request_id,
            &caller,
            &notification,
            &rejected,
            res,
            started,
        )
        .await
        {
            return;
        }
        record_delivery_receipt_outcomes(
            &delivery_receipts,
            delivered_now + skipped_delivered,
            rejected.len(),
        );
        finish_error(
            res,
            StatusCode::BAD_GATEWAY,
            "temporarily_unavailable",
            &message,
            None,
            Some(&context.request_id),
            started,
        );
        return;
    }

    let response = PushNotifyOutcome {
        request_id: context.request_id.clone(),
        accepted: delivered_now + skipped_delivered,
        rejected,
        provider_retries,
        delivery_receipts,
    };
    if !record_rejected_devices_audit_or_finish(
        &state,
        &context.request_id,
        &caller,
        &notification,
        &response.rejected,
        res,
        started,
    )
    .await
    {
        return;
    }
    if fully_settled {
        cache_success_response(&state, &dedup_key, &request_fingerprint, &response);
    }
    record_notify_delivery_outcomes(&response);
    record_notify_delivery_by_scope(
        &notification,
        &response.delivery_receipts,
        state.metrics_detailed_circle_labels,
    );
    finish_standard_notify_json(res, StatusCode::OK, &response, started);
}
