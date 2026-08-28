use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arkret_models_integration::{
    AgentEventRouting, PushNotificationEnvelope, PushNotifyDeviceOutcome, PushNotifyReasonCode,
    classify_agent_event_kind, validate_push_notify_contract_shape,
};
use salvo::http::header::{HeaderName, HeaderValue};
use salvo::http::{ParseError, StatusCode};
use salvo::prelude::*;
use uuid::Uuid;

use super::MAX_REQUEST_SIZE;
use super::metrics::{
    finish_error, record_delivery_receipt_outcomes, record_notify_delivery_by_scope,
};
use crate::audit::AuditEvent;
use crate::auth::authenticate_notify_request;
use crate::models::{DeviceExt, NotificationContext, NotificationExt, NotifyDispatchResult};
use crate::{AppState, metrics as app_metrics};

mod helpers;
mod validation;

#[cfg(test)]
mod tests;

pub(super) use helpers::idempotency_cache_key;
use helpers::{
    cache_success_response, delivery_receipt, enqueue_retry, finish_standard_notify_json,
    mark_delivered_devices, normalized_notify_dedup_key, notify_rate_limit_checks,
    optional_owned_string, record_rejected_devices_audit_or_finish, record_required_audit_event,
    rejected_device, request_destination_id, resolve_idempotency_key,
};
use validation::{
    BLIND_PROFILE_PLAINTEXT_REASON, VISIBLE_DEVICE_OPT_IN_REASON, validate_destination_id,
    validate_notification_contract, validate_origin_id, validate_plaintext_identity_metadata,
};

/// Round 4 — `reason_code=historical_only` short-circuits soland's
/// diagnostic replay. floria MUST NOT fan the request out a second
/// time; it answers 200 with one accepted gateway outcome per input
/// device and no provider retries. The wire constant comes from the SDK.
const HISTORICAL_ONLY_REASON: &str = arkret_wire::ErrorCode::HISTORICAL_ONLY;

/// Round 4 — private audit reason floria attaches to a RejectedDevice when the
/// device's `target_route_token` is not present in the
/// `mention_redirect_target_route_tokens` allow-list. Used by both the
/// device-loop reject path and the per-device dedup test that the
/// gate is fail-closed (no provider dispatch, no decryption attempt).
const MENTION_REDIRECT_NOT_TARGETED_REASON: &str = "mention_redirect_not_targeted";
const CIRCUIT_BREAKER_RETRY_AFTER: Duration = Duration::from_secs(30);
#[cfg(not(test))]
const DEFAULT_PROVIDER_TIMING_BUCKET: Duration = Duration::from_secs(60);
#[cfg(test)]
const DEFAULT_PROVIDER_TIMING_BUCKET: Duration = Duration::from_secs(0);
#[cfg(not(test))]
const HIGH_PRIVACY_PROVIDER_TIMING_BUCKET: Duration = Duration::from_secs(300);
#[cfg(test)]
const HIGH_PRIVACY_PROVIDER_TIMING_BUCKET: Duration = Duration::from_secs(0);

async fn wait_for_provider_timing_bucket(request_id: &str, bucket: Duration) {
    let delay = provider_timing_bucket_delay(SystemTime::now(), bucket);
    if delay == Duration::ZERO {
        return;
    }
    tracing::info!(
        request_id,
        delay_ms = delay.as_millis(),
        bucket_ms = bucket.as_millis(),
        "delaying provider dispatch until timing bucket boundary"
    );
    tokio::time::sleep(delay).await;
}

fn provider_timing_bucket_for_notification(notification: &PushNotificationEnvelope) -> Duration {
    if notification_uses_high_privacy_timing(notification) {
        HIGH_PRIVACY_PROVIDER_TIMING_BUCKET
    } else {
        DEFAULT_PROVIDER_TIMING_BUCKET
    }
}

fn notification_uses_high_privacy_timing(notification: &PushNotificationEnvelope) -> bool {
    notification
        .timing_profile_hint
        .is_some_and(arkret_models_integration::PushTimingProfileHint::is_traffic_metadata_hardened)
        || notification.evaluation_locus_unresolved.unwrap_or(false)
        || notification.push_hint.as_deref() == Some("l10n_key")
        || notification
            .push_hint_l10n_key
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
}

fn provider_timing_bucket_delay(now: SystemTime, bucket: Duration) -> Duration {
    if bucket == Duration::ZERO {
        return Duration::ZERO;
    }
    let Ok(elapsed) = now.duration_since(UNIX_EPOCH) else {
        return bucket;
    };
    let bucket_nanos = bucket.as_nanos();
    if bucket_nanos == 0 {
        return Duration::ZERO;
    }
    let elapsed_in_bucket = elapsed.as_nanos() % bucket_nanos;
    if elapsed_in_bucket == 0 {
        return Duration::ZERO;
    }
    Duration::from_nanos((bucket_nanos - elapsed_in_bucket).min(u64::MAX as u128) as u64)
}

fn push_target_id(notification: &PushNotificationEnvelope) -> arkret_wire::PushTargetId {
    notification
        .push_target_id
        .clone()
        .expect("validated notify request has a push_target_id")
}

fn accepted_outcomes(notification: &PushNotificationEnvelope) -> Vec<PushNotifyDeviceOutcome> {
    notification
        .devices
        .iter()
        .map(|device| PushNotifyDeviceOutcome::accepted(device.device_id.clone()))
        .collect()
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().clamp(1, u64::MAX as u128) as u64
}

fn no_fanout_response(
    request_id: &str,
    notification: &PushNotificationEnvelope,
) -> NotifyDispatchResult {
    let outcomes = accepted_outcomes(notification);
    NotifyDispatchResult::new(request_id, push_target_id(notification), outcomes)
}

fn circuit_breaker_key(
    pushkin: &str,
    notification: &PushNotificationEnvelope,
) -> crate::circuit_breaker::BreakerKey {
    crate::circuit_breaker::BreakerKey::new(
        pushkin,
        notification
            .realm_route_token()
            .or_else(|| notification.realm_id()),
        notification.scope_route_token(),
    )
}

fn circuit_breaker_scope(notification: &PushNotificationEnvelope) -> (&'static str, Option<&str>) {
    if notification.scope_route_token().is_some() {
        ("scope", None)
    } else {
        ("realm", notification.realm_id())
    }
}

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
        arkret_wire::error_codes::ErrorCode::METHOD_NOT_ALLOWED,
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
    let request_id = Uuid::new_v4().to_string();
    span.record("request_id", tracing::field::display(&request_id));

    let body = match req.payload_with_max_size(MAX_REQUEST_SIZE).await {
        Ok(bytes) => bytes.to_vec(),
        Err(ParseError::PayloadTooLarge) => {
            finish_error(
                res,
                StatusCode::PAYLOAD_TOO_LARGE,
                arkret_wire::error_codes::ErrorCode::PAYLOAD_TOO_LARGE,
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
                arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
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
            span.record("caller", tracing::field::display(&caller.origin_id));
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

    let request =
        match serde_json::from_slice::<arkret_models_integration::PushNotifyRequestBody>(&body) {
            Ok(request) => request,
            Err(error) => {
                tracing::warn!(error = %error, "expected Arkret push notify request body");
                finish_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
                    "expected Arkret push notify request body",
                    None,
                    Some(&request_id),
                    started,
                );
                return;
            }
        };
    // `push-notifications.md` §5.1: `operation_id` is determined by the URL path
    // (operationId `ak.edge.push.command.notify.v1`) and is no longer a body
    // field, so there is nothing to validate here.
    if let Err(error) = validate_origin_id(req, &caller, state.notify_auth.enabled()) {
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
        validate_destination_id(req, &state.notify_auth, state.notify_auth.enabled())
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
    if let Err(message) = validate_push_notify_contract_shape(&request) {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
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
    match request.reason_code.as_ref().map(|reason| reason.as_str()) {
        None => {}
        Some(value) if value == HISTORICAL_ONLY_REASON => {
            tracing::info!(
                request_id = %request_id,
                "answering 200 no-fanout ack for reason_code=historical_only"
            );
            let response = no_fanout_response(&request_id, &request.notification);
            finish_standard_notify_json(res, StatusCode::OK, &response, started);
            return;
        }
        Some(_) => {
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
                "reason_code is only valid as `historical_only` on /push/notify",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    }
    // Phase P2 (AKP-0008 / AKP-0009) — route Personal Agent event kinds.
    //
    // The SDK exposes seven new `ak.agent.*` kinds. Floria does not
    // surface any of them onto user-device push by default:
    //
    //   * `ak.agent.{pause, resume, deactivate}` — durable lifecycle. Silently consumed: 200 OK +
    //     zero fanout. Current lifecycle and participation admission are evaluated by the upstream
    //     Sync / notification service before it constructs this closed push envelope.
    //   * `ak.agent.{draft.propose, action_request, action_approve, action_reject}` —
    //     actor-private. Dropped: 200 OK + zero fanout. A future opt-in subscription gate may
    //     upgrade specific kinds onto a dedicated agent-runtime endpoint, but until that mechanism
    //     exists the default is drop.
    //
    // Either case answers 200 so the caller's pipeline advances, with
    // one accepted gateway outcome per input device and no provider fanout.
    if let Some(kind) = request.event_kind.as_deref()
        && let Some(routing) = classify_agent_event_kind(kind.trim())
    {
        match routing {
            AgentEventRouting::DurableLifecycle => {
                tracing::info!(
                    request_id = %request_id,
                    event_kind = %kind,
                    "answering 200 no-fanout ack: durable agent lifecycle \
                     event silently consumed (current lifecycle and participation \
                     admission remain upstream)"
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
        let response = no_fanout_response(&request_id, &request.notification);
        finish_standard_notify_json(res, StatusCode::OK, &response, started);
        return;
    }
    // Any other `event_kind` string falls through — floria does not
    // gate non-agent kinds at this layer.
    // Round 4 — route `ak.audit.policy_access{access_kind=
    // e2ee_late_recovery}` to the audit pipeline, NOT to push. floria
    // writes the audit event first, then acks 200 so the caller's
    // pipeline advances. It does not do push fanout for this shape.
    if let Some(audit_envelope) = request.audit_envelope.as_ref() {
        let access_kind = audit_envelope.access_kind.trim();
        if access_kind.is_empty() {
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
                "audit_envelope.access_kind must be a non-empty string",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
        let late_recovery_original_event_id = optional_owned_string(
            audit_envelope
                .late_recovery_original_event_id
                .as_ref()
                .map(arkret_wire::EventId::as_str),
        );
        if access_kind == "e2ee_late_recovery" && late_recovery_original_event_id.is_none() {
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
                "audit_envelope.late_recovery_original_event_id is required for e2ee_late_recovery",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
        let audit_event = AuditEvent::PolicyAccess {
            request_id: request_id.clone(),
            origin_id: caller.origin_id.clone(),
            destination_id: request_destination_id(req),
            access_kind: access_kind.to_owned(),
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
                arkret_wire::error_codes::ErrorCode::TEMPORARILY_UNAVAILABLE,
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
        let response = no_fanout_response(&request_id, &request.notification);
        finish_standard_notify_json(res, StatusCode::OK, &response, started);
        return;
    }
    let idempotency_key = match resolve_idempotency_key(req) {
        Ok(idempotency_key) => idempotency_key,
        Err(message) => {
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
                &message,
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };

    let notification = request.notification;

    match validate_notification_contract(&notification, &caller) {
        Ok(()) => {}
        // T4.3 — blind profile + plaintext metadata is a precondition
        // violation, not an authorization failure: the caller could
        // still have the right credentials, the request just can't
        // be carried by the blind profile they're scoped to.
        Err(message)
            if message.starts_with(BLIND_PROFILE_PLAINTEXT_REASON)
                || message.starts_with(VISIBLE_DEVICE_OPT_IN_REASON) =>
        {
            finish_error(
                res,
                StatusCode::PRECONDITION_FAILED,
                arkret_wire::error_codes::ErrorCode::FAILED_PRECONDITION,
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
                arkret_wire::error_codes::ErrorCode::CAPABILITY_DENIED,
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
                arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
                &message,
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    }

    if let Err(message) = validate_plaintext_identity_metadata(&notification, &caller) {
        // T4.3 — same reasoning: surface `failed_precondition` when
        // the failure is "wrong profile", and `capability_denied`
        // when the caller lacks the credential entirely.
        let (status, code) = if message.starts_with(BLIND_PROFILE_PLAINTEXT_REASON) {
            (
                StatusCode::PRECONDITION_FAILED,
                arkret_wire::error_codes::ErrorCode::FAILED_PRECONDITION,
            )
        } else {
            (
                StatusCode::FORBIDDEN,
                arkret_wire::error_codes::ErrorCode::CAPABILITY_DENIED,
            )
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
                arkret_wire::error_codes::ErrorCode::DUPLICATE_CONFLICT,
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
            arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
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
            let outcomes = notification
                .devices
                .iter()
                .map(|device| {
                    PushNotifyDeviceOutcome::rejected(
                        device.device_id.clone(),
                        PushNotifyReasonCode::RateLimited,
                        Some(duration_millis(rejection.retry_after)),
                    )
                })
                .collect();
            let response = NotifyDispatchResult::new(
                request_id.clone(),
                push_target_id(&notification),
                outcomes,
            );
            cache_success_response(&state, &dedup_key, &request_fingerprint, &response).await;
            finish_standard_notify_json(res, StatusCode::OK, &response, started);
            return;
        }
    }

    let context = NotificationContext {
        request_id: request_id.clone(),
        start_time: Instant::now(),
        allow_plaintext_metadata: caller.allow_plaintext_metadata,
    };

    let mut rejected = Vec::new();
    let mut outcomes = Vec::with_capacity(notification.devices.len());
    let mut delivered_now = 0usize;
    let mut skipped_delivered = 0usize;
    let mut delivery_receipts = Vec::new();
    let mut taken_over_this_request = HashSet::new();
    let mut first_remote_error: Option<String> = None;
    let mut first_temporary_error: Option<(String, Option<Duration>)> = None;
    let mut first_internal_error: Option<String> = None;
    let mut provider_timing_bucket_applied = false;
    let provider_timing_bucket = provider_timing_bucket_for_notification(&notification);
    for device in &notification.devices {
        let app_id = device.app_id().unwrap_or_default();
        let push_key = device.push_key().unwrap_or_default();
        if app_id.is_empty() || push_key.is_empty() {
            tracing::warn!(
                request_id = %context.request_id,
                app_id,
                push_key_hash = %device.redacted_push_key(),
                "rejecting device with empty app_id or push_key"
            );
            rejected.push(rejected_device(device, device.push_key()));
            outcomes.push(PushNotifyDeviceOutcome::rejected(
                device.device_id.clone(),
                PushNotifyReasonCode::PushTokenInvalid,
                None,
            ));
            delivery_receipts.push(delivery_receipt(
                None,
                push_key,
                "rejected",
                None,
                &context.request_id,
            ));
            continue;
        }

        // Round 4 (spec a77b995) — `mention_redirect_target_route_tokens`
        // plaintext routing gate. When soland set a non-empty allow-list
        // the device's `target_route_token` MUST appear in it, otherwise
        // the device is fail-closed: no provider dispatch, no body
        // decryption is attempted, and the rejection is recorded with
        // the wire-safe `mention_redirect_not_targeted` reason so the
        // operator can tell why the device was skipped. Devices with
        // no `target_route_token` cannot prove their inclusion in the
        // allow-list — same outcome (fail-closed).
        if !notification
            .mention_redirect_target_route_tokens()
            .is_empty()
        {
            let allowed = device.target_route_token().is_some_and(|route_token| {
                notification
                    .mention_redirect_target_route_tokens()
                    .iter()
                    .any(|allowed| allowed.as_str() == route_token)
            });
            if !allowed {
                tracing::info!(
                    request_id = %context.request_id,
                    app_id,
                    push_key_hash = %device.redacted_push_key(),
                    "fail-closed: device.target_route_token not in mention_redirect_target_route_tokens"
                );
                rejected.push(
                    rejected_device(device, device.push_key())
                        .with_reason_code(Some(MENTION_REDIRECT_NOT_TARGETED_REASON)),
                );
                outcomes.push(PushNotifyDeviceOutcome::rejected(
                    device.device_id.clone(),
                    PushNotifyReasonCode::DeliveryBindingStale,
                    None,
                ));
                delivery_receipts.push(delivery_receipt(
                    None,
                    push_key,
                    "rejected",
                    None,
                    &context.request_id,
                ));
                continue;
            }
        }

        app_metrics::device_push_received();
        let pushkins = state.registry.find_pushkins(app_id);
        match pushkins.as_slice() {
            [] => {
                tracing::warn!(request_id = %context.request_id, app_id, push_key_hash = %device.redacted_push_key(), "unknown app id");
                rejected.push(rejected_device(device, device.push_key()));
                outcomes.push(PushNotifyDeviceOutcome::rejected(
                    device.device_id.clone(),
                    PushNotifyReasonCode::UnsupportedProfile,
                    None,
                ));
                delivery_receipts.push(delivery_receipt(
                    None,
                    push_key,
                    "rejected",
                    None,
                    &context.request_id,
                ));
                continue;
            }
            [pushkin] => {
                let delivered_before = if taken_over_this_request
                    .contains(&(app_id.to_owned(), push_key.to_owned()))
                {
                    false
                } else if let Some(deduplicator) = state.notify_deduplicator.as_ref() {
                    deduplicator
                        .contains_delivered_device_async(&dedup_key, app_id, push_key)
                        .await
                } else {
                    false
                };
                if delivered_before {
                    skipped_delivered += 1;
                    outcomes.push(PushNotifyDeviceOutcome::duplicate(device.device_id.clone()));
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
                let breaker_key = circuit_breaker_key(pushkin.name(), &notification);
                let (breaker_scope_kind, breaker_scope_id) = circuit_breaker_scope(&notification);
                if let Some(breaker) = state.circuit_breaker.as_ref()
                    && breaker.is_open(&breaker_key)
                {
                    app_metrics::set_circuit_breaker_state(
                        pushkin.name(),
                        breaker_scope_kind,
                        breaker_scope_id,
                        2,
                    );
                    tracing::warn!(
                        request_id = %context.request_id,
                        app_id,
                        pushkin = %pushkin.name(),
                        realm_id = ?notification.realm_id(),
                        has_scope_route_token = notification.scope_route_token().is_some(),
                        "short-circuiting dispatch because circuit breaker is open"
                    );
                    for target in &dispatch_targets {
                        delivery_receipts.push(delivery_receipt(
                            Some(pushkin.name()),
                            &target.push_key,
                            "retryable",
                            Some(CIRCUIT_BREAKER_RETRY_AFTER),
                            &context.request_id,
                        ));
                    }
                    first_temporary_error.get_or_insert_with(|| {
                        (
                            "push provider circuit breaker is open".to_owned(),
                            Some(CIRCUIT_BREAKER_RETRY_AFTER),
                        )
                    });
                    outcomes.push(PushNotifyDeviceOutcome::rejected(
                        device.device_id.clone(),
                        PushNotifyReasonCode::PushGatewayUnreachable,
                        Some(duration_millis(CIRCUIT_BREAKER_RETRY_AFTER)),
                    ));
                    app_metrics::notify_delivery_outcome_by_app(app_id, "retryable", 1);
                    continue;
                }
                if !provider_timing_bucket_applied {
                    wait_for_provider_timing_bucket(&context.request_id, provider_timing_bucket)
                        .await;
                    provider_timing_bucket_applied = true;
                }
                let dispatch_started = Instant::now();
                let dispatch_result = pushkin
                    .dispatch_notification(&notification, device, &context)
                    .await;
                if let Some(breaker) = state.circuit_breaker.as_ref() {
                    match &dispatch_result {
                        Ok(_) => {
                            breaker.record_success(&breaker_key);
                            app_metrics::set_circuit_breaker_state(
                                pushkin.name(),
                                breaker_scope_kind,
                                breaker_scope_id,
                                0,
                            );
                        }
                        Err(error) => {
                            let opened = breaker.record_failure(&breaker_key);
                            app_metrics::set_circuit_breaker_state(
                                pushkin.name(),
                                breaker_scope_kind,
                                breaker_scope_id,
                                if opened { 2 } else { 0 },
                            );
                            if opened {
                                tracing::warn!(
                                    error = %error,
                                    request_id = %context.request_id,
                                    app_id,
                                    pushkin = %pushkin.name(),
                                    realm_id = ?notification.realm_id(),
                                    has_scope_route_token = notification.scope_route_token().is_some(),
                                    "opened push provider circuit breaker"
                                );
                            }
                        }
                    }
                }
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
                            .filter(|target| !rejected_set.contains(target.push_key.as_str()))
                            .cloned()
                            .collect::<Vec<_>>();
                        if delivered_targets.is_empty() && !pushkin_rejected.is_empty() {
                            outcomes.push(PushNotifyDeviceOutcome::rejected(
                                device.device_id.clone(),
                                PushNotifyReasonCode::PushTokenUnknown,
                                None,
                            ));
                        } else {
                            outcomes
                                .push(PushNotifyDeviceOutcome::accepted(device.device_id.clone()));
                        }
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
                            mark_delivered_devices(&state, &dedup_key, delivered_targets).await;
                            taken_over_this_request
                                .insert((app_id.to_owned(), push_key.to_owned()));
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
                            app_id,
                            push_key_hash = %device.redacted_push_key(),
                            "temporary dispatch failure"
                        );
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
                            )
                            .await;
                        }
                        if state.notify_retry_queue.is_some() {
                            outcomes
                                .push(PushNotifyDeviceOutcome::accepted(device.device_id.clone()));
                        } else {
                            outcomes.push(PushNotifyDeviceOutcome::rejected(
                                device.device_id.clone(),
                                PushNotifyReasonCode::PushGatewayUnreachable,
                                Some(duration_millis(
                                    retry_after.unwrap_or(CIRCUIT_BREAKER_RETRY_AFTER),
                                )),
                            ));
                        }
                        first_temporary_error
                            .get_or_insert_with(|| (error.to_string(), retry_after));
                    }
                    Err(error) if error.is_remote() => {
                        outcomes.push(PushNotifyDeviceOutcome::rejected(
                            device.device_id.clone(),
                            PushNotifyReasonCode::PushGatewayUnreachable,
                            Some(duration_millis(CIRCUIT_BREAKER_RETRY_AFTER)),
                        ));
                        tracing::warn!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id,
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
                        outcomes.push(PushNotifyDeviceOutcome::rejected(
                            device.device_id.clone(),
                            PushNotifyReasonCode::PushGatewayUnreachable,
                            Some(duration_millis(CIRCUIT_BREAKER_RETRY_AFTER)),
                        ));
                        tracing::error!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id,
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
                tracing::warn!(request_id = %context.request_id, app_id, push_key_hash = %device.redacted_push_key(), "ambiguous app id");
                rejected.push(rejected_device(device, device.push_key()));
                outcomes.push(PushNotifyDeviceOutcome::rejected(
                    device.device_id.clone(),
                    PushNotifyReasonCode::UnsupportedProfile,
                    None,
                ));
                delivery_receipts.push(delivery_receipt(
                    None,
                    push_key,
                    "rejected",
                    None,
                    &context.request_id,
                ));
            }
        }
    }

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
        let response = NotifyDispatchResult::new(
            context.request_id.clone(),
            push_target_id(&notification),
            outcomes,
        );
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
        cache_success_response(&state, &dedup_key, &request_fingerprint, &response).await;
        record_delivery_receipt_outcomes(&delivery_receipts, response.accepted(), rejected.len());
        record_notify_delivery_by_scope(
            &notification,
            &delivery_receipts,
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

    let response = NotifyDispatchResult::new(
        context.request_id.clone(),
        push_target_id(&notification),
        outcomes,
    );
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
    cache_success_response(&state, &dedup_key, &request_fingerprint, &response).await;
    record_delivery_receipt_outcomes(&delivery_receipts, response.accepted(), rejected.len());
    record_notify_delivery_by_scope(
        &notification,
        &delivery_receipts,
        state.metrics_detailed_circle_labels,
    );
    finish_standard_notify_json(res, StatusCode::OK, &response, started);
}
