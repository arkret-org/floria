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
use super::metrics::finish_error;
use crate::audit::AuditEvent;
use crate::auth::authenticate_notify_request;
use crate::models::{DeviceExt, NotificationContext, NotificationExt, NotifyDispatchResult};
use crate::{AppState, metrics as app_metrics};

mod dispatch;
mod helpers;
mod response;
mod validation;

#[cfg(test)]
mod tests;

use dispatch::dispatch_notification_devices;
pub(super) use helpers::idempotency_cache_key;
use helpers::{
    cache_success_response, delivery_receipt, enqueue_retry, finish_standard_notify_json,
    mark_delivered_devices, normalized_notify_dedup_key, notify_rate_limit_checks,
    optional_owned_string, record_required_audit_event, rejected_device, resolve_idempotency_key,
};
use response::finish_dispatch;
use validation::{
    BLIND_PROFILE_PLAINTEXT_REASON, VISIBLE_DEVICE_OPT_IN_REASON, validate_notification_contract,
    validate_plaintext_identity_metadata,
};

/// Round 4 — `reason_code=historical_only` short-circuits soland's
/// diagnostic replay. floria MUST NOT fan the request out a second
/// time; it answers 200 with one accepted gateway outcome per input
/// device and no provider retries. The wire constant comes from the SDK.
const HISTORICAL_ONLY_REASON: &str = arkret_wire::ErrorCode::HISTORICAL_ONLY;

const CIRCUIT_BREAKER_RETRY_AFTER: Duration = Duration::from_secs(30);

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

fn no_fanout_outcomes(notification: &PushNotificationEnvelope) -> Vec<PushNotifyDeviceOutcome> {
    notification
        .devices
        .iter()
        .map(|device| PushNotifyDeviceOutcome::duplicate(device.device_id.clone()))
        .collect()
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().clamp(1, u64::MAX as u128) as u64
}

fn no_fanout_response(
    request_id: &str,
    notification: &PushNotificationEnvelope,
) -> NotifyDispatchResult {
    let outcomes = no_fanout_outcomes(notification);
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
            span.record(
                "caller",
                tracing::field::display(
                    caller
                        .origin_id
                        .as_ref()
                        .map(arkret_wire::DidCoreId::as_str)
                        .unwrap_or("anonymous"),
                ),
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

    let Some(source) = caller.origin_id.as_ref() else {
        finish_error(
            res,
            StatusCode::UNAUTHORIZED,
            arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
            "push registration lookup requires an authenticated source service",
            None,
            Some(&request_id),
            started,
        );
        return;
    };
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
    // Route registered Personal Agent event kinds without provider fanout.
    //
    // The SDK classifies Agent event kinds. Floria does not
    // surface any of them onto user-device push by default:
    //
    //   * `ak.self.agent.{pause, resume, deactivate}` — durable lifecycle. Silently consumed: 200
    //     OK + zero fanout. Current lifecycle and participation admission are evaluated by the
    //     upstream Sync / notification service before it constructs this closed push envelope.
    //   * `ak.agent.{draft.propose, action_request, action_approve, action_reject}` —
    //     actor-private. Dropped: 200 OK + zero fanout. A future opt-in subscription gate may
    //     upgrade specific kinds onto a dedicated agent-runtime endpoint, but until that mechanism
    //     exists the default is drop.
    //
    // Either case answers 200 so the caller's pipeline advances, with
    // one duplicate gateway outcome per input device and no new route takeover.
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
            destination_id: caller.destination_id.clone(),
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
    let notification = request.notification;
    let mut registrations = Vec::with_capacity(notification.devices.len());
    for device in &notification.devices {
        match state
            .registrations
            .resolve(
                source,
                &push_target_id(&notification),
                &device.device_id,
                &state.public_base_url,
            )
            .await
        {
            Ok(registration) => registrations.push(registration),
            Err(error) => {
                tracing::error!(%error, "durable registration lookup failed");
                finish_error(
                    res,
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::error_codes::ErrorCode::TEMPORARILY_UNAVAILABLE,
                    "push registration store unavailable",
                    None,
                    Some(&request_id),
                    started,
                );
                return;
            }
        }
    }

    match validate_notification_contract(&notification, &caller, &registrations) {
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
    let request_key = idempotency_cache_key(&idempotency_key);
    let dedup_key = format!("{}:{}", source, request_key);
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
            && registrations.iter().all(Option::is_some)
        {
            app_metrics::notify_dedup_lookup("hit");
            app_metrics::notify_request_cache_hit();
            tracing::info!(
                request_id = %request_id,
                ttl_secs = deduplicator.ttl().as_secs(),
                idempotency_key = %idempotency_key,
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
        let checks =
            notify_rate_limit_checks(req, &state, &registrations, caller.origin_id.as_ref());
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

    let summary = dispatch_notification_devices(
        &state,
        &notification,
        &registrations,
        source,
        &context,
        &dedup_key,
    )
    .await;

    finish_dispatch(
        &state,
        &caller,
        &context.request_id,
        &notification,
        &dedup_key,
        &request_fingerprint,
        summary,
        res,
        started,
    )
    .await;
}
