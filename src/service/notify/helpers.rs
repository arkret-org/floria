use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Map, Value};

use super::super::metrics::{finish_error, finish_json};
use crate::audit::AuditEvent;
use crate::auth::{
    AuthenticatedNotifyCaller, DESTINATION_SERVICE_DID_HEADER, ORIGIN_SERVICE_DID_HEADER,
};
use crate::dedup::request_hash;
use crate::models::{
    DeliveryReceipt, DeviceExt, FloriaPushNotifyOutcome as PushNotifyOutcome, NotificationExt,
    ProviderRetry, PushNotification, RejectedDevice, redact_push_token,
};
use crate::rate_limit::NotifyRateLimitCheck;
use crate::{AppState, metrics as app_metrics};

pub(super) fn parse_optional_idempotency_key(
    value: Option<&str>,
    source: &str,
) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{source} must not be empty"));
    }
    Ok(Some(value.to_owned()))
}

pub(super) fn resolve_idempotency_key(req: &Request) -> Result<Option<String>, String> {
    // SPEC-CR-016: the idempotency key rides the `Idempotency-Key`
    // transport header only; it is no longer accepted as a body field.
    parse_optional_idempotency_key(
        req.header::<String>("idempotency-key").as_deref(),
        "Idempotency-Key header",
    )
}

pub(super) fn dedup_provider_retries(provider_retries: &mut Vec<ProviderRetry>) {
    provider_retries.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then(left.retry_after_ms.cmp(&right.retry_after_ms))
    });
    provider_retries.dedup();
}

pub(super) fn notify_rate_limit_checks(
    req: &Request,
    state: &AppState,
    notification: &PushNotification,
) -> Vec<NotifyRateLimitCheck> {
    let Some(rate_limiter) = state.notify_rate_limiter.as_ref() else {
        return vec![];
    };
    let config = rate_limiter.config();
    let mut checks = Vec::new();

    if let Some(limit) = config.per_origin_service.filter(|limit| *limit > 0) {
        let subject = req
            .header::<String>(ORIGIN_SERVICE_DID_HEADER)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "<missing>".to_owned());
        checks.push(NotifyRateLimitCheck {
            scope: "origin_service",
            subject,
            limit,
            units: 1,
        });
    }

    if let Some(limit) = config.per_app_id.filter(|limit| *limit > 0) {
        let app_ids = notification
            .devices
            .iter()
            .filter_map(DeviceExt::app_id)
            .collect::<HashSet<_>>();
        checks.extend(app_ids.into_iter().map(|app_id| NotifyRateLimitCheck {
            scope: "app_id",
            subject: app_id.to_owned(),
            limit,
            units: 1,
        }));
    }

    if let Some(limit) = config.per_push_key_hash.filter(|limit| *limit > 0) {
        let push_key_hashes = notification
            .devices
            .iter()
            .map(|device| device.redacted_push_key())
            .collect::<HashSet<_>>();
        checks.extend(
            push_key_hashes
                .into_iter()
                .map(|push_key_hash| NotifyRateLimitCheck {
                    scope: "push_key_hash",
                    subject: push_key_hash,
                    limit,
                    units: 1,
                }),
        );
    }

    if let Some(limit) = config.per_endpoint.filter(|limit| *limit > 0) {
        checks.push(NotifyRateLimitCheck {
            scope: "endpoint",
            subject: req.uri().path().to_owned(),
            limit,
            units: 1,
        });
    }

    if let Some(limit) = config.per_provider.filter(|limit| *limit > 0) {
        let providers = notification
            .devices
            .iter()
            .flat_map(|device| {
                device
                    .app_id()
                    .into_iter()
                    .flat_map(|app_id| state.registry.find_pushkins(app_id))
                    .map(|pushkin| pushkin.name().to_owned())
            })
            .collect::<HashSet<_>>();
        checks.extend(providers.into_iter().map(|provider| NotifyRateLimitCheck {
            scope: "provider",
            subject: provider,
            limit,
            units: 1,
        }));
    }

    checks
}

pub(super) fn optional_owned_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn request_destination_service_did(req: &Request) -> Option<String> {
    // SPEC-CR-016: destination service DID rides the
    // `Destination-Service-DID` transport header only.
    req.header::<String>(DESTINATION_SERVICE_DID_HEADER)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn audit_event_type(event: &AuditEvent) -> &'static str {
    match event {
        AuditEvent::PolicyAccess { .. } => "policy_access",
        AuditEvent::RejectedDevices { .. } => "rejected_devices",
    }
}

pub(super) async fn record_required_audit_event(
    state: &Arc<AppState>,
    event: &AuditEvent,
) -> Result<(), String> {
    let event_type = audit_event_type(event);
    let Some(sink) = state.audit_sink.as_ref() else {
        app_metrics::audit_divert(event_type, "unconfigured");
        return Err("audit sink is not configured".to_owned());
    };
    match sink.record(event).await {
        Ok(()) => {
            app_metrics::audit_divert(event_type, "success");
            Ok(())
        }
        Err(error) => {
            app_metrics::audit_divert(event_type, "failure");
            Err(error.to_string())
        }
    }
}

async fn record_rejected_devices_audit(
    state: &Arc<AppState>,
    request_id: &str,
    caller: &AuthenticatedNotifyCaller,
    _notification: &PushNotification,
    rejected: &[RejectedDevice],
) -> Result<(), String> {
    if rejected.is_empty() {
        return Ok(());
    }
    let Some(sink) = state.audit_sink.as_ref() else {
        app_metrics::audit_divert("rejected_devices", "unconfigured");
        return Ok(());
    };
    let event = AuditEvent::RejectedDevices {
        request_id: request_id.to_owned(),
        origin_service_did: caller.origin_service_did.clone(),
        devices: rejected.iter().map(rejected_device_for_audit).collect(),
    };
    match sink.record(&event).await {
        Ok(()) => {
            app_metrics::audit_divert("rejected_devices", "success");
            for device in rejected {
                app_metrics::audit_rejected_devices(device.reason_code.as_deref(), 1);
            }
            Ok(())
        }
        Err(error) => {
            app_metrics::audit_divert("rejected_devices", "failure");
            Err(error.to_string())
        }
    }
}

fn rejected_device_for_audit(device: &RejectedDevice) -> RejectedDevice {
    RejectedDevice {
        push_key: device.push_key.clone(),
        app_id: device.app_id.as_deref().map(redact_app_id_for_audit),
        reason_code: device.reason_code.clone(),
    }
}

fn redact_app_id_for_audit(app_id: &str) -> String {
    redact_push_token(app_id).replacen("pkh_", "apph_", 1)
}

pub(super) async fn record_rejected_devices_audit_or_finish(
    state: &Arc<AppState>,
    request_id: &str,
    caller: &AuthenticatedNotifyCaller,
    notification: &PushNotification,
    rejected: &[RejectedDevice],
    res: &mut Response,
    started: Instant,
) -> bool {
    if let Err(message) =
        record_rejected_devices_audit(state, request_id, caller, notification, rejected).await
    {
        tracing::error!(
            request_id = %request_id,
            error = %message,
            rejected = rejected.len(),
            "failed to write rejected-device audit event"
        );
        finish_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            cokret::error::ERROR_CODE_TEMPORARILY_UNAVAILABLE,
            &message,
            None,
            Some(request_id),
            started,
        );
        return false;
    }
    true
}

pub(super) fn finish_standard_notify_json(
    res: &mut Response,
    status: StatusCode,
    response: &PushNotifyOutcome,
    started: Instant,
) {
    finish_json(res, status, standard_notify_outcome(response), started);
}

fn standard_notify_outcome(response: &PushNotifyOutcome) -> cokret::PushNotifyOutcome {
    cokret::PushNotifyOutcome {
        rejected: response
            .rejected
            .iter()
            .filter_map(|device| serde_json::to_value(device).ok())
            .collect(),
    }
}

pub(super) async fn cache_success_response(
    state: &Arc<AppState>,
    key: &str,
    request_fingerprint: &str,
    response: &PushNotifyOutcome,
) {
    if let Some(deduplicator) = state.notify_deduplicator.as_ref() {
        deduplicator
            .insert_success_async(key, request_fingerprint, response.clone())
            .await;
    }
}

pub(super) async fn mark_delivered_devices(
    state: &Arc<AppState>,
    notification_key: &str,
    targets: Vec<crate::pushkin::DispatchTarget>,
) {
    if let Some(deduplicator) = state.notify_deduplicator.as_ref() {
        for target in targets {
            deduplicator
                .mark_delivered_device_async(notification_key, &target.app_id, &target.push_key)
                .await;
        }
    }
}

pub(super) fn rejected_device(
    device: &crate::models::Device,
    push_key: Option<&str>,
) -> RejectedDevice {
    RejectedDevice::new(
        device.app_id(),
        push_key.or_else(|| device.push_key()).unwrap_or_default(),
    )
}

pub(super) fn delivery_receipt(
    provider: Option<&str>,
    push_key: &str,
    status: &str,
    retry_after: Option<Duration>,
    request_id: &str,
) -> DeliveryReceipt {
    DeliveryReceipt {
        provider: provider.map(ToOwned::to_owned),
        provider_message_id: None,
        push_key_hash: Some(redact_push_token(push_key)),
        status: Some(status.to_owned()),
        retry_after_ms: retry_after.map(|value| value.as_millis().min(u64::MAX as u128) as u64),
        timestamp: Some(unix_timestamp_string()),
        request_id: Some(request_id.to_owned()),
    }
}

fn unix_timestamp_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

pub(super) fn idempotency_cache_key(idempotency_key: &str) -> String {
    request_hash(format!("idempotency-key\0{idempotency_key}").as_bytes())
}

pub(super) fn normalized_notify_dedup_key(notification: &PushNotification) -> Option<String> {
    let mut normalized = Map::new();

    if let Some(value) = notification.strand_title() {
        normalized.insert("strand_title".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.realm_title() {
        normalized.insert("realm_title".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.priority.as_ref() {
        normalized.insert("priority".to_owned(), Value::String(value.clone()));
    }
    if let Some(value) = notification.membership.as_ref() {
        normalized.insert("membership".to_owned(), Value::String(value.clone()));
    }
    if let Some(value) = notification.sender_actor_display_name.as_ref() {
        normalized.insert(
            "sender_actor_display_name".to_owned(),
            Value::String(value.clone()),
        );
    }
    if let Some(value) = notification.event_id.as_ref() {
        normalized.insert(
            "event_id".to_owned(),
            Value::String(value.as_str().to_owned()),
        );
    }
    if let Some(value) = notification.message_id() {
        normalized.insert("message_id".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.strand_id() {
        normalized.insert("strand_id".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.realm_id() {
        normalized.insert("realm_id".to_owned(), Value::String(value.to_owned()));
    }
    // CKP-0007 — `circle_id` and `effective_scope` are routing-affecting
    // (two pushes for the same Strand in different Circles must not
    // collide in the dedup cache).
    if let Some(value) = notification.realm_route_token() {
        normalized.insert(
            "realm_route_token".to_owned(),
            Value::String(value.to_owned()),
        );
    }
    if let Some(value) = notification.scope_route_token() {
        normalized.insert(
            "scope_route_token".to_owned(),
            Value::String(value.to_owned()),
        );
    }
    if let Some(value) = notification.delivery_binding_frontier_token() {
        normalized.insert(
            "delivery_binding_frontier_token".to_owned(),
            Value::String(value.to_owned()),
        );
    }
    if let Some(value) = notification.user_is_target {
        normalized.insert("user_is_target".to_owned(), Value::Bool(value));
    }
    if let Some(value) = notification.push_target_id.as_ref() {
        normalized.insert("push_target_id".to_owned(), Value::String(value.clone()));
    }
    if let Some(value) = notification.wakeup_kind() {
        normalized.insert("wakeup_kind".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.push_hint.as_ref() {
        normalized.insert("push_hint".to_owned(), Value::String(value.clone()));
    }
    // Round 4 (spec a77b995) — `mention_redirect_target_route_tokens` is
    // routing-affecting (two requests with different allow-lists must
    // not collide in the dedup cache). Sort canonically so the
    // fingerprint is order-independent.
    if !notification
        .mention_redirect_target_route_tokens()
        .is_empty()
    {
        let mut sorted = notification
            .mention_redirect_target_route_tokens()
            .iter()
            .map(|token| token.trim().to_owned())
            .filter(|token| !token.is_empty())
            .collect::<Vec<_>>();
        sorted.sort();
        sorted.dedup();
        normalized.insert(
            "mention_redirect_target_route_tokens".to_owned(),
            Value::Array(sorted.into_iter().map(Value::String).collect()),
        );
    }
    normalized.insert(
        "counts".to_owned(),
        serde_json::to_value(notification.counts.clone().unwrap_or_default()).ok()?,
    );

    let mut devices = notification
        .devices
        .iter()
        .map(|device| {
            let mut normalized = Map::new();
            normalized.insert(
                "app_id".to_owned(),
                Value::String(device.app_id().unwrap_or_default().to_owned()),
            );
            normalized.insert(
                "push_key".to_owned(),
                Value::String(device.push_key().unwrap_or_default().to_owned()),
            );
            // Round 4 — `target_route_token` participates in the routing
            // decision, so it must be part of the canonical fingerprint.
            if let Some(route_token) = device.target_route_token() {
                normalized.insert(
                    "target_route_token".to_owned(),
                    Value::String(route_token.to_owned()),
                );
            }
            Some(Value::Object(normalized))
        })
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    devices.sort_by_cached_key(|value| {
        cokret::canonical::canonical_json_string(value).unwrap_or_default()
    });
    devices.dedup();
    normalized.insert("devices".to_owned(), Value::Array(devices));

    // Canonicalize the whole fingerprint tree via the SDK so the
    // blind-wakeup digest is byte-identical to every other cokret
    // service (soland/yougen/chime). `canonical_json_bytes` recursively
    // sorts object keys and emits the v1 canonical encoding, replacing
    // floria's former local `canonical_json_value` helper.
    cokret::canonical::canonical_json_bytes(&Value::Object(normalized))
        .ok()
        .map(|bytes| request_hash(&bytes))
}

pub(super) async fn enqueue_retry(
    state: &Arc<AppState>,
    request_id: &str,
    pushkin: &str,
    app_id: &str,
    push_key: &str,
    retry_after: Option<Duration>,
    error: &crate::error::DispatchError,
) {
    let Some(queue) = state.notify_retry_queue.as_ref() else {
        return;
    };
    let backoff = retry_after.unwrap_or(queue.config().default_backoff);
    let envelope = crate::retry_queue::RetryEnvelope::new(
        request_id,
        pushkin,
        app_id,
        push_key,
        backoff,
        error.to_string(),
    );
    queue.enqueue_async(envelope).await;
    app_metrics::notify_retry_enqueued(pushkin);
}
