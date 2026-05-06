use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use salvo::http::ParseError;
use salvo::http::StatusCode;
use salvo::http::header::{HeaderName, HeaderValue};
use salvo::prelude::*;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::AppState;
use crate::auth::{
    AuthFailure, AuthenticatedNotifyCaller, DESTINATION_SERVICE_DID_HEADER,
    ORIGIN_SERVICE_DID_HEADER, authenticate_notify_request,
};
use crate::config::NotifyAuthConfig;
use crate::dedup::request_hash;
use crate::metrics as app_metrics;
use crate::models::{
    DeliveryReceipt, Notification, NotificationContext, NotifyResponse, ProviderRetry,
    RejectedDevice, redact_push_token, reject_legacy_notify_contract_fields,
};
use crate::rate_limit::NotifyRateLimitCheck;

use super::metrics::{
    finish_error, finish_json, record_delivery_receipt_outcomes, record_notify_delivery_outcomes,
};
use super::{
    ACTIVE_EVENT_ID_PREFIX, ACTIVE_FLOW_ID_PREFIX, ACTIVE_MESSAGE_ID_PREFIX,
    ACTIVE_SPACE_ID_PREFIX, MAX_REQUEST_SIZE, NOTIFY_OPERATION_ID,
};

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

fn parse_optional_idempotency_key(
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

fn resolve_idempotency_key(req: &Request, raw: &Value) -> Result<Option<String>, String> {
    let header = parse_optional_idempotency_key(
        req.header::<String>("idempotency-key").as_deref(),
        "Idempotency-Key header",
    )?;
    let body = match raw.get("idempotency_key") {
        None => Ok(None),
        Some(Value::String(value)) => {
            parse_optional_idempotency_key(Some(value), "idempotency_key")
        }
        Some(_) => Err("idempotency_key must be a string".to_owned()),
    }?;

    if let (Some(header), Some(body)) = (header.as_deref(), body.as_deref())
        && header != body
    {
        return Err("Idempotency-Key header does not match body idempotency_key".to_owned());
    }

    Ok(header.or(body))
}

fn validate_notify_operation_id(raw: &Value) -> Result<(), String> {
    let Some(value) = raw.get("operation_id") else {
        return Ok(());
    };
    let Value::String(value) = value else {
        return Err("operation_id must be a string".to_owned());
    };
    if value.trim() == NOTIFY_OPERATION_ID {
        return Ok(());
    }
    Err(format!("operation_id must be {NOTIFY_OPERATION_ID}"))
}

fn validate_origin_service_did(
    raw: &Value,
    caller: &AuthenticatedNotifyCaller,
    auth_enabled: bool,
) -> Result<(), AuthFailure> {
    if !auth_enabled {
        return Ok(());
    }
    let Some(origin_service_did) = optional_string_field(raw, "origin_service_did")? else {
        return Err(AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: "capability_denied",
            message: "origin_service_did is required".to_owned(),
        });
    };
    if origin_service_did != caller.origin_service_did {
        return Err(AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: "capability_denied",
            message: "origin service DID does not match the authenticated caller".to_owned(),
        });
    }
    Ok(())
}

fn validate_destination_service_did(
    raw: &Value,
    req: &Request,
    auth: &NotifyAuthConfig,
    auth_enabled: bool,
) -> Result<(), AuthFailure> {
    if !auth_enabled {
        return Ok(());
    }

    let body_destination = optional_string_field(raw, "destination_service_did")?;
    let header_destination = req
        .header::<String>(DESTINATION_SERVICE_DID_HEADER)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());

    if let (Some(body_destination), Some(header_destination)) =
        (body_destination, header_destination.as_deref())
        && body_destination != header_destination
    {
        return Err(AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: "capability_denied",
            message: "destination_service_did does not match the authenticated destination"
                .to_owned(),
        });
    }

    if let Some(expected) = auth.gateway_service_did.as_deref()
        && let Some(destination) = body_destination.or(header_destination.as_deref())
        && destination != expected
    {
        return Err(AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: "capability_denied",
            message: "destination service DID does not match this gateway".to_owned(),
        });
    }

    Ok(())
}

fn optional_string_field<'a>(raw: &'a Value, field: &str) -> Result<Option<&'a str>, AuthFailure> {
    match raw.get(field) {
        Some(Value::String(value)) => Ok(Some(value.trim())),
        Some(_) => Err(AuthFailure {
            status: StatusCode::BAD_REQUEST,
            code: "schema_violation",
            message: format!("{field} must be a string"),
        }),
        None => Ok(None),
    }
}

fn validate_notify_contract_shape(raw: &Value) -> Result<(), String> {
    let Some(notification) = raw.get("notification") else {
        return Ok(());
    };
    let Some(notification) = notification.as_object() else {
        return Ok(());
    };

    reject_legacy_notify_contract_fields("notification", &Value::Object(notification.clone()))?;
    validate_active_notification_refs(notification)?;
    validate_device_contract_shape(notification.get("devices"))?;

    Ok(())
}

fn validate_device_contract_shape(devices: Option<&Value>) -> Result<(), String> {
    let Some(devices) = devices else {
        return Ok(());
    };
    let Some(devices) = devices.as_array() else {
        return Ok(());
    };

    for (index, device) in devices.iter().enumerate() {
        let path = format!("notification.devices[{index}]");
        let Some(device) = device.as_object() else {
            continue;
        };

        if let Some(data) = device.get("data") {
            let Some(data) = data.as_object() else {
                continue;
            };
            if data.contains_key("only_last_per_room") {
                return Err(format!(
                    "legacy notify contract field `{path}.data.only_last_per_room` is not supported"
                ));
            }
            if let Some(default_payload) = data.get("default_payload") {
                if !default_payload.is_object() {
                    return Err(format!("{path}.data.default_payload must be an object"));
                }
                reject_legacy_notify_contract_fields(
                    &format!("{path}.data.default_payload"),
                    default_payload,
                )?;
                validate_blind_content(&format!("{path}.data.default_payload"), default_payload)?;
            }
        }
    }

    Ok(())
}

fn validate_active_notification_refs(notification: &Map<String, Value>) -> Result<(), String> {
    validate_active_ref(
        notification.get("event_id"),
        "notification.event_id",
        ACTIVE_EVENT_ID_PREFIX,
    )?;
    validate_active_ref(
        notification.get("message_id"),
        "notification.message_id",
        ACTIVE_MESSAGE_ID_PREFIX,
    )?;
    validate_active_ref(
        notification.get("flow_id"),
        "notification.flow_id",
        ACTIVE_FLOW_ID_PREFIX,
    )?;
    validate_active_ref(
        notification.get("space_id"),
        "notification.space_id",
        ACTIVE_SPACE_ID_PREFIX,
    )?;

    let Some(value) = notification.get("type") else {
        return Ok(());
    };
    let Value::String(value) = value else {
        return Err("notification.type must be a string".to_owned());
    };
    let value = value.trim();
    if value.is_empty() {
        return Err("notification.type must not be empty".to_owned());
    }
    if !value.starts_with("cx.") {
        return Err("notification.type must use active cx.* event names".to_owned());
    }

    Ok(())
}

fn validate_active_ref(
    value: Option<&Value>,
    path: &str,
    required_prefix: &str,
) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let Value::String(value) = value else {
        return Err(format!("{path} must be a string"));
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{path} must not be empty"));
    }
    if !value.starts_with(required_prefix) {
        return Err(format!(
            "{path} must use active `{required_prefix}*` typed IDs"
        ));
    }
    Ok(())
}

fn validate_notification_contract(
    notification: &Notification,
    caller: &AuthenticatedNotifyCaller,
) -> Result<(), String> {
    if !caller.allow_plaintext_metadata
        && (notification.sender_display_name.is_some()
            || notification.flow_name.is_some()
            || notification.space_name.is_some())
    {
        return Err(
            "caller is not authorized to send sender_display_name or flow/space name metadata"
                .to_owned(),
        );
    }

    if let Some(push_hint) = notification.push_hint.as_deref() {
        validate_push_hint(push_hint)?;
    }

    let Some(content) = notification.content.as_ref() else {
        return Ok(());
    };

    validate_blind_content("content", &Value::Object(content.clone()))?;

    Ok(())
}

fn validate_plaintext_identity_metadata(
    notification: &Map<String, Value>,
    caller: &AuthenticatedNotifyCaller,
) -> Result<(), String> {
    if caller.allow_plaintext_metadata {
        return Ok(());
    }

    for (key, value) in notification {
        let path = format!("notification.{key}");
        if key.eq_ignore_ascii_case("devices") {
            validate_device_identity_metadata(value)?;
            continue;
        }
        if is_identity_metadata_key(key) && has_visible_identity_value(value) {
            return Err(format!(
                "caller is not authorized to send plaintext identity metadata in `{path}`"
            ));
        }
        validate_plaintext_identity_tree(&path, value)?;
    }

    Ok(())
}

fn validate_device_identity_metadata(devices: &Value) -> Result<(), String> {
    let Some(devices) = devices.as_array() else {
        return Ok(());
    };

    for (index, device) in devices.iter().enumerate() {
        let Some(device) = device.as_object() else {
            continue;
        };
        let Some(data) = device.get("data").and_then(Value::as_object) else {
            continue;
        };
        let Some(default_payload) = data.get("default_payload") else {
            continue;
        };
        validate_plaintext_identity_tree(
            &format!("notification.devices[{index}].data.default_payload"),
            default_payload,
        )?;
    }

    Ok(())
}

fn validate_plaintext_identity_tree(path: &str, value: &Value) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let next_path = format!("{path}.{key}");
                if is_identity_metadata_key(key) && has_visible_identity_value(value) {
                    return Err(format!(
                        "caller is not authorized to send plaintext identity metadata in `{next_path}`"
                    ));
                }
                validate_plaintext_identity_tree(&next_path, value)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_plaintext_identity_tree(&format!("{path}[{index}]"), value)?;
            }
            Ok(())
        }
        Value::String(value) => validate_plaintext_identity_string(path, value),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn is_identity_metadata_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "sender" | "target_did"
    )
}

fn has_visible_identity_value(value: &Value) -> bool {
    match value {
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(values) => values.iter().any(has_visible_identity_value),
        Value::Object(map) => map.values().any(has_visible_identity_value),
        Value::Null => false,
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn validate_plaintext_identity_string(path: &str, value: &str) -> Result<(), String> {
    if value.to_ascii_lowercase().contains("did:") {
        Err(format!(
            "caller is not authorized to send DID literal in `{path}`"
        ))
    } else {
        Ok(())
    }
}

fn validate_push_hint(push_hint: &str) -> Result<(), String> {
    let normalized = push_hint.to_ascii_lowercase();
    let sensitive_markers = [
        "candidate:",
        "ice-ufrag",
        "ice-pwd",
        "a=crypto:",
        "turn:",
        "turns:",
        "sdp",
        "v=0\r",
        "v=0\n",
        "title:",
        "body:",
        "flow_name:",
        "space_name:",
        "flow name:",
        "space name:",
        "sender_display_name:",
        "\"title\"",
        "\"body\"",
        "\"flow_name\"",
        "\"space_name\"",
    ];

    if sensitive_markers
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        Err("Contrix blind wakeup push_hint must not contain plaintext preview or call setup material".to_owned())
    } else {
        Ok(())
    }
}

fn validate_blind_content(path: &str, value: &Value) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let path = format!("{path}.{key}");
                if is_sensitive_payload_key(key) {
                    return Err(format!(
                        "Contrix blind wakeup payloads must not include sensitive field `{path}`"
                    ));
                }
                validate_blind_content(&path, value)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_blind_content(&format!("{path}[{index}]"), value)?;
            }
            Ok(())
        }
        Value::String(value) => validate_blind_string(path, value),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn validate_blind_string(path: &str, value: &str) -> Result<(), String> {
    let normalized = value.to_ascii_lowercase();
    if normalized.contains("candidate:")
        || normalized.contains("ice-ufrag")
        || normalized.contains("ice-pwd")
        || normalized.contains("turn:")
        || normalized.contains("turns:")
        || normalized.contains("v=0\r")
        || normalized.contains("v=0\n")
    {
        Err(format!(
            "Contrix blind wakeup payloads must not include call setup material in `{path}`"
        ))
    } else {
        Ok(())
    }
}

fn is_sensitive_payload_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "body"
            | "message_body"
            | "formatted_body"
            | "notification_body"
            | "message"
            | "message_text"
            | "text"
            | "plaintext"
            | "content"
            | "title"
            | "subtitle"
            | "notification_title"
            | "alert"
            | "preview"
            | "summary"
            | "filename"
            | "file_name"
            | "attachment_name"
            | "attachment_filename"
            | "attachment_preview"
            | "flow_name"
            | "space_name"
            | "room_name"
            | "room_display_name"
            | "sender_name"
            | "sender_display_name"
            | "provider_payload"
            | "provider_data"
            | "notification_payload"
            | "payload"
            | "aps"
            | "android"
            | "webpush"
            | "facet"
            | "facets"
            | "entity_facet"
            | "entity_facets"
            | "view_renderer"
            | "view_renderers"
            | "rendered_view"
            | "renderer"
            | "template"
            | "template_vars"
            | "encrypted_payload"
            | "ciphertext"
            | "offer"
            | "sdp"
            | "ice_candidate"
            | "ice_candidates"
            | "turn"
            | "turn_credential"
            | "turn_credentials"
    )
}

fn dedup_provider_retries(provider_retries: &mut Vec<ProviderRetry>) {
    provider_retries.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then(left.retry_after_ms.cmp(&right.retry_after_ms))
    });
    provider_retries.dedup();
}

fn notify_rate_limit_checks(
    req: &Request,
    state: &AppState,
    notification: &Notification,
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
            .map(|device| device.app_id.trim())
            .filter(|app_id| !app_id.is_empty())
            .collect::<HashSet<_>>();
        checks.extend(app_ids.into_iter().map(|app_id| NotifyRateLimitCheck {
            scope: "app_id",
            subject: app_id.to_owned(),
            limit,
            units: 1,
        }));
    }

    if let Some(limit) = config.per_push_key_hash.filter(|limit| *limit > 0) {
        let pushkey_hashes = notification
            .devices
            .iter()
            .map(|device| device.redacted_pushkey())
            .collect::<HashSet<_>>();
        checks.extend(
            pushkey_hashes
                .into_iter()
                .map(|pushkey_hash| NotifyRateLimitCheck {
                    scope: "push_key_hash",
                    subject: pushkey_hash,
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
                state
                    .registry
                    .find_pushkins(&device.app_id)
                    .into_iter()
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

#[handler]
pub(super) async fn notify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let started = Instant::now();
    let _inflight = app_metrics::track_inflight("V1NotifyHandler");

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
    let caller =
        match authenticate_notify_request(req, body.as_ref(), &state.notify_auth, &request_id) {
            Ok(caller) => caller,
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
    let raw_request_hash = request_hash(body.as_ref());

    let raw = match serde_json::from_slice::<Value>(&body) {
        Ok(raw) => raw,
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
    if let Err(message) = validate_notify_operation_id(&raw) {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "unsupported_feature",
            &message,
            None,
            Some(&request_id),
            started,
        );
        return;
    }
    if let Err(error) = validate_origin_service_did(&raw, &caller, state.notify_auth.enabled()) {
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
        validate_destination_service_did(&raw, req, &state.notify_auth, state.notify_auth.enabled())
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
    if let Err(message) = validate_notify_contract_shape(&raw) {
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
    let idempotency_key = match resolve_idempotency_key(req, &raw) {
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

    let Some(notification_value) = raw.get("notification").cloned() else {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "missing notification field",
            None,
            Some(&request_id),
            started,
        );
        return;
    };

    if !notification_value.is_object() {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "notification must be an object",
            None,
            Some(&request_id),
            started,
        );
        return;
    }

    let notification_object = notification_value.as_object().cloned();

    let notification: Notification = match serde_json::from_value(notification_value) {
        Ok(notification) => notification,
        Err(error) => {
            tracing::warn!(error = %error, "invalid notification payload");
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "invalid notification payload",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };

    match validate_notification_contract(&notification, &caller) {
        Ok(()) => {}
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

    let request_fingerprint =
        normalized_notify_dedup_key(&notification).unwrap_or(raw_request_hash);
    let dedup_key = idempotency_key
        .as_deref()
        .map(idempotency_cache_key)
        .unwrap_or_else(|| request_fingerprint.clone());
    if let Some(deduplicator) = state.notify_deduplicator.as_ref() {
        if deduplicator.conflicts(&dedup_key, &request_fingerprint) {
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
        if let Some(cached) = deduplicator.lookup(&dedup_key, &request_fingerprint) {
            app_metrics::notify_request_cache_hit();
            tracing::info!(
                request_id = %request_id,
                ttl_secs = deduplicator.ttl().as_secs(),
                idempotency_key = idempotency_key
                    .as_deref()
                    .unwrap_or("<canonical-request-hash>"),
                "serving /notify response from dedup cache"
            );
            finish_json(
                res,
                StatusCode::OK,
                cached.response.with_request_id(request_id),
                started,
            );
            return;
        }
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
        if let Err(rejection) = rate_limiter.check_many(&checks) {
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
        let pushkey = device.pushkey.trim();
        if app_id.is_empty() || pushkey.is_empty() {
            tracing::warn!(
                request_id = %context.request_id,
                app_id = %device.app_id,
                pushkey_hash = %device.redacted_pushkey(),
                "rejecting device with empty app_id or pushkey"
            );
            rejected.push(rejected_device(device, Some(&device.pushkey)));
            delivery_receipts.push(delivery_receipt(
                None,
                &device.pushkey,
                "rejected",
                None,
                &context.request_id,
            ));
            continue;
        }

        if !seen_devices.insert((app_id.to_owned(), pushkey.to_owned())) {
            tracing::info!(
                request_id = %context.request_id,
                app_id,
                pushkey_hash = %device.redacted_pushkey(),
                "skipping duplicate device entry"
            );
            continue;
        }

        app_metrics::device_push_received();
        let pushkins = state.registry.find_pushkins(&device.app_id);
        match pushkins.as_slice() {
            [] => {
                tracing::warn!(request_id = %context.request_id, app_id = %device.app_id, pushkey_hash = %device.redacted_pushkey(), "unknown app id");
                rejected.push(rejected_device(device, Some(&device.pushkey)));
                delivery_receipts.push(delivery_receipt(
                    None,
                    &device.pushkey,
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
                        deduplicator.contains_delivered_device(&dedup_key, app_id, pushkey)
                    })
                {
                    skipped_delivered += 1;
                    app_metrics::notify_device_skip_hit(1);
                    app_metrics::notify_device_skip_by_pushkin(pushkin.name(), 1);
                    delivery_receipts.push(delivery_receipt(
                        Some(pushkin.name()),
                        pushkey,
                        "accepted_cached",
                        None,
                        &context.request_id,
                    ));
                    tracing::info!(
                        request_id = %context.request_id,
                        app_id,
                        pushkey_hash = %device.redacted_pushkey(),
                        pushkin = %pushkin.name(),
                        "skipping device already delivered within dedup ttl"
                    );
                    continue;
                }

                app_metrics::pushkin_selected(pushkin.name());
                let dispatch_targets = pushkin.dispatch_targets(&notification, device);
                match pushkin
                    .dispatch_notification(&notification, device, &context)
                    .await
                {
                    Ok(mut pushkin_rejected) => {
                        let rejected_set = pushkin_rejected
                            .iter()
                            .cloned()
                            .collect::<HashSet<String>>();
                        let delivered_targets = dispatch_targets
                            .iter()
                            .filter(|target| !rejected_set.contains(&target.pushkey))
                            .collect::<Vec<_>>();
                        if !delivered_targets.is_empty() {
                            delivered_now += delivered_targets.len();
                            for target in &delivered_targets {
                                delivery_receipts.push(delivery_receipt(
                                    Some(pushkin.name()),
                                    &target.pushkey,
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
                        rejected.extend(pushkin_rejected.drain(..).map(|pushkey| {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &pushkey,
                                "rejected",
                                None,
                                &context.request_id,
                            ));
                            rejected_device(device, Some(&pushkey))
                        }));
                    }
                    Err(error) if error.is_temporary() => {
                        let retry_after = error.retry_after();
                        tracing::warn!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id = %device.app_id,
                            pushkey_hash = %device.redacted_pushkey(),
                            "temporary dispatch failure"
                        );
                        provider_retries.push(ProviderRetry::new(pushkin.name(), retry_after));
                        for target in &dispatch_targets {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &target.pushkey,
                                "retryable",
                                retry_after,
                                &context.request_id,
                            ));
                        }
                        first_temporary_error
                            .get_or_insert_with(|| (error.to_string(), retry_after));
                    }
                    Err(error) if error.is_remote() => {
                        tracing::warn!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id = %device.app_id,
                            pushkey_hash = %device.redacted_pushkey(),
                            "remote dispatch failure"
                        );
                        for target in &dispatch_targets {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &target.pushkey,
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
                            pushkey_hash = %device.redacted_pushkey(),
                            "internal dispatch failure"
                        );
                        for target in &dispatch_targets {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &target.pushkey,
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
                tracing::warn!(request_id = %context.request_id, app_id = %device.app_id, pushkey_hash = %device.redacted_pushkey(), "ambiguous app id");
                rejected.push(rejected_device(device, Some(&device.pushkey)));
                delivery_receipts.push(delivery_receipt(
                    None,
                    &device.pushkey,
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
        let response = NotifyResponse {
            request_id: context.request_id.clone(),
            accepted: delivered_now + skipped_delivered,
            rejected,
            provider_retries,
            delivery_receipts,
        };
        if fully_settled {
            cache_success_response(&state, &dedup_key, &request_fingerprint, &response);
        }
        record_notify_delivery_outcomes(&response);
        finish_json(res, StatusCode::OK, response, started);
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

    let response = NotifyResponse {
        request_id: context.request_id.clone(),
        accepted: delivered_now + skipped_delivered,
        rejected,
        provider_retries,
        delivery_receipts,
    };
    if fully_settled {
        cache_success_response(&state, &dedup_key, &request_fingerprint, &response);
    }
    record_notify_delivery_outcomes(&response);
    finish_json(res, StatusCode::OK, response, started);
}

fn cache_success_response(
    state: &Arc<AppState>,
    key: &str,
    request_fingerprint: &str,
    response: &NotifyResponse,
) {
    if let Some(deduplicator) = state.notify_deduplicator.as_ref() {
        deduplicator.insert_success(key, request_fingerprint, response.clone());
    }
}

fn mark_delivered_devices<'a>(
    state: &Arc<AppState>,
    notification_key: &str,
    targets: impl Iterator<Item = &'a crate::pushkin::DispatchTarget>,
) {
    if let Some(deduplicator) = state.notify_deduplicator.as_ref() {
        for target in targets {
            deduplicator.mark_delivered_device(notification_key, &target.app_id, &target.pushkey);
        }
    }
}

fn rejected_device(device: &crate::models::Device, push_key: Option<&str>) -> RejectedDevice {
    RejectedDevice::new(Some(&device.app_id), push_key.unwrap_or(&device.pushkey))
}

fn delivery_receipt(
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

fn idempotency_cache_key(idempotency_key: &str) -> String {
    request_hash(format!("idempotency-key\0{idempotency_key}").as_bytes())
}

fn normalized_notify_dedup_key(notification: &Notification) -> Option<String> {
    let mut normalized = Map::new();

    if let Some(value) = notification.flow_name() {
        normalized.insert("flow_name".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.space_name() {
        normalized.insert("space_name".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.prio.as_ref() {
        normalized.insert("prio".to_owned(), Value::String(value.clone()));
    }
    if let Some(value) = notification.membership.as_ref() {
        normalized.insert("membership".to_owned(), Value::String(value.clone()));
    }
    if let Some(value) = notification.sender_display_name.as_ref() {
        normalized.insert(
            "sender_display_name".to_owned(),
            Value::String(value.clone()),
        );
    }
    if let Some(value) = notification.content.as_ref() {
        normalized.insert(
            "content".to_owned(),
            canonical_json_value(&Value::Object(value.clone())),
        );
    }
    if let Some(value) = notification.event_id.as_ref() {
        normalized.insert("event_id".to_owned(), Value::String(value.clone()));
    }
    if let Some(value) = notification.message_id() {
        normalized.insert("message_id".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.flow_id() {
        normalized.insert("flow_id".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.space_id() {
        normalized.insert("space_id".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.user_is_target {
        normalized.insert("user_is_target".to_owned(), Value::Bool(value));
    }
    if let Some(value) = notification.event_kind() {
        normalized.insert("type".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.sender.as_ref() {
        normalized.insert("sender".to_owned(), Value::String(value.clone()));
    }
    if let Some(value) = notification.push_hint.as_ref() {
        normalized.insert("push_hint".to_owned(), Value::String(value.clone()));
    }
    normalized.insert(
        "counts".to_owned(),
        canonical_json_value(&serde_json::to_value(&notification.counts).ok()?),
    );

    let mut devices = notification
        .devices
        .iter()
        .map(|device| {
            let mut normalized = Map::new();
            normalized.insert("app_id".to_owned(), Value::String(device.app_id.clone()));
            normalized.insert("push_key".to_owned(), Value::String(device.pushkey.clone()));
            normalized.insert(
                "push_key_ts".to_owned(),
                Value::Number(device.pushkey_ts.into()),
            );
            if let Some(data) = device.data.as_ref() {
                normalized.insert(
                    "data".to_owned(),
                    canonical_json_value(&Value::Object(data.clone())),
                );
            }
            let tweaks = serde_json::to_value(&device.tweaks).ok()?;
            normalized.insert("tweaks".to_owned(), canonical_json_value(&tweaks));
            Some(Value::Object(normalized))
        })
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    devices.sort_by_key(canonical_sort_key);
    devices.dedup();
    normalized.insert("devices".to_owned(), Value::Array(devices));

    serde_json::to_vec(&Value::Object(normalized))
        .ok()
        .map(|bytes| request_hash(&bytes))
}

fn canonical_json_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonical_json_value).collect()),
        Value::Object(object) => {
            let mut keys = object.keys().cloned().collect::<Vec<_>>();
            keys.sort_unstable();

            let mut normalized = Map::new();
            for key in keys {
                if let Some(value) = object.get(&key) {
                    normalized.insert(key, canonical_json_value(value));
                }
            }
            Value::Object(normalized)
        }
        _ => value.clone(),
    }
}

fn canonical_sort_key(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}
