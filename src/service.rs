use std::sync::Arc;
use std::time::Instant;
use std::{collections::HashSet, time::Duration};

use salvo::http::ParseError;
use salvo::http::StatusCode;
use salvo::http::header::{HeaderName, HeaderValue};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::AppState;
use crate::config::AccessLogConfig;
use crate::dedup::request_hash;
use crate::metrics;
use crate::models::{
    Notification, NotificationContext, NotifyResponse, ProviderRetry, RejectedDevice,
};

pub const MAX_REQUEST_SIZE: usize = 512 * 1024;
const ORIGIN_SERVICE_DID_HEADER: &str = "x-contrix-origin-service-did";
const DESTINATION_SERVICE_DID_HEADER: &str = "x-contrix-destination-service-did";

fn notify_route(path: &'static str) -> Router {
    Router::with_path(path)
        .post(notify)
        .get(notify_method_not_allowed)
        .put(notify_method_not_allowed)
        .delete(notify_method_not_allowed)
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::with_hoop(affix_state::inject(state))
        .push(notify_route("api/v1/push/notify"))
        .push(notify_route("contrix/push/v1/notify"))
        .push(Router::with_path("health").get(health))
}

pub fn build_router_with_access_log(state: Arc<AppState>, access_log: &AccessLogConfig) -> Router {
    let use_forwarded_for = access_log.x_forwarded_for;
    Router::with_hoop(affix_state::inject(state))
        .hoop(AccessLogger { use_forwarded_for })
        .push(notify_route("api/v1/push/notify"))
        .push(notify_route("contrix/push/v1/notify"))
        .push(Router::with_path("health").get(health))
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

        // Skip noisy health check logging at info level
        if path == "/health" {
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

#[handler]
async fn health(res: &mut Response) {
    res.status_code(StatusCode::OK);
    res.render(Text::Plain(""));
}

#[derive(Debug)]
struct AuthFailure {
    status: StatusCode,
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope<'a> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    error: ErrorBody<'a>,
}

#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_ms: Option<u64>,
}

#[handler]
async fn notify_method_not_allowed(res: &mut Response) {
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

fn authenticate_notify_request(
    req: &Request,
    state: &AppState,
    request_id: &str,
) -> Result<(), AuthFailure> {
    let auth = &state.notify_auth;
    if !auth.enabled() {
        return Ok(());
    }

    let origin_did = req
        .header::<String>(ORIGIN_SERVICE_DID_HEADER)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let destination_did = req
        .header::<String>(DESTINATION_SERVICE_DID_HEADER)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let redacted_origin = origin_did.as_deref().unwrap_or("<missing>").to_owned();
    let redacted_destination = destination_did.as_deref().unwrap_or("<missing>").to_owned();

    let token = req
        .header::<String>("authorization")
        .and_then(|value| parse_bearer_token(&value).map(ToOwned::to_owned));

    let Some(token) = token else {
        tracing::warn!(
            request_id,
            origin_service_did = %redacted_origin,
            destination_service_did = %redacted_destination,
            "rejecting unauthenticated /notify request"
        );
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthenticated",
            message: "missing bearer service token".to_owned(),
        });
    };

    if !auth
        .bearer_tokens
        .iter()
        .any(|candidate| candidate == &token)
    {
        tracing::warn!(
            request_id,
            origin_service_did = %redacted_origin,
            destination_service_did = %redacted_destination,
            "rejecting /notify request with invalid bearer token"
        );
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthenticated",
            message: "invalid bearer service token".to_owned(),
        });
    }

    if !auth.trusted_service_dids.is_empty() {
        let Some(origin_did) = origin_did else {
            tracing::warn!(
                request_id,
                destination_service_did = %redacted_destination,
                "rejecting /notify request without origin service DID"
            );
            return Err(AuthFailure {
                status: StatusCode::FORBIDDEN,
                code: "capability_denied",
                message: "origin service DID is required".to_owned(),
            });
        };
        if !auth
            .trusted_service_dids
            .iter()
            .any(|candidate| candidate == &origin_did)
        {
            tracing::warn!(
                request_id,
                origin_service_did = %origin_did,
                destination_service_did = %redacted_destination,
                "rejecting /notify request from non-allowlisted service DID"
            );
            return Err(AuthFailure {
                status: StatusCode::FORBIDDEN,
                code: "capability_denied",
                message: "origin service DID is not allowlisted".to_owned(),
            });
        }
    }

    if let Some(gateway_service_did) = auth.gateway_service_did.as_deref() {
        let Some(destination_did) = destination_did else {
            tracing::warn!(
                request_id,
                origin_service_did = %redacted_origin,
                "rejecting /notify request without destination service DID"
            );
            return Err(AuthFailure {
                status: StatusCode::FORBIDDEN,
                code: "capability_denied",
                message: "destination service DID is required".to_owned(),
            });
        };
        if destination_did != gateway_service_did {
            tracing::warn!(
                request_id,
                origin_service_did = %redacted_origin,
                destination_service_did = %destination_did,
                expected_destination_service_did = %gateway_service_did,
                "rejecting /notify request for a different gateway DID"
            );
            return Err(AuthFailure {
                status: StatusCode::FORBIDDEN,
                code: "capability_denied",
                message: "destination service DID does not match this gateway".to_owned(),
            });
        }
    }

    Ok(())
}

fn parse_bearer_token(value: &str) -> Option<&str> {
    let value = value.trim();
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    (!token.is_empty()).then_some(token)
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

fn validate_notification_contract(notification: &Notification) -> Result<(), String> {
    let is_contrix_request = notification.space_id.is_some()
        || notification.push_hint.is_some()
        || notification
            .event_kind()
            .is_some_and(|kind| kind.starts_with("cx."));
    if !is_contrix_request {
        return Ok(());
    }

    let Some(content) = notification.content.as_ref() else {
        return Ok(());
    };

    if content.contains_key("body") {
        return Err("Contrix blind wakeup payloads must not include message body".to_owned());
    }
    if content.contains_key("ciphertext") || content.contains_key("encrypted_payload") {
        return Err(
            "Contrix blind wakeup payloads must not include encrypted payload bytes".to_owned(),
        );
    }
    if content.get("offer").is_some() || content.get("sdp").is_some() {
        return Err("Contrix blind wakeup payloads must not include SDP".to_owned());
    }
    if content.get("ice_candidate").is_some() || content.get("ice_candidates").is_some() {
        return Err("Contrix blind wakeup payloads must not include ICE candidates".to_owned());
    }
    if content.get("turn").is_some() || content.get("turn_credentials").is_some() {
        return Err("Contrix blind wakeup payloads must not include TURN credentials".to_owned());
    }

    Ok(())
}

fn dedup_provider_retries(provider_retries: &mut Vec<ProviderRetry>) {
    provider_retries.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then(left.retry_after_ms.cmp(&right.retry_after_ms))
    });
    provider_retries.dedup();
}

#[handler]
async fn notify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let started = Instant::now();
    let _inflight = metrics::track_inflight("V1NotifyHandler");

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

    if let Err(error) = authenticate_notify_request(req, &state, &request_id) {
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

    let body = match req.payload_with_max_size(MAX_REQUEST_SIZE).await {
        Ok(bytes) => bytes,
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
                "invalid_request",
                "failed to read request body",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };
    let raw_request_hash = request_hash(body.as_ref());

    let raw = match serde_json::from_slice::<Value>(body) {
        Ok(raw) => raw,
        Err(error) => {
            tracing::warn!(error = %error, "expected JSON request body");
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "expected JSON request body",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };
    let idempotency_key = match resolve_idempotency_key(req, &raw) {
        Ok(idempotency_key) => idempotency_key,
        Err(message) => {
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_request",
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
            "invalid_request",
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
            "invalid_request",
            "notification must be an object",
            None,
            Some(&request_id),
            started,
        );
        return;
    }

    let notification: Notification = match serde_json::from_value(notification_value) {
        Ok(notification) => notification,
        Err(error) => {
            tracing::warn!(error = %error, "invalid notification payload");
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid notification payload",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };

    if let Err(message) = validate_notification_contract(&notification) {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_request",
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
            metrics::notify_request_cache_hit();
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
    metrics::notification_received();

    if notification.devices.is_empty() {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "no devices in notification",
            None,
            Some(&request_id),
            started,
        );
        return;
    }

    let context = NotificationContext {
        request_id: request_id.clone(),
        start_time: Instant::now(),
    };

    let mut rejected = Vec::new();
    let mut delivered_now = 0usize;
    let mut skipped_delivered = 0usize;
    let mut provider_retries = Vec::new();
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

        metrics::device_push_received();
        let pushkins = state.registry.find_pushkins(&device.app_id);
        match pushkins.as_slice() {
            [] => {
                tracing::warn!(request_id = %context.request_id, app_id = %device.app_id, pushkey_hash = %device.redacted_pushkey(), "unknown app id");
                rejected.push(rejected_device(device, Some(&device.pushkey)));
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
                    metrics::notify_device_skip_hit(1);
                    metrics::notify_device_skip_by_pushkin(pushkin.name(), 1);
                    tracing::info!(
                        request_id = %context.request_id,
                        app_id,
                        pushkey_hash = %device.redacted_pushkey(),
                        pushkin = %pushkin.name(),
                        "skipping device already delivered within dedup ttl"
                    );
                    continue;
                }

                metrics::pushkin_selected(pushkin.name());
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
                            mark_delivered_devices(
                                &state,
                                &dedup_key,
                                delivered_targets.iter().copied(),
                            );
                        }
                        rejected.extend(
                            pushkin_rejected
                                .drain(..)
                                .map(|pushkey| rejected_device(device, Some(&pushkey))),
                        );
                    }
                    Err(error) if error.is_temporary() => {
                        tracing::warn!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id = %device.app_id,
                            pushkey_hash = %device.redacted_pushkey(),
                            "temporary dispatch failure"
                        );
                        provider_retries
                            .push(ProviderRetry::new(pushkin.name(), error.retry_after()));
                        first_temporary_error
                            .get_or_insert_with(|| (error.to_string(), error.retry_after()));
                    }
                    Err(error) if error.is_remote() => {
                        tracing::warn!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id = %device.app_id,
                            pushkey_hash = %device.redacted_pushkey(),
                            "remote dispatch failure"
                        );
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
                        first_internal_error.get_or_insert_with(|| error.to_string());
                    }
                }
            }
            _ => {
                tracing::warn!(request_id = %context.request_id, app_id = %device.app_id, pushkey_hash = %device.redacted_pushkey(), "ambiguous app id");
                rejected.push(rejected_device(device, Some(&device.pushkey)));
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
            metrics::notify_partial_success(StatusCode::OK);
        }
        if skipped_delivered > 0 {
            metrics::notify_retry_with_skips(StatusCode::OK);
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
        };
        if fully_settled {
            cache_success_response(&state, &dedup_key, &request_fingerprint, &response);
        }
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
        metrics::notify_retry_with_skips(status);
        tracing::info!(
            request_id = %context.request_id,
            skipped_delivered,
            rejected = rejected.len(),
            "all currently delivered devices came from dedup cache"
        );
    }

    if let Some(message) = first_internal_error {
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
        finish_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_unavailable",
            &message,
            retry_after,
            Some(&context.request_id),
            started,
        );
        return;
    }

    if let Some(message) = first_remote_error {
        finish_error(
            res,
            StatusCode::BAD_GATEWAY,
            "provider_unavailable",
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
    };
    if fully_settled {
        cache_success_response(&state, &dedup_key, &request_fingerprint, &response);
    }
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

fn idempotency_cache_key(idempotency_key: &str) -> String {
    request_hash(format!("idempotency-key\0{idempotency_key}").as_bytes())
}

fn normalized_notify_dedup_key(notification: &Notification) -> Option<String> {
    let mut normalized = Map::new();

    if let Some(value) = notification.scope_name() {
        normalized.insert("space_name".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.room_alias.as_ref() {
        normalized.insert("room_alias".to_owned(), Value::String(value.clone()));
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
    if let Some(value) = notification.scope_id() {
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

fn finish_error(
    res: &mut Response,
    status: StatusCode,
    code: &str,
    body: &str,
    retry_after: Option<Duration>,
    request_id: Option<&str>,
    started: Instant,
) {
    if let Some(retry_after) = retry_after {
        let seconds = retry_after.as_secs().max(1).to_string();
        let _ = res.add_header(
            HeaderName::from_static("retry-after"),
            HeaderValue::from_str(&seconds).unwrap_or_else(|_| HeaderValue::from_static("1")),
            true,
        );
    }
    let body = ErrorEnvelope {
        ok: false,
        request_id,
        error: ErrorBody {
            code,
            message: body,
            retry_after_ms: retry_after.map(|value| value.as_millis().min(u64::MAX as u128) as u64),
        },
    };
    res.status_code(status);
    res.render(Json(body));
    metrics::pushgateway_response(status);
    metrics::observe_notify_handle(status, started.elapsed());
}

fn finish_json<T: Serialize + Send>(
    res: &mut Response,
    status: StatusCode,
    body: T,
    started: Instant,
) {
    res.status_code(status);
    res.render(Json(body));
    metrics::pushgateway_response(status);
    metrics::observe_notify_handle(status, started.elapsed());
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use salvo::test::{ResponseExt, TestClient};
    use serde_json::json;
    use tokio::time::sleep;

    use super::*;
    use crate::config::NotifyAuthConfig;
    use crate::dedup::NotifyDeduplicator;
    use crate::error::DispatchError;
    use crate::models::{Device, Notification, NotificationContext, RejectedDevice};
    use crate::pushkin::{AppMatcher, ConcurrencyGate, Pushkin, PushkinRegistry};

    #[derive(Debug, Clone)]
    enum TestBehavior {
        Accept,
        Reject,
        RemoteError,
        TemporaryError,
        InternalError,
        SlowAccept,
    }

    struct TestPushkin {
        matcher: AppMatcher,
        gate: Option<ConcurrencyGate>,
        behavior: TestBehavior,
        calls: Arc<AtomicUsize>,
    }

    impl TestPushkin {
        fn new(name: &str, behavior: TestBehavior) -> Self {
            Self {
                matcher: AppMatcher::new(name.to_owned()).unwrap(),
                gate: None,
                behavior,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn with_limit(name: &str, behavior: TestBehavior, limit: usize) -> Self {
            Self {
                matcher: AppMatcher::new(name.to_owned()).unwrap(),
                gate: Some(ConcurrencyGate::new(limit)),
                behavior,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl Pushkin for TestPushkin {
        fn name(&self) -> &str {
            self.matcher.name()
        }

        fn handles_appid(&self, appid: &str) -> bool {
            self.matcher.handles_appid(appid)
        }

        async fn dispatch_notification(
            &self,
            _notification: &Notification,
            device: &Device,
            _context: &NotificationContext,
        ) -> Result<Vec<String>, DispatchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _permit = self
                .gate
                .as_ref()
                .map(|gate| gate.acquire(self.name()))
                .transpose()?;

            match self.behavior {
                TestBehavior::Accept => Ok(vec![]),
                TestBehavior::Reject => Ok(vec![device.pushkey.clone()]),
                TestBehavior::RemoteError => Err(DispatchError::remote("synthetic remote failure")),
                TestBehavior::TemporaryError => Err(DispatchError::temporary(
                    "synthetic temporary failure",
                    Some(Duration::from_secs(7)),
                )),
                TestBehavior::InternalError => {
                    Err(DispatchError::internal("synthetic internal failure"))
                }
                TestBehavior::SlowAccept => {
                    sleep(Duration::from_millis(100)).await;
                    Ok(vec![])
                }
            }
        }
    }

    fn test_service(pushkins: Vec<(&str, Arc<dyn Pushkin>)>) -> Service {
        let registry = PushkinRegistry::new(
            pushkins
                .into_iter()
                .map(|(name, pushkin)| (name.to_owned(), pushkin))
                .collect::<HashMap<_, _>>(),
        );
        let state = Arc::new(AppState::new(Arc::new(registry)));
        Service::new(build_router(state))
    }

    fn test_service_with_dedup(
        pushkins: Vec<(&str, Arc<dyn Pushkin>)>,
        dedup_ttl: Duration,
    ) -> Service {
        let registry = PushkinRegistry::new(
            pushkins
                .into_iter()
                .map(|(name, pushkin)| (name.to_owned(), pushkin))
                .collect::<HashMap<_, _>>(),
        );
        let state = Arc::new(AppState::with_notify_deduplicator(
            Arc::new(registry),
            Arc::new(NotifyDeduplicator::new(dedup_ttl)),
        ));
        Service::new(build_router(state))
    }

    fn test_service_with_auth(
        pushkins: Vec<(&str, Arc<dyn Pushkin>)>,
        notify_auth: NotifyAuthConfig,
    ) -> Service {
        let registry = PushkinRegistry::new(
            pushkins
                .into_iter()
                .map(|(name, pushkin)| (name.to_owned(), pushkin))
                .collect::<HashMap<_, _>>(),
        );
        let mut state = AppState::new(Arc::new(registry));
        state.notify_auth = notify_auth;
        Service::new(build_router(Arc::new(state)))
    }

    fn notify_auth_config() -> NotifyAuthConfig {
        let mut config = NotifyAuthConfig::default();
        config.bearer_tokens = vec!["secret-token".to_owned()];
        config.trusted_service_dids = vec!["did:web:sync.example.com".to_owned()];
        config.gateway_service_did = Some("did:web:push.example.com".to_owned());
        config
    }

    fn payload(devices: Vec<Value>) -> Value {
        json!({
            "notification": {
                "event_id": "$event",
                "room_id": "!room:example.com",
                "sender": "@alice:example.com",
                "sender_display_name": "Alice",
                "type": "m.room.message",
                "content": {
                    "msgtype": "m.text",
                    "body": "hello"
                },
                "devices": devices
            }
        })
    }

    fn contrix_payload(devices: Vec<Value>) -> Value {
        json!({
            "notification": {
                "event_id": "cx:event:01JS0EV000000000000000000",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "space_name": "Engineering",
                "sender": "did:web:alice.example.com",
                "sender_display_name": "Alice",
                "type": "cx.message.create",
                "push_hint": "New message",
                "devices": devices
            }
        })
    }

    fn with_idempotency_key(mut request_body: Value, idempotency_key: &str) -> Value {
        request_body["idempotency_key"] = Value::String(idempotency_key.to_owned());
        request_body
    }

    fn device(app_id: &str, pushkey: &str) -> Value {
        json!({
            "app_id": app_id,
            "pushkey": pushkey,
            "pushkey_ts": 42
        })
    }

    fn device_with_push_key(app_id: &str, push_key: &str) -> Value {
        json!({
            "app_id": app_id,
            "push_key": push_key,
            "push_key_ts": 42
        })
    }

    fn rejected(app_id: Option<&str>, push_key: &str) -> RejectedDevice {
        RejectedDevice::new(app_id, push_key)
    }

    async fn assert_notify_error<T: ResponseExt + ?Sized>(
        response: &mut T,
        code: &str,
        expect_request_id: bool,
    ) -> Value {
        let body = response.take_json::<Value>().await.unwrap();
        assert_eq!(body["ok"], json!(false));
        assert_eq!(body["error"]["code"], json!(code));
        match (expect_request_id, body.get("request_id")) {
            (true, Some(Value::String(request_id))) => assert!(!request_id.is_empty()),
            (true, _) => panic!("expected request_id in error response"),
            (false, None) => {}
            (false, Some(Value::Null)) => {}
            (false, Some(_)) => panic!("did not expect request_id in error response"),
        }
        body
    }

    async fn assert_notify_ok<T: ResponseExt + ?Sized>(
        response: &mut T,
        accepted: usize,
        rejected_devices: Vec<RejectedDevice>,
        provider_retries: usize,
    ) {
        let body = response.take_json::<NotifyResponse>().await.unwrap();
        assert!(!body.request_id.is_empty());
        assert_eq!(body.accepted, accepted);
        assert_eq!(body.rejected, rejected_devices);
        assert_eq!(body.provider_retries.len(), provider_retries);
    }

    #[tokio::test]
    async fn accepted_devices_are_not_rejected() {
        let service = test_service(vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )]);

        let mut response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&payload(vec![device("com.example.app", "accept")]))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        assert_notify_ok(&mut response, 1, vec![], 0).await;
    }

    #[tokio::test]
    async fn contrix_endpoint_accepts_contrix_payload_shape() {
        let service = test_service(vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )]);

        let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .json(&contrix_payload(vec![device_with_push_key(
                "com.example.app",
                "accept",
            )]))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        assert_notify_ok(&mut response, 1, vec![], 0).await;
    }

    #[tokio::test]
    async fn notify_method_not_allowed_returns_standard_error_envelope() {
        let service = test_service(vec![]);

        let mut get_response = TestClient::get("http://127.0.0.1/api/v1/push/notify")
            .send(&service)
            .await;
        assert_eq!(
            get_response.status_code.unwrap(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            get_response
                .headers()
                .get("allow")
                .and_then(|value| value.to_str().ok()),
            Some("POST")
        );
        assert_notify_error(&mut get_response, "method_not_allowed", false).await;

        let mut put_response = TestClient::put("http://127.0.0.1/api/v1/push/notify")
            .send(&service)
            .await;
        assert_eq!(
            put_response.status_code.unwrap(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_notify_error(&mut put_response, "method_not_allowed", false).await;

        let mut delete_response = TestClient::delete("http://127.0.0.1/api/v1/push/notify")
            .send(&service)
            .await;
        assert_eq!(
            delete_response.status_code.unwrap(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_notify_error(&mut delete_response, "method_not_allowed", false).await;
    }

    #[tokio::test]
    async fn notify_accepts_authenticated_allowlisted_service() {
        let service = test_service_with_auth(
            vec![(
                "com.example.app",
                Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
            )],
            notify_auth_config(),
        );

        let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .add_header("authorization", "Bearer secret-token", true)
            .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
            .add_header(
                DESTINATION_SERVICE_DID_HEADER,
                "did:web:push.example.com",
                true,
            )
            .json(&contrix_payload(vec![device_with_push_key(
                "com.example.app",
                "accept",
            )]))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        assert_notify_ok(&mut response, 1, vec![], 0).await;
    }

    #[tokio::test]
    async fn notify_requires_bearer_token_when_auth_enabled() {
        let service = test_service_with_auth(
            vec![(
                "com.example.app",
                Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
            )],
            notify_auth_config(),
        );

        let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .json(&contrix_payload(vec![device_with_push_key(
                "com.example.app",
                "accept",
            )]))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
        let body = assert_notify_error(&mut response, "unauthenticated", true).await;
        assert_eq!(
            body["error"]["message"],
            json!("missing bearer service token")
        );
    }

    #[tokio::test]
    async fn notify_rejects_invalid_bearer_token() {
        let service = test_service_with_auth(
            vec![(
                "com.example.app",
                Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
            )],
            notify_auth_config(),
        );

        let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .add_header("authorization", "Bearer wrong-token", true)
            .json(&contrix_payload(vec![device_with_push_key(
                "com.example.app",
                "accept",
            )]))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
        let body = assert_notify_error(&mut response, "unauthenticated", true).await;
        assert_eq!(
            body["error"]["message"],
            json!("invalid bearer service token")
        );
    }

    #[tokio::test]
    async fn notify_rejects_non_allowlisted_origin_service_did() {
        let service = test_service_with_auth(
            vec![(
                "com.example.app",
                Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
            )],
            notify_auth_config(),
        );

        let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .add_header("authorization", "Bearer secret-token", true)
            .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:rogue.example.com", true)
            .add_header(
                DESTINATION_SERVICE_DID_HEADER,
                "did:web:push.example.com",
                true,
            )
            .json(&contrix_payload(vec![device_with_push_key(
                "com.example.app",
                "accept",
            )]))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
        let body = assert_notify_error(&mut response, "capability_denied", true).await;
        assert_eq!(
            body["error"]["message"],
            json!("origin service DID is not allowlisted")
        );
    }

    #[tokio::test]
    async fn notify_rejects_mismatched_destination_service_did() {
        let service = test_service_with_auth(
            vec![(
                "com.example.app",
                Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
            )],
            notify_auth_config(),
        );

        let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .add_header("authorization", "Bearer secret-token", true)
            .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
            .add_header(
                DESTINATION_SERVICE_DID_HEADER,
                "did:web:other-gateway.example.com",
                true,
            )
            .json(&contrix_payload(vec![device_with_push_key(
                "com.example.app",
                "accept",
            )]))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
        let body = assert_notify_error(&mut response, "capability_denied", true).await;
        assert_eq!(
            body["error"]["message"],
            json!("destination service DID does not match this gateway")
        );
    }

    #[tokio::test]
    async fn contrix_payload_with_message_body_is_rejected() {
        let service = test_service(vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )]);
        let mut request_body =
            contrix_payload(vec![device_with_push_key("com.example.app", "accept")]);
        request_body["notification"]["content"] = json!({
            "msgtype": "m.text",
            "body": "hello"
        });

        let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .json(&request_body)
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
        let body = assert_notify_error(&mut response, "invalid_request", true).await;
        assert_eq!(
            body["error"]["message"],
            json!("Contrix blind wakeup payloads must not include message body")
        );
    }

    #[tokio::test]
    async fn rejected_devices_are_reported() {
        let service = test_service(vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Reject)),
        )]);

        let mut response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&payload(vec![device("com.example.app", "reject")]))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        assert_notify_ok(
            &mut response,
            0,
            vec![rejected(Some("com.example.app"), "reject")],
            0,
        )
        .await;
    }

    #[tokio::test]
    async fn ambiguous_app_ids_are_rejected() {
        let service = test_service(vec![
            (
                "*.example.*",
                Arc::new(TestPushkin::new("*.example.*", TestBehavior::Accept)),
            ),
            (
                "com.example.a*",
                Arc::new(TestPushkin::new("com.example.a*", TestBehavior::Accept)),
            ),
        ]);

        let mut response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&payload(vec![device("com.example.app", "spqr")]))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        assert_notify_ok(
            &mut response,
            0,
            vec![rejected(Some("com.example.app"), "spqr")],
            0,
        )
        .await;
    }

    #[tokio::test]
    async fn remote_errors_map_to_502() {
        let service = test_service(vec![(
            "com.example.app",
            Arc::new(TestPushkin::new(
                "com.example.app",
                TestBehavior::RemoteError,
            )),
        )]);

        let response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&payload(vec![device("com.example.app", "remote")]))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn internal_errors_map_to_500() {
        let service = test_service(vec![(
            "com.example.app",
            Arc::new(TestPushkin::new(
                "com.example.app",
                TestBehavior::InternalError,
            )),
        )]);

        let response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&payload(vec![device("com.example.app", "boom")]))
            .send(&service)
            .await;

        assert_eq!(
            response.status_code.unwrap(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn temporary_errors_map_to_503_with_retry_after() {
        let service = test_service(vec![(
            "com.example.app",
            Arc::new(TestPushkin::new(
                "com.example.app",
                TestBehavior::TemporaryError,
            )),
        )]);

        let response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&payload(vec![device("com.example.app", "retry")]))
            .send(&service)
            .await;

        assert_eq!(
            response.status_code.unwrap(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("7")
        );
    }

    #[tokio::test]
    async fn oversized_requests_are_rejected() {
        let service = test_service(vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )]);

        let response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .text("x".repeat(MAX_REQUEST_SIZE + 1))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn per_pushkin_concurrency_limit_returns_502() {
        let service = test_service(vec![(
            "com.example.app",
            Arc::new(TestPushkin::with_limit(
                "com.example.app",
                TestBehavior::SlowAccept,
                1,
            )),
        )]);

        let request_a = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&payload(vec![device("com.example.app", "one")]))
            .send(&service);
        let request_b = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&payload(vec![device("com.example.app", "two")]))
            .send(&service);

        let (response_a, response_b) = tokio::join!(request_a, request_b);
        let statuses = [
            response_a.status_code.unwrap(),
            response_b.status_code.unwrap(),
        ];

        assert!(statuses.contains(&StatusCode::OK));
        assert!(statuses.contains(&StatusCode::BAD_GATEWAY));
    }

    #[tokio::test]
    async fn duplicate_devices_are_dispatched_only_once() {
        let service = test_service(vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Reject)),
        )]);

        let mut response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&payload(vec![
                device("com.example.app", "dup"),
                device("com.example.app", "dup"),
            ]))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        assert_notify_ok(
            &mut response,
            0,
            vec![rejected(Some("com.example.app"), "dup")],
            0,
        )
        .await;
    }

    #[tokio::test]
    async fn blank_device_fields_are_rejected_without_dispatch() {
        let service = test_service(vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )]);

        let mut response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&payload(vec![
                device("   ", "blank-app"),
                device("com.example.app", "   "),
            ]))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        assert_notify_ok(
            &mut response,
            0,
            vec![
                rejected(None, "blank-app"),
                rejected(Some("com.example.app"), "   "),
            ],
            0,
        )
        .await;
    }

    #[tokio::test]
    async fn mixed_success_and_temporary_failure_returns_200() {
        let service = test_service(vec![
            (
                "com.example.ok",
                Arc::new(TestPushkin::new("com.example.ok", TestBehavior::Accept)),
            ),
            (
                "com.example.retry",
                Arc::new(TestPushkin::new(
                    "com.example.retry",
                    TestBehavior::TemporaryError,
                )),
            ),
        ]);

        let mut response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&payload(vec![
                device("com.example.ok", "ok"),
                device("com.example.retry", "retry"),
            ]))
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        assert_notify_ok(&mut response, 1, vec![], 1).await;
    }

    #[tokio::test]
    async fn all_temporary_failures_still_return_503() {
        let service = test_service(vec![(
            "com.example.retry",
            Arc::new(TestPushkin::new(
                "com.example.retry",
                TestBehavior::TemporaryError,
            )),
        )]);

        let response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&payload(vec![device("com.example.retry", "retry")]))
            .send(&service)
            .await;

        assert_eq!(
            response.status_code.unwrap(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("7")
        );
    }

    #[tokio::test]
    async fn notify_supports_header_idempotency_key_replay() {
        let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
        let calls = pushkin.calls.clone();
        let service = test_service_with_dedup(
            vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
            Duration::from_secs(60),
        );
        let request_body = payload(vec![device("com.example.app", "cached")]);

        for _ in 0..2 {
            let response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
                .add_header("idempotency-key", "notify-123", true)
                .json(&request_body)
                .send(&service)
                .await;
            assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn notify_duplicate_idempotency_key_with_different_body_returns_conflict() {
        let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
        let calls = pushkin.calls.clone();
        let service = test_service_with_dedup(
            vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
            Duration::from_secs(60),
        );

        let first = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .add_header("idempotency-key", "notify-123", true)
            .json(&payload(vec![device("com.example.app", "one")]))
            .send(&service)
            .await;
        assert_eq!(first.status_code.unwrap(), StatusCode::OK);

        let mut second = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .add_header("idempotency-key", "notify-123", true)
            .json(&payload(vec![device("com.example.app", "two")]))
            .send(&service)
            .await;
        assert_eq!(second.status_code.unwrap(), StatusCode::CONFLICT);
        let body = assert_notify_error(&mut second, "duplicate_conflict", true).await;
        assert_eq!(
            body["error"]["message"],
            json!("same idempotency key maps to different canonical request body")
        );

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn notify_rejects_mismatched_header_and_body_idempotency_keys() {
        let service = test_service_with_dedup(vec![], Duration::from_secs(60));
        let request_body =
            with_idempotency_key(payload(vec![device("com.example.app", "one")]), "body-key");

        let mut response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .add_header("idempotency-key", "header-key", true)
            .json(&request_body)
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
        let body = assert_notify_error(&mut response, "invalid_request", true).await;
        assert_eq!(
            body["error"]["message"],
            json!("Idempotency-Key header does not match body idempotency_key")
        );
    }

    #[tokio::test]
    async fn notify_dedup_cache_serves_repeated_success_without_redispatch() {
        let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
        let calls = pushkin.calls.clone();
        let service = test_service_with_dedup(
            vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
            Duration::from_secs(60),
        );
        let request_body = payload(vec![device("com.example.app", "cached")]);

        for _ in 0..2 {
            let response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
                .json(&request_body)
                .send(&service)
                .await;
            assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn notify_dedup_cache_matches_reordered_equivalent_payloads() {
        let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
        let calls = pushkin.calls.clone();
        let service = test_service_with_dedup(
            vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
            Duration::from_secs(60),
        );

        let first = r#"{
            "notification": {
                "event_id": "$event",
                "room_id": "!room:example.com",
                "sender": "@alice:example.com",
                "sender_display_name": "Alice",
                "type": "m.room.message",
                "content": {
                    "msgtype": "m.text",
                    "body": "hello"
                },
                "devices": [
                    {"app_id": "com.example.app", "pushkey": "cached", "pushkey_ts": 42},
                    {"app_id": "com.example.app", "pushkey": "cached", "pushkey_ts": 42}
                ]
            }
        }"#;
        let second = r#"{
            "notification": {
                "devices": [
                    {"pushkey_ts": 42, "pushkey": "cached", "app_id": "com.example.app"}
                ],
                "content": {
                    "body": "hello",
                    "msgtype": "m.text"
                },
                "type": "m.room.message",
                "sender_display_name": "Alice",
                "sender": "@alice:example.com",
                "room_id": "!room:example.com",
                "event_id": "$event"
            }
        }"#;

        for request_body in [first, second] {
            let response = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
                .add_header("content-type", "application/json", true)
                .text(request_body)
                .send(&service)
                .await;
            assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn partial_success_retries_only_failed_devices() {
        let success_pushkin = Arc::new(TestPushkin::new("com.example.ok", TestBehavior::Accept));
        let success_calls = success_pushkin.calls.clone();
        let retry_pushkin = Arc::new(TestPushkin::new(
            "com.example.retry",
            TestBehavior::TemporaryError,
        ));
        let retry_calls = retry_pushkin.calls.clone();
        let service = test_service_with_dedup(
            vec![
                ("com.example.ok", success_pushkin as Arc<dyn Pushkin>),
                ("com.example.retry", retry_pushkin as Arc<dyn Pushkin>),
            ],
            Duration::from_secs(60),
        );
        let request_body = payload(vec![
            device("com.example.ok", "ok"),
            device("com.example.retry", "retry"),
        ]);

        let first = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&request_body)
            .send(&service)
            .await;
        assert_eq!(first.status_code.unwrap(), StatusCode::OK);

        let second = TestClient::post("http://127.0.0.1/contrix/push/v1/notify")
            .json(&request_body)
            .send(&service)
            .await;
        assert_eq!(second.status_code.unwrap(), StatusCode::SERVICE_UNAVAILABLE);

        assert_eq!(success_calls.load(Ordering::SeqCst), 1);
        assert_eq!(retry_calls.load(Ordering::SeqCst), 2);
    }
}
