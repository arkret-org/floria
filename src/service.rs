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
use crate::models::{Notification, NotificationContext, NotifyResponse, RejectedDevice};

pub const MAX_REQUEST_SIZE: usize = 512 * 1024;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::with_hoop(affix_state::inject(state))
        .push(Router::with_path("api/v1/push/notify").post(notify))
        .push(Router::with_path("contrix/push/v1/notify").post(notify))
        .push(Router::with_path("health").get(health))
}

pub fn build_router_with_access_log(state: Arc<AppState>, access_log: &AccessLogConfig) -> Router {
    let use_forwarded_for = access_log.x_forwarded_for;
    Router::with_hoop(affix_state::inject(state))
        .hoop(AccessLogger { use_forwarded_for })
        .push(Router::with_path("api/v1/push/notify").post(notify))
        .push(Router::with_path("contrix/push/v1/notify").post(notify))
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

#[handler]
async fn notify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let started = Instant::now();
    let _inflight = metrics::track_inflight("V1NotifyHandler");

    let state = match depot.obtain::<Arc<AppState>>() {
        Ok(state) => state.clone(),
        Err(_) => {
            finish_text(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "application state missing",
                started,
            );
            return;
        }
    };

    let body = match req.payload_with_max_size(MAX_REQUEST_SIZE).await {
        Ok(bytes) => bytes,
        Err(ParseError::PayloadTooLarge) => {
            finish_text(
                res,
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds 512 KiB",
                started,
            );
            return;
        }
        Err(error) => {
            tracing::warn!(error = %error, "failed to read request body");
            finish_text(
                res,
                StatusCode::BAD_REQUEST,
                "failed to read request body",
                started,
            );
            return;
        }
    };

    let raw = match serde_json::from_slice::<Value>(body) {
        Ok(raw) => raw,
        Err(error) => {
            tracing::warn!(error = %error, "expected JSON request body");
            finish_text(
                res,
                StatusCode::BAD_REQUEST,
                "expected JSON request body",
                started,
            );
            return;
        }
    };

    let Some(notification_value) = raw.get("notification").cloned() else {
        finish_text(
            res,
            StatusCode::BAD_REQUEST,
            "missing notification field",
            started,
        );
        return;
    };

    if !notification_value.is_object() {
        finish_text(
            res,
            StatusCode::BAD_REQUEST,
            "notification must be an object",
            started,
        );
        return;
    }

    let notification: Notification = match serde_json::from_value(notification_value) {
        Ok(notification) => notification,
        Err(error) => {
            tracing::warn!(error = %error, "invalid notification payload");
            finish_text(
                res,
                StatusCode::BAD_REQUEST,
                "invalid notification payload",
                started,
            );
            return;
        }
    };

    let dedup_key = normalized_notify_dedup_key(&notification);
    if let Some(deduplicator) = state.notify_deduplicator.as_ref()
        && let Some(cached) = dedup_key
            .as_deref()
            .and_then(|key| deduplicator.get(key))
    {
        metrics::notify_request_cache_hit();
        tracing::info!(
            request_id = %Uuid::new_v4(),
            ttl_secs = deduplicator.ttl().as_secs(),
            "serving /notify response from normalized dedup cache"
        );
        finish_json(res, StatusCode::OK, cached.response, started);
        return;
    }
    metrics::notification_received();

    if notification.devices.is_empty() {
        finish_text(
            res,
            StatusCode::BAD_REQUEST,
            "no devices in notification",
            started,
        );
        return;
    }

    let context = NotificationContext {
        request_id: Uuid::new_v4().to_string(),
        start_time: Instant::now(),
    };

    let mut rejected = Vec::new();
    let mut delivered_now = 0usize;
    let mut skipped_delivered = 0usize;
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
                pushkey = %device.pushkey,
                "rejecting device with empty app_id or pushkey"
            );
            rejected.push(rejected_device(device, Some(&device.pushkey)));
            continue;
        }

        if !seen_devices.insert((app_id.to_owned(), pushkey.to_owned())) {
            tracing::info!(
                request_id = %context.request_id,
                app_id,
                pushkey,
                "skipping duplicate device entry"
            );
            continue;
        }

        metrics::device_push_received();
        let pushkins = state.registry.find_pushkins(&device.app_id);
        match pushkins.as_slice() {
            [] => {
                tracing::warn!(request_id = %context.request_id, app_id = %device.app_id, pushkey = %device.pushkey, "unknown app id");
                rejected.push(rejected_device(device, Some(&device.pushkey)));
                continue;
            }
            [pushkin] => {
                if let Some(dedup_key) = dedup_key.as_deref()
                    && state
                        .notify_deduplicator
                        .as_ref()
                        .is_some_and(|deduplicator| {
                            deduplicator.contains_delivered_device(dedup_key, app_id, pushkey)
                        })
                {
                    skipped_delivered += 1;
                    metrics::notify_device_skip_hit(1);
                    metrics::notify_device_skip_by_pushkin(pushkin.name(), 1);
                    tracing::info!(
                        request_id = %context.request_id,
                        app_id,
                        pushkey,
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
                        let rejected_set =
                            pushkin_rejected.iter().cloned().collect::<HashSet<String>>();
                        let delivered_targets = dispatch_targets
                            .iter()
                            .filter(|target| !rejected_set.contains(&target.pushkey))
                            .collect::<Vec<_>>();
                        if !delivered_targets.is_empty() {
                            delivered_now += delivered_targets.len();
                            mark_delivered_devices(
                                &state,
                                dedup_key.as_deref(),
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
                            pushkey = %device.pushkey,
                            "temporary dispatch failure"
                        );
                        first_temporary_error
                            .get_or_insert_with(|| (error.to_string(), error.retry_after()));
                    }
                    Err(error) if error.is_remote() => {
                        tracing::warn!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id = %device.app_id,
                            pushkey = %device.pushkey,
                            "remote dispatch failure"
                        );
                        first_remote_error.get_or_insert_with(|| error.to_string());
                    }
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id = %device.app_id,
                            pushkey = %device.pushkey,
                            "internal dispatch failure"
                        );
                        first_internal_error.get_or_insert_with(|| error.to_string());
                    }
                }
            }
            _ => {
                tracing::warn!(request_id = %context.request_id, app_id = %device.app_id, pushkey = %device.pushkey, "ambiguous app id");
                rejected.push(rejected_device(device, Some(&device.pushkey)));
            }
        }
    }

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
        let response = NotifyResponse { rejected };
        if fully_settled {
            cache_success_response(&state, dedup_key.as_deref(), &response);
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
        finish_text(res, StatusCode::INTERNAL_SERVER_ERROR, &message, started);
        return;
    }

    if let Some((message, retry_after)) = first_temporary_error {
        finish_text_with_retry_after(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            &message,
            retry_after,
            started,
        );
        return;
    }

    if let Some(message) = first_remote_error {
        finish_text(res, StatusCode::BAD_GATEWAY, &message, started);
        return;
    }

    let response = NotifyResponse { rejected };
    if fully_settled {
        cache_success_response(&state, dedup_key.as_deref(), &response);
    }
    finish_json(res, StatusCode::OK, response, started);
}

fn cache_success_response(state: &Arc<AppState>, key: Option<&str>, response: &NotifyResponse) {
    if let (Some(deduplicator), Some(key)) = (state.notify_deduplicator.as_ref(), key) {
        deduplicator.insert_success(key, response.clone());
    }
}

fn mark_delivered_devices<'a>(
    state: &Arc<AppState>,
    notification_key: Option<&str>,
    targets: impl Iterator<Item = &'a crate::pushkin::DispatchTarget>,
) {
    if let (Some(deduplicator), Some(notification_key)) =
        (state.notify_deduplicator.as_ref(), notification_key)
    {
        for target in targets {
            deduplicator.mark_delivered_device(notification_key, &target.app_id, &target.pushkey);
        }
    }
}

fn rejected_device(device: &crate::models::Device, push_key: Option<&str>) -> RejectedDevice {
    RejectedDevice::new(Some(&device.app_id), push_key.unwrap_or(&device.pushkey))
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
        normalized.insert("content".to_owned(), canonical_json_value(&Value::Object(value.clone())));
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

fn finish_text(res: &mut Response, status: StatusCode, body: &str, started: Instant) {
    res.status_code(status);
    res.render(Text::Plain(body.to_owned()));
    metrics::pushgateway_response(status);
    metrics::observe_notify_handle(status, started.elapsed());
}

fn finish_text_with_retry_after(
    res: &mut Response,
    status: StatusCode,
    body: &str,
    retry_after: Option<Duration>,
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
    finish_text(res, status, body, started);
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
        assert_eq!(
            response.take_json::<NotifyResponse>().await.unwrap(),
            NotifyResponse { rejected: vec![] }
        );
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
        assert_eq!(
            response.take_json::<NotifyResponse>().await.unwrap(),
            NotifyResponse { rejected: vec![] }
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
        assert_eq!(
            response.take_json::<NotifyResponse>().await.unwrap(),
            NotifyResponse {
                rejected: vec![rejected(Some("com.example.app"), "reject")]
            }
        );
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
        assert_eq!(
            response.take_json::<NotifyResponse>().await.unwrap(),
            NotifyResponse {
                rejected: vec![rejected(Some("com.example.app"), "spqr")]
            }
        );
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
        assert_eq!(
            response.take_json::<NotifyResponse>().await.unwrap(),
            NotifyResponse {
                rejected: vec![rejected(Some("com.example.app"), "dup")]
            }
        );
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
        assert_eq!(
            response.take_json::<NotifyResponse>().await.unwrap(),
            NotifyResponse {
                rejected: vec![
                    rejected(None, "blank-app"),
                    rejected(Some("com.example.app"), "   "),
                ]
            }
        );
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
        assert_eq!(
            response.take_json::<NotifyResponse>().await.unwrap(),
            NotifyResponse { rejected: vec![] }
        );
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
