use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use md5::{Digest, Md5};
use prometheus::{
    Histogram, IntGauge, register_histogram, register_int_counter_vec, register_int_gauge,
};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::sleep;
use uuid::Uuid;

use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{Device, Notification, NotificationContext};

use super::android::build_android_notification_payload;
use super::reqwest_support::{build_reqwest_client, header_value, parse_retry_after};
use super::{AppMatcher, ConcurrencyGate, Pushkin, inflight_limit, max_connections};

static VIVO_QUEUE_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_vivo_queue_time",
        "Time taken waiting for a vivo Push request slot"
    )
    .expect("register floria_vivo_queue_time")
});

static VIVO_REQUEST_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_vivo_request_time",
        "Time taken to send HTTP request to vivo Push"
    )
    .expect("register floria_vivo_request_time")
});

static VIVO_PENDING_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_pending_vivo_requests",
        "Number of vivo Push requests waiting for a connection"
    )
    .expect("register floria_pending_vivo_requests")
});

static VIVO_ACTIVE_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_active_vivo_requests",
        "Number of vivo Push requests in flight"
    )
    .expect("register floria_active_vivo_requests")
});

static VIVO_STATUS_CODES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_vivo_status_codes",
        "Number of HTTP response status codes received from vivo Push",
        &["pushkin", "code"]
    )
    .expect("register floria_vivo_status_codes")
});

const VIVO_MAX_TRIES: usize = 3;
const VIVO_RETRY_DELAY_BASE_SECS: u64 = 10;
const VIVO_TOKEN_CACHE_SECS: u64 = 2 * 60 * 60;
const VIVO_AUTH_URL: &str = "https://api-push.vivo.com.cn/message/auth";
const VIVO_API_BASE_URL: &str = "https://api-push.vivo.com.cn";

pub struct VivoPushkin {
    matcher: AppMatcher,
    gate: ConcurrencyGate,
    connection_semaphore: Arc<Semaphore>,
    client: Client,
    auth: VivoAuth,
    auth_endpoint: String,
    send_endpoint: String,
    token_cache: Mutex<Option<CachedVivoToken>>,
    config: VivoConfig,
}

#[derive(Debug, Clone)]
struct VivoAuth {
    app_id: Value,
    app_id_string: String,
    app_key: String,
    app_secret: String,
}

#[derive(Debug, Clone)]
struct VivoConfig {
    notify_type: u64,
    time_to_live: Option<u64>,
    skip_type: u64,
    skip_content: Option<String>,
    network_type: Option<i64>,
    classification: Option<u64>,
    category: Option<String>,
    push_mode: Option<u64>,
    notify_id: Option<u64>,
    profile_id: Option<String>,
    send_online: Option<bool>,
    foreground_show: Option<bool>,
    timed_display: Option<Map<String, Value>>,
    audit_review: Option<Value>,
    extra: Map<String, Value>,
    client_custom_map: Map<String, Value>,
    send_badge_counts: bool,
}

struct CachedVivoToken {
    token: String,
    expires_at: Instant,
}

impl VivoPushkin {
    pub fn new(name: String, app: &AppConfig, config: &Config) -> Result<Self> {
        app.warn_unknown_fields(
            &name,
            &[
                "app_id",
                "app_key",
                "app_secret",
                "auth_url",
                "api_base_url",
                "notify_type",
                "time_to_live",
                "skip_type",
                "skip_content",
                "network_type",
                "classification",
                "category",
                "push_mode",
                "notify_id",
                "profile_id",
                "send_online",
                "foreground_show",
                "timed_display",
                "audit_review",
                "extra",
                "client_custom_map",
                "send_badge_counts",
                "max_connections",
                "inflight_request_limit",
            ],
        );

        let app_id = app_id_value(app, "app_id")?.context("vivo Push config requires app_id")?;
        let app_id_string = json_value_string(&app_id);
        let app_key = app
            .get_string("app_key")?
            .context("vivo Push config requires app_key")?;
        let app_secret = app
            .get_string("app_secret")?
            .context("vivo Push config requires app_secret")?;
        let auth_url = app
            .get_string("auth_url")?
            .unwrap_or_else(|| VIVO_AUTH_URL.to_owned());
        let api_base_url = app
            .get_string("api_base_url")?
            .unwrap_or_else(|| VIVO_API_BASE_URL.to_owned())
            .trim_end_matches('/')
            .to_owned();

        Ok(Self {
            matcher: AppMatcher::new(name)?,
            gate: ConcurrencyGate::new(inflight_limit(app)?),
            connection_semaphore: Arc::new(Semaphore::new(max_connections(app)?.max(1))),
            client: build_reqwest_client(config, "floria")?,
            auth: VivoAuth {
                app_id,
                app_id_string,
                app_key,
                app_secret,
            },
            auth_endpoint: auth_url,
            send_endpoint: format!("{api_base_url}/message/send"),
            token_cache: Mutex::new(None),
            config: VivoConfig {
                notify_type: app.get_u64("notify_type")?.unwrap_or(4),
                time_to_live: app.get_u64("time_to_live")?,
                skip_type: app.get_u64("skip_type")?.unwrap_or(1),
                skip_content: app.get_string("skip_content")?,
                network_type: app
                    .extra
                    .get("network_type")
                    .map(value_as_i64)
                    .transpose()?,
                classification: app.get_u64("classification")?,
                category: app.get_string("category")?,
                push_mode: app.get_u64("push_mode")?,
                notify_id: app.get_u64("notify_id")?,
                profile_id: app.get_string("profile_id")?,
                send_online: app.get_bool("send_online")?,
                foreground_show: app.get_bool("foreground_show")?,
                timed_display: app.get_object("timed_display")?,
                audit_review: app.extra.get("audit_review").cloned(),
                extra: app.get_object("extra")?.unwrap_or_default(),
                client_custom_map: app.get_object("client_custom_map")?.unwrap_or_default(),
                send_badge_counts: app.get_bool("send_badge_counts")?.unwrap_or(true),
            },
        })
    }

    async fn access_token(&self) -> Result<String, DispatchError> {
        {
            let cache = self.token_cache.lock().await;
            if let Some(token) = cache.as_ref()
                && token.expires_at > Instant::now() + Duration::from_secs(30)
            {
                return Ok(token.token.clone());
            }
        }

        self.fetch_access_token().await
    }

    async fn invalidate_token(&self) {
        let mut cache = self.token_cache.lock().await;
        *cache = None;
    }

    async fn fetch_access_token(&self) -> Result<String, DispatchError> {
        let timestamp = current_timestamp_millis()?;
        let body = self.build_auth_request(&timestamp);

        let response = self
            .client
            .post(&self.auth_endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                DispatchError::temporary(format!("vivo Push auth request failed: {error}"), None)
            })?;
        let status = response.status();
        let body = response.text().await.map_err(|error| {
            DispatchError::remote(format!("failed to read vivo Push auth response: {error}"))
        })?;

        match status.as_u16() {
            429 => Err(DispatchError::temporary(
                vivo_error_message(&body, status),
                Some(Duration::from_secs(VIVO_RETRY_DELAY_BASE_SECS)),
            )),
            500..=599 => Err(DispatchError::temporary(
                vivo_error_message(&body, status),
                None,
            )),
            200..=299 => {
                let response =
                    serde_json::from_str::<VivoAuthResponse>(&body).map_err(|error| {
                        DispatchError::remote(format!(
                            "failed to parse vivo Push auth response: {error}"
                        ))
                    })?;
                if response.result != 0 {
                    return Err(DispatchError::remote(format!(
                        "vivo Push auth rejected request: {} {}",
                        response.result, response.desc
                    )));
                }
                let token = response.auth_token.ok_or_else(|| {
                    DispatchError::remote("vivo Push auth response did not include authToken")
                })?;
                let mut cache = self.token_cache.lock().await;
                *cache = Some(CachedVivoToken {
                    token: token.clone(),
                    expires_at: Instant::now() + Duration::from_secs(VIVO_TOKEN_CACHE_SECS),
                });
                Ok(token)
            }
            _ => Err(DispatchError::remote(vivo_error_message(&body, status))),
        }
    }

    fn build_auth_request(&self, timestamp: &str) -> Value {
        json!({
            "appId": self.auth.app_id,
            "appKey": self.auth.app_key,
            "timestamp": timestamp,
            "sign": vivo_sign(
                &self.auth.app_id_string,
                &self.auth.app_key,
                timestamp,
                &self.auth.app_secret,
            ),
        })
    }

    fn build_request_body(
        &self,
        notification: &Notification,
        device: &Device,
    ) -> Result<Map<String, Value>, DispatchError> {
        let default_payload = device
            .default_payload()
            .map_err(|_| DispatchError::remote("vivo Push default_payload must be an object"))?;
        let Some(payload) = build_android_notification_payload(
            notification,
            default_payload,
            self.config.send_badge_counts,
        ) else {
            return Ok(Map::new());
        };

        let mut body = Map::new();
        body.insert("appId".to_owned(), self.auth.app_id.clone());
        body.insert("regId".to_owned(), Value::String(device.pushkey.clone()));
        body.insert(
            "notifyType".to_owned(),
            Value::Number(self.config.notify_type.into()),
        );
        body.insert("title".to_owned(), Value::String(payload.title));
        body.insert("content".to_owned(), Value::String(payload.body));
        body.insert(
            "skipType".to_owned(),
            Value::Number(self.config.skip_type.into()),
        );
        if let Some(skip_content) = &self.config.skip_content {
            body.insert(
                "skipContent".to_owned(),
                Value::String(skip_content.clone()),
            );
        }
        if let Some(time_to_live) = self.config.time_to_live {
            body.insert("timeToLive".to_owned(), Value::Number(time_to_live.into()));
        }
        if let Some(network_type) = self.config.network_type {
            body.insert("networkType".to_owned(), Value::Number(network_type.into()));
        }
        if let Some(classification) = self.config.classification {
            body.insert(
                "classification".to_owned(),
                Value::Number(classification.into()),
            );
        }
        if let Some(category) = &self.config.category {
            body.insert("category".to_owned(), Value::String(category.clone()));
        }
        if let Some(push_mode) = self.config.push_mode {
            body.insert("pushMode".to_owned(), Value::Number(push_mode.into()));
        }
        if let Some(notify_id) = self.config.notify_id {
            body.insert("notifyId".to_owned(), Value::Number(notify_id.into()));
        }
        if let Some(profile_id) = &self.config.profile_id {
            body.insert("profileId".to_owned(), Value::String(profile_id.clone()));
        }
        if let Some(send_online) = self.config.send_online {
            body.insert("sendOnline".to_owned(), Value::Bool(send_online));
        }
        if let Some(foreground_show) = self.config.foreground_show {
            body.insert("foregroundShow".to_owned(), Value::Bool(foreground_show));
        }
        if let Some(timed_display) = &self.config.timed_display {
            body.insert(
                "timedDisplay".to_owned(),
                Value::Object(timed_display.clone()),
            );
        }
        if let Some(audit_review) = &self.config.audit_review {
            body.insert("auditReview".to_owned(), audit_review.clone());
        }
        if !self.config.extra.is_empty() {
            body.insert("extra".to_owned(), Value::Object(self.config.extra.clone()));
        }
        let client_custom_map =
            vivo_client_custom_map(&payload.data, &self.config.client_custom_map);
        if !client_custom_map.is_empty() {
            body.insert(
                "clientCustomMap".to_owned(),
                Value::Object(client_custom_map),
            );
        }
        body.insert(
            "requestId".to_owned(),
            Value::String(Uuid::new_v4().to_string()),
        );

        Ok(body)
    }

    async fn send_once(
        &self,
        notification: &Notification,
        device: &Device,
    ) -> Result<Vec<String>, DispatchError> {
        let token = self.access_token().await?;
        let body = self.build_request_body(notification, device)?;
        if body.is_empty() {
            return Ok(vec![]);
        }

        VIVO_PENDING_REQUESTS.inc();
        let queue_started = Instant::now();
        let _connection_permit = self
            .connection_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| {
                VIVO_PENDING_REQUESTS.dec();
                DispatchError::internal("vivo Push connection semaphore closed")
            })?;
        VIVO_PENDING_REQUESTS.dec();
        VIVO_QUEUE_TIME.observe(queue_started.elapsed().as_secs_f64());

        let mut headers = HeaderMap::new();
        headers.insert("authToken", header_value(&token)?);
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        VIVO_ACTIVE_REQUESTS.inc();
        let request_started = Instant::now();
        let response = self
            .client
            .post(&self.send_endpoint)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                VIVO_ACTIVE_REQUESTS.dec();
                VIVO_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());
                DispatchError::temporary(format!("vivo Push request failed: {error}"), None)
            })?;
        VIVO_ACTIVE_REQUESTS.dec();
        VIVO_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());

        let status = response.status();
        VIVO_STATUS_CODES
            .with_label_values(&[self.name(), &status.as_u16().to_string()])
            .inc();
        let retry_after = parse_retry_after(response.headers());
        let body = response.text().await.map_err(|error| {
            DispatchError::remote(format!("failed to read vivo Push response: {error}"))
        })?;

        if status == StatusCode::UNAUTHORIZED
            || status == StatusCode::FORBIDDEN
            || looks_like_vivo_auth_issue(&body)
        {
            self.invalidate_token().await;
            return Err(DispatchError::temporary(
                vivo_error_message(&body, status),
                retry_after.or(Some(Duration::from_secs(VIVO_RETRY_DELAY_BASE_SECS))),
            ));
        }

        self.handle_response(status, retry_after, &body, device)
    }

    fn handle_response(
        &self,
        status: StatusCode,
        retry_after: Option<Duration>,
        body: &str,
        device: &Device,
    ) -> Result<Vec<String>, DispatchError> {
        match status.as_u16() {
            429 => Err(DispatchError::temporary(
                vivo_error_message(body, status),
                retry_after.or(Some(Duration::from_secs(VIVO_RETRY_DELAY_BASE_SECS))),
            )),
            500..=599 => Err(DispatchError::temporary(
                vivo_error_message(body, status),
                retry_after,
            )),
            200..=299 => match serde_json::from_str::<VivoSendResponse>(body) {
                Ok(response) if response.result == 0 => Ok(vec![]),
                Ok(response) if response.is_invalid_registration(device) => {
                    Ok(vec![device.pushkey.clone()])
                }
                Ok(response) => Err(DispatchError::remote(format!(
                    "vivo Push rejected request: {} {}",
                    response.result, response.desc
                ))),
                Err(_) if looks_like_invalid_registration(body) => Ok(vec![device.pushkey.clone()]),
                Err(_) => Ok(vec![]),
            },
            _ if looks_like_invalid_registration(body) => Ok(vec![device.pushkey.clone()]),
            _ => Err(DispatchError::remote(vivo_error_message(body, status))),
        }
    }
}

#[async_trait]
impl Pushkin for VivoPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn kind(&self) -> &'static str {
        "vivo"
    }

    fn handles_appid(&self, appid: &str) -> bool {
        self.matcher.handles_appid(appid)
    }

    async fn dispatch_notification(
        &self,
        notification: &Notification,
        device: &Device,
        _context: &NotificationContext,
    ) -> Result<Vec<String>, DispatchError> {
        let _permit = self.gate.acquire(self.name())?;

        if device.pushkey.trim().is_empty() {
            tracing::warn!("rejecting vivo Push device due to empty regId");
            return Ok(vec![device.pushkey.clone()]);
        }

        if device.default_payload().is_err() {
            tracing::warn!(
                pushkey_hash = %device.redacted_pushkey(),
                "rejecting vivo Push pushkey due to invalid default_payload"
            );
            return Ok(vec![device.pushkey.clone()]);
        }

        for attempt in 0..VIVO_MAX_TRIES {
            match self.send_once(notification, device).await {
                Ok(result) => return Ok(result),
                Err(error @ DispatchError::Temporary { .. }) if attempt + 1 < VIVO_MAX_TRIES => {
                    let retry_after = error.retry_after().unwrap_or_else(|| {
                        Duration::from_secs(VIVO_RETRY_DELAY_BASE_SECS * (1_u64 << attempt))
                    });
                    sleep(retry_after).await;
                }
                Err(error) => return Err(error),
            }
        }

        Err(DispatchError::remote("vivo Push retried too many times"))
    }
}

fn current_timestamp_millis() -> Result<String, DispatchError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| DispatchError::internal(format!("system clock error: {error}")))?
        .as_millis()
        .to_string())
}

fn app_id_value(app: &AppConfig, key: &str) -> Result<Option<Value>> {
    match app.extra.get(key) {
        Some(Value::String(value)) => Ok(Some(Value::String(value.clone()))),
        Some(Value::Number(value)) => Ok(Some(Value::Number(value.clone()))),
        Some(value) => Err(anyhow!(
            "{key} must be a string or unsigned integer, got {}",
            crate::config::value_type(value)
        )),
        None => Ok(None),
    }
}

fn json_value_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        _ => String::new(),
    }
}

fn value_as_i64(value: &Value) -> Result<i64> {
    match value {
        Value::Number(value) => value
            .as_i64()
            .ok_or_else(|| anyhow!("network_type must be a signed integer")),
        other => Err(anyhow!(
            "network_type must be a signed integer, got {}",
            crate::config::value_type(other)
        )),
    }
}

fn vivo_sign(app_id: &str, app_key: &str, timestamp: &str, app_secret: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(app_id.as_bytes());
    hasher.update(app_key.as_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(app_secret.as_bytes());
    hex::encode(hasher.finalize())
}

fn vivo_client_custom_map(
    payload_data: &Map<String, Value>,
    config_map: &Map<String, Value>,
) -> Map<String, Value> {
    let mut map = payload_data
        .iter()
        .map(|(key, value)| (key.clone(), vivo_json_scalar(value)))
        .collect::<Map<_, _>>();
    map.extend(
        config_map
            .iter()
            .map(|(key, value)| (key.clone(), vivo_json_scalar(value))),
    );
    map
}

fn vivo_json_scalar(value: &Value) -> Value {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.clone(),
        Value::Array(_) | Value::Object(_) => {
            Value::String(serde_json::to_string(value).unwrap_or_default())
        }
    }
}

fn looks_like_invalid_registration(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    (lower.contains("regid") || lower.contains("userid") || lower.contains("alias"))
        && (lower.contains("invalid")
            || lower.contains("not exist")
            || lower.contains("unregister")
            || lower.contains("expired"))
}

fn looks_like_vivo_auth_issue(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("authtoken")
        && (lower.contains("invalid") || lower.contains("expired") || lower.contains("not exist"))
}

fn vivo_error_message(body: &str, status: StatusCode) -> String {
    serde_json::from_str::<VivoSendResponse>(body)
        .ok()
        .map(|response| {
            format!(
                "vivo Push rejected request: {} {}",
                response.result, response.desc
            )
        })
        .unwrap_or_else(|| format!("vivo Push rejected request: {status} {body}"))
}

#[derive(Debug, Deserialize)]
struct VivoAuthResponse {
    result: i64,
    #[serde(default)]
    desc: String,
    #[serde(default, rename = "authToken")]
    auth_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VivoSendResponse {
    result: i64,
    #[serde(default)]
    desc: String,
    #[serde(default, rename = "invalidUser")]
    invalid_user: Option<VivoInvalidUser>,
    #[serde(default, rename = "invalidUsers")]
    invalid_users: Vec<VivoInvalidUser>,
}

impl VivoSendResponse {
    fn is_invalid_registration(&self, device: &Device) -> bool {
        self.result == 10302
            || self
                .invalid_user
                .as_ref()
                .is_some_and(|user| user.userid.as_deref() == Some(device.pushkey.as_str()))
            || self
                .invalid_users
                .iter()
                .any(|user| user.userid.as_deref() == Some(device.pushkey.as_str()))
            || looks_like_invalid_registration(&self.desc)
    }
}

#[derive(Debug, Deserialize)]
struct VivoInvalidUser {
    #[serde(default)]
    userid: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Counts, Device, Notification, Tweaks};

    fn device() -> Device {
        Device {
            app_id: "com.example.vivo".to_owned(),
            pushkey: "regid".to_owned(),
            pushkey_ts: 42,
            data: Some(
                json!({
                    "default_payload": {
                        "client": "android"
                    }
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
            tweaks: Tweaks::default(),
        }
    }

    fn notification() -> Notification {
        Notification {
            flow_name: Some("Mission Control".to_owned()),
            space_name: None,
            prio: None,
            membership: None,
            sender_display_name: Some("Major Tom".to_owned()),
            content: Some(
                json!({
                    "msgtype": "m.text",
                    "body": "Ground control to Major Tom"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
            event_id: Some("cx:event:01JS0EV000000000000000000".to_owned()),
            message_id: Some("cx:message:01JS0MSG0000000000000000".to_owned()),
            flow_id: Some("cx:flow:01JS0FLOW000000000000000".to_owned()),
            space_id: Some("cx:space:01JS0SP000000000000000000".to_owned()),
            user_is_target: Some(true),
            r#type: Some("cx.message.create".to_owned()),
            sender: Some("@major:example.com".to_owned()),
            push_hint: None,
            devices: vec![device()],
            counts: Counts {
                unread: Some(2),
                missed_calls: Some(1),
                highlight_count: None,
            },
        }
    }

    fn pushkin() -> VivoPushkin {
        VivoPushkin {
            matcher: AppMatcher::new("com.example.vivo".to_owned()).unwrap(),
            gate: ConcurrencyGate::new(1),
            connection_semaphore: Arc::new(Semaphore::new(1)),
            client: Client::builder().build().unwrap(),
            auth: VivoAuth {
                app_id: Value::Number(10004.into()),
                app_id_string: "10004".to_owned(),
                app_key: "25509283-3767-4b9e-83fe-b6e55ac6243e".to_owned(),
                app_secret: "7265f2a4-ebbb-44bf-88b9-b03e67dfdc21".to_owned(),
            },
            auth_endpoint: VIVO_AUTH_URL.to_owned(),
            send_endpoint: format!("{VIVO_API_BASE_URL}/message/send"),
            token_cache: Mutex::new(None),
            config: VivoConfig {
                notify_type: 4,
                time_to_live: Some(3600),
                skip_type: 4,
                skip_content: Some("intent:#Intent;end".to_owned()),
                network_type: Some(1),
                classification: Some(1),
                category: Some("IM".to_owned()),
                push_mode: Some(0),
                notify_id: Some(7),
                profile_id: Some("profile-1".to_owned()),
                send_online: Some(false),
                foreground_show: Some(true),
                timed_display: Some(
                    json!({
                        "overtimeDisplay": true,
                        "showStartTime": 1687336620000_u64,
                        "showEndTime": 1687336650000_u64
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
                audit_review: None,
                extra: json!({
                    "callback.id": "100"
                })
                .as_object()
                .unwrap()
                .clone(),
                client_custom_map: json!({
                    "manual": "override"
                })
                .as_object()
                .unwrap()
                .clone(),
                send_badge_counts: true,
            },
        }
    }

    #[test]
    fn vivo_sign_matches_official_example() {
        assert_eq!(
            vivo_sign(
                "10004",
                "25509283-3767-4b9e-83fe-b6e55ac6243e",
                "1501484120000",
                "7265f2a4-ebbb-44bf-88b9-b03e67dfdc21",
            ),
            "fe3b46a2befc60334c2388676a752bd6"
        );
    }

    #[test]
    fn builds_request_body_with_expected_fields() {
        let body = Value::Object(
            pushkin()
                .build_request_body(&notification(), &device())
                .unwrap(),
        );

        assert_eq!(
            body.pointer("/regId"),
            Some(&Value::String("regid".to_owned()))
        );
        assert_eq!(body.pointer("/notifyType"), Some(&Value::Number(4.into())));
        assert_eq!(body.pointer("/skipType"), Some(&Value::Number(4.into())));
        assert_eq!(
            body.pointer("/category"),
            Some(&Value::String("IM".to_owned()))
        );
        assert_eq!(
            body.pointer("/clientCustomMap/client"),
            Some(&Value::String("android".to_owned()))
        );
        assert_eq!(
            body.pointer("/clientCustomMap/content")
                .and_then(Value::as_str)
                .map(|value| value.contains("Ground control")),
            Some(true)
        );
        assert!(body.pointer("/requestId").and_then(Value::as_str).is_some());
    }

    #[test]
    fn invalid_registration_is_rejected() {
        let result = pushkin()
            .handle_response(
                StatusCode::OK,
                None,
                r#"{"result":10302,"desc":"regId 不合法","invalidUser":{"status":1,"userid":"regid"}}"#,
                &device(),
            )
            .unwrap();

        assert_eq!(result, vec!["regid".to_owned()]);
    }
}
