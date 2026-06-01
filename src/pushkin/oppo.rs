use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use async_trait::async_trait;
use prometheus::{
    Histogram, IntGauge, register_histogram, register_int_counter_vec, register_int_gauge,
};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::sleep;

use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{Device, Notification, NotificationContext};

use super::android::{AndroidNotificationPayload, build_android_notification_payload};
use super::reqwest_support::{build_reqwest_client, header_value, parse_retry_after};
use super::{AppMatcher, ConcurrencyGate, Pushkin, inflight_limit, max_connections};

static OPPO_QUEUE_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_oppo_queue_time",
        "Time taken waiting for an OPPO Push request slot"
    )
    .expect("register floria_oppo_queue_time")
});

static OPPO_REQUEST_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_oppo_request_time",
        "Time taken to send HTTP request to OPPO Push"
    )
    .expect("register floria_oppo_request_time")
});

static OPPO_PENDING_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_pending_oppo_requests",
        "Number of OPPO Push requests waiting for a connection"
    )
    .expect("register floria_pending_oppo_requests")
});

static OPPO_ACTIVE_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_active_oppo_requests",
        "Number of OPPO Push requests in flight"
    )
    .expect("register floria_active_oppo_requests")
});

static OPPO_STATUS_CODES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_oppo_status_codes",
        "Number of HTTP response status codes received from OPPO Push",
        &["pushkin", "code"]
    )
    .expect("register floria_oppo_status_codes")
});

const OPPO_MAX_TRIES: usize = 3;
const OPPO_RETRY_DELAY_BASE_SECS: u64 = 10;
const OPPO_TOKEN_CACHE_SECS: u64 = 3600;
const OPPO_AUTH_URL: &str = "https://api.push.oppomobile.com/server/v1/auth";
const OPPO_API_BASE_URL: &str = "https://api.push.oppomobile.com";

pub struct OppoPushkin {
    matcher: AppMatcher,
    vendor: OppoVendor,
    gate: ConcurrencyGate,
    connection_semaphore: Arc<Semaphore>,
    client: Client,
    auth: OppoAuth,
    auth_endpoint: String,
    send_endpoint: String,
    token_cache: Mutex<Option<CachedOppoToken>>,
    config: OppoConfig,
}

#[derive(Debug, Clone, Copy)]
enum OppoVendor {
    Oppo,
    Oneplus,
}

#[derive(Debug, Clone)]
struct OppoAuth {
    app_key: String,
    master_secret: String,
}

#[derive(Debug, Clone)]
struct OppoConfig {
    request: Map<String, Value>,
    notification: Map<String, Value>,
    click_action_type: Option<u64>,
    action_parameters: Option<Map<String, Value>>,
    channel_id: Option<String>,
    send_badge_counts: bool,
}

struct CachedOppoToken {
    token: String,
    expires_at: Instant,
}

impl OppoPushkin {
    pub fn new(name: String, app: &AppConfig, config: &Config) -> Result<Self> {
        Self::new_with_vendor(name, app, config, OppoVendor::Oppo)
    }

    pub fn new_oneplus(name: String, app: &AppConfig, config: &Config) -> Result<Self> {
        Self::new_with_vendor(name, app, config, OppoVendor::Oneplus)
    }

    fn new_with_vendor(
        name: String,
        app: &AppConfig,
        config: &Config,
        vendor: OppoVendor,
    ) -> Result<Self> {
        app.warn_unknown_fields(
            &name,
            &[
                "app_key",
                "master_secret",
                "app_secret",
                "auth_url",
                "api_base_url",
                "request",
                "notification",
                "click_action_type",
                "action_parameters",
                "channel_id",
                "send_badge_counts",
                "max_connections",
                "inflight_request_limit",
            ],
        );

        let app_key = app
            .get_string("app_key")?
            .context("OPPO Push config requires app_key")?;
        let master_secret = app
            .get_string("master_secret")?
            .or(app.get_string("app_secret")?)
            .context("OPPO Push config requires master_secret or app_secret")?;
        let auth_url = app
            .get_string("auth_url")?
            .unwrap_or_else(|| OPPO_AUTH_URL.to_owned());
        let api_base_url = app
            .get_string("api_base_url")?
            .unwrap_or_else(|| OPPO_API_BASE_URL.to_owned())
            .trim_end_matches('/')
            .to_owned();

        Ok(Self {
            matcher: AppMatcher::new(name)?,
            vendor,
            gate: ConcurrencyGate::new(inflight_limit(app)?),
            connection_semaphore: Arc::new(Semaphore::new(max_connections(app)?.max(1))),
            client: build_reqwest_client(config, "floria")?,
            auth: OppoAuth {
                app_key,
                master_secret,
            },
            auth_endpoint: auth_url,
            send_endpoint: format!("{api_base_url}/server/v1/message/notification/unicast"),
            token_cache: Mutex::new(None),
            config: OppoConfig {
                request: app.get_object("request")?.unwrap_or_default(),
                notification: app.get_object("notification")?.unwrap_or_default(),
                click_action_type: app.get_u64("click_action_type")?,
                action_parameters: app.get_object("action_parameters")?,
                channel_id: app.get_string("channel_id")?,
                send_badge_counts: app.get_bool("send_badge_counts")?.unwrap_or(true),
            },
        })
    }

    fn vendor_name(&self) -> &'static str {
        match self.vendor {
            OppoVendor::Oppo => "OPPO Push",
            OppoVendor::Oneplus => "OnePlus Push",
        }
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
        let sign = oppo_sign(&self.auth.app_key, &timestamp, &self.auth.master_secret);
        let body = json!({
            "app_key": self.auth.app_key,
            "timestamp": timestamp,
            "sign": sign,
        });

        let response = self
            .client
            .post(&self.auth_endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                DispatchError::temporary(
                    format!("{} auth request failed: {error}", self.vendor_name()),
                    None,
                )
            })?;
        let status = response.status();
        let body = response.text().await.map_err(|error| {
            DispatchError::remote(format!(
                "failed to read {} auth response: {error}",
                self.vendor_name()
            ))
        })?;

        match status.as_u16() {
            429 => Err(DispatchError::temporary(
                oppo_error_message(self.vendor_name(), &body, status),
                Some(Duration::from_secs(OPPO_RETRY_DELAY_BASE_SECS)),
            )),
            500..=599 => Err(DispatchError::temporary(
                oppo_error_message(self.vendor_name(), &body, status),
                None,
            )),
            200..=299 => {
                let response =
                    serde_json::from_str::<OppoAuthResponse>(&body).map_err(|error| {
                        DispatchError::remote(format!(
                            "failed to parse {} auth response: {error}",
                            self.vendor_name()
                        ))
                    })?;
                if !response.is_success() {
                    return Err(DispatchError::remote(format!(
                        "{} auth rejected request: {}",
                        self.vendor_name(),
                        response.message().unwrap_or_else(|| body.clone())
                    )));
                }
                let token = response.auth_token().ok_or_else(|| {
                    DispatchError::remote(format!(
                        "{} auth response did not include auth_token",
                        self.vendor_name()
                    ))
                })?;
                let expires_at = Instant::now() + response.expires_in();
                let mut cache = self.token_cache.lock().await;
                *cache = Some(CachedOppoToken {
                    token: token.clone(),
                    expires_at,
                });
                Ok(token)
            }
            _ => Err(DispatchError::remote(oppo_error_message(
                self.vendor_name(),
                &body,
                status,
            ))),
        }
    }

    fn build_request_body(
        &self,
        device: &Device,
        payload: AndroidNotificationPayload,
    ) -> Map<String, Value> {
        let mut body = self.config.request.clone();
        body.insert("target_type".to_owned(), Value::Number(2.into()));
        body.insert(
            "target_value".to_owned(),
            Value::String(device.push_key.clone()),
        );
        body.insert(
            "notification".to_owned(),
            Value::Object(self.notification_payload(payload)),
        );
        body
    }

    fn notification_payload(&self, payload: AndroidNotificationPayload) -> Map<String, Value> {
        let mut notification = self.config.notification.clone();
        notification.insert("title".to_owned(), Value::String(payload.title));
        notification.insert("content".to_owned(), Value::String(payload.body));
        if let Some(click_action_type) = self.config.click_action_type {
            notification.insert(
                "click_action_type".to_owned(),
                Value::Number(click_action_type.into()),
            );
        }
        if let Some(channel_id) = &self.config.channel_id {
            notification.insert("channel_id".to_owned(), Value::String(channel_id.clone()));
        }
        if let Some(action_parameters) = &self.config.action_parameters {
            notification.insert(
                "action_parameters".to_owned(),
                Value::Object(action_parameters.clone()),
            );
        }
        notification
    }

    async fn send_once(
        &self,
        device: &Device,
        payload: AndroidNotificationPayload,
    ) -> Result<Vec<String>, DispatchError> {
        let token = self.access_token().await?;
        let body = self.build_request_body(device, payload);

        OPPO_PENDING_REQUESTS.inc();
        let queue_started = Instant::now();
        let _connection_permit = self
            .connection_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| {
                OPPO_PENDING_REQUESTS.dec();
                DispatchError::internal("OPPO Push connection semaphore closed")
            })?;
        OPPO_PENDING_REQUESTS.dec();
        OPPO_QUEUE_TIME.observe(queue_started.elapsed().as_secs_f64());

        let mut headers = HeaderMap::new();
        headers.insert("auth_token", header_value(&token)?);
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        OPPO_ACTIVE_REQUESTS.inc();
        let request_started = Instant::now();
        let response = self
            .client
            .post(&self.send_endpoint)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                OPPO_ACTIVE_REQUESTS.dec();
                OPPO_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());
                DispatchError::temporary(
                    format!("{} request failed: {error}", self.vendor_name()),
                    None,
                )
            })?;
        OPPO_ACTIVE_REQUESTS.dec();
        OPPO_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());

        let status = response.status();
        OPPO_STATUS_CODES
            .with_label_values(&[self.name(), &status.as_u16().to_string()])
            .inc();
        let retry_after = parse_retry_after(response.headers());
        let body = response.text().await.map_err(|error| {
            DispatchError::remote(format!(
                "failed to read {} response: {error}",
                self.vendor_name()
            ))
        })?;

        if status == StatusCode::UNAUTHORIZED
            || status == StatusCode::FORBIDDEN
            || looks_like_oppo_auth_issue(&body)
        {
            self.invalidate_token().await;
            return Err(DispatchError::temporary(
                oppo_error_message(self.vendor_name(), &body, status),
                retry_after.or(Some(Duration::from_secs(OPPO_RETRY_DELAY_BASE_SECS))),
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
                oppo_error_message(self.vendor_name(), body, status),
                retry_after.or(Some(Duration::from_secs(OPPO_RETRY_DELAY_BASE_SECS))),
            )),
            500..=599 => Err(DispatchError::temporary(
                oppo_error_message(self.vendor_name(), body, status),
                retry_after,
            )),
            200..=299 => match serde_json::from_str::<OppoSendResponse>(body) {
                Ok(response) if response.is_success() => Ok(vec![]),
                Ok(response) if response.is_invalid_target() => Ok(vec![device.push_key.clone()]),
                Ok(response) => Err(DispatchError::remote(format!(
                    "{} rejected request: {}",
                    self.vendor_name(),
                    response.message().unwrap_or_else(|| body.to_owned())
                ))),
                Err(_) if looks_like_invalid_target(body) => Ok(vec![device.push_key.clone()]),
                Err(_) => Ok(vec![]),
            },
            _ if looks_like_invalid_target(body) => Ok(vec![device.push_key.clone()]),
            _ => Err(DispatchError::remote(oppo_error_message(
                self.vendor_name(),
                body,
                status,
            ))),
        }
    }
}

#[async_trait]
impl Pushkin for OppoPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn kind(&self) -> &'static str {
        match self.vendor {
            OppoVendor::Oppo => "oppo",
            OppoVendor::Oneplus => "oneplus",
        }
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

        if device.push_key.trim().is_empty() {
            tracing::warn!(
                "rejecting {} device due to empty target_value",
                self.vendor_name()
            );
            return Ok(vec![device.push_key.clone()]);
        }

        let default_payload = match device.default_payload() {
            Ok(default_payload) => default_payload,
            Err(_) => {
                tracing::warn!(
                    push_key_hash = %device.redacted_push_key(),
                    "rejecting {} push_key due to invalid default_payload",
                    self.vendor_name()
                );
                return Ok(vec![device.push_key.clone()]);
            }
        };
        let Some(payload) = build_android_notification_payload(
            notification,
            default_payload,
            self.config.send_badge_counts,
        ) else {
            return Ok(vec![]);
        };

        for attempt in 0..OPPO_MAX_TRIES {
            match self.send_once(device, payload.clone()).await {
                Ok(result) => return Ok(result),
                Err(error @ DispatchError::Temporary { .. }) if attempt + 1 < OPPO_MAX_TRIES => {
                    let retry_after = error.retry_after().unwrap_or_else(|| {
                        Duration::from_secs(OPPO_RETRY_DELAY_BASE_SECS * (1_u64 << attempt))
                    });
                    sleep(retry_after).await;
                }
                Err(error) => return Err(error),
            }
        }

        Err(DispatchError::remote(format!(
            "{} retried too many times",
            self.vendor_name()
        )))
    }
}

fn current_timestamp_millis() -> Result<String, DispatchError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| DispatchError::internal(format!("system clock error: {error}")))?
        .as_millis()
        .to_string())
}

fn oppo_sign(app_key: &str, timestamp: &str, master_secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(app_key.as_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(master_secret.as_bytes());
    hex::encode(hasher.finalize())
}

fn looks_like_invalid_target(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    (lower.contains("target")
        || lower.contains("registration")
        || lower.contains("token")
        || lower.contains("userid"))
        && (lower.contains("invalid")
            || lower.contains("not exist")
            || lower.contains("unregister")
            || lower.contains("expired"))
}

fn looks_like_oppo_auth_issue(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("auth")
        && (lower.contains("invalid") || lower.contains("expired") || lower.contains("token"))
}

fn oppo_error_message(vendor_name: &str, body: &str, status: StatusCode) -> String {
    serde_json::from_str::<OppoSendResponse>(body)
        .ok()
        .and_then(|response| response.message())
        .map(|message| format!("{vendor_name} rejected request: {message}"))
        .unwrap_or_else(|| format!("{vendor_name} rejected request: {status} {body}"))
}

#[derive(Debug, Deserialize)]
struct OppoAuthResponse {
    #[serde(default)]
    code: Option<i64>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    msg: Option<String>,
    #[serde(default, alias = "authToken")]
    auth_token: Option<String>,
    #[serde(default)]
    data: Option<OppoAuthData>,
}

impl OppoAuthResponse {
    fn is_success(&self) -> bool {
        self.code.unwrap_or(0) == 0
    }

    fn message(self) -> Option<String> {
        self.message.or(self.msg)
    }

    fn auth_token(&self) -> Option<String> {
        self.auth_token
            .clone()
            .or_else(|| self.data.as_ref().and_then(|data| data.auth_token.clone()))
    }

    fn expires_in(&self) -> Duration {
        self.data
            .as_ref()
            .and_then(OppoAuthData::expires_in)
            .unwrap_or_else(|| Duration::from_secs(OPPO_TOKEN_CACHE_SECS))
    }
}

#[derive(Debug, Deserialize)]
struct OppoAuthData {
    #[serde(default, alias = "authToken")]
    auth_token: Option<String>,
    #[serde(default, alias = "expiresIn")]
    expires_in_secs: Option<u64>,
    #[serde(default, alias = "expireTime", alias = "expiredTime")]
    expire_time: Option<u64>,
}

impl OppoAuthData {
    fn expires_in(&self) -> Option<Duration> {
        if let Some(expires_in_secs) = self.expires_in_secs {
            return Some(Duration::from_secs(expires_in_secs.max(60)));
        }
        let expire_time = self.expire_time?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis() as u64;
        if expire_time <= now {
            return Some(Duration::from_secs(60));
        }
        Some(Duration::from_millis(expire_time - now))
    }
}

#[derive(Debug, Deserialize)]
struct OppoSendResponse {
    #[serde(default)]
    code: Option<i64>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    msg: Option<String>,
}

impl OppoSendResponse {
    fn is_success(&self) -> bool {
        self.code.unwrap_or(0) == 0
    }

    fn is_invalid_target(&self) -> bool {
        self.message()
            .is_some_and(|message| looks_like_invalid_target(&message))
    }

    fn message(&self) -> Option<String> {
        self.message.clone().or_else(|| self.msg.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Counts, Device, Notification, Tweaks};

    fn device() -> Device {
        Device {
            app_id: "com.example.oppo".to_owned(),
            push_key: "target-value".to_owned(),
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
            push_decision: None,
            target_actor_id: None,
        }
    }

    fn notification() -> Notification {
        Notification {
            flow_name: Some("Mission Control".to_owned()),
            realm_name: None,
            prio: None,
            membership: None,
            sender_actor_display_name: Some("Major Tom".to_owned()),
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
            realm_id: Some("cx:realm:01JS0SP000000000000000000".to_owned()),
            user_is_target: Some(true),
            push_target_id: Some("cx:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
            recipient_service_did: None,
            delivery_binding_frontier: None,
            wakeup_kind: Some("message".to_owned()),
            sender: Some("@major:example.com".to_owned()),
            push_hint: None,
            devices: vec![device()],
            mention_redirect_target_actor_ids: Vec::new(),
            counts: Counts {
                unread: Some(2),
                missed_calls: Some(1),
                highlight_count: None,
            },
            ..Default::default()
        }
    }

    fn pushkin(vendor: OppoVendor) -> OppoPushkin {
        OppoPushkin {
            matcher: AppMatcher::new("com.example.oppo".to_owned()).unwrap(),
            vendor,
            gate: ConcurrencyGate::new(1),
            connection_semaphore: Arc::new(Semaphore::new(1)),
            client: Client::builder().build().unwrap(),
            auth: OppoAuth {
                app_key: "app-key".to_owned(),
                master_secret: "master-secret".to_owned(),
            },
            auth_endpoint: OPPO_AUTH_URL.to_owned(),
            send_endpoint: format!("{OPPO_API_BASE_URL}/server/v1/message/notification/unicast"),
            token_cache: Mutex::new(None),
            config: OppoConfig {
                request: Map::new(),
                notification: json!({
                    "style": 1
                })
                .as_object()
                .unwrap()
                .clone(),
                click_action_type: Some(1),
                action_parameters: Some(
                    json!({
                        "action_type": 1
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
                channel_id: Some("messages".to_owned()),
                send_badge_counts: true,
            },
        }
    }

    #[test]
    fn builds_request_body_with_notification_payload() {
        let device = device();
        let payload = build_android_notification_payload(
            &notification(),
            device.default_payload().unwrap(),
            true,
        )
        .unwrap();

        let body = Value::Object(pushkin(OppoVendor::Oppo).build_request_body(&device, payload));

        assert_eq!(
            body.pointer("/target_value"),
            Some(&Value::String("target-value".to_owned()))
        );
        assert_eq!(
            body.pointer("/notification/title"),
            Some(&Value::String("Mission Control".to_owned()))
        );
        assert_eq!(
            body.pointer("/notification/channel_id"),
            Some(&Value::String("messages".to_owned()))
        );
        assert_eq!(
            body.pointer("/notification/action_parameters/action_type"),
            Some(&Value::Number(1.into()))
        );
    }

    #[test]
    fn invalid_target_response_rejects_push_key() {
        let result = pushkin(OppoVendor::Oppo)
            .handle_response(
                StatusCode::OK,
                None,
                r#"{"code":1,"message":"target_value invalid"}"#,
                &device(),
            )
            .unwrap();

        assert_eq!(result, vec!["target-value".to_owned()]);
    }

    #[test]
    fn oneplus_vendor_name_is_distinct() {
        assert_eq!(pushkin(OppoVendor::Oneplus).vendor_name(), "OnePlus Push");
    }
}
