use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use prometheus::{
    Histogram, IntGauge, register_histogram, register_int_counter_vec, register_int_gauge,
};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::Semaphore;
use tokio::time::sleep;

use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{Device, Notification, NotificationContext};

use super::android::{
    AndroidNotificationPayload, AndroidPriority, build_android_notification_payload,
};
use super::reqwest_support::{
    ClientCredentialsGrant, bearer, build_reqwest_client, looks_like_invalid_token,
    parse_retry_after,
};
use super::{AppMatcher, ConcurrencyGate, Pushkin, inflight_limit, max_connections};

static HONOR_QUEUE_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_honor_queue_time",
        "Time taken waiting for an HONOR Push request slot"
    )
    .expect("register floria_honor_queue_time")
});

static HONOR_REQUEST_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_honor_request_time",
        "Time taken to send HTTP request to HONOR Push"
    )
    .expect("register floria_honor_request_time")
});

static HONOR_PENDING_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_pending_honor_requests",
        "Number of HONOR Push requests waiting for a connection"
    )
    .expect("register floria_pending_honor_requests")
});

static HONOR_ACTIVE_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_active_honor_requests",
        "Number of HONOR Push requests in flight"
    )
    .expect("register floria_active_honor_requests")
});

static HONOR_STATUS_CODES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_honor_status_codes",
        "Number of HTTP response status codes received from HONOR Push",
        &["pushkin", "code"]
    )
    .expect("register floria_honor_status_codes")
});

const HONOR_MAX_TRIES: usize = 3;
const HONOR_RETRY_DELAY_BASE_SECS: u64 = 10;
const HONOR_TOKEN_URL: &str = "https://hnoauth-login.cloud.honor.com/oauth2/v3/token";
const HONOR_API_BASE_URL: &str = "https://push-api.cloud.honor.com/v1";

pub struct HonorPushkin {
    matcher: AppMatcher,
    gate: ConcurrencyGate,
    connection_semaphore: Arc<Semaphore>,
    client: Client,
    token_grant: ClientCredentialsGrant,
    endpoint: String,
    config: HonorConfig,
}

#[derive(Debug, Clone)]
struct HonorConfig {
    channel_id: Option<String>,
    ttl_seconds: Option<u64>,
    android_config: Map<String, Value>,
    android_notification: Map<String, Value>,
    click_action: Option<Map<String, Value>>,
    send_badge_counts: bool,
}

impl HonorPushkin {
    pub fn new(name: String, app: &AppConfig, config: &Config) -> Result<Self> {
        app.warn_unknown_fields(
            &name,
            &[
                "app_id",
                "app_secret",
                "token_url",
                "api_base_url",
                "channel_id",
                "ttl_seconds",
                "android_config",
                "android_notification",
                "click_action",
                "send_badge_counts",
                "max_connections",
                "inflight_request_limit",
            ],
        );

        let app_id = app
            .extra
            .get("app_id")
            .map(value_to_string)
            .transpose()?
            .context("HONOR Push config requires app_id")?;
        let app_secret = app
            .get_string("app_secret")?
            .context("HONOR Push config requires app_secret")?;
        let token_url = app
            .get_string("token_url")?
            .unwrap_or_else(|| HONOR_TOKEN_URL.to_owned());
        let api_base_url = app
            .get_string("api_base_url")?
            .unwrap_or_else(|| HONOR_API_BASE_URL.to_owned())
            .trim_end_matches('/')
            .to_owned();

        Ok(Self {
            matcher: AppMatcher::new(name)?,
            gate: ConcurrencyGate::new(inflight_limit(app)?),
            connection_semaphore: Arc::new(Semaphore::new(max_connections(app)?.max(1))),
            client: build_reqwest_client(config, "floria")?,
            token_grant: ClientCredentialsGrant::new(app_id.clone(), app_secret, token_url),
            endpoint: format!("{api_base_url}/{app_id}/messages:send"),
            config: HonorConfig {
                channel_id: app.get_string("channel_id")?,
                ttl_seconds: app.get_u64("ttl_seconds")?,
                android_config: app.get_object("android_config")?.unwrap_or_default(),
                android_notification: app.get_object("android_notification")?.unwrap_or_default(),
                click_action: app.get_object("click_action")?,
                send_badge_counts: app.get_bool("send_badge_counts")?.unwrap_or(true),
            },
        })
    }

    fn build_request_body(
        &self,
        device: &Device,
        payload: AndroidNotificationPayload,
    ) -> Result<Map<String, Value>, DispatchError> {
        let data = serde_json::to_string(&payload.data).map_err(|error| {
            DispatchError::internal(format!("failed to encode HONOR Push data payload: {error}"))
        })?;

        let mut message = Map::new();
        message.insert(
            "token".to_owned(),
            Value::Array(vec![Value::String(device.pushkey.clone())]),
        );
        message.insert(
            "notification".to_owned(),
            json!({
                "title": payload.title,
                "body": payload.body,
            }),
        );
        message.insert("data".to_owned(), Value::String(data));
        message.insert(
            "android".to_owned(),
            Value::Object(self.android_config(payload)),
        );

        Ok(json!({
            "validate_only": false,
            "message": Value::Object(message),
        })
        .as_object()
        .unwrap()
        .clone())
    }

    fn android_config(&self, payload: AndroidNotificationPayload) -> Map<String, Value> {
        let mut android = self.config.android_config.clone();
        android.insert(
            "urgency".to_owned(),
            Value::String(
                match payload.priority {
                    AndroidPriority::Normal => "NORMAL",
                    AndroidPriority::High => "HIGH",
                }
                .to_owned(),
            ),
        );
        if let Some(ttl_seconds) = self.config.ttl_seconds {
            android.insert("ttl".to_owned(), Value::String(format!("{ttl_seconds}s")));
        }

        let mut android_notification = android
            .remove("notification")
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        android_notification.extend(self.config.android_notification.clone());
        android_notification.insert("title".to_owned(), Value::String(payload.title));
        android_notification.insert("body".to_owned(), Value::String(payload.body));
        if let Some(channel_id) = &self.config.channel_id {
            android_notification.insert("channel_id".to_owned(), Value::String(channel_id.clone()));
        }
        if let Some(click_action) = &self.config.click_action {
            android_notification.insert(
                "click_action".to_owned(),
                Value::Object(click_action.clone()),
            );
        }
        android.insert(
            "notification".to_owned(),
            Value::Object(android_notification),
        );

        android
    }

    async fn send_once(
        &self,
        device: &Device,
        payload: AndroidNotificationPayload,
    ) -> Result<Vec<String>, DispatchError> {
        let token = self.token_grant.access_token(&self.client).await?;
        let body = self.build_request_body(device, payload)?;

        HONOR_PENDING_REQUESTS.inc();
        let queue_started = Instant::now();
        let _connection_permit = self
            .connection_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| {
                HONOR_PENDING_REQUESTS.dec();
                DispatchError::internal("HONOR Push connection semaphore closed")
            })?;
        HONOR_PENDING_REQUESTS.dec();
        HONOR_QUEUE_TIME.observe(queue_started.elapsed().as_secs_f64());

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, bearer(&token)?);
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/json; charset=utf-8"),
        );

        HONOR_ACTIVE_REQUESTS.inc();
        let request_started = Instant::now();
        let response = self
            .client
            .post(&self.endpoint)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                HONOR_ACTIVE_REQUESTS.dec();
                HONOR_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());
                DispatchError::temporary(format!("HONOR Push request failed: {error}"), None)
            })?;
        HONOR_ACTIVE_REQUESTS.dec();
        HONOR_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());

        let status = response.status();
        HONOR_STATUS_CODES
            .with_label_values(&[self.name(), &status.as_u16().to_string()])
            .inc();
        let retry_after = parse_retry_after(response.headers());
        let body = response.text().await.map_err(|error| {
            DispatchError::remote(format!("failed to read HONOR Push response: {error}"))
        })?;
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
                honor_error_message(body, status),
                retry_after.or(Some(Duration::from_secs(HONOR_RETRY_DELAY_BASE_SECS))),
            )),
            500..=599 => Err(DispatchError::temporary(
                honor_error_message(body, status),
                retry_after,
            )),
            200..=299 => match serde_json::from_str::<HonorSendResponse>(body) {
                Ok(response) if response.code.as_deref().is_none_or(is_honor_success_code) => {
                    Ok(vec![])
                }
                Ok(response) if response.is_invalid_token() => Ok(vec![device.pushkey.clone()]),
                Ok(response) => Err(DispatchError::remote(format!(
                    "HONOR Push rejected request: {} {}",
                    response.code.unwrap_or_else(|| status.as_u16().to_string()),
                    response.msg.unwrap_or_else(|| body.to_owned())
                ))),
                Err(_) if looks_like_invalid_token(body) => Ok(vec![device.pushkey.clone()]),
                Err(_) => Ok(vec![]),
            },
            _ if looks_like_invalid_token(body) => Ok(vec![device.pushkey.clone()]),
            _ => Err(DispatchError::remote(honor_error_message(body, status))),
        }
    }
}

#[async_trait]
impl Pushkin for HonorPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
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
            tracing::warn!("rejecting HONOR Push device due to empty token");
            return Ok(vec![device.pushkey.clone()]);
        }

        let default_payload = match device.default_payload() {
            Ok(default_payload) => default_payload,
            Err(_) => {
                tracing::warn!(
                    pushkey = %device.pushkey,
                    "rejecting HONOR Push token due to invalid default_payload"
                );
                return Ok(vec![device.pushkey.clone()]);
            }
        };
        let Some(payload) = build_android_notification_payload(
            notification,
            default_payload,
            self.config.send_badge_counts,
        ) else {
            return Ok(vec![]);
        };

        for attempt in 0..HONOR_MAX_TRIES {
            match self.send_once(device, payload.clone()).await {
                Ok(result) => return Ok(result),
                Err(error @ DispatchError::Temporary { .. }) if attempt + 1 < HONOR_MAX_TRIES => {
                    let retry_after = error.retry_after().unwrap_or_else(|| {
                        Duration::from_secs(HONOR_RETRY_DELAY_BASE_SECS * (1_u64 << attempt))
                    });
                    sleep(retry_after).await;
                }
                Err(error) => return Err(error),
            }
        }

        Err(DispatchError::remote("HONOR Push retried too many times"))
    }
}

fn value_to_string(value: &Value) -> Result<String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        other => Err(anyhow!(
            "app_id must be a string or unsigned integer, got {}",
            crate::config::value_type(other)
        )),
    }
}

fn is_honor_success_code(code: &str) -> bool {
    matches!(code, "80000000" | "0" | "")
}

fn honor_error_message(body: &str, status: StatusCode) -> String {
    serde_json::from_str::<HonorSendResponse>(body)
        .ok()
        .map(|response| {
            format!(
                "HONOR Push rejected request: {} {}",
                response.code.unwrap_or_else(|| status.as_u16().to_string()),
                response.msg.unwrap_or_else(|| body.to_owned())
            )
        })
        .unwrap_or_else(|| format!("HONOR Push rejected request: {status} {body}"))
}

#[derive(Debug, Deserialize)]
struct HonorSendResponse {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    msg: Option<String>,
}

impl HonorSendResponse {
    fn is_invalid_token(&self) -> bool {
        self.msg.as_deref().is_some_and(looks_like_invalid_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Counts, Device, Notification, Tweaks};

    fn device() -> Device {
        Device {
            app_id: "com.example.honor".to_owned(),
            pushkey: "honor-token".to_owned(),
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
            room_name: Some("Mission Control".to_owned()),
            room_alias: None,
            prio: Some("low".to_owned()),
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
            event_id: Some("$event".to_owned()),
            room_id: Some("!room:example.com".to_owned()),
            user_is_target: Some(true),
            r#type: Some("m.room.message".to_owned()),
            sender: Some("@major:example.com".to_owned()),
            devices: vec![device()],
            counts: Counts {
                unread: Some(2),
                missed_calls: Some(1),
            },
        }
    }

    fn pushkin() -> HonorPushkin {
        HonorPushkin {
            matcher: AppMatcher::new("com.example.honor".to_owned()).unwrap(),
            gate: ConcurrencyGate::new(1),
            connection_semaphore: Arc::new(Semaphore::new(1)),
            client: Client::builder().build().unwrap(),
            token_grant: ClientCredentialsGrant::new(
                "12345".to_owned(),
                "secret".to_owned(),
                HONOR_TOKEN_URL.to_owned(),
            ),
            endpoint: format!("{HONOR_API_BASE_URL}/12345/messages:send"),
            config: HonorConfig {
                channel_id: Some("messages".to_owned()),
                ttl_seconds: Some(3600),
                android_config: Map::new(),
                android_notification: Map::new(),
                click_action: Some(
                    json!({
                        "type": 2,
                        "url": "https://example.com"
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
                send_badge_counts: true,
            },
        }
    }

    #[test]
    fn builds_request_body() {
        let device = device();
        let payload = build_android_notification_payload(
            &notification(),
            device.default_payload().unwrap(),
            true,
        )
        .unwrap();
        let body = Value::Object(pushkin().build_request_body(&device, payload).unwrap());

        assert_eq!(
            body.pointer("/message/token/0"),
            Some(&Value::String("honor-token".to_owned()))
        );
        assert_eq!(
            body.pointer("/message/notification/title"),
            Some(&Value::String("Mission Control".to_owned()))
        );
        assert_eq!(
            body.pointer("/message/android/notification/channel_id"),
            Some(&Value::String("messages".to_owned()))
        );
        assert_eq!(
            body.pointer("/message/android/notification/click_action/type"),
            Some(&Value::Number(2.into()))
        );
        assert_eq!(
            body.pointer("/message/android/urgency"),
            Some(&Value::String("NORMAL".to_owned()))
        );
    }

    #[test]
    fn invalid_token_response_rejects_pushkey() {
        let result = pushkin()
            .handle_response(
                StatusCode::OK,
                None,
                r#"{"code":"80300007","msg":"invalid token"}"#,
                &device(),
            )
            .unwrap();

        assert_eq!(result, vec!["honor-token".to_owned()]);
    }

    #[test]
    fn success_code_is_treated_as_success() {
        let result = pushkin()
            .handle_response(
                StatusCode::OK,
                None,
                r#"{"code":"80000000","msg":"Success"}"#,
                &device(),
            )
            .unwrap();

        assert!(result.is_empty());
    }
}
