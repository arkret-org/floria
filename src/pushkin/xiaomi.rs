use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arkret_models_integration::{PushDeviceRoute, PushNotificationEnvelope};
use async_trait::async_trait;
use prometheus::{
    Histogram, IntGauge, register_histogram, register_int_counter_vec, register_int_gauge,
};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value};
use tokio::sync::Semaphore;
use tokio::time::sleep;

use super::android::build_android_notification_payload;
use super::reqwest_support::{build_reqwest_client, parse_retry_after};
use super::{AppMatcher, ConcurrencyGate, Pushkin, inflight_limit, max_connections};
use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{DeviceExt, NotificationContext};

static XIAOMI_QUEUE_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_xiaomi_queue_time",
        "Time taken waiting for a Xiaomi Push request slot"
    )
    .expect("register floria_xiaomi_queue_time")
});

static XIAOMI_REQUEST_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_xiaomi_request_time",
        "Time taken to send HTTP request to Xiaomi Push"
    )
    .expect("register floria_xiaomi_request_time")
});

static XIAOMI_PENDING_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_pending_xiaomi_requests",
        "Number of Xiaomi Push requests waiting for a connection"
    )
    .expect("register floria_pending_xiaomi_requests")
});

static XIAOMI_ACTIVE_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_active_xiaomi_requests",
        "Number of Xiaomi Push requests in flight"
    )
    .expect("register floria_active_xiaomi_requests")
});

static XIAOMI_STATUS_CODES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_xiaomi_status_codes",
        "Number of HTTP response status codes received from Xiaomi Push",
        &["pushkin", "code"]
    )
    .expect("register floria_xiaomi_status_codes")
});

const XIAOMI_MAX_TRIES: usize = 3;
const XIAOMI_RETRY_DELAY_BASE_SECS: u64 = 10;
const XIAOMI_API_BASE_URL: &str = "https://api.xmpush.xiaomi.com";

pub struct XiaomiPushkin {
    matcher: AppMatcher,
    gate: ConcurrencyGate,
    connection_semaphore: Arc<Semaphore>,
    client: Client,
    authorization: HeaderValue,
    endpoint: String,
    config: XiaomiConfig,
}

#[derive(Debug, Clone)]
struct XiaomiConfig {
    restricted_package_name: String,
    pass_through: bool,
    notify_type: Option<u64>,
    time_to_live: Option<u64>,
    notify_id: Option<u64>,
    channel_id: Option<String>,
    notify_effect: Option<String>,
    intent_uri: Option<String>,
    web_uri: Option<String>,
    extra: Map<String, Value>,
    send_badge_counts: bool,
}

impl XiaomiPushkin {
    pub fn new(name: String, app: &AppConfig, config: &Config) -> Result<Self> {
        app.warn_unknown_fields(
            &name,
            &[
                "app_secret",
                "api_base_url",
                "restricted_package_name",
                "pass_through",
                "notify_type",
                "time_to_live",
                "notify_id",
                "channel_id",
                "notify_effect",
                "intent_uri",
                "web_uri",
                "extra",
                "send_badge_counts",
                "max_connections",
                "inflight_request_limit",
            ],
        );

        let app_secret = app
            .get_string("app_secret")?
            .context("Xiaomi Push config requires app_secret")?;
        let api_base_url = app
            .get_string("api_base_url")?
            .unwrap_or_else(|| XIAOMI_API_BASE_URL.to_owned())
            .trim_end_matches('/')
            .to_owned();

        let endpoint = format!("{api_base_url}/v3/message/regid");
        crate::egress::validate_http_url_for_egress(&endpoint, "Xiaomi push endpoint")
            .map_err(|error| anyhow::anyhow!(error))?;

        Ok(Self {
            matcher: AppMatcher::new(name)?,
            gate: ConcurrencyGate::new(inflight_limit(app)?),
            connection_semaphore: Arc::new(Semaphore::new(max_connections(app)?.max(1))),
            client: build_reqwest_client(config, "floria")?,
            authorization: xiaomi_authorization(&app_secret)?,
            endpoint,
            config: XiaomiConfig {
                restricted_package_name: app
                    .get_string("restricted_package_name")?
                    .context("Xiaomi Push config requires restricted_package_name")?,
                pass_through: app.get_bool("pass_through")?.unwrap_or(false),
                notify_type: app.get_u64("notify_type")?,
                time_to_live: app.get_u64("time_to_live")?,
                notify_id: app.get_u64("notify_id")?,
                channel_id: app.get_string("channel_id")?,
                notify_effect: app.get_string("notify_effect")?,
                intent_uri: app.get_string("intent_uri")?,
                web_uri: app.get_string("web_uri")?,
                extra: app.get_object("extra")?.unwrap_or_default(),
                send_badge_counts: app.get_bool("send_badge_counts")?.unwrap_or(true),
            },
        })
    }

    fn build_form(
        &self,
        notification: &PushNotificationEnvelope,
        device: &PushDeviceRoute,
        allow_visible_notification: bool,
    ) -> Result<Vec<(String, String)>, DispatchError> {
        let Some(payload) = build_android_notification_payload(
            notification,
            Map::new(),
            allow_visible_notification,
            self.config.send_badge_counts,
        ) else {
            return Ok(vec![]);
        };

        let payload_data = serde_json::to_string(&payload.data).map_err(|error| {
            DispatchError::internal(format!("failed to encode Xiaomi payload data: {error}"))
        })?;

        let mut form = vec![
            (
                "registration_id".to_owned(),
                device.push_key().unwrap_or_default().to_owned(),
            ),
            (
                "restricted_package_name".to_owned(),
                self.config.restricted_package_name.clone(),
            ),
            (
                "pass_through".to_owned(),
                if self.config.pass_through { "1" } else { "0" }.to_owned(),
            ),
            ("payload".to_owned(), payload_data),
        ];

        if let Some(title) = payload.title {
            form.push(("title".to_owned(), title));
        }
        if let Some(body) = payload.body {
            form.push(("description".to_owned(), body));
        }

        if let Some(notify_type) = self.config.notify_type {
            form.push(("notify_type".to_owned(), notify_type.to_string()));
        }
        if let Some(time_to_live) = self.config.time_to_live {
            form.push(("time_to_live".to_owned(), time_to_live.to_string()));
        }
        if let Some(notify_id) = self.config.notify_id {
            form.push(("notify_id".to_owned(), notify_id.to_string()));
        }

        for (key, value) in self.extra_pairs() {
            form.push((format!("extra.{key}"), value));
        }

        Ok(form)
    }

    fn extra_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        if let Some(channel_id) = &self.config.channel_id {
            pairs.push(("channel_id".to_owned(), channel_id.clone()));
        }
        if let Some(notify_effect) = &self.config.notify_effect {
            pairs.push(("notify_effect".to_owned(), notify_effect.clone()));
        }
        if let Some(intent_uri) = &self.config.intent_uri {
            pairs.push(("intent_uri".to_owned(), intent_uri.clone()));
        }
        if let Some(web_uri) = &self.config.web_uri {
            pairs.push(("web_uri".to_owned(), web_uri.clone()));
        }
        pairs.extend(
            self.config
                .extra
                .iter()
                .map(|(key, value)| (key.clone(), xiaomi_string(value))),
        );
        pairs
    }

    async fn send_once(
        &self,
        notification: &PushNotificationEnvelope,
        device: &PushDeviceRoute,
        allow_visible_notification: bool,
    ) -> Result<Vec<String>, DispatchError> {
        let form = self.build_form(notification, device, allow_visible_notification)?;
        if form.is_empty() {
            return Ok(vec![]);
        }

        XIAOMI_PENDING_REQUESTS.inc();
        let queue_started = Instant::now();
        let _connection_permit = self
            .connection_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| {
                XIAOMI_PENDING_REQUESTS.dec();
                DispatchError::internal("Xiaomi Push connection semaphore closed")
            })?;
        XIAOMI_PENDING_REQUESTS.dec();
        XIAOMI_QUEUE_TIME.observe(queue_started.elapsed().as_secs_f64());

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, self.authorization.clone());

        XIAOMI_ACTIVE_REQUESTS.inc();
        let request_started = Instant::now();
        let response = self
            .client
            .post(&self.endpoint)
            .headers(headers)
            .form(&form)
            .send()
            .await
            .map_err(|error| {
                XIAOMI_ACTIVE_REQUESTS.dec();
                XIAOMI_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());
                DispatchError::temporary(format!("Xiaomi Push request failed: {error}"), None)
            })?;
        XIAOMI_ACTIVE_REQUESTS.dec();
        XIAOMI_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());

        let status = response.status();
        XIAOMI_STATUS_CODES
            .with_label_values(&[self.name(), &status.as_u16().to_string()])
            .inc();
        let retry_after = parse_retry_after(response.headers());
        let body = response.text().await.map_err(|error| {
            DispatchError::remote(format!("failed to read Xiaomi Push response: {error}"))
        })?;
        self.handle_response(status, retry_after, &body, device)
    }

    fn handle_response(
        &self,
        status: StatusCode,
        retry_after: Option<Duration>,
        body: &str,
        device: &PushDeviceRoute,
    ) -> Result<Vec<String>, DispatchError> {
        match status.as_u16() {
            429 => Err(DispatchError::temporary(
                xiaomi_error_message(body, status),
                retry_after.or(Some(Duration::from_secs(XIAOMI_RETRY_DELAY_BASE_SECS))),
            )),
            500..=599 => Err(DispatchError::temporary(
                xiaomi_error_message(body, status),
                retry_after,
            )),
            200..=299 => match serde_json::from_str::<XiaomiSendResponse>(body) {
                Ok(response) if response.code == 0 => Ok(vec![]),
                Ok(response) if response.is_invalid_registration() => {
                    Ok(vec![device.push_key().unwrap_or_default().to_owned()])
                }
                Ok(response) => Err(DispatchError::remote(format!(
                    "Xiaomi Push rejected request: {} {}",
                    response.code, response.description
                ))),
                Err(_) if looks_like_invalid_registration(body) => {
                    Ok(vec![device.push_key().unwrap_or_default().to_owned()])
                }
                Err(_) => Ok(vec![]),
            },
            _ if looks_like_invalid_registration(body) => {
                Ok(vec![device.push_key().unwrap_or_default().to_owned()])
            }
            _ => Err(DispatchError::remote(xiaomi_error_message(body, status))),
        }
    }
}

#[async_trait]
impl Pushkin for XiaomiPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn kind(&self) -> &'static str {
        "xiaomi"
    }

    fn handles_app_id(&self, app_id: &str) -> bool {
        self.matcher.handles_app_id(app_id)
    }

    async fn dispatch_notification(
        &self,
        notification: &PushNotificationEnvelope,
        device: &PushDeviceRoute,
        context: &NotificationContext,
    ) -> Result<Vec<String>, DispatchError> {
        let _permit = self.gate.acquire(self.name())?;

        if device.push_key().is_none() {
            tracing::warn!("rejecting Xiaomi Push device due to empty registration_id");
            return Ok(vec![device.push_key().unwrap_or_default().to_owned()]);
        }

        for attempt in 0..XIAOMI_MAX_TRIES {
            match self
                .send_once(
                    notification,
                    device,
                    context.allow_plaintext_metadata && device.visible_notification_opt_in(),
                )
                .await
            {
                Ok(result) => return Ok(result),
                Err(error @ DispatchError::Temporary { .. }) if attempt + 1 < XIAOMI_MAX_TRIES => {
                    let retry_after = error.retry_after().unwrap_or_else(|| {
                        Duration::from_secs(XIAOMI_RETRY_DELAY_BASE_SECS * (1_u64 << attempt))
                    });
                    sleep(retry_after).await;
                }
                Err(error) => return Err(error),
            }
        }

        Err(DispatchError::remote("Xiaomi Push retried too many times"))
    }
}

fn xiaomi_authorization(app_secret: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(&format!("key={app_secret}"))
        .map_err(|error| anyhow::anyhow!("invalid Xiaomi authorization header: {error}"))
}

fn xiaomi_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(value) => {
            if *value {
                "true".to_owned()
            } else {
                "false".to_owned()
            }
        }
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn looks_like_invalid_registration(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("registration")
        && (lower.contains("invalid")
            || lower.contains("expired")
            || lower.contains("unregistered")
            || lower.contains("not exist"))
}

fn xiaomi_error_message(body: &str, status: StatusCode) -> String {
    serde_json::from_str::<XiaomiSendResponse>(body)
        .ok()
        .map(|response| {
            format!(
                "Xiaomi Push rejected request: {} {}",
                response.code, response.description
            )
        })
        .unwrap_or_else(|| format!("Xiaomi Push rejected request: {status} {body}"))
}

#[derive(Debug, Deserialize)]
struct XiaomiSendResponse {
    code: i64,
    #[serde(default)]
    description: String,
}

impl XiaomiSendResponse {
    fn is_invalid_registration(&self) -> bool {
        looks_like_invalid_registration(&self.description)
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_integration::{
        PushCounts, PushDeviceRoute, PushNotificationEnvelope, PushRouteTokens,
    };

    use super::*;

    fn device() -> PushDeviceRoute {
        PushDeviceRoute {
            device_id: arkret_wire::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
            app_id: Some("com.example.xiaomi".to_owned()),
            push_key: Some(arkret_models_integration::PushKey::new("regid").unwrap()),
            platform: None,
            target_route_token: None,
            visible_notification_opt_in: false,
        }
    }

    fn notification() -> PushNotificationEnvelope {
        PushNotificationEnvelope {
            strand_title: Some("Mission Control".to_owned()),
            realm_title: None,
            priority: None,
            membership: None,
            sender_actor_display_name: Some("Major Tom".to_owned()),
            event_id: Some(
                arkret_wire::EventId::new("ak:event:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS")
                    .unwrap(),
            ),
            message_id: Some(
                arkret_wire::MessageId::new(
                    "ak:message:AevYtAp_mjd9pPNtsNoiquL8rnoJUC0S0gYtV6_SwmD1",
                )
                .unwrap(),
            ),
            strand_id: Some(
                arkret_wire::StrandId::new(
                    "ak:strand:AZfy3leHQNK3ezr_x4HPHq09HrnS3Eb6wM-IwyFH8fQD",
                )
                .unwrap(),
            ),
            route_tokens: Some(PushRouteTokens {
                realm_route_token: Some(
                    arkret_models_integration::PushRouteToken::new("realm_route_token_000000001")
                        .unwrap(),
                ),
                ..Default::default()
            }),
            user_is_target: Some(true),
            push_target_id: Some("ak:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
            wakeup_kind: Some("message".to_owned()),
            push_hint: None,
            devices: vec![device()],
            counts: Some(PushCounts {
                badge: Some(arkret_models_integration::PushCountIndicator::Bucket(
                    "2-5".to_owned(),
                )),
                unread_increment: Some(2),
                missed_call: Some(arkret_models_integration::PushCountIndicator::Present(true)),
            }),
            ..Default::default()
        }
    }

    fn pushkin() -> XiaomiPushkin {
        XiaomiPushkin {
            matcher: AppMatcher::new("com.example.xiaomi".to_owned()).unwrap(),
            gate: ConcurrencyGate::new(1),
            connection_semaphore: Arc::new(Semaphore::new(1)),
            client: Client::builder().build().unwrap(),
            authorization: HeaderValue::from_static("key=secret"),
            endpoint: format!("{XIAOMI_API_BASE_URL}/v3/message/regid"),
            config: XiaomiConfig {
                restricted_package_name: "com.example.xiaomi".to_owned(),
                pass_through: false,
                notify_type: Some(2),
                time_to_live: Some(3600),
                notify_id: Some(7),
                channel_id: Some("messages".to_owned()),
                notify_effect: Some("2".to_owned()),
                intent_uri: Some("intent:#Intent;end".to_owned()),
                web_uri: None,
                extra: serde_json::json!({
                    "notification_style_type": 1
                })
                .as_object()
                .unwrap()
                .clone()
                .into_iter()
                .collect(),
                send_badge_counts: true,
            },
        }
    }

    #[test]
    fn builds_form_with_expected_fields() {
        let form = pushkin()
            .build_form(&notification(), &device(), true)
            .unwrap();
        let map = form
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(map.get("registration_id"), Some(&"regid".to_owned()));
        assert_eq!(
            map.get("restricted_package_name"),
            Some(&"com.example.xiaomi".to_owned())
        );
        assert_eq!(map.get("pass_through"), Some(&"0".to_owned()));
        assert_eq!(map.get("title"), Some(&"Mission Control".to_owned()));
        assert_eq!(map.get("notify_type"), Some(&"2".to_owned()));
        assert_eq!(map.get("extra.channel_id"), Some(&"messages".to_owned()));
        // T4.3 — payload blob no longer carries strand_id / event_id /
        // sender. Only push_target_id (opaque) survives as the routing
        // hook the client uses to fetch the e2ee envelope.
        let payload_blob = map.get("payload").cloned().unwrap_or_default();
        assert!(
            !payload_blob.contains("\"strand_id\""),
            "xiaomi payload must not carry strand_id: {payload_blob}"
        );
        assert!(
            !payload_blob.contains("\"event_id\""),
            "xiaomi payload must not carry event_id: {payload_blob}"
        );
        assert!(
            !payload_blob.contains("\"sender\""),
            "xiaomi payload must not carry sender: {payload_blob}"
        );
        assert!(
            payload_blob
                .contains("\"push_target_id\":\"ak:pseudonym:push:01HYZ8Z000000000000000\""),
            "xiaomi payload must carry push_target_id: {payload_blob}"
        );
    }

    #[test]
    fn success_response_is_accepted() {
        let result = pushkin()
            .handle_response(
                StatusCode::OK,
                None,
                r#"{"result":"ok","code":0,"description":"Success"}"#,
                &device(),
            )
            .unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn invalid_registration_is_rejected() {
        let result = pushkin()
            .handle_response(
                StatusCode::OK,
                None,
                r#"{"result":"error","code":700000,"description":"invalid registration id"}"#,
                &device(),
            )
            .unwrap();

        assert_eq!(result, vec!["regid".to_owned()]);
    }
}
