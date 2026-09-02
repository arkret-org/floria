use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use arkret_models_integration::{PushDeviceRoute, PushNotificationEnvelope};
use async_trait::async_trait;
use md5::{Digest, Md5};
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::android::build_android_notification_payload;
use super::oem_family::{self, OemMetrics, OemTransport};
use super::reqwest_support::{ExpiringTokenCache, build_reqwest_client, header_value};
use super::{AppMatcher, ConcurrencyGate, Pushkin, inflight_limit, max_connections};
use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{DeviceExt, NotificationContext};

static VIVO_METRICS: LazyLock<OemMetrics> =
    LazyLock::new(|| OemMetrics::new("vivo", "vivo Push", "a"));

const VIVO_DISPLAY: &str = "vivo Push";
const VIVO_MAX_TRIES: usize = 3;
const VIVO_RETRY_DELAY_BASE_SECS: u64 = 10;
const VIVO_TOKEN_CACHE_SECS: u64 = 2 * 60 * 60;
const VIVO_AUTH_URL: &str = "https://api-push.vivo.com.cn/message/auth";
const VIVO_API_BASE_URL: &str = "https://api-push.vivo.com.cn";

pub struct VivoPushkin {
    matcher: AppMatcher,
    gate: ConcurrencyGate,
    transport: OemTransport,
    auth: VivoAuth,
    auth_endpoint: String,
    send_endpoint: String,
    token_cache: ExpiringTokenCache,
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

        let send_endpoint = format!("{api_base_url}/message/send");
        crate::egress::validate_http_url_for_egress(&auth_url, "vivo auth endpoint")
            .map_err(|error| anyhow!(error))?;
        crate::egress::validate_http_url_for_egress(&send_endpoint, "vivo push endpoint")
            .map_err(|error| anyhow!(error))?;

        Ok(Self {
            matcher: AppMatcher::new(name)?,
            gate: ConcurrencyGate::new(inflight_limit(app)?),
            transport: OemTransport::new(
                &VIVO_METRICS,
                build_reqwest_client(config, "floria")?,
                max_connections(app)?,
            ),
            auth: VivoAuth {
                app_id,
                app_id_string,
                app_key,
                app_secret,
            },
            auth_endpoint: auth_url,
            send_endpoint,
            token_cache: ExpiringTokenCache::default(),
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
        if let Some(token) = self.token_cache.valid_token().await {
            return Ok(token);
        }

        self.fetch_access_token().await
    }

    async fn invalidate_token(&self) {
        self.token_cache.invalidate().await;
    }

    async fn fetch_access_token(&self) -> Result<String, DispatchError> {
        let timestamp = oem_family::current_timestamp_millis()?;
        let body = self.build_auth_request(&timestamp);

        let response = self
            .transport
            .client()
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
                self.token_cache
                    .store(
                        token.clone(),
                        Instant::now() + Duration::from_secs(VIVO_TOKEN_CACHE_SECS),
                    )
                    .await;
                Ok(token)
            }
            _ => Err(DispatchError::remote(vivo_error_message(&body, status))),
        }
    }

    fn build_auth_request(&self, timestamp: &str) -> Value {
        json!({
            "app_id": self.auth.app_id,
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
        notification: &PushNotificationEnvelope,
        device: &PushDeviceRoute,
        allow_visible_notification: bool,
    ) -> Result<Map<String, Value>, DispatchError> {
        let Some(payload) = build_android_notification_payload(
            notification,
            Map::new(),
            allow_visible_notification,
            self.config.send_badge_counts,
        ) else {
            return Ok(Map::new());
        };

        let mut body = Map::new();
        body.insert("app_id".to_owned(), self.auth.app_id.clone());
        body.insert(
            "regId".to_owned(),
            Value::String(device.push_key().unwrap_or_default().to_owned()),
        );
        body.insert(
            "notifyType".to_owned(),
            Value::Number(self.config.notify_type.into()),
        );
        if let Some(title) = payload.title {
            body.insert("title".to_owned(), Value::String(title));
        }
        if let Some(content) = payload.body {
            body.insert("content".to_owned(), Value::String(content));
        }
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
        notification: &PushNotificationEnvelope,
        device: &PushDeviceRoute,
        allow_visible_notification: bool,
    ) -> Result<Vec<String>, DispatchError> {
        let token = self.access_token().await?;
        let body = self.build_request_body(notification, device, allow_visible_notification)?;
        if body.is_empty() {
            return Ok(vec![]);
        }

        let mut headers = HeaderMap::new();
        headers.insert("authToken", header_value(&token)?);
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let response = self
            .transport
            .send(
                self.name(),
                VIVO_DISPLAY,
                self.transport
                    .client()
                    .post(&self.send_endpoint)
                    .headers(headers)
                    .json(&body),
            )
            .await?;

        // vivo's authToken has a much shorter life than OPPO's and the
        // gateway may still hold a cached one when it expires; drop it
        // on any auth-shaped rejection so the retry re-authenticates.
        if response.status == StatusCode::UNAUTHORIZED
            || response.status == StatusCode::FORBIDDEN
            || looks_like_vivo_auth_issue(&response.body)
        {
            self.invalidate_token().await;
            return Err(DispatchError::temporary(
                vivo_error_message(&response.body, response.status),
                response
                    .retry_after
                    .or(Some(Duration::from_secs(VIVO_RETRY_DELAY_BASE_SECS))),
            ));
        }

        self.handle_response(
            response.status,
            response.retry_after,
            &response.body,
            device,
        )
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
                    Ok(vec![device.push_key().unwrap_or_default().to_owned()])
                }
                Ok(response) => Err(DispatchError::remote(format!(
                    "vivo Push rejected request: {} {}",
                    response.result, response.desc
                ))),
                Err(_) if looks_like_invalid_registration(body) => {
                    Ok(vec![device.push_key().unwrap_or_default().to_owned()])
                }
                Err(_) => Ok(vec![]),
            },
            _ if looks_like_invalid_registration(body) => {
                Ok(vec![device.push_key().unwrap_or_default().to_owned()])
            }
            _ => Err(DispatchError::remote(vivo_error_message(body, status))),
        }
    }
}

#[async_trait]
impl Pushkin for VivoPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
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

        if let Some(rejected) = oem_family::empty_push_key_rejection(VIVO_DISPLAY, "regId", device)
        {
            return Ok(rejected);
        }

        let allow_visible_notification =
            context.allow_plaintext_metadata && device.visible_notification_opt_in();

        oem_family::dispatch_with_retries(
            VIVO_DISPLAY,
            VIVO_MAX_TRIES,
            VIVO_RETRY_DELAY_BASE_SECS,
            || async move {
                self.send_once(notification, device, allow_visible_notification)
                    .await
            },
            oem_family::no_retry_hook,
        )
        .await
    }
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

/// vivo names the recipient `regId`/`alias`; the keyword set differs
/// from OPPO's and Xiaomi's and must stay separate.
fn looks_like_invalid_registration(body: &str) -> bool {
    oem_family::body_mentions(
        body,
        &["regid", "userid", "alias"],
        &["invalid", "not exist", "unregister", "expired"],
    )
}

fn looks_like_vivo_auth_issue(body: &str) -> bool {
    oem_family::body_mentions(body, &["authtoken"], &["invalid", "expired", "not exist"])
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
    fn is_invalid_registration(&self, device: &PushDeviceRoute) -> bool {
        let push_key = device.push_key().unwrap_or_default();
        self.result == 10302
            || self
                .invalid_user
                .as_ref()
                .is_some_and(|user| user.userid.as_deref() == Some(push_key))
            || self
                .invalid_users
                .iter()
                .any(|user| user.userid.as_deref() == Some(push_key))
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
    use arkret_models_integration::{PushDeviceRoute, PushNotificationEnvelope};

    use super::*;

    fn device() -> PushDeviceRoute {
        crate::pushkin::test_fixtures::device("com.example.vivo", "regid")
    }

    fn notification() -> PushNotificationEnvelope {
        crate::pushkin::test_fixtures::notification(vec![device()], None, Some(true))
    }

    fn pushkin() -> VivoPushkin {
        VivoPushkin {
            matcher: AppMatcher::new("com.example.vivo".to_owned()).unwrap(),
            gate: ConcurrencyGate::new(1),
            transport: OemTransport::new(
                &VIVO_METRICS,
                reqwest::Client::builder().build().unwrap(),
                1,
            ),
            auth: VivoAuth {
                app_id: Value::Number(10004.into()),
                app_id_string: "10004".to_owned(),
                app_key: "25509283-3767-4b9e-83fe-b6e55ac6243e".to_owned(),
                app_secret: "7265f2a4-ebbb-44bf-88b9-b03e67dfdc21".to_owned(),
            },
            auth_endpoint: VIVO_AUTH_URL.to_owned(),
            send_endpoint: format!("{VIVO_API_BASE_URL}/message/send"),
            token_cache: ExpiringTokenCache::default(),
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
                    .clone()
                    .into_iter()
                    .collect(),
                ),
                audit_review: None,
                extra: json!({
                    "callback.id": "100"
                })
                .as_object()
                .unwrap()
                .clone()
                .into_iter()
                .collect(),
                client_custom_map: json!({
                    "manual": "override"
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
                .build_request_body(&notification(), &device(), true)
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
        assert!(body.pointer("/clientCustomMap/client").is_none());
        // T4.3 - `content` (m.text body) is no longer mirrored into the
        // freeform clientCustomMap. The opaque push_target_id is what
        // the client uses to fetch the e2ee envelope server-side.
        assert!(
            body.pointer("/clientCustomMap/content").is_none(),
            "vivo clientCustomMap must not carry plaintext content"
        );
        assert_eq!(
            body.pointer("/clientCustomMap/push_target_id"),
            Some(&Value::String(
                "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8".to_owned()
            ))
        );
        assert!(body.pointer("/requestId").and_then(Value::as_str).is_some());
    }

    #[test]
    fn invalid_registration_is_rejected() {
        let result = pushkin()
            .handle_response(
                StatusCode::OK,
                None,
                r#"{"result":10302,"desc":"regId ä¸åˆæ³•","invalidUser":{"status":1,"userid":"regid"}}"#,
                &device(),
            )
            .unwrap();

        assert_eq!(result, vec!["regid".to_owned()]);
    }
}
