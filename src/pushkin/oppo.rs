use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arkret_models_integration::{PushDeviceRoute, PushNotificationEnvelope};
use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::android::{AndroidNotificationPayload, build_android_notification_payload};
use super::oem_family::{self, OemMetrics, OemTransport};
use super::reqwest_support::{ExpiringTokenCache, build_reqwest_client, header_value};
use super::{AppMatcher, ConcurrencyGate, Pushkin, inflight_limit, max_connections};
use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{DeviceExt, NotificationContext};

static OPPO_METRICS: LazyLock<OemMetrics> =
    LazyLock::new(|| OemMetrics::new("oppo", "OPPO Push", "an"));

const OPPO_MAX_TRIES: usize = 3;
const OPPO_RETRY_DELAY_BASE_SECS: u64 = 10;
const OPPO_TOKEN_CACHE_SECS: u64 = 24 * 60 * 60;
const OPPO_AUTH_URL: &str = "https://api.push.oppomobile.com/server/v1/auth";
const OPPO_API_BASE_URL: &str = "https://api.push.oppomobile.com";

pub struct OppoPushkin {
    matcher: AppMatcher,
    vendor: OppoVendor,
    gate: ConcurrencyGate,
    transport: OemTransport,
    auth: OppoAuth,
    auth_endpoint: String,
    send_endpoint: String,
    token_cache: ExpiringTokenCache,
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

        let send_endpoint = format!("{api_base_url}/server/v1/message/notification/unicast");
        crate::egress::validate_http_url_for_egress(&auth_url, "OPPO auth endpoint")
            .map_err(|error| anyhow::anyhow!(error))?;
        crate::egress::validate_http_url_for_egress(&send_endpoint, "OPPO push endpoint")
            .map_err(|error| anyhow::anyhow!(error))?;

        Ok(Self {
            matcher: AppMatcher::new(name)?,
            vendor,
            gate: ConcurrencyGate::new(inflight_limit(app)?),
            transport: OemTransport::new(
                &OPPO_METRICS,
                build_reqwest_client(config, "floria")?,
                max_connections(app)?,
            ),
            auth: OppoAuth {
                app_key,
                master_secret,
            },
            auth_endpoint: auth_url,
            send_endpoint,
            token_cache: ExpiringTokenCache::default(),
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
        let sign = oppo_sign(&self.auth.app_key, &timestamp, &self.auth.master_secret);
        let body = json!({
            "app_key": self.auth.app_key,
            "timestamp": timestamp,
            "sign": sign,
        });

        let response = self
            .transport
            .client()
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
                self.token_cache.store(token.clone(), expires_at).await;
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
        device: &PushDeviceRoute,
        payload: AndroidNotificationPayload,
    ) -> Map<String, Value> {
        let mut body = self.config.request.clone();
        body.insert("target_type".to_owned(), Value::Number(2.into()));
        body.insert(
            "target_value".to_owned(),
            Value::String(device.push_key().unwrap_or_default().to_owned()),
        );
        if payload.title.is_some() && payload.body.is_some() {
            body.insert(
                "notification".to_owned(),
                Value::Object(self.notification_payload(payload)),
            );
        } else if !payload.data.is_empty() {
            body.insert("extra".to_owned(), Value::Object(payload.data));
        }
        body
    }

    fn notification_payload(&self, payload: AndroidNotificationPayload) -> Map<String, Value> {
        let mut notification = self.config.notification.clone();
        if let Some(title) = payload.title {
            notification.insert("title".to_owned(), Value::String(title));
        }
        if let Some(body) = payload.body {
            notification.insert("content".to_owned(), Value::String(body));
        }
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
        device: &PushDeviceRoute,
        payload: AndroidNotificationPayload,
    ) -> Result<Vec<String>, DispatchError> {
        let token = self.access_token().await?;
        let body = self.build_request_body(device, payload);

        let mut headers = HeaderMap::new();
        headers.insert("auth_token", header_value(&token)?);
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let response = self
            .transport
            .send(
                self.name(),
                self.vendor_name(),
                self.transport
                    .client()
                    .post(&self.send_endpoint)
                    .headers(headers)
                    .json(&body),
            )
            .await?;

        // OPPO answers a stale auth_token with 401/403 or a free-text
        // auth complaint on 200; either way the cached token must be
        // dropped so the next attempt re-authenticates.
        if response.status == StatusCode::UNAUTHORIZED
            || response.status == StatusCode::FORBIDDEN
            || looks_like_oppo_auth_issue(&response.body)
        {
            self.invalidate_token().await;
            return Err(DispatchError::temporary(
                oppo_error_message(self.vendor_name(), &response.body, response.status),
                response
                    .retry_after
                    .or(Some(Duration::from_secs(OPPO_RETRY_DELAY_BASE_SECS))),
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
                oppo_error_message(self.vendor_name(), body, status),
                retry_after.or(Some(Duration::from_secs(OPPO_RETRY_DELAY_BASE_SECS))),
            )),
            500..=599 => Err(DispatchError::temporary(
                oppo_error_message(self.vendor_name(), body, status),
                retry_after,
            )),
            200..=299 => match serde_json::from_str::<OppoSendResponse>(body) {
                Ok(response) if response.is_success() => Ok(vec![]),
                Ok(response) if response.is_invalid_target() => {
                    Ok(vec![device.push_key().unwrap_or_default().to_owned()])
                }
                Ok(response) => Err(DispatchError::remote(format!(
                    "{} rejected request: {}",
                    self.vendor_name(),
                    response.message().unwrap_or_else(|| body.to_owned())
                ))),
                Err(_) if looks_like_invalid_target(body) => {
                    Ok(vec![device.push_key().unwrap_or_default().to_owned()])
                }
                Err(_) => Ok(vec![]),
            },
            _ if looks_like_invalid_target(body) => {
                Ok(vec![device.push_key().unwrap_or_default().to_owned()])
            }
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

        if let Some(rejected) =
            oem_family::empty_push_key_rejection(self.vendor_name(), "target_value", device)
        {
            return Ok(rejected);
        }

        let Some(payload) = build_android_notification_payload(
            notification,
            Map::new(),
            context.allow_plaintext_metadata && device.visible_notification_opt_in(),
            self.config.send_badge_counts,
        ) else {
            return Ok(vec![]);
        };

        oem_family::dispatch_with_retries(
            self.vendor_name(),
            OPPO_MAX_TRIES,
            OPPO_RETRY_DELAY_BASE_SECS,
            || {
                let payload = payload.clone();
                async move { self.send_once(device, payload).await }
            },
            oem_family::no_retry_hook,
        )
        .await
    }
}

fn oppo_sign(app_key: &str, timestamp: &str, master_secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(app_key.as_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(master_secret.as_bytes());
    hex::encode(hasher.finalize())
}

/// OPPO reports a dead `target_value` as free text; the vocabulary is
/// vendor-specific and deliberately not shared with vivo/Xiaomi.
fn looks_like_invalid_target(body: &str) -> bool {
    oem_family::body_mentions(
        body,
        &["target", "registration", "token", "userid"],
        &["invalid", "not exist", "unregister", "expired"],
    )
}

fn looks_like_oppo_auth_issue(body: &str) -> bool {
    oem_family::body_mentions(body, &["auth"], &["invalid", "expired", "token"])
}

fn oppo_error_message(vendor_name: &str, body: &str, status: StatusCode) -> String {
    serde_json::from_str::<OppoSendResponse>(body)
        .ok()
        .and_then(|response| response.message())
        .map(|message| format!("{vendor_name} rejected request: {message}"))
        .unwrap_or_else(|| format!("{vendor_name} rejected request: {status} {body}"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OppoAuthResponse {
    #[serde(default)]
    code: Option<i64>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<OppoAuthData>,
}

impl OppoAuthResponse {
    fn is_success(&self) -> bool {
        self.code.unwrap_or(0) == 0
    }

    fn message(self) -> Option<String> {
        self.message
    }

    fn auth_token(&self) -> Option<String> {
        self.data.as_ref().and_then(|data| data.auth_token.clone())
    }

    fn expires_in(&self) -> Duration {
        Duration::from_secs(OPPO_TOKEN_CACHE_SECS)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OppoAuthData {
    #[serde(default)]
    auth_token: Option<String>,
    #[serde(default)]
    #[serde(rename = "create_time")]
    _create_time: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct OppoSendResponse {
    #[serde(default)]
    code: Option<i64>,
    #[serde(default)]
    message: Option<String>,
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
        self.message.clone()
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_integration::{PushDeviceRoute, PushNotificationEnvelope};

    use super::*;

    fn device() -> PushDeviceRoute {
        crate::pushkin::test_fixtures::device("com.example.oppo", "target-value")
    }

    fn notification() -> PushNotificationEnvelope {
        crate::pushkin::test_fixtures::notification(vec![device()], None, Some(true))
    }

    fn pushkin(vendor: OppoVendor) -> OppoPushkin {
        crate::ensure_rustls_crypto_provider();
        OppoPushkin {
            matcher: AppMatcher::new("com.example.oppo".to_owned()).unwrap(),
            vendor,
            gate: ConcurrencyGate::new(1),
            transport: OemTransport::new(
                &OPPO_METRICS,
                reqwest::Client::builder().build().unwrap(),
                1,
            ),
            auth: OppoAuth {
                app_key: "app-key".to_owned(),
                master_secret: "master-secret".to_owned(),
            },
            auth_endpoint: OPPO_AUTH_URL.to_owned(),
            send_endpoint: format!("{OPPO_API_BASE_URL}/server/v1/message/notification/unicast"),
            token_cache: ExpiringTokenCache::default(),
            config: OppoConfig {
                request: Map::new(),
                notification: json!({
                    "style": 1
                })
                .as_object()
                .unwrap()
                .clone()
                .into_iter()
                .collect(),
                click_action_type: Some(1),
                action_parameters: Some(
                    json!({
                        "action_type": 1
                    })
                    .as_object()
                    .unwrap()
                    .clone()
                    .into_iter()
                    .collect(),
                ),
                channel_id: Some("messages".to_owned()),
                send_badge_counts: true,
            },
        }
    }

    #[test]
    fn builds_request_body_with_notification_payload() {
        let device = device();
        let payload =
            build_android_notification_payload(&notification(), Map::new(), true, true).unwrap();

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

    #[test]
    fn auth_response_uses_canonical_oppo_shape() {
        let response: OppoAuthResponse = serde_json::from_str(
            r#"{"code":0,"message":"success","data":{"auth_token":"token-value","create_time":"1"}}"#,
        )
        .unwrap();

        assert!(response.is_success());
        assert_eq!(response.auth_token().as_deref(), Some("token-value"));
        assert_eq!(
            response.expires_in(),
            Duration::from_secs(OPPO_TOKEN_CACHE_SECS)
        );
        assert_eq!(
            response
                .data
                .as_ref()
                .and_then(|data| data._create_time.as_ref()),
            Some(&Value::String("1".to_owned()))
        );

        assert!(
            serde_json::from_str::<OppoAuthResponse>(
                r#"{"code":0,"authToken":"legacy","data":{"authToken":"legacy"}}"#,
            )
            .is_err()
        );
    }
}
