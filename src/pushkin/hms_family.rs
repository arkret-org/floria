//! The HMS push family: Huawei Push and HONOR Push.
//!
//! Both vendors expose the same `POST {base}/{app_id}/messages:send`
//! API, the same OAuth2 client-credentials grant, the same request body
//! and the same `{code, msg}` response envelope, so one adapter serves
//! both. The differences that do exist are held on [`HmsVendor`] and
//! are deliberately explicit:
//!
//! * different token and API hosts;
//! * HONOR's console issues a numeric `app_id`, Huawei's a string, so only HONOR accepts a JSON
//!   number in that config field;
//! * separate Prometheus instrument names, one set per vendor.
//!
//! Transport, retry and instrumentation come from [`super::oem_family`],
//! shared with the non-HMS OEM adapters.

use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use arkret_models_integration::{PushNotificationEnvelope, PushRegistrationRecord};
use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::android::{
    AndroidNotificationPayload, AndroidPriority, build_android_notification_payload,
};
use super::oem_family::{self, OemMetrics, OemTransport};
use super::reqwest_support::{
    ClientCredentialsGrant, bearer, build_reqwest_client, looks_like_invalid_token,
};
use super::{AppMatcher, ConcurrencyGate, Pushkin, inflight_limit, max_connections};
use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{DeviceExt, NotificationContext};

static HUAWEI_METRICS: LazyLock<OemMetrics> =
    LazyLock::new(|| OemMetrics::new("huawei", "Huawei Push", "a"));

static HONOR_METRICS: LazyLock<OemMetrics> =
    LazyLock::new(|| OemMetrics::new("honor", "HONOR Push", "an"));

const HMS_MAX_TRIES: usize = 3;
const HMS_RETRY_DELAY_BASE_SECS: u64 = 10;
const HUAWEI_TOKEN_URL: &str = "https://oauth-login.cloud.huawei.com/oauth2/v3/token";
const HUAWEI_API_BASE_URL: &str = "https://push-api.cloud.huawei.com/v1";
const HONOR_TOKEN_URL: &str = "https://hnoauth-login.cloud.honor.com/oauth2/v3/token";
const HONOR_API_BASE_URL: &str = "https://push-api.cloud.honor.com/v1";

/// Which HMS vendor an [`HmsPushkin`] is configured for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HmsVendor {
    Huawei,
    Honor,
}

impl HmsVendor {
    /// Name used in operator-facing errors and log messages.
    fn display(self) -> &'static str {
        match self {
            Self::Huawei => "Huawei Push",
            Self::Honor => "HONOR Push",
        }
    }

    /// Name used in egress-validation labels.
    fn short(self) -> &'static str {
        match self {
            Self::Huawei => "Huawei",
            Self::Honor => "HONOR",
        }
    }

    fn default_token_url(self) -> &'static str {
        match self {
            Self::Huawei => HUAWEI_TOKEN_URL,
            Self::Honor => HONOR_TOKEN_URL,
        }
    }

    fn default_api_base_url(self) -> &'static str {
        match self {
            Self::Huawei => HUAWEI_API_BASE_URL,
            Self::Honor => HONOR_API_BASE_URL,
        }
    }

    fn metrics(self) -> &'static OemMetrics {
        match self {
            Self::Huawei => &HUAWEI_METRICS,
            Self::Honor => &HONOR_METRICS,
        }
    }

    /// Huawei's AppGallery console issues a string `app_id`; HONOR's
    /// issues a bare number, so only HONOR accepts a JSON number here.
    /// Widening Huawei to match would silently accept configs the
    /// vendor rejects at runtime.
    fn read_app_id(self, app: &AppConfig) -> Result<Option<String>> {
        match self {
            Self::Huawei => app.get_string("app_id"),
            Self::Honor => app.extra.get("app_id").map(value_to_string).transpose(),
        }
    }
}

pub struct HmsPushkin {
    matcher: AppMatcher,
    vendor: HmsVendor,
    gate: ConcurrencyGate,
    transport: OemTransport,
    token_grant: ClientCredentialsGrant,
    endpoint: String,
    config: HmsAndroidConfig,
}

impl HmsPushkin {
    pub fn new_huawei(name: String, app: &AppConfig, config: &Config) -> Result<Self> {
        Self::new(name, app, config, HmsVendor::Huawei)
    }

    pub fn new_honor(name: String, app: &AppConfig, config: &Config) -> Result<Self> {
        Self::new(name, app, config, HmsVendor::Honor)
    }

    fn new(name: String, app: &AppConfig, config: &Config, vendor: HmsVendor) -> Result<Self> {
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

        let display = vendor.display();
        let app_id = vendor
            .read_app_id(app)?
            .with_context(|| format!("{display} config requires app_id"))?;
        let app_secret = app
            .get_string("app_secret")?
            .with_context(|| format!("{display} config requires app_secret"))?;
        let token_url = app
            .get_string("token_url")?
            .unwrap_or_else(|| vendor.default_token_url().to_owned());
        let api_base_url = app
            .get_string("api_base_url")?
            .unwrap_or_else(|| vendor.default_api_base_url().to_owned())
            .trim_end_matches('/')
            .to_owned();

        let endpoint = format!("{api_base_url}/{app_id}/messages:send");
        let short = vendor.short();
        crate::egress::validate_http_url_for_egress(&token_url, &format!("{short} token endpoint"))
            .map_err(|error| anyhow!(error))?;
        crate::egress::validate_http_url_for_egress(&endpoint, &format!("{short} push endpoint"))
            .map_err(|error| anyhow!(error))?;

        Ok(Self {
            matcher: AppMatcher::new(name)?,
            vendor,
            gate: ConcurrencyGate::new(inflight_limit(app)?),
            transport: OemTransport::new(
                vendor.metrics(),
                build_reqwest_client(config, "floria")?,
                max_connections(app)?,
            ),
            token_grant: ClientCredentialsGrant::new(app_id, app_secret, token_url),
            endpoint,
            config: HmsAndroidConfig::from_app(app)?,
        })
    }

    fn build_request_body(
        &self,
        device: &PushRegistrationRecord,
        payload: AndroidNotificationPayload,
    ) -> Result<Map<String, Value>, DispatchError> {
        build_request_body(self.vendor.display(), &self.config, device, payload)
    }

    async fn send_once(
        &self,
        device: &PushRegistrationRecord,
        payload: AndroidNotificationPayload,
    ) -> Result<Vec<String>, DispatchError> {
        // The client-credentials grant is deliberately not routed
        // through the transport: token calls take no connection permit
        // and are not counted by the send instruments.
        let token = self
            .token_grant
            .access_token(self.transport.client())
            .await?;
        let body = self.build_request_body(device, payload)?;

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, bearer(&token)?);
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/json; charset=utf-8"),
        );

        let response = self
            .transport
            .send(
                self.name(),
                self.vendor.display(),
                self.transport
                    .client()
                    .post(&self.endpoint)
                    .headers(headers)
                    .json(&body),
            )
            .await?;

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
        device: &PushRegistrationRecord,
    ) -> Result<Vec<String>, DispatchError> {
        handle_response(
            self.vendor.display(),
            HMS_RETRY_DELAY_BASE_SECS,
            status,
            retry_after,
            body,
            device,
        )
    }
}

#[async_trait]
impl Pushkin for HmsPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn handles_app_id(&self, app_id: &str) -> bool {
        self.matcher.handles_app_id(app_id)
    }

    async fn dispatch_notification(
        &self,
        notification: &PushNotificationEnvelope,
        device: &PushRegistrationRecord,
        context: &NotificationContext,
    ) -> Result<Vec<String>, DispatchError> {
        let _permit = self.gate.acquire(self.name())?;

        let display = self.vendor.display();
        if let Some(rejected) = oem_family::empty_push_key_rejection(display, "token", device) {
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
            display,
            HMS_MAX_TRIES,
            HMS_RETRY_DELAY_BASE_SECS,
            || {
                let payload = payload.clone();
                async move { self.send_once(device, payload).await }
            },
            oem_family::no_retry_hook,
        )
        .await
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

#[derive(Debug, Clone)]
pub(super) struct HmsAndroidConfig {
    pub channel_id: Option<String>,
    pub ttl_seconds: Option<u64>,
    pub android_config: Map<String, Value>,
    pub android_notification: Map<String, Value>,
    pub click_action: Option<Map<String, Value>>,
    pub send_badge_counts: bool,
}

impl HmsAndroidConfig {
    pub fn from_app(app: &AppConfig) -> anyhow::Result<Self> {
        Ok(Self {
            channel_id: app.get_string("channel_id")?,
            ttl_seconds: app.get_u64("ttl_seconds")?,
            android_config: app.get_object("android_config")?.unwrap_or_default(),
            android_notification: app.get_object("android_notification")?.unwrap_or_default(),
            click_action: app.get_object("click_action")?,
            send_badge_counts: app.get_bool("send_badge_counts")?.unwrap_or(true),
        })
    }
}

fn build_request_body(
    provider: &str,
    config: &HmsAndroidConfig,
    device: &PushRegistrationRecord,
    payload: AndroidNotificationPayload,
) -> Result<Map<String, Value>, DispatchError> {
    let data = serde_json::to_string(&payload.data).map_err(|error| {
        DispatchError::internal(format!("failed to encode {provider} data payload: {error}"))
    })?;

    let mut message = Map::new();
    message.insert(
        "token".to_owned(),
        Value::Array(vec![Value::String(
            device.push_key().unwrap_or_default().to_owned(),
        )]),
    );
    if let (Some(title), Some(body)) = (&payload.title, &payload.body) {
        message.insert(
            "notification".to_owned(),
            json!({
                "title": title,
                "body": body,
            }),
        );
    }
    message.insert("data".to_owned(), Value::String(data));
    message.insert(
        "android".to_owned(),
        Value::Object(android_config(config, payload)),
    );

    Ok(json!({
        "validate_only": false,
        "message": Value::Object(message),
    })
    .as_object()
    .unwrap()
    .clone()
    .into_iter()
    .collect())
}

fn android_config(
    config: &HmsAndroidConfig,
    payload: AndroidNotificationPayload,
) -> Map<String, Value> {
    let mut android = config.android_config.clone();
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
    if let Some(ttl_seconds) = config.ttl_seconds {
        android.insert("ttl".to_owned(), Value::String(format!("{ttl_seconds}s")));
    }

    if let (Some(title), Some(body)) = (payload.title, payload.body) {
        let mut android_notification = android
            .remove("notification")
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        android_notification.extend(config.android_notification.clone());
        android_notification.insert("title".to_owned(), Value::String(title));
        android_notification.insert("body".to_owned(), Value::String(body));
        if let Some(channel_id) = &config.channel_id {
            android_notification.insert("channel_id".to_owned(), Value::String(channel_id.clone()));
        }
        if let Some(click_action) = &config.click_action {
            android_notification.insert(
                "click_action".to_owned(),
                Value::Object(click_action.clone()),
            );
        }
        android.insert(
            "notification".to_owned(),
            Value::Object(android_notification),
        );
    }

    android
}

fn handle_response(
    provider: &str,
    retry_delay_base_secs: u64,
    status: StatusCode,
    retry_after: Option<std::time::Duration>,
    body: &str,
    device: &PushRegistrationRecord,
) -> Result<Vec<String>, DispatchError> {
    match status.as_u16() {
        429 => Err(DispatchError::temporary(
            error_message(provider, body, status),
            retry_after.or(Some(std::time::Duration::from_secs(retry_delay_base_secs))),
        )),
        500..=599 => Err(DispatchError::temporary(
            error_message(provider, body, status),
            retry_after,
        )),
        200..=299 => match serde_json::from_str::<HmsSendResponse>(body) {
            Ok(response) if response.code.as_deref().is_none_or(is_success_code) => Ok(vec![]),
            Ok(response) if response.is_invalid_token() => {
                Ok(vec![device.push_key().unwrap_or_default().to_owned()])
            }
            Ok(response) => Err(DispatchError::remote(format!(
                "{provider} rejected request: {} {}",
                response.code.unwrap_or_else(|| status.as_u16().to_string()),
                response.msg.unwrap_or_else(|| body.to_owned())
            ))),
            Err(_) if looks_like_invalid_token(body) => {
                Ok(vec![device.push_key().unwrap_or_default().to_owned()])
            }
            Err(_) => Ok(vec![]),
        },
        _ if looks_like_invalid_token(body) => {
            Ok(vec![device.push_key().unwrap_or_default().to_owned()])
        }
        _ => Err(DispatchError::remote(error_message(provider, body, status))),
    }
}

fn is_success_code(code: &str) -> bool {
    matches!(code, "80000000" | "0" | "")
}

fn error_message(provider: &str, body: &str, status: StatusCode) -> String {
    serde_json::from_str::<HmsSendResponse>(body)
        .ok()
        .map(|response| {
            format!(
                "{provider} rejected request: {} {}",
                response.code.unwrap_or_else(|| status.as_u16().to_string()),
                response.msg.unwrap_or_else(|| body.to_owned())
            )
        })
        .unwrap_or_else(|| format!("{provider} rejected request: {status} {body}"))
}

#[derive(Debug, Deserialize)]
struct HmsSendResponse {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    msg: Option<String>,
}

impl HmsSendResponse {
    fn is_invalid_token(&self) -> bool {
        self.msg.as_deref().is_some_and(looks_like_invalid_token)
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_integration::{PushNotificationEnvelope, PushRegistrationRecord};

    use super::*;

    const VENDORS: [(HmsVendor, &str, &str); 2] = [
        (HmsVendor::Huawei, "com.example.huawei", "hw-token"),
        (HmsVendor::Honor, "com.example.honor", "honor-token"),
    ];

    fn device(app_id: &str, push_key: &str) -> PushRegistrationRecord {
        crate::pushkin::test_fixtures::device(app_id, push_key)
    }

    fn notification(device: PushRegistrationRecord) -> PushNotificationEnvelope {
        crate::pushkin::test_fixtures::notification(vec![device], Some("low"), Some(true))
    }

    fn pushkin(vendor: HmsVendor, app_id: &str) -> HmsPushkin {
        HmsPushkin {
            matcher: AppMatcher::new(app_id.to_owned()).unwrap(),
            vendor,
            gate: ConcurrencyGate::new(1),
            transport: OemTransport::new(
                vendor.metrics(),
                reqwest::Client::builder().build().unwrap(),
                1,
            ),
            token_grant: ClientCredentialsGrant::new(
                "12345".to_owned(),
                "secret".to_owned(),
                vendor.default_token_url().to_owned(),
            ),
            endpoint: format!("{}/12345/messages:send", vendor.default_api_base_url()),
            config: HmsAndroidConfig {
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
                    .clone()
                    .into_iter()
                    .collect(),
                ),
                send_badge_counts: true,
            },
        }
    }

    #[test]
    fn builds_request_body() {
        for (vendor, app_id, push_key) in VENDORS {
            let device = device(app_id, push_key);
            let payload = build_android_notification_payload(
                &notification(device.clone()),
                Map::new(),
                true,
                true,
            )
            .unwrap();
            let body = Value::Object(
                pushkin(vendor, app_id)
                    .build_request_body(&device, payload)
                    .unwrap(),
            );

            assert_eq!(
                body.pointer("/message/token/0"),
                Some(&Value::String(push_key.to_owned()))
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

            // T4.3 - the freeform data dictionary must NOT carry stable
            // correlation identifiers any more. push_target_id is the
            // only opaque scope hook that survives.
            let data_blob = body
                .pointer("/message/data")
                .and_then(Value::as_str)
                .unwrap_or_default();
            for forbidden in ["\"strand_id\"", "\"event_id\"", "\"sender\""] {
                assert!(
                    !data_blob.contains(forbidden),
                    "{} data must not carry {forbidden}: {data_blob}",
                    vendor.display()
                );
            }
            assert!(
                data_blob.contains(
                    "\"push_target_id\":\"ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8\""
                ),
                "{} data must carry push_target_id: {data_blob}",
                vendor.display()
            );
        }
    }

    #[test]
    fn invalid_token_response_rejects_push_key() {
        for (vendor, app_id, push_key) in VENDORS {
            let result = pushkin(vendor, app_id)
                .handle_response(
                    StatusCode::OK,
                    None,
                    r#"{"code":"80300007","msg":"invalid token"}"#,
                    &device(app_id, push_key),
                )
                .unwrap();

            assert_eq!(result, vec![push_key.to_owned()]);
        }
    }

    #[test]
    fn success_code_is_treated_as_success() {
        for (vendor, app_id, push_key) in VENDORS {
            let result = pushkin(vendor, app_id)
                .handle_response(
                    StatusCode::OK,
                    None,
                    r#"{"code":"80000000","msg":"Success"}"#,
                    &device(app_id, push_key),
                )
                .unwrap();

            assert!(result.is_empty());
        }
    }

    #[test]
    fn vendor_endpoints_and_display_names_stay_distinct() {
        assert_eq!(HmsVendor::Huawei.display(), "Huawei Push");
        assert_eq!(HmsVendor::Honor.display(), "HONOR Push");
        assert_eq!(HmsVendor::Huawei.short(), "Huawei");
        assert_eq!(HmsVendor::Honor.short(), "HONOR");
        assert_eq!(HmsVendor::Huawei.default_token_url(), HUAWEI_TOKEN_URL);
        assert_eq!(HmsVendor::Honor.default_token_url(), HONOR_TOKEN_URL);
        assert_eq!(
            HmsVendor::Huawei.default_api_base_url(),
            HUAWEI_API_BASE_URL
        );
        assert_eq!(HmsVendor::Honor.default_api_base_url(), HONOR_API_BASE_URL);
    }

    /// HONOR's console issues a numeric `app_id`; Huawei's issues a
    /// string. Accepting a number for Huawei would take a config the
    /// vendor rejects, so the asymmetry is load-bearing.
    #[test]
    fn only_honor_accepts_a_numeric_app_id() {
        let app = AppConfig {
            kind: "honor".to_owned(),
            extra: json!({ "app_id": 12345 })
                .as_object()
                .unwrap()
                .clone()
                .into_iter()
                .collect(),
        };

        assert_eq!(
            HmsVendor::Honor.read_app_id(&app).unwrap().as_deref(),
            Some("12345")
        );
        assert!(HmsVendor::Huawei.read_app_id(&app).is_err());
    }
}
