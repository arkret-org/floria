use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::android::{AndroidNotificationPayload, AndroidPriority};
use super::reqwest_support::looks_like_invalid_token;
use crate::config::AppConfig;
use crate::error::DispatchError;
use crate::models::{Device, DeviceExt};

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

pub(super) fn build_request_body(
    provider: &str,
    config: &HmsAndroidConfig,
    device: &Device,
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

pub(super) fn handle_response(
    provider: &str,
    retry_delay_base_secs: u64,
    status: StatusCode,
    retry_after: Option<std::time::Duration>,
    body: &str,
    device: &Device,
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
