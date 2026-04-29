use std::time::Instant;

use blake2::Blake2s256;
use blake2::digest::Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

#[derive(Debug, Clone, Deserialize)]
pub struct NotifyRequest {
    pub notification: Notification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotifyResponse {
    pub request_id: String,
    pub accepted: usize,
    pub rejected: Vec<RejectedDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_retries: Vec<ProviderRetry>,
}

impl NotifyResponse {
    pub fn with_request_id(&self, request_id: impl Into<String>) -> Self {
        let mut cloned = self.clone();
        cloned.request_id = request_id.into();
        cloned
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderRetry {
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl ProviderRetry {
    pub fn new(provider: impl Into<String>, retry_after: Option<std::time::Duration>) -> Self {
        Self {
            provider: provider.into(),
            retry_after_ms: retry_after.map(|value| value.as_millis().min(u64::MAX as u128) as u64),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectedDevice {
    pub push_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

impl RejectedDevice {
    pub fn new(app_id: Option<&str>, push_key: impl Into<String>) -> Self {
        let push_key = push_key.into();
        Self {
            push_key: redact_push_token(&push_key),
            app_id: app_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Notification {
    #[serde(default)]
    pub room_name: Option<String>,
    #[serde(default)]
    pub room_alias: Option<String>,
    #[serde(default)]
    pub space_name: Option<String>,
    #[serde(default)]
    pub prio: Option<String>,
    #[serde(default)]
    pub membership: Option<String>,
    #[serde(default)]
    pub sender_display_name: Option<String>,
    #[serde(default)]
    pub content: Option<Map<String, Value>>,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub room_id: Option<String>,
    #[serde(default)]
    pub space_id: Option<String>,
    #[serde(default)]
    pub user_is_target: Option<bool>,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub sender: Option<String>,
    #[serde(default)]
    pub push_hint: Option<String>,
    #[serde(default)]
    pub devices: Vec<Device>,
    #[serde(default)]
    pub counts: Counts,
}

impl Notification {
    pub fn scope_id(&self) -> Option<&str> {
        non_empty(self.space_id.as_deref()).or(non_empty(self.room_id.as_deref()))
    }

    pub fn scope_name(&self) -> Option<&str> {
        non_empty(self.space_name.as_deref())
            .or(non_empty(self.room_name.as_deref()))
            .or(non_empty(self.room_alias.as_deref()))
    }

    pub fn sender_label(&self) -> Option<&str> {
        non_empty(self.sender_display_name.as_deref()).or(non_empty(self.sender.as_deref()))
    }

    pub fn event_kind(&self) -> Option<&str> {
        non_empty(self.r#type.as_deref())
    }

    pub fn push_hint_text(&self) -> Option<&str> {
        non_empty(self.push_hint.as_deref())
    }

    pub fn content_body(&self) -> Option<&str> {
        self.content
            .as_ref()
            .and_then(|content| content.get("body"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| self.push_hint_text())
    }

    pub fn is_low_priority(&self) -> bool {
        self.prio.as_deref() == Some("low")
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Device {
    pub app_id: String,
    #[serde(alias = "push_key")]
    pub pushkey: String,
    #[serde(default)]
    #[serde(alias = "push_key_ts")]
    pub pushkey_ts: u64,
    #[serde(default)]
    pub data: Option<Map<String, Value>>,
    #[serde(default)]
    pub tweaks: Tweaks,
}

impl Device {
    pub fn data_value(&self, key: &str) -> Option<&Value> {
        self.data.as_ref()?.get(key)
    }

    pub fn data_string(&self, key: &str) -> Option<&str> {
        self.data_value(key)?.as_str()
    }

    pub fn data_bool(&self, key: &str) -> Option<bool> {
        self.data_value(key)?.as_bool()
    }

    pub fn default_payload(&self) -> Result<Map<String, Value>, DefaultPayloadError> {
        let Some(data) = &self.data else {
            return Ok(Map::new());
        };
        let Some(value) = data.get("default_payload") else {
            return Ok(Map::new());
        };
        match value {
            Value::Object(object) => Ok(object.clone()),
            _ => Err(DefaultPayloadError::InvalidType),
        }
    }

    pub fn default_payload_lossy(&self) -> Map<String, Value> {
        self.data_value("default_payload")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
    }

    pub fn redacted_pushkey(&self) -> String {
        redact_push_token(&self.pushkey)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DefaultPayloadError {
    #[error("device default_payload must be a JSON object")]
    InvalidType,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Tweaks {
    #[serde(default)]
    pub sound: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Counts {
    #[serde(default)]
    #[serde(alias = "notification_count")]
    pub unread: Option<u64>,
    #[serde(default)]
    pub missed_calls: Option<u64>,
    #[serde(default)]
    #[serde(alias = "highlight")]
    pub highlight_count: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct NotificationContext {
    pub request_id: String,
    pub start_time: Instant,
}

pub fn redact_push_token(token: &str) -> String {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return "pkh_empty".to_owned();
    }

    let mut hasher = Blake2s256::new();
    hasher.update(trimmed.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("pkh_{}", &digest[..12])
}

pub fn redact_push_tokens(tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .map(|token| redact_push_token(token))
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::Counts;

    #[test]
    fn counts_accept_notification_and_highlight_aliases() {
        let counts: Counts = serde_json::from_value(json!({
            "notification_count": 3,
            "highlight_count": 1
        }))
        .unwrap();

        assert_eq!(counts.unread, Some(3));
        assert_eq!(counts.highlight_count, Some(1));
    }

    #[test]
    fn rejected_device_redacts_push_key() {
        let rejected = super::RejectedDevice::new(Some("com.example.app"), "token-123");

        assert_eq!(rejected.app_id.as_deref(), Some("com.example.app"));
        assert!(rejected.push_key.starts_with("pkh_"));
        assert_ne!(rejected.push_key, "token-123");
    }
}
