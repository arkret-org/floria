use std::time::Instant;

use blake2::Blake2s256;
use blake2::digest::Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

#[derive(Debug, Clone, Deserialize)]
pub struct NotifyRequest {
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub origin_service_did: Option<String>,
    #[serde(default)]
    pub destination_service_did: Option<String>,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    #[serde(default)]
    pub collapse_key: Option<String>,
    pub notification: Notification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotifyResponse {
    pub request_id: String,
    pub accepted: usize,
    pub rejected: Vec<RejectedDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_retries: Vec<ProviderRetry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_receipts: Vec<DeliveryReceipt>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
            reason: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryReceipt {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Notification {
    #[serde(default)]
    pub flow_name: Option<String>,
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
    pub message_id: Option<String>,
    #[serde(default)]
    pub flow_id: Option<String>,
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
        self.flow_id().or(self.space_id())
    }

    pub fn scope_name(&self) -> Option<&str> {
        self.flow_name().or(self.space_name())
    }

    pub fn flow_id(&self) -> Option<&str> {
        non_empty(self.flow_id.as_deref())
    }

    pub fn message_id(&self) -> Option<&str> {
        non_empty(self.message_id.as_deref())
    }

    pub fn space_id(&self) -> Option<&str> {
        non_empty(self.space_id.as_deref())
    }

    pub fn flow_name(&self) -> Option<&str> {
        non_empty(self.flow_name.as_deref())
    }

    pub fn space_name(&self) -> Option<&str> {
        non_empty(self.space_name.as_deref())
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
    pub pushkey: String,
    #[serde(default)]
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
    pub unread: Option<u64>,
    #[serde(default)]
    pub missed_calls: Option<u64>,
    #[serde(default)]
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

pub fn reject_legacy_notify_contract_fields(path: &str, value: &Value) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if is_legacy_contract_key(key) {
                    return Err(format!(
                        "legacy notify contract field `{path}.{key}` is not supported"
                    ));
                }
                let next_path = format!("{path}.{key}");
                if key == "schema" && value.as_str().is_some_and(looks_like_legacy_contract_value) {
                    return Err(format!(
                        "legacy notify contract value `{next_path}` is not supported"
                    ));
                }
                reject_legacy_notify_contract_fields(&next_path, value)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_legacy_notify_contract_fields(&format!("{path}[{index}]"), value)?;
            }
            Ok(())
        }
        Value::String(value) if path.ends_with(".type") => {
            if looks_like_legacy_event_type(value) || is_legacy_typed_id(value) {
                Err(format!(
                    "legacy notify contract value `{path}` is not supported"
                ))
            } else {
                Ok(())
            }
        }
        Value::String(value) if is_legacy_typed_id(value) => Err(format!(
            "legacy notify contract value `{path}` is not supported"
        )),
        Value::String(_) | Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

pub fn is_legacy_typed_id(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.starts_with("cx:room:")
        || normalized.starts_with("cx:card:")
        || normalized.starts_with("cx:subject:")
}

fn is_legacy_contract_key(key: &str) -> bool {
    let lower = key.trim().to_ascii_lowercase();
    lower == "subject"
        || lower.starts_with("room_")
        || lower.starts_with("card_")
        || lower.starts_with("subject_")
}

fn looks_like_legacy_event_type(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.starts_with("m.room.")
        || normalized.starts_with("m.call.")
        || normalized.contains(".room.")
        || normalized.contains(".card.")
        || normalized.contains(".subject.")
}

fn looks_like_legacy_contract_value(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.contains("room") || normalized.contains("card") || normalized.contains("subject")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        Counts, DeliveryReceipt, NotifyRequest, NotifyResponse,
        reject_legacy_notify_contract_fields,
    };

    #[test]
    fn counts_accept_active_fields() {
        let counts: Counts = serde_json::from_value(json!({
            "unread": 3,
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
        assert!(rejected.reason.is_none());
    }

    #[test]
    fn notify_request_accepts_cx_push_notify_contract_metadata() {
        let request: NotifyRequest = serde_json::from_value(json!({
            "operation_id": "cx.push.notify",
            "idempotency_key": "notify-1",
            "origin_service_did": "did:web:sync.example.com",
            "destination_service_did": "did:web:push.example.com",
            "app_id": "app.example.android",
            "priority": "high",
            "ttl_seconds": 900,
            "collapse_key": "space-1",
            "notification": {
                "event_id": "cx:event:01JS0EV000000000000000000",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "type": "cx.message.create",
                "devices": [{
                    "app_id": "app.example.android",
                    "pushkey": "token-123",
                    "pushkey_ts": 42
                }]
            }
        }))
        .unwrap();

        assert_eq!(request.operation_id.as_deref(), Some("cx.push.notify"));
        assert_eq!(
            request.origin_service_did.as_deref(),
            Some("did:web:sync.example.com")
        );
        assert_eq!(request.priority.as_deref(), Some("high"));
        assert_eq!(request.ttl_seconds, Some(900));
        assert_eq!(request.notification.devices.len(), 1);
    }

    #[test]
    fn notify_response_serializes_delivery_receipt_refs_without_tokens() {
        let response = NotifyResponse {
            request_id: "cx:req:123".to_owned(),
            accepted: 1,
            rejected: vec![super::RejectedDevice::new(
                Some("app.example.android"),
                "token-123",
            )],
            provider_retries: vec![],
            delivery_receipts: vec![DeliveryReceipt {
                provider: Some("fcm".to_owned()),
                provider_message_id: Some("projects/example/messages/1".to_owned()),
                push_key_hash: Some("pkh_abc".to_owned()),
                status: Some("accepted".to_owned()),
                retry_after_ms: None,
                timestamp: Some("2026-05-02T00:00:00Z".to_owned()),
                request_id: Some("cx:req:123".to_owned()),
            }],
        };

        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains("delivery_receipts"));
        assert!(encoded.contains("pkh_"));
        assert!(!encoded.contains("token-123"));
    }

    #[test]
    fn reject_legacy_notify_contract_fields_rejects_legacy_key_names() {
        let error = reject_legacy_notify_contract_fields(
            "notification",
            &json!({
                "room_id": "!legacy:example.com"
            }),
        )
        .unwrap_err();

        assert_eq!(
            error,
            "legacy notify contract field `notification.room_id` is not supported"
        );
    }

    #[test]
    fn reject_legacy_notify_contract_fields_rejects_legacy_typed_ids_in_active_fields() {
        let error = reject_legacy_notify_contract_fields(
            "notification",
            &json!({
                "flow_id": "cx:card:legacy-card"
            }),
        )
        .unwrap_err();

        assert_eq!(
            error,
            "legacy notify contract value `notification.flow_id` is not supported"
        );
    }
}
