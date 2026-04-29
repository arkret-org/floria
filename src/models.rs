use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

#[derive(Debug, Clone, Deserialize)]
pub struct NotifyRequest {
    pub notification: Notification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotifyResponse {
    pub rejected: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Notification {
    #[serde(default)]
    pub room_name: Option<String>,
    #[serde(default)]
    pub room_alias: Option<String>,
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
    pub user_is_target: Option<bool>,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub sender: Option<String>,
    pub devices: Vec<Device>,
    #[serde(default)]
    pub counts: Counts,
}

#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DefaultPayloadError {
    #[error("device default_payload must be a JSON object")]
    InvalidType,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Tweaks {
    #[serde(default)]
    pub sound: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Counts {
    #[serde(default)]
    pub unread: Option<u64>,
    #[serde(default)]
    pub missed_calls: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct NotificationContext {
    pub request_id: String,
    pub start_time: Instant,
}
