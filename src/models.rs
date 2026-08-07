use std::time::Instant;

use blake2::Blake2s256;
use blake2::digest::Digest;
use serde::{Deserialize, Serialize};

pub type Counts = arkret_models_integration::PushCounts;
pub type Device = arkret_models_integration::PushDeviceRoute;
pub type PushNotification = arkret_models_integration::PushNotificationEnvelope;
pub type RouteTokens = arkret_models_integration::PushRouteTokens;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FloriaPushNotifyOutcome {
    pub request_id: String,
    pub push_target_id: String,
    pub outcomes: Vec<arkret_models_integration::PushNotifyDeviceOutcome>,
    pub rejected: Vec<RejectedDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_retries: Vec<ProviderRetry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_receipts: Vec<DeliveryReceipt>,
}

impl FloriaPushNotifyOutcome {
    pub fn with_request_id(&self, request_id: impl Into<String>) -> Self {
        let mut cloned = self.clone();
        cloned.request_id = request_id.into();
        cloned
    }

    pub fn accepted(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| {
                outcome.gateway_status
                    != arkret_models_integration::PushNotifyGatewayStatus::Rejected
            })
            .count()
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
    pub reason_code: Option<String>,
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
            reason_code: None,
        }
    }

    pub fn with_reason_code(mut self, reason_code: Option<&str>) -> Self {
        self.reason_code = reason_code
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        self
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

pub trait NotificationExt {
    fn scope_id(&self) -> Option<&str>;
    fn scope_title(&self) -> Option<&str>;
    fn realm_route_token(&self) -> Option<&str>;
    fn scope_route_token(&self) -> Option<&str>;
    fn delivery_binding_frontier_token(&self) -> Option<&str>;
    fn mention_redirect_target_route_tokens(&self) -> &[String];
    fn strand_id(&self) -> Option<&str>;
    fn message_id(&self) -> Option<&str>;
    fn realm_id(&self) -> Option<&str>;
    fn strand_title(&self) -> Option<&str>;
    fn realm_title(&self) -> Option<&str>;
    fn sender_label(&self) -> Option<&str>;
    fn wakeup_kind(&self) -> Option<&str>;
    fn push_hint_text(&self) -> Option<&str>;
    fn is_low_priority(&self) -> bool;
}

impl NotificationExt for PushNotification {
    fn scope_id(&self) -> Option<&str> {
        self.strand_id().or_else(|| self.realm_id())
    }

    fn scope_title(&self) -> Option<&str> {
        self.strand_title().or_else(|| self.realm_title())
    }

    fn realm_route_token(&self) -> Option<&str> {
        self.route_tokens
            .as_ref()
            .and_then(|routing| routing.realm_route_token.as_deref())
            .and_then(non_empty)
    }

    fn scope_route_token(&self) -> Option<&str> {
        self.route_tokens
            .as_ref()
            .and_then(|routing| routing.scope_route_token.as_deref())
            .and_then(non_empty)
    }

    fn delivery_binding_frontier_token(&self) -> Option<&str> {
        self.route_tokens
            .as_ref()
            .and_then(|routing| routing.delivery_binding_frontier_token.as_deref())
            .and_then(non_empty)
    }

    fn mention_redirect_target_route_tokens(&self) -> &[String] {
        self.route_tokens
            .as_ref()
            .map(|routing| routing.mention_redirect_target_route_tokens.as_slice())
            .unwrap_or(&[])
    }

    fn strand_id(&self) -> Option<&str> {
        self.strand_id
            .as_ref()
            .map(arkret_wire::StrandId::as_str)
            .and_then(non_empty)
    }

    fn message_id(&self) -> Option<&str> {
        self.message_id
            .as_ref()
            .map(arkret_wire::MessageId::as_str)
            .and_then(non_empty)
    }

    fn realm_id(&self) -> Option<&str> {
        self.realm_id
            .as_ref()
            .map(arkret_wire::RealmId::as_str)
            .and_then(non_empty)
    }

    fn strand_title(&self) -> Option<&str> {
        self.strand_title.as_deref().and_then(non_empty)
    }

    fn realm_title(&self) -> Option<&str> {
        self.realm_title.as_deref().and_then(non_empty)
    }

    fn sender_label(&self) -> Option<&str> {
        self.sender_actor_display_name
            .as_deref()
            .and_then(non_empty)
    }

    fn wakeup_kind(&self) -> Option<&str> {
        self.wakeup_kind.as_deref().and_then(non_empty)
    }

    fn push_hint_text(&self) -> Option<&str> {
        self.push_hint.as_deref().and_then(non_empty)
    }

    fn is_low_priority(&self) -> bool {
        self.priority.as_deref() == Some("low")
    }
}

pub trait DeviceExt {
    fn app_id(&self) -> Option<&str>;
    fn push_key(&self) -> Option<&str>;
    fn target_route_token(&self) -> Option<&str>;
    fn visible_notification_opt_in(&self) -> bool;
    fn redacted_push_key(&self) -> String;
}

impl DeviceExt for Device {
    fn app_id(&self) -> Option<&str> {
        self.app_id.as_deref().and_then(non_empty)
    }

    fn push_key(&self) -> Option<&str> {
        self.push_key.as_deref().and_then(non_empty)
    }

    fn target_route_token(&self) -> Option<&str> {
        self.target_route_token.as_deref().and_then(non_empty)
    }

    fn visible_notification_opt_in(&self) -> bool {
        self.visible_notification_opt_in
    }

    fn redacted_push_key(&self) -> String {
        redact_push_token(self.push_key().unwrap_or_default())
    }
}

#[derive(Debug, Clone)]
pub struct NotificationContext {
    pub request_id: String,
    pub start_time: Instant,
    pub allow_plaintext_metadata: bool,
}

fn non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() { None } else { Some(value) }
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        Counts, DeliveryReceipt, FloriaPushNotifyOutcome as PushNotifyOutcome, NotificationExt,
        PushNotification,
    };

    #[test]
    fn notification_uses_priority_wire_field() {
        let notification: PushNotification = serde_json::from_value(json!({
            "priority": "low",
            "devices": []
        }))
        .unwrap();

        assert_eq!(notification.priority.as_deref(), Some("low"));
        assert!(notification.is_low_priority());
    }

    #[test]
    fn counts_accept_active_fields() {
        let counts: Counts = serde_json::from_value(json!({
            "badge": "2-5",
            "unread_increment": 2,
            "missed_call": false
        }))
        .unwrap();

        assert_eq!(
            counts.badge,
            Some(arkret_models_integration::PushCountIndicator::Bucket(
                "2-5".to_owned()
            ))
        );
        assert_eq!(counts.unread_increment, Some(2));
        assert_eq!(
            counts.missed_call,
            Some(arkret_models_integration::PushCountIndicator::Present(
                false
            ))
        );
    }

    #[test]
    fn counts_reject_absolute_integer_indicators() {
        for absolute_count in [0, 1, 99] {
            let result = serde_json::from_value::<Counts>(json!({
                "missed_call": absolute_count
            }));

            assert!(result.is_err());
        }
    }

    #[test]
    fn counts_accept_boolean_and_bucket_indicators() {
        for indicator in [json!(false), json!(true), json!("2-5")] {
            assert!(serde_json::from_value::<Counts>(json!({ "missed_call": indicator })).is_ok());
        }
    }

    #[test]
    fn rejected_device_redacts_push_key() {
        let rejected = super::RejectedDevice::new(Some("com.example.app"), "token-123");

        assert_eq!(rejected.app_id.as_deref(), Some("com.example.app"));
        assert!(rejected.push_key.starts_with("pkh_"));
        assert_ne!(rejected.push_key, "token-123");
        assert!(rejected.reason_code.is_none());
    }

    #[test]
    fn notify_request_accepts_cx_push_notify_contract_metadata() {
        let request: arkret_models_integration::PushNotifyRequestBody =
            serde_json::from_value(json!({
                "event_kind": "ak.message",
                "notification": {
                    "event_id": "ak:event:0196419b-0000-7000-8000-000000000001",
                    "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
                    "wakeup_kind": "message",
                    "realm_id": "ak:realm:AYZQCyAMEvY_8vHSQUIly6vISE8zV9kwLHkd17skJdyW",
                    "route_tokens": {
                        "realm_route_token": "realm_route_token_000000001"
                    },
                    "devices": [{
                        "device_id": "ak:device:0196419b-0000-7000-8000-000000000004",
                        "app_id": "app.example.android",
                        "push_key": "token-123"
                    }]
                }
            }))
            .unwrap();

        assert_eq!(request.event_kind.as_deref(), Some("ak.message"));
        assert_eq!(
            request.notification.realm_id(),
            Some("ak:realm:AYZQCyAMEvY_8vHSQUIly6vISE8zV9kwLHkd17skJdyW")
        );
        assert_eq!(
            request.notification.realm_route_token(),
            Some("realm_route_token_000000001")
        );
        assert_eq!(request.notification.devices.len(), 1);
    }

    #[test]
    fn notify_envelope_rejects_transport_fields_in_body() {
        for field in [
            "operation_id",
            "idempotency_key",
            "origin_service_id",
            "destination_service_id",
        ] {
            let err =
                serde_json::from_value::<arkret_models_integration::PushNotifyRequestBody>(json!({
                    field: "x",
                    "notification": { "devices": [] }
                }))
                .unwrap_err();
            assert!(
                err.to_string().contains("unknown field"),
                "expected `{field}` to be rejected in body, got: {err}"
            );
        }
    }

    #[test]
    fn notify_response_serializes_delivery_receipt_refs_without_tokens() {
        let response = PushNotifyOutcome {
            request_id: "ak:request:123".to_owned(),
            push_target_id: "ak:pseudonym:push:01HYZ8Z000000000000000".to_owned(),
            outcomes: vec![
                arkret_models_integration::PushNotifyDeviceOutcome::accepted(
                    arkret_wire::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000004")
                        .unwrap(),
                ),
            ],
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
                timestamp: Some("2026-05-02T00:00:00.000Z".to_owned()),
                request_id: Some("ak:request:123".to_owned()),
            }],
        };

        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains("delivery_receipts"));
        assert!(encoded.contains("pkh_"));
        assert!(!encoded.contains("token-123"));
    }
}
