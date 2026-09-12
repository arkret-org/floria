use std::time::Instant;

use arkret_models_integration::{
    PushNotificationEnvelope, PushNotifyDeviceOutcome, PushNotifyOutcome, PushRegistrationRecord,
};
use blake2::Blake2s256;
use blake2::digest::Digest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotifyDispatchResult {
    pub request_id: String,
    pub wire_outcome: PushNotifyOutcome,
}

impl NotifyDispatchResult {
    pub fn new(
        request_id: impl Into<String>,
        push_target_id: arkret_wire::PushTargetId,
        outcomes: Vec<PushNotifyDeviceOutcome>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            wire_outcome: PushNotifyOutcome {
                push_target_id,
                outcomes,
            },
        }
    }

    pub fn with_request_id(&self, request_id: impl Into<String>) -> Self {
        let mut cloned = self.clone();
        cloned.request_id = request_id.into();
        cloned
    }

    pub fn accepted(&self) -> usize {
        self.wire_outcome
            .outcomes
            .iter()
            .filter(|outcome| {
                outcome.gateway_status
                    != arkret_models_integration::PushNotifyGatewayStatus::Rejected
            })
            .count()
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
pub(crate) struct DeliveryReceipt {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provider_message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) push_key_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) request_id: Option<String>,
}

pub trait NotificationExt {
    fn scope_title(&self) -> Option<&str>;
    fn realm_route_token(&self) -> Option<&str>;
    fn scope_route_token(&self) -> Option<&str>;
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

impl NotificationExt for PushNotificationEnvelope {
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
    fn visible_notification_opt_in(&self) -> bool;
    fn redacted_push_key(&self) -> String;
}

impl DeviceExt for PushRegistrationRecord {
    fn app_id(&self) -> Option<&str> {
        self.app_id.as_deref().and_then(non_empty)
    }

    fn push_key(&self) -> Option<&str> {
        non_empty(self.push_key.as_str())
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
    use arkret_models_integration::{PushCounts, PushNotificationEnvelope};
    use serde_json::json;

    use super::{NotificationExt, NotifyDispatchResult};

    #[test]
    fn notification_uses_priority_wire_field() {
        let notification: PushNotificationEnvelope = serde_json::from_value(json!({
            "priority": "low",
            "devices": []
        }))
        .unwrap();

        assert_eq!(notification.priority.as_deref(), Some("low"));
        assert!(notification.is_low_priority());
    }

    #[test]
    fn counts_accept_active_fields() {
        let counts: PushCounts = serde_json::from_value(json!({
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
            let result = serde_json::from_value::<PushCounts>(json!({
                "missed_call": absolute_count
            }));

            assert!(result.is_err());
        }
    }

    #[test]
    fn counts_accept_boolean_and_bucket_indicators() {
        for indicator in [json!(false), json!(true), json!("2-5")] {
            assert!(
                serde_json::from_value::<PushCounts>(json!({ "missed_call": indicator })).is_ok()
            );
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
                    "event_id": "ak:event:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS",
                    "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
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
            "origin_id",
            "destination_id",
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
    fn notify_response_carries_no_provider_identifiers() {
        let response = NotifyDispatchResult::new(
            "ak:request:0196419b-0000-7000-8000-000000000010",
            arkret_wire::PushTargetId::new(
                "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            )
            .unwrap(),
            vec![
                arkret_models_integration::PushNotifyDeviceOutcome::accepted(
                    arkret_wire::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000004")
                        .unwrap(),
                ),
            ],
        );

        let encoded = serde_json::to_string(&response.wire_outcome).unwrap();
        for forbidden in [
            "push_key",
            "app_id",
            "provider_message_id",
            "push_key_hash",
            "rejected",
            "provider_retries",
            "delivery_receipts",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "notify response must not contain `{forbidden}`, got: {encoded}"
            );
        }
    }
}
