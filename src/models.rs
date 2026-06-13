use std::time::Instant;

use blake2::Blake2s256;
use blake2::digest::Digest;
use cokret::EffectiveScope;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FloriaPushNotifyEnvelope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_service_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_service_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<String>,
    /// Round 4 (spec a77b995) — caller-supplied wire-safe `reason_code`
    /// on the inbound request. When set to
    /// [`cokret::ERROR_CODE_HISTORICAL_ONLY`] the request is a soland
    /// diagnostic replay and MUST NOT trigger a fresh push fanout — the
    /// gateway answers a 200 idempotency-style ack instead. Other values
    /// are rejected with `schema_violation` (floria only honors the
    /// `historical_only` no-op shape).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    /// Round 4 — `ck.audit.policy_access` envelope routing fragment.
    /// When present, the request is an audit-pipeline event (e.g. an
    /// `e2ee_late_recovery` access notice), NOT a push notify. The
    /// gateway writes the audit event, acks with 200, and skips the
    /// push pipeline entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_envelope: Option<AuditEnvelopeMetadata>,
    pub notification: Notification,
}

/// Round 4 — typed `ck.audit.policy_access` envelope routing fragment
/// carried alongside a `ck.edge.push.notify` request. Receiving the
/// `e2ee_late_recovery` access_kind here means soland routed an audit
/// event through the gateway's HTTP surface; the gateway forwards it
/// to the configured audit sink and MUST NOT do any push fanout.
/// Mirrors [`cokret::AuditPolicyAccessPayload`] but with
/// only the wire fields floria needs to make the routing decision.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditEnvelopeMetadata {
    /// `ck.audit.policy_access.access_kind`. The round-4 enum widens
    /// to include `e2ee_late_recovery`; floria specifically branches
    /// on that value to skip the push pipeline.
    pub access_kind: String,
    /// REQUIRED when `access_kind == e2ee_late_recovery`. References
    /// the original event the late recovery targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_recovery_original_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FloriaPushNotifyOutcome {
    pub request_id: String,
    pub accepted: usize,
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

    /// Attach a wire-safe reason code. Empty / whitespace strings are
    /// dropped — floria never emits an empty `reason_code` field, only
    /// `None`. The matching T4.4 contract is: caller is responsible
    /// for using only the wire-safe `reason_code` set (e.g.
    /// `muted` / `not_mentioned` / `not_participating`); internal
    /// diagnostic strings are caller's problem to suppress before
    /// they reach floria.
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

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Notification {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_title: Option<String>,
    /// Human-readable label for the Realm security boundary. Container
    /// Space names do not surface on the push wire model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_actor_display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    /// Security-boundary id (`ck:realm:`). Container `space_id` is
    /// forbidden on the push wire model and does not appear on this struct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    /// CKP-0007 Circle primitive (spec b7d35be) — typed `ck:circle:` id
    /// of the encryption sub-boundary this notification belongs to. When
    /// present, routing / dedup / per-(provider,realm,circle) circuit
    /// breaker stats key off this id rather than the parent realm so two
    /// flows with the same name in different Circles do not collide.
    /// Plaintext `circle_id` is NEVER forwarded to providers — it lives
    /// on the wire only to drive gateway-internal routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circle_id: Option<String>,
    /// CKP-0007 — reducer-stamped envelope scope binding mirrored on the
    /// push wire model (`event_envelope.effective_scope`). Carries the
    /// `{realm_id}` (Realm-default scope) or `{realm_id, circle_id}`
    /// (Circle scope) discriminator the principal server stamped onto
    /// the originating Event. When present and inconsistent with the
    /// notification's `realm_id` / `circle_id` the request is rejected
    /// with `effective_scope_mismatch`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<EffectiveScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_is_target: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_target_id: Option<String>,
    /// Service DID of the recipient Principal Server this push is scoped
    /// to. Spec 0a5ab85: `push_target_id` cell_subject is composite over
    /// `(recipient_service_did, principal_id, device_id, push_route)`;
    /// dispatch MUST validate the inbound binding matches this scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_service_did: Option<String>,
    /// Receiver's accepted Realm delivery-binding frontier when the
    /// notify originated from a federation hop. Receiver returns
    /// `delivery_binding_stale` if its accepted frontier is ahead.
    /// Delivery binding is a Realm-level concept. Spec 0a5ab85 §4.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_binding_frontier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wakeup_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_hint: Option<String>,
    /// Round 4 (spec a77b995, commit 7fae9ba) — plaintext routing
    /// fragment that mirrors the SDK's
    /// [`cokret::MentionRedirectRouting`]. When the list is non-empty
    /// each device's [`Device::target_actor_id`] MUST appear in this
    /// allow-list or the device is failed-closed (rejected without
    /// fanout, no provider call, no body decryption). An empty / missing
    /// list means "no mention-redirect scope is in effect" — every
    /// device passes the routing gate. The receiver gets to verify its
    /// inclusion via this plaintext field WITHOUT needing to decrypt
    /// the message blob.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mention_redirect_target_actor_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<Device>,
    #[serde(default)]
    pub counts: Counts,
}

impl Notification {
    /// CKP-0007 — the most-specific scope id the gateway should key
    /// per-(provider, scope) state off (rate limits, circuit breaker
    /// windows, retry queues). Precedence:
    ///   1. `circle_id` (encryption sub-boundary)
    ///   2. `flow_id`   (Realm-default-scoped conversation)
    ///   3. `realm_id`  (security boundary)
    pub fn scope_id(&self) -> Option<&str> {
        self.circle_id()
            .or_else(|| self.flow_id())
            .or_else(|| self.realm_id())
    }

    pub fn scope_title(&self) -> Option<&str> {
        self.flow_title().or(self.realm_title())
    }

    pub fn circle_id(&self) -> Option<&str> {
        non_empty(self.circle_id.as_deref())
    }

    pub fn flow_id(&self) -> Option<&str> {
        non_empty(self.flow_id.as_deref())
    }

    pub fn message_id(&self) -> Option<&str> {
        non_empty(self.message_id.as_deref())
    }

    pub fn realm_id(&self) -> Option<&str> {
        non_empty(self.realm_id.as_deref())
    }

    pub fn flow_title(&self) -> Option<&str> {
        non_empty(self.flow_title.as_deref())
    }

    pub fn realm_title(&self) -> Option<&str> {
        non_empty(self.realm_title.as_deref())
    }

    pub fn sender_label(&self) -> Option<&str> {
        non_empty(self.sender_actor_display_name.as_deref())
    }

    pub fn wakeup_kind(&self) -> Option<&str> {
        non_empty(self.wakeup_kind.as_deref())
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
        self.priority.as_deref() == Some("low")
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub push_key: String,
    pub app_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Map<String, Value>>,
    #[serde(default)]
    pub tweaks: Tweaks,
    /// T4.4 — Caller-supplied push-rule decision. When `deliver=false`
    /// floria records the device as rejected with the supplied
    /// `reason_code` (without re-evaluating watch-level rules, which
    /// are the Sync Service's responsibility). When absent the device
    /// is treated as delivery-eligible. Internal reasons never travel
    /// across this hop — only the wire-safe `reason_code` is honored,
    /// matching the `ck.edge.push.notify` privacy descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_decision: Option<PushDecisionHint>,
    /// Round 4 (spec a77b995) — actor DID this device's user is
    /// registered as on the recipient principal server. Used as the
    /// lookup key for the plaintext
    /// [`Notification::mention_redirect_target_actor_ids`] allow-list.
    /// MUST be a DID (the SDK enforces the round-4 tightened DID regex
    /// upstream); floria treats it as an opaque token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<String>,
}

/// T4.4 — Caller-supplied wire-safe push-rule decision hint.
///
/// floria does **not** evaluate watch levels itself — receiver-level
/// muted / mentions_only / participating / all checks are the Sync
/// Service's job. When the caller has already evaluated and chose to
/// skip the device, it forwards the decision here so the rejection
/// surfaces with a stable wire reason (e.g. `not_mentioned`) in the
/// delivery receipt.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PushDecisionHint {
    /// `true` if the dispatcher should fan the device out to the
    /// gateway. `false` means caller's rule engine already decided
    /// `dont_notify`.
    #[serde(default = "default_deliver")]
    pub deliver: bool,
    /// `true` when delivery should be a body-free blind wakeup. Only
    /// meaningful when `deliver=true`. floria does not currently
    /// rewrite the wakeup_kind based on this flag — it's recorded for
    /// downstream observability.
    #[serde(default)]
    pub blind_wakeup: bool,
    /// Wire-safe reason code. Mirrored into
    /// `RejectedDevice.reason_code` when `deliver=false`. Empty / missing
    /// is treated as `dont_notify` (no public reason emitted) — this
    /// keeps the wire surface tight without leaking diagnostics.
    #[serde(default)]
    pub reason_code: Option<String>,
}

fn default_deliver() -> bool {
    true
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

    pub fn redacted_push_key(&self) -> String {
        redact_push_token(&self.push_key)
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        Counts, DeliveryReceipt, FloriaPushNotifyEnvelope as PushNotifyRequestBody,
        FloriaPushNotifyOutcome as PushNotifyOutcome, Notification,
    };

    #[test]
    fn notification_uses_priority_wire_field() {
        let notification: Notification = serde_json::from_value(json!({
            "priority": "low",
            "devices": []
        }))
        .unwrap();

        assert_eq!(notification.priority.as_deref(), Some("low"));
        assert!(notification.is_low_priority());
    }

    #[test]
    fn notification_rejects_legacy_prio_wire_field() {
        let err = serde_json::from_value::<Notification>(json!({
            "prio": "low",
            "devices": []
        }))
        .unwrap_err();

        assert!(
            err.to_string().contains("unknown field `prio`"),
            "expected legacy prio to be rejected, got: {err}"
        );
    }

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
        assert!(rejected.reason_code.is_none());
    }

    #[test]
    fn notify_request_accepts_cx_push_notify_contract_metadata() {
        let request: PushNotifyRequestBody = serde_json::from_value(json!({
            "operation_id": "ck.edge.push.notify",
            "idempotency_key": "notify-1",
            "origin_service_did": "did:web:sync.example.com",
            "destination_service_did": "did:web:push.example.com",
            "event_kind": "ck.message",
            "notification": {
                "event_id": "ck:event:01JS0EV000000000000000000",
                "realm_id": "ck:realm:01JS0SP000000000000000000",
                "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
                "devices": [{
                    "app_id": "app.example.android",
                    "push_key": "token-123"
                }]
            }
        }))
        .unwrap();

        assert_eq!(request.operation_id.as_deref(), Some("ck.edge.push.notify"));
        assert_eq!(
            request.origin_service_did.as_deref(),
            Some("did:web:sync.example.com")
        );
        assert_eq!(request.event_kind.as_deref(), Some("ck.message"));
        assert_eq!(request.notification.devices.len(), 1);
    }

    #[test]
    fn notify_response_serializes_delivery_receipt_refs_without_tokens() {
        let response = PushNotifyOutcome {
            request_id: "ck:request:123".to_owned(),
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
                request_id: Some("ck:request:123".to_owned()),
            }],
        };

        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains("delivery_receipts"));
        assert!(encoded.contains("pkh_"));
        assert!(!encoded.contains("token-123"));
    }
}
