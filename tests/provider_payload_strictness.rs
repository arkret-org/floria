//! T4.3 — end-to-end snapshot tests for the provider payload
//! sanitization layer.
//!
//! These tests assert that the provider-facing payload that floria
//! emits NEVER carries the stable correlation identifiers
//! (`event_id` / `realm_id` / `space_id` / `flow_id` / `message_id` / sender /
//! space-name / flow-name / `target_did` / call-setup material …) that
//! used to leak via the freeform data dictionary. Coverage is split
//! across three layers:
//!
//!   1. **Builder snapshots** — drive `pushkin::sanitized_provider_payload`
//!      with payload trees that include forbidden keys and assert that
//!      they are stripped (or the request is rejected).
//!   2. **Profile gating** — drive the `/api/v1/push/notify` HTTP
//!      handler with blind-profile callers carrying plaintext content
//!      and assert that the response is `failed_precondition` (412)
//!      with the `plaintext_in_blind_profile` reason.
//!   3. **WebPush collapse key randomness** — drive
//!      `pushkin::random_collapse_key` to confirm two consecutive
//!      calls produce different opaque base64url tokens that don't
//!      embed any `cx:` / typed-id substring.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use floria::AppState;
use floria::auth::ORIGIN_SERVICE_DID_HEADER;
use floria::config::{NotifyAuthConfig, NotifyServicePrincipalConfig};
use floria::error::DispatchError;
use floria::models::{Device, Notification, NotificationContext};
use floria::pushkin::{
    Pushkin, PushkinRegistry, build_blind_provider_data, random_collapse_key,
    sanitized_provider_payload,
};
use floria::service::build_router;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// (1) Provider payload sanitizer — per-provider snapshot assertions.
// ---------------------------------------------------------------------------

#[test]
fn sanitizer_strips_apns_correlation_identifiers() {
    let payload = json!({
        "client": "ios",
        "event_id": "cx:event:01JS0EV000000000000000000",
        "space_id": "cx:space:01JS0SP000000000000000000",
        "flow_id":  "cx:flow:01JS0FLOW000000000000000",
        "message_id": "cx:message:01JS0MSG0000000000000000",
        "sender": "@alice:example.com",
        "sender_display_name": "Alice",
        "flow_name": "Project Apollo",
        "space_name": "Mission Control",
        "wakeup_kind": "message",
    })
    .as_object()
    .unwrap()
    .clone();
    let sanitized = sanitized_provider_payload(payload).unwrap();
    for forbidden in [
        "event_id",
        "space_id",
        "flow_id",
        "message_id",
        "sender",
        "sender_display_name",
        "flow_name",
        "space_name",
    ] {
        assert!(
            sanitized.get(forbidden).is_none(),
            "forbidden field `{forbidden}` survived the sanitizer"
        );
    }
    // Non-forbidden static config keys are preserved.
    assert_eq!(sanitized.get("client"), Some(&json!("ios")));
    assert_eq!(sanitized.get("wakeup_kind"), Some(&json!("message")));
}

#[test]
fn sanitizer_strips_fcm_data_only_forbidden_fields() {
    // FCM v1 used to carry `content_*` keys with the m.text body.
    // None of them are allowed any more.
    let payload = json!({
        "client": "android",
        "content_body": "I'm floating in a most peculiar way.",
        "content_msgtype": "m.text",
        "event_id": "cx:event:01JS0EV000000000000000000",
        "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
        "wakeup_kind": "message",
    })
    .as_object()
    .unwrap()
    .clone();
    let sanitized = sanitized_provider_payload(payload).unwrap();
    assert!(sanitized.get("event_id").is_none());
    // content_body / content_msgtype are not in the forbidden allow-list
    // *by name*, but they carry the same plaintext-correlation risk —
    // the gateway should not be emitting them in the first place. This
    // test pins that they survive a sanitizer call but the BUILDERS
    // never produce them. (See `notify_blind_profile_rejects_plaintext_content`.)
    assert_eq!(sanitized.get("client"), Some(&json!("android")));
}

#[test]
fn sanitizer_strips_webpush_correlation_identifiers() {
    let payload = json!({
        "client": "web",
        "flow_id": "cx:flow:01JS0FLOW000000000000000",
        "space_id": "cx:space:01JS0SP000000000000000000",
        "event_id": "cx:event:01JS0EV000000000000000000",
        "content": {"body": "secret message"},
        "wakeup_kind": "message",
    })
    .as_object()
    .unwrap()
    .clone();
    let sanitized = sanitized_provider_payload(payload).unwrap();
    for forbidden in ["flow_id", "space_id", "event_id", "content"] {
        assert!(
            sanitized.get(forbidden).is_none(),
            "webpush forbidden field `{forbidden}` survived the sanitizer"
        );
    }
}

#[test]
fn sanitizer_rejects_did_literal() {
    let payload = json!({
        "extra": "did:web:bob.example.com",
    })
    .as_object()
    .unwrap()
    .clone();
    let err = sanitized_provider_payload(payload).unwrap_err();
    assert_eq!(err.reason_code, "sensitive_literal");
}

#[test]
fn build_blind_provider_data_emits_only_allowed_fields() {
    // Drive build_blind_provider_data with a fully-populated Notification
    // (via serde_json::from_value to avoid the recipient_service_did /
    // delivery_binding_frontier struct-literal hazard) and assert that
    // only the SDK-allowed blind fields make it out.
    let notification: Notification = serde_json::from_value(json!({
        "flow_name": "Mission Control",
        // Realm/Space reversal — security-boundary name is now `realm_name`.
        "realm_name": "Apollo",
        "sender_display_name": "Major Tom",
        "content": { "body": "Ground control to Major Tom" },
        "event_id":   "cx:event:01JS0EV000000000000000000",
        "message_id": "cx:message:01JS0MSG0000000000000000",
        "flow_id":    "cx:flow:01JS0FLOW000000000000000",
        "realm_id":   "cx:realm:01JS0SP000000000000000000",
        "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
        "wakeup_kind": "message",
        "sender": "@major:example.com",
        "push_hint": "new_message",
        "counts": { "unread": 3 },
    }))
    .unwrap();

    let data = build_blind_provider_data(&notification);
    assert_eq!(
        data.get("push_target_id"),
        Some(&json!("cx:pseudonym:push:01HYZ8Z000000000000000"))
    );
    assert_eq!(data.get("wakeup_kind"), Some(&json!("message")));
    assert_eq!(data.get("push_hint"), Some(&json!("new_message")));
    assert_eq!(data.get("unread_count"), Some(&json!(3)));
    for forbidden in [
        "event_id",
        "message_id",
        "flow_id",
        // Both `space_id` (SDK list since 59ac1d4) and `realm_id`
        // (renamed security boundary) MUST stay off the wire.
        "space_id",
        "realm_id",
        // CXP-0007 — Circle routing identifiers MUST NOT leak.
        "circle_id",
        "effective_scope",
        "scope_circle_id",
        "sender",
        "sender_display_name",
        "flow_name",
        "space_name",
        "realm_name",
        "content",
    ] {
        assert!(
            data.get(forbidden).is_none(),
            "build_blind_provider_data should never emit `{forbidden}`"
        );
    }
}

// ---------------------------------------------------------------------------
// CXP-0007 Circle primitive — privacy invariants.
//
// Circle routing metadata (`circle_id`, `effective_scope`,
// `scope_circle_id`) drives gateway-internal routing only. It MUST
// NOT surface in any provider plaintext payload, regardless of which
// profile (blind / visible) the caller is on — Circle identifiers
// reveal the encryption sub-boundary an observer is looking at and
// the reducer-stamped realm/circle binding.
// ---------------------------------------------------------------------------

#[test]
fn sanitizer_strips_circle_routing_identifiers() {
    let payload = json!({
        "client": "ios",
        "circle_id":         "cx:circle:0196419b-0000-7000-8000-000000000456",
        "effective_scope":   {
            "kind": "circle",
            "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000123",
            "circle_id": "cx:circle:0196419b-0000-7000-8000-000000000456",
        },
        "scope_circle_id":   "cx:circle:0196419b-0000-7000-8000-000000000456",
        "wakeup_kind": "message",
    })
    .as_object()
    .unwrap()
    .clone();
    let sanitized = sanitized_provider_payload(payload).unwrap();
    for forbidden in ["circle_id", "effective_scope", "scope_circle_id"] {
        assert!(
            sanitized.get(forbidden).is_none(),
            "CXP-0007 circle identifier `{forbidden}` survived the sanitizer"
        );
    }
    assert_eq!(sanitized.get("wakeup_kind"), Some(&json!("message")));
}

#[test]
fn sanitizer_strips_nested_circle_metadata() {
    // Circle metadata smuggled inside a provider-defined wrapper (e.g.
    // an APNs `aps` block, an Android `notification` block) must also
    // get stripped by the recursive walk. The strings here are
    // opaque to the sanitizer (it walks by key name, not value
    // shape), so any cx-prefixed string works.
    let payload = json!({
        "client": "android",
        "extra_block": {
            "level_one": {
                "circle_id": "cx:circle:0196419b-0000-7000-8000-000000000456",
                "nested": {
                    "effective_scope": {
                        "kind": "circle",
                        "realm_id": "cx:realm:0196419b-0000-7000-8000-000000000123",
                        "circle_id": "cx:circle:0196419b-0000-7000-8000-000000000456",
                    },
                },
            },
        },
        "wakeup_kind": "message",
    })
    .as_object()
    .unwrap()
    .clone();
    let sanitized = sanitized_provider_payload(payload).unwrap();
    let serialized = serde_json::to_string(&sanitized).unwrap();
    assert!(
        !serialized.contains("circle_id"),
        "nested circle_id leaked through the recursive sanitizer: {serialized}"
    );
    assert!(
        !serialized.contains("effective_scope"),
        "nested effective_scope leaked through the recursive sanitizer: {serialized}"
    );
}

#[test]
fn build_blind_provider_data_never_emits_circle_metadata() {
    // Realm + Circle ids must be canonical lower-case UUIDv7 to satisfy
    // the SDK `EffectiveScope` deserializer (which is strict per
    // `conformance/encoding.md` §4).
    let notification: Notification = serde_json::from_value(json!({
        "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
        "wakeup_kind": "message",
        "realm_id":  "cx:realm:0196419b-0000-7000-8000-000000000123",
        "circle_id": "cx:circle:0196419b-0000-7000-8000-000000000456",
        "effective_scope": {
            "kind": "circle",
            "realm_id":  "cx:realm:0196419b-0000-7000-8000-000000000123",
            "circle_id": "cx:circle:0196419b-0000-7000-8000-000000000456",
        },
        "counts": { "unread": 3 },
    }))
    .unwrap();

    let data = build_blind_provider_data(&notification);
    for forbidden in [
        "circle_id",
        "effective_scope",
        "scope_circle_id",
        "realm_id",
    ] {
        assert!(
            data.get(forbidden).is_none(),
            "blind provider data must never carry `{forbidden}`"
        );
    }
    // The allow-listed blind fields still survive.
    assert_eq!(data.get("wakeup_kind"), Some(&json!("message")));
    assert_eq!(data.get("unread_count"), Some(&json!(3)));
}

// ---------------------------------------------------------------------------
// (2) WebPush collapse-key randomness.
// ---------------------------------------------------------------------------

#[test]
fn webpush_collapse_key_is_random_and_opaque() {
    let keys: Vec<_> = (0..20).map(|_| random_collapse_key()).collect();
    let unique: std::collections::HashSet<_> = keys.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        keys.len(),
        "random_collapse_key collisions in 20 samples: {keys:?}"
    );
    for key in &keys {
        assert!(
            !key.contains(':'),
            "collapse key must not contain `:` (would embed typed id): {key}"
        );
        assert!(
            !key.to_ascii_lowercase().contains("cx:"),
            "collapse key must not contain `cx:` substring: {key}"
        );
        assert!(
            !key.to_ascii_lowercase().contains("did:"),
            "collapse key must not contain `did:` substring: {key}"
        );
        assert!(
            key.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'),
            "collapse key must be base64url-only: {key}"
        );
    }
}

// ---------------------------------------------------------------------------
// (3) HTTP-level profile gating.
// ---------------------------------------------------------------------------

struct AcceptPushkin;

#[async_trait]
impl Pushkin for AcceptPushkin {
    fn name(&self) -> &str {
        "accept"
    }
    fn kind(&self) -> &'static str {
        "noop"
    }
    fn handles_appid(&self, appid: &str) -> bool {
        appid == "com.example.app"
    }
    async fn dispatch_notification(
        &self,
        _notification: &Notification,
        _device: &Device,
        _context: &NotificationContext,
    ) -> Result<Vec<String>, DispatchError> {
        Ok(vec![])
    }
}

fn blind_profile_service() -> salvo::Service {
    // Authenticated principal scoped to the BLIND profile: gives bearer
    // credentials and a delegated service_type that is NOT in the
    // plaintext-eligible kind list. allow_plaintext_metadata must
    // resolve to false at the auth layer regardless of how the operator
    // flipped the flag.
    let mut auth = NotifyAuthConfig::default();
    auth.gateway_service_did = Some("did:web:push.example.com".to_owned());
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.service_type = Some("push".to_owned());
    principal.bearer_tokens = vec!["secret-token".to_owned()];
    principal.allow_plaintext_metadata = true; // operator flipped it on
    auth.service_principals
        .insert("did:web:sync.example.com".to_owned(), principal);

    let registry = PushkinRegistry::new(HashMap::from([(
        "com.example.app".to_owned(),
        Arc::new(AcceptPushkin) as Arc<dyn Pushkin>,
    )]));
    let mut state = AppState::new(Arc::new(registry));
    state.notify_auth = auth;
    salvo::Service::new(build_router(Arc::new(state)))
}

fn visible_profile_service() -> salvo::Service {
    // Authenticated principal scoped to the VISIBLE profile: explicitly
    // a plaintext-eligible service_type (`sync`) AND
    // allow_plaintext_metadata is set, so the visible-notification
    // profile is in effect.
    let mut auth = NotifyAuthConfig::default();
    auth.gateway_service_did = Some("did:web:push.example.com".to_owned());
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.service_type = Some("sync".to_owned());
    principal.bearer_tokens = vec!["secret-token".to_owned()];
    principal.allow_plaintext_metadata = true;
    auth.service_principals
        .insert("did:web:sync.example.com".to_owned(), principal);

    let registry = PushkinRegistry::new(HashMap::from([(
        "com.example.app".to_owned(),
        Arc::new(AcceptPushkin) as Arc<dyn Pushkin>,
    )]));
    let mut state = AppState::new(Arc::new(registry));
    state.notify_auth = auth;
    salvo::Service::new(build_router(Arc::new(state)))
}

fn blind_payload(extra_notification_fields: serde_json::Map<String, Value>) -> Value {
    let mut notification = json!({
        "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
        "wakeup_kind": "message",
        "devices": [{
            "app_id": "com.example.app",
            "push_key": "device-token"
        }]
    });
    let obj = notification.as_object_mut().unwrap();
    obj.extend(extra_notification_fields);
    json!({
        "operation_id": "cx.push.notify",
        "origin_service_did": "did:web:sync.example.com",
        "destination_service_did": "did:web:push.example.com",
        "notification": notification,
    })
}

#[tokio::test]
async fn notify_blind_profile_rejects_plaintext_sender_display_name() {
    let service = blind_profile_service();
    let body = blind_payload(
        json!({"sender_display_name": "Major Tom"})
            .as_object()
            .unwrap()
            .clone(),
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            "x-contrix-destination-service-did",
            "did:web:push.example.com",
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::PRECONDITION_FAILED,
        "blind profile + plaintext sender_display_name must be 412 failed_precondition"
    );
    let body_text = response.take_string().await.unwrap();
    assert!(
        body_text.contains("failed_precondition"),
        "expected failed_precondition code, got: {body_text}"
    );
    assert!(
        body_text.contains("plaintext_in_blind_profile"),
        "expected plaintext_in_blind_profile reason, got: {body_text}"
    );
}

#[tokio::test]
async fn notify_blind_profile_rejects_plaintext_content_body() {
    let service = blind_profile_service();
    let body = blind_payload(
        json!({"content": {"body": "secret message"}})
            .as_object()
            .unwrap()
            .clone(),
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            "x-contrix-destination-service-did",
            "did:web:push.example.com",
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::PRECONDITION_FAILED
    );
    let body_text = response.take_string().await.unwrap();
    assert!(
        body_text.contains("plaintext_in_blind_profile"),
        "expected plaintext_in_blind_profile reason, got: {body_text}"
    );
}

#[tokio::test]
async fn notify_visible_profile_accepts_plaintext_metadata() {
    let service = visible_profile_service();
    let body = blind_payload(
        json!({
            "flow_name": "Mission Control",
            "sender_display_name": "Major Tom",
        })
        .as_object()
        .unwrap()
        .clone(),
    );

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            "x-contrix-destination-service-did",
            "did:web:push.example.com",
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    // Visible-profile caller is allowed to send plaintext metadata.
    // The dispatch goes through the no-op pushkin and returns 200.
    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::OK,
        "visible-profile caller must be allowed to send plaintext metadata"
    );
}

#[tokio::test]
async fn notify_blind_profile_accepts_pure_blind_payload() {
    let service = blind_profile_service();
    let body = blind_payload(serde_json::Map::new());

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            "x-contrix-destination-service-did",
            "did:web:push.example.com",
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::OK,
        "pure blind-wakeup payload must be accepted under the blind profile"
    );
}
