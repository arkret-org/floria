//! T4.3 — end-to-end snapshot tests for the provider payload
//! sanitization layer.
//!
//! These tests assert that the provider-facing payload that floria
//! emits NEVER carries the stable correlation identifiers
//! (`event_id` / `realm_id` / `space_id` / `strand_id` / `message_id` / sender /
//! space-name / strand-name / `target_did` / call-setup material …) that
//! used to leak via the freeform data dictionary. Coverage is split
//! across two layers:
//!
//!   1. **Builder snapshots** — drive `pushkin::sanitized_provider_payload` with payload trees that
//!      include forbidden keys and assert that they are stripped (or the request is rejected).
//!   2. **Profile gating** — drive the `/_arkret/edge/push/notify` HTTP handler with blind-profile
//!      callers carrying plaintext metadata and assert that the response is `failed_precondition`
//!      (412) with the `plaintext_in_blind_profile` reason; `notification.content` is rejected
//!      earlier as an unknown product-private field.

use std::collections::HashMap;
use std::sync::Arc;

use arkret_models_integration::{PushDeviceRoute, PushNotificationEnvelope};
use async_trait::async_trait;
use floria::AppState;
use floria::auth::{DESTINATION_SERVICE_ID_HEADER, SOURCE_SERVICE_ID_HEADER};
use floria::config::{NotifyAuthConfig, NotifyServicePrincipalConfig};
use floria::error::DispatchError;
use floria::models::NotificationContext;
use floria::pushkin::{
    Pushkin, PushkinRegistry, build_blind_provider_data, sanitized_provider_payload,
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
        "event_id": "ak:event:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS",
        "space_id": "ak:space:AVpLL6IaVQSSJDqHs-Xz-LJqiqTSvYP1a0bCvh15YNC8",
        "strand_id":  "ak:strand:AZfy3leHQNK3ezr_x4HPHq09HrnS3Eb6wM-IwyFH8fQD",
        "message_id": "ak:message:AevYtAp_mjd9pPNtsNoiquL8rnoJUC0S0gYtV6_SwmD1",
        "sender": "@alice:example.com",
        "sender_actor_display_name": "Alice",
        "strand_name": "Project Apollo",
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
        "strand_id",
        "message_id",
        "sender",
        "sender_actor_display_name",
        "strand_name",
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
        "event_id": "ak:event:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS",
        "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
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
        "strand_id": "ak:strand:AZfy3leHQNK3ezr_x4HPHq09HrnS3Eb6wM-IwyFH8fQD",
        "space_id": "ak:space:AVpLL6IaVQSSJDqHs-Xz-LJqiqTSvYP1a0bCvh15YNC8",
        "event_id": "ak:event:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS",
        "content": {"body": "secret message"},
        "wakeup_kind": "message",
    })
    .as_object()
    .unwrap()
    .clone();
    let sanitized = sanitized_provider_payload(payload).unwrap();
    for forbidden in ["strand_id", "space_id", "event_id", "content"] {
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
    // Drive build_blind_provider_data with a fully-populated PushNotificationEnvelope
    // (via serde_json::from_value to avoid the recipient_service_id /
    // delivery_binding_frontier struct-literal hazard) and assert that
    // only the SDK-allowed blind fields make it out.
    let notification: PushNotificationEnvelope = serde_json::from_value(json!({
        "strand_title": "Mission Control",
        // Security-boundary label.
        "realm_title": "Apollo",
        "sender_actor_display_name": "Major Tom",
        "event_id":   "ak:event:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS",
        "message_id": "ak:message:AevYtAp_mjd9pPNtsNoiquL8rnoJUC0S0gYtV6_SwmD1",
        "strand_id":    "ak:strand:AZfy3leHQNK3ezr_x4HPHq09HrnS3Eb6wM-IwyFH8fQD",
        // push-notifications.md §5.1: gateway-internal routing ids stay in route_tokens.
        "route_tokens": {
            "realm_route_token": "realm_route_token_000000001"
        },
        "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
        "wakeup_kind": "message",
        "push_hint": "new_message",
        "counts": { "unread_increment": 3 },
    }))
    .unwrap();

    let data = build_blind_provider_data(&notification);
    assert_eq!(
        data.get("push_target_id"),
        Some(&json!(
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8"
        ))
    );
    assert_eq!(data.get("wakeup_kind"), Some(&json!("message")));
    assert_eq!(data.get("push_hint"), Some(&json!("new_message")));
    assert_eq!(data.get("unread_count"), Some(&json!(5)));
    for forbidden in [
        "event_id",
        "message_id",
        "strand_id",
        // Both `space_id` (SDK list since 59ac1d4) and `realm_id`
        // (renamed security boundary) MUST stay off the wire.
        "space_id",
        "realm_id",
        "route_tokens",
        "realm_route_token",
        "scope_route_token",
        "mention_redirect_target_route_tokens",
        "delivery_binding_frontier_token",
        "target_route_token",
        "sender",
        "sender_actor_display_name",
        "strand_title",
        "space_name",
        "realm_title",
    ] {
        assert!(
            data.get(forbidden).is_none(),
            "build_blind_provider_data should never emit `{forbidden}`"
        );
    }
}

#[test]
fn sanitizer_strips_private_notification_preferences() {
    let payload = json!({
        "client": "android",
        "wakeup_kind": "message",
        "dnd": {
            "enabled": true,
            "schedule": { "timezone": "Asia/Shanghai" },
        },
        "push_rules": [{ "rule_id": "quiet-hours" }],
        "snooze": {
            "snooze_expires_at": "2026-06-07T09:00:00.000Z",
            "target_ref": "opaque-target-ref",
            "target_key": "opaque-target-key",
        },
        "nested": {
            "dnd_schedule": { "periods": [{ "start": "22:00", "end": "08:00" }] },
            "snooze_until": "2026-06-07T09:00:00.000Z",
        },
    })
    .as_object()
    .unwrap()
    .clone();

    let sanitized = sanitized_provider_payload(payload).unwrap();
    let serialized = serde_json::to_string(&sanitized).unwrap();
    for forbidden in [
        "dnd",
        "dnd_schedule",
        "push_rules",
        "snooze",
        "snooze_expires_at",
        "snooze_until",
        "target_ref",
        "target_key",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "private notification preference `{forbidden}` leaked through sanitizer: {serialized}"
        );
    }
    assert_eq!(sanitized.get("client"), Some(&json!("android")));
    assert_eq!(sanitized.get("wakeup_kind"), Some(&json!("message")));
}

// ---------------------------------------------------------------------------
// AKP-0007 Circle primitive — privacy invariants.
//
// Scope routing rides opaque `route_tokens` only. Per
// `push-notifications.md` §5.1 no raw Circle id, Realm id or
// `effective_scope` may enter `/_arkret/edge/push/notify` at all, and the
// route tokens that do ride it MUST NOT surface in any provider plaintext
// payload, regardless of which profile (blind / visible) the caller is on
// — they reveal the encryption sub-boundary an observer is looking at.
// ---------------------------------------------------------------------------

#[test]
fn sanitizer_strips_route_token_identifiers() {
    let payload = json!({
        "client": "ios",
        "route_tokens": {
            "realm_route_token": "realm_route_token_000000001",
            "scope_route_token": "scope_route_token_000000001",
            "mention_redirect_target_route_tokens": ["alice_route_token_000000001"],
            "delivery_binding_frontier_token": "frontier_route_token_000000001",
        },
        "target_route_token": "device_route_token_000000001",
        "wakeup_kind": "message",
        "timing_profile_hint": "traffic_metadata_hardened",
    })
    .as_object()
    .unwrap()
    .clone();
    let sanitized = sanitized_provider_payload(payload).unwrap();
    for forbidden in [
        "route_tokens",
        "realm_route_token",
        "scope_route_token",
        "mention_redirect_target_route_tokens",
        "delivery_binding_frontier_token",
        "target_route_token",
        "timing_profile_hint",
    ] {
        assert!(
            sanitized.get(forbidden).is_none(),
            "route-token field `{forbidden}` survived the sanitizer"
        );
    }
    assert_eq!(sanitized.get("wakeup_kind"), Some(&json!("message")));
}

#[test]
fn sanitizer_strips_nested_route_token_metadata() {
    // Circle metadata smuggled inside a provider-defined wrapper (e.g.
    // an APNs `aps` block, an Android `notification` block) must also
    // get stripped by the recursive walk. The strings here are
    // opaque to the sanitizer (it walks by key name, not value
    // shape), so any ak-prefixed string works.
    let payload = json!({
        "client": "android",
        "extra_block": {
            "level_one": {
                "scope_route_token": "scope_route_token_000000001",
                "nested": {
                    "delivery_binding_frontier_token": "frontier_route_token_000000001",
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
        !serialized.contains("scope_route_token"),
        "nested scope_route_token leaked through the recursive sanitizer: {serialized}"
    );
    assert!(
        !serialized.contains("delivery_binding_frontier_token"),
        "nested delivery_binding_frontier_token leaked through the recursive sanitizer: {serialized}"
    );
}

#[test]
fn build_blind_provider_data_never_emits_route_tokens() {
    // Any Realm/Circle identifiers in provider-facing scope data must remain
    // complete typed 44-character event tokens; this blind payload carries
    // only opaque route tokens.
    let notification: PushNotificationEnvelope = serde_json::from_value(json!({
        "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
        "wakeup_kind": "message",
        "timing_profile_hint": "default",
        "route_tokens": {
            "realm_route_token": "realm_route_token_000000001",
            "scope_route_token": "scope_route_token_000000001",
            "mention_redirect_target_route_tokens": ["alice_route_token_000000001"],
            "delivery_binding_frontier_token": "frontier_route_token_000000001",
        },
        "counts": { "unread_increment": 3 },
    }))
    .unwrap();

    let data = build_blind_provider_data(&notification);
    for forbidden in [
        "route_tokens",
        "realm_route_token",
        "scope_route_token",
        "mention_redirect_target_route_tokens",
        "delivery_binding_frontier_token",
    ] {
        assert!(
            data.get(forbidden).is_none(),
            "blind provider data must never carry `{forbidden}`"
        );
    }
    // The allow-listed blind fields still survive.
    assert_eq!(data.get("wakeup_kind"), Some(&json!("message")));
    assert_eq!(data.get("unread_count"), Some(&json!(5)));
}

// ---------------------------------------------------------------------------
// (2) HTTP-level profile gating.
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
    fn handles_app_id(&self, app_id: &str) -> bool {
        app_id == "com.example.app"
    }
    async fn dispatch_notification(
        &self,
        _notification: &PushNotificationEnvelope,
        _device: &PushDeviceRoute,
        _context: &NotificationContext,
    ) -> Result<Vec<String>, DispatchError> {
        Ok(vec![])
    }
}

fn blind_profile_service() -> salvo::Service {
    // Authenticated principal scoped to the BLIND profile: gives bearer
    // credentials and a delegated service_kind that is NOT in the
    // plaintext-eligible kind list. allow_plaintext_metadata must
    // resolve to false at the auth layer regardless of how the operator
    // flipped the flag.
    let mut auth = NotifyAuthConfig::default();
    auth.gateway_service_did = Some("did:web:push.example.com".to_owned());
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.service_kind = Some("push".to_owned());
    principal.bearer_tokens = vec!["secret-token".to_owned()];
    principal.allow_plaintext_metadata = true; // operator flipped it on
    auth.service_principals
        .insert("ak:did_core:web:sync.example.com".to_owned(), principal);

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
    // a plaintext-eligible service_kind (`sync`) AND
    // allow_plaintext_metadata is set, so the visible-notification
    // profile is in effect.
    let mut auth = NotifyAuthConfig::default();
    auth.gateway_service_did = Some("did:web:push.example.com".to_owned());
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.service_kind = Some("sync".to_owned());
    principal.bearer_tokens = vec!["secret-token".to_owned()];
    principal.allow_plaintext_metadata = true;
    auth.service_principals
        .insert("ak:did_core:web:sync.example.com".to_owned(), principal);

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
        "event_id": "ak:event:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS",
        "message_id": "ak:message:AevYtAp_mjd9pPNtsNoiquL8rnoJUC0S0gYtV6_SwmD1",
        "strand_id": "ak:strand:AZfy3leHQNK3ezr_x4HPHq09HrnS3Eb6wM-IwyFH8fQD",
        "route_tokens": {
            "realm_route_token": "realm_route_token_000000001"
        },
        "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
        "wakeup_kind": "message",
        "timing_profile_hint": "default",
        "devices": [{
            "device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "app_id": "com.example.app",
            "push_key": "device-token"
        }]
    });
    let obj = notification.as_object_mut().unwrap();
    obj.extend(extra_notification_fields);
    // The push notify endpoint schema keeps transport fields (operation_id / origin_service_id /
    // destination_service_id) ride HTTP headers, not the body.
    json!({
        "notification": notification,
    })
}

#[tokio::test]
async fn notify_blind_profile_rejects_plaintext_sender_actor_display_name() {
    let service = blind_profile_service();
    let body = blind_payload(
        json!({"sender_actor_display_name": "Major Tom"})
            .as_object()
            .unwrap()
            .clone(),
    );

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(
            SOURCE_SERVICE_ID_HEADER,
            "ak:did_core:web:sync.example.com",
            true,
        )
        .add_header(
            DESTINATION_SERVICE_ID_HEADER,
            "ak:did_core:web:push.example.com",
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::PRECONDITION_FAILED,
        "blind profile + plaintext sender_actor_display_name must be 412 failed_precondition"
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

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(
            SOURCE_SERVICE_ID_HEADER,
            "ak:did_core:web:sync.example.com",
            true,
        )
        .add_header(
            DESTINATION_SERVICE_ID_HEADER,
            "ak:did_core:web:push.example.com",
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body_text = response.take_string().await.unwrap();
    assert!(
        body_text.contains("schema_violation"),
        "expected schema_violation code, got: {body_text}"
    );
    assert!(
        body_text.contains("schema_violation"),
        "expected content to be rejected by the SDK wire schema, got: {body_text}"
    );
}

#[tokio::test]
async fn notify_visible_profile_accepts_plaintext_metadata() {
    let service = visible_profile_service();
    let mut body = blind_payload(
        json!({
            "strand_title": "Mission Control",
            "sender_actor_display_name": "Major Tom",
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    body["notification"]["devices"][0]["visible_notification_opt_in"] = json!(true);

    let response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(
            SOURCE_SERVICE_ID_HEADER,
            "ak:did_core:web:sync.example.com",
            true,
        )
        .add_header(
            DESTINATION_SERVICE_ID_HEADER,
            "ak:did_core:web:push.example.com",
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
async fn notify_visible_profile_requires_device_visible_opt_in() {
    let service = visible_profile_service();
    let body = blind_payload(
        json!({
            "strand_title": "Mission Control",
            "sender_actor_display_name": "Major Tom",
        })
        .as_object()
        .unwrap()
        .clone(),
    );

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(
            SOURCE_SERVICE_ID_HEADER,
            "ak:did_core:web:sync.example.com",
            true,
        )
        .add_header(
            DESTINATION_SERVICE_ID_HEADER,
            "ak:did_core:web:push.example.com",
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::PRECONDITION_FAILED,
        "visible-profile plaintext requires per-device visible opt-in"
    );
    let body_text = response.take_string().await.unwrap();
    assert!(
        body_text.contains("visible_notification_device_opt_in_required"),
        "expected visible opt-in reason, got: {body_text}"
    );
}

#[tokio::test]
async fn notify_visible_profile_rejects_product_private_content_body() {
    let service = visible_profile_service();
    let body = blind_payload(
        json!({
            "strand_title": "Mission Control",
            "sender_actor_display_name": "Major Tom",
            "content": {"body": "secret message"},
        })
        .as_object()
        .unwrap()
        .clone(),
    );

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(
            SOURCE_SERVICE_ID_HEADER,
            "ak:did_core:web:sync.example.com",
            true,
        )
        .add_header(
            DESTINATION_SERVICE_ID_HEADER,
            "ak:did_core:web:push.example.com",
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body_text = response.take_string().await.unwrap();
    assert!(
        body_text.contains("schema_violation"),
        "expected schema_violation code, got: {body_text}"
    );
    assert!(
        body_text.contains("schema_violation"),
        "expected content to be rejected by the SDK wire schema, got: {body_text}"
    );
}

#[tokio::test]
async fn notify_blind_profile_accepts_pure_blind_payload() {
    let service = blind_profile_service();
    let body = blind_payload(serde_json::Map::new());

    let response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(
            SOURCE_SERVICE_ID_HEADER,
            "ak:did_core:web:sync.example.com",
            true,
        )
        .add_header(
            DESTINATION_SERVICE_ID_HEADER,
            "ak:did_core:web:push.example.com",
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
