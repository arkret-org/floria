//! T4.4 — floria honors caller-supplied push_decision hints.
//!
//! floria does not evaluate watch levels itself (that's the Sync
//! Service's job). When the caller pre-decides `dont_notify` it
//! attaches a wire-safe `push_decision` block on the device entry;
//! floria records the device as rejected with the caller's
//! `reason_code` and skips dispatch.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

use super::*;
use crate::audit::AuditEvent;

/// Build a device entry with a `push_decision` block attached.
fn device_with_decision(
    app_id: &str,
    push_key: &str,
    deliver: bool,
    reason_code: Option<&str>,
) -> Value {
    let mut entry = device(app_id, push_key);
    let mut decision = json!({"deliver": deliver});
    if let Some(code) = reason_code {
        decision["reason_code"] = Value::String(code.to_owned());
    }
    entry["push_decision"] = decision;
    entry
}

#[tokio::test]
async fn caller_push_decision_dont_notify_skips_dispatch_and_records_reason() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&payload(vec![device_with_decision(
            "com.example.app",
            "muted-token",
            false,
            Some("muted"),
        )]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<PushNotifyOutcome>().await.unwrap();
    // Caller's `dont_notify` decision propagates to RejectedDevice with
    // the wire-safe reason code.
    assert_eq!(body.accepted, 0);
    assert_eq!(body.rejected.len(), 1);
    assert_eq!(body.rejected[0].reason_code.as_deref(), Some("muted"));
    // The pushkin never sees the device — caller's decision short-
    // circuits dispatch entirely.
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn caller_push_decision_deliver_true_falls_through_to_dispatch() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&payload(vec![device_with_decision(
            "com.example.app",
            "wakeup-token",
            true,
            Some("watch_allows"),
        )]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<PushNotifyOutcome>().await.unwrap();
    // `deliver=true` is treated as pass-through — floria does not
    // surface the `watch_allows` reason on accepted devices because
    // delivery receipts already cover the success path.
    assert_eq!(body.accepted, 1);
    assert_eq!(body.rejected.len(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn missing_push_decision_defaults_to_pass_through() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    // No push_decision attached at all — floria must not assume
    // anything about the watch level and must deliver.
    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "plain-token")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<PushNotifyOutcome>().await.unwrap();
    assert_eq!(body.accepted, 1);
    assert_eq!(body.rejected.len(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn push_decision_internal_reason_field_is_rejected_as_unknown() {
    // Sanity check: deny_unknown_fields keeps soland-internal
    // diagnostic strings (`internal_reason`) from ever reaching
    // floria over the wire.
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut entry = device("com.example.app", "muted-token");
    entry["push_decision"] = json!({
        "deliver": false,
        "reason_code": "muted",
        "internal_reason": "muted_short_circuit",
    });

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&payload(vec![entry]))
        .send(&service)
        .await;

    // Body parsing failure — deny_unknown_fields enforces the privacy
    // boundary at the wire layer.
    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(body["ok"], json!(false));
}

// ────────────────────────────────────────────────────────────────────────
// mention-redirect routing gate, historical_only short-circuit, and audit
// envelope routing (spec B4).
// ────────────────────────────────────────────────────────────────────────

fn device_with_target(app_id: &str, push_key: &str, target_actor_id: &str) -> Value {
    let mut entry = device(app_id, push_key);
    entry["target_actor_id"] = Value::String(target_actor_id.to_owned());
    entry
}

#[tokio::test]
async fn mention_redirect_routing_delivers_when_target_actor_is_listed() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut body = payload(vec![device_with_target(
        "com.example.app",
        "alice-token",
        "did:web:alice.example",
    )]);
    body["notification"]["mention_redirect_target_actor_ids"] =
        json!(["did:web:alice.example", "did:web:bob.example",]);

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<PushNotifyOutcome>().await.unwrap();
    assert_eq!(body.accepted, 1);
    assert!(body.rejected.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mention_redirect_routing_fail_closed_when_target_actor_missing() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let (events, audit_sink) = recording_audit_sink();
    let service = test_service_with_audit_sink(vec![("com.example.app", pushkin)], audit_sink);

    // Device's target_actor_id (carol) is NOT in the routing allow-list
    // (alice / bob). Fail-closed: no provider call, rejected with the
    // wire-safe `mention_redirect_not_targeted` reason.
    let mut body = payload(vec![device_with_target(
        "com.example.app",
        "carol-token",
        "did:web:carol.example",
    )]);
    body["notification"]["mention_redirect_target_actor_ids"] =
        json!(["did:web:alice.example", "did:web:bob.example",]);

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response.take_json::<PushNotifyOutcome>().await.unwrap();
    assert_eq!(resp.accepted, 0);
    assert_eq!(resp.rejected.len(), 1);
    assert_eq!(
        resp.rejected[0].reason_code.as_deref(),
        Some("mention_redirect_not_targeted")
    );
    // Critical: the pushkin MUST NOT see the device — fail-closed means
    // no body decryption can occur at the gateway layer.
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let events = events.lock().await;
    assert_eq!(events.len(), 1);
    let AuditEvent::RejectedDevices {
        origin_service_did,
        notification_event_id,
        notification_strand_id,
        notification_realm_id,
        devices,
        ..
    } = &events[0]
    else {
        panic!("expected rejected_devices audit event");
    };
    assert_eq!(origin_service_did, "<anonymous>");
    assert_eq!(
        notification_event_id.as_deref(),
        Some("ck:event:01JS0EV000000000000000000")
    );
    assert_eq!(
        notification_strand_id.as_deref(),
        Some("ck:strand:019640f9-8000-7000-8000-000000000000")
    );
    assert_eq!(
        notification_realm_id.as_deref(),
        Some("ck:realm:01JS0SP000000000000000000")
    );
    assert_eq!(devices, &resp.rejected);
}

#[tokio::test]
async fn mention_redirect_routing_fail_closed_when_target_actor_id_missing() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    // Device has no target_actor_id at all — the allow-list cannot
    // confirm inclusion, so the same fail-closed path fires.
    let mut body = payload(vec![device("com.example.app", "alice-token")]);
    body["notification"]["mention_redirect_target_actor_ids"] = json!(["did:web:alice.example"]);

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response.take_json::<PushNotifyOutcome>().await.unwrap();
    assert_eq!(resp.accepted, 0);
    assert_eq!(resp.rejected.len(), 1);
    assert_eq!(
        resp.rejected[0].reason_code.as_deref(),
        Some("mention_redirect_not_targeted")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn mention_redirect_empty_list_is_a_no_op() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    // Empty allow-list / missing key means "no mention-redirect in
    // effect". Every device passes the routing gate.
    let mut body = payload(vec![device("com.example.app", "alice-token")]);
    body["notification"]["mention_redirect_target_actor_ids"] = json!([]);

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response.take_json::<PushNotifyOutcome>().await.unwrap();
    assert_eq!(resp.accepted, 1);
    assert!(resp.rejected.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mention_reference_v2_fields_are_not_push_payload_fields() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    // ROST-FLO-1..3 N/A for floria: mention reference v2 is a Message
    // AST concern and MUST NOT be accepted by the push notification
    // wire model.
    let mut body = payload(vec![device("com.example.app", "alice-token")]);
    body["notification"]["subject_id"] = json!("ck:message:01JS0MSG0000000000000000");
    body["notification"]["display_name_at_time"] = json!("Alice");

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(body["error"]["code"], json!("schema_violation"));
}

#[tokio::test]
async fn historical_only_reason_code_short_circuits_without_fanout() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut body = payload(vec![device("com.example.app", "would-be-pushed-token")]);
    body["reason_code"] = json!("historical_only");

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response.take_json::<PushNotifyOutcome>().await.unwrap();
    assert_eq!(resp.accepted, 0);
    assert!(resp.rejected.is_empty());
    assert!(resp.delivery_receipts.is_empty());
    assert!(resp.provider_retries.is_empty());
    // Critical: the soland diagnostic replay MUST NOT trigger a new
    // push fanout.
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unknown_reason_code_is_rejected_as_schema_violation() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut body = payload(vec![device("com.example.app", "x")]);
    body["reason_code"] = json!("some_other_reason");

    let response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn audit_envelope_e2ee_late_recovery_skips_push_pipeline() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let (events, audit_sink) = recording_audit_sink();
    let service = test_service_with_audit_sink(vec![("com.example.app", pushkin)], audit_sink);

    let mut body = payload(vec![device("com.example.app", "x-token")]);
    body["audit_envelope"] = json!({
        "access_kind": "e2ee_late_recovery",
        "late_recovery_original_event_id": "ck:event:01JS0EV000000000000000000",
    });

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response.take_json::<PushNotifyOutcome>().await.unwrap();
    assert_eq!(resp.accepted, 0);
    assert!(resp.rejected.is_empty());
    // Push pipeline MUST be skipped — the request is an audit
    // policy_access notice, routed elsewhere.
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let events = events.lock().await;
    assert_eq!(events.len(), 1);
    let AuditEvent::PolicyAccess {
        origin_service_did,
        access_kind,
        late_recovery_original_event_id,
        notification_event_id,
        notification_strand_id,
        notification_realm_id,
        ..
    } = &events[0]
    else {
        panic!("expected policy_access audit event");
    };
    assert_eq!(origin_service_did, "<anonymous>");
    assert_eq!(access_kind, "e2ee_late_recovery");
    assert_eq!(
        late_recovery_original_event_id.as_deref(),
        Some("ck:event:01JS0EV000000000000000000")
    );
    assert_eq!(
        notification_event_id.as_deref(),
        Some("ck:event:01JS0EV000000000000000000")
    );
    assert_eq!(
        notification_strand_id.as_deref(),
        Some("ck:strand:019640f9-8000-7000-8000-000000000000")
    );
    assert_eq!(
        notification_realm_id.as_deref(),
        Some("ck:realm:01JS0SP000000000000000000")
    );
}

#[tokio::test]
async fn audit_envelope_without_sink_is_temporarily_unavailable() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut body = payload(vec![device("com.example.app", "x-token")]);
    body["audit_envelope"] = json!({
        "access_kind": "e2ee_late_recovery",
        "late_recovery_original_event_id": "ck:event:01JS0EV000000000000000000",
    });

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(body["error"]["code"], json!("temporarily_unavailable"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn audit_envelope_late_recovery_without_original_event_id_is_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut body = payload(vec![device("com.example.app", "x-token")]);
    body["audit_envelope"] = json!({
        "access_kind": "e2ee_late_recovery",
        // missing late_recovery_original_event_id
    });

    let response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}
