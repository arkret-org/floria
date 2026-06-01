//! Round 4 (spec a77b995) — push gateway closures.
//!
//! Covers the four wire-affecting changes carried in by B4:
//!
//! 1. `mention_redirect_target_actor_ids` plaintext routing gate —
//!    devices whose `target_actor_id` is NOT in the allow-list MUST
//!    be fail-closed (no provider dispatch, no body decryption, no
//!    delivery, rejection recorded with `mention_redirect_not_targeted`).
//! 2. `reason_code=historical_only` — soland's diagnostic replay MUST
//!    short-circuit to a 200 idempotency-style ack with no push fanout.
//! 3. `cx.audit.policy_access{access_kind=e2ee_late_recovery}` —
//!    routed to the audit pipeline; the push pipeline MUST be skipped.
//! 4. Round-4 sanitizer hardening — `binding_proof.signature`,
//!    `subject_proof.signature`, `expected_previous_generation`, and
//!    `attestation_evidence` MUST be rejected as forbidden plaintext
//!    fields regardless of profile.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

use super::*;
use crate::audit::AuditEvent;

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

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<NotifyResponse>().await.unwrap();
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

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response.take_json::<NotifyResponse>().await.unwrap();
    assert_eq!(resp.accepted, 0);
    assert_eq!(resp.rejected.len(), 1);
    assert_eq!(
        resp.rejected[0].reason.as_deref(),
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
        notification_flow_id,
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
        Some("cx:event:01JS0EV000000000000000000")
    );
    assert_eq!(
        notification_flow_id.as_deref(),
        Some("cx:flow:01JS0FLOW000000000000000")
    );
    assert_eq!(
        notification_realm_id.as_deref(),
        Some("cx:realm:01JS0SP000000000000000000")
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

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response.take_json::<NotifyResponse>().await.unwrap();
    assert_eq!(resp.accepted, 0);
    assert_eq!(resp.rejected.len(), 1);
    assert_eq!(
        resp.rejected[0].reason.as_deref(),
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

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response.take_json::<NotifyResponse>().await.unwrap();
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
    body["notification"]["subject_id"] = json!("cx:message:01JS0MSG0000000000000000");
    body["notification"]["display_name_at_time"] = json!("Alice");

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
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

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response.take_json::<NotifyResponse>().await.unwrap();
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

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
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
        "late_recovery_original_event_id": "cx:event:01JS0EV000000000000000000",
    });

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response.take_json::<NotifyResponse>().await.unwrap();
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
        notification_flow_id,
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
        Some("cx:event:01JS0EV000000000000000000")
    );
    assert_eq!(
        notification_event_id.as_deref(),
        Some("cx:event:01JS0EV000000000000000000")
    );
    assert_eq!(
        notification_flow_id.as_deref(),
        Some("cx:flow:01JS0FLOW000000000000000")
    );
    assert_eq!(
        notification_realm_id.as_deref(),
        Some("cx:realm:01JS0SP000000000000000000")
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
        "late_recovery_original_event_id": "cx:event:01JS0EV000000000000000000",
    });

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
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

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn round4_sanitizer_rejects_binding_proof_signature() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut body = payload(vec![device("com.example.app", "x-token")]);
    body["notification"]["binding_proof"] = json!({
        "signature": "deadbeef",
    });

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(body["error"]["code"], json!("schema_violation"));
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("binding_proof.signature")
    );
}

#[tokio::test]
async fn round4_sanitizer_rejects_subject_proof_signature() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut body = payload(vec![device("com.example.app", "x-token")]);
    body["notification"]["subject_proof"] = json!({
        "signature": "deadbeef",
    });

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn round4_sanitizer_rejects_expected_previous_generation() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut body = payload(vec![device("com.example.app", "x-token")]);
    body["expected_previous_generation"] = json!(7);

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn round4_sanitizer_rejects_attestation_evidence() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut body = payload(vec![device("com.example.app", "x-token")]);
    body["notification"]["attestation_evidence"] = json!({
        "tee_quote": "deadbeef",
    });

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}
