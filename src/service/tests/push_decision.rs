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

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device_with_decision(
            "com.example.app",
            "muted-token",
            false,
            Some("muted"),
        )]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<NotifyResponse>().await.unwrap();
    // Caller's `dont_notify` decision propagates to RejectedDevice with
    // the wire-safe reason code.
    assert_eq!(body.accepted, 0);
    assert_eq!(body.rejected.len(), 1);
    assert_eq!(body.rejected[0].reason.as_deref(), Some("muted"));
    // The pushkin never sees the device — caller's decision short-
    // circuits dispatch entirely.
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn caller_push_decision_deliver_true_falls_through_to_dispatch() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device_with_decision(
            "com.example.app",
            "wakeup-token",
            true,
            Some("watch_allows"),
        )]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<NotifyResponse>().await.unwrap();
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
    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "plain-token")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<NotifyResponse>().await.unwrap();
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

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![entry]))
        .send(&service)
        .await;

    // Body parsing failure — deny_unknown_fields enforces the privacy
    // boundary at the wire layer.
    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(body["ok"], json!(false));
}
