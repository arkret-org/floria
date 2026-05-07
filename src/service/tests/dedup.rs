use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use salvo::test::{ResponseExt, TestClient};
use serde_json::json;

use super::*;

#[tokio::test]
async fn notify_supports_header_idempotency_key_replay() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service_with_dedup(
        vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
        Duration::from_secs(60),
    );
    let request_body = payload(vec![device("com.example.app", "cached")]);

    for _ in 0..2 {
        let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .add_header("idempotency-key", "notify-123", true)
            .json(&request_body)
            .send(&service)
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn notify_duplicate_idempotency_key_with_different_body_returns_conflict() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service_with_dedup(
        vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
        Duration::from_secs(60),
    );

    let first = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("idempotency-key", "notify-123", true)
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("idempotency-key", "notify-123", true)
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::CONFLICT);
    let body = assert_notify_error(&mut second, "duplicate_conflict", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("same idempotency key maps to different canonical request body")
    );

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn notify_rejects_mismatched_header_and_body_idempotency_keys() {
    let service = test_service_with_dedup(vec![], Duration::from_secs(60));
    let request_body =
        with_idempotency_key(payload(vec![device("com.example.app", "one")]), "body-key");

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("idempotency-key", "header-key", true)
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = assert_notify_error(&mut response, "schema_violation", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("Idempotency-Key header does not match body idempotency_key")
    );
}

#[tokio::test]
async fn notify_dedup_cache_serves_repeated_success_without_redispatch() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service_with_dedup(
        vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
        Duration::from_secs(60),
    );
    let request_body = payload(vec![device("com.example.app", "cached")]);

    for _ in 0..2 {
        let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .json(&request_body)
            .send(&service)
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn notify_dedup_cache_matches_reordered_equivalent_payloads() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service_with_dedup(
        vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
        Duration::from_secs(60),
    );

    let first = r#"{
            "notification": {
                "event_id": "cx:event:01JS0EV000000000000000000",
                "message_id": "cx:message:01JS0MSG0000000000000000",
                "flow_id": "cx:flow:01JS0FLOW000000000000000",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "sender": "did:web:alice.example.com",
                "sender_display_name": "Alice",
                "type": "cx.message.create",
                "push_hint": "New message",
                "devices": [
                    {"app_id": "com.example.app", "pushkey": "cached", "pushkey_ts": 42},
                    {"app_id": "com.example.app", "pushkey": "cached", "pushkey_ts": 42}
                ]
            }
        }"#;
    let second = r#"{
            "notification": {
                "devices": [
                    {"pushkey_ts": 42, "pushkey": "cached", "app_id": "com.example.app"}
                ],
                "push_hint": "New message",
                "type": "cx.message.create",
                "sender_display_name": "Alice",
                "sender": "did:web:alice.example.com",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "flow_id": "cx:flow:01JS0FLOW000000000000000",
                "message_id": "cx:message:01JS0MSG0000000000000000",
                "event_id": "cx:event:01JS0EV000000000000000000"
            }
        }"#;

    for request_body in [first, second] {
        let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .add_header("content-type", "application/json", true)
            .text(request_body)
            .send(&service)
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
