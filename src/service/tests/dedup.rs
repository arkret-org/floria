use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use salvo::test::TestClient;
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
        let response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
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

    let first = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header("idempotency-key", "notify-123", true)
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
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
async fn notify_rejects_idempotency_key_in_body() {
    // SPEC-CR-016: the idempotency key rides the `Idempotency-Key` header
    // only; it is no longer a body field. A body `idempotency_key` is now
    // rejected as an unknown field (deny_unknown_fields).
    let service = test_service_with_dedup(vec![], Duration::from_secs(60));
    let request_body =
        with_idempotency_key(payload(vec![device("com.example.app", "one")]), "body-key");

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header("idempotency-key", "header-key", true)
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    assert_notify_error(&mut response, "schema_violation", true).await;
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
        let response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
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
                "event_id": "ak:event:0196419b-0000-7000-8000-000000000001",
                "message_id": "ak:message:0196419b-0000-7000-8000-000000000002",
                "strand_id": "ak:strand:019640f9-8000-7000-8000-000000000000",
                "route_tokens": {
                    "realm_route_token": "realm_route_token_000000001"
                },
                "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
                "timing_profile_hint": "default",
                "push_hint": "new_message",
                "devices": [
                    {"device_id": "ak:device:0196419b-0000-7000-8000-000000000001", "app_id": "com.example.app", "push_key": "cached"},
                    {"device_id": "ak:device:0196419b-0000-7000-8000-000000000001", "app_id": "com.example.app", "push_key": "cached"}
                ]
            }
        }"#;
    let second = r#"{
            "notification": {
                "devices": [
                    {"push_key": "cached", "app_id": "com.example.app", "device_id": "ak:device:0196419b-0000-7000-8000-000000000001"}
                ],
                "push_hint": "new_message",
                "wakeup_kind": "message",
                "timing_profile_hint": "default",
                "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
                "route_tokens": {
                    "realm_route_token": "realm_route_token_000000001"
                },
                "strand_id": "ak:strand:019640f9-8000-7000-8000-000000000000",
                "message_id": "ak:message:0196419b-0000-7000-8000-000000000002",
                "event_id": "ak:event:0196419b-0000-7000-8000-000000000001"
            }
        }"#;

    for request_body in [first, second] {
        let response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
            .add_header("content-type", "application/json", true)
            .text(request_body)
            .send(&service)
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
