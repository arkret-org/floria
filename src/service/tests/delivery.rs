use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use salvo::test::TestClient;

use super::*;

#[tokio::test]
async fn rejected_devices_are_reported() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Reject)),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "reject")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(&mut response, vec![]).await;
}

#[tokio::test]
async fn ambiguous_app_ids_are_rejected() {
    let service = test_service(vec![
        (
            "*.example.*",
            Arc::new(TestPushkin::new("*.example.*", TestBehavior::Accept)),
        ),
        (
            "com.example.a*",
            Arc::new(TestPushkin::new("com.example.a*", TestBehavior::Accept)),
        ),
    ]);

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "spqr")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        vec![rejected(Some("com.example.app"), "spqr")],
    )
    .await;
}

#[tokio::test]
async fn remote_provider_errors_do_not_reopen_caller_ownership() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new(
            "com.example.app",
            TestBehavior::RemoteError,
        )),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "remote")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(&mut response, vec![]).await;
}

#[tokio::test]
async fn internal_gateway_errors_return_caller_retryable_outcome() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new(
            "com.example.app",
            TestBehavior::InternalError,
        )),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "boom")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        vec![rejected(Some("com.example.app"), "boom")],
    )
    .await;
}

#[tokio::test]
async fn temporary_errors_without_durable_retry_return_per_device_backoff() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new(
            "com.example.app",
            TestBehavior::TemporaryError,
        )),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "retry")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response
        .take_json::<arkret_models_integration::PushNotifyOutcome>()
        .await
        .unwrap();
    assert_eq!(
        body.outcomes[0].gateway_status,
        arkret_models_integration::PushNotifyGatewayStatus::Rejected
    );
    assert_eq!(
        body.outcomes[0].reason_code,
        Some(arkret_models_integration::PushNotifyReasonCode::PushGatewayUnreachable)
    );
    assert_eq!(body.outcomes[0].retry_after_ms, Some(7_000));
}

#[tokio::test]
async fn oversized_requests_are_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .text("x".repeat(MAX_REQUEST_SIZE + 1))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn per_pushkin_concurrency_limit_does_not_leak_provider_state() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::with_limit(
            "com.example.app",
            TestBehavior::SlowAccept,
            1,
        )),
    )]);

    let request_a = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service);
    let request_b = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service);

    let (response_a, response_b) = tokio::join!(request_a, request_b);
    let statuses = [
        response_a.status_code.unwrap(),
        response_b.status_code.unwrap(),
    ];

    assert_eq!(statuses, [StatusCode::OK, StatusCode::OK]);
}

#[tokio::test]
async fn duplicate_device_ids_are_rejected_at_ingress() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Reject)),
    )]);

    let response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![
            device("com.example.app", "dup"),
            device("com.example.app", "dup"),
        ]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn distinct_device_ids_are_not_deduplicated_within_one_request() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service_with_dedup(
        vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
        Duration::from_secs(60),
    );
    let first = device("com.example.app", "shared-route");
    let mut second = device("com.example.app", "shared-route");
    second["device_id"] = serde_json::json!("ak:device:0196419b-0000-7000-8000-000000000099");

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![first, second]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(&mut response, vec![]).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn blank_device_fields_are_rejected_without_dispatch() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![
            device("   ", "blank-app"),
            device("com.example.app", "   "),
        ]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        vec![
            rejected(None, "blank-app"),
            rejected(Some("com.example.app"), "   "),
        ],
    )
    .await;
}

#[tokio::test]
async fn mixed_success_and_temporary_failure_returns_200() {
    let service = test_service(vec![
        (
            "com.example.ok",
            Arc::new(TestPushkin::new("com.example.ok", TestBehavior::Accept)),
        ),
        (
            "com.example.retry",
            Arc::new(TestPushkin::new(
                "com.example.retry",
                TestBehavior::TemporaryError,
            )),
        ),
    ]);

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![
            device("com.example.ok", "ok"),
            device("com.example.retry", "retry"),
        ]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        vec![rejected(Some("com.example.retry"), "retry")],
    )
    .await;
}

#[tokio::test]
async fn all_temporary_failures_return_conserved_rejections() {
    let service = test_service(vec![(
        "com.example.retry",
        Arc::new(TestPushkin::new(
            "com.example.retry",
            TestBehavior::TemporaryError,
        )),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.retry", "retry")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        vec![rejected(Some("com.example.retry"), "retry")],
    )
    .await;
}

#[tokio::test]
async fn exact_replay_returns_the_original_per_device_outcomes() {
    let success_pushkin = Arc::new(TestPushkin::new("com.example.ok", TestBehavior::Accept));
    let success_calls = success_pushkin.calls.clone();
    let retry_pushkin = Arc::new(TestPushkin::new(
        "com.example.retry",
        TestBehavior::TemporaryError,
    ));
    let retry_calls = retry_pushkin.calls.clone();
    let service = test_service_with_dedup(
        vec![
            ("com.example.ok", success_pushkin as Arc<dyn Pushkin>),
            ("com.example.retry", retry_pushkin as Arc<dyn Pushkin>),
        ],
        Duration::from_secs(60),
    );
    let request_body = payload(vec![
        device("com.example.ok", "ok"),
        device("com.example.retry", "retry"),
    ]);

    let first = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&request_body)
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let second = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&request_body)
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::OK);

    assert_eq!(success_calls.load(Ordering::SeqCst), 1);
    assert_eq!(retry_calls.load(Ordering::SeqCst), 1);
}
