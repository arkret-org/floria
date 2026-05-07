use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use salvo::test::{ResponseExt, TestClient};

use super::*;

#[tokio::test]
async fn rejected_devices_are_reported() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Reject)),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "reject")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        0,
        vec![rejected(Some("com.example.app"), "reject")],
        0,
    )
    .await;
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

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "spqr")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        0,
        vec![rejected(Some("com.example.app"), "spqr")],
        0,
    )
    .await;
}

#[tokio::test]
async fn remote_errors_map_to_502() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new(
            "com.example.app",
            TestBehavior::RemoteError,
        )),
    )]);

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "remote")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn internal_errors_map_to_500() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new(
            "com.example.app",
            TestBehavior::InternalError,
        )),
    )]);

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "boom")]))
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn temporary_errors_map_to_503_with_retry_after() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new(
            "com.example.app",
            TestBehavior::TemporaryError,
        )),
    )]);

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "retry")]))
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("7")
    );
}

#[tokio::test]
async fn oversized_requests_are_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .text("x".repeat(MAX_REQUEST_SIZE + 1))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn per_pushkin_concurrency_limit_returns_502() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::with_limit(
            "com.example.app",
            TestBehavior::SlowAccept,
            1,
        )),
    )]);

    let request_a = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service);
    let request_b = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service);

    let (response_a, response_b) = tokio::join!(request_a, request_b);
    let statuses = [
        response_a.status_code.unwrap(),
        response_b.status_code.unwrap(),
    ];

    assert!(statuses.contains(&StatusCode::OK));
    assert!(statuses.contains(&StatusCode::BAD_GATEWAY));
}

#[tokio::test]
async fn duplicate_devices_are_dispatched_only_once() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Reject)),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![
            device("com.example.app", "dup"),
            device("com.example.app", "dup"),
        ]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        0,
        vec![rejected(Some("com.example.app"), "dup")],
        0,
    )
    .await;
}

#[tokio::test]
async fn blank_device_fields_are_rejected_without_dispatch() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![
            device("   ", "blank-app"),
            device("com.example.app", "   "),
        ]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        0,
        vec![
            rejected(None, "blank-app"),
            rejected(Some("com.example.app"), "   "),
        ],
        0,
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

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![
            device("com.example.ok", "ok"),
            device("com.example.retry", "retry"),
        ]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(&mut response, 1, vec![], 1).await;
}

#[tokio::test]
async fn all_temporary_failures_still_return_503() {
    let service = test_service(vec![(
        "com.example.retry",
        Arc::new(TestPushkin::new(
            "com.example.retry",
            TestBehavior::TemporaryError,
        )),
    )]);

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.retry", "retry")]))
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("7")
    );
}

#[tokio::test]
async fn partial_success_retries_only_failed_devices() {
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

    let first = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&request_body)
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let second = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&request_body)
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::SERVICE_UNAVAILABLE);

    assert_eq!(success_calls.load(Ordering::SeqCst), 1);
    assert_eq!(retry_calls.load(Ordering::SeqCst), 2);
}
