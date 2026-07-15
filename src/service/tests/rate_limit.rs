use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use salvo::test::TestClient;
use serde_json::json;

use super::*;

#[tokio::test]
async fn notify_rate_limit_returns_429_with_retry_after() {
    let service = test_service_with_rate_limits(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        {
            let mut config = NotifyRateLimitConfig::default();
            config.window_seconds = 60;
            config.per_origin_service = Some(1);
            config
        },
    );

    let first = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(ORIGIN_SERVICE_ID_HEADER, "did:web:sync.example.com", true)
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(ORIGIN_SERVICE_ID_HEADER, "did:web:sync.example.com", true)
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        second
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|value| value >= 1)
    );
    let body = assert_notify_error(&mut second, "rate_limited", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("notify rate limit exceeded for origin_service")
    );
    assert!(
        body["error"]["retry_after_ms"]
            .as_u64()
            .is_some_and(|value| value >= 1000)
    );
}

#[tokio::test]
async fn notify_rate_limit_can_apply_per_app_id() {
    let service = test_service_with_rate_limits(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        {
            let mut config = NotifyRateLimitConfig::default();
            config.window_seconds = 60;
            config.per_app_id = Some(1);
            config
        },
    );

    let first = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    let body = assert_notify_error(&mut second, "rate_limited", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("notify rate limit exceeded for app_id")
    );
}

#[tokio::test]
async fn notify_rate_limit_can_apply_per_provider() {
    let service = test_service_with_rate_limits(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        {
            let mut config = NotifyRateLimitConfig::default();
            config.window_seconds = 60;
            config.per_provider = Some(1);
            config
        },
    );

    let first = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    let body = assert_notify_error(&mut second, "rate_limited", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("notify rate limit exceeded for provider")
    );
}

#[tokio::test]
async fn notify_rate_limit_can_apply_per_push_key_hash() {
    let service = test_service_with_rate_limits(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        {
            let mut config = NotifyRateLimitConfig::default();
            config.window_seconds = 60;
            config.per_push_key_hash = Some(1);
            config
        },
    );

    let first = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "same-push-key")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "same-push-key")]))
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    let body = assert_notify_error(&mut second, "rate_limited", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("notify rate limit exceeded for push_key_hash")
    );
}

#[tokio::test]
async fn notify_rate_limit_can_apply_per_endpoint() {
    let service = test_service_with_rate_limits(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        {
            let mut config = NotifyRateLimitConfig::default();
            config.window_seconds = 60;
            config.per_endpoint = Some(1);
            config
        },
    );

    let first = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    let body = assert_notify_error(&mut second, "rate_limited", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("notify rate limit exceeded for endpoint")
    );
}

#[tokio::test]
async fn dedup_replay_bypasses_rate_limit() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service_with_dedup_and_rate_limits(
        vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
        Duration::from_secs(60),
        {
            let mut config = NotifyRateLimitConfig::default();
            config.window_seconds = 60;
            config.per_origin_service = Some(1);
            config
        },
    );
    let request_body = payload(vec![device("com.example.app", "cached")]);

    for _ in 0..2 {
        let response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
            .add_header(ORIGIN_SERVICE_ID_HEADER, "did:web:sync.example.com", true)
            .add_header("idempotency-key", "notify-123", true)
            .json(&request_body)
            .send(&service)
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
