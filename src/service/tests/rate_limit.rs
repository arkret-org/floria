use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use salvo::test::{ResponseExt, TestClient};

use super::*;

async fn assert_rate_limited(response: &mut salvo::Response, expected_devices: usize) {
    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert!(response.headers().get("retry-after").is_none());
    let body = response
        .take_json::<arkret_models_integration::PushNotifyOutcome>()
        .await
        .unwrap();
    assert_eq!(body.outcomes.len(), expected_devices);
    for outcome in body.outcomes {
        assert_eq!(
            outcome.gateway_status,
            arkret_models_integration::PushNotifyGatewayStatus::Rejected
        );
        assert_eq!(
            outcome.reason_code,
            Some(arkret_models_integration::PushNotifyReasonCode::RateLimited)
        );
        assert!(outcome.retry_after_ms.is_some_and(|value| value >= 1_000));
    }
}

#[tokio::test]
async fn notify_rate_limit_returns_conserved_outcome_with_retry_after() {
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
        .add_header(SOURCE_SERVICE_ID_HEADER, "did:web:sync.example.com", true)
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(SOURCE_SERVICE_ID_HEADER, "did:web:sync.example.com", true)
        .json(&payload(vec![
            device("com.example.app", "two"),
            device("com.example.app", "three"),
        ]))
        .send(&service)
        .await;
    assert_rate_limited(&mut second, 2).await;
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
    assert_rate_limited(&mut second, 1).await;
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
    assert_rate_limited(&mut second, 1).await;
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
    assert_rate_limited(&mut second, 1).await;
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
    assert_rate_limited(&mut second, 1).await;
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
            .add_header(SOURCE_SERVICE_ID_HEADER, "did:web:sync.example.com", true)
            .add_header("idempotency-key", "notify-123", true)
            .json(&request_body)
            .send(&service)
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
