//! Operator authentication and rejection of the retired identity-bearing broadcast.

use std::sync::Arc;

use arkret_push_policy::blind_payload_sanitizer::PROVIDER_EGRESS_STRIP_KEYS;
use salvo::test::{RequestBuilder, ResponseExt, TestClient};
use serde_json::{Value, json};

use super::*;
use crate::AppState;
use crate::config::InternalAuthConfig;
use crate::pushkin::PushkinRegistry;
use crate::retry_queue::{RetryEnvelope, RetryQueue, RetryQueueConfig};

const INTERNAL_TOKEN: &str = "internal-test-token";

fn test_service_with_internal_auth() -> Service {
    let registry = PushkinRegistry::new(HashMap::new());
    let mut state = AppState::new(Arc::new(registry));
    state.internal_auth = internal_auth_config();
    Service::new(build_router(Arc::new(state)))
}

fn test_service_without_internal_auth() -> Service {
    let registry = PushkinRegistry::new(HashMap::new());
    let state = AppState::new(Arc::new(registry));
    Service::new(build_router(Arc::new(state)))
}

fn test_service_with_internal_auth_config(internal_auth: InternalAuthConfig) -> Service {
    let registry = PushkinRegistry::new(HashMap::new());
    let mut state = AppState::new(Arc::new(registry));
    state.internal_auth = internal_auth;
    Service::new(build_router(Arc::new(state)))
}

fn test_service_with_retry_queue(queue: Arc<RetryQueue>) -> Service {
    let registry = PushkinRegistry::new(HashMap::new());
    let mut state = AppState::new(Arc::new(registry));
    state.notify_retry_queue = Some(queue);
    state.internal_auth = internal_auth_config();
    Service::new(build_router(Arc::new(state)))
}

fn dead_letter_envelope(request_id: &str) -> RetryEnvelope {
    RetryEnvelope::new(
        request_id,
        "test-pushkin",
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        serde_json::from_value(serde_json::json!({"push_target_id":"ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8", "wakeup_kind":"message", "devices":[{"device_id":"ak:device:0196419b-0000-7000-8000-000000000001"}]})).unwrap(),
        std::time::Duration::from_secs(30),
        "provider timeout",
    )
}

fn internal_auth(request: RequestBuilder) -> RequestBuilder {
    request.bearer_auth(INTERNAL_TOKEN)
}

fn internal_auth_config() -> InternalAuthConfig {
    let mut config = InternalAuthConfig::default();
    config.bearer_tokens = vec![INTERNAL_TOKEN.to_owned()];
    config
}

#[tokio::test]
async fn internal_routes_fail_closed_when_auth_unconfigured() {
    let service = test_service_without_internal_auth();

    let mut response = TestClient::get("http://127.0.0.1/_floria/admin/push/status/missing")
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(
        body["type"],
        json!("https://arkret.org/problems/service_unavailable")
    );
    assert_eq!(
        body["detail"],
        json!("internal endpoint authentication is not configured")
    );
}

#[tokio::test]
async fn internal_routes_reject_missing_and_invalid_bearer() {
    let service = test_service_with_internal_auth();

    let mut missing = TestClient::get("http://127.0.0.1/_floria/admin/push/status/missing")
        .send(&service)
        .await;
    assert_eq!(missing.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let missing_body: Value = missing.take_json().await.unwrap();
    assert_eq!(
        missing_body["type"],
        json!("https://arkret.org/problems/unauthenticated")
    );
    assert_eq!(
        missing_body["detail"],
        json!("missing internal bearer token")
    );

    let mut invalid = TestClient::get("http://127.0.0.1/_floria/admin/push/status/missing")
        .bearer_auth("wrong-token")
        .send(&service)
        .await;
    assert_eq!(invalid.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let invalid_body: Value = invalid.take_json().await.unwrap();
    assert_eq!(
        invalid_body["type"],
        json!("https://arkret.org/problems/unauthenticated")
    );
    assert_eq!(
        invalid_body["detail"],
        json!("invalid internal bearer token")
    );
}

#[tokio::test]
async fn internal_routes_accept_hashed_bearer_token() {
    let mut config = InternalAuthConfig::default();
    config.bearer_token_hashes = vec![crate::auth::bearer_token_sha256_hex(INTERNAL_TOKEN)];
    let service = test_service_with_internal_auth_config(config);

    let mut response = internal_auth(TestClient::get(
        "http://127.0.0.1/_floria/admin/push/status/missing",
    ))
    .send(&service)
    .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(
        body["type"],
        json!("https://arkret.org/problems/service_unavailable")
    );
    assert_eq!(
        body["detail"],
        json!("notify deduplication cache is disabled; status lookup unavailable")
    );
}

#[tokio::test]
async fn status_requires_internal_bearer() {
    let service = test_service_with_internal_auth();

    let mut status = TestClient::get("http://127.0.0.1/_floria/admin/push/status/key-1")
        .send(&service)
        .await;
    assert_eq!(status.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let status_body: Value = status.take_json().await.unwrap();
    assert_eq!(
        status_body["type"],
        json!("https://arkret.org/problems/unauthenticated")
    );
}

#[tokio::test]
async fn dead_letters_requires_internal_bearer() {
    let service =
        test_service_with_retry_queue(Arc::new(RetryQueue::memory(RetryQueueConfig::default())));

    let mut response = TestClient::get("http://127.0.0.1/_floria/admin/push/dead-letters")
        .send(&service)
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(
        body["type"],
        json!("https://arkret.org/problems/unauthenticated")
    );
}

#[tokio::test]
async fn dead_letters_returns_503_when_retry_queue_disabled() {
    // No retry queue configured at all — the route must answer 503, not
    // pretend the ring is empty.
    let service = test_service_with_internal_auth();

    let mut response = internal_auth(TestClient::get(
        "http://127.0.0.1/_floria/admin/push/dead-letters",
    ))
    .send(&service)
    .await;
    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(
        body["type"],
        json!("https://arkret.org/problems/service_unavailable")
    );
    assert_eq!(
        body["detail"],
        json!("notify retry queue is disabled; dead-letter snapshot unavailable")
    );
}

#[tokio::test]
async fn dead_letters_empty_ring_returns_empty_snapshot() {
    let service =
        test_service_with_retry_queue(Arc::new(RetryQueue::memory(RetryQueueConfig::default())));

    let mut response = internal_auth(TestClient::get(
        "http://127.0.0.1/_floria/admin/push/dead-letters",
    ))
    .send(&service)
    .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["backend"], json!("memory"));
    assert_eq!(body["count"], json!(0));
    assert_eq!(body["dead_letters"], json!([]));
}

#[tokio::test]
async fn dead_letters_full_ring_returns_newest_first_and_strips_egress_keys() {
    // Capacity 3 and 5 inserts — the ring must evict the two oldest.
    let config = RetryQueueConfig {
        dead_letter_capacity: 3,
        ..RetryQueueConfig::default()
    };
    let queue = Arc::new(RetryQueue::memory(config));
    for index in 1..=5 {
        queue.dead_letter(dead_letter_envelope(&format!("req-{index}")));
    }
    let service = test_service_with_retry_queue(queue);

    let mut response = internal_auth(TestClient::get(
        "http://127.0.0.1/_floria/admin/push/dead-letters",
    ))
    .send(&service)
    .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["backend"], json!("memory"));
    assert_eq!(body["count"], json!(3));
    // Newest first; req-1 / req-2 were evicted by the ring.
    assert_eq!(body["dead_letters"][0]["request_id"], json!("req-5"));
    assert_eq!(body["dead_letters"][1]["request_id"], json!("req-4"));
    assert_eq!(body["dead_letters"][2]["request_id"], json!("req-3"));
    assert_eq!(body["dead_letters"][0]["pushkin"], json!("test-pushkin"));
    assert_eq!(
        body["dead_letters"][0]["last_error"],
        json!("provider timeout")
    );

    // Egress hygiene: no strip-only routing/audit key may appear
    // anywhere in the rendered snapshot.
    let rendered = serde_json::to_string(&body).unwrap().to_ascii_lowercase();
    for name in PROVIDER_EGRESS_STRIP_KEYS {
        assert!(
            !rendered.contains(*name),
            "strip-only key `{name}` leaked into dead-letter snapshot"
        );
    }

    // `limit` truncates from the newest end.
    let mut limited = internal_auth(TestClient::get(
        "http://127.0.0.1/_floria/admin/push/dead-letters?limit=1",
    ))
    .send(&service)
    .await;
    assert_eq!(limited.status_code.unwrap(), StatusCode::OK);
    let limited_body: Value = limited.take_json().await.unwrap();
    assert_eq!(limited_body["count"], json!(1));
    assert_eq!(
        limited_body["dead_letters"][0]["request_id"],
        json!("req-5")
    );
}

#[tokio::test]
async fn dead_letters_rejects_invalid_limit() {
    let service =
        test_service_with_retry_queue(Arc::new(RetryQueue::memory(RetryQueueConfig::default())));

    for bad in ["0", "abc", "-1", "1001"] {
        let mut response = internal_auth(TestClient::get(format!(
            "http://127.0.0.1/_floria/admin/push/dead-letters?limit={bad}"
        )))
        .send(&service)
        .await;
        assert_eq!(
            response.status_code.unwrap(),
            StatusCode::BAD_REQUEST,
            "limit={bad} must be rejected"
        );
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(
            body["type"],
            json!("https://arkret.org/problems/schema_violation")
        );
    }
}

#[tokio::test]
async fn retired_account_deactivation_route_is_absent_even_with_valid_bearer() {
    let service = test_service_with_internal_auth();
    for token in [None, Some(INTERNAL_TOKEN)] {
        let request =
            TestClient::post("http://127.0.0.1/_floria/internal/account_deactivate_fanout");
        let request = if let Some(token) = token {
            request.bearer_auth(token)
        } else {
            request
        };
        let response = request
            .json(&json!({
                "fanout_id": "retired-request", "actor_id": "ak:did_core:web:alice.example",
                "devices": [{"device_id": "device-a"}]
            }))
            .send(&service)
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::NOT_FOUND);
    }
}
