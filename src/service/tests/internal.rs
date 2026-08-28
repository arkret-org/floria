//! Service tests for the internal account-deactivation broadcast endpoint.
//! Verifies wire-shape rejection and idempotency.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arkret_push_policy::blind_payload_sanitizer::PROVIDER_EGRESS_STRIP_KEYS;
use salvo::test::{RequestBuilder, ResponseExt, TestClient};
use serde_json::{Value, json};

use super::*;
use crate::AppState;
use crate::broadcast::InProcessBroadcastBus;
use crate::config::InternalAuthConfig;
use crate::deactivation::{
    AccountDeactivateFanoutBroadcast, DeactivationLedger, DeactivationQueueDrain,
};
use crate::pushkin::PushkinRegistry;
use crate::retry_queue::{RetryEnvelope, RetryQueue, RetryQueueConfig};

const INTERNAL_TOKEN: &str = "internal-test-token";

#[derive(Debug)]
struct TestQueueDrain {
    calls: Arc<AtomicUsize>,
    drained: usize,
}

impl DeactivationQueueDrain for TestQueueDrain {
    fn drain(&self, _broadcast: &AccountDeactivateFanoutBroadcast) -> anyhow::Result<usize> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.drained)
    }
}

fn test_service_with_internal_state(
    deactivation_ledger: Option<Arc<DeactivationLedger>>,
) -> Service {
    let registry = PushkinRegistry::new(HashMap::new());
    let mut state = AppState::new(Arc::new(registry));
    state.deactivation_ledger = deactivation_ledger;
    state.broadcast_bus = Some(Arc::new(InProcessBroadcastBus::new(
        state.deactivation_ledger.clone(),
    )));
    state.internal_auth = internal_auth_config();
    Service::new(build_router(Arc::new(state)))
}

fn test_service_without_broadcast_bus() -> Service {
    let registry = PushkinRegistry::new(HashMap::new());
    let mut state = AppState::new(Arc::new(registry));
    state.internal_auth = internal_auth_config();
    Service::new(build_router(Arc::new(state)))
}

fn test_service_without_internal_auth() -> Service {
    let registry = PushkinRegistry::new(HashMap::new());
    let mut state = AppState::new(Arc::new(registry));
    state.broadcast_bus = Some(Arc::new(InProcessBroadcastBus::new(None)));
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
        "app-1",
        arkret_models_integration::PushKey::new("push-key-1").unwrap(),
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

    let mut response =
        TestClient::post("http://127.0.0.1/_floria/internal/account_deactivate_fanout")
            .json(&json!({
                "fanout_id": "fanout-1",
                "actor_id": "ak:did_core:web:alice.example",
                "devices": []
            }))
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
    let service = test_service_without_broadcast_bus();

    let mut missing =
        TestClient::post("http://127.0.0.1/_floria/internal/account_deactivate_fanout")
            .json(&json!({
                "fanout_id": "fanout-1",
                "actor_id": "ak:did_core:web:alice.example",
                "devices": []
            }))
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

    let mut invalid =
        TestClient::post("http://127.0.0.1/_floria/internal/account_deactivate_fanout")
            .bearer_auth("wrong-token")
            .json(&json!({
                "fanout_id": "fanout-1",
                "actor_id": "ak:did_core:web:alice.example",
                "devices": []
            }))
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

    let mut response = internal_auth(TestClient::post(
        "http://127.0.0.1/_floria/internal/account_deactivate_fanout",
    ))
    .json(&json!({
        "fanout_id": "fanout-1",
        "actor_id": "ak:did_core:web:alice.example",
        "devices": []
    }))
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
        json!("in-process broadcast bus is not configured on this push gateway")
    );
}

#[tokio::test]
async fn status_requires_internal_bearer() {
    let service = test_service_without_broadcast_bus();

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
    let service = test_service_without_broadcast_bus();

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
async fn account_deactivate_fanout_completes_for_drained_devices() {
    let ledger = Arc::new(DeactivationLedger::new());
    let service = test_service_with_internal_state(Some(ledger.clone()));

    let mut response = internal_auth(TestClient::post(
        "http://127.0.0.1/_floria/internal/account_deactivate_fanout",
    ))
    .json(&json!({
        "fanout_id": "fanout-1",
        "actor_id": "ak:did_core:web:alice.example",
        "devices": [
            {"device_id": "device-a"},
            {"device_id": "device-b"}
        ]
    }))
    .send(&service)
    .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["fanout_id"], json!("fanout-1"));
    assert_eq!(body["outcome"], json!("completed"));
    assert_eq!(body["device_bindings_unbound"], json!(2));
    assert_eq!(body["actor_bindings_unbound"], json!(1));
}

#[tokio::test]
async fn account_deactivate_fanout_is_idempotent_across_retries() {
    let ledger = Arc::new(DeactivationLedger::new());
    let service = test_service_with_internal_state(Some(ledger.clone()));

    let payload = json!({
        "fanout_id": "fanout-1",
        "actor_id": "ak:did_core:web:alice.example",
        "devices": [{"device_id": "device-a"}]
    });

    let mut first = internal_auth(TestClient::post(
        "http://127.0.0.1/_floria/internal/account_deactivate_fanout",
    ))
    .json(&payload)
    .send(&service)
    .await;
    let first_body: Value = first.take_json().await.unwrap();

    let mut second = internal_auth(TestClient::post(
        "http://127.0.0.1/_floria/internal/account_deactivate_fanout",
    ))
    .json(&payload)
    .send(&service)
    .await;
    let second_body: Value = second.take_json().await.unwrap();

    assert_eq!(first_body, second_body);
    // Critical property — the retry does NOT double-count.
    assert_eq!(second_body["device_bindings_unbound"], json!(1));
}

#[tokio::test]
async fn account_deactivate_fanout_reports_drained_queue_count() {
    let drain_calls = Arc::new(AtomicUsize::new(0));
    let ledger = Arc::new(DeactivationLedger::with_queue_drain(Arc::new(
        TestQueueDrain {
            calls: drain_calls.clone(),
            drained: 7,
        },
    )));
    let service = test_service_with_internal_state(Some(ledger));

    let payload = json!({
        "fanout_id": "fanout-drain-1",
        "actor_id": "ak:did_core:web:alice.example",
        "devices": [
            {"device_id": "device-a", "push_key_hash": "hash-a"},
            {"device_id": "device-b"}
        ]
    });

    let mut first = internal_auth(TestClient::post(
        "http://127.0.0.1/_floria/internal/account_deactivate_fanout",
    ))
    .json(&payload)
    .send(&service)
    .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);
    let first_body: Value = first.take_json().await.unwrap();
    assert_eq!(first_body["outcome"], json!("completed"));
    assert_eq!(first_body["messages_drained"], json!(7));
    assert_eq!(drain_calls.load(Ordering::SeqCst), 1);

    let mut second = internal_auth(TestClient::post(
        "http://127.0.0.1/_floria/internal/account_deactivate_fanout",
    ))
    .json(&payload)
    .send(&service)
    .await;
    let second_body: Value = second.take_json().await.unwrap();
    assert_eq!(second_body, first_body);
    assert_eq!(
        drain_calls.load(Ordering::SeqCst),
        1,
        "idempotent retry must not drain the queue twice"
    );
}

#[tokio::test]
async fn account_deactivate_fanout_rejects_missing_actor_id() {
    let ledger = Arc::new(DeactivationLedger::new());
    let service = test_service_with_internal_state(Some(ledger));

    let mut response = internal_auth(TestClient::post(
        "http://127.0.0.1/_floria/internal/account_deactivate_fanout",
    ))
    .json(&json!({
        "fanout_id": "fanout-1",
        "actor_id": "",
        "devices": []
    }))
    .send(&service)
    .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(
        body["type"],
        json!("https://arkret.org/problems/schema_violation")
    );
}

#[tokio::test]
async fn account_deactivate_fanout_returns_503_when_ledger_unwired() {
    let service = test_service_without_broadcast_bus();

    let mut response = internal_auth(TestClient::post(
        "http://127.0.0.1/_floria/internal/account_deactivate_fanout",
    ))
    .json(&json!({
        "fanout_id": "fanout-1",
        "actor_id": "ak:did_core:web:alice.example",
        "devices": []
    }))
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
}
