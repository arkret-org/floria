//! Service tests for the internal account-deactivation broadcast endpoint.
//! Verifies wire-shape rejection, idempotency, and the sealed-channel
//! "still complete" outcome.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
                "actor_id": "did:web:alice.example",
                "devices": []
            }))
            .send(&service)
            .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], json!("service_unavailable"));
    assert_eq!(
        body["error"]["message"],
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
                "actor_id": "did:web:alice.example",
                "devices": []
            }))
            .send(&service)
            .await;
    assert_eq!(missing.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let missing_body: Value = missing.take_json().await.unwrap();
    assert_eq!(missing_body["error"]["code"], json!("unauthenticated"));
    assert_eq!(
        missing_body["error"]["message"],
        json!("missing internal bearer token")
    );

    let mut invalid =
        TestClient::post("http://127.0.0.1/_floria/internal/account_deactivate_fanout")
            .bearer_auth("wrong-token")
            .json(&json!({
                "fanout_id": "fanout-1",
                "actor_id": "did:web:alice.example",
                "devices": []
            }))
            .send(&service)
            .await;
    assert_eq!(invalid.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let invalid_body: Value = invalid.take_json().await.unwrap();
    assert_eq!(invalid_body["error"]["code"], json!("unauthenticated"));
    assert_eq!(
        invalid_body["error"]["message"],
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
        "actor_id": "did:web:alice.example",
        "devices": []
    }))
    .send(&service)
    .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], json!("service_unavailable"));
    assert_eq!(
        body["error"]["message"],
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
    assert_eq!(status_body["error"]["code"], json!("unauthenticated"));
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
        "actor_id": "did:web:alice.example",
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
    assert_eq!(body["sealed_channels"], json!(0));
}

#[tokio::test]
async fn account_deactivate_fanout_is_idempotent_across_retries() {
    let ledger = Arc::new(DeactivationLedger::new());
    let service = test_service_with_internal_state(Some(ledger.clone()));

    let payload = json!({
        "fanout_id": "fanout-1",
        "actor_id": "did:web:alice.example",
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
        "actor_id": "did:web:alice.example",
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
async fn account_deactivate_fanout_marks_sealed_channels_as_drained() {
    let ledger = Arc::new(DeactivationLedger::new());
    ledger.mark_channel_sealed("did:web:alice.example", "device-a");
    let service = test_service_with_internal_state(Some(ledger.clone()));

    let mut response = internal_auth(TestClient::post(
        "http://127.0.0.1/_floria/internal/account_deactivate_fanout",
    ))
    .json(&json!({
        "fanout_id": "fanout-1",
        "actor_id": "did:web:alice.example",
        "devices": [
            {"device_id": "device-a"},
            {"device_id": "device-b"}
        ]
    }))
    .send(&service)
    .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body: Value = response.take_json().await.unwrap();
    // Sealed channels count as drained — outcome MUST be `completed`
    // so soland's fanout state is not blocked.
    assert_eq!(body["outcome"], json!("completed"));
    assert_eq!(body["sealed_channels"], json!(1));
    assert_eq!(body["device_bindings_unbound"], json!(1));
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
    assert_eq!(body["error"]["code"], json!("schema_violation"));
}

#[tokio::test]
async fn account_deactivate_fanout_returns_503_when_ledger_unwired() {
    let service = test_service_without_broadcast_bus();

    let mut response = internal_auth(TestClient::post(
        "http://127.0.0.1/_floria/internal/account_deactivate_fanout",
    ))
    .json(&json!({
        "fanout_id": "fanout-1",
        "actor_id": "did:web:alice.example",
        "devices": []
    }))
    .send(&service)
    .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], json!("service_unavailable"));
}
