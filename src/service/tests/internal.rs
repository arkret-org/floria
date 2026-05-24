//! Round R2/R3 (T07 + T17) — service tests for the internal
//! soland-broadcast endpoints (`account_deactivate_fanout`,
//! `consent_revoke`). Verifies wire-shape rejection, idempotency, and
//! the sealed-channel "still complete" outcome.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

use super::*;
use crate::AppState;
use crate::broadcast::InProcessBroadcastBus;
use crate::deactivation::{
    AccountDeactivateFanoutBroadcast, DeactivationLedger, DeactivationQueueDrain,
};
use crate::push_contact_cache::{PsiVerdict, PushContactCache};
use crate::pushkin::PushkinRegistry;

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
    push_contact_cache: Option<Arc<PushContactCache>>,
) -> Service {
    let registry = PushkinRegistry::new(HashMap::new());
    let mut state = AppState::new(Arc::new(registry));
    state.deactivation_ledger = deactivation_ledger;
    state.push_contact_cache = push_contact_cache;
    state.broadcast_bus = Some(Arc::new(InProcessBroadcastBus::new(
        state.deactivation_ledger.clone(),
        state.push_contact_cache.clone(),
    )));
    Service::new(build_router(Arc::new(state)))
}

fn test_service_without_broadcast_bus() -> Service {
    let registry = PushkinRegistry::new(HashMap::new());
    Service::new(build_router(Arc::new(AppState::new(Arc::new(registry)))))
}

#[tokio::test]
async fn account_deactivate_fanout_completes_for_drained_devices() {
    let ledger = Arc::new(DeactivationLedger::new());
    let service = test_service_with_internal_state(Some(ledger.clone()), None);

    let mut response =
        TestClient::post("http://127.0.0.1/api/v1/internal/account_deactivate_fanout")
            .json(&json!({
                "fanout_id": "fanout-1",
                "actor_did": "did:web:alice.example",
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
    let service = test_service_with_internal_state(Some(ledger.clone()), None);

    let payload = json!({
        "fanout_id": "fanout-1",
        "actor_did": "did:web:alice.example",
        "devices": [{"device_id": "device-a"}]
    });

    let mut first = TestClient::post("http://127.0.0.1/api/v1/internal/account_deactivate_fanout")
        .json(&payload)
        .send(&service)
        .await;
    let first_body: Value = first.take_json().await.unwrap();

    let mut second = TestClient::post("http://127.0.0.1/api/v1/internal/account_deactivate_fanout")
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
    let service = test_service_with_internal_state(Some(ledger), None);

    let payload = json!({
        "fanout_id": "fanout-drain-1",
        "actor_did": "did:web:alice.example",
        "devices": [
            {"device_id": "device-a", "push_key_hash": "hash-a"},
            {"device_id": "device-b"}
        ]
    });

    let mut first = TestClient::post("http://127.0.0.1/api/v1/internal/account_deactivate_fanout")
        .json(&payload)
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);
    let first_body: Value = first.take_json().await.unwrap();
    assert_eq!(first_body["outcome"], json!("completed"));
    assert_eq!(first_body["messages_drained"], json!(7));
    assert_eq!(drain_calls.load(Ordering::SeqCst), 1);

    let mut second = TestClient::post("http://127.0.0.1/api/v1/internal/account_deactivate_fanout")
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
    let service = test_service_with_internal_state(Some(ledger.clone()), None);

    let mut response =
        TestClient::post("http://127.0.0.1/api/v1/internal/account_deactivate_fanout")
            .json(&json!({
                "fanout_id": "fanout-1",
                "actor_did": "did:web:alice.example",
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
async fn account_deactivate_fanout_rejects_missing_actor_did() {
    let ledger = Arc::new(DeactivationLedger::new());
    let service = test_service_with_internal_state(Some(ledger), None);

    let mut response =
        TestClient::post("http://127.0.0.1/api/v1/internal/account_deactivate_fanout")
            .json(&json!({
                "fanout_id": "fanout-1",
                "actor_did": "",
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

    let mut response =
        TestClient::post("http://127.0.0.1/api/v1/internal/account_deactivate_fanout")
            .json(&json!({
                "fanout_id": "fanout-1",
                "actor_did": "did:web:alice.example",
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

#[tokio::test]
async fn consent_revoke_scope_any_invalidates_principal_entries() {
    let cache = Arc::new(PushContactCache::in_memory());
    cache.insert("did:web:alice.example", "psi-1", PsiVerdict::Allowed);
    cache.insert("did:web:alice.example", "psi-2", PsiVerdict::Denied);
    cache.insert("did:web:bob.example", "psi-1", PsiVerdict::Allowed);

    let service = test_service_with_internal_state(None, Some(cache.clone()));

    let mut response = TestClient::post("http://127.0.0.1/api/v1/internal/consent_revoke")
        .json(&json!({
            "broadcast_id": "bcast-1",
            "principal_did": "did:web:alice.example",
            "scope": "any"
        }))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["entries_evicted"], json!(2));
    assert_eq!(body["scope"], json!("any"));

    // Alice's entries gone, Bob's still cached.
    assert!(cache.get("did:web:alice.example", "psi-1").is_none());
    assert_eq!(
        cache.get("did:web:bob.example", "psi-1"),
        Some(PsiVerdict::Allowed)
    );
}

#[tokio::test]
async fn consent_revoke_rejects_scoped_revocation() {
    let cache = Arc::new(PushContactCache::in_memory());
    let service = test_service_with_internal_state(None, Some(cache));

    let mut response = TestClient::post("http://127.0.0.1/api/v1/internal/consent_revoke")
        .json(&json!({
            "broadcast_id": "bcast-1",
            "principal_did": "did:web:alice.example",
            "scope": "realm"
        }))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], json!("unsupported_feature"));
}

#[tokio::test]
async fn consent_revoke_returns_503_when_cache_unwired() {
    let service = test_service_without_broadcast_bus();

    let mut response = TestClient::post("http://127.0.0.1/api/v1/internal/consent_revoke")
        .json(&json!({
            "broadcast_id": "bcast-1",
            "principal_did": "did:web:alice.example",
            "scope": "any"
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
