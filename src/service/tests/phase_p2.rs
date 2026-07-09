//! Phase P2 (spec 37ce729, SDK 4d5a1af) — Personal Agent + Sidecar
//! push-routing closures.
//!
//! Covers the three wire-affecting changes carried by phase P2 / B-A
//! and B-B:
//!
//! 1. Durable agent lifecycle events (`ck.agent.{pause,resume,deactivate}`) MUST be silently
//!    consumed on the `/push/notify` endpoint — 200 OK + zero provider fanout. The authoritative
//!    capability-cache invalidation path is the `/internal/consent_revoke` listener with
//!    `reason=agent_paused` or `agent_deactivated`.
//! 2. Actor-private agent events (`ck.agent.{draft.propose,action_request,action_approve,
//!    action_reject}`) MUST be dropped by default — same 200 OK + zero-fanout shape, but logged
//!    separately so an operator can later opt a subscription gate in.
use std::sync::Arc;
use std::sync::atomic::Ordering;

use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

use super::*;

#[tokio::test]
async fn agent_pause_event_is_silently_consumed_without_fanout() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut body = payload(vec![device("com.example.app", "would-be-pushed-token")]);
    body["event_kind"] = json!("ck.self.agent.pause");

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response
        .take_json::<arkret::PushNotifyOutcome>()
        .await
        .unwrap();
    assert!(resp.rejected.is_empty());
    // Critical: durable agent lifecycle event MUST NOT trigger a
    // user-device push fanout. Capability cache invalidation strands
    // through `/internal/consent_revoke` with `reason=agent_paused`.
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn agent_resume_event_is_silently_consumed_without_fanout() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut body = payload(vec![device("com.example.app", "would-be-pushed-token")]);
    body["event_kind"] = json!("ck.self.agent.resume");

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response
        .take_json::<arkret::PushNotifyOutcome>()
        .await
        .unwrap();
    assert!(resp.rejected.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn agent_deactivate_event_is_silently_consumed_without_fanout() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut body = payload(vec![device("com.example.app", "would-be-pushed-token")]);
    body["event_kind"] = json!("ck.self.agent.deactivate");

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response
        .take_json::<arkret::PushNotifyOutcome>()
        .await
        .unwrap();
    assert!(resp.rejected.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn agent_actor_private_kinds_are_dropped_without_fanout() {
    for kind in [
        "ck.agent.draft.propose",
        "ck.agent.action_request",
        "ck.agent.action_approve",
        "ck.agent.action_reject",
    ] {
        let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
        let calls = pushkin.calls.clone();
        let service = test_service(vec![("com.example.app", pushkin)]);

        let mut body = payload(vec![device("com.example.app", "would-be-pushed-token")]);
        body["event_kind"] = json!(kind);

        let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
            .json(&body)
            .send(&service)
            .await;

        assert_eq!(
            response.status_code.unwrap(),
            StatusCode::OK,
            "actor_private agent kind {kind} should be dropped (200 OK)"
        );
        let resp = response
            .take_json::<arkret::PushNotifyOutcome>()
            .await
            .unwrap();
        assert!(
            resp.rejected.is_empty(),
            "kind {kind} unexpectedly returned rejected devices"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "actor_private kind {kind} MUST NOT hit the provider"
        );
    }
}

#[tokio::test]
async fn non_agent_event_kind_falls_through_to_push_fanout() {
    // Any other `event_kind` string (or non-agent durable kind) must
    // continue down the historical push pipeline. We use `ck.message`
    // here as a placeholder for the normal-fanout kind.
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut body = payload(vec![device("com.example.app", "alice-token")]);
    body["event_kind"] = json!("ck.message");

    let mut response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response
        .take_json::<arkret::PushNotifyOutcome>()
        .await
        .unwrap();
    assert!(resp.rejected.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn non_string_event_kind_is_rejected_as_schema_violation() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut body = payload(vec![device("com.example.app", "x")]);
    body["event_kind"] = json!(42);

    let response = TestClient::post("http://127.0.0.1/_cokret/edge/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}
