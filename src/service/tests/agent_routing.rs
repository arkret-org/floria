//! Agent lifecycle and private-event no-fanout acknowledgements.
//! Every input device is acknowledged without new provider delivery.
use std::sync::Arc;
use std::sync::atomic::Ordering;

use salvo::http::StatusCode;
use salvo::test::ResponseExt;
use serde_json::json;

use super::*;

#[tokio::test]
async fn agent_pause_event_is_silently_consumed_without_fanout() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut body = payload(vec![device("com.example.app", "would-be-pushed-token")]);
    body["event_kind"] = json!("ak.self.agent.pause");

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response
        .take_json::<arkret_models_integration::PushNotifyOutcome>()
        .await
        .unwrap();
    assert_eq!(
        resp.outcomes[0].gateway_status,
        arkret_models_integration::PushNotifyGatewayStatus::Duplicate
    );
    // Critical: durable agent lifecycle event MUST NOT trigger a
    // user-device push fanout. Upstream current admission already gates
    // lifecycle and participation before constructing this envelope.
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn agent_resume_event_is_silently_consumed_without_fanout() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut body = payload(vec![device("com.example.app", "would-be-pushed-token")]);
    body["event_kind"] = json!("ak.self.agent.resume");

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response
        .take_json::<arkret_models_integration::PushNotifyOutcome>()
        .await
        .unwrap();
    assert_eq!(
        resp.outcomes[0].gateway_status,
        arkret_models_integration::PushNotifyGatewayStatus::Duplicate
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn agent_deactivate_event_is_silently_consumed_without_fanout() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut body = payload(vec![device("com.example.app", "would-be-pushed-token")]);
    body["event_kind"] = json!("ak.self.agent.deactivate");

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response
        .take_json::<arkret_models_integration::PushNotifyOutcome>()
        .await
        .unwrap();
    assert_eq!(
        resp.outcomes[0].gateway_status,
        arkret_models_integration::PushNotifyGatewayStatus::Duplicate
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn agent_actor_private_kinds_are_dropped_without_fanout() {
    for kind in [
        "ak.agent.draft.propose",
        "ak.agent.action_request",
        "ak.agent.action_approve",
        "ak.agent.action_reject",
    ] {
        let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
        let calls = pushkin.calls.clone();
        let service = test_service(vec![("com.example.app", pushkin)]);

        let mut body = payload(vec![device("com.example.app", "would-be-pushed-token")]);
        body["event_kind"] = json!(kind);

        let mut response =
            authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
                .add_header(
                    "Arkret-Operation",
                    arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
                    true,
                )
                .json(&body)
                .send(&service)
                .await;

        assert_eq!(
            response.status_code.unwrap(),
            StatusCode::OK,
            "actor_private agent kind {kind} should be dropped (200 OK)"
        );
        let resp = response
            .take_json::<arkret_models_integration::PushNotifyOutcome>()
            .await
            .unwrap();
        assert_eq!(
            resp.outcomes[0].gateway_status,
            arkret_models_integration::PushNotifyGatewayStatus::Duplicate,
            "kind {kind} did not return a conserved no-fanout outcome"
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
    // continue down the historical push pipeline. The registered `ak.message.create` kind exercises
    // normal fanout.
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);

    let mut body = payload(vec![device("com.example.app", "alice-token")]);
    body["event_kind"] = json!("ak.message.create");

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let resp = response
        .take_json::<arkret_models_integration::PushNotifyOutcome>()
        .await
        .unwrap();
    assert_eq!(
        resp.outcomes[0].gateway_status,
        arkret_models_integration::PushNotifyGatewayStatus::Accepted
    );
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

    let response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}
